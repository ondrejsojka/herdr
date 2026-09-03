//! Lazy SSH-authorized QUIC transport for remote app clients.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quinn::{Connection, Endpoint, SendStream, VarInt};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use crate::config::RemoteConfig;
use crate::protocol::{
    self, ClientLaunchMode, ClientMessage, RemoteBootstrapRecord, RemoteBootstrapRequest,
    RemoteQuicHello, RemoteQuicRenderRecord, RemoteQuicResourceRef, RemoteQuicStreamHeader,
    RenderEncoding, ServerMessage, TerminalFrame, MAX_FRAME_SIZE, MAX_GRAPHICS_FRAME_SIZE,
    PROTOCOL_VERSION, REMOTE_QUIC_ALPN, REMOTE_QUIC_HASH_BYTES, REMOTE_QUIC_ID_BYTES,
    REMOTE_QUIC_MAX_RESOURCE_INVENTORY, REMOTE_QUIC_MAX_RESOURCE_SIZE, REMOTE_QUIC_TOKEN_BYTES,
};
use crate::remote::frame::{hash_bytes, lock, read_async_message, write_async_message};
use crate::remote::quic_policy::{
    MAX_RESOURCE_REFS_PER_FRAME, PRIORITY_CONTROL, PRIORITY_RENDER, PRIORITY_RESOURCE,
    REMOTE_QUIC_CLOSE_AUTH, REMOTE_QUIC_CLOSE_EVICTED, REMOTE_QUIC_CLOSE_HANDOFF,
    REMOTE_QUIC_CLOSE_PROTOCOL, REMOTE_QUIC_CLOSE_REPLACED, REMOTE_QUIC_CLOSE_RESYNC,
    REMOTE_QUIC_CLOSE_SHUTDOWN,
};

use crate::server::client_transport::{
    clamp_terminal_size, client_message_to_event, parse_client_keybindings, ClientWriter,
    ServerEvent,
};

const MAX_TOKENS: usize = 64;
const MAX_CONTROL_ITEMS: usize = 64;
const MAX_CONTROL_BYTES: usize = 1024 * 1024;
const MAX_RESOURCE_TRANSFERS: usize = 2;
/// Outbound resource bytes are admitted against a byte-weighted budget, in
/// KiB so the total fits a `Semaphore`'s permit count: at most
/// `MAX_RESOURCE_TRANSFERS` maximum-size resources may be buffered for
/// transfer at once, however many refs a frame carries.
const RESOURCE_BUDGET_KIB: usize = MAX_RESOURCE_TRANSFERS * REMOTE_QUIC_MAX_RESOURCE_SIZE / 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_MIN_LIFETIME: Duration = Duration::from_secs(60);
const TOKEN_MAX_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The server's own NAT keep-alive. The client drives resume probes; this is
/// only the cheap heartbeat that keeps a middlebox binding warm well inside
/// `remote.quic_transport_idle_timeout_seconds`.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
// Flow-control caps, not allocations; see the client-side note in
// src/remote/quic.rs. Sized for the render stream's burst, which carries
// multi-MB graphics frames, not for one high-latency link profile.
const QUIC_SEND_WINDOW: u64 = 4 * 1024 * 1024;
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const QUIC_RECEIVE_WINDOW: u32 = 1024 * 1024;
// Connection close codes live in src/remote/quic_policy.rs: they are on the
// wire, so the client and the server must read them from one place.

#[derive(Debug)]
struct Capability {
    session: String,
    logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
    expires_unix_seconds: u64,
    connection_generation: u64,
    active_connection: Option<Connection>,
    issued_order: u64,
}

struct ServerState {
    server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    tokens: Mutex<HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Capability>>,
    token_order: AtomicU64,
    next_client_id: AtomicU64,
    server_event_tx: mpsc::Sender<ServerEvent>,
}

/// Process-lifetime QUIC endpoint. It is constructed only after an authenticated
/// local bootstrap request, so ordinary/local Herdr never binds UDP or creates TLS material.
pub(crate) struct RemoteQuicServer {
    endpoints: Vec<Endpoint>,
    /// Duplicates of the bound UDP sockets, kept only so a live handoff can
    /// pass the listening sockets to the successor process. They are never
    /// read from: quinn owns its own duplicate of each.
    sockets: Vec<UdpSocket>,
    state: Arc<ServerState>,
    port: u16,
    identity: ServerIdentity,
    token_lifetime: Duration,
    ssh_fallback_available: bool,
    handed_off: AtomicBool,
}

impl RemoteQuicServer {
    pub(crate) fn start(
        config: &RemoteConfig,
        server_event_tx: mpsc::Sender<ServerEvent>,
    ) -> Result<Self, String> {
        let (start_port, end_port) = parse_port_range(&config.quic_port_range)?;
        let identity = ServerIdentity::generate().map_err(|err| err.to_string())?;
        let server_config =
            make_server_config(&identity, config.validated_transport_idle_timeout())
                .map_err(|err| err.to_string())?;
        let (sockets, port) = bind_sockets(start_port, end_port).map_err(|err| {
            format!("failed to bind remote QUIC port {start_port}-{end_port}: {err}")
        })?;
        let endpoints = make_endpoints(&server_config, &sockets)
            .map_err(|err| format!("failed to start remote QUIC endpoint on port {port}: {err}"))?;

        let mut server_instance_id = [0u8; REMOTE_QUIC_ID_BYTES];
        getrandom::fill(&mut server_instance_id)
            .map_err(|err| format!("failed to generate QUIC server instance id: {err}"))?;
        let state = Arc::new(ServerState {
            server_instance_id,
            tokens: Mutex::new(HashMap::new()),
            token_order: AtomicU64::new(1),
            next_client_id: AtomicU64::new(1u64 << 63),
            server_event_tx,
        });

        for endpoint in &endpoints {
            tokio::spawn(accept_connections(endpoint.clone(), Arc::clone(&state)));
        }
        info!(
            port,
            endpoints = endpoints.len(),
            "remote QUIC endpoint enabled"
        );
        Ok(Self {
            endpoints,
            sockets,
            state,
            port,
            identity,
            token_lifetime: token_lifetime(config),
            ssh_fallback_available: config.ssh_fallback,
            handed_off: AtomicBool::new(false),
        })
    }

    pub(crate) fn bootstrap(
        &self,
        request: RemoteBootstrapRequest,
    ) -> Result<RemoteBootstrapRecord, String> {
        let active_session = crate::session::active_name()
            .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
        if request.session != active_session {
            return Err(format!(
                "remote bootstrap session mismatch: requested {}, server owns {active_session}",
                request.session
            ));
        }

        let mut token = [0u8; REMOTE_QUIC_TOKEN_BYTES];
        getrandom::fill(&mut token)
            .map_err(|err| format!("failed to generate remote capability: {err}"))?;
        let token_hash = hash_bytes(&token);
        let expires_unix_seconds = unix_seconds().saturating_add(self.token_lifetime.as_secs());
        let issued_order = self.state.token_order.fetch_add(1, Ordering::Relaxed);

        let mut tokens = lock(&self.state.tokens);
        tokens.retain(|_, capability| capability.expires_unix_seconds > unix_seconds());
        if tokens.len() >= MAX_TOKENS {
            if let Some(oldest) = tokens
                .iter()
                .min_by_key(|(_, capability)| capability.issued_order)
                .map(|(hash, _)| *hash)
            {
                if let Some(removed) = tokens.remove(&oldest) {
                    if let Some(connection) = removed.active_connection {
                        // The capability is gone from the table, so the token
                        // this client holds can no longer validate: it has to
                        // bootstrap a new one rather than retry with a
                        // credential that now resolves to nothing.
                        connection.close(
                            VarInt::from_u32(REMOTE_QUIC_CLOSE_EVICTED),
                            b"capability evicted",
                        );
                    }
                }
            }
        }
        tokens.insert(
            token_hash,
            Capability {
                session: request.session,
                logical_client_id: request.logical_client_id,
                expires_unix_seconds,
                connection_generation: 0,
                active_connection: None,
                issued_order,
            },
        );

        Ok(RemoteBootstrapRecord {
            version: PROTOCOL_VERSION,
            server_instance_id: self.state.server_instance_id,
            port: self.port,
            certificate_fingerprint: self.identity.fingerprint,
            capability_token: token,
            expires_unix_seconds,
            ssh_fallback_available: self.ssh_fallback_available,
        })
    }

    /// Closes every endpoint with the handoff code, telling connected clients
    /// to reconnect with the capability they already hold instead of
    /// rebootstrapping over SSH. Suppresses the shutdown close on drop.
    pub(crate) fn close_for_handoff(&self) {
        self.handed_off.store(true, Ordering::Release);
        for endpoint in &self.endpoints {
            endpoint.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_HANDOFF),
                b"server handoff",
            );
        }
    }

    /// Closes every live client connection while keeping the endpoints
    /// listening and the capability table intact, so each client re-dials
    /// *this* process with the credential it already holds.
    ///
    /// The rollback counterpart of [`Self::close_for_handoff`]: a handoff that
    /// fails before the commit has already dropped its clients from the
    /// server's client table, and a still-healthy connection is exactly what
    /// keeps the client from noticing that its client id no longer exists.
    pub(crate) fn close_connections(&self, code: u32, reason: &[u8]) {
        let mut closed = 0usize;
        for capability in lock(&self.state.tokens).values_mut() {
            // Taken, not just closed: the capability's generation is
            // unchanged, so the reconnect fences itself past this one, and a
            // dead connection has no business staying reachable here.
            if let Some(connection) = capability.active_connection.take() {
                connection.close(VarInt::from_u32(code), reason);
                closed += 1;
            }
        }
        if closed > 0 {
            info!(closed, code, "closed live remote QUIC connections");
        }
    }

    /// Snapshots everything a successor process needs to keep existing
    /// capabilities usable, together with duplicates of the listening UDP
    /// sockets (IPv4 first, then IPv6 when bound).
    pub(crate) fn export_handoff(&self) -> io::Result<(RemoteQuicHandoffState, Vec<OwnedFd>)> {
        let mut fds = Vec::with_capacity(self.sockets.len());
        for socket in &self.sockets {
            fds.push(OwnedFd::from(socket.try_clone()?));
        }
        let socket_fd_count = u8::try_from(fds.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "too many remote QUIC sockets to hand off",
            )
        })?;
        let tokens = lock(&self.state.tokens)
            .iter()
            .map(|(token_hash, capability)| HandoffToken {
                token_hash: *token_hash,
                session: capability.session.clone(),
                logical_client_id: capability.logical_client_id,
                expires_unix_seconds: capability.expires_unix_seconds,
                connection_generation: capability.connection_generation,
                issued_order: capability.issued_order,
            })
            .collect();
        Ok((
            RemoteQuicHandoffState {
                server_instance_id: self.state.server_instance_id,
                certificate_der: self.identity.certificate_der.clone(),
                private_key_der: self.identity.private_key_der.clone(),
                certificate_fingerprint: self.identity.fingerprint,
                port: self.port,
                socket_fd_count,
                tokens,
            },
            fds,
        ))
    }

    /// Rebuilds the endpoint in a successor process from the exported state
    /// and the inherited sockets. The server instance id, certificate, and
    /// port are preserved, so a client's existing capability and pinned
    /// certificate fingerprint keep validating: it reconnects instead of
    /// rebootstrapping over SSH.
    pub(crate) fn import_handoff(
        state: RemoteQuicHandoffState,
        fds: Vec<OwnedFd>,
        config: &RemoteConfig,
        server_event_tx: mpsc::Sender<ServerEvent>,
    ) -> io::Result<Self> {
        if fds.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote QUIC handoff carried no sockets",
            ));
        }
        let identity = ServerIdentity {
            certificate_der: state.certificate_der,
            private_key_der: state.private_key_der,
            fingerprint: state.certificate_fingerprint,
        };
        let server_config =
            make_server_config(&identity, config.validated_transport_idle_timeout()).map_err(
                |err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to restore remote QUIC certificate: {err}"),
                    )
                },
            )?;
        let mut sockets = Vec::with_capacity(fds.len());
        for fd in fds {
            let socket = UdpSocket::from(fd);
            socket.set_nonblocking(true)?;
            sockets.push(socket);
        }
        let endpoints = make_endpoints(&server_config, &sockets)?;

        let now = unix_seconds();
        let mut inherited: Vec<HandoffToken> = state
            .tokens
            .into_iter()
            .filter(|token| token.expires_unix_seconds > now)
            .collect();
        // Newest capabilities win if the snapshot somehow carries more than
        // this process would ever mint.
        inherited.sort_unstable_by_key(|token| std::cmp::Reverse(token.issued_order));
        inherited.truncate(MAX_TOKENS);
        let token_order = inherited
            .iter()
            .map(|token| token.issued_order)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let tokens = inherited
            .into_iter()
            .map(|token| {
                (
                    token.token_hash,
                    Capability {
                        session: token.session,
                        logical_client_id: token.logical_client_id,
                        expires_unix_seconds: token.expires_unix_seconds,
                        connection_generation: token.connection_generation,
                        active_connection: None,
                        issued_order: token.issued_order,
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let server_state = Arc::new(ServerState {
            server_instance_id: state.server_instance_id,
            tokens: Mutex::new(tokens),
            token_order: AtomicU64::new(token_order),
            next_client_id: AtomicU64::new(1u64 << 63),
            server_event_tx,
        });
        for endpoint in &endpoints {
            tokio::spawn(accept_connections(
                endpoint.clone(),
                Arc::clone(&server_state),
            ));
        }
        info!(
            port = state.port,
            endpoints = endpoints.len(),
            capabilities = lock(&server_state.tokens).len(),
            "remote QUIC endpoint resumed from handoff"
        );
        Ok(Self {
            endpoints,
            sockets,
            state: server_state,
            port: state.port,
            identity,
            token_lifetime: token_lifetime(config),
            ssh_fallback_available: config.ssh_fallback,
            handed_off: AtomicBool::new(false),
        })
    }
}

impl Drop for RemoteQuicServer {
    fn drop(&mut self) {
        if self.handed_off.load(Ordering::Acquire) {
            // `close_for_handoff` already told clients to reconnect; a second
            // close would look like a permanent shutdown.
            return;
        }
        for endpoint in &self.endpoints {
            endpoint.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_SHUTDOWN),
                b"server shutdown",
            );
        }
    }
}

/// Everything a successor process needs to keep already-issued capabilities
/// valid across a live handoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RemoteQuicHandoffState {
    pub(crate) server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) private_key_der: Vec<u8>,
    pub(crate) certificate_fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    pub(crate) port: u16,
    /// Number of UDP socket descriptors that travel with this state.
    #[serde(default)]
    pub(crate) socket_fd_count: u8,
    pub(crate) tokens: Vec<HandoffToken>,
}

/// One capability, hashed rather than in the clear: the plaintext token never
/// leaves the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HandoffToken {
    pub(crate) token_hash: [u8; REMOTE_QUIC_HASH_BYTES],
    pub(crate) session: String,
    pub(crate) logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
    pub(crate) expires_unix_seconds: u64,
    pub(crate) connection_generation: u64,
    pub(crate) issued_order: u64,
}

fn token_lifetime(config: &RemoteConfig) -> Duration {
    Duration::from_secs(config.quic_idle_timeout_seconds)
        .clamp(TOKEN_MIN_LIFETIME, TOKEN_MAX_LIFETIME)
}

fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| "remote.quic_port_range must look like 48000-48100".to_owned())?;
    let start = start
        .trim()
        .parse::<u16>()
        .map_err(|_| "remote.quic_port_range has an invalid start port".to_owned())?;
    let end = end
        .trim()
        .parse::<u16>()
        .map_err(|_| "remote.quic_port_range has an invalid end port".to_owned())?;
    if start < 1024 || start > end {
        return Err("remote.quic_port_range must be an ascending unprivileged range".to_owned());
    }
    Ok((start, end))
}

/// The self-signed TLS material the client pins by fingerprint. Kept in DER
/// so a live handoff can rebuild the exact same identity in the successor.
#[derive(Clone)]
struct ServerIdentity {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
}

impl ServerIdentity {
    fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["herdr".to_owned()])?;
        let certificate_der = cert.der().to_vec();
        Ok(Self {
            fingerprint: hash_bytes(&certificate_der),
            certificate_der,
            private_key_der: signing_key.serialize_der(),
        })
    }
}

fn make_server_config(
    identity: &ServerIdentity,
    idle_timeout: Duration,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    let cert_der = rustls::pki_types::CertificateDer::from(identity.certificate_der.clone());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;
    tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.migration(true);
    server_config.transport_config(Arc::new(transport_config(idle_timeout)?));
    Ok(server_config)
}

fn transport_config(idle_timeout: Duration) -> Result<quinn::TransportConfig, io::Error> {
    let mut transport = quinn::TransportConfig::default();
    let idle = idle_timeout.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC idle timeout is too large",
        )
    })?;
    transport
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .max_concurrent_bidi_streams(VarInt::from_u32(2))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_RECEIVE_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        // See the matching note in src/remote/quic.rs: BBR paces to measured
        // bottleneck bandwidth, so random loss on a mobile path does not
        // collapse the send window the way loss-based Cubic does.
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Ok(transport)
}

/// Binds the first port in the range that IPv4 accepts. IPv6 is best effort
/// at that same port: refusing the port because its v6 half is taken would
/// leave the client with no endpoint at all, so the failure is logged and the
/// IPv4-only listener is kept.
fn bind_sockets(start_port: u16, end_port: u16) -> io::Result<(Vec<UdpSocket>, u16)> {
    let mut last_error = None;
    for port in start_port..=end_port {
        let ipv4_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let ipv4_socket = match bind_udp_socket(Domain::IPV4, ipv4_address) {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut sockets = vec![ipv4_socket];

        let ipv6_address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
        match bind_udp_socket(Domain::IPV6, ipv6_address) {
            Ok(socket) => sockets.push(socket),
            Err(error) => {
                debug!(%error, port, "IPv6 QUIC listener unavailable; using IPv4");
            }
        }
        return Ok((sockets, port));
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "empty port range")))
}

/// Hands quinn its own duplicate of each socket, so the originals stay
/// available for a later handoff.
fn make_endpoints(
    server_config: &quinn::ServerConfig,
    sockets: &[UdpSocket],
) -> io::Result<Vec<Endpoint>> {
    sockets
        .iter()
        .map(|socket| make_endpoint(server_config.clone(), socket.try_clone()?))
        .collect()
}

fn bind_udp_socket(domain: Domain, address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn make_endpoint(server_config: quinn::ServerConfig, socket: UdpSocket) -> io::Result<Endpoint> {
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Pre-auth admission cap: each accepted handshake spawns unauthenticated work
/// (TLS handshake, hello decode) and quinn's default allows up to 65,536
/// concurrent incoming, so without a bound an attacker can exhaust memory/CPU
/// before ever authenticating. Excess handshakes are refused outright.
const MAX_PREAUTH_CONNECTIONS: usize = 32;

async fn accept_connections(endpoint: Endpoint, state: Arc<ServerState>) {
    let admission = Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            debug!(remote = %incoming.remote_address(), "refusing QUIC connection: admission limit reached");
            incoming.refuse();
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = serve_connection(connection.clone(), state).await {
                        debug!(err = %err, remote = %connection.remote_address(), "remote QUIC connection ended");
                        connection.close(
                            VarInt::from_u32(REMOTE_QUIC_CLOSE_PROTOCOL),
                            err.to_string().as_bytes(),
                        );
                    }
                }
                Err(err) => debug!(err = %err, "remote QUIC handshake failed"),
            }
        });
    }
}

async fn serve_connection(connection: Connection, state: Arc<ServerState>) -> Result<(), String> {
    let (mut control_send, mut control_recv) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| "timed out waiting for QUIC control stream".to_owned())?
            .map_err(|err| format!("failed to accept QUIC control stream: {err}"))?;
    // Server->client half of the control stream: pongs, welcome, and detach
    // notices must outrank the render and resource streams for the same
    // reason the client prioritizes its half.
    // A closed stream surfaces on the next write; priority is an
    // optimization, so it does not warrant a separate error path.
    let _ = control_send.set_priority(PRIORITY_CONTROL);
    let hello: RemoteQuicHello = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        read_async_message(&mut control_recv, MAX_FRAME_SIZE),
    )
    .await
    .map_err(|_| "timed out waiting for QUIC hello".to_owned())??;

    let fence = validate_and_fence(&state, &connection, &hello)?;
    let keybindings = parse_client_keybindings(hello.keybindings.clone())?;
    if hello.launch_mode != ClientLaunchMode::App {
        return Err("remote QUIC currently accepts app clients only".to_owned());
    }
    let (cols, rows) = clamp_terminal_size(hello.cols, hello.rows);
    let client_id = state.next_client_id.fetch_add(1, Ordering::Relaxed);

    write_async_message(
        &mut control_send,
        &ServerMessage::Welcome {
            version: PROTOCOL_VERSION,
            encoding: RenderEncoding::TerminalAnsi,
            error: None,
        },
        MAX_FRAME_SIZE,
    )
    .await?;

    let cached_resources = hello
        .cached_resources
        .into_iter()
        .take(REMOTE_QUIC_MAX_RESOURCE_INVENTORY)
        .collect::<HashSet<_>>();
    let (control_writer, control_queue) = QuicControlSender::new();
    let heartbeat_writer = control_writer.clone();
    let (render_writer, render_rx, generation_rx) = QuicRenderSender::new();
    let render_sender_inner = Arc::clone(&render_writer.inner);
    let writer = ClientWriter::quic(control_writer, render_writer);

    state
        .server_event_tx
        .send(ServerEvent::ClientConnected {
            client_id,
            cols,
            rows,
            cell_width_px: hello.cell_width_px,
            cell_height_px: hello.cell_height_px,
            render_encoding: RenderEncoding::TerminalAnsi,
            keybindings,
            direct_attach_requested: false,
            direct_graphics: false,
            writer,
        })
        .await
        .map_err(|_| "server event loop stopped".to_owned())?;

    let control_publisher = tokio::spawn(publish_control_output(
        connection.clone(),
        control_send,
        Arc::clone(&control_queue),
    ));
    let render_publisher = tokio::spawn(publish_server_output(
        connection.clone(),
        render_rx,
        generation_rx,
        render_sender_inner,
        hello.connection_generation,
        cached_resources,
        client_id,
        state.server_event_tx.clone(),
    ));

    let read_result = receive_client_control(
        &mut control_recv,
        client_id,
        &state,
        fence,
        &heartbeat_writer,
    )
    .await;
    let _ = state
        .server_event_tx
        .send(ServerEvent::ClientDisconnected { client_id })
        .await;
    control_publisher.abort();
    render_publisher.abort();
    clear_active_connection(&state, fence);
    read_result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityValidationError {
    ProtocolMismatch { client: u32 },
    ServerInstanceChanged,
    UnknownOrRevoked,
    Expired,
    DifferentLogicalClient,
    DifferentSession,
    StaleGeneration,
}

impl std::fmt::Display for CapabilityValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolMismatch { client } => write!(
                formatter,
                "remote protocol mismatch: client {client}, server {PROTOCOL_VERSION}"
            ),
            Self::ServerInstanceChanged => {
                formatter.write_str("remote server instance changed; SSH rebootstrap required")
            }
            Self::UnknownOrRevoked => {
                formatter.write_str("remote capability is unknown or revoked")
            }
            Self::Expired => {
                formatter.write_str("remote capability expired; SSH rebootstrap required")
            }
            Self::DifferentLogicalClient => {
                formatter.write_str("remote capability belongs to a different logical client")
            }
            Self::DifferentSession => {
                formatter.write_str("remote capability belongs to a different session")
            }
            Self::StaleGeneration => formatter.write_str("stale remote connection generation"),
        }
    }
}

fn validate_capability(
    server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    tokens: &HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Capability>,
    hello: &RemoteQuicHello,
    active_session: &str,
    now: u64,
) -> Result<[u8; REMOTE_QUIC_HASH_BYTES], CapabilityValidationError> {
    if hello.version != PROTOCOL_VERSION {
        return Err(CapabilityValidationError::ProtocolMismatch {
            client: hello.version,
        });
    }
    if hello.server_instance_id != server_instance_id {
        return Err(CapabilityValidationError::ServerInstanceChanged);
    }
    let token_hash = hash_bytes(&hello.capability_token);
    let capability = tokens
        .get(&token_hash)
        .ok_or(CapabilityValidationError::UnknownOrRevoked)?;
    if capability.expires_unix_seconds <= now {
        return Err(CapabilityValidationError::Expired);
    }
    if capability.logical_client_id != hello.logical_client_id {
        return Err(CapabilityValidationError::DifferentLogicalClient);
    }
    if capability.session != active_session {
        return Err(CapabilityValidationError::DifferentSession);
    }
    if hello.connection_generation <= capability.connection_generation {
        return Err(CapabilityValidationError::StaleGeneration);
    }
    Ok(token_hash)
}

/// Identifies one accepted connection inside its capability, so late input
/// from a replaced connection can be told apart from the live one's.
#[derive(Clone, Copy)]
struct ConnectionFence {
    token_hash: [u8; REMOTE_QUIC_HASH_BYTES],
    connection_generation: u64,
}

fn validate_and_fence(
    state: &ServerState,
    connection: &Connection,
    hello: &RemoteQuicHello,
) -> Result<ConnectionFence, String> {
    let active_session = crate::session::active_name()
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    let mut tokens = lock(&state.tokens);
    let token_hash = match validate_capability(
        state.server_instance_id,
        &tokens,
        hello,
        &active_session,
        unix_seconds(),
    ) {
        Ok(token_hash) => token_hash,
        Err(error) => {
            match error {
                CapabilityValidationError::ProtocolMismatch { .. } => {
                    connection.close(
                        VarInt::from_u32(REMOTE_QUIC_CLOSE_PROTOCOL),
                        b"protocol mismatch",
                    );
                }
                CapabilityValidationError::StaleGeneration => {
                    connection.close(
                        VarInt::from_u32(REMOTE_QUIC_CLOSE_AUTH),
                        b"stale connection generation",
                    );
                }
                _ => {}
            }
            return Err(error.to_string());
        }
    };
    let Some(capability) = tokens.get_mut(&token_hash) else {
        return Err(CapabilityValidationError::UnknownOrRevoked.to_string());
    };
    if let Some(previous) = capability.active_connection.replace(connection.clone()) {
        previous.close(
            VarInt::from_u32(REMOTE_QUIC_CLOSE_REPLACED),
            b"newer connection generation accepted",
        );
    }
    capability.connection_generation = hello.connection_generation;
    Ok(ConnectionFence {
        token_hash,
        connection_generation: hello.connection_generation,
    })
}

fn clear_active_connection(state: &ServerState, fence: ConnectionFence) {
    if let Some(capability) = lock(&state.tokens).get_mut(&fence.token_hash) {
        if capability.connection_generation == fence.connection_generation {
            capability.active_connection = None;
        }
    }
}

/// Closing a replaced connection does not unread what it already delivered:
/// quinn hands the stream's queued bytes to the reader regardless, so input
/// typed before a roam could be replayed behind the resumed connection's
/// input. Every decoded frame is fenced against the capability's current
/// generation instead.
fn fence_is_current(state: &ServerState, fence: ConnectionFence) -> bool {
    lock(&state.tokens)
        .get(&fence.token_hash)
        .is_some_and(|capability| capability.connection_generation == fence.connection_generation)
}

async fn receive_client_control(
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    client_id: u64,
    state: &ServerState,
    fence: ConnectionFence,
    heartbeat_writer: &QuicControlSender,
) -> Result<(), String> {
    loop {
        let message: ClientMessage = read_async_message(recv, MAX_GRAPHICS_FRAME_SIZE).await?;
        if !fence_is_current(state, fence) {
            return Err("remote connection replaced by a newer generation".to_owned());
        }
        let message = match message {
            ClientMessage::RemotePing { nonce } => {
                let mut framed = Vec::new();
                protocol::write_message(&mut framed, &ServerMessage::RemotePong { nonce })
                    .map_err(|err| format!("failed to encode remote heartbeat: {err}"))?;
                heartbeat_writer
                    .send(framed)
                    .map_err(|_| "remote control writer closed".to_owned())?;
                continue;
            }

            ClientMessage::Hello { .. } | ClientMessage::RemoteBootstrap(_) => continue,
            message => message,
        };
        let Some(event) = client_message_to_event(client_id, message)
            .map_err(|reason| format!("invalid remote client message: {reason}"))?
        else {
            continue;
        };
        let detached = matches!(event, ServerEvent::ClientDetach { .. });
        state
            .server_event_tx
            .send(event)
            .await
            .map_err(|_| "server event loop stopped".to_owned())?;
        if detached {
            return Ok(());
        }
    }
}

#[derive(Clone)]
pub(crate) struct QuicControlSender {
    queue: Arc<BoundedControlQueue>,
}

impl std::fmt::Debug for QuicControlSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicControlSender").finish_non_exhaustive()
    }
}

impl QuicControlSender {
    pub(crate) fn new() -> (Self, Arc<BoundedControlQueue>) {
        let queue = Arc::new(BoundedControlQueue::default());
        (
            Self {
                queue: Arc::clone(&queue),
            },
            queue,
        )
    }

    pub(crate) fn send(&self, data: Vec<u8>) -> Result<(), std::sync::mpsc::SendError<Vec<u8>>> {
        self.queue
            .send(data)
            .map_err(|(_, data)| std::sync::mpsc::SendError(data))
    }
}

#[derive(Default)]
pub(crate) struct BoundedControlQueue {
    state: Mutex<ControlQueueState>,
    ready: Notify,
}

#[derive(Default)]
struct ControlQueueState {
    items: VecDeque<QueuedControl>,
    bytes: usize,
    closed: bool,
    overflowed: bool,
}

/// A queued control frame with the policy decided at enqueue time: coalescing
/// and overflow both scan the queue, and re-decoding every queued frame on
/// every send made that scan quadratic in bincode work.
struct QueuedControl {
    key: Option<u8>,
    drop_on_overflow: bool,
    data: Vec<u8>,
}

impl ControlQueueState {
    fn remove_at(&mut self, index: usize) {
        if let Some(removed) = self.items.remove(index) {
            self.bytes = self.bytes.saturating_sub(removed.data.len());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlSendError {
    /// The publisher is gone; the connection is already finished.
    Closed,
    /// The queue is full of frames that must not be dropped. The connection
    /// has to go: the client resyncs over a fresh one instead of silently
    /// missing a shutdown or replace frame.
    Overflow,
}

impl BoundedControlQueue {
    fn send(&self, data: Vec<u8>) -> Result<(), (ControlSendError, Vec<u8>)> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err((ControlSendError::Closed, data));
        }
        let (key, drop_on_overflow) = match protocol::read_message::<_, ServerMessage>(
            &mut data.as_slice(),
            MAX_GRAPHICS_FRAME_SIZE,
        ) {
            Ok(ServerMessage::WindowTitle { .. }) => (Some(1), false),
            Ok(ServerMessage::MouseCapture { .. }) => (Some(2), false),
            Ok(ServerMessage::PrefixInputSource { .. }) => (Some(3), false),
            Ok(ServerMessage::ReloadSoundConfig) => (Some(4), false),
            Ok(
                ServerMessage::Notify { .. }
                | ServerMessage::Clipboard { .. }
                | ServerMessage::OpenUrl { .. },
            ) => (None, true),
            _ => (None, false),
        };
        if data.len() > MAX_CONTROL_BYTES {
            return if drop_on_overflow {
                Ok(())
            } else {
                Err(Self::overflow(&mut state, data))
            };
        }
        if let Some(key) = key {
            if let Some(index) = state
                .items
                .iter()
                .position(|queued| queued.key == Some(key))
            {
                state.remove_at(index);
            }
        }
        while state.items.len() >= MAX_CONTROL_ITEMS
            || state.bytes.saturating_add(data.len()) > MAX_CONTROL_BYTES
        {
            if drop_on_overflow {
                return Ok(());
            }
            let Some(index) = state
                .items
                .iter()
                .position(|queued| queued.drop_on_overflow)
            else {
                return Err(Self::overflow(&mut state, data));
            };
            state.remove_at(index);
        }
        state.bytes = state.bytes.saturating_add(data.len());
        state.items.push_back(QueuedControl {
            key,
            drop_on_overflow,
            data,
        });
        drop(state);
        self.ready.notify_one();
        Ok(())
    }

    /// Marks the queue fatally full: already queued frames still drain, then
    /// the publisher tears the connection down.
    fn overflow(state: &mut ControlQueueState, data: Vec<u8>) -> (ControlSendError, Vec<u8>) {
        warn!(
            bytes = data.len(),
            queued = state.items.len(),
            "remote control queue overflowed with undroppable frames; closing connection"
        );
        state.overflowed = true;
        state.closed = true;
        (ControlSendError::Overflow, data)
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        loop {
            let notified = self.ready.notified();
            {
                let mut state = lock(&self.state);
                if let Some(queued) = state.items.pop_front() {
                    state.bytes = state.bytes.saturating_sub(queued.data.len());
                    return Some(queued.data);
                }
                if state.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    fn close(&self) {
        lock(&self.state).closed = true;
        self.ready.notify_waiters();
    }

    fn overflowed(&self) -> bool {
        lock(&self.state).overflowed
    }

    /// Queued item count and byte total, for tests asserting what a
    /// connection was (or was not) told.
    #[cfg(test)]
    pub(crate) fn bounds(&self) -> (usize, usize) {
        let state = lock(&self.state);
        (state.items.len(), state.bytes)
    }
}

#[derive(Clone)]
pub(crate) struct QuicRenderSender {
    inner: Arc<QuicRenderSenderInner>,
}

impl std::fmt::Debug for QuicRenderSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicRenderSender")
            .field("busy", &self.inner.busy.load(Ordering::Relaxed))
            .finish()
    }
}

struct QuicRenderSenderInner {
    tx: mpsc::UnboundedSender<TerminalFrame>,
    busy: AtomicBool,
    generation: AtomicU64,
    generation_tx: watch::Sender<u64>,
}

impl QuicRenderSender {
    pub(crate) fn new() -> (
        Self,
        mpsc::UnboundedReceiver<TerminalFrame>,
        watch::Receiver<u64>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (generation_tx, generation_rx) = watch::channel(1);
        (
            Self {
                inner: Arc::new(QuicRenderSenderInner {
                    tx,
                    busy: AtomicBool::new(false),
                    generation: AtomicU64::new(1),
                    generation_tx,
                }),
            },
            rx,
            generation_rx,
        )
    }

    pub(crate) fn try_send_frame(
        &self,
        frame: TerminalFrame,
    ) -> Result<(), std::sync::mpsc::TrySendError<TerminalFrame>> {
        if self
            .inner
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(std::sync::mpsc::TrySendError::Full(frame));
        }
        if let Err(err) = self.inner.tx.send(frame) {
            self.inner.busy.store(false, Ordering::Release);
            return Err(std::sync::mpsc::TrySendError::Disconnected(err.0));
        }
        Ok(())
    }

    pub(crate) fn try_send(
        &self,
        data: Vec<u8>,
    ) -> Result<(), std::sync::mpsc::TrySendError<Vec<u8>>> {
        let mut input = data.as_slice();
        if let Ok(ServerMessage::Terminal(frame)) =
            protocol::read_message::<_, ServerMessage>(&mut input, MAX_GRAPHICS_FRAME_SIZE)
        {
            return self.try_send_frame(frame).map_err(|e| match e {
                std::sync::mpsc::TrySendError::Full(_) => std::sync::mpsc::TrySendError::Full(data),
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    std::sync::mpsc::TrySendError::Disconnected(data)
                }
            });
        }
        if self.inner.tx.is_closed() {
            Err(std::sync::mpsc::TrySendError::Disconnected(data))
        } else {
            Ok(())
        }
    }

    pub(crate) fn reset_generation(&self) {
        let generation = self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.inner.generation_tx.send_replace(generation);
    }
}

async fn publish_control_output(
    connection: Connection,
    mut stream: SendStream,
    queue: Arc<BoundedControlQueue>,
) {
    while let Some(control) = queue.recv().await {
        if stream.write_all(&control).await.is_err() {
            break;
        }
    }
    if queue.overflowed() {
        connection.close(
            VarInt::from_u32(REMOTE_QUIC_CLOSE_RESYNC),
            b"control queue overflow",
        );
    }
    queue.close();
}

async fn publish_server_output(
    connection: Connection,
    mut render_rx: mpsc::UnboundedReceiver<TerminalFrame>,
    mut generation_rx: watch::Receiver<u64>,
    render_sender: Arc<QuicRenderSenderInner>,
    connection_generation: u64,
    cached_resources: HashSet<[u8; REMOTE_QUIC_HASH_BYTES]>,
    client_id: u64,
    server_event_tx: mpsc::Sender<ServerEvent>,
) {
    let resource_limit = Arc::new(Semaphore::new(RESOURCE_BUDGET_KIB));
    let sent_resources = Arc::new(Mutex::new(cached_resources));
    let state_revision = AtomicU64::new(0);
    let mut render_stream: Option<SendStream> = None;
    let mut active_generation = *generation_rx.borrow_and_update();

    loop {
        tokio::select! {
            biased;
            changed = generation_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                active_generation = *generation_rx.borrow_and_update();
                if let Some(mut stream) = render_stream.take() {
                    let _ = stream.reset(VarInt::from_u32(REMOTE_QUIC_CLOSE_REPLACED));
                }
            }
            render = render_rx.recv() => {
                let Some(render) = render else { break; };
                let result = publish_render(
                    &connection,
                    &mut render_stream,
                    &mut generation_rx,
                    connection_generation,
                    active_generation,
                    state_revision.fetch_add(1, Ordering::Relaxed) + 1,
                    render,
                    Arc::clone(&resource_limit),
                    Arc::clone(&sent_resources),
                ).await;
                if result == PublishRenderResult::GenerationChanged {
                    active_generation = *generation_rx.borrow_and_update();
                    if let Some(mut stream) = render_stream.take() {
                        let _ = stream.reset(VarInt::from_u32(REMOTE_QUIC_CLOSE_REPLACED));
                    }
                }
                render_sender.busy.store(false, Ordering::Release);
                let _ = server_event_tx.send(ServerEvent::ClientWriterDrained { client_id }).await;
                if result == PublishRenderResult::Closed {
                    // The publisher is the only thing that repaints this
                    // client, so exiting on a write failure while the
                    // connection is still up leaves a healthy session that
                    // never updates again. Closing makes the client re-dial
                    // with the capability it holds; an already-closed
                    // connection ignores it.
                    connection.close(
                        VarInt::from_u32(REMOTE_QUIC_CLOSE_RESYNC),
                        b"render write failed",
                    );
                    break;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishRenderResult {
    Sent,
    GenerationChanged,
    Closed,
}

async fn publish_render(
    connection: &Connection,
    render_stream: &mut Option<SendStream>,
    generation_rx: &mut watch::Receiver<u64>,
    connection_generation: u64,
    render_generation: u64,
    state_revision: u64,
    mut frame: TerminalFrame,
    resource_limit: Arc<Semaphore>,
    sent_resources: Arc<Mutex<HashSet<[u8; REMOTE_QUIC_HASH_BYTES]>>>,
) -> PublishRenderResult {
    let original = std::mem::take(&mut frame.bytes);
    let (text, graphics) = split_kitty_sequences(&original);
    let can_externalize = graphics.len() <= MAX_RESOURCE_REFS_PER_FRAME
        && graphics
            .iter()
            .all(|segment| segment.bytes.len() <= REMOTE_QUIC_MAX_RESOURCE_SIZE);
    let admission = if can_externalize {
        admit_resources(graphics, &resource_limit, &sent_resources)
    } else {
        None
    };
    // The queued message was admitted at `MAX_GRAPHICS_FRAME_SIZE`, and the
    // record wraps it in a generation/revision/resource envelope, so a frame
    // that already sits near that limit no longer fits once wrapped. Writing
    // it anyway fails, ends this publisher, and strands the client on a
    // healthy connection that never repaints again, so an oversize record is
    // degraded to text instead: this frame loses its graphics, and a later
    // one carries them as resources.
    let (bytes, resources) = match admission {
        Some(admission) => {
            for transfer in admission.transfers {
                spawn_resource_transfer(
                    connection.clone(),
                    connection_generation,
                    render_generation,
                    transfer,
                );
            }
            // A resource ref costs more bytes than the shortest escape it
            // replaces, so a frame packed with tiny graphics can grow. The
            // bytes are already admitted and marked sent, so only this
            // record's refs are dropped.
            if projected_record_size(text.len(), admission.refs.len()) <= MAX_GRAPHICS_FRAME_SIZE {
                (text, admission.refs)
            } else {
                warn!(
                    text_bytes = text.len(),
                    resources = admission.refs.len(),
                    "QUIC render record with resource refs exceeds the frame limit; dropping this frame's graphics"
                );
                (text, Vec::new())
            }
        }
        // The transfer budget is committed to earlier frames, so nothing was
        // cloned: ship the graphics inline and let a later render externalize
        // them once those transfers drain.
        None if projected_record_size(original.len(), 0) <= MAX_GRAPHICS_FRAME_SIZE => {
            (original, Vec::new())
        }
        None => {
            warn!(
                inline_bytes = original.len(),
                "inline QUIC graphics do not fit the render record; sending this frame text only"
            );
            (text, Vec::new())
        }
    };
    frame.bytes = bytes;

    if render_stream.is_none() {
        let Ok(mut stream) = connection.open_uni().await else {
            return PublishRenderResult::Closed;
        };
        let _ = stream.set_priority(PRIORITY_RENDER);
        let header = RemoteQuicStreamHeader::Render {
            connection_generation,
            render_generation,
        };
        if write_async_message(&mut stream, &header, MAX_FRAME_SIZE)
            .await
            .is_err()
        {
            return PublishRenderResult::Closed;
        }
        *render_stream = Some(stream);
    }

    let record = RemoteQuicRenderRecord {
        connection_generation,
        render_generation,
        state_revision,
        frame,
        resources,
    };
    let Some(stream) = render_stream.as_mut() else {
        return PublishRenderResult::Closed;
    };
    tokio::select! {
        result = write_async_message(stream, &record, MAX_GRAPHICS_FRAME_SIZE) => {
            if result.is_ok() { PublishRenderResult::Sent } else { PublishRenderResult::Closed }
        }
        changed = generation_rx.changed() => {
            if changed.is_ok() { PublishRenderResult::GenerationChanged } else { PublishRenderResult::Closed }
        }
    }
}

/// Upper bound on the bincode bytes a [`RemoteQuicRenderRecord`] spends
/// outside the frame payload: three varint generation/revision fences, the
/// frame's own scalar fields and byte-length prefix, and the resource
/// vector's length prefix.
const RENDER_RECORD_ENVELOPE_BYTES: usize = 64;
/// Upper bound on the bincode bytes one [`RemoteQuicResourceRef`] costs: a
/// fixed-size hash plus a varint text offset.
const RENDER_RECORD_RESOURCE_REF_BYTES: usize = REMOTE_QUIC_HASH_BYTES + 5;

/// Conservative encoded size of the record that would carry `payload` frame
/// bytes and `resources` resource references.
///
/// Sizing the record before it is built is what keeps a frame admitted at
/// `MAX_GRAPHICS_FRAME_SIZE` from exceeding that same limit once the record
/// envelope is added: `write_async_message` would reject it, and a rejected
/// render write closes the connection instead of repainting the client.
fn projected_record_size(payload: usize, resources: usize) -> usize {
    payload
        .saturating_add(RENDER_RECORD_ENVELOPE_BYTES)
        .saturating_add(resources.saturating_mul(RENDER_RECORD_RESOURCE_REF_BYTES))
}

/// One admitted graphics resource: its bytes plus the budget permit that
/// covers them. Dropping the pair releases the budget, so the permit and the
/// allocation it accounts for always live and die together.
struct ResourceTransfer {
    hash: [u8; REMOTE_QUIC_HASH_BYTES],
    bytes: Vec<u8>,
    permit: OwnedSemaphorePermit,
}

struct ResourceAdmission {
    refs: Vec<RemoteQuicResourceRef>,
    transfers: Vec<ResourceTransfer>,
}

/// Permit weight for one resource, in KiB rounded up so that even a tiny
/// resource costs budget.
fn resource_weight(len: usize) -> u32 {
    u32::try_from(len.div_ceil(1024).max(1)).unwrap_or(u32::MAX)
}

/// Reserves transfer budget for every not-yet-sent resource in one frame
/// *before* its bytes are cloned out of the frame, which is what bounds the
/// resource memory a burst of graphics can pin.
///
/// All-or-nothing on purpose: a client cannot apply a render record that
/// references a resource it never receives, so a frame that does not fit is
/// reported as unadmitted and sent inline instead.
fn admit_resources(
    graphics: Vec<GraphicsSegment>,
    limit: &Arc<Semaphore>,
    sent_resources: &Mutex<HashSet<[u8; REMOTE_QUIC_HASH_BYTES]>>,
) -> Option<ResourceAdmission> {
    let mut refs = Vec::with_capacity(graphics.len());
    let mut transfers: Vec<ResourceTransfer> = Vec::new();
    let mut known = lock(sent_resources);
    for segment in graphics {
        let hash = hash_bytes(&segment.bytes);
        refs.push(RemoteQuicResourceRef {
            hash,
            text_offset: segment.text_offset,
        });
        if known.contains(&hash) || transfers.iter().any(|transfer| transfer.hash == hash) {
            continue;
        }
        let permit = Arc::clone(limit)
            .try_acquire_many_owned(resource_weight(segment.bytes.len()))
            .ok()?;
        transfers.push(ResourceTransfer {
            hash,
            bytes: segment.bytes,
            permit,
        });
    }
    known.extend(transfers.iter().map(|transfer| transfer.hash));
    Some(ResourceAdmission { refs, transfers })
}

fn spawn_resource_transfer(
    connection: Connection,
    connection_generation: u64,
    render_generation: u64,
    transfer: ResourceTransfer,
) {
    tokio::spawn(async move {
        let ResourceTransfer {
            hash,
            bytes,
            permit,
        } = transfer;
        // Held for the whole transfer: the budget only frees once these bytes
        // are on the wire and dropped.
        let _permit = permit;
        let Ok(mut stream) = connection.open_uni().await else {
            return;
        };
        // Above the render stream: a render record referencing this hash is
        // unapplicable until these bytes land, and the client's pending-render
        // queue is bounded, so starving this transfer forces a reconnect.
        let _ = stream.set_priority(PRIORITY_RESOURCE);
        let Ok(length) = u32::try_from(bytes.len()) else {
            return;
        };
        let header = RemoteQuicStreamHeader::Resource {
            connection_generation,
            render_generation,
            hash,
            length,
        };
        if write_async_message(&mut stream, &header, MAX_FRAME_SIZE)
            .await
            .is_err()
        {
            return;
        }
        if stream.write_all(&bytes).await.is_ok() {
            let _ = stream.finish();
        }
    });
}

struct GraphicsSegment {
    text_offset: u32,
    bytes: Vec<u8>,
}

fn split_kitty_sequences(bytes: &[u8]) -> (Vec<u8>, Vec<GraphicsSegment>) {
    const START: &[u8] = b"\x1b_G";
    const END: &[u8] = b"\x1b\\";
    let mut text = Vec::with_capacity(bytes.len());
    let mut graphics = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = memchr::memmem::find(&bytes[cursor..], START) {
        let start = cursor + relative_start;
        text.extend_from_slice(&bytes[cursor..start]);
        let payload_start = start + START.len();
        let Some(relative_end) = memchr::memmem::find(&bytes[payload_start..], END) else {
            text.extend_from_slice(&bytes[start..]);
            return (text, graphics);
        };
        let end = payload_start + relative_end + END.len();
        let Ok(text_offset) = u32::try_from(text.len()) else {
            return (bytes.to_vec(), Vec::new());
        };
        graphics.push(GraphicsSegment {
            text_offset,
            bytes: bytes[start..end].to_vec(),
        });
        cursor = end;
    }
    text.extend_from_slice(&bytes[cursor..]);
    (text, graphics)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `pub(crate)` because the handoff rollback path lives in
/// `crate::server::headless` and needs the same live client fixture: one real
/// QUIC connection is the only way to observe a close.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::remote::quic_policy::{MAX_RECORD_OVERHEAD, STRUCTURAL_RECORD_HEADER_BOUND};

    #[test]
    fn port_range_requires_ascending_unprivileged_ports() {
        assert_eq!(parse_port_range("48000-48100"), Ok((48000, 48100)));
        assert!(parse_port_range("80-81").is_err());
        assert!(parse_port_range("48100-48000").is_err());
        assert!(parse_port_range("invalid").is_err());
    }

    #[test]
    fn test_quic_record_structural_overhead_bound() {
        let frame = TerminalFrame {
            seq: u64::MAX,
            width: u16::MAX,
            height: u16::MAX,
            full: true,
            bytes: vec![0; 64],
        };
        let mut rec = RemoteQuicRenderRecord {
            connection_generation: u64::MAX,
            render_generation: u64::MAX,
            state_revision: u64::MAX,
            frame,
            resources: Vec::new(),
        };
        let text_overhead = bincode::serde::encode_to_vec(&rec, bincode::config::standard())
            .unwrap()
            .len()
            - 64;
        assert!(text_overhead <= STRUCTURAL_RECORD_HEADER_BOUND);
        rec.resources = vec![
            RemoteQuicResourceRef {
                hash: [0xFF; REMOTE_QUIC_HASH_BYTES],
                text_offset: u32::MAX,
            };
            MAX_RESOURCE_REFS_PER_FRAME
        ];
        let gfx_overhead = bincode::serde::encode_to_vec(&rec, bincode::config::standard())
            .unwrap()
            .len()
            - 64;
        assert!(gfx_overhead <= MAX_RECORD_OVERHEAD);
    }

    fn capability_fixture() -> (
        [u8; REMOTE_QUIC_ID_BYTES],
        HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Capability>,
        RemoteQuicHello,
    ) {
        let server_instance_id = [2; REMOTE_QUIC_ID_BYTES];
        let capability_token = [3; REMOTE_QUIC_TOKEN_BYTES];
        let logical_client_id = [4; REMOTE_QUIC_ID_BYTES];
        let mut tokens = HashMap::new();
        tokens.insert(
            hash_bytes(&capability_token),
            Capability {
                session: "session-a".to_owned(),
                logical_client_id,
                expires_unix_seconds: 2_000,
                connection_generation: 0,
                active_connection: None,
                issued_order: 1,
            },
        );
        let hello = RemoteQuicHello {
            version: PROTOCOL_VERSION,
            server_instance_id,
            logical_client_id,
            capability_token,
            connection_generation: 1,
            cols: 80,
            rows: 24,
            cell_width_px: 8,
            cell_height_px: 16,
            keybindings: crate::protocol::ClientKeybindings::Server,
            launch_mode: ClientLaunchMode::App,
            cached_resources: Vec::new(),
        };
        (server_instance_id, tokens, hello)
    }

    #[test]
    fn capability_validation_rejects_protocol_identity_and_revocation_failures() {
        let (server_instance_id, tokens, hello) = capability_fixture();
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, "session-a", 1_000),
            Ok(hash_bytes(&hello.capability_token))
        );

        let mut wrong_protocol = hello.clone();
        wrong_protocol.version = PROTOCOL_VERSION.saturating_sub(1);
        assert_eq!(
            validate_capability(
                server_instance_id,
                &tokens,
                &wrong_protocol,
                "session-a",
                1_000,
            ),
            Err(CapabilityValidationError::ProtocolMismatch {
                client: PROTOCOL_VERSION.saturating_sub(1),
            })
        );

        assert_eq!(
            validate_capability(
                [9; REMOTE_QUIC_ID_BYTES],
                &tokens,
                &hello,
                "session-a",
                1_000
            ),
            Err(CapabilityValidationError::ServerInstanceChanged)
        );
        assert_eq!(
            validate_capability(
                server_instance_id,
                &HashMap::new(),
                &hello,
                "session-a",
                1_000,
            ),
            Err(CapabilityValidationError::UnknownOrRevoked)
        );
    }

    #[test]
    fn capability_validation_rejects_expiry_cross_scope_and_stale_generation() {
        let (server_instance_id, mut tokens, hello) = capability_fixture();
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, "session-a", 2_000),
            Err(CapabilityValidationError::Expired)
        );

        let mut wrong_client = hello.clone();
        wrong_client.logical_client_id = [9; REMOTE_QUIC_ID_BYTES];
        assert_eq!(
            validate_capability(
                server_instance_id,
                &tokens,
                &wrong_client,
                "session-a",
                1_000,
            ),
            Err(CapabilityValidationError::DifferentLogicalClient)
        );
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, "session-b", 1_000),
            Err(CapabilityValidationError::DifferentSession)
        );

        tokens
            .get_mut(&hash_bytes(&hello.capability_token))
            .expect("fixture capability")
            .connection_generation = hello.connection_generation;
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, "session-a", 1_000),
            Err(CapabilityValidationError::StaleGeneration)
        );
    }

    #[tokio::test]
    async fn bootstrap_tokens_have_bounded_inventory_lifetime_and_session_scope() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            quic_idle_timeout_seconds: 1,
            ..Default::default()
        };
        let (server_event_tx, _server_event_rx) = mpsc::channel(1);
        let server = RemoteQuicServer::start(&config, server_event_tx).expect("start QUIC server");
        let session = crate::session::active_name()
            .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
        assert!(server
            .bootstrap(RemoteBootstrapRequest {
                session: format!("{session}-wrong"),
                logical_client_id: [0; REMOTE_QUIC_ID_BYTES],
            })
            .is_err());

        let issued_at = unix_seconds();
        let first = server
            .bootstrap(RemoteBootstrapRequest {
                session: session.clone(),
                logical_client_id: [0; REMOTE_QUIC_ID_BYTES],
            })
            .expect("issue first capability");
        assert!(first.expires_unix_seconds >= issued_at + TOKEN_MIN_LIFETIME.as_secs());
        assert!(first.expires_unix_seconds <= issued_at + TOKEN_MIN_LIFETIME.as_secs() + 1);
        for index in 1..=MAX_TOKENS {
            server
                .bootstrap(RemoteBootstrapRequest {
                    session: session.clone(),
                    logical_client_id: [index as u8; REMOTE_QUIC_ID_BYTES],
                })
                .expect("issue bounded capability");
        }
        assert_eq!(lock(&server.state.tokens).len(), MAX_TOKENS);
    }

    #[test]
    fn kitty_sequences_are_split_without_touching_text() {
        let input = b"before\x1b_Gf=100,i=3;AAAA\x1b\\after\x1b_Ga=p,i=3\x1b\\";
        let (text, graphics) = split_kitty_sequences(input);
        assert_eq!(text, b"beforeafter");
        assert_eq!(graphics.len(), 2);
        assert_eq!(graphics[0].text_offset, 6);
        assert_eq!(graphics[0].bytes, b"\x1b_Gf=100,i=3;AAAA\x1b\\");
        assert_eq!(graphics[1].text_offset, 11);
        assert_eq!(graphics[1].bytes, b"\x1b_Ga=p,i=3\x1b\\");
    }

    #[tokio::test]
    async fn control_queue_is_bounded_and_coalesces_current_state() {
        let queue = BoundedControlQueue::default();
        for index in 0..200 {
            let mut data = Vec::new();
            protocol::write_message(
                &mut data,
                &ServerMessage::WindowTitle {
                    title: Some(format!("title-{index}")),
                },
            )
            .expect("serialize title");
            queue.send(data).expect("queue open");
        }
        let (items, bytes) = queue.bounds();
        assert_eq!(items, 1);
        assert!(bytes <= MAX_CONTROL_BYTES);
    }

    fn framed_shutdown(reason: &str) -> Vec<u8> {
        let mut data = Vec::new();
        protocol::write_message(
            &mut data,
            &ServerMessage::ServerShutdown {
                reason: Some(reason.to_owned()),
            },
        )
        .expect("serialize critical control");
        data
    }

    #[tokio::test]
    async fn reliable_control_overflow_closes_instead_of_dropping_messages() {
        let (sender, queue) = QuicControlSender::new();
        for index in 0..MAX_CONTROL_ITEMS {
            sender
                .send(framed_shutdown(&format!("critical-{index}")))
                .expect("reliable queue capacity");
        }
        // The caller must learn that an undroppable frame did not make it, and
        // the queue must mark itself fatal so the publisher closes the
        // connection rather than leaving the client silently out of sync.
        assert!(sender.send(framed_shutdown("must not disappear")).is_err());
        assert!(queue.overflowed());
        assert_eq!(queue.bounds().0, MAX_CONTROL_ITEMS);

        for index in 0..MAX_CONTROL_ITEMS {
            assert_eq!(
                queue.recv().await,
                Some(framed_shutdown(&format!("critical-{index}"))),
                "queued frames still drain before the close"
            );
        }
        assert_eq!(queue.recv().await, None);
    }

    #[test]
    fn resource_and_certificate_hashes_are_content_addressed() {
        assert_eq!(hash_bytes(b"same"), hash_bytes(b"same"));
        assert_ne!(hash_bytes(b"same"), hash_bytes(b"different"));
    }

    #[test]
    fn admission_semaphore_refuses_beyond_cap_and_recovers() {
        let admission = Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS));
        let permits: Vec<_> = (0..MAX_PREAUTH_CONNECTIONS)
            .map(|_| {
                Arc::clone(&admission)
                    .try_acquire_owned()
                    .expect("permit within cap")
            })
            .collect();
        assert!(Arc::clone(&admission).try_acquire_owned().is_err());
        drop(permits);
        assert!(Arc::clone(&admission).try_acquire_owned().is_ok());
    }

    #[test]
    fn transport_idle_timeout_is_separate_from_token_lifetime() {
        let config = crate::config::RemoteConfig::default();
        assert_eq!(token_lifetime(&config), Duration::from_secs(86_400));
        assert_eq!(
            config.validated_transport_idle_timeout(),
            Duration::from_secs(45)
        );

        let transport =
            transport_config(config.validated_transport_idle_timeout()).expect("transport config");
        let rendered = format!("{transport:?}");
        assert!(
            rendered.contains(&format!(
                "max_idle_timeout: {:?}",
                Some(VarInt::from_u32(45_000))
            )),
            "transport must idle out on the transport timeout, not the token lifetime: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "keep_alive_interval: {:?}",
                Some(KEEP_ALIVE_INTERVAL)
            )),
            "{rendered}"
        );
    }

    fn graphics_segments(count: usize, len: usize, fill: u8) -> Vec<GraphicsSegment> {
        (0..count)
            .map(|index| GraphicsSegment {
                text_offset: index as u32,
                // Distinct content per segment, so each hashes differently.
                bytes: vec![fill.wrapping_add(index as u8); len],
            })
            .collect()
    }

    #[test]
    fn resource_weight_charges_at_least_one_kib() {
        assert_eq!(resource_weight(0), 1);
        assert_eq!(resource_weight(1), 1);
        assert_eq!(resource_weight(1024), 1);
        assert_eq!(resource_weight(1025), 2);
        assert_eq!(
            RESOURCE_BUDGET_KIB,
            MAX_RESOURCE_TRANSFERS * REMOTE_QUIC_MAX_RESOURCE_SIZE / 1024
        );
    }

    #[tokio::test]
    async fn resource_admission_never_buffers_beyond_the_budget() {
        const MIB: usize = 1024 * 1024;
        let budget = 4 * 1024;
        let limit = Arc::new(Semaphore::new(budget));
        let sent = Mutex::new(HashSet::new());

        // Eight 1 MiB refs against a 4 MiB budget: the frame is refused
        // outright, so none of those bytes are cloned or pinned.
        assert!(admit_resources(graphics_segments(8, MIB, 0), &limit, &sent).is_none());
        assert_eq!(limit.available_permits(), budget);
        assert!(lock(&sent).is_empty());

        let admission = admit_resources(graphics_segments(4, MIB, 0), &limit, &sent)
            .expect("a frame inside the budget is admitted");
        assert_eq!(admission.refs.len(), 4);
        assert_eq!(admission.transfers.len(), 4);
        assert_eq!(limit.available_permits(), 0);
        assert_eq!(lock(&sent).len(), 4);

        // Nothing else fits while those transfers hold their bytes.
        assert!(admit_resources(graphics_segments(1, MIB, 200), &limit, &sent).is_none());

        // Already-sent resources are referenced without re-buffering.
        drop(admission);
        assert_eq!(limit.available_permits(), budget);
        let cached = admit_resources(graphics_segments(4, MIB, 0), &limit, &sent)
            .expect("cached resources need no budget");
        assert_eq!(cached.refs.len(), 4);
        assert!(cached.transfers.is_empty());
        assert_eq!(limit.available_permits(), budget);
    }

    fn fenced_state(
        connection_generation: u64,
        server_event_tx: mpsc::Sender<ServerEvent>,
    ) -> (ServerState, ConnectionFence) {
        let token_hash = hash_bytes(&[3; REMOTE_QUIC_TOKEN_BYTES]);
        let mut tokens = HashMap::new();
        tokens.insert(
            token_hash,
            Capability {
                session: "session-a".to_owned(),
                logical_client_id: [4; REMOTE_QUIC_ID_BYTES],
                expires_unix_seconds: unix_seconds() + 600,
                connection_generation,
                active_connection: None,
                issued_order: 1,
            },
        );
        (
            ServerState {
                server_instance_id: [2; REMOTE_QUIC_ID_BYTES],
                tokens: Mutex::new(tokens),
                token_order: AtomicU64::new(2),
                next_client_id: AtomicU64::new(1),
                server_event_tx,
            },
            ConnectionFence {
                token_hash,
                connection_generation: 1,
            },
        )
    }

    async fn framed_input(data: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        write_async_message(
            &mut buffer,
            &ClientMessage::Input {
                data: data.to_vec(),
            },
            MAX_FRAME_SIZE,
        )
        .await
        .expect("frame input");
        buffer
    }

    #[tokio::test]
    async fn live_connection_input_is_forwarded() {
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let (state, fence) = fenced_state(1, server_event_tx);
        let (writer, _queue) = QuicControlSender::new();
        let input = framed_input(b"live").await;

        let result = receive_client_control(&mut input.as_slice(), 7, &state, fence, &writer).await;
        assert!(result.is_err(), "the stream ends after the last frame");
        assert!(matches!(
            server_event_rx.try_recv(),
            Ok(ServerEvent::ClientInput { client_id: 7, .. })
        ));
    }

    #[tokio::test]
    async fn replaced_connection_input_is_never_forwarded() {
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        // A second connection for the same capability was accepted while this
        // one still had input queued: the capability now sits at generation 2.
        let (state, fence) = fenced_state(2, server_event_tx);
        let (writer, _queue) = QuicControlSender::new();
        let mut queued = framed_input(b"stale").await;
        queued.extend(framed_input(b"stale-too").await);

        let error = receive_client_control(&mut queued.as_slice(), 7, &state, fence, &writer)
            .await
            .expect_err("a replaced connection must stop reading");
        assert!(error.contains("replaced by a newer generation"), "{error}");
        assert!(server_event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handoff_export_and_import_keep_capabilities_valid() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let session = crate::session::active_name()
            .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
        let (server_event_tx, _server_event_rx) = mpsc::channel(1);
        let server = RemoteQuicServer::start(&config, server_event_tx).expect("start QUIC server");
        let record = server
            .bootstrap(RemoteBootstrapRequest {
                session: session.clone(),
                logical_client_id: [7; REMOTE_QUIC_ID_BYTES],
            })
            .expect("mint capability");

        let (state, fds) = server.export_handoff().expect("export handoff");
        assert_eq!(usize::from(state.socket_fd_count), fds.len());
        assert_eq!(state.socket_fd_count as usize, server.endpoints.len());
        assert_eq!(state.port, port);
        assert_eq!(
            state.certificate_fingerprint,
            record.certificate_fingerprint
        );
        assert_eq!(state.server_instance_id, record.server_instance_id);
        assert_eq!(state.tokens.len(), 1);

        server.close_for_handoff();
        drop(server);

        let (resumed_event_tx, _resumed_event_rx) = mpsc::channel(1);
        let resumed = RemoteQuicServer::import_handoff(state, fds, &config, resumed_event_tx)
            .expect("import handoff");
        // Same listening socket, same identity: the client's pinned
        // fingerprint and its capability both still apply.
        assert_eq!(resumed.port, port);
        assert_eq!(
            resumed
                .sockets
                .first()
                .expect("inherited socket")
                .local_addr()
                .expect("inherited address")
                .port(),
            port
        );
        assert_eq!(resumed.identity.fingerprint, record.certificate_fingerprint);

        let mut hello = capability_fixture().2;
        hello.server_instance_id = record.server_instance_id;
        hello.logical_client_id = [7; REMOTE_QUIC_ID_BYTES];
        hello.capability_token = record.capability_token;
        hello.connection_generation = 1;
        let tokens = lock(&resumed.state.tokens);
        assert_eq!(
            validate_capability(
                resumed.state.server_instance_id,
                &tokens,
                &hello,
                &session,
                unix_seconds(),
            ),
            Ok(hash_bytes(&record.capability_token))
        );
        drop(tokens);

        // Freshly minted capabilities order after the inherited ones.
        let next = resumed
            .bootstrap(RemoteBootstrapRequest {
                session,
                logical_client_id: [8; REMOTE_QUIC_ID_BYTES],
            })
            .expect("mint after handoff");
        assert_eq!(next.server_instance_id, record.server_instance_id);
        assert_eq!(next.certificate_fingerprint, record.certificate_fingerprint);
        assert_eq!(lock(&resumed.state.tokens).len(), 2);
    }

    /// Test-only stand-in for the client's own fingerprint verifier: these
    /// tests dial the real endpoint, so they need the real self-signed
    /// certificate to validate.
    #[derive(Debug)]
    struct PinnedTestCert {
        fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedTestCert {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if hash_bytes(end_entity.as_ref()) == self.fingerprint {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General("fingerprint mismatch".to_owned()))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// One real client, connected and past the hello handshake, plus the
    /// server side of the same connection as the token table sees it.
    pub(crate) struct LiveTestClient {
        _endpoint: Endpoint,
        pub(crate) connection: Connection,
        _control_send: SendStream,
        _control_recv: quinn::RecvStream,
        server_side: Connection,
        record: RemoteBootstrapRecord,
    }

    pub(crate) fn test_server_on_free_port(
    ) -> (RemoteQuicServer, mpsc::Receiver<ServerEvent>, String) {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (server_event_tx, server_event_rx) = mpsc::channel(8);
        let server = RemoteQuicServer::start(&config, server_event_tx).expect("start QUIC server");
        let session = crate::session::active_name()
            .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
        (server, server_event_rx, session)
    }

    pub(crate) async fn connect_live_test_client(
        server: &RemoteQuicServer,
        session: &str,
        logical_client_id: u8,
    ) -> LiveTestClient {
        let record = server
            .bootstrap(RemoteBootstrapRequest {
                session: session.to_owned(),
                logical_client_id: [logical_client_id; REMOTE_QUIC_ID_BYTES],
            })
            .expect("mint capability");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("enable TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTestCert {
                fingerprint: record.certificate_fingerprint,
                provider,
            }))
            .with_no_client_auth();
        tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client crypto");
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(VarInt::from_u32(8));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind test client endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(
                SocketAddr::from((Ipv4Addr::LOCALHOST, record.port)),
                "herdr",
            )
            .expect("start QUIC connect")
            .await
            .expect("QUIC handshake");

        let (mut control_send, mut control_recv) =
            connection.open_bi().await.expect("open control stream");
        let mut hello = capability_fixture().2;
        hello.server_instance_id = record.server_instance_id;
        hello.logical_client_id = [logical_client_id; REMOTE_QUIC_ID_BYTES];
        hello.capability_token = record.capability_token;
        hello.connection_generation = 1;
        write_async_message(&mut control_send, &hello, MAX_FRAME_SIZE)
            .await
            .expect("send hello");
        assert!(matches!(
            read_async_message::<ServerMessage>(&mut control_recv, MAX_FRAME_SIZE)
                .await
                .expect("read welcome"),
            ServerMessage::Welcome { error: None, .. }
        ));

        // The welcome is written after `validate_and_fence`, so the capability
        // now holds this connection.
        let server_side = lock(&server.state.tokens)
            .get(&hash_bytes(&record.capability_token))
            .and_then(|capability| capability.active_connection.clone())
            .expect("server side of the live connection");
        LiveTestClient {
            _endpoint: endpoint,
            connection,
            _control_send: control_send,
            _control_recv: control_recv,
            server_side,
            record,
        }
    }

    /// A handoff that fails before the commit restores this server, but its
    /// QUIC clients were already dropped from the client table: only a close
    /// makes them re-dial, and the endpoint and capability have to survive so
    /// the re-dial lands here with the token the client already holds.
    #[tokio::test]
    async fn close_connections_closes_live_clients_but_keeps_endpoints_and_tokens() {
        let (server, mut events, session) = test_server_on_free_port();
        let client = connect_live_test_client(&server, &session, 21).await;
        assert!(matches!(
            events.recv().await,
            Some(ServerEvent::ClientConnected { .. })
        ));

        server.close_connections(REMOTE_QUIC_CLOSE_HANDOFF, b"handoff rolled back");

        let closed = tokio::time::timeout(Duration::from_secs(5), client.connection.closed())
            .await
            .expect("client learns the connection closed");
        match closed {
            quinn::ConnectionError::ApplicationClosed(frame) => assert_eq!(
                u64::from(frame.error_code),
                u64::from(REMOTE_QUIC_CLOSE_HANDOFF)
            ),
            other => panic!("expected an application close, got {other}"),
        }

        // Endpoint still listening, capability still valid: the client comes
        // back as a fresh connection on the credential it already has.
        assert!(!server.handed_off.load(Ordering::Acquire));
        let token_hash = hash_bytes(&client.record.capability_token);
        let tokens = lock(&server.state.tokens);
        let capability = tokens.get(&token_hash).expect("capability survives");
        assert!(capability.active_connection.is_none());
        assert_eq!(capability.connection_generation, 1);
        let mut hello = capability_fixture().2;
        hello.server_instance_id = server.state.server_instance_id;
        hello.logical_client_id = [21; REMOTE_QUIC_ID_BYTES];
        hello.capability_token = client.record.capability_token;
        hello.connection_generation = 2;
        assert_eq!(
            validate_capability(
                server.state.server_instance_id,
                &tokens,
                &hello,
                &session,
                unix_seconds(),
            ),
            Ok(token_hash)
        );
    }

    /// A frame admitted at the frame limit no longer fits once the render
    /// record's envelope is added, and failing that write would end the
    /// publisher on a healthy connection: the graphics are dropped from this
    /// one frame instead.
    #[tokio::test]
    async fn a_near_limit_inline_graphics_frame_is_published_as_text() {
        let (server, mut events, session) = test_server_on_free_port();
        let client = connect_live_test_client(&server, &session, 22).await;
        assert!(matches!(
            events.recv().await,
            Some(ServerEvent::ClientConnected { .. })
        ));

        // One inline graphics segment, sized so the frame is admissible at
        // MAX_GRAPHICS_FRAME_SIZE but the record around it would not be.
        let head = b"head";
        let mut bytes = Vec::with_capacity(MAX_GRAPHICS_FRAME_SIZE);
        bytes.extend_from_slice(head);
        bytes.extend_from_slice(b"\x1b_Gf=100,i=1;");
        bytes.resize(MAX_GRAPHICS_FRAME_SIZE - 32 - 2, b'A');
        bytes.extend_from_slice(b"\x1b\\");
        assert_eq!(bytes.len(), MAX_GRAPHICS_FRAME_SIZE - 32);
        assert!(
            projected_record_size(bytes.len(), 0) > MAX_GRAPHICS_FRAME_SIZE,
            "the fixture must not fit the record limit inline, or it tests nothing"
        );
        let frame = crate::protocol::TerminalFrame {
            seq: 1,
            width: 80,
            height: 24,
            full: true,
            bytes,
        };

        // Budget fully committed to earlier transfers, which is what forces
        // the inline fallback in the first place.
        let (_generation_tx, mut generation_rx) = watch::channel(1u64);
        let mut render_stream = None;
        let result = publish_render(
            &client.server_side,
            &mut render_stream,
            &mut generation_rx,
            1,
            1,
            1,
            frame,
            Arc::new(Semaphore::new(0)),
            Arc::new(Mutex::new(HashSet::new())),
        )
        .await;
        assert_eq!(result, PublishRenderResult::Sent);

        let mut stream =
            tokio::time::timeout(Duration::from_secs(5), client.connection.accept_uni())
                .await
                .expect("render stream arrives")
                .expect("accept render stream");
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                read_async_message::<RemoteQuicStreamHeader>(&mut stream, MAX_FRAME_SIZE),
            )
            .await
            .expect("render header arrives")
            .expect("read render header"),
            RemoteQuicStreamHeader::Render { .. }
        ));
        // Timed out rather than awaited: an oversize record is never written
        // and, until the publisher closes, never will be — the exact hang this
        // guard exists to prevent.
        let record = tokio::time::timeout(
            Duration::from_secs(5),
            read_async_message::<RemoteQuicRenderRecord>(&mut stream, MAX_GRAPHICS_FRAME_SIZE),
        )
        .await
        .expect("render record arrives")
        .expect("read render record");
        assert_eq!(record.frame.bytes, head);
        assert!(record.resources.is_empty());
    }

    #[test]
    fn the_record_envelope_estimate_bounds_the_encoded_record() {
        let refs = 1024;
        let record = RemoteQuicRenderRecord {
            connection_generation: u64::MAX,
            render_generation: u64::MAX,
            state_revision: u64::MAX,
            frame: crate::protocol::TerminalFrame {
                seq: u64::MAX,
                width: u16::MAX,
                height: u16::MAX,
                full: true,
                bytes: vec![0u8; 64 * 1024],
            },
            resources: (0..refs)
                .map(|index| RemoteQuicResourceRef {
                    hash: [7; REMOTE_QUIC_HASH_BYTES],
                    text_offset: index,
                })
                .collect(),
        };
        let encoded = bincode::serde::encode_to_vec(&record, bincode::config::standard())
            .expect("encode record");
        assert!(
            encoded.len() <= projected_record_size(record.frame.bytes.len(), refs as usize),
            "envelope estimate {} must bound the encoded record {}",
            projected_record_size(record.frame.bytes.len(), refs as usize),
            encoded.len()
        );
    }

    fn framed_terminal(bytes: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        protocol::write_message(
            &mut framed,
            &ServerMessage::Terminal(crate::protocol::TerminalFrame {
                seq: 1,
                width: 80,
                height: 24,
                full: true,
                bytes: bytes.to_vec(),
            }),
        )
        .expect("frame terminal message");
        framed
    }

    /// The publisher is the only thing that repaints a client, so exiting on
    /// a write failure without closing leaves a healthy connection that never
    /// updates again.
    #[tokio::test]
    async fn a_failed_render_write_closes_the_connection_for_resync() {
        let (server, mut events, session) = test_server_on_free_port();
        let client = connect_live_test_client(&server, &session, 23).await;
        assert!(matches!(
            events.recv().await,
            Some(ServerEvent::ClientConnected { .. })
        ));

        let (render_writer, render_rx, generation_rx) = QuicRenderSender::new();
        let (drain_tx, mut drain_rx) = mpsc::channel(8);
        tokio::spawn(publish_server_output(
            client.server_side.clone(),
            render_rx,
            generation_rx,
            Arc::clone(&render_writer.inner),
            1,
            HashSet::new(),
            7,
            drain_tx,
        ));

        render_writer
            .try_send(framed_terminal(b"first"))
            .expect("queue the first render");
        let mut stream =
            tokio::time::timeout(Duration::from_secs(5), client.connection.accept_uni())
                .await
                .expect("render stream arrives")
                .expect("accept render stream");
        assert!(matches!(
            read_async_message::<RemoteQuicStreamHeader>(&mut stream, MAX_FRAME_SIZE)
                .await
                .expect("read render header"),
            RemoteQuicStreamHeader::Render { .. }
        ));
        let record =
            read_async_message::<RemoteQuicRenderRecord>(&mut stream, MAX_GRAPHICS_FRAME_SIZE)
                .await
                .expect("read render record");
        assert_eq!(record.frame.bytes, b"first");
        assert!(matches!(
            drain_rx.recv().await,
            Some(ServerEvent::ClientWriterDrained { .. })
        ));

        // The client stops the render stream while the connection stays up:
        // the next record cannot be written, which is the failure the close
        // has to report.
        stream
            .stop(VarInt::from_u32(0))
            .expect("stop the render stream");
        let mut closed = None;
        // STOP_SENDING has to reach the server before its next write fails.
        for _ in 0..50 {
            let _ = render_writer.try_send(framed_terminal(b"second"));
            if let Ok(reason) =
                tokio::time::timeout(Duration::from_millis(100), client.connection.closed()).await
            {
                closed = Some(reason);
                break;
            }
        }
        match closed.expect("the publisher closes after a failed render write") {
            quinn::ConnectionError::ApplicationClosed(frame) => assert_eq!(
                u64::from(frame.error_code),
                u64::from(REMOTE_QUIC_CLOSE_RESYNC),
                "a stale render stream must make the client re-dial"
            ),
            other => panic!("expected an application close, got {other}"),
        }
    }

    /// Eviction removes the capability itself, so the token the client holds
    /// can never validate again: it has to bootstrap a new one instead of
    /// reconnecting with the one it has, which is what `REPLACED` means.
    #[tokio::test]
    async fn evicting_a_capability_closes_its_connection_as_evicted() {
        let (server, mut events, session) = test_server_on_free_port();
        let client = connect_live_test_client(&server, &session, 24).await;
        assert!(matches!(
            events.recv().await,
            Some(ServerEvent::ClientConnected { .. })
        ));

        // The live client holds the oldest capability, so overflowing the
        // token table evicts exactly that one.
        for index in 0..=MAX_TOKENS {
            server
                .bootstrap(RemoteBootstrapRequest {
                    session: session.clone(),
                    logical_client_id: [index as u8; REMOTE_QUIC_ID_BYTES],
                })
                .expect("issue bounded capability");
        }
        assert!(
            !lock(&server.state.tokens).contains_key(&hash_bytes(&client.record.capability_token))
        );

        let closed = tokio::time::timeout(Duration::from_secs(5), client.connection.closed())
            .await
            .expect("the evicted client learns its capability is gone");
        match closed {
            quinn::ConnectionError::ApplicationClosed(frame) => assert_eq!(
                u64::from(frame.error_code),
                u64::from(REMOTE_QUIC_CLOSE_EVICTED),
                "an evicted capability must send the client back to bootstrap"
            ),
            other => panic!("expected an application close, got {other}"),
        }
    }
}
