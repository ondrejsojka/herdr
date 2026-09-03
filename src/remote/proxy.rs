//! Local Unix-socket proxy that keeps the thin client alive while remote transports recover.

use std::io;
use std::net::{Shutdown, SocketAddr};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as sync_mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::frame::lock;

use super::attach::{
    apply_managed_ssh_options, remote_bridge_command, remote_quic_candidates,
    request_remote_quic_bootstrap, ManagedSshOptions, RemoteHerdr,
};
use super::quic::{ConnectParams, QuicSession, ResourceCache, SessionExit};
use crate::config::{RemoteConfig, RemoteTransportConfig};
use crate::protocol::{
    ClientKeybindings, ClientLaunchMode, ClientMessage, RemoteBootstrapRecord,
    RemoteTransportStatus, RenderEncoding, ServerMessage, MAX_FRAME_SIZE, MAX_GRAPHICS_FRAME_SIZE,
    PROTOCOL_VERSION, REMOTE_QUIC_ID_BYTES,
};

const ACCEPT_POLL: Duration = Duration::from_millis(50);
const SOCKET_PERMISSION_MODE: u32 = 0o600;
const INPUT_QUEUE_ITEMS: usize = 64;
const OUTPUT_QUEUE_ITEMS: usize = 16;
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);
/// Head start the QUIC handshake gets before the SSH stdio bridge joins the
/// first-attach race.
const SSH_RACE_HEAD_START: Duration = Duration::from_millis(500);
const RACE_POLL: Duration = Duration::from_millis(50);
/// Delay between consecutive QUIC dials so the preferred address wins a tie
/// without giving up the whole per-candidate budget on a black hole.
const QUIC_DIAL_STAGGER: Duration = Duration::from_millis(250);
const SSH_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(1);
const SSH_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
/// `1 << 5` seconds already exceeds [`SSH_RECONNECT_MAX_DELAY`]; the shift is
/// capped so the doubling cannot overflow on a long-lived failure streak.
const SSH_RECONNECT_MAX_SHIFT: u32 = 5;
const SSH_RECONNECT_GIVE_UP: Duration = Duration::from_secs(600);
/// A bridge session that lasted this long counts as progress and resets the
/// reconnect backoff.
const SSH_SESSION_PROGRESS: Duration = Duration::from_secs(5);
const SSH_REBOOTSTRAP_DEADLINE: Duration = Duration::from_secs(15);
const SSH_REBOOTSTRAP_RETRY_DELAY: Duration = Duration::from_millis(250);
/// First delay before retrying QUIC after a live session dropped, doubling per
/// consecutive failure up to [`QUIC_RECONNECT_MAX_DELAY`]. Without it a session
/// that fails immediately on connect — a displaced generation, a reset render
/// stream — spins full-speed TLS handshakes on both ends.
const QUIC_RECONNECT_BASE_DELAY: Duration = Duration::from_millis(250);
const QUIC_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(4);
/// Consecutive immediate session failures tolerated before escalating to SSH
/// rebootstrap. Backoff alone cannot fix a stale capability; the ladder must
/// still reach a state that can.
const MAX_CONSECUTIVE_QUIC_RETRIES: u32 = 5;
/// A session that stayed up this long counts as healthy, so its next failure
/// starts a fresh retry budget instead of inheriting an old outage's count.
const QUIC_SESSION_STABLE_AFTER: Duration = Duration::from_secs(30);
/// Shown to the local client when the remote server fenced this session
/// because a newer generation of the same capability took over: reconnecting
/// would only fence out the client that just replaced this one.
const REMOTE_SESSION_SUPERSEDED: &str = "another client took over this remote session";

pub(super) struct BridgeConfig {
    pub(super) target: String,
    pub(super) remote_herdr: RemoteHerdr,
    pub(super) local_socket: PathBuf,
    pub(super) session_name: String,
    pub(super) ssh_options: Option<ManagedSshOptions>,
    pub(super) remote_config: RemoteConfig,
    pub(super) logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
    pub(super) ssh_hostname: Option<String>,
    pub(super) bootstrap: Option<RemoteBootstrapRecord>,
    pub(super) bootstrap_error: Option<String>,
}

pub(super) struct ResumableRemoteBridge {
    local_socket: PathBuf,
    should_stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ResumableRemoteBridge {
    pub(super) fn start(config: BridgeConfig) -> io::Result<Self> {
        let _ = std::fs::remove_file(&config.local_socket);
        let listener = UnixListener::bind(&config.local_socket)?;
        crate::ipc::restrict_socket_permissions(&config.local_socket, SOCKET_PERMISSION_MODE)?;
        listener.set_nonblocking(true)?;

        let local_socket = config.local_socket.clone();
        // Shared: the first-attach race hands the SSH bridge handshake to a
        // helper thread that outlives an early QUIC win.
        let config = Arc::new(config);
        let should_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&should_stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = stream.set_nonblocking(false) {
                            eprintln!(
                                "herdr: remote proxy failed to prepare client socket: {error}"
                            );
                            continue;
                        }
                        if let Err(error) = bridge_connection(stream, &config, &thread_stop) {
                            eprintln!("herdr: remote proxy failed: {error}");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(error) => {
                        eprintln!("herdr: remote proxy listener failed: {error}");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            local_socket,
            should_stop,
            thread: Some(thread),
        })
    }
}

impl Drop for ResumableRemoteBridge {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::Release);
        let _ = std::fs::remove_file(&self.local_socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalClientPhase {
    AwaitingWelcome,
    Connected,
}

impl LocalClientPhase {
    fn is_connected(self) -> bool {
        self == Self::Connected
    }
}

#[derive(Clone)]
struct HelloState {
    cols: u16,
    rows: u16,
    cell_width_px: u32,
    cell_height_px: u32,
    requested_encoding: RenderEncoding,
    keybindings: ClientKeybindings,
}

impl HelloState {
    fn from_message(message: ClientMessage) -> Result<Self, String> {
        let ClientMessage::Hello {
            version,
            cols,
            rows,
            cell_width_px,
            cell_height_px,
            requested_encoding,
            keybindings,
            launch_mode,
        } = message
        else {
            return Err("expected local client Hello as first message".to_owned());
        };
        if version != PROTOCOL_VERSION {
            return Err(format!(
                "local client protocol {version} does not match proxy protocol {PROTOCOL_VERSION}"
            ));
        }
        if launch_mode != ClientLaunchMode::App {
            return Err("remote proxy accepts full app clients only".to_owned());
        }
        if requested_encoding != RenderEncoding::TerminalAnsi {
            return Err("remote proxy requires Terminal-ANSI rendering".to_owned());
        }
        Ok(Self {
            cols,
            rows,
            cell_width_px,
            cell_height_px,
            requested_encoding,
            keybindings,
        })
    }

    fn message(&self) -> ClientMessage {
        ClientMessage::Hello {
            version: PROTOCOL_VERSION,
            cols: self.cols,
            rows: self.rows,
            cell_width_px: self.cell_width_px,
            cell_height_px: self.cell_height_px,
            requested_encoding: self.requested_encoding,
            keybindings: self.keybindings.clone(),
            launch_mode: ClientLaunchMode::App,
        }
    }

    fn apply_resize(&mut self, message: &ClientMessage) {
        if let ClientMessage::Resize {
            cols,
            rows,
            cell_width_px,
            cell_height_px,
        } = message
        {
            self.cols = *cols;
            self.rows = *rows;
            self.cell_width_px = *cell_width_px;
            self.cell_height_px = *cell_height_px;
        }
    }
}

struct InputRouter {
    state: Mutex<InputRouterState>,
    detached: AtomicBool,
}

struct InputRouterState {
    hello: HelloState,
    active: Option<mpsc::Sender<ClientMessage>>,
}

impl InputRouter {
    fn new(hello: HelloState) -> Self {
        Self {
            state: Mutex::new(InputRouterState {
                hello,
                active: None,
            }),
            detached: AtomicBool::new(false),
        }
    }

    fn hello(&self) -> HelloState {
        lock(&self.state).hello.clone()
    }

    fn set_active(&self, sender: mpsc::Sender<ClientMessage>) {
        let resize = {
            let mut state = lock(&self.state);
            state.active = Some(sender.clone());
            ClientMessage::Resize {
                cols: state.hello.cols,
                rows: state.hello.rows,
                cell_width_px: state.hello.cell_width_px,
                cell_height_px: state.hello.cell_height_px,
            }
        };
        let _ = sender.try_send(resize);
    }

    fn clear_active(&self) {
        lock(&self.state).active = None;
    }

    fn route(&self, message: ClientMessage) {
        if matches!(message, ClientMessage::Detach) {
            self.detached.store(true, Ordering::Release);
        }
        let sender = {
            let mut state = lock(&self.state);
            state.hello.apply_resize(&message);
            state.active.clone()
        };
        let Some(sender) = sender else {
            return;
        };
        match sender.try_send(message) {
            Ok(()) => {}
            // Backpressure while the transport is active: block until the queue
            // drains so ordered input is never dropped. Input is only discarded
            // when there is no active sender (connection dead), handled above.
            Err(mpsc::error::TrySendError::Full(message)) => {
                if sender.blocking_send(message).is_err() {
                    self.clear_active();
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => self.clear_active(),
        }
    }

    fn mark_closed(&self) {
        self.detached.store(true, Ordering::Release);
        self.clear_active();
    }

    fn is_detached(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }
}

/// Pump client messages from the local socket into the router. On EOF or a
/// read error without a prior Detach, mark the router closed so the bridge
/// thread unblocks and SSH child cleanup runs; mark_closed is idempotent.
fn read_local_input(input_stream: &mut impl io::Read, router: &InputRouter) {
    while let Ok(message) =
        crate::protocol::read_message::<_, ClientMessage>(input_stream, MAX_GRAPHICS_FRAME_SIZE)
    {
        let detached = matches!(message, ClientMessage::Detach);
        router.route(message);
        if detached || router.is_detached() {
            break;
        }
    }
    router.mark_closed();
}

/// Decide whether the SSH stdio bridge may carry the live session.
///
/// `transport = "quic"` means QUIC only: it never falls back to the stdio
/// bridge (it still uses SSH to authenticate and mint QUIC credentials), so
/// `ssh_fallback` applies to `auto` alone.
fn ssh_stream_allowed(config: &RemoteConfig) -> bool {
    match config.transport {
        RemoteTransportConfig::Ssh => true,
        RemoteTransportConfig::Quic => false,
        RemoteTransportConfig::Auto => config.ssh_fallback,
    }
}

fn bridge_connection(
    mut stream: UnixStream,
    config: &Arc<BridgeConfig>,
    should_stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let hello_message: ClientMessage = crate::protocol::read_message(&mut stream, MAX_FRAME_SIZE)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let hello = HelloState::from_message(hello_message).map_err(io::Error::other)?;
    let router = Arc::new(InputRouter::new(hello));

    let (output_tx, mut output_rx) = mpsc::channel::<ServerMessage>(OUTPUT_QUEUE_ITEMS);
    let mut output_stream = stream.try_clone()?;
    let output_router = Arc::clone(&router);
    let output_thread = thread::spawn(move || {
        while let Some(message) = output_rx.blocking_recv() {
            if crate::protocol::write_message(&mut output_stream, &message).is_err() {
                break;
            }
        }
        output_router.mark_closed();
        let _ = output_stream.shutdown(Shutdown::Both);
    });

    let mut input_stream = stream;
    let input_router = Arc::clone(&router);
    let input_thread = thread::spawn(move || {
        read_local_input(&mut input_stream, &input_router);
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("herdr-remote-quic")
        .build()?;
    let mut client_phase = LocalClientPhase::AwaitingWelcome;
    info!(
        target = %config.target,
        transport = ?config.remote_config.transport,
        ssh_fallback = config.remote_config.ssh_fallback,
        "remote transport bridge started"
    );
    let ssh_stream = ssh_stream_allowed(&config.remote_config);
    let mut use_ssh = config.remote_config.transport == RemoteTransportConfig::Ssh;
    let mut ssh_winner: Option<SshHandshake> = None;

    if !use_ssh {
        // Racing needs a bootstrap to dial; without one QUIC is already known
        // to be unavailable and the bridge starts immediately instead.
        let race_ssh_bridge = ssh_stream && config.bootstrap.is_some();
        match run_transport_ladder(
            &runtime,
            config,
            Arc::clone(&router),
            output_tx.clone(),
            &mut client_phase,
            should_stop,
            race_ssh_bridge,
            &mut ssh_winner,
        ) {
            QuicOutcome::Detached => {}
            QuicOutcome::SshRaceWon => {
                info!(
                    target = %config.target,
                    "remote SSH bridge won the first-attach race"
                );
                use_ssh = true;
            }
            QuicOutcome::Superseded(detail) => {
                warn!(
                    target = %config.target,
                    reason = %detail,
                    "remote session was taken over by another client"
                );
                // Terminal even when the SSH bridge is available: attaching
                // again would fence out the client that took over.
                send_proxy_error(
                    &output_tx,
                    &mut client_phase,
                    REMOTE_SESSION_SUPERSEDED.to_owned(),
                );
            }
            QuicOutcome::Fallback(detail) => {
                if ssh_stream {
                    warn!(
                        target = %config.target,
                        reason = %detail,
                        "remote QUIC unavailable; falling back to SSH"
                    );
                    if client_phase.is_connected() {
                        let _ = output_tx.blocking_send(ServerMessage::TransportStatus {
                            status: RemoteTransportStatus::SshFallbackConnecting,
                            detail: Some(detail),
                        });
                    }
                    use_ssh = true;
                } else {
                    send_proxy_error(&output_tx, &mut client_phase, detail);
                }
            }
        }
    }

    if use_ssh && !router.is_detached() && !should_stop.load(Ordering::Acquire) {
        run_ssh_reconnect_loop(
            config,
            Arc::clone(&router),
            output_tx.clone(),
            &mut client_phase,
            should_stop,
            ssh_winner.take(),
        );
    } else if let Some(handshake) = ssh_winner.take() {
        handshake.discard();
    }

    router.mark_closed();
    drop(output_tx);
    let _ = output_thread.join();
    let _ = input_thread.join();
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QuicOutcome {
    Detached,
    /// The first-attach race was won by the SSH stdio bridge. The live
    /// handshake travels out of band, like a connected QUIC session does.
    SshRaceWon,
    /// A newer generation of the same capability took over the remote
    /// session. Terminal: this client exits instead of fencing the client
    /// that replaced it back out.
    Superseded(String),
    Fallback(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuicAttempt {
    Initial,
    /// Reconnect after a live session dropped, carrying the count of
    /// consecutive short-lived sessions so the ladder can escalate.
    Fresh(u32),
    Rebootstrapped,
}

impl QuicAttempt {
    /// Consecutive failures already spent. A connect that follows anything but
    /// a failed live session starts the budget over.
    fn retries(self) -> u32 {
        match self {
            Self::Fresh(retries) => retries,
            Self::Initial | Self::Rebootstrapped => 0,
        }
    }
}

/// Exponential backoff for the `retries`-th consecutive reconnect, capped so a
/// long outage still retries at a useful cadence.
fn quic_reconnect_delay(retries: u32) -> Duration {
    QUIC_RECONNECT_BASE_DELAY
        .saturating_mul(
            1u32.checked_shl(retries.saturating_sub(1))
                .unwrap_or(u32::MAX),
        )
        .min(QUIC_RECONNECT_MAX_DELAY)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TransportPhase {
    InitialRace,
    QuicConnecting(QuicAttempt),
    /// Carries the retry budget spent reaching this session so an immediately
    /// failing session cannot reset it by connecting successfully.
    QuicLive(u32),
    SshRebootstrap,
    SshFallback(String),
    Done(QuicOutcome),
}

#[derive(Debug)]
enum TransportEvent {
    QuicConnected,
    QuicConnectFailed(String),
    SshRaceWon,
    SessionExited {
        exit: SessionExit,
        /// Whether the session stayed up long enough to count as healthy.
        stable: bool,
    },
    RebootstrapSucceeded,
    RebootstrapFailed(String),
    ClientDetached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TransportAction {
    RaceInitialTransports,
    ConnectQuic {
        recovering: bool,
        detail: Option<String>,
        /// Slept before dialing, so repeated immediate failures back off.
        delay: Duration,
    },
    RunQuic {
        recovering: bool,
    },
    Rebootstrap {
        detail: String,
    },
    StartSshFallback,
    Finish,
}

fn next_transport_phase(
    phase: TransportPhase,
    event: TransportEvent,
) -> (TransportPhase, TransportAction) {
    if matches!(event, TransportEvent::ClientDetached) {
        return (
            TransportPhase::Done(QuicOutcome::Detached),
            TransportAction::Finish,
        );
    }

    match (phase, event) {
        (TransportPhase::InitialRace, TransportEvent::QuicConnected) => (
            TransportPhase::QuicLive(0),
            TransportAction::RunQuic { recovering: false },
        ),
        (TransportPhase::InitialRace, TransportEvent::SshRaceWon) => (
            TransportPhase::Done(QuicOutcome::SshRaceWon),
            TransportAction::Finish,
        ),
        (TransportPhase::QuicConnecting(attempt), TransportEvent::QuicConnected) => (
            TransportPhase::QuicLive(attempt.retries()),
            TransportAction::RunQuic {
                recovering: attempt != QuicAttempt::Initial,
            },
        ),
        // Both first-attach transports failed, or the very first QUIC dial
        // failed with the race disabled: the SSH reconnect loop owns retrying.
        (TransportPhase::InitialRace, TransportEvent::QuicConnectFailed(detail))
        | (
            TransportPhase::QuicConnecting(QuicAttempt::Initial),
            TransportEvent::QuicConnectFailed(detail),
        )
        | (
            TransportPhase::QuicConnecting(QuicAttempt::Rebootstrapped),
            TransportEvent::QuicConnectFailed(detail),
        ) => (
            TransportPhase::SshFallback(detail),
            TransportAction::StartSshFallback,
        ),
        (
            TransportPhase::QuicConnecting(QuicAttempt::Fresh(_)),
            TransportEvent::QuicConnectFailed(detail),
        ) => (
            TransportPhase::SshRebootstrap,
            TransportAction::Rebootstrap { detail },
        ),
        (
            TransportPhase::QuicLive(spent),
            TransportEvent::SessionExited {
                exit: SessionExit::RetryFresh(detail),
                stable,
            },
        ) => {
            // A healthy session that finally dropped starts a new budget; a
            // session that died immediately keeps spending the old one.
            let retries = if stable { 1 } else { spent.saturating_add(1) };
            if retries > MAX_CONSECUTIVE_QUIC_RETRIES {
                // Backoff cannot repair a stale capability or a replaced
                // generation, so escalate to the rung that can.
                (
                    TransportPhase::SshRebootstrap,
                    TransportAction::Rebootstrap { detail },
                )
            } else {
                (
                    TransportPhase::QuicConnecting(QuicAttempt::Fresh(retries)),
                    TransportAction::ConnectQuic {
                        recovering: true,
                        detail: Some(detail),
                        delay: quic_reconnect_delay(retries),
                    },
                )
            }
        }
        (
            TransportPhase::QuicLive(_),
            TransportEvent::SessionExited {
                exit: SessionExit::Rebootstrap(detail),
                ..
            },
        ) => (
            TransportPhase::SshRebootstrap,
            TransportAction::Rebootstrap { detail },
        ),
        (
            TransportPhase::QuicLive(_),
            TransportEvent::SessionExited {
                exit: SessionExit::Superseded(detail),
                ..
            },
        ) => (
            TransportPhase::Done(QuicOutcome::Superseded(detail)),
            TransportAction::Finish,
        ),
        (
            TransportPhase::QuicLive(_),
            TransportEvent::SessionExited {
                exit: SessionExit::Detached,
                ..
            },
        ) => (
            TransportPhase::Done(QuicOutcome::Detached),
            TransportAction::Finish,
        ),
        (TransportPhase::SshRebootstrap, TransportEvent::RebootstrapSucceeded) => (
            TransportPhase::QuicConnecting(QuicAttempt::Rebootstrapped),
            TransportAction::ConnectQuic {
                recovering: true,
                detail: None,
                delay: Duration::ZERO,
            },
        ),
        (TransportPhase::SshRebootstrap, TransportEvent::RebootstrapFailed(detail)) => (
            TransportPhase::SshFallback(detail),
            TransportAction::StartSshFallback,
        ),
        (phase, event) => {
            let detail =
                format!("invalid remote transport transition: phase={phase:?}, event={event:?}");
            (
                TransportPhase::Done(QuicOutcome::Fallback(detail)),
                TransportAction::Finish,
            )
        }
    }
}

struct QuicDial {
    bootstrap: RemoteBootstrapRecord,
    candidates: Vec<SocketAddr>,
    logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
    connection_generation: u64,
    hello: HelloState,
    resource_cache: Arc<Mutex<ResourceCache>>,
}

/// Dial every resolved address at once, Happy-Eyeballs style: one QUIC
/// handshake per candidate, staggered so the preferred (IPv6-first) address
/// keeps a small head start, and the first completed handshake wins. The
/// remaining dials are aborted when this future resolves. Every dial carries
/// the same connection generation, so the server fences all but one of them
/// out even if two handshakes overlap; at most one can be accepted.
async fn dial_quic_candidates(dial: QuicDial) -> Result<(QuicSession, ServerMessage), String> {
    let QuicDial {
        bootstrap,
        candidates,
        logical_client_id,
        connection_generation,
        hello,
        resource_cache,
    } = dial;

    let mut dials = tokio::task::JoinSet::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        let params = ConnectParams {
            bootstrap: bootstrap.clone(),
            candidates: vec![candidate],
            logical_client_id,
            connection_generation,
            cols: hello.cols,
            rows: hello.rows,
            cell_width_px: hello.cell_width_px,
            cell_height_px: hello.cell_height_px,
            keybindings: hello.keybindings.clone(),
        };
        let cache = Arc::clone(&resource_cache);
        let stagger = QUIC_DIAL_STAGGER.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
        dials.spawn(async move {
            if !stagger.is_zero() {
                tokio::time::sleep(stagger).await;
            }
            (candidate, QuicSession::connect(params, cache).await)
        });
    }

    // Only the winner's result reaches the transport state machine: a loser's
    // error (typically a stale-generation or duplicate-attach close of a
    // candidate the server fenced out) is collected here but reported only
    // when every dial failed, so it can never turn a successful attach into a
    // rebootstrap decision.
    let mut errors = Vec::new();
    while let Some(joined) = dials.join_next().await {
        match joined {
            Ok((_, Ok(connected))) => return Ok(connected),
            Ok((candidate, Err(error))) => errors.push(format!("{candidate}: {error}")),
            Err(error) => errors.push(format!("QUIC dial task failed: {error}")),
        }
    }
    if errors.is_empty() {
        return Err("remote QUIC bootstrap returned no reachable address candidates".to_owned());
    }
    Err(format!(
        "all remote QUIC paths failed: {}",
        errors.join("; ")
    ))
}

enum RaceEvent {
    Quic(Result<Box<(QuicSession, ServerMessage)>, String>),
    Ssh(Result<Box<SshHandshake>, SshExit>),
}

enum RaceOutcome {
    Quic(Box<(QuicSession, ServerMessage)>),
    Ssh(Box<SshHandshake>),
    Failed(String),
    Detached,
}

/// Hand a race result to the coordinator, or tear it down when the
/// coordinator already picked the other transport and dropped the receiver.
fn send_race_event(events: &sync_mpsc::Sender<RaceEvent>, event: RaceEvent) {
    if let Err(sync_mpsc::SendError(event)) = events.send(event) {
        match event {
            RaceEvent::Ssh(Ok(handshake)) => handshake.discard(),
            // Dropping the session drops its quinn endpoint and connection,
            // which closes the losing QUIC path.
            RaceEvent::Quic(_) | RaceEvent::Ssh(Err(_)) => {}
        }
    }
}

/// Race the QUIC handshake against the SSH stdio bridge on first attach.
///
/// QUIC gets a head start, then the SSH bridge starts in parallel; the first
/// completed handshake wins and the loser is torn down. Without this, a host
/// that silently drops UDP would wait out the whole QUIC deadline before the
/// bridge is even spawned, making the first attach strictly slower than the
/// plain SSH bridge it replaced.
fn race_initial_transports(
    runtime: &tokio::runtime::Runtime,
    config: &Arc<BridgeConfig>,
    router: &Arc<InputRouter>,
    should_stop: &Arc<AtomicBool>,
    dial: QuicDial,
) -> RaceOutcome {
    let (events, results) = sync_mpsc::channel::<RaceEvent>();
    let hello = dial.hello.clone();
    let settled = Arc::new(AtomicBool::new(false));
    let ssh_child = SshBridgeChild::default();

    let quic_events = events.clone();
    let quic_dial = runtime.spawn(async move {
        let result = dial_quic_candidates(dial).await;
        send_race_event(&quic_events, RaceEvent::Quic(result.map(Box::new)));
    });

    let ssh_config = Arc::clone(config);
    let ssh_router = Arc::clone(router);
    let ssh_stop = Arc::clone(should_stop);
    let ssh_settled = Arc::clone(&settled);
    let ssh_child_handle = ssh_child.clone();
    let ssh_thread = thread::Builder::new()
        .name("herdr-remote-ssh-race".to_owned())
        .spawn(move || {
            if !sleep_interruptible(SSH_RACE_HEAD_START, &ssh_router, &ssh_stop) {
                return;
            }
            // QUIC already won inside its head start: never spawn ssh at all,
            // so the common healthy case costs no remote process.
            if ssh_settled.load(Ordering::Acquire) {
                return;
            }
            let result = ssh_handshake(&ssh_config, &hello, &ssh_child_handle).map(Box::new);
            send_race_event(&events, RaceEvent::Ssh(result));
        });
    let mut pending_ssh = match ssh_thread {
        // The worker is deliberately detached rather than joined: cancelling
        // the race kills its child, which unblocks its blocking handshake
        // reads and lets it exit on its own, whereas joining here would let a
        // wedged ssh process stall the winning attach.
        Ok(_) => true,
        Err(error) => {
            warn!(%error, "failed to start the racing SSH bridge; using QUIC only");
            false
        }
    };

    let mut pending_quic = true;
    let mut failures = Vec::new();
    let outcome = loop {
        if !pending_quic && !pending_ssh {
            break RaceOutcome::Failed(race_failure_detail(&failures));
        }
        match results.recv_timeout(RACE_POLL) {
            Ok(RaceEvent::Quic(Ok(connected))) => break RaceOutcome::Quic(connected),
            Ok(RaceEvent::Ssh(Ok(handshake))) => break RaceOutcome::Ssh(handshake),
            Ok(RaceEvent::Quic(Err(detail))) => {
                pending_quic = false;
                failures.push(format!("QUIC: {detail}"));
            }
            Ok(RaceEvent::Ssh(Err(exit))) => {
                pending_ssh = false;
                failures.push(format!("SSH bridge: {}", ssh_exit_detail(&exit)));
            }
            Err(sync_mpsc::RecvTimeoutError::Timeout) => {
                if router.is_detached() || should_stop.load(Ordering::Acquire) {
                    break RaceOutcome::Detached;
                }
            }
            Err(sync_mpsc::RecvTimeoutError::Disconnected) => {
                break RaceOutcome::Failed(race_failure_detail(&failures));
            }
        }
    };

    settled.store(true, Ordering::Release);
    match &outcome {
        // The bridge won: its child belongs to the returned handshake now.
        // Stop the losing dial before it can register a second attach with
        // the remote server; a completed-but-unwanted session is dropped by
        // send_race_event instead.
        RaceOutcome::Ssh(_) => quic_dial.abort(),
        RaceOutcome::Detached => {
            quic_dial.abort();
            ssh_child.cancel();
        }
        // `settled` only stops a worker that has not spawned ssh yet, so the
        // published child is killed as well: that unblocks a worker parked in
        // the blocking welcome read and reaps the process here instead of
        // leaving it, and its thread, alive for the life of the proxy.
        RaceOutcome::Quic(_) | RaceOutcome::Failed(_) => {
            ssh_child.cancel();
        }
    }
    outcome
}

fn race_failure_detail(failures: &[String]) -> String {
    if failures.is_empty() {
        return "remote transport race produced no result".to_owned();
    }
    failures.join("; ")
}

fn run_transport_ladder(
    runtime: &tokio::runtime::Runtime,
    config: &Arc<BridgeConfig>,
    router: Arc<InputRouter>,
    output: mpsc::Sender<ServerMessage>,
    client_phase: &mut LocalClientPhase,
    should_stop: &Arc<AtomicBool>,
    race_ssh_bridge: bool,
    ssh_winner: &mut Option<SshHandshake>,
) -> QuicOutcome {
    let Some(mut bootstrap) = config.bootstrap.clone() else {
        return QuicOutcome::Fallback(
            config
                .bootstrap_error
                .clone()
                .unwrap_or_else(|| "SSH bootstrap did not enable QUIC".to_owned()),
        );
    };
    let Some(hostname) = config.ssh_hostname.as_deref() else {
        return QuicOutcome::Fallback("SSH target hostname could not be resolved".to_owned());
    };

    let resource_cache = Arc::new(Mutex::new(ResourceCache::default()));
    let mut connection_generation = 0u64;
    let mut connected_session = None;
    let (mut phase, mut action) = if race_ssh_bridge {
        (
            TransportPhase::InitialRace,
            TransportAction::RaceInitialTransports,
        )
    } else {
        (
            TransportPhase::QuicConnecting(QuicAttempt::Initial),
            TransportAction::ConnectQuic {
                recovering: false,
                detail: None,
                delay: Duration::ZERO,
            },
        )
    };

    loop {
        if router.is_detached() && !matches!(&action, TransportAction::Finish) {
            (phase, action) = next_transport_phase(phase, TransportEvent::ClientDetached);
        }

        let event = match action {
            TransportAction::RaceInitialTransports => {
                let candidates = match remote_quic_candidates(hostname, bootstrap.port) {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        (phase, action) = next_transport_phase(
                            phase,
                            TransportEvent::QuicConnectFailed(error.to_string()),
                        );
                        continue;
                    }
                };
                connection_generation = connection_generation.saturating_add(1);
                info!(
                    target = %config.target,
                    generation = connection_generation,
                    candidates = candidates.len(),
                    "racing remote QUIC transport against the SSH bridge"
                );
                let dial = QuicDial {
                    bootstrap: bootstrap.clone(),
                    candidates,
                    logical_client_id: config.logical_client_id,
                    connection_generation,
                    hello: router.hello(),
                    resource_cache: Arc::clone(&resource_cache),
                };
                match race_initial_transports(runtime, config, &router, should_stop, dial) {
                    RaceOutcome::Quic(connected) => {
                        info!(
                            target = %config.target,
                            generation = connection_generation,
                            "remote QUIC transport won the first-attach race"
                        );
                        connected_session = Some(*connected);
                        TransportEvent::QuicConnected
                    }
                    RaceOutcome::Ssh(handshake) => {
                        *ssh_winner = Some(*handshake);
                        TransportEvent::SshRaceWon
                    }
                    RaceOutcome::Failed(detail) => TransportEvent::QuicConnectFailed(detail),
                    RaceOutcome::Detached => TransportEvent::ClientDetached,
                }
            }
            TransportAction::ConnectQuic {
                recovering,
                detail,
                delay,
            } => {
                if let Some(detail) = detail {
                    debug!(%detail, "remote QUIC connection lost; trying fresh QUIC");
                }
                // Announce before the backoff, not after. The router already
                // cleared its active sender, so input is being discarded for the
                // whole delay, and a session that failed without going stale
                // first never announced PathRecovering. Waiting until after the
                // sleep leaves the client showing a connected transport for up
                // to QUIC_RECONNECT_MAX_DELAY while its keystrokes vanish.
                if recovering
                    && output
                        .blocking_send(ServerMessage::TransportStatus {
                            status: RemoteTransportStatus::FreshQuicConnecting,
                            detail: None,
                        })
                        .is_err()
                {
                    return QuicOutcome::Detached;
                }
                if !delay.is_zero() {
                    // Detached clients must not be held here for the full backoff.
                    let deadline = Instant::now() + delay;
                    while Instant::now() < deadline && !router.is_detached() {
                        thread::sleep(ACCEPT_POLL.min(deadline - Instant::now()));
                    }
                    if router.is_detached() {
                        (phase, action) =
                            next_transport_phase(phase, TransportEvent::ClientDetached);
                        continue;
                    }
                }

                let candidates = match remote_quic_candidates(hostname, bootstrap.port) {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        (phase, action) = next_transport_phase(
                            phase,
                            TransportEvent::QuicConnectFailed(error.to_string()),
                        );
                        continue;
                    }
                };
                connection_generation = connection_generation.saturating_add(1);
                info!(
                    target = %config.target,
                    generation = connection_generation,
                    recovering,
                    "connecting remote QUIC transport"
                );
                match runtime.block_on(dial_quic_candidates(QuicDial {
                    bootstrap: bootstrap.clone(),
                    candidates,
                    logical_client_id: config.logical_client_id,
                    connection_generation,
                    hello: router.hello(),
                    resource_cache: Arc::clone(&resource_cache),
                })) {
                    Ok(connected) => {
                        info!(
                            target = %config.target,
                            generation = connection_generation,
                            "remote QUIC transport connected"
                        );
                        connected_session = Some(connected);
                        TransportEvent::QuicConnected
                    }
                    Err(error) => TransportEvent::QuicConnectFailed(error),
                }
            }
            TransportAction::RunQuic { recovering } => {
                let Some((session, welcome)) = connected_session.take() else {
                    return QuicOutcome::Fallback(
                        "remote transport entered QUIC live state without a connection".to_owned(),
                    );
                };
                if *client_phase == LocalClientPhase::AwaitingWelcome {
                    if output.blocking_send(welcome).is_err() {
                        return QuicOutcome::Detached;
                    }
                    *client_phase = LocalClientPhase::Connected;
                }
                let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE_ITEMS);
                router.set_active(input_tx);
                let started_at = Instant::now();
                let exit = runtime.block_on(session.run(input_rx, output.clone(), recovering));
                let stable = started_at.elapsed() >= QUIC_SESSION_STABLE_AFTER;
                warn!(
                    target = %config.target,
                    generation = connection_generation,
                    ?exit,
                    stable,
                    "remote QUIC session ended"
                );
                router.clear_active();
                TransportEvent::SessionExited { exit, stable }
            }
            TransportAction::Rebootstrap { detail } => {
                if output
                    .blocking_send(ServerMessage::TransportStatus {
                        status: RemoteTransportStatus::SshRebootstrap,
                        detail: Some(detail),
                    })
                    .is_err()
                {
                    return QuicOutcome::Detached;
                }
                match rebootstrap(config) {
                    Ok(record) => {
                        bootstrap = record;
                        TransportEvent::RebootstrapSucceeded
                    }
                    Err(error) => TransportEvent::RebootstrapFailed(error.to_string()),
                }
            }
            TransportAction::StartSshFallback => {
                let TransportPhase::SshFallback(detail) = phase else {
                    return QuicOutcome::Fallback(
                        "remote transport fallback action had no failure detail".to_owned(),
                    );
                };
                return QuicOutcome::Fallback(detail);
            }
            TransportAction::Finish => {
                let TransportPhase::Done(outcome) = phase else {
                    return QuicOutcome::Fallback(
                        "remote transport finished outside a terminal state".to_owned(),
                    );
                };
                return outcome;
            }
        };
        (phase, action) = next_transport_phase(phase, event);
    }
}

fn rebootstrap(config: &BridgeConfig) -> io::Result<RemoteBootstrapRecord> {
    let deadline = Instant::now() + SSH_REBOOTSTRAP_DEADLINE;
    loop {
        match request_remote_quic_bootstrap(
            &config.target,
            &config.remote_herdr,
            &config.session_name,
            &config.logical_client_id,
            config.ssh_options.as_ref(),
        ) {
            Ok(record) => return Ok(record),
            Err(error) if Instant::now() < deadline => {
                debug!(%error, "SSH QUIC rebootstrap not ready; retrying");
                thread::sleep(SSH_REBOOTSTRAP_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Sleep in short slices so a long reconnect backoff never delays detach or
/// bridge shutdown. Returns false when the wait was cut short.
fn sleep_interruptible(total: Duration, router: &InputRouter, should_stop: &AtomicBool) -> bool {
    let deadline = Instant::now() + total;
    loop {
        if router.is_detached() || should_stop.load(Ordering::Acquire) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        thread::sleep(deadline.saturating_duration_since(now).min(SHUTDOWN_POLL));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshRetryDecision {
    Wait(Duration),
    GiveUp(Duration),
}

/// Exponential reconnect backoff for the SSH bridge: 1s, 2s, 4s ... capped at
/// [`SSH_RECONNECT_MAX_DELAY`]. A bridge that keeps failing for
/// [`SSH_RECONNECT_GIVE_UP`] gives up so the client exits with the underlying
/// SSH error instead of spinning forever on, say, a revoked key.
fn ssh_retry_decision(consecutive_failures: u32, failing_for: Duration) -> SshRetryDecision {
    if failing_for >= SSH_RECONNECT_GIVE_UP {
        return SshRetryDecision::GiveUp(failing_for);
    }
    let shift = consecutive_failures
        .saturating_sub(1)
        .min(SSH_RECONNECT_MAX_SHIFT);
    let delay = SSH_RECONNECT_BASE_DELAY
        .saturating_mul(1u32 << shift)
        .min(SSH_RECONNECT_MAX_DELAY);
    SshRetryDecision::Wait(delay)
}

#[derive(Default)]
struct SshRetryState {
    consecutive_failures: u32,
    failing_since: Option<Instant>,
}

impl SshRetryState {
    fn record_failure(&mut self, now: Instant) -> SshRetryDecision {
        let since = *self.failing_since.get_or_insert(now);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        ssh_retry_decision(
            self.consecutive_failures,
            now.saturating_duration_since(since),
        )
    }

    fn record_progress(&mut self) {
        self.consecutive_failures = 0;
        self.failing_since = None;
    }
}

fn run_ssh_reconnect_loop(
    config: &BridgeConfig,
    router: Arc<InputRouter>,
    output: mpsc::Sender<ServerMessage>,
    client_phase: &mut LocalClientPhase,
    should_stop: &AtomicBool,
    mut connected: Option<SshHandshake>,
) {
    let mut attempt = 0u64;
    let mut retry = SshRetryState::default();
    while !router.is_detached() && !should_stop.load(Ordering::Acquire) {
        attempt = attempt.saturating_add(1);
        let handshake = match connected.take() {
            Some(handshake) => handshake,
            None => {
                if client_phase.is_connected()
                    && output
                        .blocking_send(ServerMessage::TransportStatus {
                            status: RemoteTransportStatus::SshFallbackConnecting,
                            detail: None,
                        })
                        .is_err()
                {
                    return;
                }
                info!(
                    target = %config.target,
                    attempt,
                    "connecting remote SSH transport"
                );
                match ssh_handshake(config, &router.hello(), &SshBridgeChild::default()) {
                    Ok(handshake) => handshake,
                    Err(SshExit::Detached) => return,
                    Err(SshExit::Fatal(detail)) => {
                        send_proxy_error(&output, client_phase, detail);
                        return;
                    }
                    Err(SshExit::Reconnect(detail)) => {
                        if !handle_ssh_failure(
                            config,
                            &mut retry,
                            attempt,
                            detail,
                            &router,
                            &output,
                            client_phase,
                            should_stop,
                        ) {
                            return;
                        }
                        continue;
                    }
                }
            }
        };
        let started = Instant::now();
        match run_ssh_session(
            config,
            handshake,
            Arc::clone(&router),
            &output,
            client_phase,
        ) {
            SshExit::Detached => return,
            SshExit::Fatal(detail) => {
                send_proxy_error(&output, client_phase, detail);
                return;
            }
            SshExit::Reconnect(detail) => {
                // A session that carried the UI for a while is progress, so it
                // resets the backoff; a session that dies immediately keeps
                // counting towards the give-up window.
                if started.elapsed() >= SSH_SESSION_PROGRESS {
                    retry.record_progress();
                }
                if !handle_ssh_failure(
                    config,
                    &mut retry,
                    attempt,
                    detail,
                    &router,
                    &output,
                    client_phase,
                    should_stop,
                ) {
                    return;
                }
            }
        }
    }
}

/// Apply the reconnect backoff after a failed SSH attempt. Returns false when
/// the loop must stop, either because the bridge kept failing past the
/// give-up window or because the client went away while waiting.
fn handle_ssh_failure(
    config: &BridgeConfig,
    retry: &mut SshRetryState,
    attempt: u64,
    detail: String,
    router: &InputRouter,
    output: &mpsc::Sender<ServerMessage>,
    client_phase: &mut LocalClientPhase,
    should_stop: &AtomicBool,
) -> bool {
    match retry.record_failure(Instant::now()) {
        SshRetryDecision::GiveUp(failing_for) => {
            warn!(
                target = %config.target,
                attempt,
                reason = %detail,
                failing_for_seconds = failing_for.as_secs(),
                "remote SSH transport kept failing; giving up"
            );
            send_proxy_error(
                output,
                client_phase,
                format!(
                    "remote SSH bridge kept failing for {} minutes: {detail}",
                    failing_for.as_secs() / 60
                ),
            );
            false
        }
        SshRetryDecision::Wait(delay) => {
            warn!(
                target = %config.target,
                attempt,
                reason = %detail,
                retry_in_seconds = delay.as_secs(),
                "remote SSH transport disconnected; reconnecting"
            );
            sleep_interruptible(delay, router, should_stop)
        }
    }
}

#[derive(Debug)]
enum SshExit {
    Detached,
    Reconnect(String),
    Fatal(String),
}

fn ssh_exit_detail(exit: &SshExit) -> &str {
    match exit {
        SshExit::Detached => "local client detached",
        SshExit::Reconnect(detail) | SshExit::Fatal(detail) => detail,
    }
}

/// Shared ownership of a spawned SSH bridge child process.
///
/// The first-attach race publishes its child here as soon as the process
/// exists so the coordinator can kill it the moment QUIC wins: killing the
/// child is the only way to unblock a worker that is already parked in the
/// blocking welcome read. Every clone shares one slot, and the slot reaps
/// whatever is left in it when the last clone drops, so a
/// completed-but-unconsumed handshake (both race results queued) cannot leak
/// a process either.
#[derive(Clone, Default)]
struct SshBridgeChild {
    slot: Arc<Mutex<SshBridgeChildSlot>>,
}

#[derive(Default)]
struct SshBridgeChildSlot {
    child: Option<Child>,
    cancelled: bool,
}

impl SshBridgeChild {
    /// Publish a freshly spawned child. Returns false when the handle was
    /// already cancelled; the child is killed and reaped here in that case
    /// and the handshake must be abandoned.
    fn publish(&self, child: Child) -> bool {
        let mut slot = lock(&self.slot);
        if slot.cancelled {
            drop(slot);
            reap_ssh_bridge_child(child);
            return false;
        }
        slot.child = Some(child);
        true
    }

    /// Hand the child to a caller that owns its lifetime from here on.
    fn take(&self) -> Option<Child> {
        lock(&self.slot).child.take()
    }

    /// Kill and reap the published child, and reject later publishes.
    /// Idempotent: a repeated cancel, a winner that already took the child,
    /// and the slot's own drop all become no-ops.
    fn cancel(&self) -> Option<(u32, ExitStatus)> {
        let child = {
            let mut slot = lock(&self.slot);
            slot.cancelled = true;
            slot.child.take()?
        };
        reap_ssh_bridge_child(child)
    }
}

impl Drop for SshBridgeChildSlot {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            reap_ssh_bridge_child(child);
        }
    }
}

/// Kill a bridge child and wait for it, so no path leaves a zombie behind.
fn reap_ssh_bridge_child(mut child: Child) -> Option<(u32, ExitStatus)> {
    let pid = child.id();
    let _ = child.kill();
    match child.wait() {
        Ok(status) => {
            debug!(
                child_pid = pid,
                ?status,
                "killed and reaped the SSH bridge process"
            );
            Some((pid, status))
        }
        Err(error) => {
            warn!(
                child_pid = pid,
                %error,
                "failed to reap the SSH bridge process"
            );
            None
        }
    }
}

/// A live SSH stdio bridge that finished its protocol handshake but has not
/// started pumping messages yet, so the first-attach race can hand it over or
/// throw it away.
struct SshHandshake {
    child: SshBridgeChild,
    stdin: ChildStdin,
    stdout: ChildStdout,
    welcome: ServerMessage,
}

impl SshHandshake {
    fn discard(self) {
        self.child.cancel();
    }
}

fn ssh_handshake(
    config: &BridgeConfig,
    hello: &HelloState,
    child_handle: &SshBridgeChild,
) -> Result<SshHandshake, SshExit> {
    let mut command = Command::new("ssh");
    apply_managed_ssh_options(&mut command, config.ssh_options.as_ref());
    command
        .arg("-T")
        .arg(&config.target)
        .arg(remote_bridge_command(
            &config.remote_herdr,
            &config.session_name,
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Err(SshExit::Reconnect(format!(
                "failed to start SSH bridge: {error}"
            )))
        }
    };
    info!(
        target = %config.target,
        child_pid = child.id(),
        "remote SSH bridge process started"
    );
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    // Publish before the blocking handshake I/O: from here on the race
    // coordinator can kill this child to unblock and unwind this handshake.
    if !child_handle.publish(child) {
        return Err(SshExit::Reconnect(
            "SSH bridge handshake was cancelled".to_owned(),
        ));
    }
    let Some(mut stdin) = stdin else {
        child_handle.cancel();
        return Err(SshExit::Fatal("SSH bridge stdin is unavailable".to_owned()));
    };
    let Some(mut stdout) = stdout else {
        child_handle.cancel();
        return Err(SshExit::Fatal(
            "SSH bridge stdout is unavailable".to_owned(),
        ));
    };

    if let Err(error) = crate::protocol::write_message(&mut stdin, &hello.message()) {
        child_handle.cancel();
        return Err(SshExit::Reconnect(format!(
            "failed to send SSH bridge hello: {error}"
        )));
    }
    let welcome: ServerMessage = match crate::protocol::read_message(&mut stdout, MAX_FRAME_SIZE) {
        Ok(welcome @ ServerMessage::Welcome { error: None, .. }) => welcome,
        Ok(ServerMessage::Welcome {
            error: Some(error), ..
        }) => {
            child_handle.cancel();
            return Err(SshExit::Fatal(error));
        }
        Ok(_) => {
            child_handle.cancel();
            return Err(SshExit::Reconnect(
                "SSH bridge sent an invalid welcome".to_owned(),
            ));
        }
        Err(error) => {
            child_handle.cancel();
            return Err(SshExit::Reconnect(format!(
                "failed to read SSH bridge welcome: {error}"
            )));
        }
    };
    Ok(SshHandshake {
        child: child_handle.clone(),
        stdin,
        stdout,
        welcome,
    })
}

fn run_ssh_session(
    config: &BridgeConfig,
    handshake: SshHandshake,
    router: Arc<InputRouter>,
    output: &mpsc::Sender<ServerMessage>,
    client_phase: &mut LocalClientPhase,
) -> SshExit {
    let SshHandshake {
        child: child_handle,
        mut stdin,
        mut stdout,
        welcome,
    } = handshake;
    let Some(mut child) = child_handle.take() else {
        return SshExit::Reconnect("SSH bridge process was already reaped".to_owned());
    };
    if !deliver_ssh_welcome(output, client_phase, welcome) {
        let _ = child.kill();
        let _ = child.wait();
        return SshExit::Detached;
    }
    info!(
        target = %config.target,
        child_pid = child.id(),
        "remote SSH transport connected"
    );

    let (input_tx, mut input_rx) = mpsc::channel::<ClientMessage>(INPUT_QUEUE_ITEMS);
    router.set_active(input_tx);
    let writer = thread::spawn(move || {
        while let Some(message) = input_rx.blocking_recv() {
            if crate::protocol::write_message(&mut stdin, &message).is_err() {
                break;
            }
            if matches!(message, ClientMessage::Detach) {
                break;
            }
        }
    });

    let result = loop {
        match crate::protocol::read_message::<_, ServerMessage>(
            &mut stdout,
            MAX_GRAPHICS_FRAME_SIZE,
        ) {
            Ok(ServerMessage::ClientDetached) => {
                let _ = output.blocking_send(ServerMessage::ClientDetached);
                break SshExit::Detached;
            }
            Ok(ServerMessage::ServerShutdown { reason }) if !router.is_detached() => {
                break SshExit::Reconnect(
                    reason.unwrap_or_else(|| "remote server restarted".to_owned()),
                );
            }
            Ok(message) => {
                if output.blocking_send(message).is_err() {
                    break SshExit::Detached;
                }
            }
            Err(error) => {
                if router.is_detached() {
                    break SshExit::Detached;
                }
                break SshExit::Reconnect(error.to_string());
            }
        }
    };
    router.clear_active();
    let _ = child.kill();
    let _ = child.wait();
    let _ = writer.join();
    info!(
        target = %config.target,
        child_pid = child.id(),
        ?result,
        "remote SSH bridge process stopped"
    );
    result
}

/// Send the welcome (first connection only) and then, mirroring the QUIC
/// path, a `Connected` transport status so the local client clears its
/// transport_stale flag and resumes forwarding stdin after an SSH reconnect.
/// Returns false when the local client is gone.
fn deliver_ssh_welcome(
    output: &mpsc::Sender<ServerMessage>,
    client_phase: &mut LocalClientPhase,
    welcome: ServerMessage,
) -> bool {
    if *client_phase == LocalClientPhase::AwaitingWelcome {
        if output.blocking_send(welcome).is_err() {
            return false;
        }
        *client_phase = LocalClientPhase::Connected;
    }
    output
        .blocking_send(ServerMessage::TransportStatus {
            status: RemoteTransportStatus::Connected,
            detail: None,
        })
        .is_ok()
}

fn send_proxy_error(
    output: &mpsc::Sender<ServerMessage>,
    client_phase: &mut LocalClientPhase,
    detail: String,
) {
    let message = if client_phase.is_connected() {
        ServerMessage::ServerShutdown {
            reason: Some(detail),
        }
    } else {
        *client_phase = LocalClientPhase::Connected;
        ServerMessage::Welcome {
            version: PROTOCOL_VERSION,
            encoding: RenderEncoding::TerminalAnsi,
            error: Some(detail),
        }
    };
    let _ = output.blocking_send(message);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> HelloState {
        HelloState {
            cols: 80,
            rows: 24,
            cell_width_px: 8,
            cell_height_px: 16,
            requested_encoding: RenderEncoding::TerminalAnsi,
            keybindings: ClientKeybindings::Server,
        }
    }

    #[test]
    fn disconnected_router_drops_input_and_keeps_latest_geometry() {
        let router = InputRouter::new(hello());
        router.route(ClientMessage::Input {
            data: b"must not replay".to_vec(),
        });
        router.route(ClientMessage::Resize {
            cols: 120,
            rows: 40,
            cell_width_px: 9,
            cell_height_px: 18,
        });
        let current = router.hello();
        assert_eq!((current.cols, current.rows), (120, 40));
    }

    #[test]
    fn detach_is_local_even_without_an_active_transport() {
        let router = InputRouter::new(hello());
        router.route(ClientMessage::Detach);
        assert!(router.is_detached());
    }

    #[test]
    fn ssh_welcome_announces_connected_after_reconnect() {
        let (output_tx, mut output_rx) = mpsc::channel::<ServerMessage>(4);

        // First connection: welcome then Connected.
        let mut phase = LocalClientPhase::AwaitingWelcome;
        let welcome = ServerMessage::Welcome {
            version: PROTOCOL_VERSION,
            encoding: RenderEncoding::TerminalAnsi,
            error: None,
        };
        assert!(deliver_ssh_welcome(&output_tx, &mut phase, welcome.clone()));
        assert_eq!(phase, LocalClientPhase::Connected);
        assert!(matches!(
            output_rx.blocking_recv(),
            Some(ServerMessage::Welcome { .. })
        ));
        assert!(matches!(
            output_rx.blocking_recv(),
            Some(ServerMessage::TransportStatus {
                status: RemoteTransportStatus::Connected,
                ..
            })
        ));

        // Reconnect (already connected): Connected is still emitted so the
        // client clears transport_stale and resumes forwarding stdin.
        assert!(deliver_ssh_welcome(&output_tx, &mut phase, welcome));
        assert!(matches!(
            output_rx.blocking_recv(),
            Some(ServerMessage::TransportStatus {
                status: RemoteTransportStatus::Connected,
                ..
            })
        ));
    }

    #[test]
    fn local_socket_eof_marks_router_closed() {
        let router = InputRouter::new(hello());
        let mut eof: &[u8] = &[];
        read_local_input(&mut eof, &router);
        assert!(router.is_detached());
        // A prior Detach must not cause trouble on the EOF teardown path.
        read_local_input(&mut eof, &router);
        assert!(router.is_detached());
    }

    #[test]
    fn active_transport_backpressures_instead_of_dropping_input() {
        let router = Arc::new(InputRouter::new(hello()));
        let (tx, mut rx) = mpsc::channel::<ClientMessage>(1);
        router.set_active(tx); // set_active enqueues a Resize, filling the queue

        let route_router = Arc::clone(&router);
        let sender = thread::spawn(move || {
            route_router.route(ClientMessage::Input {
                data: b"typed while full".to_vec(),
            });
        });

        // Drain the queue: the blocked route() must deliver the input.
        assert!(matches!(
            rx.blocking_recv(),
            Some(ClientMessage::Resize { .. })
        ));
        assert_eq!(
            rx.blocking_recv(),
            Some(ClientMessage::Input {
                data: b"typed while full".to_vec(),
            })
        );
        sender.join().unwrap();
    }
    #[test]
    fn transport_machine_uses_one_ordered_recovery_ladder() {
        let (phase, action) = next_transport_phase(
            TransportPhase::QuicConnecting(QuicAttempt::Initial),
            TransportEvent::QuicConnected,
        );
        assert_eq!(phase, TransportPhase::QuicLive(0));
        assert_eq!(action, TransportAction::RunQuic { recovering: false });

        let (phase, action) = next_transport_phase(
            phase,
            TransportEvent::SessionExited {
                exit: SessionExit::RetryFresh("path lost".to_owned()),
                stable: false,
            },
        );
        assert_eq!(phase, TransportPhase::QuicConnecting(QuicAttempt::Fresh(1)));
        assert_eq!(
            action,
            TransportAction::ConnectQuic {
                recovering: true,
                detail: Some("path lost".to_owned()),
                delay: QUIC_RECONNECT_BASE_DELAY,
            }
        );

        let (phase, action) = next_transport_phase(
            phase,
            TransportEvent::QuicConnectFailed("fresh failed".to_owned()),
        );
        assert_eq!(phase, TransportPhase::SshRebootstrap);
        assert_eq!(
            action,
            TransportAction::Rebootstrap {
                detail: "fresh failed".to_owned()
            }
        );

        let (phase, action) = next_transport_phase(phase, TransportEvent::RebootstrapSucceeded);
        assert_eq!(
            phase,
            TransportPhase::QuicConnecting(QuicAttempt::Rebootstrapped)
        );
        assert_eq!(
            action,
            TransportAction::ConnectQuic {
                recovering: true,
                detail: None,
                delay: Duration::ZERO,
            }
        );

        let (phase, action) = next_transport_phase(
            phase,
            TransportEvent::QuicConnectFailed("new endpoint failed".to_owned()),
        );
        assert_eq!(
            phase,
            TransportPhase::SshFallback("new endpoint failed".to_owned())
        );
        assert_eq!(action, TransportAction::StartSshFallback);
    }

    #[test]
    fn transport_machine_handles_direct_rebootstrap_and_terminal_states() {
        let (phase, action) = next_transport_phase(
            TransportPhase::QuicLive(0),
            TransportEvent::SessionExited {
                exit: SessionExit::Rebootstrap("server instance changed".to_owned()),
                stable: false,
            },
        );
        assert_eq!(phase, TransportPhase::SshRebootstrap);
        assert_eq!(
            action,
            TransportAction::Rebootstrap {
                detail: "server instance changed".to_owned()
            }
        );

        let (phase, action) = next_transport_phase(
            phase,
            TransportEvent::RebootstrapFailed("SSH unavailable".to_owned()),
        );
        assert_eq!(
            phase,
            TransportPhase::SshFallback("SSH unavailable".to_owned())
        );
        assert_eq!(action, TransportAction::StartSshFallback);

        let (phase, action) =
            next_transport_phase(TransportPhase::QuicLive(0), TransportEvent::ClientDetached);
        assert_eq!(phase, TransportPhase::Done(QuicOutcome::Detached));
        assert_eq!(action, TransportAction::Finish);
    }

    #[test]
    fn repeated_immediate_session_failures_back_off_then_escalate() {
        let mut phase = TransportPhase::QuicLive(0);
        let mut delays = Vec::new();

        // A session that connects and dies immediately, over and over, must not
        // reconnect without pause and must eventually leave the QUIC rung.
        let escalation = loop {
            let (next, action) = next_transport_phase(
                phase,
                TransportEvent::SessionExited {
                    exit: SessionExit::RetryFresh("displaced".to_owned()),
                    stable: false,
                },
            );
            match action {
                TransportAction::ConnectQuic { delay, .. } => {
                    assert!(!delay.is_zero(), "reconnect must wait before redialing");
                    delays.push(delay);
                    // The driver reconnects, so the next failure spends more budget.
                    let (live, _) = next_transport_phase(next, TransportEvent::QuicConnected);
                    phase = live;
                }
                other => break other,
            }
            assert!(
                delays.len() <= MAX_CONSECUTIVE_QUIC_RETRIES as usize,
                "retry budget must be finite"
            );
        };

        assert_eq!(
            escalation,
            TransportAction::Rebootstrap {
                detail: "displaced".to_owned()
            }
        );
        // Exact sequence, not merely nondecreasing: a constant 250ms would pass
        // a monotonicity check while silently dropping exponential backoff.
        assert_eq!(
            delays,
            vec![
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
            ],
            "backoff must double until it reaches the cap"
        );
        assert_eq!(
            delays.last().copied(),
            Some(QUIC_RECONNECT_MAX_DELAY),
            "the budget must be spent at the cap, not below it"
        );
    }

    #[test]
    fn a_healthy_session_restores_the_quic_retry_budget() {
        let (phase, action) = next_transport_phase(
            TransportPhase::QuicLive(MAX_CONSECUTIVE_QUIC_RETRIES),
            TransportEvent::SessionExited {
                exit: SessionExit::RetryFresh("path lost".to_owned()),
                stable: true,
            },
        );

        assert_eq!(phase, TransportPhase::QuicConnecting(QuicAttempt::Fresh(1)));
        assert_eq!(
            action,
            TransportAction::ConnectQuic {
                recovering: true,
                detail: Some("path lost".to_owned()),
                delay: QUIC_RECONNECT_BASE_DELAY,
            }
        );
    }

    #[test]
    fn transport_machine_treats_a_superseded_session_as_terminal() {
        // A newer generation of the same capability took over the session:
        // the ladder must stop here instead of dialing fresh QUIC,
        // rebootstrapping, or falling back to the SSH bridge, all of which
        // would fence out the client that just replaced this one.
        let (phase, action) = next_transport_phase(
            TransportPhase::QuicLive(MAX_CONSECUTIVE_QUIC_RETRIES),
            TransportEvent::SessionExited {
                exit: SessionExit::Superseded("closed by peer: replaced".to_owned()),
                stable: false,
            },
        );
        assert_eq!(
            phase,
            TransportPhase::Done(QuicOutcome::Superseded(
                "closed by peer: replaced".to_owned()
            ))
        );
        assert_eq!(action, TransportAction::Finish);
    }

    #[test]
    fn superseded_outcome_shuts_the_local_client_down_with_a_reason() {
        let (output_tx, mut output_rx) = mpsc::channel::<ServerMessage>(2);
        let mut phase = LocalClientPhase::Connected;
        send_proxy_error(&output_tx, &mut phase, REMOTE_SESSION_SUPERSEDED.to_owned());
        assert!(matches!(
            output_rx.blocking_recv(),
            Some(ServerMessage::ServerShutdown { reason: Some(reason) })
                if reason == "another client took over this remote session"
        ));
    }

    /// A reaped child leaves no `/proc` entry, while a killed-but-unwaited
    /// child lingers there as a zombie. Returns `None` where `/proc` is not
    /// available, so the assertions below simply do not apply.
    fn proc_entry_exists(pid: u32) -> Option<bool> {
        let proc = std::path::Path::new("/proc");
        if !proc.exists() {
            return None;
        }
        Some(proc.join(pid.to_string()).exists())
    }

    fn spawn_stand_in_ssh_child() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn a stand-in ssh bridge child")
    }

    #[test]
    fn race_cancellation_kills_and_reaps_the_losing_ssh_child() {
        let child_handle = SshBridgeChild::default();
        let child = spawn_stand_in_ssh_child();
        let pid = child.id();
        assert!(child_handle.publish(child));
        assert_ne!(proc_entry_exists(pid), Some(false));

        // QUIC won after the bridge already spawned: cancelling kills the
        // published child and waits for it, which unblocks the worker's
        // blocking welcome read and leaves no zombie behind.
        let (reaped_pid, status) = child_handle.cancel().expect("cancel reaps the child");
        assert_eq!(reaped_pid, pid);
        assert!(!status.success());
        assert_ne!(proc_entry_exists(pid), Some(true));

        // Idempotent: a second cancel (or a discard, or the slot's drop) has
        // nothing left to kill.
        assert!(child_handle.cancel().is_none());
        assert!(child_handle.take().is_none());

        // A worker that spawned ssh just after the race settled cannot leak
        // it either: publishing on a cancelled handle reaps the child.
        let late = spawn_stand_in_ssh_child();
        let late_pid = late.id();
        assert!(!child_handle.publish(late));
        assert_ne!(proc_entry_exists(late_pid), Some(true));
    }

    #[test]
    fn dropping_an_unconsumed_handshake_reaps_its_bridge_child() {
        let child_handle = SshBridgeChild::default();
        let queued = child_handle.clone();
        let child = spawn_stand_in_ssh_child();
        let pid = child.id();
        assert!(child_handle.publish(child));

        // The coordinator's handle goes away while the completed handshake is
        // still queued: the child stays owned by the queued clone.
        drop(child_handle);
        assert_ne!(proc_entry_exists(pid), Some(false));

        // Nobody consumed the handshake, so dropping it reaps the process
        // instead of dropping a live `Child` on the floor.
        drop(queued);
        assert_ne!(proc_entry_exists(pid), Some(true));
    }

    #[test]
    fn transport_machine_races_the_ssh_bridge_on_first_attach() {
        // QUIC wins: the ladder continues exactly as an unraced first connect.
        let (phase, action) =
            next_transport_phase(TransportPhase::InitialRace, TransportEvent::QuicConnected);
        assert_eq!(phase, TransportPhase::QuicLive(0));
        assert_eq!(action, TransportAction::RunQuic { recovering: false });

        // The SSH bridge wins: the QUIC ladder is done and the handed-over
        // handshake carries the session.
        let (phase, action) =
            next_transport_phase(TransportPhase::InitialRace, TransportEvent::SshRaceWon);
        assert_eq!(phase, TransportPhase::Done(QuicOutcome::SshRaceWon));
        assert_eq!(action, TransportAction::Finish);

        // Both raced transports failed: the SSH reconnect loop owns retrying.
        let (phase, action) = next_transport_phase(
            TransportPhase::InitialRace,
            TransportEvent::QuicConnectFailed("QUIC: timed out; SSH bridge: no route".to_owned()),
        );
        assert_eq!(
            phase,
            TransportPhase::SshFallback("QUIC: timed out; SSH bridge: no route".to_owned())
        );
        assert_eq!(action, TransportAction::StartSshFallback);

        // Detaching mid-race is terminal.
        let (phase, action) =
            next_transport_phase(TransportPhase::InitialRace, TransportEvent::ClientDetached);
        assert_eq!(phase, TransportPhase::Done(QuicOutcome::Detached));
        assert_eq!(action, TransportAction::Finish);
    }

    #[test]
    fn quic_race_win_does_not_reenter_the_race_after_a_live_loss() {
        // The ladder is one-way: a lost live QUIC session retries fresh QUIC,
        // then rebootstraps, then hands over to SSH; it never races again.
        let (phase, _) =
            next_transport_phase(TransportPhase::InitialRace, TransportEvent::QuicConnected);
        let (phase, action) = next_transport_phase(
            phase,
            TransportEvent::SessionExited {
                exit: SessionExit::RetryFresh("path lost".to_owned()),
                stable: false,
            },
        );
        assert_eq!(phase, TransportPhase::QuicConnecting(QuicAttempt::Fresh(1)));
        assert_eq!(
            action,
            TransportAction::ConnectQuic {
                recovering: true,
                detail: Some("path lost".to_owned()),
                delay: QUIC_RECONNECT_BASE_DELAY,
            }
        );

        let (phase, action) =
            next_transport_phase(phase, TransportEvent::QuicConnectFailed("gone".to_owned()));
        assert_eq!(phase, TransportPhase::SshRebootstrap);
        assert_eq!(
            action,
            TransportAction::Rebootstrap {
                detail: "gone".to_owned()
            }
        );
    }

    #[test]
    fn ssh_retry_decision_backs_off_exponentially_then_gives_up() {
        let schedule = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 30), (12, 30)];
        for (failures, expected_seconds) in schedule {
            assert_eq!(
                ssh_retry_decision(failures, Duration::from_secs(60)),
                SshRetryDecision::Wait(Duration::from_secs(expected_seconds)),
                "failure {failures} should wait {expected_seconds}s"
            );
        }

        // The give-up window ends the loop no matter how few attempts fit in it.
        assert_eq!(
            ssh_retry_decision(3, SSH_RECONNECT_GIVE_UP),
            SshRetryDecision::GiveUp(SSH_RECONNECT_GIVE_UP)
        );
        assert_eq!(
            ssh_retry_decision(500, Duration::from_secs(3_600)),
            SshRetryDecision::GiveUp(Duration::from_secs(3_600))
        );
        // Just inside the window still retries.
        assert!(matches!(
            ssh_retry_decision(50, SSH_RECONNECT_GIVE_UP - Duration::from_secs(1)),
            SshRetryDecision::Wait(_)
        ));
    }

    #[test]
    fn ssh_retry_state_gives_up_only_after_a_continuous_failure_window() {
        let mut retry = SshRetryState::default();
        let start = Instant::now();
        assert_eq!(
            retry.record_failure(start),
            SshRetryDecision::Wait(SSH_RECONNECT_BASE_DELAY)
        );
        assert_eq!(
            retry.record_failure(start + Duration::from_secs(1)),
            SshRetryDecision::Wait(Duration::from_secs(2))
        );

        // A session that made progress resets both the delay and the window.
        retry.record_progress();
        assert_eq!(
            retry.record_failure(start + SSH_RECONNECT_GIVE_UP),
            SshRetryDecision::Wait(SSH_RECONNECT_BASE_DELAY)
        );
        assert!(matches!(
            retry.record_failure(start + SSH_RECONNECT_GIVE_UP + SSH_RECONNECT_GIVE_UP),
            SshRetryDecision::GiveUp(_)
        ));
    }

    #[test]
    fn interruptible_sleep_returns_early_when_the_client_detaches() {
        let router = Arc::new(InputRouter::new(hello()));
        let should_stop = AtomicBool::new(false);
        let started = Instant::now();
        assert!(sleep_interruptible(
            Duration::from_millis(20),
            &router,
            &should_stop
        ));

        router.route(ClientMessage::Detach);
        assert!(!sleep_interruptible(
            Duration::from_secs(30),
            &router,
            &should_stop
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Two dead candidates each burn the full per-candidate QUIC connect
    /// budget. Dialing them in parallel must cost about one budget, not two,
    /// so a host with both an AAAA and an A record is not punished.
    #[test]
    fn quic_candidates_are_dialed_in_parallel() {
        // Bound but never read: the handshake gets no response and times out.
        let silent_ipv4 =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent ipv4 socket");
        let silent_alias =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent alias socket");
        let candidates = vec![
            silent_ipv4.local_addr().expect("silent ipv4 addr"),
            silent_alias.local_addr().expect("silent alias addr"),
        ];

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let started = Instant::now();
        let error = runtime
            .block_on(dial_quic_candidates(QuicDial {
                bootstrap: RemoteBootstrapRecord {
                    version: PROTOCOL_VERSION,
                    server_instance_id: [7u8; REMOTE_QUIC_ID_BYTES],
                    port: candidates[0].port(),
                    certificate_fingerprint: [9u8; crate::protocol::REMOTE_QUIC_HASH_BYTES],
                    capability_token: [3u8; crate::protocol::REMOTE_QUIC_TOKEN_BYTES],
                    expires_unix_seconds: u64::MAX,
                    ssh_fallback_available: true,
                },
                candidates: candidates.clone(),
                logical_client_id: [1u8; REMOTE_QUIC_ID_BYTES],
                connection_generation: 1,
                hello: hello(),
                resource_cache: Arc::new(Mutex::new(ResourceCache::default())),
            }))
            .expect_err("silent candidates cannot complete a handshake");
        let elapsed = started.elapsed();

        for candidate in &candidates {
            assert!(
                error.contains(&candidate.to_string()),
                "every candidate must be reported: {error}"
            );
        }
        // Sequential dialing would need two full 2s budgets; parallel dialing
        // needs one plus the stagger.
        assert!(
            elapsed < Duration::from_millis(3_500),
            "parallel dial took {elapsed:?}"
        );
    }

    #[test]
    fn quic_transport_never_uses_the_ssh_stream() {
        // `quic` means QUIC only: no race, no fallback, ssh_fallback ignored.
        for ssh_fallback in [true, false] {
            let config = RemoteConfig {
                transport: RemoteTransportConfig::Quic,
                ssh_fallback,
                ..Default::default()
            };
            assert!(!ssh_stream_allowed(&config));
        }

        // `auto` is the only mode ssh_fallback applies to.
        assert!(ssh_stream_allowed(&RemoteConfig {
            transport: RemoteTransportConfig::Auto,
            ssh_fallback: true,
            ..Default::default()
        }));
        assert!(!ssh_stream_allowed(&RemoteConfig {
            transport: RemoteTransportConfig::Auto,
            ssh_fallback: false,
            ..Default::default()
        }));

        // `ssh` always uses the bridge, whatever ssh_fallback says.
        assert!(ssh_stream_allowed(&RemoteConfig {
            transport: RemoteTransportConfig::Ssh,
            ssh_fallback: false,
            ..Default::default()
        }));
    }
}
