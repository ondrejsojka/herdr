//! QUIC client used by the `herdr --remote` local proxy.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::mpsc;
use tracing::debug;

use super::frame::{hash_bytes, lock, read_async_message, write_async_message};
use super::quic_policy::{
    PRIORITY_CONTROL, REMOTE_QUIC_CLOSE_AUTH, REMOTE_QUIC_CLOSE_EVICTED,
    REMOTE_QUIC_CLOSE_PROTOCOL, REMOTE_QUIC_CLOSE_REPLACED, REMOTE_QUIC_CLOSE_SHUTDOWN,
};

use crate::protocol::{
    ClientKeybindings, ClientLaunchMode, ClientMessage, RemoteBootstrapRecord, RemoteQuicHello,
    RemoteQuicRenderRecord, RemoteQuicStreamHeader, RemoteTransportStatus, ServerMessage,
    MAX_FRAME_SIZE, MAX_GRAPHICS_FRAME_SIZE, PROTOCOL_VERSION, REMOTE_QUIC_ALPN,
    REMOTE_QUIC_HASH_BYTES, REMOTE_QUIC_MAX_RESOURCE_INVENTORY, REMOTE_QUIC_MAX_RESOURCE_SIZE,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Deadline for a single write on the reliable control stream. A write that
/// cannot complete in this long means the stream itself is wedged, which is
/// not something probing can diagnose. Path liveness is judged from probe
/// silence alone, never from this.
const CONTROL_WRITE_DEADLINE: Duration = Duration::from_secs(3);
/// Silence at which probing switches to `FAST_PROBE_INTERVAL`. Nothing the
/// user can see happens here: no status change, no change in how input is
/// handled. Probes into a dead path are free, so this is deliberately eager.
const FAST_PROBE_AFTER: Duration = Duration::from_secs(1);
/// Silence required — together with `RECOVERING_MIN_UNANSWERED_PROBES` —
/// before the path is *presumed dead*: the UI is told it is recovering,
/// geometry and mode changes are coalesced instead of sent, and a full resync
/// is forced when the path returns.
///
/// Pane input keeps flowing across this threshold. The control stream is
/// reliable and ordered, so while the connection lives it delivers keystrokes
/// in order exactly as the old SSH bridge did; input stops only when the
/// connection is abandoned, which ends the session. What this threshold buys
/// is the right to *withhold* state and repaint, and that must not fire on a
/// merely slow path: probes share the connection-level send window with the
/// render streams, so a saturated but live path can starve a pong for over a
/// second.
pub(super) const STALE_CORROBORATED_AFTER: Duration = Duration::from_secs(2);
/// Consecutive unanswered probes required before presuming the path dead.
///
/// Silence alone is not enough evidence, because silence is measured against
/// a wall clock the peer never agreed to: a delayed timer — a stalled
/// runtime, a suspended laptop whose monotonic clock skipped the sleep —
/// can make one outstanding probe look ancient the moment we wake, before the
/// peer has had a single round trip in which to answer. Two probes means at
/// least one full fast round happened while we were actually awake.
const RECOVERING_MIN_UNANSWERED_PROBES: u32 = 2;
/// Probe cadence while the path is stale, for the first `FAST_PROBE_WINDOW`.
/// Detecting the path's *return* is the only latency-critical part of an
/// outage, and probes sent into a dead path cost nothing.
const FAST_PROBE_INTERVAL: Duration = Duration::from_millis(500);
/// How long to probe aggressively before backing off, so a long outage does
/// not hold a mobile radio awake for its whole duration.
const FAST_PROBE_WINDOW: Duration = Duration::from_secs(30);
/// Probe cadence after `FAST_PROBE_WINDOW` of continuous staleness.
const SLOW_PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// Rebind the local socket after this much silence, and again after every
/// further `REBIND_AFTER` the silence continues. Rebinding answers a local
/// address change from sleep or roaming; doing it for a brief flap only
/// forces needless path validation and discards congestion state, and doing
/// it *once* per outage strands a sleep -> tether -> wifi sequence on the
/// second-to-last address.
const REBIND_AFTER: Duration = Duration::from_secs(10);
/// Abandon the connection after this much continuous silence. This, not
/// quinn's idle timeout, is the client's dead-peer bound: the negotiated idle
/// timeout is the minimum of the two peers' advertised values, so it is the
/// server's configured `quic_transport_idle_timeout_seconds` — anywhere from
/// 10 to 600 seconds — and may be far longer than this. `Connection::closed`
/// still reports real failures immediately; this covers only a peer that keeps
/// the transport nominally alive while never answering a probe.
const PATH_LOST_AFTER: Duration = Duration::from_secs(120);

const MAX_RESOURCE_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESOURCE_CACHE_ENTRIES: usize = REMOTE_QUIC_MAX_RESOURCE_INVENTORY;
/// Transport-level idle timeout advertised by the client. Only a backstop: the
/// application probes every `HEARTBEAT_INTERVAL` and gives up after
/// `PATH_LOST_AFTER`, so the app, not quinn, owns liveness detection.
///
/// The negotiated timeout is min(client, server), so any client value below
/// the server's would silently override the configured
/// `quic_transport_idle_timeout_seconds`. Advertising the largest value the
/// server can be configured with, plus slack, keeps the server's setting the
/// one that governs across its whole supported range.
const CLIENT_MAX_IDLE_TIMEOUT: Duration =
    Duration::from_secs(crate::config::REMOTE_TRANSPORT_IDLE_TIMEOUT_MAX_SECONDS + 10);
// Flow-control caps, not allocations. They are deliberately generous: the
// ceiling is send_window/RTT on every path, so shrinking them to suit one
// high-latency profile would throttle low-RTT attach and stall the multi-MB
// graphics frames MAX_GRAPHICS_FRAME_SIZE exists to carry. The per-stream
// window has to cover a full-screen repaint plus an inline graphics payload
// in flight at once, or a high-BDP path blocks the render stream mid-frame.
const CLIENT_STREAM_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;
const CLIENT_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CLIENT_SEND_WINDOW: u64 = 1024 * 1024;
const MAX_PENDING_RENDER_RECORDS: usize = 8;
/// Best-effort window for telling the server we detached when the path is
/// already believed dead. Short on purpose: the local client is leaving either
/// way, and the server reaps the session on its own.
const DETACH_NOTIFY_TIMEOUT: Duration = Duration::from_millis(250);

/// How a `ClientMessage` is treated once the path is presumed dead but the
/// QUIC connection is still alive.
///
/// The input channel is heterogeneous: it carries ephemeral keystrokes,
/// connection-lifetime state, and a graceful-exit request. Treating all of it
/// as keystrokes silently loses geometry and mode changes the server needs to
/// stay correct; treating all of it as state withholds the user's typing from
/// a stream that is still perfectly capable of delivering it.
#[derive(Debug, PartialEq, Eq)]
enum StalePolicy {
    /// Positional, and the wire is the only thing that can decide whether it
    /// still applies. Handed straight to the reliable control stream: while
    /// the connection lives, QUIC delivers it in order, exactly as the SSH
    /// bridge it replaces did. Uncertain input is discarded only by
    /// abandoning the connection, which ends the session and never replays.
    DeliverEphemeral,
    /// Terminal geometry. A state: the newest value is the whole truth, so
    /// intermediate values are coalesced away rather than streamed.
    DeferResize,
    /// A terminal-mode transition (`AttachTerminal`, `ObserveTerminal`,
    /// `ControlTerminal`). These are commands with validation and ownership
    /// side effects, not independent fields: the server rejects an attach
    /// arriving after an observe and drops the client, so only the newest
    /// transition may be replayed.
    DeferTerminalMode,
    /// The user asked to leave; act locally and notify best-effort.
    Detach,
}

fn stale_policy(message: &ClientMessage) -> StalePolicy {
    match message {
        ClientMessage::Detach => StalePolicy::Detach,
        ClientMessage::Resize { .. } => StalePolicy::DeferResize,
        ClientMessage::AttachTerminal { .. }
        | ClientMessage::ObserveTerminal { .. }
        | ClientMessage::ControlTerminal { .. } => StalePolicy::DeferTerminalMode,
        // Keystrokes, mouse reports, scrolls, and pastes. Positional, and the
        // user is entitled to have them arrive if the stream can carry them.
        ClientMessage::Input { .. }
        | ClientMessage::InputEvents { .. }
        | ClientMessage::InputPixels { .. }
        | ClientMessage::AttachScroll { .. }
        | ClientMessage::ClipboardImage { .. } => StalePolicy::DeliverEphemeral,
        // These answer a specific in-flight transfer, which the recovery
        // redraw re-drives from scratch; ordered late delivery is harmless
        // and cheaper to reason about than a second dropping rule.
        ClientMessage::GraphicsTransmissionResult { .. }
        | ClientMessage::GraphicsTransmissionStarted { .. } => StalePolicy::DeliverEphemeral,
        // Handshake-only or generated inside this loop; never arrives here.
        ClientMessage::Hello { .. }
        | ClientMessage::RemoteBootstrap(_)
        | ClientMessage::RemotePing { .. }
        | ClientMessage::SyncRequest => StalePolicy::DeliverEphemeral,
    }
}

/// Connection state withheld while the path is corroborated dead, replayed
/// before the recovery `SyncRequest` so the full redraw is generated against
/// what the user actually has.
///
/// Deliberately two named slots rather than a message list: the only safe
/// replay is at most one terminal-mode transition plus the newest geometry.
#[derive(Debug, Default)]
struct DeferredState {
    resize: Option<ClientMessage>,
    terminal_mode: Option<ClientMessage>,
}
impl DeferredState {
    /// Classifies `message` against the presumed-dead path: coalescable
    /// connection state is absorbed for replay on recovery, and everything
    /// else is handed back for immediate delivery on the still-live control
    /// stream (or, for `Detach`, for the local exit path).
    fn hold(&mut self, message: ClientMessage) -> FilteredInput {
        match stale_policy(&message) {
            StalePolicy::DeferResize => {
                self.resize = Some(message);
                FilteredInput::Absorbed
            }
            // Newest transition replaces any earlier one, across variants:
            // replaying observe-then-control would be rejected as an
            // upgrade and disconnect the client.
            StalePolicy::DeferTerminalMode => {
                self.terminal_mode = Some(message);
                FilteredInput::Absorbed
            }
            StalePolicy::DeliverEphemeral => FilteredInput::Deliver(message),
            StalePolicy::Detach => FilteredInput::Detach(message),
        }
    }

    /// Mode transition first, then geometry: the server validates a mode
    /// change against the client's pending state, and the resize that follows
    /// applies to whichever surface that left it on.
    fn replay(&mut self) -> impl Iterator<Item = ClientMessage> + '_ {
        self.terminal_mode
            .take()
            .into_iter()
            .chain(self.resize.take())
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.resize.is_none() && self.terminal_mode.is_none()
    }
}

/// Outcome of filtering input against current path liveness.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FilteredInput {
    /// Deliver this input message over the live transport.
    Deliver(ClientMessage),
    /// Absorbed: coalesced into the deferred state for replay on recovery.
    Absorbed,
    /// User requested detach while dark; notify best-effort and exit.
    Detach(ClientMessage),
}

/// Outcome of receiving a pong from the remote peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PongOutcome {
    /// Path was healthy; no recovery action required.
    Healthy,
    /// Path had been corroborated dead; replayed messages must be sent
    /// before the recovery SyncRequest.
    Recovered { replay: Vec<ClientMessage> },
}

/// Outcome of a scheduled timer tick for path liveness evaluation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TickOutcome {
    /// Continuous silence exceeded PATH_LOST_AFTER; the connection should be abandoned.
    Lost { silence: Duration },
    /// Scheduled probe to send, along with any threshold notifications.
    Probe {
        message: ClientMessage,
        announce_recovering: bool,
        needs_rebind: bool,
    },
}

/// Owns path liveness monitoring, probe scheduling, silence tracking,
/// outage state progression, and input deferral during outages.
///
/// Owns both probe deadlines (when to send the next probe on a healthy path,
/// and when to judge a probe that has gone unanswered), silence-driven
/// thresholds (announcing path recovery, presuming the path dead, socket
/// rebind, and connection abandonment), and the connection state coalesced
/// while the path is presumed dead.
#[derive(Debug)]
pub(crate) struct PathMonitor {
    /// When the last probe was sent. Drives scheduling only.
    last_probe_at: Instant,
    /// Send time of the oldest probe no pong has retired yet. Drives silence only.
    oldest_unacked_at: Option<Instant>,
    /// How many probes have been sent since the last pong. Corroborates
    /// silence, which a delayed timer can otherwise overstate.
    unanswered_probes: u32,
    /// Instant when silence first exceeded FAST_PROBE_AFTER, starting the
    /// fast-probe window.
    fast_probe_since: Option<Instant>,
    /// Set once the path is presumed dead; gates state coalescing and the
    /// recovery replay plus resync on return. Never gates pane input.
    stale_corroborated: bool,
    /// Instant of the most recent endpoint rebind, so the next one can be
    /// re-armed a further REBIND_AFTER into the same outage.
    rebound_at: Option<Instant>,
    /// Nonce sequence for probe messages.
    next_nonce: u64,
    /// Connection state withheld while the path is presumed dead.
    deferred: DeferredState,
}

impl PathMonitor {
    /// The first probe is due immediately: liveness has to be measured from
    /// connect, not from one HEARTBEAT_INTERVAL later.
    ///
    /// Every threshold here is measured with `Instant`, i.e. CLOCK_MONOTONIC,
    /// which on Linux excludes time the machine spent suspended. A laptop that
    /// sleeps for an hour therefore measures ~0 silence on wake, no matter how
    /// long the peer has actually been unreachable: nothing in this type can
    /// detect the outage until the first post-wake probe round trip fails,
    /// which is why detection is driven by probe *responses* rather than by
    /// elapsed time, and why `RECOVERING_MIN_UNANSWERED_PROBES` refuses to act
    /// on a single stale-looking probe. Deliberate: CLOCK_BOOTTIME would
    /// report the sleep as silence and announce an outage on a path that is
    /// fine, and no clock can shorten the one round trip recovery costs.
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            last_probe_at: now.checked_sub(HEARTBEAT_INTERVAL).unwrap_or(now),
            oldest_unacked_at: None,
            unanswered_probes: 0,
            fast_probe_since: None,
            stale_corroborated: false,
            rebound_at: None,
            next_nonce: 1,
            deferred: DeferredState::default(),
        }
    }

    pub(crate) fn probe_outstanding(&self) -> bool {
        self.oldest_unacked_at.is_some()
    }

    /// How long the peer has been silent, measured from the oldest probe it
    /// has not answered. `None` when nothing is outstanding.
    pub(crate) fn silence(&self, now: Instant) -> Option<Duration> {
        self.oldest_unacked_at
            .and_then(|sent_at| now.checked_duration_since(sent_at))
    }

    #[cfg(test)]
    pub(crate) fn is_stale_corroborated(&self) -> bool {
        self.stale_corroborated
    }

    /// Next instant the loop must wake to send and judge.
    ///
    /// One deadline covers both because sending advances `last_probe_at`: an
    /// unanswered probe is re-evaluated a judge interval after the last send,
    /// and a healthy path is simply probed again a heartbeat later.
    pub(crate) fn wake_at(&self, now: Instant) -> Instant {
        let interval = if self.probe_outstanding() {
            self.judge_interval(now)
        } else {
            HEARTBEAT_INTERVAL
        };
        self.last_probe_at + interval
    }

    /// Long outages back off so a dead radio is not held awake, but only past
    /// the window in which the path plausibly returns soon.
    fn judge_interval(&self, now: Instant) -> Duration {
        match self.fast_probe_since {
            Some(since)
                if now
                    .checked_duration_since(since)
                    .is_some_and(|d| d >= FAST_PROBE_WINDOW) =>
            {
                SLOW_PROBE_INTERVAL
            }
            _ => FAST_PROBE_INTERVAL,
        }
    }

    pub(crate) fn on_probe_sent(&mut self, now: Instant) {
        self.last_probe_at = now;
        // Keep the oldest: it, not the newest, measures the silence.
        self.oldest_unacked_at.get_or_insert(now);
        self.unanswered_probes = self.unanswered_probes.saturating_add(1);
    }

    /// Typing starts the liveness clock if no probe is currently outstanding.
    pub(crate) fn maybe_input_probe(&mut self, now: Instant) -> Option<ClientMessage> {
        if self.probe_outstanding() {
            None
        } else {
            let nonce = self.next_nonce;
            self.next_nonce = self.next_nonce.saturating_add(1);
            self.on_probe_sent(now);
            Some(ClientMessage::RemotePing { nonce })
        }
    }

    /// Filters client input against path liveness.
    ///
    /// Pane input is always delivered: the control stream is reliable and
    /// ordered, so as long as the connection exists it carries keystrokes in
    /// order, and withholding them would lose typing on a link that is merely
    /// slow. Only coalescable connection state (geometry, terminal mode) is
    /// absorbed while the path is presumed dead, and detach passes through for
    /// best-effort delivery plus a local exit.
    pub(crate) fn filter_input(&mut self, input: ClientMessage) -> FilteredInput {
        if self.stale_corroborated {
            self.deferred.hold(input)
        } else {
            FilteredInput::Deliver(input)
        }
    }

    /// Any pong proves liveness now, so it retires every outstanding probe.
    /// If the path had been presumed dead, the coalesced state is returned
    /// to be sent before the recovery SyncRequest.
    pub(crate) fn on_pong(&mut self) -> PongOutcome {
        self.oldest_unacked_at = None;
        self.unanswered_probes = 0;
        self.fast_probe_since = None;
        self.rebound_at = None;
        if std::mem::take(&mut self.stale_corroborated) {
            PongOutcome::Recovered {
                replay: self.deferred.replay().collect(),
            }
        } else {
            PongOutcome::Healthy
        }
    }

    /// Evaluates silence thresholds and produces the next scheduled probe.
    pub(crate) fn on_tick(&mut self, now: Instant) -> TickOutcome {
        let silence = self.silence(now);
        let mut announce_recovering = false;
        let mut needs_rebind = false;

        if let Some(silence) = silence {
            if silence >= PATH_LOST_AFTER {
                return TickOutcome::Lost { silence };
            }
            if silence >= FAST_PROBE_AFTER && self.fast_probe_since.is_none() {
                self.fast_probe_since = Some(now);
            }
            // Two independent pieces of evidence, and the transition is
            // announced exactly once: the probe count is checked before this
            // tick's own probe is sent, so a timer that fired late still owes
            // the peer one honest fast round before the UI repaints.
            if silence >= STALE_CORROBORATED_AFTER
                && self.unanswered_probes >= RECOVERING_MIN_UNANSWERED_PROBES
                && !self.stale_corroborated
            {
                self.stale_corroborated = true;
                announce_recovering = true;
            }
            // Re-armed every REBIND_AFTER of continued silence, not once per
            // outage: sleep -> tether -> wifi changes the local address more
            // than once inside a single outage, and only the rebind that
            // follows the *final* change can recover the connection.
            let rebind_due = match self.rebound_at {
                None => silence >= REBIND_AFTER,
                Some(previous) => now
                    .checked_duration_since(previous)
                    .is_some_and(|since| since >= REBIND_AFTER),
            };
            if rebind_due {
                self.rebound_at = Some(now);
                needs_rebind = true;
            }
        }

        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.saturating_add(1);
        self.on_probe_sent(now);
        TickOutcome::Probe {
            message: ClientMessage::RemotePing { nonce },
            announce_recovering,
            needs_rebind,
        }
    }
}

pub(crate) type ProxyOutputSender = mpsc::Sender<ServerMessage>;

pub(crate) struct ConnectParams {
    pub(crate) bootstrap: RemoteBootstrapRecord,
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) logical_client_id: [u8; crate::protocol::REMOTE_QUIC_ID_BYTES],
    pub(crate) connection_generation: u64,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    pub(crate) cell_width_px: u32,
    pub(crate) cell_height_px: u32,
    pub(crate) keybindings: ClientKeybindings,
}

/// `Debug` so tests can `expect_err` on `connect`; the derive prints only
/// quinn handles and counters, never buffered bytes.
#[derive(Debug)]
pub(crate) struct QuicSession {
    endpoint: Endpoint,
    connection: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    connection_generation: u64,
    resource_cache: Arc<Mutex<ResourceCache>>,
}

#[derive(Debug)]
pub(crate) enum SessionExit {
    RetryFresh(String),
    Rebootstrap(String),
    /// A newer generation of this capability was accepted: another client has
    /// taken the session over. Terminal — reconnecting would fence the client
    /// that just won, which would fence this one straight back.
    Superseded(String),
    Detached,
}

#[derive(Debug, Default)]
pub(crate) struct ResourceCache {
    entries: HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Vec<u8>>,
    order: VecDeque<[u8; REMOTE_QUIC_HASH_BYTES]>,
    bytes: usize,
}

impl ResourceCache {
    pub(crate) fn inventory(&self) -> Vec<[u8; REMOTE_QUIC_HASH_BYTES]> {
        self.order
            .iter()
            .rev()
            .take(REMOTE_QUIC_MAX_RESOURCE_INVENTORY)
            .copied()
            .collect()
    }

    fn get(&mut self, hash: &[u8; REMOTE_QUIC_HASH_BYTES]) -> Option<Vec<u8>> {
        let value = self.entries.get(hash)?.clone();
        self.touch(*hash);
        Some(value)
    }

    fn insert(&mut self, hash: [u8; REMOTE_QUIC_HASH_BYTES], bytes: Vec<u8>) {
        if bytes.len() > REMOTE_QUIC_MAX_RESOURCE_SIZE {
            return;
        }
        if let Some(previous) = self.entries.insert(hash, bytes) {
            self.bytes = self.bytes.saturating_sub(previous.len());
        }
        self.bytes = self
            .bytes
            .saturating_add(self.entries.get(&hash).map_or(0, Vec::len));
        self.touch(hash);
        while self.entries.len() > MAX_RESOURCE_CACHE_ENTRIES
            || self.bytes > MAX_RESOURCE_CACHE_BYTES
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.len());
            }
        }
    }

    fn touch(&mut self, hash: [u8; REMOTE_QUIC_HASH_BYTES]) {
        if let Some(index) = self.order.iter().position(|entry| *entry == hash) {
            self.order.remove(index);
        }
        self.order.push_back(hash);
    }
}

impl QuicSession {
    pub(crate) async fn connect(
        params: ConnectParams,
        resource_cache: Arc<Mutex<ResourceCache>>,
    ) -> Result<(Self, ServerMessage), String> {
        if params.bootstrap.version != PROTOCOL_VERSION {
            return Err(format!(
                "remote bootstrap protocol {}, local protocol {PROTOCOL_VERSION}",
                params.bootstrap.version
            ));
        }
        if params.candidates.is_empty() {
            return Err(
                "remote QUIC bootstrap returned no reachable address candidates".to_owned(),
            );
        }

        let mut errors = Vec::new();
        for candidate in params.candidates {
            let endpoint =
                make_client_endpoint(candidate.ip(), params.bootstrap.certificate_fingerprint)?;
            let connecting = endpoint
                .connect(candidate, "herdr")
                .map_err(|err| format!("failed to start QUIC connection to {candidate}: {err}"))?;
            let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
                Ok(Ok(connection)) => connection,
                Ok(Err(err)) => {
                    errors.push(format!("{candidate}: {err}"));
                    endpoint.close(VarInt::from_u32(0), b"path attempt failed");
                    continue;
                }
                Err(_) => {
                    errors.push(format!("{candidate}: timed out"));
                    endpoint.close(VarInt::from_u32(0), b"path attempt timed out");
                    continue;
                }
            };
            let (mut control_send, mut control_recv) =
                match tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, connection.open_bi()).await {
                    Ok(Ok(streams)) => streams,
                    Ok(Err(err)) => {
                        return Err(abandon(
                            &endpoint,
                            format!("failed to open QUIC control stream: {err}"),
                        ));
                    }
                    Err(_) => {
                        return Err(abandon(
                            &endpoint,
                            "timed out opening QUIC control stream".to_owned(),
                        ));
                    }
                };
            // Heartbeats and keystrokes share this stream. Without a priority
            // above the render stream, a saturated link can queue a pong
            // behind a screen repaint for seconds and manufacture a
            // false-positive path staleness.
            // A closed stream here surfaces on the next write; priority is an
            // optimization, so it is not worth a second error path.
            let _ = control_send.set_priority(PRIORITY_CONTROL);
            let cached_resources = lock(&resource_cache).inventory();
            let hello = RemoteQuicHello {
                version: PROTOCOL_VERSION,
                server_instance_id: params.bootstrap.server_instance_id,
                logical_client_id: params.logical_client_id,
                capability_token: params.bootstrap.capability_token,
                connection_generation: params.connection_generation,
                cols: params.cols,
                rows: params.rows,
                cell_width_px: params.cell_width_px,
                cell_height_px: params.cell_height_px,
                keybindings: params.keybindings.clone(),
                launch_mode: ClientLaunchMode::App,
                cached_resources,
            };
            if let Err(error) = write_async_message(&mut control_send, &hello, MAX_FRAME_SIZE).await
            {
                return Err(abandon(&endpoint, error));
            }
            let welcome: ServerMessage = match tokio::time::timeout(
                CONTROL_HANDSHAKE_TIMEOUT,
                read_async_message(&mut control_recv, MAX_FRAME_SIZE),
            )
            .await
            {
                Ok(Ok(welcome)) => welcome,
                Ok(Err(error)) => return Err(abandon(&endpoint, error)),
                Err(_) => {
                    return Err(abandon(
                        &endpoint,
                        "timed out waiting for remote QUIC welcome".to_owned(),
                    ));
                }
            };
            match &welcome {
                ServerMessage::Welcome {
                    version,
                    error: None,
                    ..
                } if *version == PROTOCOL_VERSION => {}
                ServerMessage::Welcome {
                    version,
                    error: Some(error),
                    ..
                } => {
                    return Err(abandon(
                        &endpoint,
                        format!("remote QUIC server {version} rejected attach: {error}"),
                    ));
                }
                _ => {
                    return Err(abandon(
                        &endpoint,
                        "remote QUIC server sent an invalid welcome".to_owned(),
                    ))
                }
            }
            return Ok((
                Self {
                    endpoint,
                    connection,
                    control_send,
                    control_recv,
                    connection_generation: params.connection_generation,
                    resource_cache,
                },
                welcome,
            ));
        }
        Err(format!(
            "all remote QUIC paths failed: {}",
            errors.join("; ")
        ))
    }

    pub(crate) async fn run(
        mut self,
        mut input_rx: mpsc::Receiver<ClientMessage>,
        output: ProxyOutputSender,
        reconnecting: bool,
    ) -> SessionExit {
        let (control_event_tx, mut control_event_rx) = mpsc::channel(16);
        let mut control_recv = self.control_recv;
        tokio::spawn(async move {
            loop {
                match read_async_message::<ServerMessage>(
                    &mut control_recv,
                    MAX_GRAPHICS_FRAME_SIZE,
                )
                .await
                {
                    Ok(message) => {
                        if control_event_tx
                            .send(ControlEvent::Message(message))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = control_event_tx.send(ControlEvent::Closed(error)).await;
                        break;
                    }
                }
            }
        });

        let (stream_event_tx, mut stream_event_rx) = mpsc::channel(16);
        let connection_for_accept = self.connection.clone();
        tokio::spawn(async move {
            loop {
                match connection_for_accept.accept_uni().await {
                    Ok(stream) => {
                        let stream_event_tx = stream_event_tx.clone();
                        tokio::spawn(async move {
                            read_server_stream(stream, stream_event_tx).await;
                        });
                    }
                    Err(error) => {
                        let _ = stream_event_tx
                            .send(StreamEvent::Closed(error.to_string()))
                            .await;
                        break;
                    }
                }
            }
        });

        // Only pongs retire probes. Inbound render frames must not, or an
        // asymmetric failure — server->client alive, client->server dead —
        // would look healthy forever while keystrokes vanished.
        let mut monitor = PathMonitor::new(Instant::now());
        let mut render_generation = 0u64;
        let mut last_state_revision = 0u64;
        let mut expected_seq = 1u64;
        let mut connected_announced = !reconnecting;
        let mut pending_renders = VecDeque::<RemoteQuicRenderRecord>::new();
        loop {
            tokio::select! {
                input = input_rx.recv() => {
                    let Some(input) = input else {
                        return SessionExit::RetryFresh("local client input channel closed".to_owned());
                    };
                    // Pane input keeps flowing for as long as this connection
                    // exists, presumed-dead path or not: the control stream is
                    // reliable and ordered, so QUIC either delivers a
                    // keystroke in order or the connection dies and the
                    // session ends. Withholding input here would lose typing
                    // on a link that is merely slow, and dropping it after the
                    // write is impossible anyway — quinn owns the bytes and
                    // will retransmit them when the path returns.
                    //
                    // Only coalescable connection state is absorbed (newest
                    // geometry and terminal mode win) and replayed before the
                    // recovery resync, so the full redraw is generated at the
                    // state the user actually has. Uncertain input is never
                    // replayed across a *new* connection: that path exits the
                    // session instead.
                    let (input, detached) = match monitor.filter_input(input) {
                        FilteredInput::Deliver(msg) => {
                            let detached = matches!(msg, ClientMessage::Detach);
                            (msg, detached)
                        }
                        FilteredInput::Absorbed => continue,
                        FilteredInput::Detach(detach) => {
                            let _ = tokio::time::timeout(
                                DETACH_NOTIFY_TIMEOUT,
                                write_async_message(
                                    &mut self.control_send,
                                    &detach,
                                    MAX_FRAME_SIZE,
                                ),
                            )
                            .await;
                            let _ = self.control_send.finish();
                            return SessionExit::Detached;
                        }
                    };
                    match tokio::time::timeout(
                        CONTROL_WRITE_DEADLINE,
                        write_async_message(&mut self.control_send, &input, MAX_GRAPHICS_FRAME_SIZE),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return SessionExit::RetryFresh(error),
                        Err(_) => {
                            return SessionExit::RetryFresh(
                                "remote QUIC control write timed out".to_owned(),
                            );
                        }
                    }
                    if detached {
                        let _ = self.control_send.finish();
                        return SessionExit::Detached;
                    }
                    if let Some(probe) = monitor.maybe_input_probe(Instant::now()) {
                        if let Err(error) = write_async_message(
                            &mut self.control_send,
                            &probe,
                            MAX_FRAME_SIZE,
                        )
                        .await
                        {
                            return SessionExit::RetryFresh(error);
                        }
                    }
                }
                event = control_event_rx.recv() => {
                    let Some(event) = event else {
                        return classify_reader_close(
                            &self.connection,
                            "remote control reader stopped".to_owned(),
                        );
                    };
                    match event {
                        ControlEvent::Message(ServerMessage::RemotePong { nonce: _ }) => {
                            match monitor.on_pong() {
                                PongOutcome::Healthy => {}
                                PongOutcome::Recovered { replay } => {
                                    // Mode transition then geometry, before the
                                    // SyncRequest: the full redraw it triggers must
                                    // be generated against the state the user
                                    // actually has, or recovery paints the
                                    // pre-outage surface and dimensions.
                                    for message in replay {
                                        if let Err(error) = write_async_message(
                                            &mut self.control_send,
                                            &message,
                                            MAX_GRAPHICS_FRAME_SIZE,
                                        )
                                        .await
                                        {
                                            return SessionExit::RetryFresh(error);
                                        }
                                    }
                                    // Coalesced geometry/mode aside, the
                                    // server's render generation may have
                                    // moved on while its frames went nowhere.
                                    // Ask for a fresh generation now the path
                                    // is back; a request sent while dark was
                                    // queued behind the stall, not delivered.
                                    if let Err(error) = write_async_message(
                                        &mut self.control_send,
                                        &ClientMessage::SyncRequest,
                                        MAX_FRAME_SIZE,
                                    )
                                    .await
                                    {
                                        return SessionExit::RetryFresh(error);
                                    }
                                    // The transport is provably back, so say
                                    // so here rather than waiting for a frame
                                    // to flush: the resync above can take a
                                    // whole round trip plus a full repaint,
                                    // and leaving "waiting for the remote
                                    // path" on screen for that long is a lie.
                                    // Idempotent — flush_pending_renders reads
                                    // the same flag, so no duplicate status.
                                    if !connected_announced {
                                        connected_announced = true;
                                        if output
                                            .send(ServerMessage::TransportStatus {
                                                status: RemoteTransportStatus::Connected,
                                                detail: None,
                                            })
                                            .await
                                            .is_err()
                                        {
                                            return SessionExit::Detached;
                                        }
                                    }
                                }
                            }
                        }
                        ControlEvent::Message(message @ ServerMessage::ClientDetached) => {
                            let _ = output.send(message).await;
                            return SessionExit::Detached;
                        }
                        ControlEvent::Message(ServerMessage::ServerShutdown { reason }) => {
                            let detail = reason.unwrap_or_else(|| "remote server restarted".to_owned());
                            return SessionExit::Rebootstrap(detail);
                        }
                        ControlEvent::Message(message) => {
                            if output.send(message).await.is_err() {
                                return SessionExit::Detached;
                            }
                        }
                        ControlEvent::Closed(error) => {
                            return classify_reader_close(&self.connection, error);
                        }
                    }
                }
                event = stream_event_rx.recv() => {
                    let Some(event) = event else {
                        return classify_reader_close(
                            &self.connection,
                            "remote stream reader stopped".to_owned(),
                        );
                    };
                    match event {
                        StreamEvent::Render(record) => {
                            if record.connection_generation != self.connection_generation {
                                continue;
                            }
                            if record.render_generation < render_generation {
                                continue;
                            }
                            if record.state_revision <= last_state_revision {
                                continue;
                            }
                            if record.render_generation == render_generation
                                && last_state_revision != 0
                                && record.state_revision != last_state_revision.saturating_add(1)
                            {
                                let _ = write_async_message(
                                    &mut self.control_send,
                                    &ClientMessage::SyncRequest,
                                    MAX_FRAME_SIZE,
                                )
                                .await;
                                render_generation = render_generation.saturating_add(1);
                                expected_seq = 1;
                                pending_renders.clear();
                                continue;
                            }
                            if record.render_generation > render_generation {
                                if !record.frame.full || record.frame.seq != 1 {
                                    let _ = write_async_message(&mut self.control_send, &ClientMessage::SyncRequest, MAX_FRAME_SIZE).await;
                                    continue;
                                }
                                render_generation = record.render_generation;
                                expected_seq = 1;
                                pending_renders.clear();
                            }
                            if record.frame.seq != expected_seq {
                                let _ = write_async_message(&mut self.control_send, &ClientMessage::SyncRequest, MAX_FRAME_SIZE).await;
                                render_generation = render_generation.saturating_add(1);
                                expected_seq = 1;
                                continue;
                            }
                            last_state_revision = record.state_revision;
                            expected_seq = expected_seq.saturating_add(1);
                            pending_renders.push_back(record);
                            let pending_bytes = pending_renders
                                .iter()
                                .map(|pending| pending.frame.bytes.len())
                                .sum::<usize>();
                            if pending_renders.len() > MAX_PENDING_RENDER_RECORDS
                                || pending_bytes > MAX_GRAPHICS_FRAME_SIZE
                            {
                                return SessionExit::RetryFresh(
                                    "remote graphics resources did not arrive before the bounded render queue filled".to_owned(),
                                );
                            }
                            if flush_pending_renders(
                                &mut pending_renders,
                                &self.resource_cache,
                                &output,
                                &mut connected_announced,
                            )
                            .await
                            .is_err()
                            {
                                return SessionExit::Detached;
                            }
                        }
                        StreamEvent::Resource {
                            connection_generation,
                            hash,
                            bytes,
                        } => {
                            if connection_generation != self.connection_generation
                                || hash_bytes(&bytes) != hash
                            {
                                continue;
                            }
                            lock(&self.resource_cache).insert(hash, bytes);
                            if flush_pending_renders(
                                &mut pending_renders,
                                &self.resource_cache,
                                &output,
                                &mut connected_announced,
                            )
                            .await
                            .is_err()
                            {
                                return SessionExit::Detached;
                            }
                        }
                        StreamEvent::Closed(error) => {
                            // A stream dies either because the connection
                            // died or on its own. The former must reach the
                            // same verdict as the `closed()` arm this event
                            // races, so ask the connection first.
                            if let Some(closed) = self.connection.close_reason() {
                                return classify_close(&closed);
                            }
                            if !pending_renders.is_empty() {
                                return SessionExit::RetryFresh(format!(
                                    "remote graphics resource stream failed: {error}"
                                ));
                            }
                            debug!(%error, "remote QUIC unidirectional stream closed");
                        }
                    }
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(
                    monitor.wake_at(Instant::now()),
                )) => {
                    let now = Instant::now();
                    match monitor.on_tick(now) {
                        TickOutcome::Lost { silence } => {
                            return SessionExit::RetryFresh(format!(
                                "remote QUIC path silent for {silence:?}"
                            ));
                        }
                        TickOutcome::Probe {
                            message,
                            announce_recovering,
                            needs_rebind,
                        } => {
                            if announce_recovering {
                                connected_announced = false;
                                let _ = output
                                    .send(ServerMessage::TransportStatus {
                                        status: RemoteTransportStatus::PathRecovering,
                                        detail: Some("waiting for the remote path".to_owned()),
                                    })
                                    .await;
                            }
                            if needs_rebind {
                                if let Err(error) = rebind_endpoint(
                                    &self.endpoint,
                                    self.connection.remote_address().ip(),
                                ) {
                                    return SessionExit::RetryFresh(format!(
                                        "failed to rebind QUIC path: {error}"
                                    ));
                                }
                            }
                            if let Err(error) = write_async_message(
                                &mut self.control_send,
                                &message,
                                MAX_FRAME_SIZE,
                            )
                            .await
                            {
                                return SessionExit::RetryFresh(error);
                            }
                        }
                    }
                }
                error = self.connection.closed() => {
                    return classify_close(&error);
                }
            }
        }
    }
}

/// Releases a client endpoint whose handshake failed, handing `error` back so
/// the call site stays one expression.
///
/// Dropping an `Endpoint` does not close it: its driver task and UDP socket
/// outlive the handle, so a candidate abandoned mid-handshake would leak both
/// for the life of the process. The connect-timeout path already closes; every
/// other exit from `connect` has to as well, and parallel dialing makes the
/// losers of a race the common case rather than the exception.
fn abandon(endpoint: &Endpoint, error: String) -> String {
    endpoint.close(VarInt::from_u32(0), b"handshake abandoned");
    error
}

/// Decides whether a closed connection can be retried with the credential we
/// hold, needs a fresh bootstrap, or must not be reconnected at all.
///
/// Keyed on the QUIC application close code, never on the reason string: the
/// reason is a human-readable diagnostic the server is free to reword, and
/// matching substrings in it made every log message a load-bearing part of the
/// protocol. Unknown codes and every transport-level failure retry, because
/// re-bootstrapping costs an SSH round trip and only helps when the
/// credential, the protocol, or the server process itself is the problem.
fn classify_close(error: &quinn::ConnectionError) -> SessionExit {
    let detail = error.to_string();
    let quinn::ConnectionError::ApplicationClosed(frame) = error else {
        return SessionExit::RetryFresh(detail);
    };
    match u32::try_from(u64::from(frame.error_code)) {
        // The credential itself is the problem — rejected, from an
        // incompatible build, tied to a process that is gone, or evicted from
        // the server's token table. Redialing with it can only fail again.
        Ok(
            REMOTE_QUIC_CLOSE_AUTH
            | REMOTE_QUIC_CLOSE_PROTOCOL
            | REMOTE_QUIC_CLOSE_SHUTDOWN
            | REMOTE_QUIC_CLOSE_EVICTED,
        ) => SessionExit::Rebootstrap(detail),
        // Another client took the session over. Reconnecting would fence it
        // and invite it to fence us back, forever, so this one stops.
        Ok(REMOTE_QUIC_CLOSE_REPLACED) => SessionExit::Superseded(detail),
        // HANDOFF and RESYNC both want the credential we hold, and so does
        // any code a newer server invents: a redial is the cheap guess.
        _ => SessionExit::RetryFresh(detail),
    }
}

/// Classifies a reader-observed close, which arrives as a formatted string
/// rather than a `ConnectionError`.
///
/// The control and unidirectional readers race `Connection::closed` in the
/// session select. Whoever wins, the outcome must be the same, so the reader
/// branches ask the connection for the real reason instead of trusting their
/// stringified stream error. `close_reason` is `None` only while the
/// connection is still live — a stream that failed on its own — which is a
/// plain retry.
fn classify_reader_close(connection: &Connection, detail: String) -> SessionExit {
    match connection.close_reason() {
        Some(error) => classify_close(&error),
        None => SessionExit::RetryFresh(detail),
    }
}

async fn flush_pending_renders(
    pending: &mut VecDeque<RemoteQuicRenderRecord>,
    cache: &Arc<Mutex<ResourceCache>>,
    output: &ProxyOutputSender,
    connected_announced: &mut bool,
) -> Result<(), ()> {
    loop {
        let Some(record) = pending.front() else {
            return Ok(());
        };
        let graphics = {
            let mut cache = lock(cache);
            let mut graphics = Vec::with_capacity(record.resources.len());
            for resource in &record.resources {
                let Some(bytes) = cache.get(&resource.hash) else {
                    return Ok(());
                };
                graphics.push(bytes);
            }
            graphics
        };
        let Some(record) = pending.pop_front() else {
            return Ok(());
        };
        let frame = reconstruct_frame(record, graphics)?;
        if output.send(ServerMessage::Terminal(frame)).await.is_err() {
            return Err(());
        }
        if !*connected_announced {
            *connected_announced = true;
            if output
                .send(ServerMessage::TransportStatus {
                    status: RemoteTransportStatus::Connected,
                    detail: None,
                })
                .await
                .is_err()
            {
                return Err(());
            }
        }
    }
}

pub(super) fn reconstruct_frame(
    mut record: RemoteQuicRenderRecord,
    graphics: Vec<Vec<u8>>,
) -> Result<crate::protocol::TerminalFrame, ()> {
    if record.resources.is_empty() {
        return Ok(record.frame);
    }
    let stripped = std::mem::take(&mut record.frame.bytes);
    let graphics_bytes = graphics.iter().map(Vec::len).sum::<usize>();
    let mut reconstructed = Vec::with_capacity(stripped.len().saturating_add(graphics_bytes));
    let mut cursor = 0usize;
    for (resource, bytes) in record.resources.iter().zip(graphics) {
        let offset = resource.text_offset as usize;
        if offset < cursor || offset > stripped.len() {
            return Err(());
        }
        reconstructed.extend_from_slice(&stripped[cursor..offset]);
        reconstructed.extend_from_slice(&bytes);
        cursor = offset;
    }
    reconstructed.extend_from_slice(&stripped[cursor..]);
    record.frame.bytes = reconstructed;
    Ok(record.frame)
}

#[derive(Debug)]
enum ControlEvent {
    Message(ServerMessage),
    Closed(String),
}

#[derive(Debug)]
enum StreamEvent {
    Render(RemoteQuicRenderRecord),
    Resource {
        connection_generation: u64,
        hash: [u8; REMOTE_QUIC_HASH_BYTES],
        bytes: Vec<u8>,
    },
    Closed(String),
}

async fn read_server_stream(mut stream: RecvStream, events: mpsc::Sender<StreamEvent>) {
    let header: RemoteQuicStreamHeader = match read_async_message(&mut stream, MAX_FRAME_SIZE).await
    {
        Ok(header) => header,
        Err(error) => {
            let _ = events.send(StreamEvent::Closed(error)).await;
            return;
        }
    };
    match header {
        RemoteQuicStreamHeader::Render { .. } => loop {
            match read_async_message::<RemoteQuicRenderRecord>(&mut stream, MAX_GRAPHICS_FRAME_SIZE)
                .await
            {
                Ok(record) => {
                    if events.send(StreamEvent::Render(record)).await.is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = events.send(StreamEvent::Closed(error)).await;
                    return;
                }
            }
        },
        RemoteQuicStreamHeader::Resource {
            connection_generation,
            render_generation: _,
            hash,
            length,
        } => {
            let length = length as usize;
            if length > REMOTE_QUIC_MAX_RESOURCE_SIZE {
                let _ = stream.stop(VarInt::from_u32(1));
                let _ = events
                    .send(StreamEvent::Closed(format!(
                        "remote resource size {length} exceeds maximum {REMOTE_QUIC_MAX_RESOURCE_SIZE}"
                    )))
                    .await;
                return;
            }
            let mut bytes = vec![0u8; length];
            if let Err(error) = stream.read_exact(&mut bytes).await {
                let _ = events.send(StreamEvent::Closed(error.to_string())).await;
                return;
            }
            let _ = events
                .send(StreamEvent::Resource {
                    connection_generation,
                    hash,
                    bytes,
                })
                .await;
        }
    }
}

fn make_client_endpoint(
    remote_ip: IpAddr,
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
) -> Result<Endpoint, String> {
    let bind_address = match remote_ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let mut endpoint = Endpoint::client(bind_address)
        .map_err(|err| format!("failed to bind local QUIC socket: {err}"))?;
    endpoint.set_default_client_config(client_config(fingerprint)?);
    Ok(endpoint)
}

fn client_config(fingerprint: [u8; REMOTE_QUIC_HASH_BYTES]) -> Result<quinn::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(FingerprintVerifier {
        fingerprint,
        provider: Arc::clone(&provider),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| format!("failed to enable TLS 1.3: {err}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| format!("failed to configure QUIC TLS: {err}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            CLIENT_MAX_IDLE_TIMEOUT
                .try_into()
                .map_err(|_| "QUIC idle timeout is too large".to_owned())?,
        ))
        // No `keep_alive_interval`: the application already probes every
        // HEARTBEAT_INTERVAL on the control stream and judges the answers, so
        // a quinn PING timer would be a second, dumber liveness mechanism —
        // it keeps a dead connection nominally alive without telling anyone,
        // and its traffic is exactly what our probes already provide.
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .max_concurrent_uni_streams(VarInt::from_u32(4))
        .stream_receive_window(VarInt::from_u32(CLIENT_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(CLIENT_RECEIVE_WINDOW))
        .send_window(CLIENT_SEND_WINDOW)
        // Loss-based control (quinn's Cubic default) treats random radio loss
        // as congestion and repeatedly collapses the window; the classic
        // MSS/(RTT*sqrt(p)) ceiling is Reno's, and Cubic's window growth
        // differs, so treat that only as the qualitative direction, not as a
        // predicted rate. BBR paces to measured bottleneck bandwidth instead.
        // quinn documents its BBR as experimental, and this default currently
        // rests on single-trial shaped-link measurements rather than a
        // counterbalanced CUBIC/BBR comparison across RTTs and loads.
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[derive(Debug)]
struct FingerprintVerifier {
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if hash_bytes(end_entity.as_ref()) == self.fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "remote QUIC certificate fingerprint mismatch".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
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
        cert: &CertificateDer<'_>,
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

fn rebind_endpoint(endpoint: &Endpoint, remote_ip: IpAddr) -> Result<(), String> {
    let bind_address = match remote_ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(bind_address)
        .map_err(|err| format!("failed to bind replacement UDP socket: {err}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("failed to configure replacement UDP socket: {err}"))?;
    endpoint
        .rebind(socket)
        .map_err(|err| format!("failed to migrate QUIC endpoint: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier as _;

    #[test]
    fn the_first_probe_is_due_immediately_then_once_per_heartbeat() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        assert_eq!(
            monitor.wake_at(now),
            now,
            "liveness must be measured from connect, not one interval later"
        );
        let tick = monitor.on_tick(now);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 1 },
                announce_recovering: false,
                needs_rebind: false,
            }
        );
        assert_eq!(monitor.on_pong(), PongOutcome::Healthy);
        assert_eq!(
            monitor.wake_at(now),
            now + HEARTBEAT_INTERVAL,
            "an idle healthy path must not be probed more often than this"
        );
    }

    #[test]
    fn every_probe_is_judged_on_the_fast_deadline_whatever_prompted_it() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.on_probe_sent(sent);
        // The bug this pins: deciding cadence before sending left a
        // heartbeat-originated probe unjudged for a whole HEARTBEAT_INTERVAL
        // while an input-originated one was judged in FAST_PROBE_INTERVAL.
        assert_eq!(monitor.wake_at(sent), sent + FAST_PROBE_INTERVAL);
        assert_eq!(
            monitor.silence(sent + Duration::from_secs(1)),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn a_pong_returns_the_path_to_the_healthy_cadence() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.on_probe_sent(sent);
        assert_eq!(monitor.on_pong(), PongOutcome::Healthy);
        assert!(!monitor.probe_outstanding());
        assert_eq!(monitor.silence(sent + Duration::from_secs(9)), None);
        // Measured from the probe that was sent, so one keystroke cannot pin
        // the connection at the fast cadence.
        assert_eq!(monitor.wake_at(sent), sent + HEARTBEAT_INTERVAL);
    }

    #[test]
    fn the_oldest_unanswered_probe_measures_silence() {
        let first = Instant::now();
        let mut monitor = PathMonitor::new(first);
        monitor.on_probe_sent(first);
        monitor.on_probe_sent(first + Duration::from_secs(1));
        assert_eq!(
            monitor.silence(first + Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            "a newer probe must not reset the silence the older one proves"
        );
    }

    #[test]
    fn probing_backs_off_only_after_the_fast_window() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.on_probe_sent(sent);
        let stale_at = sent + FAST_PROBE_AFTER;
        let _ = monitor.on_tick(stale_at);
        assert!(monitor.fast_probe_since.is_some());

        let just_stale = stale_at + (FAST_PROBE_WINDOW - Duration::from_millis(1));
        assert_eq!(monitor.wake_at(just_stale), stale_at + FAST_PROBE_INTERVAL);
        let long_stale = stale_at + FAST_PROBE_WINDOW;
        assert_eq!(
            monitor.wake_at(long_stale),
            stale_at + SLOW_PROBE_INTERVAL,
            "a long outage must stop holding the radio awake at 2 Hz"
        );
    }

    #[test]
    fn path_monitor_outage_lifecycle_and_recovery() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);

        // 1. Initial connect tick sends probe 1 immediately
        assert_eq!(monitor.wake_at(now), now);
        let tick = monitor.on_tick(now);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 1 },
                announce_recovering: false,
                needs_rebind: false,
            }
        );
        assert!(!monitor.is_stale_corroborated());

        // Normal typing when path is healthy delivers directly and does not send duplicate probe
        assert_eq!(
            monitor.filter_input(resize(80)),
            FilteredInput::Deliver(resize(80))
        );
        assert!(monitor
            .maybe_input_probe(now + Duration::from_millis(100))
            .is_none());

        // 2. Advance to FAST_PROBE_AFTER (1s): probing speeds up, but nothing
        // the user can see happens yet — one late pong is not an outage.
        let t1 = now + FAST_PROBE_AFTER;
        let tick = monitor.on_tick(t1);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 2 },
                announce_recovering: false,
                needs_rebind: false,
            }
        );
        assert!(monitor.fast_probe_since.is_some());
        assert!(!monitor.is_stale_corroborated());

        // 3. Advance to STALE_CORROBORATED_AFTER (2s) with two probes already
        // unanswered: the path is presumed dead and announced exactly once.
        let t2 = now + STALE_CORROBORATED_AFTER;
        let tick = monitor.on_tick(t2);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 3 },
                announce_recovering: true,
                needs_rebind: false,
            }
        );
        assert!(monitor.is_stale_corroborated());

        // Presumed dead but still connected: keystrokes go out on the reliable
        // control stream, geometry is coalesced, detach is handed back.
        assert_eq!(
            monitor.filter_input(ClientMessage::Input { data: vec![b'x'] }),
            FilteredInput::Deliver(ClientMessage::Input { data: vec![b'x'] })
        );
        assert_eq!(monitor.filter_input(resize(120)), FilteredInput::Absorbed);
        assert_eq!(
            monitor.filter_input(ClientMessage::Detach),
            FilteredInput::Detach(ClientMessage::Detach)
        );

        // A second announcement must not fire while the path stays dead, or
        // the status line thrashes for the whole outage.
        let tick = monitor.on_tick(t2 + FAST_PROBE_INTERVAL);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 4 },
                announce_recovering: false,
                needs_rebind: false,
            }
        );

        // 4. Advance to REBIND_AFTER (10s): requests a socket rebind
        let t10 = now + REBIND_AFTER;
        let tick = monitor.on_tick(t10);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 5 },
                announce_recovering: false,
                needs_rebind: true,
            }
        );
        // Rebinding again immediately would only discard congestion state.
        let t11 = t10 + Duration::from_secs(1);
        let tick = monitor.on_tick(t11);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 6 },
                announce_recovering: false,
                needs_rebind: false,
            }
        );

        // 5. Pong arrives! Path recovers and replays the coalesced geometry.
        // The keystroke is not in the replay: it was delivered when typed.
        let pong = monitor.on_pong();
        assert_eq!(
            pong,
            PongOutcome::Recovered {
                replay: vec![resize(120)]
            }
        );
        assert!(!monitor.is_stale_corroborated());
        assert!(!monitor.probe_outstanding());
        assert_eq!(monitor.wake_at(t11), t11 + HEARTBEAT_INTERVAL);

        // 6. Check lost outcome after PATH_LOST_AFTER
        monitor.on_probe_sent(t11);
        let t_lost = t11 + PATH_LOST_AFTER;
        assert_eq!(
            monitor.on_tick(t_lost),
            TickOutcome::Lost {
                silence: PATH_LOST_AFTER
            }
        );
    }

    #[test]
    fn stale_path_policy_separates_input_from_connection_state() {
        assert_eq!(
            stale_policy(&ClientMessage::Input { data: vec![b'y'] }),
            StalePolicy::DeliverEphemeral,
            "a live control stream can still carry keystrokes in order"
        );
        assert_eq!(
            stale_policy(&ClientMessage::Detach),
            StalePolicy::Detach,
            "detach must never be swallowed with pane input"
        );
        assert_eq!(
            stale_policy(&ClientMessage::Resize {
                cols: 80,
                rows: 24,
                cell_width_px: 8,
                cell_height_px: 16,
            }),
            StalePolicy::DeferResize,
            "geometry outlives the outage and must reach the server before the redraw"
        );
    }

    /// Presumed-dead is a rendering statement, not an input statement: as long
    /// as the connection exists, QUIC's reliable ordered control stream
    /// delivers typing exactly as the SSH bridge did. Dropping it here cost
    /// the user keystrokes on any link slow enough to starve a pong.
    #[test]
    fn ephemeral_input_is_delivered_while_the_path_is_presumed_dead() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        monitor.on_probe_sent(now);
        monitor.on_probe_sent(now + FAST_PROBE_INTERVAL);
        let _ = monitor.on_tick(now + STALE_CORROBORATED_AFTER);
        assert!(monitor.is_stale_corroborated());

        for input in [
            ClientMessage::Input {
                data: b"git commit\r".to_vec(),
            },
            ClientMessage::InputEvents { events: Vec::new() },
            ClientMessage::AttachScroll {
                source: crate::protocol::AttachScrollSource::Wheel,
                direction: crate::protocol::AttachScrollDirection::Up,
                lines: 3,
                column: Some(4),
                row: Some(9),
                modifiers: 0,
            },
            ClientMessage::ClipboardImage {
                extension: "png".to_owned(),
                data: vec![0u8; 8],
            },
        ] {
            assert_eq!(
                monitor.filter_input(input.clone()),
                FilteredInput::Deliver(input.clone()),
                "{input:?} must keep flowing while the connection is alive"
            );
        }

        // Nothing was withheld, so recovery replays only coalesced state.
        assert_eq!(monitor.on_pong(), PongOutcome::Recovered { replay: vec![] });
    }

    /// A timer that fires late — a stalled runtime, a laptop resuming from
    /// sleep — can make a single outstanding probe look ancient before the
    /// peer has had one round trip in which to answer. Announcing on that
    /// evidence repaints the UI for a path that is fine.
    #[test]
    fn one_unanswered_probe_never_announces_however_old_it_looks() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.on_probe_sent(sent);

        let long_after = sent + STALE_CORROBORATED_AFTER * 10;
        let tick = monitor.on_tick(long_after);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 1 },
                announce_recovering: false,
                needs_rebind: true,
            },
            "one probe is not evidence of an outage, however stale it looks"
        );
        assert!(!monitor.is_stale_corroborated());

        // The probe this tick sent is the second one, so the next round has
        // the two independent failures the announcement requires.
        let next = long_after + FAST_PROBE_INTERVAL;
        let tick = monitor.on_tick(next);
        assert_eq!(
            tick,
            TickOutcome::Probe {
                message: ClientMessage::RemotePing { nonce: 2 },
                announce_recovering: true,
                needs_rebind: false,
            }
        );
        assert!(monitor.is_stale_corroborated());
    }

    /// A single sleep -> tether -> wifi sequence changes the local address more
    /// than once inside one outage, and only the rebind that follows the last
    /// change can revive the connection.
    #[test]
    fn rebind_is_re_armed_every_interval_of_continued_silence() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.on_probe_sent(sent);

        let mut rebinds = Vec::new();
        let mut elapsed = Duration::ZERO;
        // Walk the whole outage at the fast cadence, which is the shortest
        // tick spacing and so the strictest test of the re-arm window.
        while elapsed < PATH_LOST_AFTER {
            elapsed += FAST_PROBE_INTERVAL;
            match monitor.on_tick(sent + elapsed) {
                TickOutcome::Probe {
                    needs_rebind: true, ..
                } => rebinds.push(elapsed),
                TickOutcome::Probe { .. } => {}
                TickOutcome::Lost { .. } => break,
            }
        }
        assert_eq!(
            rebinds,
            vec![
                REBIND_AFTER,
                REBIND_AFTER * 2,
                REBIND_AFTER * 3,
                REBIND_AFTER * 4,
                REBIND_AFTER * 5,
                REBIND_AFTER * 6,
                REBIND_AFTER * 7,
                REBIND_AFTER * 8,
                REBIND_AFTER * 9,
                REBIND_AFTER * 10,
                REBIND_AFTER * 11,
            ],
            "rebind must re-arm every REBIND_AFTER of silence up to PATH_LOST_AFTER"
        );

        // A pong disarms it: the next outage starts its own schedule.
        let mut monitor = PathMonitor::new(sent);
        monitor.on_probe_sent(sent);
        let first = sent + REBIND_AFTER;
        assert!(matches!(
            monitor.on_tick(first),
            TickOutcome::Probe {
                needs_rebind: true,
                ..
            }
        ));
        let _ = monitor.on_pong();
        monitor.on_probe_sent(first);
        assert!(
            matches!(
                monitor.on_tick(first + FAST_PROBE_INTERVAL),
                TickOutcome::Probe {
                    needs_rebind: false,
                    ..
                }
            ),
            "a recovered path must not inherit the previous outage's rebind clock"
        );
    }

    /// The reason string is a diagnostic the server may reword at will, so the
    /// classification hangs off the numeric close code. Every code the server
    /// can send is pinned here: getting this wrong either loops the client
    /// through a doomed reconnect or throws away a still-valid credential and
    /// an SSH round trip.
    #[test]
    fn close_classification_follows_the_application_code_not_the_reason() {
        use super::super::quic_policy::{REMOTE_QUIC_CLOSE_HANDOFF, REMOTE_QUIC_CLOSE_RESYNC};

        let closed = |code: u32, reason: &'static str| {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: VarInt::from_u32(code),
                reason: bytes::Bytes::from_static(reason.as_bytes()),
            })
        };

        for code in [REMOTE_QUIC_CLOSE_HANDOFF, REMOTE_QUIC_CLOSE_RESYNC, 0xdead] {
            assert!(
                matches!(
                    classify_close(&closed(code, "capability protocol server instance")),
                    SessionExit::RetryFresh(_)
                ),
                "code {code:#x} must reconnect with the credential we hold, whatever the reason says"
            );
        }

        for code in [
            REMOTE_QUIC_CLOSE_AUTH,
            REMOTE_QUIC_CLOSE_PROTOCOL,
            REMOTE_QUIC_CLOSE_SHUTDOWN,
            REMOTE_QUIC_CLOSE_EVICTED,
        ] {
            assert!(
                matches!(
                    classify_close(&closed(code, "nothing quotable here")),
                    SessionExit::Rebootstrap(_)
                ),
                "code {code:#x} invalidates the credential and must re-bootstrap"
            );
        }

        // Two clients that both redial on REPLACED fence each other forever:
        // each reconnect makes a newer generation that evicts the other.
        assert!(
            matches!(
                classify_close(&closed(REMOTE_QUIC_CLOSE_REPLACED, "replaced")),
                SessionExit::Superseded(_)
            ),
            "a superseded generation must stop, not race the client that took over"
        );

        assert!(
            matches!(
                classify_close(&quinn::ConnectionError::TimedOut),
                SessionExit::RetryFresh(_)
            ),
            "a transport timeout says nothing about the credential"
        );
    }

    fn resize(cols: u16) -> ClientMessage {
        ClientMessage::Resize {
            cols,
            rows: 24,
            cell_width_px: 8,
            cell_height_px: 16,
        }
    }

    #[test]
    fn deferred_resize_keeps_only_the_newest_geometry() {
        let mut deferred = DeferredState::default();
        assert_eq!(deferred.hold(resize(80)), FilteredInput::Absorbed);
        assert_eq!(deferred.hold(resize(120)), FilteredInput::Absorbed);
        assert_eq!(deferred.replay().collect::<Vec<_>>(), vec![resize(120)]);
    }

    #[test]
    fn deferred_terminal_mode_replaces_across_variants() {
        let mut deferred = DeferredState::default();
        assert_eq!(
            deferred.hold(ClientMessage::ObserveTerminal {
                target: "pane-1".to_owned(),
            }),
            FilteredInput::Absorbed
        );
        assert_eq!(
            deferred.hold(ClientMessage::ControlTerminal {
                target: "pane-1".to_owned(),
                takeover: true,
            }),
            FilteredInput::Absorbed
        );
        // Replaying the observe first would be rejected as an illegal upgrade
        // and would disconnect the client, so only the newest survives.
        assert_eq!(
            deferred.replay().collect::<Vec<_>>(),
            vec![ClientMessage::ControlTerminal {
                target: "pane-1".to_owned(),
                takeover: true,
            }]
        );
    }

    #[test]
    fn deferred_replay_sends_mode_before_geometry() {
        let mut deferred = DeferredState::default();
        assert_eq!(deferred.hold(resize(100)), FilteredInput::Absorbed);
        assert_eq!(
            deferred.hold(ClientMessage::AttachTerminal {
                terminal_id: "t1".to_owned(),
                takeover: false,
            }),
            FilteredInput::Absorbed
        );
        let replayed = deferred.replay().collect::<Vec<_>>();
        assert!(
            matches!(replayed.first(), Some(ClientMessage::AttachTerminal { .. })),
            "mode transition must precede the resize it applies to: {replayed:?}"
        );
        assert_eq!(replayed.len(), 2);
        assert!(deferred.is_empty(), "replay must consume the held state");
    }

    #[test]
    fn ephemeral_input_passes_through_while_deferred_state_accumulates() {
        let mut deferred = DeferredState::default();
        assert_eq!(deferred.hold(resize(90)), FilteredInput::Absorbed);
        for ephemeral in [
            ClientMessage::Input { data: vec![b'q'] },
            ClientMessage::InputEvents { events: Vec::new() },
            ClientMessage::ClipboardImage {
                extension: "png".to_owned(),
                data: vec![0u8; 8],
            },
        ] {
            assert_eq!(
                deferred.hold(ephemeral.clone()),
                FilteredInput::Deliver(ephemeral),
                "input is the transport's job to deliver, not this type's to hoard"
            );
        }
        // Only coalescable state is held back.
        assert_eq!(deferred.replay().collect::<Vec<_>>(), vec![resize(90)]);
    }

    #[test]
    fn detach_is_never_absorbed_by_the_stale_path() {
        let mut deferred = DeferredState::default();
        assert_eq!(
            deferred.hold(ClientMessage::Detach),
            FilteredInput::Detach(ClientMessage::Detach),
            "detach must be handed back so the session can exit locally"
        );
        assert!(deferred.is_empty());
    }

    #[test]
    fn pinned_verifier_rejects_a_different_certificate() {
        let expected = hash_bytes(b"expected certificate");
        let verifier = FingerprintVerifier {
            fingerprint: expected,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let wrong = CertificateDer::from(vec![1, 2, 3]);
        assert!(verifier
            .verify_server_cert(
                &wrong,
                &[],
                &ServerName::try_from("herdr").expect("server name"),
                &[],
                UnixTime::since_unix_epoch(Duration::ZERO),
            )
            .is_err());
    }

    #[test]
    fn resource_cache_is_bounded_and_content_addressed() {
        let mut cache = ResourceCache::default();
        for value in 0..300u16 {
            let bytes = vec![(value & 0xff) as u8; 4];
            cache.insert(hash_bytes(&value.to_le_bytes()), bytes);
        }
        assert!(cache.entries.len() <= MAX_RESOURCE_CACHE_ENTRIES);
        assert!(cache.bytes <= MAX_RESOURCE_CACHE_BYTES);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_round_trip_reconstructs_graphics_before_publishing_frame() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);

        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (server_event_tx, mut server_event_rx) = mpsc::channel(8);
        let server = crate::server::remote_quic::RemoteQuicServer::start(&config, server_event_tx)
            .expect("start QUIC server");
        let logical_client_id = [7; crate::protocol::REMOTE_QUIC_ID_BYTES];
        let bootstrap = server
            .bootstrap(crate::protocol::RemoteBootstrapRequest {
                session: crate::session::active_name()
                    .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned()),
                logical_client_id,
            })
            .expect("bootstrap QUIC client");
        let cache = Arc::new(Mutex::new(ResourceCache::default()));
        let (session, welcome) = QuicSession::connect(
            ConnectParams {
                bootstrap,
                candidates: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))],
                logical_client_id,
                connection_generation: 1,
                cols: 80,
                rows: 24,
                cell_width_px: 8,
                cell_height_px: 16,
                keybindings: ClientKeybindings::Server,
            },
            cache,
        )
        .await
        .expect("connect QUIC client");
        assert!(matches!(
            welcome,
            ServerMessage::Welcome { error: None, .. }
        ));

        let writer = match tokio::time::timeout(Duration::from_secs(2), server_event_rx.recv())
            .await
            .expect("client connection event timeout")
            .expect("client connection event")
        {
            crate::server::client_transport::ServerEvent::ClientConnected { writer, .. } => writer,
            _ => panic!("expected QUIC client connection event"),
        };
        let (_input_tx, input_rx) = mpsc::channel(4);
        let (output_tx, mut output_rx) = mpsc::channel(4);
        let session_task = tokio::spawn(session.run(input_rx, output_tx, false));

        let expected = b"before\x1b_Gf=100,i=3;AAAA\x1b\\middle\x1b_Ga=p,i=3\x1b\\after".to_vec();
        let mut framed = Vec::new();
        crate::protocol::write_message(
            &mut framed,
            &ServerMessage::Terminal(crate::protocol::TerminalFrame {
                seq: 1,
                width: 80,
                height: 24,
                full: true,
                bytes: expected.clone(),
            }),
        )
        .expect("frame terminal message");
        writer.render.try_send(framed).expect("queue QUIC render");

        let delivered = tokio::time::timeout(Duration::from_secs(2), output_rx.recv())
            .await
            .expect("render delivery timeout")
            .expect("render output");
        let ServerMessage::Terminal(frame) = delivered else {
            panic!("expected terminal frame");
        };
        assert_eq!(frame.bytes, expected);

        let mut framed = Vec::new();
        crate::protocol::write_message(&mut framed, &ServerMessage::ClientDetached)
            .expect("frame server detach");
        writer.control.send(framed).expect("send server detach");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), output_rx.recv())
                .await
                .expect("detach delivery timeout"),
            Some(ServerMessage::ClientDetached)
        ));
        assert!(matches!(
            session_task.await.expect("session task"),
            SessionExit::Detached
        ));
    }

    /// A resource far larger than the connection send window is still spliced
    /// back into its referencing frame, and the session survives it while
    /// render traffic runs concurrently.
    ///
    /// This does NOT verify the `control > resource > render` stream priority
    /// ordering, and cannot: on loopback there is no bandwidth bottleneck for
    /// priorities to arbitrate, and `publish_render`'s single-slot busy flag
    /// keeps only one render record in flight, so the render stream cannot
    /// out-compete the resource regardless of priority. Verified by inverting
    /// `PRIORITY_RESOURCE` to -10 and observing this test still pass.
    /// Protecting that ordering needs a shaped bottleneck, which is the
    /// `HERDR_BENCH_KERNEL_SHAPING` netem harness rather than a unit test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_resource_is_reconstructed_and_the_session_survives() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (server_event_tx, mut server_event_rx) = mpsc::channel(8);
        let server = crate::server::remote_quic::RemoteQuicServer::start(&config, server_event_tx)
            .expect("start QUIC server");
        let logical_client_id = [21; crate::protocol::REMOTE_QUIC_ID_BYTES];
        let bootstrap = server
            .bootstrap(crate::protocol::RemoteBootstrapRequest {
                session: crate::session::active_name()
                    .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned()),
                logical_client_id,
            })
            .expect("bootstrap QUIC client");
        let (session, _) = QuicSession::connect(
            ConnectParams {
                bootstrap,
                candidates: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))],
                logical_client_id,
                connection_generation: 1,
                cols: 80,
                rows: 24,
                cell_width_px: 8,
                cell_height_px: 16,
                keybindings: ClientKeybindings::Server,
            },
            Arc::new(Mutex::new(ResourceCache::default())),
        )
        .await
        .expect("connect QUIC client");
        let writer = match tokio::time::timeout(Duration::from_secs(2), server_event_rx.recv())
            .await
            .expect("client connection event timeout")
            .expect("client connection event")
        {
            crate::server::client_transport::ServerEvent::ClientConnected { writer, .. } => writer,
            _ => panic!("expected QUIC client connection event"),
        };
        let (input_tx, input_rx) = mpsc::channel(4);
        let (output_tx, mut output_rx) = mpsc::channel(64);
        let session_task = tokio::spawn(session.run(input_rx, output_tx, false));

        // Larger than the server's 4 MiB connection send window, so the window
        // itself is the contended resource and stream priority is what decides
        // whether this transfer ever finishes. On loopback there is no
        // bandwidth bottleneck, so without exceeding the window the ordering
        // would never be exercised.
        let payload = vec![b'A'; 8 * 1024 * 1024];
        let mut with_resource = b"head\x1b_Gf=100,i=9;".to_vec();
        with_resource.extend_from_slice(&payload);
        with_resource.extend_from_slice(b"\x1b\\tail");
        writer
            .render
            .try_send(framed_terminal(1, true, with_resource.clone()))
            .expect("queue resource-bearing render");

        // Keep the render stream busy for the whole transfer with frames big
        // enough to compete for the same window. `try_send` is a single slot,
        // so Full is the expected steady state and is ignored.
        let saturator = {
            let writer = writer.clone();
            tokio::spawn(async move {
                let busy = vec![b'B'; 64 * 1024];
                for seq in 2..2_000u64 {
                    let _ = writer
                        .render
                        .try_send(framed_terminal(seq, false, busy.clone()));
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };

        let delivered = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match output_rx.recv().await {
                    Some(ServerMessage::Terminal(frame)) if frame.seq == 1 => break frame,
                    Some(_) => {}
                    None => panic!("session output closed before the resource frame arrived"),
                }
            }
        })
        .await
        .expect("resource-bearing frame was never reconstructed");
        assert_eq!(
            delivered.bytes, with_resource,
            "resource was not spliced back into its referencing frame"
        );

        saturator.abort();
        input_tx
            .send(ClientMessage::Detach)
            .await
            .expect("send detach");
        // The session must still be alive to observe the detach: a starved
        // resource would have exited through RetryFresh instead.
        assert!(
            matches!(
                session_task.await.expect("session task"),
                SessionExit::Detached
            ),
            "session did not survive a saturated resource transfer"
        );
    }

    /// A live session fenced by a newer generation of its own capability must
    /// stop, and must reach that verdict whichever select arm observes the
    /// close first.
    ///
    /// The control reader, the uni-stream acceptor, and `Connection::closed`
    /// all wake on the same close and race into the same `select!`. The
    /// readers only carry a formatted string, so unless every one of them
    /// consults the connection's close code, the session's exit is decided by
    /// a scheduler coin flip: here, between stopping and immediately redialing
    /// to fence the client that just took over.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_superseded_generation_stops_whichever_reader_sees_the_close() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (server_event_tx, mut server_event_rx) = mpsc::channel(16);
        let server = crate::server::remote_quic::RemoteQuicServer::start(&config, server_event_tx)
            .expect("start QUIC server");
        let logical_client_id = [31; crate::protocol::REMOTE_QUIC_ID_BYTES];
        let bootstrap = server
            .bootstrap(crate::protocol::RemoteBootstrapRequest {
                session: crate::session::active_name()
                    .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned()),
                logical_client_id,
            })
            .expect("bootstrap QUIC client");
        // Same capability, later generation: exactly what a second local proxy
        // attaching to this session does.
        let dial = |connection_generation: u64| {
            let bootstrap = bootstrap.clone();
            async move {
                QuicSession::connect(
                    ConnectParams {
                        bootstrap,
                        candidates: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))],
                        logical_client_id,
                        connection_generation,
                        cols: 80,
                        rows: 24,
                        cell_width_px: 8,
                        cell_height_px: 16,
                        keybindings: ClientKeybindings::Server,
                    },
                    Arc::new(Mutex::new(ResourceCache::default())),
                )
                .await
                .expect("connect QUIC client")
                .0
            }
        };

        let first = dial(1).await;
        let (_input_tx, input_rx) = mpsc::channel(4);
        let (output_tx, _output_rx) = mpsc::channel(16);
        let session_task = tokio::spawn(first.run(input_rx, output_tx, false));

        let second = dial(2).await;
        let exit = tokio::time::timeout(Duration::from_secs(5), session_task)
            .await
            .expect("superseded session never exited")
            .expect("session task");
        assert!(
            matches!(exit, SessionExit::Superseded(_)),
            "a fenced generation must not redial and fence the client that replaced it: {exit:?}"
        );

        // The same close observed through a reader event rather than the
        // `closed()` arm: the string says nothing, so the branch has to ask the
        // connection.
        let fenced = second.connection.clone();
        let _third = dial(3).await;
        let closed = tokio::time::timeout(Duration::from_secs(5), fenced.closed())
            .await
            .expect("second generation was never fenced");
        assert!(
            matches!(
                classify_reader_close(&fenced, "remote control reader stopped".to_owned()),
                SessionExit::Superseded(_)
            ),
            "reader-observed close must be classified by the connection's code, not its text: \
             {closed}"
        );

        while server_event_rx.try_recv().is_ok() {}
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_render_stream_does_not_block_control_or_input() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (server_event_tx, mut server_event_rx) = mpsc::channel(16);
        let server = crate::server::remote_quic::RemoteQuicServer::start(&config, server_event_tx)
            .expect("start QUIC server");
        let logical_client_id = [8; crate::protocol::REMOTE_QUIC_ID_BYTES];
        let bootstrap = server
            .bootstrap(crate::protocol::RemoteBootstrapRequest {
                session: crate::session::active_name()
                    .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned()),
                logical_client_id,
            })
            .expect("bootstrap QUIC client");
        let endpoint = make_client_endpoint(
            Ipv4Addr::LOCALHOST.into(),
            bootstrap.certificate_fingerprint,
        )
        .expect("create QUIC client endpoint");
        let connection = endpoint
            .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), "herdr")
            .expect("start QUIC connection")
            .await
            .expect("connect QUIC client");
        let (mut control_send, mut control_recv) =
            connection.open_bi().await.expect("open control stream");
        write_async_message(
            &mut control_send,
            &RemoteQuicHello {
                version: PROTOCOL_VERSION,
                server_instance_id: bootstrap.server_instance_id,
                logical_client_id,
                capability_token: bootstrap.capability_token,
                connection_generation: 1,
                cols: 80,
                rows: 24,
                cell_width_px: 8,
                cell_height_px: 16,
                keybindings: ClientKeybindings::Server,
                launch_mode: ClientLaunchMode::App,
                cached_resources: Vec::new(),
            },
            MAX_FRAME_SIZE,
        )
        .await
        .expect("send QUIC hello");
        assert!(matches!(
            read_async_message::<ServerMessage>(&mut control_recv, MAX_GRAPHICS_FRAME_SIZE)
                .await
                .expect("read QUIC welcome"),
            ServerMessage::Welcome { error: None, .. }
        ));
        let writer = match tokio::time::timeout(Duration::from_secs(2), server_event_rx.recv())
            .await
            .expect("client connection event timeout")
            .expect("client connection event")
        {
            crate::server::client_transport::ServerEvent::ClientConnected { writer, .. } => writer,
            _ => panic!("expected QUIC client connection event"),
        };

        let large_frame = vec![b'x'; 2 * 1024 * 1024];
        writer
            .render
            .try_send(framed_terminal(1, true, large_frame.clone()))
            .expect("queue blocking render");
        let mut render_stream =
            tokio::time::timeout(Duration::from_secs(2), connection.accept_uni())
                .await
                .expect("render stream open timeout")
                .expect("accept render stream");
        assert!(matches!(
            read_async_message::<RemoteQuicStreamHeader>(
                &mut render_stream,
                MAX_GRAPHICS_FRAME_SIZE
            )
            .await
            .expect("read render stream header"),
            RemoteQuicStreamHeader::Render { .. }
        ));
        assert!(matches!(
            writer
                .render
                .try_send(framed_terminal(2, false, b"newer".to_vec())),
            Err(std::sync::mpsc::TrySendError::Full(_))
        ));

        let mut control = Vec::new();
        crate::protocol::write_message(
            &mut control,
            &ServerMessage::WindowTitle {
                title: Some("control-progress".to_owned()),
            },
        )
        .expect("frame control message");
        writer.control.send(control).expect("queue control message");
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                read_async_message::<ServerMessage>(&mut control_recv, MAX_FRAME_SIZE),
            )
            .await
            .expect("control progress timeout")
            .expect("read control message"),
            ServerMessage::WindowTitle { title: Some(title) } if title == "control-progress"
        ));

        write_async_message(
            &mut control_send,
            &ClientMessage::Input {
                data: b"input-progress".to_vec(),
            },
            MAX_FRAME_SIZE,
        )
        .await
        .expect("send input while render is stalled");
        let input = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match server_event_rx.recv().await {
                    Some(crate::server::client_transport::ServerEvent::ClientInput {
                        data,
                        ..
                    }) => break data,
                    Some(_) => {}
                    None => panic!("server event channel closed"),
                }
            }
        })
        .await
        .expect("input progress timeout");
        assert_eq!(input, b"input-progress");

        let record = tokio::time::timeout(
            Duration::from_secs(2),
            read_async_message::<RemoteQuicRenderRecord>(
                &mut render_stream,
                MAX_GRAPHICS_FRAME_SIZE,
            ),
        )
        .await
        .expect("render resume timeout")
        .expect("read resumed render");
        assert_eq!(record.frame.bytes, large_frame);
        write_async_message(&mut control_send, &ClientMessage::Detach, MAX_FRAME_SIZE)
            .await
            .expect("send detach");
    }

    #[derive(Clone, Copy)]
    enum NetworkMode {
        Online,
        Degraded,
        Blackhole,
    }

    async fn run_udp_proxy(
        socket: Arc<tokio::net::UdpSocket>,
        server: SocketAddr,
        mode: tokio::sync::watch::Receiver<NetworkMode>,
    ) {
        let mut client = None;
        let mut packet_index = 0u64;
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let target = if source == server {
                let Some(client) = client else {
                    continue;
                };
                client
            } else {
                client = Some(source);
                server
            };
            packet_index = packet_index.saturating_add(1);
            let current_mode = *mode.borrow();
            if matches!(current_mode, NetworkMode::Blackhole)
                || matches!(current_mode, NetworkMode::Degraded) && packet_index.is_multiple_of(11)
            {
                continue;
            }
            let packet = buffer[..length].to_vec();
            let socket = Arc::clone(&socket);
            let delay = if matches!(current_mode, NetworkMode::Degraded)
                && packet_index.is_multiple_of(4)
            {
                Duration::from_millis(50)
            } else {
                Duration::ZERO
            };
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = socket.send_to(&packet, target).await;
            });
        }
    }

    fn framed_terminal(seq: u64, full: bool, bytes: Vec<u8>) -> Vec<u8> {
        let mut framed = Vec::new();
        crate::protocol::write_message(
            &mut framed,
            &ServerMessage::Terminal(crate::protocol::TerminalFrame {
                seq,
                width: 80,
                height: 24,
                full,
                bytes,
            }),
        )
        .expect("frame terminal message");
        framed
    }

    type CanonicalCell = (
        String,
        crate::ghostty::CellBasicData,
        Option<crate::ghostty::RgbColor>,
        Option<crate::ghostty::RgbColor>,
    );

    #[derive(Debug, PartialEq, Eq)]
    struct CanonicalTerminalState {
        active_screen: crate::ghostty::ActiveScreen,
        cursor: Option<crate::ghostty::CursorViewport>,
        cursor_visible: bool,
        cursor_blinking: bool,
        cursor_style: crate::ghostty::CursorVisualStyle,
        colors: crate::ghostty::RenderColors,
        screen_text: Vec<crate::ghostty::ScreenTextRow>,
        hyperlinks: Vec<Vec<Option<String>>>,
        modes: [bool; 5],
        rows: Vec<Vec<CanonicalCell>>,
    }

    fn canonical_terminal_state(bytes: &[u8]) -> CanonicalTerminalState {
        let mut terminal =
            crate::ghostty::Terminal::new(80, 24, 1_000_000).expect("create canonical terminal");
        terminal.write(bytes);
        let mut render_state =
            crate::ghostty::RenderState::new().expect("create canonical render state");
        render_state
            .update(&terminal)
            .expect("update canonical render state");
        let mut row_iterator =
            crate::ghostty::RowIterator::new().expect("create canonical row iterator");
        let mut row_cells = crate::ghostty::RowCells::new().expect("create canonical row cells");
        let mut rows = Vec::new();
        {
            let mut row = render_state
                .populate_row_iterator(&mut row_iterator)
                .expect("populate canonical rows");
            while row.next() {
                let mut cells = row
                    .populate_cells(&mut row_cells)
                    .expect("populate canonical cells");
                let mut snapshot = Vec::new();
                while cells.next() {
                    snapshot.push((
                        cells.grapheme_text().expect("read canonical grapheme"),
                        cells.basic_data().expect("read canonical cell"),
                        cells.fg_color().expect("read canonical foreground"),
                        cells.bg_color().expect("read canonical background"),
                    ));
                }
                rows.push(snapshot);
            }
        }
        let hyperlinks = (0..24u32)
            .map(|y| {
                (0..80u16)
                    .map(|x| {
                        terminal
                            .viewport_hyperlink_uri(x, y)
                            .expect("read canonical hyperlink")
                    })
                    .collect()
            })
            .collect();
        CanonicalTerminalState {
            active_screen: terminal.active_screen().expect("read active screen"),
            cursor: render_state
                .cursor_viewport()
                .expect("read canonical cursor"),
            cursor_visible: render_state
                .cursor_visible()
                .expect("read canonical cursor visibility"),
            cursor_blinking: render_state
                .cursor_blinking()
                .expect("read canonical cursor blinking"),
            cursor_style: render_state
                .cursor_visual_style()
                .expect("read canonical cursor style"),
            colors: render_state.colors().expect("read canonical colors"),
            screen_text: terminal
                .screen_text_rows()
                .expect("read canonical screen text"),
            hyperlinks,
            modes: [
                terminal
                    .mode_get(crate::ghostty::MODE_APPLICATION_CURSOR_KEYS)
                    .expect("read application cursor mode"),
                terminal
                    .mode_get(crate::ghostty::MODE_FOCUS_EVENT)
                    .expect("read focus mode"),
                terminal
                    .mode_get(crate::ghostty::MODE_MOUSE_SGR)
                    .expect("read mouse mode"),
                terminal
                    .mode_get(crate::ghostty::MODE_BRACKETED_PASTE)
                    .expect("read bracketed paste mode"),
                terminal
                    .mouse_tracking_enabled()
                    .expect("read mouse tracking"),
            ],
            rows,
        }
    }

    fn assert_recovered_terminal_matches_perfect_path(
        initial: &[u8],
        degraded: &[u8],
        recovered: &[u8],
    ) {
        let mut interrupted = Vec::with_capacity(
            initial
                .len()
                .saturating_add(degraded.len())
                .saturating_add(recovered.len()),
        );
        interrupted.extend_from_slice(initial);
        interrupted.extend_from_slice(degraded);
        interrupted.extend_from_slice(recovered);
        assert_eq!(
            canonical_terminal_state(&interrupted),
            canonical_terminal_state(recovered),
            "recovered terminal state must equal an uninterrupted authoritative redraw"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn quic_survives_loss_delay_and_blackhole_with_full_redraw_recovery() {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let server_port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{server_port}-{server_port}"),
            ..Default::default()
        };
        let (server_event_tx, mut server_event_rx) = mpsc::channel(16);
        let server = crate::server::remote_quic::RemoteQuicServer::start(&config, server_event_tx)
            .expect("start QUIC server");

        let proxy_socket = Arc::new(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind UDP proxy"),
        );
        let proxy_address = proxy_socket.local_addr().expect("proxy address");
        let (mode_tx, mode_rx) = tokio::sync::watch::channel(NetworkMode::Online);
        let proxy_task = tokio::spawn(run_udp_proxy(
            Arc::clone(&proxy_socket),
            SocketAddr::from((Ipv4Addr::LOCALHOST, server_port)),
            mode_rx,
        ));

        let logical_client_id = [9; crate::protocol::REMOTE_QUIC_ID_BYTES];
        let bootstrap = server
            .bootstrap(crate::protocol::RemoteBootstrapRequest {
                session: crate::session::active_name()
                    .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned()),
                logical_client_id,
            })
            .expect("bootstrap QUIC client");
        let (session, _) = QuicSession::connect(
            ConnectParams {
                bootstrap,
                candidates: vec![proxy_address],
                logical_client_id,
                connection_generation: 1,
                cols: 80,
                rows: 24,
                cell_width_px: 8,
                cell_height_px: 16,
                keybindings: ClientKeybindings::Server,
            },
            Arc::new(Mutex::new(ResourceCache::default())),
        )
        .await
        .expect("connect through UDP proxy");
        let writer = match tokio::time::timeout(Duration::from_secs(2), server_event_rx.recv())
            .await
            .expect("client event timeout")
            .expect("client event")
        {
            crate::server::client_transport::ServerEvent::ClientConnected { writer, .. } => writer,
            _ => panic!("expected client connection"),
        };
        let (input_tx, input_rx) = mpsc::channel(8);
        let (output_tx, mut output_rx) = mpsc::channel(8);
        let mut session_task = tokio::spawn(session.run(input_rx, output_tx, false));

        writer
            .render
            .try_send(framed_terminal(1, true, b"initial".to_vec()))
            .expect("send initial frame");
        let initial = tokio::time::timeout(Duration::from_secs(2), output_rx.recv())
            .await
            .expect("initial frame timeout")
            .expect("initial frame");
        assert!(matches!(
            initial,
            ServerMessage::Terminal(crate::protocol::TerminalFrame { bytes, .. })
                if bytes == b"initial"
        ));

        mode_tx
            .send(NetworkMode::Degraded)
            .expect("enable degraded network");
        let graphics = vec![b'A'; 64 * 1024];
        let mut degraded_frame = b"before\x1b_Gf=100;".to_vec();
        degraded_frame.extend_from_slice(&graphics);
        degraded_frame.extend_from_slice(b"\x1b\\after");
        writer
            .render
            .try_send(framed_terminal(2, false, degraded_frame.clone()))
            .expect("send degraded frame");
        let degraded = tokio::time::timeout(Duration::from_secs(12), output_rx.recv())
            .await
            .expect("degraded frame timeout")
            .expect("degraded frame");
        assert!(matches!(
            degraded,
            ServerMessage::Terminal(crate::protocol::TerminalFrame { bytes, .. })
                if bytes == degraded_frame
        ));

        mode_tx
            .send(NetworkMode::Blackhole)
            .expect("enable blackhole");
        let status = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(ServerMessage::TransportStatus { status, .. }) = output_rx.recv().await
                {
                    if status == RemoteTransportStatus::PathRecovering {
                        break status;
                    }
                }
            }
        })
        .await
        .expect("path recovery status timeout");
        assert_eq!(status, RemoteTransportStatus::PathRecovering);
        // Hold the outage past STALE_CORROBORATED_AFTER before restoring. The
        // full-redraw request is deliberately gated on that threshold: a
        // shorter stall is recovered by the reliable stream's own
        // retransmissions, in order, with nothing lost and so nothing to
        // resync. Only a presumed-dead path coalesces state and needs a fresh
        // generation built against it.
        tokio::time::sleep(STALE_CORROBORATED_AFTER + Duration::from_millis(500)).await;
        // Typing into a presumed-dead path must still reach the server. The
        // control stream is reliable and ordered, so quinn retransmits this
        // keystroke when the path returns — the exact guarantee the SSH bridge
        // gave, and the one dropping input here used to break.
        input_tx
            .send(ClientMessage::Input {
                data: b"typed-in-the-dark".to_vec(),
            })
            .await
            .expect("send input while the path is presumed dead");
        mode_tx.send(NetworkMode::Online).expect("restore network");

        let mut saw_typed_input = false;
        let mut saw_sync_request = false;
        tokio::time::timeout(Duration::from_secs(8), async {
            while !saw_typed_input || !saw_sync_request {
                match server_event_rx.recv().await {
                    Some(crate::server::client_transport::ServerEvent::ClientInput {
                        data,
                        ..
                    }) => {
                        if data == b"typed-in-the-dark" {
                            saw_typed_input = true;
                        }
                    }
                    Some(crate::server::client_transport::ServerEvent::ClientSyncRequest {
                        ..
                    }) => {
                        saw_sync_request = true;
                    }
                    Some(_) => {}
                    None => panic!("server event channel closed"),
                }
            }
        })
        .await
        .expect("input written while dark, and the full redraw request, must both arrive");
        let canonical_frame = concat!(
            "\x1b[?1049h\x1b[?2026h\x1b[2J\x1b[H",
            "plain e\u{301} 界 👩‍💻\r\n",
            "\x1b[1;3;9;4:3;38;2;12;34;56;48;5;17mstyled\x1b[0m\r\n",
            "\x1b]8;;https://example.test/item\x1b\\Link\x1b]8;;\x1b\\",
            "\x1b[5;1HabcXYZ\x1b[5;4H\x1b[3P\x1b[2@++",
            "\x1b[6;1Hgarbage\x1b[2Kfinal-row",
            "\x1b[7;78Hwrap界",
            "\x1b[?1h\x1b[?1003h\x1b[?1006h\x1b[?1004h\x1b[?2004h",
            "\x1b[10;20H\x1b[5 q\x1b[?25l\x1b[?2026l",
        )
        .as_bytes()
        .to_vec();
        writer.render.reset_generation();
        writer
            .render
            .try_send(framed_terminal(1, true, canonical_frame.clone()))
            .expect("send recovery full frame");

        let mut saw_final = false;
        let mut saw_connected = false;
        tokio::time::timeout(Duration::from_secs(8), async {
            while !saw_final || !saw_connected {
                match output_rx.recv().await {
                    Some(ServerMessage::Terminal(frame)) if frame.bytes == canonical_frame => {
                        saw_final = true;
                    }
                    Some(ServerMessage::TransportStatus {
                        status: RemoteTransportStatus::Connected,
                        ..
                    }) => saw_connected = true,
                    Some(_) => {}
                    None => {
                        let exit = (&mut session_task).await.expect("failed session task");
                        panic!("proxy output closed during recovery: {exit:?}");
                    }
                }
            }
        })
        .await
        .expect("canonical recovery timeout");
        assert_recovered_terminal_matches_perfect_path(
            b"initial",
            &degraded_frame,
            &canonical_frame,
        );

        input_tx.send(ClientMessage::Detach).await.expect("detach");
        assert!(matches!(
            session_task.await.expect("session task"),
            SessionExit::Detached
        ));
        proxy_task.abort();
    }
}
