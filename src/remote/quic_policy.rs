//! Local QUIC scheduling policy shared by the remote client and the remote
//! server.
//!
//! The stream priorities are quinn tuning values, not serialized protocol
//! constants: nothing about them appears on the wire, and changing one cannot
//! break compatibility with a peer running a different build. The close codes
//! below *are* on the wire — they are the server's only way to tell the client
//! whether to reconnect with the credential it already holds or to bootstrap a
//! new one — so they may only be added to, never renumbered. Both live outside
//! either endpoint so neither has to depend on the other's implementation
//! module.

/// Connection superseded: a newer generation of the *same* capability was
/// accepted, so another client now owns this session. The credential is still
/// valid, but reconnecting with it would fence the client that just took
/// over, which would fence this one back — an endless replacement loop. The
/// losing client stops instead.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_REPLACED: u32 = 0x100;
/// Capability rejected: unknown, expired, or a stale connection generation.
/// The client must bootstrap a fresh credential.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_AUTH: u32 = 0x101;
/// Protocol version mismatch or an unreadable handshake. Bootstrapping again
/// is the only thing that can resolve it, since the peer's build changed.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_PROTOCOL: u32 = 0x102;
/// The server process is going away for good. The port, certificate, and
/// instance id all die with it, so the client must bootstrap again.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_SHUTDOWN: u32 = 0x103;
/// The server is handing this session to a successor process that inherits the
/// same UDP socket, certificate, instance id, and capability tokens. The
/// client reconnects with the credential it already holds; bootstrapping again
/// would be pointless work during an update.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_HANDOFF: u32 = 0x104;
/// The server could not queue an undroppable control frame and closed rather
/// than silently dropping it and desyncing the client. The credential is still
/// valid, so the client reconnects with the one it holds.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_RESYNC: u32 = 0x105;
/// The capability itself was evicted from the server's token table (overflow),
/// so the credential the client holds no longer resolves to anything. Retrying
/// with it can only fail; the client must bootstrap a new one.
#[cfg(unix)]
pub(crate) const REMOTE_QUIC_CLOSE_EVICTED: u32 = 0x106;

/// Stream send priority for the bidirectional control stream, which carries
/// the handshake, heartbeats, pane input, and detach.
///
/// quinn drains higher-priority streams first when the connection send window
/// is contended. Only relative order matters. Control outranks the data
/// streams so a pong is never queued behind a screen repaint, which would
/// otherwise manufacture a false-positive path staleness under saturation.
#[cfg(unix)]
pub(crate) const PRIORITY_CONTROL: i32 = 10;

/// Stream send priority for graphics resource transfers.
///
/// Above [`PRIORITY_RENDER`] on purpose: the client cannot apply a render
/// record that references an uncached resource hash, and its pending-render
/// queue is bounded, so ranking a resource below the record that depends on it
/// starves the dependency and eventually forces a reconnect.
#[cfg(unix)]
pub(crate) const PRIORITY_RESOURCE: i32 = 5;

/// Stream send priority for the terminal render stream.
#[cfg(unix)]
pub(crate) const PRIORITY_RENDER: i32 = 0;

/// Maximum resource references allowed per single frame.
pub(crate) const MAX_RESOURCE_REFS_PER_FRAME: usize = 1024;
/// Maximum bincode varint and field overhead for a RemoteQuicRenderRecord
/// without resource references (three u64 headers, TerminalFrame sequence,
/// dimensions, full flag, bytes length prefix, and empty resources vec prefix).
pub(crate) const STRUCTURAL_RECORD_HEADER_BOUND: usize = 61;
/// Maximum bincode serialization overhead per resource reference (32-byte hash
/// plus up to 5-byte varint text offset).
pub(crate) const RESOURCE_REF_MAX_BOUND: usize = 37;
/// Structurally proven upper bound on serialization overhead when all
/// `MAX_RESOURCE_REFS_PER_FRAME` references are present.
pub(crate) const MAX_RECORD_OVERHEAD: usize =
    STRUCTURAL_RECORD_HEADER_BOUND + (MAX_RESOURCE_REFS_PER_FRAME * RESOURCE_REF_MAX_BOUND);

/// Returns the structurally proven serialization overhead headroom required
/// for a QUIC render record with or without externalized graphics.
pub(crate) const fn max_record_headroom(has_graphics: bool) -> usize {
    if has_graphics {
        MAX_RECORD_OVERHEAD
    } else {
        STRUCTURAL_RECORD_HEADER_BOUND
    }
}
