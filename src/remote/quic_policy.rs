//! Local QUIC scheduling policy shared by the remote client and the remote
//! server.
//!
//! These are quinn tuning values, not serialized protocol constants: nothing
//! here appears on the wire, and changing a value cannot break compatibility
//! with a peer running a different build. They live outside both endpoints so
//! neither has to depend on the other's implementation module.

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
