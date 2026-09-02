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
pub(crate) const PRIORITY_CONTROL: i32 = 10;

/// Stream send priority for graphics resource transfers.
///
/// Above [`PRIORITY_RENDER`] on purpose: the client cannot apply a render
/// record that references an uncached resource hash, and its pending-render
/// queue is bounded, so ranking a resource below the record that depends on it
/// starves the dependency and eventually forces a reconnect.
pub(crate) const PRIORITY_RESOURCE: i32 = 5;

/// Stream send priority for the terminal render stream.
pub(crate) const PRIORITY_RENDER: i32 = 0;
