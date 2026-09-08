//! QUIC application close codes shared by the remote client and the remote
//! server.
//!
//! These are on the wire: they are the server's only way to tell the client
//! whether to reconnect with the credential it already holds or to bootstrap a
//! new one, so they may only be added to, never renumbered. They live outside
//! either endpoint so neither has to depend on the other's implementation
//! module.

/// Connection superseded: a newer generation of the *same* capability was
/// accepted, so another client now owns this session. The credential is still
/// valid, but reconnecting with it would fence the client that just took
/// over, which would fence this one back — an endless replacement loop. The
/// losing client stops instead.
pub(crate) const REMOTE_QUIC_CLOSE_REPLACED: u32 = 0x100;
/// Capability rejected: unknown, expired, or a stale connection generation.
/// The client must bootstrap a fresh credential.
pub(crate) const REMOTE_QUIC_CLOSE_AUTH: u32 = 0x101;
/// Schema version mismatch or an unreadable hello. Bootstrapping again is the
/// only thing that can resolve it, since the peer's build changed.
pub(crate) const REMOTE_QUIC_CLOSE_PROTOCOL: u32 = 0x102;
/// The server process is going away for good. The port, certificate, and
/// instance id all die with it, so the client must bootstrap again.
pub(crate) const REMOTE_QUIC_CLOSE_SHUTDOWN: u32 = 0x103;
/// The server is handing this session to a successor process that inherits the
/// same UDP socket, certificate, instance id, and capability tokens. The
/// client reconnects with the credential it already holds; bootstrapping again
/// would be pointless work during an update.
pub(crate) const REMOTE_QUIC_CLOSE_HANDOFF: u32 = 0x104;
/// The server-side client connection ended (the server's client acceptor
/// closed its end of the pipe). The credential is still valid, so the client
/// reconnects with the one it holds.
pub(crate) const REMOTE_QUIC_CLOSE_RESYNC: u32 = 0x105;
/// The capability itself was evicted from the server's token table (overflow),
/// so the credential the client holds no longer resolves to anything. Retrying
/// with it can only fail; the client must bootstrap a new one.
pub(crate) const REMOTE_QUIC_CLOSE_EVICTED: u32 = 0x106;
