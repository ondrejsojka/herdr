# Resumable remote Herdr: SSH-bootstrapped QUIC behind the endpoint seam

Status: design for branch `feat/quic-endpoint`, based on `v0.9.0` (`b99002ac`).
Supersedes the 0.7.x-era design and the post-0.9.0 plan; the earlier
`feat/resumable-quic` branch is the source inventory (§9), not the target.

## 1. Summary

Herdr keeps OpenSSH for authentication, host verification, remote platform
detection, binary bootstrap, server start, and fallback. For the live client
protocol it prefers an SSH-bootstrapped, certificate-pinned QUIC connection that
carries the **unmodified framed `ClientMessage`/`ServerMessage` byte stream** —
exactly what the SSH stdio bridge carries today — and plugs in behind v0.9.0's
endpoint seam (`ConnectTarget` → `LocalStream` + lifetime) as an opaque,
resilient pipe. QUIC does not interpret render content and the server render
path is untouched.

User-visible contract:

> Start `herdr --remote fedora` or add the machine with `herdr machine add`.
> Change networks, ride through a 2-minute tunnel, or close the laptop, and
> return to the same server-owned session without re-authenticating. While the
> path is recovering the screen stays live and input keeps flowing; if the path
> is truly lost, the client reconnects over QUIC with a cached credential and
> receives a fresh complete state. If UDP is unavailable, the existing SSH bridge
> is used transparently.

Not Mosh prediction, not Eternal Terminal byte replay. Herdr already owns the
important primitive — authoritative server-side terminal state rendered into
complete client state (`ClientShellSnapshot` + `PaneSurfaceFrame`) — and v0.9.0
already has revision/baseline fencing and supervisor-driven resync. QUIC's job is
to make a lost connection rare (path migration, retransmission) and cheap when it
happens (no `ssh` re-exec, no auth round).

## 2. Requirements, in priority order

1. **No regressions outside remote.** Local Unix-socket clients, direct attach,
   plugins/APIs, server persistence, handoff, stock `--remote` over SSH, and
   render/layout performance are unchanged. Stock servers and clients never bind
   UDP, mint TLS material, or start reconnect tasks. Pane-scaled loops gain no
   work: the adapter is per-connection.
2. **Follow upstream's boundaries.** Runtime/session facts live in the server and
   are exposed through negotiated capabilities; presentation state lives in the
   client. QUIC sits entirely behind `EndpointTransport`/`ConnectTarget` and one
   capability string. Never touch `headless/*` render, `client_transport.rs`
   writer internals, or `retained_surface.rs`.
3. **Roam and tunnel.** IP change, NAT rebind, ≥120 s blackholes, and laptop sleep
   recover without re-authentication, without terminating pane processes, and
   without freezing input before the connection is presumed dead.
4. **Perform on lossy links.** Random radio loss must not collapse throughput
   (BBR), control must not be starved by bulk output, and stale output must not
   accumulate unboundedly.
5. **Network health is never pane-process health.** A sleeping client or blocked
   transport must not backpressure a remote application. Upstream's one-slot
   render queue and PTY/render separation already guarantee this for the Unix
   socket; the QUIC adapter presents itself as an ordinary Unix client so the
   same guarantee holds.

## 3. Decisions

| Area | Decision |
| --- | --- |
| Integration depth | Opaque framed-byte pipe. No QUIC-specific render generations, sync requests, resource caches, or status wire messages. Recovery after a truly lost connection is upstream's: drop the client connection, supervisor re-handshakes, fresh snapshot + full surface. |
| Server placement | In-process `RemoteQuicServer` inside the server. Authenticated QUIC connections are adapted via a Unix socketpair into the existing client accept path. One userspace copy per frame; no sidecar daemon. |
| Client placement | A bridge task owned by `connect_saved_ssh` (saved machines, noninteractive) and `run_remote` (standalone, interactive). Both return `{ stream: LocalStream, lifetime }` to their existing callers. The thin client is unaware of QUIC except for a local-only status hint. |
| Liveness signal | Upstream's `endpoint.health.ping.v1`/`pong.v1` flow end-to-end through QUIC. The bridge peeks frame kinds and feeds `PathMonitor`. When no client ping is in flight (always true for standalone `--remote`, whose forwarded socket is the unprobed Local endpoint), the bridge originates pings on `PathMonitor`'s schedule; pongs are forwarded (any received message satisfies client health). `RemotePing/RemotePong` wire variants are deleted. |
| Recovering-path grace | The bridge injects a local-only `ServerMessage::EndpointControl { kind: "endpoint.transport.status.v1" }` toward the thin client when the QUIC path enters/leaves `recovering`. While recovering, the client's heartbeat deadline is 150 s instead of 10 s and the endpoint shows Roaming rather than Reconnecting; input keeps flowing on the reliable control stream. The hint never crosses the server API. SSH endpoints are unchanged. |
| After grace | Bridge closes the QUIC connection and (saved machines) the local socket; the supervisor's next attempt runs the ladder again and re-dials QUIC with the cached token — no SSH. Supervisor backoff stays upstream's 0.5→30 s. Standalone `--remote` has no supervisor, so its bridge keeps the local socket open and runs the ladder itself. |
| Transport ladder | `InitialRace → QuicLive → FreshQuic (cached token) → SshRebootstrap → SshFallback`. One-way: once on SSH fallback, stay for that attach. QUIC gets a 500 ms head start over the SSH bridge in the initial race; first `Welcome` wins. |
| Auth bootstrap | Normal OpenSSH. Hidden `herdr [--session S] remote-quic-bootstrap` runs on the remote host, talks to the running server over its protected Unix socket, and returns a versioned record `{ schema version, server instance id, UDP candidates, certificate SHA-256 fingerprint, capability token, expiry, ssh_fallback }`. Never log the token. |
| TLS identity | Per-server-process self-signed certificate (rcgen), key in memory only. Client pins the fingerprint delivered over SSH. ALPN `herdr/1`. No 0-RTT; no mutating data as early data. |
| Client authorization | 32-byte capability token scoped to Unix user, session, server instance, logical client id. Server stores SHA-256 only, bounded table, fenced per connection generation. Presented only inside the pinned TLS connection as the first frame (`RemoteQuicHello`). |
| Credential lifetime | Token/idle lifetime default 24 h, configurable. Not persisted across a cold restart. Transferred across live handoff. |
| Handoff | `perform_live_handoff` exports/imports cert, key, instance id, tokens, and UDP fds so QUIC clients re-dial the successor with their token and no SSH. `HandoffManifest.remote_quic` is optional; absent on stock servers. |
| Capability negotiation | Server advertises `remote_quic` in `endpoint.welcome.v1` capabilities when it can start QUIC (Unix, `remote.transport = auto`). Bridge attempts bootstrap only when advertised; against stock servers it never tries. `remote-quic-bootstrap` failing on stock binaries is belt-and-braces. Bootstrap record and `RemoteQuicHello` carry their own `REMOTE_QUIC_SCHEMA_VERSION`, never `PROTOCOL_VERSION`. |
| Congestion control | quinn with BBR on both sides. No runtime knob. A compile-time Cubic swap exists only if it stays under 20 LOC. |
| Streams | One bidirectional stream per connection carrying the framed protocol in both directions. QUIC provides reliability, ordering, retransmission, migration. No stream-per-message, no application TCP analogue. |
| Input semantics | Input flows while the connection is alive, regardless of render staleness. Frozen only once the client is Reconnecting. No replay across a destroyed connection: a final pre-loss key may be lost, never duplicated. |
| Multi-client | A fresh QUIC connection is an ordinary new client connection; upstream's foreground/projection semantics apply unchanged. Older connection generations for the same token are fenced. |
| Config | `[remote] transport = "auto" \| "ssh"`, `quic_port_range`, `quic_idle_timeout_seconds` (credential lifetime), `quic_transport_idle_timeout_seconds`. `auto` = QUIC then SSH. No `quic`-only mode, no `ssh_fallback` toggle, no grace knob. `endpoints.json` schema unchanged (`deny_unknown_fields`). |
| Platform | Unix clients; Linux/macOS remotes. Windows client remains SSH-only; quinn deps are Unix-gated. |
| Upstream engagement | Fork feature, no PR. Capability negotiation makes fork clients work against stock servers and stock clients ignore fork servers. |

## 4. Goals and non-goals

Goals: recover from blackholes, NAT rebinding, IP change, and sleep without
re-auth or pane interruption; keep SSH keys/aliases/agent/bootstrap unchanged;
prefer QUIC when reachable with zero-surprise SSH fallback; keep input alive
during path recovery; bound every queue; prove recovered display equals a
perfect-connectivity session at the same server state.

Non-goals: predictive local echo; byte or frame replay; surviving server-process
death; exactly-once input across a destroyed connection; public-CA/ACME or a
Herdr network service; privileged host-wide gateway; 0-RTT; mixing local and
remote panes in one session; replacing SSH auth or forwarding SSH over QUIC;
per-machine transport preference in the saved-machine catalog.

## 5. Architecture

### 5.1 Topology

```
local machine                                                        remote machine
┌──────────────────────────────────────────────────────────┐
│ herdr client (upstream shell/UI, untouched)              │
│   EndpointSupervisors.connect_once(ConnectTarget)        │
│     Local        ── unix sock ─► local server            │
│     Ssh(profile) ── unix sock ─► QuicBridge  ┐           │
│                                              │           │        herdr server daemon
│      ladder: race → QuicLive → FreshQuic →   │           │          ├─ herdr-client.sock ◄── remote-client-bridge (ssh, unchanged)
│              SshRebootstrap → SshFallback    │           │          │
│      ┌── ssh -T … remote-quic-bootstrap ─────┼───────────┼─────────►│  bootstrap only → record{instance,port,fp,token}
│      └── QUIC bi-stream (pinned fp, token) ──┼───────────┼─────────►└─ RemoteQuicServer: accept → verify hello → socketpair
│                                                                         → existing client acceptor (same as a unix client)
└──────────────────────────────────────────────────────────┘
```

Standalone `herdr --remote <target>` uses the same bridge; its local socket is
the client's Local endpoint.

### 5.2 Bootstrap sequence

```
client                          ssh -T target                     remote herdr server
  │ prepare_remote_herdr (locate/install/start, as today)           │
  │ Welcome.capabilities ∋ remote_quic?  ──no──► SSH bridge only     │
  │ ── remote-quic-bootstrap <client-id> ────► ClientMessage::RemoteBootstrap
  │ ◄── RemoteBootstrapRecord ─────────────── ServerMessage::RemoteBootstrap
  │   (lazily starts RemoteQuicServer: bind UDP from range, mint identity)
  │ QUIC dial: IPv6-first happy-eyeballs on `ssh -G` hostname, ALPN herdr/1, pinned fp
  │ first frame: RemoteQuicHello{schema, instance, client id, token}
  │ ◄── accepted → socketpair → normal Hello/Welcome over the stream
```

The server binds UDP and creates TLS material only on the first bootstrap
request; a server that never sees one is byte-identical in behavior to stock.

### 5.3 Client bridge

One task per connection attempt:

- Runs the ladder; whichever transport yields a `Welcome` first becomes the
  live pipe. The loser is torn down (ssh child reaped).
- Copies frames between the local Unix socket and the QUIC bidirectional stream
  with bounded buffers and backpressure in both directions. Frames are decoded
  only to the extent of reading the `EndpointControl.kind` for health frames;
  everything else is opaque.
- Owns `PathMonitor`: fast-probe after 1 s of silence, stale after 2 s + 2
  unanswered probes, `Endpoint::rebind()` every 10 s of silence (sleep → tether →
  wifi must not strand on the second-to-last address), recovering → lost at
  150 s. Probes are health pings; only pongs retire probes (asymmetric-path
  safe).
- Emits `endpoint.transport.status.v1 { state: live | recovering | ssh }` to the
  thin client on transitions. Never forwards it upstream.
- On lost: FreshQuic with cached token (bounded budget: 5 attempts,
  250 ms → 4 s) → SshRebootstrap (15 s) → SshFallback. Saved machines: on entering
  Reconnecting (client-declared or bridge-declared) close the local socket and
  let the supervisor drive the next attempt through the same adapter.
  Standalone: keep the local socket open across the whole ladder because a Local
  disconnect exits the client when no saved machine is enabled.

### 5.4 Server adapter

`RemoteQuicServer` (lazy, one per server process): quinn endpoint on a port from
`quic_port_range`, `ServerIdentity`, token table, 32-connection pre-auth
admission semaphore. Per accepted connection: read `RemoteQuicHello`, validate
token/instance/schema, fence older generations of the same token, create a
`UnixStream::pair()`, hand one end to the existing client acceptor path, and
copy bytes between the other end and the QUIC stream. Close codes follow
`quic_policy` (0x100–0x106, add-only). Handoff exports identity, tokens, and UDP
fds; the successor imports them before accepting.

### 5.5 Client health integration

`registry.rs` gains awareness of `endpoint.transport.status.v1` from its local
transport: `EndpointHealth` takes a `recovering: bool`; `action()` uses 150 s
when set, 10 s otherwise. The endpoint status enum gains `Roaming` (presentation
only, client-side). No server change.

### 5.6 Congestion control

BBR (`quinn::congestion::BbrConfig`) on both endpoints, already wired. Cubic is
loss-based and treats random radio loss as congestion; BBR paces to measured
bottleneck bandwidth. quinn documents BBR as experimental; the benchmark harness
(§8) records the numbers, but no runtime switch is exposed.

## 6. Integration seams in v0.9.0

| File | Change |
| --- | --- |
| `src/client/endpoint/supervisor.rs::connect_once` | `ConnectTarget::Ssh` arm unchanged; `connect_saved_ssh` internally runs the ladder and still returns `{ stream, bridge }`. |
| `src/remote/saved.rs::connect_saved_ssh` | Replace `SshStdioBridge::start` with the ladder-driven bridge (noninteractive: never prompts; QUIC failure is silent). |
| `src/remote/attach.rs::run_remote` | Same replacement (interactive); `run_client_process` unchanged. Add `remote-quic-bootstrap` subcommand + `request_remote_quic_bootstrap` + candidate resolution. |
| `src/main.rs` | Hidden `remote-quic-bootstrap` dispatch next to `remote-client-bridge`. |
| `src/protocol/endpoint.rs` | `REMOTE_QUIC_CAPABILITY = "remote_quic"`, `TRANSPORT_STATUS_KIND = "endpoint.transport.status.v1"`. Advertise from `EndpointServerWelcome::compatible` when the server can start QUIC. |
| `src/protocol/wire.rs` | `ClientMessage::RemoteBootstrap(RemoteBootstrapRequest)`, `ServerMessage::RemoteBootstrap(RemoteBootstrapRecord)`, `RemoteQuicHello`, `REMOTE_QUIC_SCHEMA_VERSION`. Bump `PROTOCOL_VERSION` per the published-protocol rule. |
| `src/server/headless/bootstrap.rs` (or `headless.rs`) | Hold `Option<RemoteQuicServer>`; lazy start on `ServerEvent::RemoteBootstrap`; accepted socketpairs enter the existing acceptor. |
| `src/server/handoff.rs`, `headless/lifecycle.rs` | Optional `remote_quic` manifest field; export/import around `perform_live_handoff`. |
| `src/client/endpoint/{health,registry,control}.rs`, endpoint status UI | Recovering-aware deadline, `Roaming` status, parse of the local hint. |
| `src/config/model.rs`, docs config reference | `[remote]` keys above. |
| `Cargo.toml` | quinn, rustls, rcgen, tokio net features — Unix-gated. |
| New: `src/remote/quic.rs`, `src/remote/quic_bridge.rs`, `src/remote/quic_policy.rs`, `src/remote/frame.rs`, `src/server/remote_quic.rs` | Cherry-picked and trimmed per §9. |

## 7. Wire and protocol changes

- Bootstrap request/record and `RemoteQuicHello` are bincode messages inside the
  existing framing. Their compatibility is `REMOTE_QUIC_SCHEMA_VERSION`,
  independent of client/server build versions (which may differ post-0.9.0).
- `endpoint.transport.status.v1` is client-local. The server never emits or
  receives it.
- No render, sync, status, URL, or resource messages are added.

## 8. Verification

### 8.1 Compatibility gate

- Stock v0.9.0 client ↔ fork server: identical behavior; extra capability ignored.
- Fork client ↔ stock server: SSH path only; no bootstrap attempt; no UDP bind.
- Fork server without any `--remote` client: no UDP socket, no TLS material.
- `transport = "ssh"`: byte-for-byte today's SSH bridge behavior.
- `just check` green; `just bench-render-scale` unchanged.

### 8.2 Unit and in-process tests

Fingerprint pin success/failure; wrong/expired/cross-session/cross-instance
tokens; admission semaphore; generation fencing; no token in logs; accepted QUIC
connection is an ordinary client to the acceptor (one test through the real
acceptor); ladder transitions incl. fake-ssh race bound (~1.2 s to fallback when
UDP is blocked); `PathMonitor` schedule and rebind cadence; bridge-originated
pings suppressed while a client ping is in flight; health deadline 150 s while
recovering, 10 s otherwise; handoff continuity (`tests/live_handoff.rs`: successor
keeps instance/port/fingerprint/tokens).

### 8.3 Real-surface scenarios (throwaway named session on a remote host)

Recorded outcomes for each: time-to-usable, keystroke loss, redraw correctness.

| Scenario | Expected |
| --- | --- |
| 3 s UDP blackhole | no visible event |
| IP change (netns / interface flap) | recovers within one rebind interval, no re-handshake |
| 30 s blackhole | Roaming shown, input still accepted and delivered on recovery, no reconnect |
| 120 s blackhole (tunnel) | same as 30 s |
| 200 s blackhole | Reconnecting at 150 s, input frozen, QUIC re-dial with cached token after restore, zero SSH, full redraw correct |
| Laptop sleep 10 min | reattached with cached token, zero SSH prompts |
| Server `--handoff` | QUIC clients re-dial successor without SSH |
| UDP blocked from start | SSH fallback within race bound |
| Screen equivalence after every recovery | client state equals a perfect-connectivity session at the same snapshot/surface revision |

### 8.4 Benchmark

Rework `src/remote/benchmark/*` to drive a real server and semantic client
through the bridge under 3G shaping (1.6/0.75 Mbit, 260–340 ms RTT, ~1% loss)
and blackout windows. Report fps, bytes/frame, p50/p95/p99 input-to-visible,
recovery latency, stalled RSS. Numbers go in this document before any are cited.

## 9. Source inventory from `feat/resumable-quic`

Cherry-pick files, not commits (commits interleave core and integration).

| Keep (re-home) | Delete |
| --- | --- |
| `remote/quic.rs`: `PathMonitor`, `FingerprintVerifier`, `QuicSession::connect`, candidate dialing, `rebind_endpoint`, TLS/ALPN/BBR config | `remote/quic.rs`: render-record gap validation, `reconstruct_frame`, `ResourceCache`, resize/terminal-mode deferral, `SyncRequest` emission |
| `server/remote_quic.rs`: `ServerIdentity`, token table + `validate_capability` + fencing, admission semaphore, listener start/stop, `export_handoff`/`import_handoff` | `server/remote_quic.rs`: `QuicControlSender`, `BoundedControlQueue`, `QuicRenderSender`, Kitty splitting, `publish_server_output`, direct `ServerEvent::ClientConnected` construction |
| `remote/proxy.rs` → `quic_bridge.rs`: `TransportPhase` ladder, QUIC/SSH race, reconnect budget, SSH rebootstrap/fallback loops, ssh child reaping | `remote/proxy.rs`: input router, transport status fan-out, `ClientDetached` handling |
| `remote/quic_policy.rs`, `remote/frame.rs` unchanged | `wire.rs`: `RemoteQuicStreamHeader`, `RemoteQuicResourceRef`, `RemoteQuicRenderRecord`, `RemoteTransportStatus`, `RemotePing/Pong`, `ServerMessage::{TransportStatus, ClientDetached, OpenUrl}`, `ClientMessage::SyncRequest` |
| `remote/attach.rs`: `remote-quic-bootstrap`, `request_remote_quic_bootstrap`, candidate resolution | all edits to `headless.rs`, `client_transport.rs`, `render_stream.rs`, `clients.rs`, `client/mod.rs`, `app/input/*`, `ui/scrollbar.rs` (upstream has the fixes or the feature) |
| `wire.rs`: `RemoteBootstrapRequest/Record`, `RemoteQuicHello` (drop `launch_mode`, add schema version) | `config`: `transport = quic`, `ssh_fallback` |
| `config/model.rs` `[remote]` keys listed in §3; config reference docs | Benchmark arms driving `ClientWriter`/`TerminalFrame` (rework per §8.4) |
| `tests/live_handoff.rs` QUIC authority assertions | |

## 10. Rollout

1. **Scaffold.** Cherry-pick kept modules, Cargo deps (Unix-gated), config keys.
   Compile with render-lane code removed. No integration.
2. **Server adapter.** Accept → hello/token → socketpair → acceptor. Lazy start on
   `ServerEvent::RemoteBootstrap`. Advertise `remote_quic`. Tests in §8.2.
3. **Client bridge.** Ladder-driven bridge returning `{ LocalStream, lifetime }`;
   wire into `connect_saved_ssh` and `run_remote`. Health-ping peeking and
   bridge-originated probes. Local status hint.
4. **Client grace.** Recovering-aware `EndpointHealth`, `Roaming` status.
5. **Handoff.** Manifest field, export/import, re-enable live_handoff assertions.
6. **Real-surface verification** (§8.3) via `herdr-throwaway-repro`.
7. **Benchmark rework** (§8.4); record numbers here.
8. **Docs.** `docs/next/.../persistence-remote.mdx` and `connecting-machines.mdx`
   transport paragraphs; config reference.

## 11. Risks

- **Supervisor backoff cap.** After the 150 s grace, a saved-machine reconnect
  can wait up to 30 s in upstream's backoff even though a QUIC re-dial is cheap.
  Measure; a transport-aware cap is a small follow-up in `supervisor.rs`.
- **Herdr Cloud.** If Cloud's agent is a machine-out tunnel that also serves
  SSH-reachable hosts, direct-path QUIC narrows to users who refuse an account.
  The footprint is small enough that abandonment is cheap; the bootstrap record
  shape is broker-friendly by construction.
- **Two close policies.** Standalone `--remote` keeps its local socket alive
  across the ladder; saved machines hand off to the supervisor. Both go through
  one bridge with a policy flag; tests must cover both.
- **Version skew is normal.** Bootstrap record and hello have their own schema
  version. Never compare `PROTOCOL_VERSION` for QUIC negotiation.
- **Firewalls / ProxyJump / Tailscale.** QUIC dials the `ssh -G` resolved host;
  unreachable UDP falls back one-way to SSH. Tailnet users get QUIC over the
  tailnet IP when UDP is allowed — document it.
- **Upstream churn.** ~6 upstream files touched lightly; expect trivial conflicts
  per release.
- **BBR is quinn-experimental.** Benchmark numbers must come from the reworked
  harness before being cited.

## Appendix: branch mechanics

- Target: `../herdr-worktrees/quic-endpoint` on `feat/quic-endpoint` from `v0.9.0`.
- Source: `feat/resumable-quic` (`8cdc4519`) in `../herdr`, kept as archived
  reference; merge base with `v0.9.0` is `c2637dc1`.
- Clean upstream reference: `../herdr-worktrees/v0.9.0`.
