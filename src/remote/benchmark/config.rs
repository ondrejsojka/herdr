use super::*;
/// Default synthetic-frame count: 3 seconds of 60 Hz output. Tail latency at
/// this size is dominated by which individual packets a lossy profile happens
/// to drop, so raise it with `HERDR_BENCH_SOURCE_FRAMES` when measuring p95
/// or p99.
pub(super) const SOURCE_FRAMES: u64 = 180;

/// Returns the synthetic-frame count for this run.
pub(super) fn source_frames() -> u64 {
    std::env::var("HERDR_BENCH_SOURCE_FRAMES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(SOURCE_FRAMES)
}

/// Nominal duration of the streaming portion of a run: the producer's own
/// 60 Hz tick window, before the `delivery_timeout` margin. The blackout
/// schedule is generated against this duration so every window falls
/// inside the period frames are actually being produced.
pub(super) fn producer_window_duration() -> Duration {
    Duration::from_millis(source_frames() * 1000 / 60)
}

/// Returns how long an arm waits for the frames it accepted, allowing the
/// producer window plus margin for in-flight delivery. When a blackout plan
/// is active, the margin also covers every scheduled outage: frames queued
/// right before a long outage only drain once it ends, and the base 8 s
/// margin alone is sized for steady-state jitter, not "train tunnel"
/// windows tens of seconds long.
pub(super) fn delivery_timeout(blackout: Option<&BlackoutPlan>) -> Duration {
    let base = Duration::from_millis(source_frames() * 1000 / 60 + 8_000);
    match blackout {
        Some(plan) => {
            let total_blackout: Duration = plan.schedule.iter().map(|window| window.length).sum();
            base + total_blackout
        }
        None => base,
    }
}

/// Selects which frame content `produce_frames` pushes into
/// `writer.render`, via `HERDR_BENCH_WORKLOAD`. `synthetic` (the default) is
/// a 33-byte cursor-home-plus-counter frame that never queues against the
/// shaped link and bypasses herdr's real render pipeline. `htop` replays a
/// captured `htop` PTY session through the real terminal emulator and
/// `BlitEncoder`, which can partially load the shaped link. `scroll`
/// replays a captured continuously-scrolling PTY session (e.g. `find /`),
/// which repaints nearly the full screen every frame and is the only
/// workload of the three that actually saturates the shaped link -- the
/// realistic case of a coding agent streaming build/compiler output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Workload {
    Synthetic,
    Htop,
    Scroll,
}

pub(super) fn workload() -> Workload {
    match std::env::var("HERDR_BENCH_WORKLOAD") {
        Ok(value) if value == "htop" => Workload::Htop,
        Ok(value) if value == "scroll" => Workload::Scroll,
        Ok(value) if value == "synthetic" => Workload::Synthetic,
        Ok(value) => {
            panic!(
                "unknown HERDR_BENCH_WORKLOAD={value:?}; expected \"synthetic\", \"htop\", or \
                 \"scroll\""
            )
        }
        Err(_) => Workload::Synthetic,
    }
}

pub(super) const INPUT_SAMPLES: u64 = 20;

/// Downstream (server -> client) sustained throughput, bytes/second, shared
/// by every shaped-network arm so the arms cannot silently drift apart.
pub(super) const DOWN_BYTES_PER_SECOND: f64 = 200_000.0;
/// Upstream (client -> server) sustained throughput, bytes/second.
pub(super) const UP_BYTES_PER_SECOND: f64 = 93_750.0;
/// One-way latency floor applied per shaped hop, milliseconds.
pub(super) const BASE_LATENCY_MS: u64 = 130;
/// One-way jitter added on top of the floor, uniformly in `[0, JITTER_SPAN_MS)`
/// milliseconds. Combined with `BASE_LATENCY_MS` and doubled for a round
/// trip, this reproduces the "260-340 ms RTT jitter" 3G profile.
pub(super) const JITTER_SPAN_MS: u64 = 41;
/// Deterministic 1-in-101 packet loss (~0.99%), applied only where the
/// transport can actually tolerate dropped packets.
pub(super) const LOSS_EVERY_NTH: u64 = 101;

/// Delay/jitter/bandwidth/loss model shared by every shaped relay so the
/// QUIC and TCP arms are measured under identical network conditions.
#[derive(Clone, Copy)]
pub(super) struct ShapingProfile {
    pub(super) down_bytes_per_second: f64,
    pub(super) up_bytes_per_second: f64,
    pub(super) base_latency_ms: u64,
    pub(super) jitter_span_ms: u64,
    /// `Some(n)` drops 1-in-`n` packets deterministically. Must be `None` for
    /// `run_tcp_proxy`: dropping bytes mid-stream desyncs length-prefixed
    /// framing rather than emulating a retransmitted packet, so a userspace
    /// TCP relay cannot honestly emulate loss at this layer.
    pub(super) loss_every_nth: Option<u64>,
}

/// The reference "3G" profile: 1.6 Mbit/s down, 0.75 Mbit/s up, 260-340 ms
/// RTT jitter, deterministic 0.99% packet loss. Used by the original QUIC
/// benchmark, and as the QUIC-with-loss reference point in the transport
/// comparison.
pub(super) const THREE_G_PROFILE: ShapingProfile = ShapingProfile {
    down_bytes_per_second: DOWN_BYTES_PER_SECOND,
    up_bytes_per_second: UP_BYTES_PER_SECOND,
    base_latency_ms: BASE_LATENCY_MS,
    jitter_span_ms: JITTER_SPAN_MS,
    loss_every_nth: Some(LOSS_EVERY_NTH),
};

/// Same delay/jitter/bandwidth as `THREE_G_PROFILE` with loss disabled --
/// required for the TCP arm, and used for the QUIC arm in the head-to-head
/// comparison so neither side is penalized by loss the other cannot suffer.
pub(super) const THREE_G_PROFILE_NO_LOSS: ShapingProfile = ShapingProfile {
    loss_every_nth: None,
    ..THREE_G_PROFILE
};

/// Reports whether the kernel owns network shaping for this run.
///
/// With `HERDR_BENCH_KERNEL_SHAPING=1` every arm binds plain sockets and does
/// no userspace shaping. Linux `tc netem` then applies delay, jitter,
/// bandwidth, and real packet loss identically to QUIC and TCP, which a
/// byte-stream TCP relay cannot do.
///
/// Requires Linux and `CAP_NET_ADMIN`. Set the path MTU first: loopback
/// defaults to 65536, and because netem drops whole packets, a TCP stream at
/// that MTU sends ~45x fewer, ~45x larger packets than QUIC (capped near
/// 1452 B) for the same byte rate, so it takes ~45x fewer loss events. Any
/// loss comparison at MTU 65536 measures that asymmetry, not the transports.
///
/// ```text
/// ip link set dev lo mtu 1500
/// tc qdisc add dev lo root netem \
///   delay 130ms 20ms distribution normal loss 0.99% rate 1.6mbit
/// ```
///
/// Pass the same values through `HERDR_BENCH_NETEM_*` so the blackout
/// controller's "link up" state matches the qdisc it inherits.
pub(super) fn kernel_shaping() -> bool {
    std::env::var_os("HERDR_BENCH_KERNEL_SHAPING").is_some_and(|value| value == "1")
}

/// Fraction of wall-clock time (0-100) the in-process blackout controller
/// should spend in a "train tunnel" outage. `0` (the default) disables the
/// controller entirely.
pub(super) fn blackout_duty_pct() -> f64 {
    std::env::var("HERDR_BENCH_BLACKOUT_DUTY_PCT")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Shortest outage the schedule may draw, milliseconds. Short windows test
/// path-recovery detection; long ones test whether the session survives at
/// all.
pub(super) fn blackout_min_ms() -> u64 {
    std::env::var("HERDR_BENCH_BLACKOUT_MIN_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100)
}

/// Longest outage the schedule may draw, milliseconds. Raise
/// `HERDR_BENCH_SOURCE_FRAMES` alongside it: at low duty cycles the mean
/// good period scales with the mean outage, so a short run can contain zero
/// complete windows.
pub(super) fn blackout_max_ms() -> u64 {
    std::env::var("HERDR_BENCH_BLACKOUT_MAX_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(500)
}

pub(super) fn netem_iface() -> String {
    std::env::var("HERDR_BENCH_NETEM_IFACE").unwrap_or_else(|_| "lo".to_owned())
}

/// Base one-way delay the controller must preserve on every flip. Defaults
/// to `BASE_LATENCY_MS` (the userspace-shaping value) purely so an
/// unconfigured run still resembles the reference 3G profile; a real
/// kernel-shaped run always sets this explicitly to whatever `delay` the
/// inherited qdisc was created with.
pub(super) fn netem_delay_ms() -> u64 {
    std::env::var("HERDR_BENCH_NETEM_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(BASE_LATENCY_MS)
}

pub(super) fn netem_jitter_ms() -> u64 {
    std::env::var("HERDR_BENCH_NETEM_JITTER_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(20)
}

pub(super) fn netem_rate() -> String {
    std::env::var("HERDR_BENCH_NETEM_RATE").unwrap_or_else(|_| "1.6mbit".to_owned())
}

/// Base ("link up") loss percentage the controller restores when it flips a
/// window back on. Must match the `loss` the inherited `tc qdisc add` used,
/// or the controller's "up" state silently diverges from the qdisc's actual
/// starting state and every window recovers into the wrong baseline.
pub(super) fn netem_loss_pct() -> f64 {
    std::env::var("HERDR_BENCH_NETEM_LOSS_PCT")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Whether the path an arm ran on actually dropped packets.
///
/// Under kernel shaping the qdisc owns loss, so an arm must consult the value
/// the runner applied rather than assume shaping implies loss: the blackout
/// regimes deliberately run at 0% base loss to isolate outage recovery from
/// steady-state loss, and reporting `loss=on` for those runs mislabels them.
pub(super) fn loss_active(userspace_loss: bool) -> bool {
    if kernel_shaping() {
        netem_loss_pct() > 0.0
    } else {
        userspace_loss
    }
}
