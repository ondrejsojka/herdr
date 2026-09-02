use super::*;
pub(super) fn format_optional_duration(value: Option<Duration>) -> String {
    match value {
        Some(value) => format!("{value:?}"),
        None => "n/a".to_owned(),
    }
}

/// Per-arm result of the streaming portion of the transport comparison.
///
/// `encoded_bytes` is the producer-encoded `ServerMessage::Terminal` frame
/// size handed to `writer.render.try_send`, not necessarily the arm's true
/// wire size: the TCP arm writes these exact bytes to the socket, but the
/// QUIC transport re-encodes accepted frames into `RemoteQuicRenderRecord`s
/// (with resource dedup) before they hit the wire. Both arms are measured
/// from the same input, so the byte counts remain comparable as an input
/// workload size even though they are not both literal wire sizes.
pub(super) struct ArmReport {
    pub(super) label: &'static str,
    pub(super) loss_enabled: bool,
    pub(super) source_frames: u64,
    pub(super) accepted: u64,
    pub(super) delivered: u64,
    /// Accepted frames from superseded QUIC render generations.
    pub(super) superseded: u64,
    /// Accepted frames from the final generation that never arrived.
    pub(super) outstanding: u64,
    pub(super) source_duration: Duration,
    pub(super) encoded_bytes: usize,
    /// `None` when the arm delivered no frames at all.
    pub(super) delivery_burst_span: Option<Duration>,
    pub(super) frame_latencies: Vec<Duration>,
    /// The four moments of each blackout recovery, kept separate. Empty when
    /// blackout was disabled.
    pub(super) recovery: RecoveryLatencies,
    /// Set when the arm's session ended abnormally before this benchmark's
    /// own teardown asked it to (QUIC only: a `RetryFresh`/`Rebootstrap`
    /// exit instead of `Detached`). `None` on a normal run and always
    /// `None` for the TCP arm, which has no early-give-up mechanism.
    pub(super) session_note: Option<String>,
    /// Set when the final render generation did not drain by its deadline.
    pub(super) delivery_timed_out: bool,
}

impl ArmReport {
    pub(super) fn delivered_fps(&self) -> f64 {
        self.delivered.saturating_sub(1) as f64 / self.source_duration.as_secs_f64()
    }

    pub(super) fn bytes_per_delivered_frame(&self) -> f64 {
        self.encoded_bytes as f64 / self.delivered.max(1) as f64
    }

    pub(super) fn bytes_per_second(&self) -> f64 {
        self.encoded_bytes as f64 / self.source_duration.as_secs_f64()
    }

    pub(super) fn latency_percentile(&self, percent: usize) -> Option<Duration> {
        percentile(&self.frame_latencies, percent)
    }

    pub(super) fn blackout_window_count(&self) -> usize {
        self.recovery.windows()
    }

    /// The head-to-head recovery number: time until a frame accepted after
    /// link-up arrives. Both transports can offer it.
    pub(super) fn fresh_output_percentile(&self, percent: usize) -> Option<Duration> {
        percentile(&self.recovery.fresh_output, percent)
    }

    pub(super) fn report(&self) {
        eprintln!(
            "[{label}] loss={loss} frames: source={source} accepted={accepted} delivered={delivered} \
             superseded={superseded} outstanding={outstanding} fps={fps:.2} \
             delivery-burst-span={span} bytes/delivered-frame={bpf:.1} bytes/s={bps:.1}",
            label = self.label,
            loss = if self.loss_enabled { "on" } else { "off" },
            source = self.source_frames,
            accepted = self.accepted,
            delivered = self.delivered,
            superseded = self.superseded,
            outstanding = self.outstanding,
            fps = self.delivered_fps(),
            span = format_optional_duration(self.delivery_burst_span),
            bpf = self.bytes_per_delivered_frame(),
            bps = self.bytes_per_second(),
        );
        eprintln!(
            "[{label}] frame-delivery latency (n={n}): p50={p50} p95={p95} p99={p99}",
            label = self.label,
            n = self.frame_latencies.len(),
            p50 = format_optional_duration(self.latency_percentile(50)),
            p95 = format_optional_duration(self.latency_percentile(95)),
            p99 = format_optional_duration(self.latency_percentile(99)),
        );
        if self.blackout_window_count() > 0 {
            // Four separate moments, not one "recovery": control becoming
            // usable, pixels moving again, the screen becoming fresh, and
            // the screen becoming canonically correct are different events.
            eprintln!(
                "[{label}] blackout recovery (windows={windows} unrecovered={unrecovered}):",
                label = self.label,
                windows = self.blackout_window_count(),
                unrecovered = self.recovery.unrecovered,
            );
            for (name, samples, note) in [
                (
                    "control-ready  ",
                    &self.recovery.control_ready,
                    "server received post-pong control",
                ),
                (
                    "first-output   ",
                    &self.recovery.first_output,
                    "any frame arrived",
                ),
                (
                    "fresh-output   ",
                    &self.recovery.fresh_output,
                    "frame accepted after link-up arrived",
                ),
                (
                    "full-converge  ",
                    &self.recovery.full_convergence,
                    "full redraw applied",
                ),
            ] {
                if samples.is_empty() {
                    eprintln!(
                        "[{label}]   {name} n/a ({note}; not produced by this transport)",
                        label = self.label,
                    );
                    continue;
                }
                eprintln!(
                    "[{label}]   {name} n={n} p50={p50} p95={p95} max={max}  -- {note}",
                    label = self.label,
                    n = samples.len(),
                    p50 = format_optional_duration(percentile(samples, 50)),
                    p95 = format_optional_duration(percentile(samples, 95)),
                    max = format_optional_duration(samples.last().copied()),
                );
            }
        }
        if self.delivery_timed_out {
            eprintln!(
                "[{label}] final-generation delivery drain hit its deadline with \
                 {outstanding} frames outstanding; {superseded} older-generation frames \
                 were intentionally superseded",
                label = self.label,
                outstanding = self.outstanding,
                superseded = self.superseded,
            );
        }
        if let Some(note) = &self.session_note {
            eprintln!("[{label}] {note}", label = self.label);
        }
    }
}
