use super::*;
/// The netem parameters the blackout controller must preserve on every
/// flip -- `tc qdisc change` respecifies the whole qdisc line, so dropping
/// one silently resets it (e.g. back to unlimited rate).
#[derive(Clone)]
pub(super) struct BlackoutConfig {
    pub(super) iface: String,
    pub(super) delay_ms: u64,
    pub(super) jitter_ms: u64,
    pub(super) rate: String,
    /// Loss percentage restored on flip-up: the run's base loss (0 for the
    /// blackout regimes exercised here, which isolate outage recovery from
    /// steady-state loss).
    pub(super) up_loss_pct: f64,
}

/// One scheduled outage: `offset` is time since the arm's own streaming
/// start, `length` is how long the link stays down.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlackoutWindow {
    pub(super) offset: Duration,
    pub(super) length: Duration,
}

/// A blackout schedule plus the qdisc parameters needed to replay it,
/// resolved once from environment and cloned into both arms so QUIC and TCP
/// see byte-for-byte the same outage timeline relative to their own start.
#[derive(Clone)]
pub(super) struct BlackoutPlan {
    pub(super) schedule: Vec<BlackoutWindow>,
    pub(super) config: BlackoutConfig,
}

/// Fixed seed for the blackout schedule PRNG. Deliberately a source
/// constant rather than anything derived from wall-clock time: the single
/// most important correctness property of the blackout controller is that
/// QUIC and TCP see an identical schedule, and generating it once from a
/// fixed seed before either arm runs (and cloning the resulting `Vec` into
/// both) is what actually guarantees that.
pub(super) const BLACKOUT_SCHEDULE_SEED: u64 = 0x5EED_B1AC_C0FF_EE42;

/// Minimal seeded PRNG (SplitMix64) so the blackout schedule is
/// reproducible without adding a `rand` dependency for a test-only file.
pub(super) struct DeterministicRng(pub(super) u64);

impl DeterministicRng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform integer in `[lo, hi]` inclusive.
    pub(super) fn next_range_ms(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        let span = hi - lo + 1;
        lo + self.next_u64() % span
    }
}

/// Builds a deterministic blackout schedule covering `run_duration`.
///
/// Outage lengths are drawn uniformly from `[min_ms, max_ms]`, so their
/// expectation is `mean_outage = (min_ms + max_ms) / 2`. For a target duty
/// cycle `d = duty_pct / 100` (the fraction of wall-clock time in
/// blackout), each outage/good-period pair forms one renewal cycle whose
/// long-run outage fraction is `E[outage] / (E[good] + E[outage])` by the
/// renewal-reward theorem -- so setting that equal to `d` and solving gives
/// `mean_good = mean_outage * (1 - d) / d`. Each good period is then drawn
/// uniformly from `[0.5, 1.5] * mean_good` (not paired to that cycle's own
/// outage draw), so individual cycles vary while the population mean --
/// and hence the realized duty cycle over many windows -- matches `d`.
///
/// Stops before scheduling a window whose outage would end after
/// `run_duration`, so every window fits inside the arm's own streaming
/// window with room for its recovery frame to be produced and delivered.
pub(super) fn build_blackout_schedule(
    duty_pct: f64,
    min_ms: u64,
    max_ms: u64,
    run_duration: Duration,
    seed: u64,
) -> Vec<BlackoutWindow> {
    assert!(
        duty_pct > 0.0,
        "build_blackout_schedule requires a positive duty cycle"
    );
    let duty = (duty_pct / 100.0).min(0.95);
    let mean_outage_ms = (min_ms + max_ms) as f64 / 2.0;
    let mean_good_ms = mean_outage_ms * (1.0 - duty) / duty;
    let good_lo_ms = (mean_good_ms * 0.5).max(1.0);
    let good_hi_ms = (mean_good_ms * 1.5).max(good_lo_ms + 1.0);

    let mut rng = DeterministicRng::new(seed);
    let run_ms = run_duration.as_millis() as u64;
    let mut offset_ms = 0u64;
    let mut windows = Vec::new();
    loop {
        offset_ms =
            offset_ms.saturating_add(rng.next_range_ms(good_lo_ms as u64, good_hi_ms as u64));
        let outage_ms = rng.next_range_ms(min_ms, max_ms);
        if offset_ms.saturating_add(outage_ms) > run_ms {
            break;
        }
        windows.push(BlackoutWindow {
            offset: Duration::from_millis(offset_ms),
            length: Duration::from_millis(outage_ms),
        });
        offset_ms += outage_ms;
    }
    windows
}

/// Resolves the blackout plan from environment once, so both arms replay an
/// identical `Vec<BlackoutWindow>`. Returns `None` when disabled
/// (`HERDR_BENCH_BLACKOUT_DUTY_PCT` unset or `<= 0`).
///
/// Blackout requires `HERDR_BENCH_KERNEL_SHAPING=1`: the controller flips a
/// real qdisc, which only exists once kernel shaping binds plain sockets
/// instead of routing through the userspace relays. Requesting blackout
/// without kernel shaping fails loudly instead of silently running with no
/// outages, since that would look like "zero effect" in the results for a
/// reason that has nothing to do with the transport comparison.
pub(super) fn blackout_plan() -> Option<BlackoutPlan> {
    let duty_pct = blackout_duty_pct();
    if duty_pct <= 0.0 {
        return None;
    }
    assert!(
        kernel_shaping(),
        "HERDR_BENCH_BLACKOUT_DUTY_PCT={duty_pct} requires HERDR_BENCH_KERNEL_SHAPING=1: the \
         blackout controller flips a real tc qdisc and has no userspace-relay equivalent"
    );
    let min_ms = blackout_min_ms();
    let max_ms = blackout_max_ms();
    assert!(
        min_ms > 0 && max_ms >= min_ms,
        "HERDR_BENCH_BLACKOUT_MIN_MS/MAX_MS must satisfy 0 < min <= max, got {min_ms}..{max_ms}"
    );
    let config = BlackoutConfig {
        iface: netem_iface(),
        delay_ms: netem_delay_ms(),
        jitter_ms: netem_jitter_ms(),
        rate: netem_rate(),
        up_loss_pct: netem_loss_pct(),
    };
    let run_duration = producer_window_duration();
    let schedule = build_blackout_schedule(
        duty_pct,
        min_ms,
        max_ms,
        run_duration,
        BLACKOUT_SCHEDULE_SEED,
    );
    eprintln!(
        "[blackout] schedule: duty={duty_pct}% outage=[{min_ms},{max_ms}]ms windows={n} over \
         {run_ms}ms (seed=0x{seed:016X})",
        n = schedule.len(),
        run_ms = run_duration.as_millis(),
        seed = BLACKOUT_SCHEDULE_SEED,
    );
    for (index, window) in schedule.iter().enumerate() {
        eprintln!(
            "[blackout] scheduled window {index}: start_offset={offset}ms length={length}ms",
            offset = window.offset.as_millis(),
            length = window.length.as_millis(),
        );
    }
    Some(BlackoutPlan { schedule, config })
}

/// Flips the qdisc's loss to `loss_pct` via `tc qdisc change` (never
/// `add`), respecifying delay/jitter/rate on every call so the qdisc's rate
/// limiter state is never reset mid-run. Returns the wall-clock cost of the
/// flip itself, measured tightly around the blocking call.
pub(super) async fn tc_qdisc_change_loss(config: &BlackoutConfig, loss_pct: f64) -> Duration {
    let started = Instant::now();
    let status = tokio::process::Command::new("tc")
        .args([
            "qdisc",
            "change",
            "dev",
            &config.iface,
            "root",
            "netem",
            "delay",
            &format!("{}ms", config.delay_ms),
            &format!("{}ms", config.jitter_ms),
            "distribution",
            "normal",
            "loss",
            &format!("{loss_pct}%"),
            "rate",
            &config.rate,
        ])
        .status()
        .await
        .expect("run tc qdisc change for blackout controller");
    let elapsed = started.elapsed();
    assert!(
        status.success(),
        "tc qdisc change failed (loss={loss_pct}%); is CAP_NET_ADMIN available?"
    );
    elapsed
}

/// Bookkeeping captured the instant the controller flips a window's link back
/// up, on the same `Instant` clock the arm's arrival timestamps use.
pub(super) struct BlackoutRecoveryPoint {
    /// Freshest frame the producer had accepted when the link came back.
    /// Anything at or beyond this mark reflects post-outage state.
    pub(super) mark_at_up: FrameMark,
    pub(super) t_up: Instant,
    /// Start of the next blackout. Recovery after this instant belongs to a
    /// later window and must not make this one look successful.
    pub(super) recover_before: Option<Instant>,
}

/// The four distinct moments an outage recovery passes through. Collapsing
/// them into one "recovery latency" is what made the old oracle meaningless:
/// in a 6 s blackout they were seconds apart from each other.
#[derive(Default)]
pub(super) struct RecoveryLatencies {
    /// Link up -> the server receives the client's post-pong sync request.
    /// This proves the bidirectional control path, and therefore pane input,
    /// works again. QUIC only.
    pub(super) control_ready: Vec<Duration>,
    /// Link up -> any frame arrives. The screen starts moving, but may still
    /// be painting pre-outage state.
    pub(super) first_output: Vec<Duration>,
    /// Link up -> a frame accepted after the link-up watermark arrives. This
    /// is the freshness/age-of-information measure, and the only one both
    /// transports can offer.
    pub(super) fresh_output: Vec<Duration>,
    /// Link up -> the first full redraw from a newer epoch arrives. The
    /// screen is now canonically correct rather than diffed against a
    /// baseline the client may no longer share. QUIC only.
    pub(super) full_convergence: Vec<Duration>,
    /// Windows where no frame at or beyond `mark_at_up` ever arrived.
    pub(super) unrecovered: usize,
}

impl RecoveryLatencies {
    fn sort(&mut self) {
        self.control_ready.sort_unstable();
        self.first_output.sort_unstable();
        self.fresh_output.sort_unstable();
        self.full_convergence.sort_unstable();
    }

    pub(super) fn windows(&self) -> usize {
        self.fresh_output.len() + self.unrecovered
    }
}

/// Spawns the blackout controller alongside an arm's producer when a plan is
/// active, so both arms wire it up identically.
pub(super) fn spawn_blackout(
    blackout: Option<BlackoutPlan>,
    arm_start: Instant,
    highest_accepted_mark: &Arc<AtomicU64>,
    label: &'static str,
) -> Option<tokio::task::JoinHandle<Vec<BlackoutRecoveryPoint>>> {
    blackout.map(|plan| {
        tokio::spawn(run_blackout_controller(
            plan,
            arm_start,
            Arc::clone(highest_accepted_mark),
            label,
        ))
    })
}

/// Resolves per-window recovery latencies once the controller has finished.
///
/// `control_ready_at` carries timestamps for the server receiving the
/// client's post-pong sync request, which only the QUIC arm produces.
pub(super) async fn resolve_recovery(
    task: Option<tokio::task::JoinHandle<Vec<BlackoutRecoveryPoint>>>,
    arrivals: &[Arrival],
    control_ready_at: &[Instant],
) -> RecoveryLatencies {
    match task {
        Some(task) => {
            let points = task.await.expect("blackout controller");
            blackout_recovery_latencies(&points, arrivals, control_ready_at)
        }
        None => RecoveryLatencies::default(),
    }
}

/// Replays `plan.schedule` against the real qdisc on the caller's own
/// `Instant` clock, anchored at `arm_start`, so outage timing and the arm's
/// frame-arrival timestamps are directly comparable. Flips are never `add`,
/// always `change`.
pub(super) async fn run_blackout_controller(
    plan: BlackoutPlan,
    arm_start: Instant,
    highest_accepted_mark: Arc<AtomicU64>,
    label: &'static str,
) -> Vec<BlackoutRecoveryPoint> {
    let mut points: Vec<BlackoutRecoveryPoint> = Vec::with_capacity(plan.schedule.len());
    let mut flip_costs = Vec::with_capacity(plan.schedule.len() * 2);
    for (index, window) in plan.schedule.iter().enumerate() {
        let target = arm_start + window.offset;
        let now = Instant::now();
        if target > now {
            tokio::time::sleep(target - now).await;
        }
        let down_cost = tc_qdisc_change_loss(&plan.config, 100.0).await;
        let t_down = Instant::now();
        if let Some(previous) = points.last_mut() {
            previous.recover_before = Some(t_down);
        }
        flip_costs.push(down_cost);
        eprintln!(
            "[{label} blackout] window {index}: start_offset={offset}ms length={length}ms \
             (flip-down cost={down_cost:?})",
            offset = window.offset.as_millis(),
            length = window.length.as_millis(),
        );

        tokio::time::sleep(window.length).await;

        let up_cost = tc_qdisc_change_loss(&plan.config, plan.config.up_loss_pct).await;
        let t_up = Instant::now();
        let mark_at_up = FrameMark::unpack(highest_accepted_mark.load(Ordering::Acquire));
        flip_costs.push(up_cost);
        eprintln!(
            "[{label} blackout] window {index}: restored at +{restored}ms (flip-up \
             cost={up_cost:?}) mark_at_up={epoch}:{seq}",
            restored = t_up.saturating_duration_since(arm_start).as_millis(),
            epoch = mark_at_up.epoch,
            seq = mark_at_up.seq,
        );

        points.push(BlackoutRecoveryPoint {
            mark_at_up,
            t_up,
            recover_before: None,
        });
    }

    let total_blackout_ms: u64 = plan
        .schedule
        .iter()
        .map(|window| window.length.as_millis() as u64)
        .sum();
    let run_ms = producer_window_duration().as_millis().max(1) as f64;
    eprintln!(
        "[{label} blackout] summary: windows={windows} total_blackout={total_blackout_ms}ms \
         realized_duty={duty:.2}% over {run_ms:.0}ms",
        windows = points.len(),
        duty = total_blackout_ms as f64 / run_ms * 100.0,
    );
    if let (Some(min_cost), Some(max_cost)) = (flip_costs.iter().min(), flip_costs.iter().max()) {
        eprintln!(
            "[{label} blackout] tc flip cost: min={min_cost:?} max={max_cost:?} across \
             {n} flips -- negligible next to a recovery-latency measurement dominated by the \
             ~260-340ms shaped RTT unless max climbs into double-digit milliseconds",
            n = flip_costs.len(),
        );
    }

    points
}

/// Separates the four moments a recovery passes through, per completed
/// blackout window.
///
/// `arrivals` must be in arrival order, which is how the collector records
/// them, so the first match scanning forward from `t_up` is the earliest.
/// Identity is `(epoch, seq)`: a real `ClientSyncRequest` restarts `seq`, so
/// comparing bare sequence numbers across a recovery would match a
/// pre-outage frame and report a stale screen as recovered.
pub(super) fn blackout_recovery_latencies(
    points: &[BlackoutRecoveryPoint],
    arrivals: &[Arrival],
    control_ready_at: &[Instant],
) -> RecoveryLatencies {
    let mut out = RecoveryLatencies::default();
    for point in points {
        let in_recovery_window =
            |at: Instant| at >= point.t_up && point.recover_before.is_none_or(|limit| at < limit);

        let mut first_output = None;
        let mut fresh_output = None;
        let mut full_convergence = None;
        for arrival in arrivals
            .iter()
            .filter(|arrival| in_recovery_window(arrival.at))
        {
            if first_output.is_none() {
                first_output = Some(arrival.at);
            }
            if fresh_output.is_none() && arrival.mark > point.mark_at_up {
                fresh_output = Some(arrival.at);
            }
            if full_convergence.is_none()
                && arrival.full
                && arrival.mark.epoch > point.mark_at_up.epoch
            {
                full_convergence = Some(arrival.at);
            }
            if fresh_output.is_some() && full_convergence.is_some() {
                break;
            }
        }

        let since_up = |at: Instant| at.saturating_duration_since(point.t_up);
        out.first_output.extend(first_output.map(since_up));
        out.full_convergence.extend(full_convergence.map(since_up));
        match fresh_output {
            Some(at) => out.fresh_output.push(since_up(at)),
            // No post-outage frame landed before the next outage: counted,
            // never folded into a percentile as if it recovered quickly.
            None => out.unrecovered += 1,
        }
        out.control_ready.extend(
            control_ready_at
                .iter()
                .find(|at| in_recovery_window(**at))
                .copied()
                .map(since_up),
        );
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(epoch: u32, seq: u64) -> FrameMark {
        FrameMark { epoch, seq }
    }

    fn arrival(base: Instant, millis: u64, mark: FrameMark, full: bool) -> Arrival {
        Arrival {
            mark,
            full,
            at: base + Duration::from_millis(millis),
        }
    }

    #[test]
    fn recovery_requires_post_up_work_and_a_new_epoch_for_convergence() {
        let base = Instant::now();
        let points = [BlackoutRecoveryPoint {
            mark_at_up: mark(0, 5),
            t_up: base + Duration::from_millis(10),
            recover_before: None,
        }];
        let arrivals = [
            arrival(base, 11, mark(0, 5), false),
            arrival(base, 12, mark(0, 6), true),
            arrival(base, 13, mark(1, 1), true),
        ];

        let recovery =
            blackout_recovery_latencies(&points, &arrivals, &[base + Duration::from_millis(12)]);

        assert_eq!(recovery.first_output, [Duration::from_millis(1)]);
        assert_eq!(recovery.fresh_output, [Duration::from_millis(2)]);
        assert_eq!(recovery.full_convergence, [Duration::from_millis(3)]);
        assert_eq!(recovery.control_ready, [Duration::from_millis(2)]);
        assert_eq!(recovery.unrecovered, 0);
    }

    #[test]
    fn later_window_cannot_recover_an_earlier_window() {
        let base = Instant::now();
        let points = [
            BlackoutRecoveryPoint {
                mark_at_up: mark(0, 5),
                t_up: base + Duration::from_millis(10),
                recover_before: Some(base + Duration::from_millis(20)),
            },
            BlackoutRecoveryPoint {
                mark_at_up: mark(0, 8),
                t_up: base + Duration::from_millis(30),
                recover_before: None,
            },
        ];
        let arrivals = [arrival(base, 31, mark(1, 1), true)];

        let recovery = blackout_recovery_latencies(&points, &arrivals, &[]);

        assert_eq!(recovery.first_output, [Duration::from_millis(1)]);
        assert_eq!(recovery.fresh_output, [Duration::from_millis(1)]);
        assert_eq!(recovery.full_convergence, [Duration::from_millis(1)]);
        assert_eq!(recovery.unrecovered, 1);
    }
}
