use super::*;
pub(super) fn framed_terminal(seq: u64, full: bool, bytes: Vec<u8>) -> Vec<u8> {
    let mut framed = Vec::new();
    crate::protocol::write_message(
        &mut framed,
        &ServerMessage::Terminal(TerminalFrame {
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

pub(super) struct FrameProducerResult {
    pub(super) source_duration: Duration,
    pub(super) accepted: u64,
    pub(super) encoded_bytes: usize,
    /// `(seq, accepted-at)` in send order, for matching against arrival
    /// timestamps to compute per-frame delivery latency.
    pub(super) sent_at: Vec<(FrameMark, Instant)>,
    /// Final producer epoch, including a reset that happened too late to
    /// accept another frame. Delivery only waits for this epoch: older
    /// accepted frames are intentionally superseded by a generation reset.
    pub(super) final_epoch: u32,
}

/// Pushes the configured `Workload` into `writer.render`, identically for
/// every transport arm so accepted/delivered counts and delivery latencies
/// are directly comparable across arms -- and, since every workload shares
/// this same acceptance accounting, across workloads too.
pub(super) async fn produce_frames(
    writer: ClientWriter,
    highest_accepted_mark: Arc<AtomicU64>,
    sync_requested: Arc<AtomicBool>,
) -> FrameProducerResult {
    match workload() {
        Workload::Synthetic => {
            produce_synthetic_frames(writer, highest_accepted_mark, sync_requested).await
        }
        Workload::Htop => {
            produce_trace_frames(
                writer,
                highest_accepted_mark,
                sync_requested,
                load_htop_trace(),
            )
            .await
        }
        Workload::Scroll => {
            produce_trace_frames(
                writer,
                highest_accepted_mark,
                sync_requested,
                load_scroll_trace(),
            )
            .await
        }
    }
}

/// Identifies one produced frame across a render-generation reset.
///
/// Handling `ClientSyncRequest` the way production does calls
/// `reset_transport_generation`, which sets the encoder's `seq` back to 0. Seq
/// alone therefore stops being unique the moment recovery is real: the first
/// frame after an outage collides with the first frame of the run. `epoch`
/// counts generation resets, so `(epoch, seq)` stays monotonic for the whole
/// run and ordering comparisons mean what they say.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub(super) struct FrameMark {
    pub(super) epoch: u32,
    pub(super) seq: u64,
}

/// Bits reserved for `seq` when packing a `FrameMark` into one `AtomicU64`.
/// The blackout controller samples the watermark from another task on every
/// flip-up, and a single relaxed load beats a mutex in that path.
const FRAME_MARK_SEQ_BITS: u32 = 48;

impl FrameMark {
    pub(super) fn pack(self) -> u64 {
        (u64::from(self.epoch) << FRAME_MARK_SEQ_BITS)
            | (self.seq & ((1 << FRAME_MARK_SEQ_BITS) - 1))
    }

    pub(super) fn unpack(packed: u64) -> Self {
        Self {
            epoch: u32::try_from(packed >> FRAME_MARK_SEQ_BITS).unwrap_or(u32::MAX),
            seq: packed & ((1 << FRAME_MARK_SEQ_BITS) - 1),
        }
    }
}

/// One delivered frame as the consumer saw it.
pub(super) struct Arrival {
    pub(super) mark: FrameMark,
    /// A post-sync full redraw, i.e. the canonical screen rather than a diff
    /// against a baseline the client may no longer share.
    pub(super) full: bool,
    pub(super) at: Instant,
}

/// Shared accepted-frame accounting for every workload: the single point
/// where `writer.render.try_send` is attempted, tallied, and timestamped,
/// so a later change (e.g. blackout-recovery bookkeeping keyed by producer
/// seq) only has to hook this one place instead of duplicating it per
/// workload.
pub(super) struct FrameAcceptance {
    pub(super) accepted: u64,
    /// Frames accepted since the current epoch began.
    accepted_in_epoch: u64,
    pub(super) encoded_bytes: usize,
    /// `(mark, accepted-at)` in send order, for matching against arrival
    /// timestamps to compute per-frame delivery latency.
    pub(super) sent_at: Vec<(FrameMark, Instant)>,
    /// Generation resets observed so far, i.e. the current epoch.
    epoch: u32,
    /// Highest `FrameMark` accepted so far, packed and published with a
    /// `Release` store on every successful `try_accept` so a concurrently
    /// running task (the blackout controller, flipping the link back up on
    /// its own `Instant` clock) can sample "freshest frame accepted at this
    /// instant" without a mutex in the per-frame accept path.
    pub(super) highest_accepted_mark: Arc<AtomicU64>,
}

impl FrameAcceptance {
    pub(super) fn new(highest_accepted_mark: Arc<AtomicU64>) -> Self {
        Self {
            accepted: 0,
            accepted_in_epoch: 0,
            encoded_bytes: 0,
            sent_at: Vec::new(),
            epoch: 0,
            highest_accepted_mark,
        }
    }

    /// Frames accepted since the current epoch began, so a caller assigning
    /// its own sequence numbers can keep them dense within the epoch.
    pub(super) fn accepted_in_epoch(&self) -> u64 {
        self.accepted_in_epoch
    }

    /// Records that the server reset the render generation in response to a
    /// `ClientSyncRequest`, so subsequent `seq` values restart from 1.
    pub(super) fn begin_epoch(&mut self) {
        self.epoch += 1;
        self.accepted_in_epoch = 0;
    }

    /// Attempts to hand `framed` (sequence `seq` within the current epoch) to
    /// `writer.render`. On acceptance, records the send timestamp, tallies
    /// count/bytes, and publishes the new watermark. Returns the underlying
    /// `try_send` result so the caller decides what acceptance means for
    /// its own baseline (e.g. whether to commit a `BlitEncoder` baseline).
    pub(super) fn try_accept(
        &mut self,
        writer: &ClientWriter,
        seq: u64,
        framed: Vec<u8>,
    ) -> Result<(), std::sync::mpsc::TrySendError<Vec<u8>>> {
        let length = framed.len();
        let mark = FrameMark {
            epoch: self.epoch,
            seq,
        };
        writer.render.try_send(framed).map(|()| {
            self.sent_at.push((mark, Instant::now()));
            self.accepted += 1;
            self.accepted_in_epoch += 1;
            self.encoded_bytes += length;
            self.highest_accepted_mark
                .store(mark.pack(), Ordering::Release);
        })
    }

    pub(super) fn into_result(self, source_duration: Duration) -> FrameProducerResult {
        FrameProducerResult {
            source_duration,
            accepted: self.accepted,
            encoded_bytes: self.encoded_bytes,
            sent_at: self.sent_at,
            final_epoch: self.epoch,
        }
    }
}

/// Pushes the synthetic 60 Hz terminal-frame workload into `writer.render`:
/// a 33-byte cursor-home-plus-counter frame that never queues against the
/// shaped link and bypasses herdr's real render pipeline. See
/// `produce_trace_frames` for the realistic alternatives.
pub(super) async fn produce_synthetic_frames(
    writer: ClientWriter,
    highest_accepted_mark: Arc<AtomicU64>,
    sync_requested: Arc<AtomicBool>,
) -> FrameProducerResult {
    let mut interval = tokio::time::interval(Duration::from_nanos(16_666_667));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let source_started = Instant::now();
    let mut acceptance = FrameAcceptance::new(highest_accepted_mark);
    let frames = source_frames();
    for source_index in 0..frames {
        interval.tick().await;
        // Mirrors what `reset_transport_generation` does to a real encoder:
        // the sequence restarts and the next frame is a full screen rather
        // than a diff against a baseline the client no longer shares.
        if sync_requested.swap(false, Ordering::AcqRel) {
            acceptance.begin_epoch();
        }
        // Seq advances only on acceptance, so seqs stay dense within an
        // epoch. A rejected frame must not burn a sequence number: the
        // recovery oracle and the delivery drain both assume the Nth accepted
        // frame of an epoch is seq N.
        let seq = acceptance.accepted_in_epoch() + 1;
        let framed = framed_terminal(
            seq,
            seq == 1,
            format!("\x1b[Hmeaningful-frame-{source_index:03}").into_bytes(),
        );
        let _ = acceptance.try_accept(&writer, seq, framed);
    }
    acceptance.into_result(source_started.elapsed())
}

/// Feeds a recorded PTY trace (`load_htop_trace` / `load_scroll_trace`)
/// through herdr's real terminal emulation (`TerminalRuntime`) and
/// `BlitEncoder` diffing (`ClientRenderState::TerminalAnsi`), pushing
/// whatever `ClientRenderState::prepare_frame` produces through the same
/// `FrameAcceptance::try_accept` acceptance point `produce_synthetic_frames`
/// uses, so every workload stays comparable across arms and keyed by the
/// same producer `seq` identity. Shared by the `htop` and `scroll`
/// workloads -- they differ only in which trace is fed in.
///
/// Mirrors `send_retained_frame_to_client` in `headless.rs`: on
/// `TrySendError::Full` the prepared frame is dropped without calling
/// `commit_sent_frame`, so the encoder's baseline stays exactly where it
/// was and the next tick's diff covers everything the terminal did while
/// the queue was full. Committing on `Full` instead would silently desync
/// the diff stream from what the client actually received.
pub(super) async fn produce_trace_frames(
    writer: ClientWriter,
    highest_accepted_mark: Arc<AtomicU64>,
    sync_requested: Arc<AtomicBool>,
    trace: Vec<PtyTraceChunk>,
) -> FrameProducerResult {
    let trace_span_micros = trace.last().map_or(1, |chunk| chunk.at.as_micros().max(1));

    let area = ratatui::layout::Rect::new(0, 0, 80, 24);
    let (terminal, _pty_input) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
    let mut render_state = crate::server::render_stream::ClientRenderState::new(
        crate::protocol::RenderEncoding::TerminalAnsi,
    );

    let mut interval = tokio::time::interval(Duration::from_nanos(16_666_667));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let source_started = Instant::now();
    let frames = source_frames();
    let mut acceptance = FrameAcceptance::new(highest_accepted_mark);
    let mut next_chunk = 0usize;
    let mut current_loop = 0u128;
    let mut looped = false;

    for _ in 0..frames {
        interval.tick().await;
        // Exactly what `headless.rs` does for ClientSyncRequest: reset the
        // transport generation (which also restarts `seq`) and force the next
        // frame to be a full screen. Without this the arm measures an old
        // generation draining, not Herdr's recovery.
        if sync_requested.swap(false, Ordering::AcqRel) {
            render_state.reset_transport_generation();
            render_state.request_repaint();
            acceptance.begin_epoch();
        }
        let elapsed_micros = source_started.elapsed().as_micros();
        let loop_index = elapsed_micros / trace_span_micros;
        if loop_index != current_loop {
            current_loop = loop_index;
            next_chunk = 0;
            looped = true;
        }
        let elapsed_in_loop_micros = elapsed_micros % trace_span_micros;
        while next_chunk < trace.len() && trace[next_chunk].at.as_micros() <= elapsed_in_loop_micros
        {
            terminal.test_process_pty_bytes(&trace[next_chunk].bytes);
            next_chunk += 1;
        }

        let (buffer, cursor) =
            crate::server::render_stream::render_terminal_virtual(&terminal, area);
        let frame =
            crate::protocol::FrameData::from_ratatui_buffer_with_hyperlinks(&buffer, cursor, &[]);
        let Some(prepared) = render_state.prepare_frame(frame) else {
            continue;
        };
        let seq = match prepared.message() {
            ServerMessage::Terminal(frame) => frame.seq,
            _ => unreachable!("TerminalAnsi render state always prepares a Terminal message"),
        };
        let mut framed = Vec::new();
        crate::protocol::write_message(&mut framed, prepared.message())
            .expect("frame trace terminal message");
        match acceptance.try_accept(&writer, seq, framed) {
            Ok(()) => render_state.commit_sent_frame(prepared),
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                // Leave `render_state` dirty; retried against the same
                // baseline next tick, exactly like `headless.rs` deferring a
                // retained render when the queue is full.
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
        }
    }
    if looped {
        eprintln!(
            "[trace workload] {trace_span_ms} ms trace looped to cover a {run_ms} ms run",
            trace_span_ms = trace_span_micros / 1000,
            run_ms = source_started.elapsed().as_millis(),
        );
    }
    acceptance.into_result(source_started.elapsed())
}

/// Returns the `percent`-th percentile of pre-sorted-ascending `samples`
/// (nearest-rank method), or `None` when there are no samples -- which
/// happens whenever a session dies before delivering anything, exactly the
/// case the report exists to describe.
pub(super) fn percentile(samples: &[Duration], percent: usize) -> Option<Duration> {
    let index = (samples.len() * percent).div_ceil(100).saturating_sub(1);
    samples.get(index).copied()
}

/// Outcome of draining one arm's arrival channel.
pub(super) struct DeliveryMeasurement {
    /// Every arrival in arrival order, which the recovery oracle relies on.
    pub(super) arrivals: Vec<Arrival>,
    /// Arrival time per produced frame, keyed by `(epoch, seq)` so a
    /// generation reset cannot make post-recovery seq 1 collide with the
    /// first frame of the run.
    pub(super) received_at: HashMap<FrameMark, Instant>,
    pub(super) delivered: u64,
    /// Accepted frames from older epochs that a generation reset deliberately
    /// made obsolete before they arrived.
    pub(super) superseded: u64,
    /// Accepted frames from the final epoch that did not arrive.
    pub(super) outstanding: u64,
    /// `None` when not a single frame arrived, so there is no interval to
    /// measure between a first and last arrival.
    pub(super) burst_span: Option<Duration>,
    /// Set when the final epoch did not drain before the deadline.
    pub(super) timed_out: bool,
}

/// Drains `arrival_rx` until every accepted frame in the final producer epoch
/// has landed, the producer side hangs up, or `deadline` elapses.
///
/// A real QUIC generation reset intentionally abandons accepted records from
/// older epochs. Waiting for the raw accepted count would therefore hang every
/// successful recovery until the deadline. TCP never resets and has epoch 0,
/// so the same rule still requires all of its accepted frames.
pub(super) async fn collect_deliveries(
    arrival_rx: &mut mpsc::UnboundedReceiver<Arrival>,
    sent_at: &[(FrameMark, Instant)],
    final_epoch: u32,
    deadline: Duration,
) -> DeliveryMeasurement {
    let expected_final = sent_at
        .iter()
        .filter(|(mark, _)| mark.epoch == final_epoch)
        .count() as u64;
    let mut arrivals: Vec<Arrival> = Vec::new();
    let mut received_at = HashMap::new();
    let mut delivered = 0u64;
    let mut delivered_final = 0u64;
    let drained_final = tokio::time::timeout(deadline, async {
        while delivered_final < expected_final {
            let Some(arrival) = arrival_rx.recv().await else {
                return false;
            };
            if received_at.insert(arrival.mark, arrival.at).is_none() {
                delivered += 1;
                if arrival.mark.epoch == final_epoch {
                    delivered_final += 1;
                }
                arrivals.push(arrival);
            }
        }
        true
    })
    .await
    .unwrap_or(false);

    let superseded = sent_at
        .iter()
        .filter(|(mark, _)| mark.epoch < final_epoch && !received_at.contains_key(mark))
        .count() as u64;
    let outstanding = sent_at
        .iter()
        .filter(|(mark, _)| mark.epoch >= final_epoch && !received_at.contains_key(mark))
        .count() as u64;
    let burst_span = match (arrivals.first(), arrivals.last()) {
        (Some(first), Some(last)) => Some(last.at.saturating_duration_since(first.at)),
        _ => None,
    };
    DeliveryMeasurement {
        arrivals,
        received_at,
        delivered,
        superseded,
        outstanding,
        burst_span,
        timed_out: !drained_final,
    }
}

/// Matches producer send timestamps against consumer arrival timestamps by
/// sequence number and returns sorted-ascending per-frame delivery
/// latencies.
pub(super) fn frame_latencies(
    sent_at: &[(FrameMark, Instant)],
    received_at: &HashMap<FrameMark, Instant>,
) -> Vec<Duration> {
    let mut latencies: Vec<Duration> = sent_at
        .iter()
        .filter_map(|(mark, sent)| {
            received_at
                .get(mark)
                .map(|received| received.saturating_duration_since(*sent))
        })
        .collect();
    latencies.sort_unstable();
    latencies
}

/// The bootstrap-and-connect sequence every QUIC arm needs: bind a port,
/// start a `RemoteQuicServer` on exactly that port, optionally interpose the
/// userspace shaping relay, bootstrap a client, connect, and take the
/// resulting `ClientWriter`. Exists once so `run_quic_arm` and
/// `terminal_ansi_3g_benchmark` cannot drift apart on transport setup while
/// claiming to measure the same transport.
pub(super) struct QuicArmHarness {
    pub(super) session: QuicSession,
    pub(super) writer: ClientWriter,
    pub(super) server_event_rx: mpsc::Receiver<ServerEvent>,
    /// `None` when the client dials the server directly and the kernel qdisc
    /// shapes the path.
    pub(super) proxy_task: Option<tokio::task::JoinHandle<()>>,
    /// Drives the userspace relay's `NetworkMode`. Sends fail harmlessly
    /// when there is no relay, since nothing is listening on the receiver.
    pub(super) mode_tx: watch::Sender<NetworkMode>,
    /// Held only to keep the server endpoint open for the arm's lifetime;
    /// dropping it would tear the session down mid-measurement.
    pub(super) _server: crate::server::remote_quic::RemoteQuicServer,
}

impl QuicArmHarness {
    /// `client_id_byte` distinguishes concurrent arms' logical client ids.
    ///
    /// `force_relay` keeps the userspace relay even under kernel shaping, for
    /// callers that need its in-process `NetworkMode::Blackhole` kill switch
    /// rather than a qdisc flip.
    pub(super) async fn start(
        profile: ShapingProfile,
        client_id_byte: u8,
        force_relay: bool,
    ) -> Self {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let server_port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = crate::config::RemoteConfig {
            quic_port_range: format!("{server_port}-{server_port}"),
            ..Default::default()
        };
        let (server_event_tx, mut server_event_rx) = mpsc::channel(64);
        let server = crate::server::remote_quic::RemoteQuicServer::start(&config, server_event_tx)
            .expect("start QUIC server");

        let server_address = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
        let (mode_tx, mode_rx) = watch::channel(NetworkMode::Online);
        let (candidate, proxy_task) = if kernel_shaping() && !force_relay {
            drop(mode_rx);
            (server_address, None)
        } else {
            let proxy_socket = Arc::new(
                tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("bind UDP proxy"),
            );
            let proxy_address = proxy_socket.local_addr().expect("proxy address");
            let task = tokio::spawn(run_udp_proxy(
                Arc::clone(&proxy_socket),
                server_address,
                mode_rx,
                profile,
            ));
            (proxy_address, Some(task))
        };

        let logical_client_id = [client_id_byte; crate::protocol::REMOTE_QUIC_ID_BYTES];
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
                candidates: vec![candidate],
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
        .expect("connect QUIC session");
        let writer = match server_event_rx.recv().await.expect("client event") {
            ServerEvent::ClientConnected { writer, .. } => writer,
            _ => panic!("expected client connection"),
        };

        Self {
            session,
            writer,
            server_event_rx,
            proxy_task,
            mode_tx,
            _server: server,
        }
    }
}

/// Runs the streaming portion of the QUIC arm (bootstrap, shaped UDP relay,
/// 60 Hz producer, delivery measurement) under `profile` and tears the
/// session down cleanly. Mirrors the setup in `terminal_ansi_3g_benchmark`
/// but omits the input-latency, CPU, and blackhole-recovery sections, which
/// exercise QUIC-specific resumability with no TCP-baseline analog.
///
/// `blackout`, when `Some`, runs the in-process blackout controller
/// alongside the producer, replaying `blackout.schedule` against the real
/// qdisc and recording a recovery point per window; `ArmReport` then
/// reports recovery latency computed from those points.
pub(super) async fn run_quic_arm(
    profile: ShapingProfile,
    blackout: Option<BlackoutPlan>,
) -> ArmReport {
    let QuicArmHarness {
        session,
        writer,
        mut server_event_rx,
        proxy_task,
        mode_tx,
        _server,
    } = QuicArmHarness::start(profile, 23, false).await;
    // Anchors both the blackout schedule's offsets and the transport-status
    // log below, so "when did the outage start" and "when did QUIC notice"
    // are directly comparable.
    let arm_start = Instant::now();
    // Handle ClientSyncRequest exactly as headless.rs does, rather than
    // draining it: reset the writer's render generation and tell the producer
    // to reset its encoder and repaint. Discarding this event is what made
    // the old oracle time backlog drainage instead of Herdr's recovery.
    let sync_requested = Arc::new(AtomicBool::new(false));
    let (control_ready_tx, mut control_ready_rx) = mpsc::unbounded_channel::<Instant>();
    let event_forwarder = {
        let sync_requested = Arc::clone(&sync_requested);
        let sync_writer = writer.clone();
        let control_ready_tx = control_ready_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = server_event_rx.recv().await {
                if matches!(event, ServerEvent::ClientSyncRequest { .. }) {
                    // The server receiving this post-pong control message is
                    // the first observable proof that the bidirectional
                    // control path, and therefore pane input, works again.
                    let _ = control_ready_tx.send(Instant::now());
                    sync_writer.render.reset_generation();
                    sync_requested.store(true, Ordering::Release);
                    eprintln!(
                        "[QUIC sync] +{ms}ms full-redraw requested",
                        ms = arm_start.elapsed().as_millis(),
                    );
                }
            }
        })
    };

    let (input_tx, input_rx) = mpsc::channel(16);
    let (output_tx, mut output_rx) = mpsc::channel(16);
    let session_task = tokio::spawn(session.run(input_rx, output_tx, false));

    // Timestamp arrivals on a dedicated task, the moment the session yields
    // each frame, and buffer them through an unbounded channel. The TCP arm
    // timestamps on its reader thread the same way (see `run_tcp_arm`).
    // Timestamping inside the later draining loop instead records when this
    // test got around to reading, which with a 3 s producer window inflates
    // every latency by up to the whole window. Also logs `TransportStatus`
    // events (heartbeat-driven path recovery, sync requests) so a blackout
    // run's log makes it possible to tell whether the QUIC heartbeat
    // deadline actually fired during a given outage.
    let (arrival_tx, mut arrival_rx) = mpsc::unbounded_channel::<Arrival>();
    let arrival_collector = tokio::spawn(async move {
        let mut epoch = 0u32;
        let mut last_seq = 0u64;
        while let Some(message) = output_rx.recv().await {
            match message {
                ServerMessage::Terminal(frame) => {
                    // A sequence that stops advancing is a generation reset:
                    // the server restarted numbering, so this frame belongs to
                    // a new epoch.
                    if frame.seq <= last_seq {
                        epoch += 1;
                    }
                    last_seq = frame.seq;
                    let arrival = Arrival {
                        mark: FrameMark {
                            epoch,
                            seq: frame.seq,
                        },
                        full: frame.full,
                        at: Instant::now(),
                    };
                    if arrival_tx.send(arrival).is_err() {
                        break;
                    }
                }
                ServerMessage::TransportStatus { status, detail } => {
                    eprintln!(
                        "[QUIC transport status] +{ms}ms {status:?} {detail}",
                        ms = arm_start.elapsed().as_millis(),
                        detail = detail.as_deref().unwrap_or(""),
                    );
                }
                _ => {}
            }
        }
    });

    // Under kernel shaping there is no relay listening; the qdisc is already
    // in place, so a dropped send is expected.
    let _ = mode_tx.send(NetworkMode::ThreeG);

    let producer_writer = writer.clone();
    let highest_accepted_mark = Arc::new(AtomicU64::new(0));
    let effective_delivery_timeout = delivery_timeout(blackout.as_ref());
    let blackout_task = spawn_blackout(blackout, arm_start, &highest_accepted_mark, "QUIC");
    let producer = tokio::spawn(produce_frames(
        producer_writer,
        Arc::clone(&highest_accepted_mark),
        Arc::clone(&sync_requested),
    ));
    let FrameProducerResult {
        source_duration,
        accepted,
        encoded_bytes,
        sent_at,
        final_epoch,
    } = producer.await.expect("frame producer");

    let DeliveryMeasurement {
        arrivals,
        received_at,
        delivered,
        superseded,
        outstanding,
        burst_span,
        timed_out,
    } = collect_deliveries(
        &mut arrival_rx,
        &sent_at,
        final_epoch,
        effective_delivery_timeout,
    )
    .await;

    let mut control_ready_at = Vec::new();
    while let Ok(at) = control_ready_rx.try_recv() {
        control_ready_at.push(at);
    }
    let recovery = resolve_recovery(blackout_task, &arrivals, &control_ready_at).await;

    let detach_sent = input_tx.send(ClientMessage::Detach).await.is_ok();
    let session_exit = session_task.await.expect("session task");
    let session_note = match session_exit {
        SessionExit::Detached => None,
        other => Some(format!(
            "QUIC session ended abnormally before this benchmark's own detach ({other:?}, \
             detach_sent={detach_sent}): the session abandons a connection only after \
             PATH_LOST_AFTER of unbroken silence, or when Connection::closed reports a real \
             failure, so reaching here means one of those happened rather than a recoverable \
             stall. Frames accepted/delivered before that point are still reported below; \
             nothing after it is."
        )),
    };
    if let Some(task) = proxy_task {
        task.abort();
    }
    event_forwarder.abort();
    arrival_collector.abort();

    ArmReport {
        label: "QUIC (resumable)",
        loss_enabled: loss_active(profile.loss_every_nth.is_some()),
        source_frames: source_frames(),
        accepted,
        delivered,
        superseded,
        outstanding,
        source_duration,
        encoded_bytes,
        delivery_burst_span: burst_span,
        frame_latencies: frame_latencies(&sent_at, &received_at),
        recovery,
        session_note,
        delivery_timed_out: timed_out,
    }
}

/// Runs the streaming portion of the TCP arm: a `ClientWriter` targeting
/// `ClientRenderTarget::Queue` drains through a writer thread that frames
/// bytes onto a raw TCP socket exactly like `client_writer_loop` does for
/// the SSH stdio bridge (`client_transport.rs`), and decoded on a reader
/// thread exactly like `client_read_loop`. This is the correct baseline for
/// any reliable-ordered tunnel (SSH's own bridge, or a third-party TCP
/// tunnel such as Eternal Terminal).
///
/// The path is shaped either by `run_tcp_proxy` or, under
/// `HERDR_BENCH_KERNEL_SHAPING=1`, by the kernel qdisc. `blackout` mirrors
/// `run_quic_arm`: when `Some`, the same schedule replays against the real
/// qdisc and `ArmReport` reports recovery latency from it. TCP has no
/// heartbeat/rebind/`SyncRequest` analog -- recovery here is purely "drain
/// whatever the kernel already accepted into the socket, once loss clears".
pub(super) async fn run_tcp_arm(
    profile: ShapingProfile,
    blackout: Option<BlackoutPlan>,
) -> ArmReport {
    assert!(
        kernel_shaping() || profile.loss_every_nth.is_none(),
        "a userspace TCP relay cannot drop bytes without corrupting length-prefixed framing; \
         run with HERDR_BENCH_KERNEL_SHAPING=1 to apply real packet loss with tc netem"
    );

    let server_listener =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind tcp server");
    let server_address = server_listener.local_addr().expect("tcp server address");

    let (mode_tx, mode_rx) = watch::channel(NetworkMode::Online);
    let (client_target, proxy_task) = if kernel_shaping() {
        drop(mode_rx);
        (server_address, None)
    } else {
        let proxy_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind tcp proxy");
        let proxy_address = proxy_listener.local_addr().expect("tcp proxy address");
        let task = tokio::spawn(run_tcp_proxy(
            proxy_listener,
            server_address,
            mode_rx,
            profile,
        ));
        (proxy_address, Some(task))
    };

    // Server side: a queue-backed `ClientWriter`, exactly like a real thin
    // client, drained by a thread that writes framed bytes straight onto
    // the TCP socket (mirrors `client_writer_loop`/`write_framed_bytes`).
    //
    // `test_queue`, not `test_channel`: the latter bypasses
    // `ClientWriterQueue` and hands every render to a channel, which would
    // give this arm a multi-frame application queue while the QUIC arm
    // accepts one render at a time behind `publish_render`'s busy flag.
    // Accepted counts, coalescing rate, and the encoder's dirty baseline all
    // follow from that gate, so the arms must share it or the comparison
    // measures queue policy instead of transport.
    let (writer, drain) = ClientWriter::test_queue();
    let writer_thread = std::thread::spawn(move || {
        let (mut server_conn, _) = server_listener
            .accept()
            .expect("accept tcp server connection");
        let _ = server_conn.set_nodelay(true);
        while let Some(data) = drain.recv() {
            if server_conn.write_all(&data).is_err() || server_conn.flush().is_err() {
                break;
            }
        }
        drain.close();
    });

    // Client side: decodes length-prefixed `ServerMessage` frames off the
    // shaped socket and timestamps arrival (mirrors `client_read_loop`).
    let mut client_conn = std::net::TcpStream::connect(client_target).expect("connect tcp client");
    client_conn.set_nodelay(true).expect("set nodelay");
    let (arrival_tx, mut arrival_rx) = mpsc::unbounded_channel::<Arrival>();
    let reader_thread = std::thread::spawn(move || {
        // TCP has no sync mechanism, so no generation reset and a single
        // epoch for the whole run. Tracked the same way regardless so the
        // two arms share one identity scheme.
        let mut epoch = 0u32;
        let mut last_seq = 0u64;
        loop {
            let message: Result<ServerMessage, _> =
                crate::protocol::read_message(&mut client_conn, crate::protocol::MAX_FRAME_SIZE);
            match message {
                Ok(ServerMessage::Terminal(frame)) => {
                    if frame.seq <= last_seq {
                        epoch += 1;
                    }
                    last_seq = frame.seq;
                    let arrival = Arrival {
                        mark: FrameMark {
                            epoch,
                            seq: frame.seq,
                        },
                        full: frame.full,
                        at: Instant::now(),
                    };
                    if arrival_tx.send(arrival).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Anchors the blackout schedule's offsets, exactly like `arm_start` in
    // `run_quic_arm`, so both arms replay the same schedule relative to
    // their own streaming start.
    let arm_start = Instant::now();

    // No relay receiver under kernel shaping.
    let _ = mode_tx.send(NetworkMode::ThreeG);

    let producer_writer = writer.clone();
    let highest_accepted_mark = Arc::new(AtomicU64::new(0));
    let effective_delivery_timeout = delivery_timeout(blackout.as_ref());
    let blackout_task = spawn_blackout(blackout, arm_start, &highest_accepted_mark, "TCP");
    // TCP never receives a sync request, so this flag is never set: the arm
    // recovers only by finishing its backlog, which is precisely the
    // behaviour under comparison.
    let producer = tokio::spawn(produce_frames(
        producer_writer,
        Arc::clone(&highest_accepted_mark),
        Arc::new(AtomicBool::new(false)),
    ));
    let FrameProducerResult {
        source_duration,
        accepted,
        encoded_bytes,
        sent_at,
        final_epoch,
    } = producer.await.expect("frame producer");

    let DeliveryMeasurement {
        arrivals,
        received_at,
        delivered,
        superseded,
        outstanding,
        burst_span,
        timed_out,
    } = collect_deliveries(
        &mut arrival_rx,
        &sent_at,
        final_epoch,
        effective_delivery_timeout,
    )
    .await;

    let recovery = resolve_recovery(blackout_task, &arrivals, &[]).await;

    // Dropping the writer removes the queue's last live sender, which
    // cascades: the internal drain thread exits and drops its channel
    // senders, the writer thread's `recv()` ends and closes the socket, and
    // the reader thread observes EOF and exits.
    drop(writer);
    let _ = writer_thread.join();
    let _ = reader_thread.join();
    if let Some(task) = proxy_task {
        task.abort();
    }

    ArmReport {
        label: "TCP (shaped, reliable)",
        loss_enabled: loss_active(false),
        source_frames: source_frames(),
        accepted,
        delivered,
        superseded,
        outstanding,
        source_duration,
        encoded_bytes,
        delivery_burst_span: burst_span,
        frame_latencies: frame_latencies(&sent_at, &received_at),
        recovery,
        session_note: None,
        delivery_timed_out: timed_out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(epoch: u32, seq: u64) -> FrameMark {
        FrameMark { epoch, seq }
    }

    #[tokio::test]
    async fn delivery_drain_classifies_missing_older_epochs_as_superseded() {
        let now = Instant::now();
        let sent_at = [(mark(0, 1), now), (mark(0, 2), now), (mark(1, 1), now)];
        let (arrival_tx, mut arrival_rx) = mpsc::unbounded_channel();
        for arrival in [
            Arrival {
                mark: mark(0, 1),
                full: true,
                at: now,
            },
            Arrival {
                mark: mark(1, 1),
                full: true,
                at: now,
            },
        ] {
            arrival_tx.send(arrival).expect("arrival receiver");
        }

        let measured =
            collect_deliveries(&mut arrival_rx, &sent_at, 1, Duration::from_secs(1)).await;

        assert_eq!(measured.delivered, 2);
        assert_eq!(measured.superseded, 1);
        assert_eq!(measured.outstanding, 0);
        assert!(!measured.timed_out);
    }

    #[tokio::test]
    async fn delivery_drain_reports_missing_final_epoch_as_outstanding() {
        let now = Instant::now();
        let sent_at = [(mark(1, 1), now)];
        let (arrival_tx, mut arrival_rx) = mpsc::unbounded_channel();
        drop(arrival_tx);

        let measured =
            collect_deliveries(&mut arrival_rx, &sent_at, 1, Duration::from_secs(1)).await;

        assert_eq!(measured.delivered, 0);
        assert_eq!(measured.superseded, 0);
        assert_eq!(measured.outstanding, 1);
        assert!(measured.timed_out);
    }
}
