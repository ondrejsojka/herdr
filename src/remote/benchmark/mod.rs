//! Explicit network benchmarks comparing transports for the Terminal-ANSI
//! stream: the resumable QUIC path, and a shaped reliable-TCP baseline
//! standing in for any reliable-ordered tunnel (SSH, or a third-party
//! solution such as Eternal Terminal).
//!
//! Entry points, all `#[ignore]`d — run explicitly:
//!
//! ```text
//! # benchmarks
//! cargo test --release --bin herdr -- --ignored --nocapture \
//!   terminal_ansi_3g_benchmark
//! cargo test --release --bin herdr -- --ignored --nocapture \
//!   terminal_transport_3g_comparison_benchmark
//!
//! # workload trace capture, prerequisites for HERDR_BENCH_WORKLOAD=htop|scroll
//! cargo test --release --bin herdr -- --ignored --nocapture capture_htop_trace
//! cargo test --release --bin herdr -- --ignored --nocapture capture_scroll_trace
//! ```
//!
//! Layout: [`config`] resolves every `HERDR_BENCH_*` knob and the shaping
//! profiles, [`trace`] captures and replays PTY workload traces, [`shaping`]
//! holds the userspace relays, [`blackout`] schedules and drives outages
//! against a real qdisc, [`arms`] runs the per-transport measurement arms,
//! and [`report`] formats their results. This module keeps only the test
//! entry points and the helpers they share.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};

use super::quic::{
    reconstruct_frame, ConnectParams, QuicSession, ResourceCache, SessionExit,
    STALE_CORROBORATED_AFTER,
};
use crate::protocol::{
    ClientKeybindings, ClientMessage, RemoteQuicRenderRecord, RemoteQuicResourceRef,
    RemoteTransportStatus, ServerMessage, TerminalFrame,
};
use crate::server::client_transport::{ClientWriter, ServerEvent};

mod arms;
mod blackout;
mod config;
mod report;
mod shaping;
mod trace;

use arms::*;
use blackout::*;
use config::*;
use report::*;
use shaping::*;
use trace::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit network performance benchmark"]
async fn terminal_ansi_3g_benchmark() {
    // Forces the userspace relay even under kernel shaping: the
    // blackhole-recovery section below needs an in-process kill switch it can
    // toggle synchronously, not a qdisc flip.
    let QuicArmHarness {
        session,
        writer,
        mut server_event_rx,
        proxy_task,
        mode_tx,
        _server,
    } = QuicArmHarness::start(THREE_G_PROFILE, 13, true).await;
    let proxy_task = proxy_task.expect("forced userspace relay");

    let (forwarded_event_tx, mut forwarded_event_rx) = mpsc::unbounded_channel();
    let event_forwarder = tokio::spawn(async move {
        while let Some(event) = server_event_rx.recv().await {
            if forwarded_event_tx.send(event).is_err() {
                break;
            }
        }
    });
    let (input_tx, input_rx) = mpsc::channel(16);
    let (output_tx, mut output_rx) = mpsc::channel(16);
    let session_task = tokio::spawn(session.run(input_rx, output_tx, false));
    let (application_tx, mut application_rx) = mpsc::unbounded_channel();
    let output_forwarder = tokio::spawn(async move {
        while let Some(message) = output_rx.recv().await {
            if application_tx.send(message).is_err() {
                break;
            }
        }
    });
    mode_tx
        .send(NetworkMode::ThreeG)
        .expect("enable 3G profile");

    let producer_writer = writer.clone();
    let highest_accepted_mark = Arc::new(AtomicU64::new(0));
    // This benchmark drives no blackout and never syncs, so the flag stays
    // clear and the producer runs in a single epoch.
    let producer = tokio::spawn(produce_frames(
        producer_writer,
        Arc::clone(&highest_accepted_mark),
        Arc::new(AtomicBool::new(false)),
    ));
    let FrameProducerResult {
        source_duration,
        accepted,
        encoded_bytes,
        ..
    } = producer.await.expect("frame producer");
    let mut delivered = 0u64;
    let mut first_visible = None;
    let mut last_visible = None;
    tokio::time::timeout(delivery_timeout(None), async {
        while delivered < accepted {
            // A closed channel must break, not fall through: the `while`
            // condition alone would spin at full CPU until the deadline, in
            // the one test that also measures CPU per frame.
            let Some(message) = application_rx.recv().await else {
                break;
            };
            if matches!(message, ServerMessage::Terminal(_)) {
                let now = Instant::now();
                first_visible.get_or_insert(now);
                last_visible = Some(now);
                delivered += 1;
            }
        }
    })
    .await
    .expect("60 fps delivery timeout");
    // This test asserts a sustained frame rate, so no delivery is a genuine
    // failure rather than something to report as `n/a`.
    let visible_span = last_visible
        .expect("last visible frame")
        .duration_since(first_visible.expect("first visible frame"));
    let delivered_fps = delivered.saturating_sub(1) as f64 / source_duration.as_secs_f64();
    let source_seconds = source_duration.as_secs_f64();
    let bytes_per_frame = encoded_bytes as f64 / accepted as f64;
    let bytes_per_second = encoded_bytes as f64 / source_seconds;

    let mut input_latencies = Vec::new();
    for (next_seq, sample) in (accepted + 1..).zip(0..INPUT_SAMPLES) {
        let payload = format!("latency-{sample}").into_bytes();
        let started = Instant::now();
        input_tx
            .send(ClientMessage::Input {
                data: payload.clone(),
            })
            .await
            .expect("send latency input");
        loop {
            match forwarded_event_rx.recv().await {
                Some(ServerEvent::ClientInput { data, .. }) if data == payload => break,
                Some(_) => {}
                None => panic!("server events ended"),
            }
        }
        let marker = format!("visible-{sample}").into_bytes();
        let framed = framed_terminal(next_seq, false, marker.clone());
        loop {
            match writer.render.try_send(framed.clone()) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    while !matches!(
                        forwarded_event_rx.recv().await,
                        Some(ServerEvent::ClientWriterDrained { .. })
                    ) {}
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    panic!("render writer disconnected")
                }
            }
        }
        loop {
            match application_rx.recv().await {
                Some(ServerMessage::Terminal(frame)) if frame.bytes == marker => break,
                Some(_) => {}
                None => panic!("application output ended"),
            }
        }
        input_latencies.push(started.elapsed());
    }
    input_latencies.sort_unstable();
    assert_eq!(
        input_latencies.len(),
        INPUT_SAMPLES as usize,
        "input latency sampling did not complete"
    );
    let p50 = percentile(&input_latencies, 50).expect("input latency samples");
    let p95 = percentile(&input_latencies, 95).expect("input latency samples");
    let p99 = percentile(&input_latencies, 99).expect("input latency samples");

    let application_record = RemoteQuicRenderRecord {
        connection_generation: 1,
        render_generation: 1,
        state_revision: 1,
        frame: TerminalFrame {
            seq: 1,
            width: 80,
            height: 24,
            full: true,
            bytes: b"beforemiddleafter".to_vec(),
        },
        resources: vec![
            RemoteQuicResourceRef {
                hash: [1; crate::protocol::REMOTE_QUIC_HASH_BYTES],
                text_offset: 6,
            },
            RemoteQuicResourceRef {
                hash: [2; crate::protocol::REMOTE_QUIC_HASH_BYTES],
                text_offset: 12,
            },
        ],
    };
    let application_started = Instant::now();
    for _ in 0..10_000 {
        let frame = reconstruct_frame(
            application_record.clone(),
            vec![
                b"\x1b_Gpayload\x1b\\".to_vec(),
                b"\x1b_Gplace\x1b\\".to_vec(),
            ],
        )
        .expect("reconstruct benchmark frame");
        std::hint::black_box(frame);
    }
    let application_cpu = application_started.elapsed() / 10_000;

    let serialization_started = Instant::now();
    for revision in 1..=10_000u64 {
        let _ = framed_terminal(revision, revision == 1, b"\x1b[Hcpu-sample".to_vec());
    }
    let serialization_cpu = serialization_started.elapsed() / 10_000;

    let rss_before_blackhole = linux_rss_bytes();
    mode_tx
        .send(NetworkMode::Blackhole)
        .expect("enable benchmark blackhole");
    tokio::time::timeout(Duration::from_secs(12), async {
        while !matches!(
            application_rx.recv().await,
            Some(ServerMessage::TransportStatus {
                status: RemoteTransportStatus::PathRecovering,
                ..
            })
        ) {}
    })
    .await
    .expect("benchmark recovery status timeout");
    // PathRecovering is announced before staleness is corroborated. Keep the
    // path dark past that second threshold so this benchmark actually drops
    // uncertain input and exercises the full-redraw recovery path.
    tokio::time::sleep(STALE_CORROBORATED_AFTER + Duration::from_millis(500)).await;
    let restored_at = Instant::now();
    mode_tx
        .send(NetworkMode::Online)
        .expect("restore benchmark path");
    while !matches!(
        forwarded_event_rx.recv().await,
        Some(ServerEvent::ClientSyncRequest { .. })
    ) {}
    writer.render.reset_generation();
    writer
        .render
        .try_send(framed_terminal(1, true, b"\x1b[2J\x1b[Hrecovered".to_vec()))
        .expect("send recovery keyframe");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !matches!(
            application_rx.recv().await,
            Some(ServerMessage::TransportStatus {
                status: RemoteTransportStatus::Connected,
                ..
            })
        ) {}
    })
    .await
    .expect("recovery keyframe timeout");
    let recovery_keyframe_latency = restored_at.elapsed();
    let stalled_memory_delta = linux_rss_bytes().saturating_sub(rss_before_blackhole);

    eprintln!(
        "3G profile: 1.6 Mbit/s down, 0.75 Mbit/s up, 260-340 ms RTT jitter, deterministic 0.99% packet loss"
    );
    eprintln!(
        "frames: source={frames} accepted={accepted} delivered={delivered} fps={delivered_fps:.2} delivery-burst-span={visible_span:?} bytes/frame={bytes_per_frame:.1} bytes/s={bytes_per_second:.1}",
        frames = source_frames(),
    );
    eprintln!(
        "input-to-visible: p50={p50:?} p95={p95:?} p99={p99:?}; serialization CPU/frame={serialization_cpu:?}; client application CPU/frame={application_cpu:?}"
    );
    eprintln!(
        "stalled RSS delta={stalled_memory_delta} bytes; recovery keyframe latency={recovery_keyframe_latency:?}"
    );

    assert_eq!(delivered, accepted);
    assert!(
        accepted >= 170,
        "render coalescing was excessive: {accepted}"
    );
    assert!(
        delivered_fps >= 57.0,
        "delivered fps was {delivered_fps:.2}"
    );
    assert!(
        p95 <= Duration::from_secs(1),
        "p95 input latency was {p95:?}"
    );
    assert!(
        recovery_keyframe_latency <= Duration::from_secs(3),
        "recovery keyframe took {recovery_keyframe_latency:?}"
    );
    assert!(stalled_memory_delta <= 128 * 1024 * 1024);

    input_tx.send(ClientMessage::Detach).await.expect("detach");
    assert!(matches!(
        session_task.await.expect("session task"),
        SessionExit::Detached
    ));
    proxy_task.abort();
    event_forwarder.abort();
    output_forwarder.abort();
}

/// Compares the QUIC arm against a shaped reliable-TCP baseline under the
/// same 3G-quality profile. Packet loss cannot be emulated on a userspace
/// TCP relay without corrupting the byte stream (dropping bytes desyncs
/// length-prefixed framing rather than triggering a retransmit), so the
/// head-to-head comparison runs both arms with loss disabled; the QUIC arm
/// with loss enabled (matching `terminal_ansi_3g_benchmark`) is reported
/// separately as a reference point, not as part of the apples-to-apples
/// comparison.
///
/// Under `HERDR_BENCH_KERNEL_SHAPING=1`, `blackout_plan()` additionally
/// resolves the in-process blackout controller from environment once (see
/// its doc comment) and the identical resulting schedule is cloned into
/// both arms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit network performance benchmark"]
async fn terminal_transport_3g_comparison_benchmark() {
    eprintln!(
        "3G profile: {down:.2} Mbit/s down, {up:.2} Mbit/s up, {lat_lo}-{lat_hi} ms RTT jitter",
        down = THREE_G_PROFILE.down_bytes_per_second * 8.0 / 1_000_000.0,
        up = THREE_G_PROFILE.up_bytes_per_second * 8.0 / 1_000_000.0,
        lat_lo = THREE_G_PROFILE.base_latency_ms * 2,
        lat_hi = (THREE_G_PROFILE.base_latency_ms + THREE_G_PROFILE.jitter_span_ms - 1) * 2,
    );
    // Resolved once, regardless of which branch runs below, so requesting
    // blackout without kernel shaping fails loudly instead of silently
    // running with no outages (see `blackout_plan`'s doc comment).
    let blackout = blackout_plan();

    if kernel_shaping() {
        eprintln!(
            "shaping: kernel qdisc (tc netem). Both arms bind plain sockets, so QUIC and TCP \
             see the same delay, jitter, bandwidth, and real packet loss. The qdisc \
             configuration is printed by the runner, not by this test."
        );
        let quic = run_quic_arm(THREE_G_PROFILE_NO_LOSS, blackout.clone()).await;
        let tcp = run_tcp_arm(THREE_G_PROFILE_NO_LOSS, blackout).await;
        eprintln!("-- head-to-head under kernel shaping --");
        quic.report();
        tcp.report();
        eprintln!(
            "comparison (kernel shaping, identical for both arms): QUIC fps={quic_fps:.2} p50={quic_p50} p95={quic_p95} p99={quic_p99} \
             vs TCP fps={tcp_fps:.2} p50={tcp_p50} p95={tcp_p95} p99={tcp_p99}",
            quic_fps = quic.delivered_fps(),
            quic_p50 = format_optional_duration(quic.latency_percentile(50)),
            quic_p95 = format_optional_duration(quic.latency_percentile(95)),
            quic_p99 = format_optional_duration(quic.latency_percentile(99)),
            tcp_fps = tcp.delivered_fps(),
            tcp_p50 = format_optional_duration(tcp.latency_percentile(50)),
            tcp_p95 = format_optional_duration(tcp.latency_percentile(95)),
            tcp_p99 = format_optional_duration(tcp.latency_percentile(99)),
        );
        if quic.blackout_window_count() > 0 || tcp.blackout_window_count() > 0 {
            // Only fresh-output is compared: it is the one moment both
            // transports can produce. QUIC additionally reports path-live and
            // full-convergence in its own block above; TCP has no sync
            // mechanism and therefore no canonical convergence event.
            eprintln!(
                "fresh-output recovery comparison (time until a post-outage frame lands): \
                 QUIC windows={quic_windows} unrecovered={quic_unrec} p50={quic_p50} \
                 p95={quic_p95} vs TCP windows={tcp_windows} unrecovered={tcp_unrec} \
                 p50={tcp_p50} p95={tcp_p95}",
                quic_windows = quic.blackout_window_count(),
                quic_unrec = quic.recovery.unrecovered,
                quic_p50 = format_optional_duration(quic.fresh_output_percentile(50)),
                quic_p95 = format_optional_duration(quic.fresh_output_percentile(95)),
                tcp_windows = tcp.blackout_window_count(),
                tcp_unrec = tcp.recovery.unrecovered,
                tcp_p50 = format_optional_duration(tcp.fresh_output_percentile(50)),
                tcp_p95 = format_optional_duration(tcp.fresh_output_percentile(95)),
            );
        }
        assert_eq!(
            quic.accepted,
            quic.delivered + quic.superseded + quic.outstanding
        );
        if quic.session_note.is_none() {
            assert_eq!(quic.outstanding, 0);
        }
        assert_eq!(tcp.accepted, tcp.delivered + tcp.outstanding);
        assert_eq!(tcp.superseded, 0);
        assert_eq!(tcp.outstanding, 0);
        return;
    }

    eprintln!(
        "loss caveat: a userspace TCP relay cannot emulate packet loss without corrupting the \
         byte stream (dropping bytes desyncs length-prefixed framing rather than triggering a \
         retransmit, unlike a real lossy link under TCP). The head-to-head QUIC-vs-TCP \
         comparison below therefore runs both arms with loss disabled; QUIC-with-loss is run \
         and reported separately as a reference point, not part of the apples-to-apples \
         comparison."
    );

    let quic_lossy = run_quic_arm(THREE_G_PROFILE, blackout.clone()).await;
    let quic_clean = run_quic_arm(THREE_G_PROFILE_NO_LOSS, blackout.clone()).await;
    let tcp_clean = run_tcp_arm(THREE_G_PROFILE_NO_LOSS, blackout).await;

    eprintln!("-- reference only (not part of the head-to-head): QUIC with loss enabled --");
    quic_lossy.report();
    eprintln!("-- head-to-head: loss disabled on both arms --");
    quic_clean.report();
    tcp_clean.report();

    eprintln!(
        "comparison (loss disabled on both): QUIC fps={quic_fps:.2} p50={quic_p50} p95={quic_p95} p99={quic_p99} bytes/frame={quic_bpf:.1} \
         vs TCP fps={tcp_fps:.2} p50={tcp_p50} p95={tcp_p95} p99={tcp_p99} bytes/frame={tcp_bpf:.1}; \
         reference QUIC-with-loss: fps={ref_fps:.2} p95={ref_p95} p99={ref_p99}",
        quic_fps = quic_clean.delivered_fps(),
        quic_p50 = format_optional_duration(quic_clean.latency_percentile(50)),
        quic_p95 = format_optional_duration(quic_clean.latency_percentile(95)),
        quic_p99 = format_optional_duration(quic_clean.latency_percentile(99)),
        quic_bpf = quic_clean.bytes_per_delivered_frame(),
        tcp_fps = tcp_clean.delivered_fps(),
        tcp_p50 = format_optional_duration(tcp_clean.latency_percentile(50)),
        tcp_p95 = format_optional_duration(tcp_clean.latency_percentile(95)),
        tcp_p99 = format_optional_duration(tcp_clean.latency_percentile(99)),
        tcp_bpf = tcp_clean.bytes_per_delivered_frame(),
        ref_fps = quic_lossy.delivered_fps(),
        ref_p95 = format_optional_duration(quic_lossy.latency_percentile(95)),
        ref_p99 = format_optional_duration(quic_lossy.latency_percentile(99)),
    );

    assert_eq!(quic_clean.superseded, 0);
    assert_eq!(quic_clean.outstanding, 0);
    assert_eq!(quic_clean.delivered, quic_clean.accepted);
    assert_eq!(tcp_clean.superseded, 0);
    assert_eq!(tcp_clean.outstanding, 0);
    assert_eq!(tcp_clean.delivered, tcp_clean.accepted);
}

fn linux_rss_bytes() -> usize {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .saturating_mul(1024)
}
