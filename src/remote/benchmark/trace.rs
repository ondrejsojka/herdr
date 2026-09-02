use super::*;
/// Envvar overriding where the `htop` workload reads its captured PTY
/// trace. Capture one with `capture_htop_trace` below.
pub(super) const HTOP_TRACE_PATH_ENV: &str = "HERDR_BENCH_HTOP_TRACE";
/// Default location of the captured htop trace. Gitignored under `.local/`:
/// it is a binary blob, not source.
pub(super) const HTOP_TRACE_DEFAULT_PATH: &str = ".local/htop-trace.bin";
/// Tags the trace file format so pointing the env var at an unrelated file
/// fails clearly instead of misparsing.
pub(super) const HTOP_TRACE_MAGIC: &[u8; 8] = b"HTOPTRC1";

/// Envvar overriding where the `scroll` workload reads its captured PTY
/// trace. Capture one with `capture_scroll_trace` below.
pub(super) const SCROLL_TRACE_PATH_ENV: &str = "HERDR_BENCH_SCROLL_TRACE";
/// Default location of the captured scroll trace. Gitignored under
/// `.local/`: it is a binary blob, not source.
pub(super) const SCROLL_TRACE_DEFAULT_PATH: &str = ".local/scroll-trace.bin";
/// Tags the trace file format so pointing the env var at an unrelated file
/// fails clearly instead of misparsing.
pub(super) const SCROLL_TRACE_MAGIC: &[u8; 8] = b"SCRLTRC1";

pub(super) fn trace_path(env: &str, default: &str) -> std::path::PathBuf {
    std::env::var_os(env)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(default))
}

pub(super) fn htop_trace_path() -> std::path::PathBuf {
    trace_path(HTOP_TRACE_PATH_ENV, HTOP_TRACE_DEFAULT_PATH)
}

pub(super) fn scroll_trace_path() -> std::path::PathBuf {
    trace_path(SCROLL_TRACE_PATH_ENV, SCROLL_TRACE_DEFAULT_PATH)
}

/// One PTY read from a captured session (`htop` or `scroll`): `at` is
/// elapsed time since the capture started, `bytes` is exactly what the PTY
/// master returned.
pub(super) struct PtyTraceChunk {
    pub(super) at: Duration,
    pub(super) bytes: Vec<u8>,
}

/// Loads a deterministic PTY trace consumed by `HERDR_BENCH_WORKLOAD=htop`
/// or `=scroll`. Shared by both workloads so the trace file format and
/// parser exist exactly once.
///
/// Fails naming the exact capture command rather than silently falling back
/// to the synthetic workload, since workloads must never be interchanged
/// inside a single comparison run without the caller knowing.
pub(super) fn load_pty_trace(
    path: std::path::PathBuf,
    magic: &[u8; 8],
    capture_test_name: &str,
) -> Vec<PtyTraceChunk> {
    let bytes = std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "this workload requires a captured trace at {path} ({err}); capture one with: \
             cargo test --release --bin herdr -- --ignored --nocapture {capture_test_name}",
            path = path.display(),
        )
    });
    assert!(
        bytes.len() >= magic.len() && bytes[..magic.len()] == magic[..],
        "{} is not a recognized trace for {capture_test_name} (bad magic); recapture with \
         {capture_test_name}",
        path.display(),
    );
    let mut cursor = &bytes[magic.len()..];
    let mut chunks = Vec::new();
    while !cursor.is_empty() {
        let (at_bytes, rest) = cursor.split_at(8);
        let at = Duration::from_micros(u64::from_le_bytes(at_bytes.try_into().unwrap()));
        let (len_bytes, rest) = rest.split_at(4);
        let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        let (payload, rest) = rest.split_at(len);
        chunks.push(PtyTraceChunk {
            at,
            bytes: payload.to_vec(),
        });
        cursor = rest;
    }
    assert!(
        !chunks.is_empty(),
        "{} contains no captured chunks",
        path.display()
    );
    chunks
}

pub(super) fn load_htop_trace() -> Vec<PtyTraceChunk> {
    load_pty_trace(htop_trace_path(), HTOP_TRACE_MAGIC, "capture_htop_trace")
}

pub(super) fn load_scroll_trace() -> Vec<PtyTraceChunk> {
    load_pty_trace(
        scroll_trace_path(),
        SCROLL_TRACE_MAGIC,
        "capture_scroll_trace",
    )
}

/// Captures a deterministic PTY trace at 80x24: every PTY-master read is
/// recorded as `(elapsed, bytes)` so replay reproduces the exact same
/// content and pacing on every run. Shared by `capture_htop_trace` and
/// `capture_scroll_trace` so both traces use exactly one file format and
/// exactly one parser (`load_pty_trace`).
pub(super) fn capture_pty_trace(
    mut cmd: portable_pty::CommandBuilder,
    spawn_error: &str,
    path: std::path::PathBuf,
    magic: &[u8; 8],
    capture_seconds_env: &str,
    default_seconds: u64,
) {
    use portable_pty::{native_pty_system, PtyPair, PtySize};
    use std::io::Read;

    let capture_duration = Duration::from_secs(
        std::env::var(capture_seconds_env)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .unwrap_or(default_seconds),
    );

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open pty for trace capture");
    let PtyPair { slave, master } = pair;
    cmd.env("TERM", "xterm-256color");
    let mut child = slave.spawn_command(cmd).expect(spawn_error);
    drop(slave);

    let mut killer = child.clone_killer();
    let killer_thread = std::thread::spawn(move || {
        std::thread::sleep(capture_duration);
        let _ = killer.kill();
    });

    let mut reader = master
        .try_clone_reader()
        .expect("clone pty reader for trace capture");
    let started = Instant::now();
    let mut chunks: Vec<(Duration, Vec<u8>)> = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => chunks.push((started.elapsed(), buf[..n].to_vec())),
            Err(_) => break,
        }
    }
    drop(reader);
    let _ = child.wait();
    let _ = killer_thread.join();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create trace directory");
    }
    let mut file = std::fs::File::create(&path).expect("create trace file");
    file.write_all(magic).expect("write trace magic");
    let mut total_bytes = 0usize;
    for (at, bytes) in &chunks {
        file.write_all(&(at.as_micros() as u64).to_le_bytes())
            .expect("write chunk timestamp");
        file.write_all(&(bytes.len() as u32).to_le_bytes())
            .expect("write chunk length");
        file.write_all(bytes).expect("write chunk bytes");
        total_bytes += bytes.len();
    }
    file.flush().expect("flush trace file");

    eprintln!(
        "captured {chunks} PTY reads, {bytes} bytes, over {elapsed:?} to {path}",
        chunks = chunks.len(),
        bytes = total_bytes,
        elapsed = started.elapsed(),
        path = path.display(),
    );
}

/// Captures a deterministic htop trace for `HERDR_BENCH_WORKLOAD=htop`:
/// `htop` runs under a real PTY fixed at 80x24. Requires `htop` on this
/// host (the netem container installs it separately for its own runs;
/// install locally too -- e.g. `brew install htop` or `apt-get install
/// htop` -- to run this specific test here).
///
/// Run manually; it is not part of any suite and writes a binary blob under
/// `.local/` (gitignored), never to `src/`:
///
/// `HERDR_BENCH_HTOP_CAPTURE_SECONDS=150 cargo test --release --bin herdr -- \
///   --ignored --nocapture capture_htop_trace`
///
/// 150s comfortably covers a 120s (7200-frame) run without looping.
#[test]
#[ignore = "captures a real htop PTY session; run manually, see doc comment"]
pub(super) fn capture_htop_trace() {
    capture_pty_trace(
        portable_pty::CommandBuilder::new("htop"),
        "spawn htop for capture; install it first (brew install htop / apt-get install htop)",
        htop_trace_path(),
        HTOP_TRACE_MAGIC,
        "HERDR_BENCH_HTOP_CAPTURE_SECONDS",
        150,
    );
}

/// Captures a deterministic continuously-scrolling trace for
/// `HERDR_BENCH_WORKLOAD=scroll`, standing in for a build log, `yes`,
/// `find /`, or any other command that repaints nearly the whole 80x24
/// screen every frame. Uses `find /`, which prints varying-length paths
/// (plus permission-denied noise on stderr, also realistic build-log
/// texture) fast enough to keep the terminal continuously scrolling for the
/// whole capture window; needs no extra host dependency.
///
/// Run manually; it is not part of any suite and writes a binary blob under
/// `.local/` (gitignored), never to `src/`:
///
/// `HERDR_BENCH_SCROLL_CAPTURE_SECONDS=150 cargo test --release --bin herdr -- \
///   --ignored --nocapture capture_scroll_trace`
///
/// 150s comfortably covers a 120s (7200-frame) run without looping.
#[test]
#[ignore = "captures a continuously scrolling PTY session; run manually, see doc comment"]
pub(super) fn capture_scroll_trace() {
    let mut cmd = portable_pty::CommandBuilder::new("find");
    cmd.arg("/");
    capture_pty_trace(
        cmd,
        "spawn find for scroll-trace capture",
        scroll_trace_path(),
        SCROLL_TRACE_MAGIC,
        "HERDR_BENCH_SCROLL_CAPTURE_SECONDS",
        150,
    );
}
