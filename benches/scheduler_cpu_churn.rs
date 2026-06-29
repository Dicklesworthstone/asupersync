//! Scheduler CPU/churn benchmark harness + recorded baseline
//! (`asupersync-runtime-cpu-overhaul-5vt09v.2`).
//!
//! This is ONE reproducible harness that reproduces the scheduler shape the
//! `frankenterm-gui` profile caught — many tasks each awaiting timers in a
//! loop, plus external readiness wakeups — and records the BASELINE numbers
//! every lever in the epic is measured against. It is also the regression gate.
//!
//! # What it drives
//! For each task count `M` in a sweep (`1, 16, 64, 256` by default):
//!   * an IDLE phase: the runtime exists but has no work for `idle_secs`; this
//!     is where the `sched_yield` busy-spin (Lever 2) and any idle thread churn
//!     show up. A correctly-parking runtime burns ~0 CPU here.
//!   * a LOAD phase: `M` tasks each loop awaiting `sleep()` at varied durations
//!     (1ms..250ms) — this is what produces the thread-per-`sleep` churn today
//!     (Lever 1) — while an external "I/O poker" thread enqueues wake-tasks at a
//!     fixed cadence (simulated I/O readiness so the worker park must wake on
//!     BOTH timers and external enqueues) and periodically fires a timestamped
//!     latency probe.
//!
//! # What it measures (idle phase AND load phase)
//!   * Process CPU time from `/proc/self/stat` (utime+stime ticks).
//!   * OS thread high-water from `/proc/self/task` sampled over the phase.
//!   * The [`runtime::metrics`](asupersync::runtime::metrics) counters:
//!     `timer_threads_spawned` (the headline churn signal), `sched_yield_calls`,
//!     `worker_spins`, `worker_parks`/`worker_unparks`, and the timer
//!     register/fire/cancel tally.
//!   * Wakeup latency p50/p99/p999: time from enqueue to first execution. This
//!     is the metric Lever 2 (bounded spin-then-park) must NOT regress.
//!
//! # Output
//! A structured JSON report (written to `--out <path>`, default
//! `artifacts/scheduler_cpu_churn/latest.json`) plus a human summary on stdout.
//! Commit the JSON as the baseline artifact and paste the key figures into the
//! bead so future self has the before-state without re-running.
//!
//! # Requires
//! `--features runtime-metrics,test-internals`. Without `runtime-metrics` the
//! counters read zero, so the harness is gated on it (`required-features`).
//!
//! Run:
//! ```bash
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_sched_churn \
//!   cargo bench --bench scheduler_cpu_churn \
//!   --features runtime-metrics,test-internals -- --out artifacts/scheduler_cpu_churn/baseline.json
//! ```

#![allow(missing_docs)]
// Measurement harness: counter/tick values are converted to f64 for human-facing
// percentages and to usize for percentile indexing. Precision loss / truncation on
// these diagnostic magnitudes is intentional and irrelevant to correctness.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::runtime::builder::RuntimeBuilder;
use asupersync::runtime::metrics::{self, Metrics};
use asupersync::time::sleep;

/// Read cumulative process CPU time (utime+stime) in clock ticks.
///
/// Parses `/proc/self/stat`. `comm` (field 2) may contain spaces/parens, so we
/// split after the final `)`; in the remainder `utime` and `stime` are the 12th
/// and 13th whitespace fields (0-based 11 and 12).
fn read_cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let Some(close) = stat.rfind(')') else {
        return 0;
    };
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    if fields.len() <= 12 {
        return 0;
    }
    let utime: u64 = fields[11].parse().unwrap_or(0);
    let stime: u64 = fields[12].parse().unwrap_or(0);
    utime + stime
}

/// `USER_HZ`: clock ticks per second. 100 on essentially all Linux builds.
const USER_HZ: f64 = 100.0;

/// Count live OS threads via `/proc/self/task`.
fn read_thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(Iterator::count)
        .unwrap_or(0)
}

/// `permille`-th percentile (e.g. 500 = p50, 990 = p99, 999 = p99.9) of a
/// pre-sorted slice, by nearest-rank with integer arithmetic.
fn percentile(sorted: &[u64], permille: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = permille * (sorted.len() - 1) / 1000;
    sorted[idx]
}

/// Samples the OS thread count on a background thread until stopped, recording
/// the high-water mark.
struct ThreadHighWater {
    stop: Arc<AtomicBool>,
    max: Arc<AtomicUsize>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ThreadHighWater {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let max = Arc::new(AtomicUsize::new(read_thread_count()));
        let handle = {
            let stop = Arc::clone(&stop);
            let max = Arc::clone(&max);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let n = read_thread_count();
                    max.fetch_max(n, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(20));
                }
                max.fetch_max(read_thread_count(), Ordering::Relaxed);
            })
        };
        Self {
            stop,
            max,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.max.load(Ordering::Relaxed)
    }
}

/// Per-phase measured deltas.
struct PhaseResult {
    cpu_ticks: u64,
    wall: Duration,
    thread_high_water: usize,
    metrics_delta: MetricsDelta,
}

struct MetricsDelta {
    timer_threads_spawned: u64,
    sched_yield_calls: u64,
    worker_spins: u64,
    worker_parks: u64,
    worker_unparks: u64,
    timers_registered: u64,
    timers_fired: u64,
    timers_cancelled: u64,
    active_timers_end: u64,
}

impl MetricsDelta {
    fn between(before: &Metrics, after: &Metrics) -> Self {
        Self {
            timer_threads_spawned: after
                .timer_threads_spawned
                .saturating_sub(before.timer_threads_spawned),
            sched_yield_calls: after
                .sched_yield_calls
                .saturating_sub(before.sched_yield_calls),
            worker_spins: after.worker_spins.saturating_sub(before.worker_spins),
            worker_parks: after.worker_parks.saturating_sub(before.worker_parks),
            worker_unparks: after.worker_unparks.saturating_sub(before.worker_unparks),
            timers_registered: after
                .timers_registered
                .saturating_sub(before.timers_registered),
            timers_fired: after.timers_fired.saturating_sub(before.timers_fired),
            timers_cancelled: after
                .timers_cancelled
                .saturating_sub(before.timers_cancelled),
            active_timers_end: after.active_timers,
        }
    }
}

fn cpu_percent(ticks: u64, wall: Duration) -> f64 {
    let cpu_secs = ticks as f64 / USER_HZ;
    let wall_secs = wall.as_secs_f64();
    if wall_secs <= 0.0 {
        0.0
    } else {
        cpu_secs / wall_secs * 100.0
    }
}

/// Run the IDLE phase: build a fresh runtime, do nothing for `dur`, measure.
fn measure_idle(workers: usize, dur: Duration) -> PhaseResult {
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .build()
        .expect("build idle runtime");
    // Give workers a beat to reach steady-state parking before sampling.
    std::thread::sleep(Duration::from_millis(100));

    let before = metrics::snapshot();
    let cpu0 = read_cpu_ticks();
    let hw = ThreadHighWater::start();
    let t0 = Instant::now();

    std::thread::sleep(dur);

    let wall = t0.elapsed();
    let cpu1 = read_cpu_ticks();
    let after = metrics::snapshot();
    let thread_high_water = hw.finish();

    drop(runtime);

    PhaseResult {
        cpu_ticks: cpu1.saturating_sub(cpu0),
        wall,
        thread_high_water,
        metrics_delta: MetricsDelta::between(&before, &after),
    }
}

/// Varied sleep durations cycled by each load task (1ms..250ms).
const DURS_MS: [u64; 8] = [1, 2, 5, 10, 25, 50, 100, 250];

/// Run the LOAD phase: `m` looping-sleep tasks + an external I/O poker that also
/// fires latency probes. Returns the phase result and sorted latency samples.
fn measure_load(workers: usize, m: usize, dur: Duration) -> (PhaseResult, Vec<u64>) {
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .build()
        .expect("build load runtime");
    std::thread::sleep(Duration::from_millis(100));

    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    let durs: Vec<Duration> = DURS_MS
        .iter()
        .map(|&ms| Duration::from_millis(ms))
        .collect();

    let before = metrics::snapshot();
    let cpu0 = read_cpu_ticks();
    let hw = ThreadHighWater::start();
    let t0 = Instant::now();

    // M sleeper tasks: each loops awaiting varied-duration sleeps until stopped.
    let handle = runtime.handle();
    for _ in 0..m {
        let stop = Arc::clone(&stop);
        let done = Arc::clone(&done);
        let durs = durs.clone();
        drop(handle.spawn(async move {
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let cx = Cx::current().expect("load task installs a Cx");
                let dur = durs[i % durs.len()];
                sleep(cx.now(), dur).await;
                i += 1;
            }
            done.fetch_add(1, Ordering::Release);
        }));
    }

    // External I/O poker: enqueue wake-tasks (simulated readiness) and fire
    // timestamped latency probes at a fixed cadence.
    let latencies = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    let poker = {
        let poker_handle = runtime.handle();
        let stop = Arc::clone(&stop);
        let latencies = Arc::clone(&latencies);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Simulated I/O readiness: an external enqueue that must unpark a
                // worker.
                drop(poker_handle.spawn(async {}));
                // Latency probe: measure enqueue -> first-execution time.
                let probe_t0 = Instant::now();
                let latencies = Arc::clone(&latencies);
                drop(poker_handle.spawn(async move {
                    let ns = u64::try_from(probe_t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    latencies.lock().expect("latency mutex").push(ns);
                }));
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };

    std::thread::sleep(dur);
    stop.store(true, Ordering::Release);
    let _ = poker.join();

    // Drain the sleeper tasks: each finishes its in-flight sleep then exits.
    let deadline = Instant::now() + Duration::from_secs(5);
    while done.load(Ordering::Acquire) < m && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }

    let wall = t0.elapsed();
    let cpu1 = read_cpu_ticks();
    let after = metrics::snapshot();
    let thread_high_water = hw.finish();

    drop(runtime);

    // The runtime is shut down, so all latency-probe tasks (which held Arc
    // clones) have been dropped; lock-and-clone is robust regardless.
    let mut lat = latencies.lock().expect("latency mutex").clone();
    lat.sort_unstable();

    (
        PhaseResult {
            cpu_ticks: cpu1.saturating_sub(cpu0),
            wall,
            thread_high_water,
            metrics_delta: MetricsDelta::between(&before, &after),
        },
        lat,
    )
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    // --out <path> from args; env overrides for phase shape.
    let mut out_path = String::from("artifacts/scheduler_cpu_churn/latest.json");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--out" {
            if let Some(p) = args.next() {
                out_path = p;
            }
        }
    }
    let workers = env_usize("SCHED_CHURN_WORKERS", 4);
    let idle_secs = env_usize("SCHED_CHURN_IDLE_SECS", 2);
    let load_secs = env_usize("SCHED_CHURN_LOAD_SECS", 3);
    let m_sweep: Vec<usize> = std::env::var("SCHED_CHURN_M")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 16, 64, 256]);

    if !metrics_enabled() {
        eprintln!(
            "WARNING: built without --features runtime-metrics; counters will read zero. \
             Rebuild with --features runtime-metrics,test-internals for a real baseline."
        );
    }

    eprintln!(
        "scheduler_cpu_churn: workers={workers} idle={idle_secs}s load={load_secs}s M={m_sweep:?}"
    );

    let mut rows = Vec::new();

    // One shared idle phase (M is irrelevant when idle); measured once.
    let idle = measure_idle(workers, Duration::from_secs(idle_secs as u64));
    let idle_json = phase_json("idle", 0, &idle, &[]);
    eprintln!(
        "  IDLE: cpu={:.1}% threads_hw={} sched_yield={} worker_parks={} timer_threads={}",
        cpu_percent(idle.cpu_ticks, idle.wall),
        idle.thread_high_water,
        idle.metrics_delta.sched_yield_calls,
        idle.metrics_delta.worker_parks,
        idle.metrics_delta.timer_threads_spawned,
    );
    rows.push(idle_json);

    for &m in &m_sweep {
        let (load, lat) = measure_load(workers, m, Duration::from_secs(load_secs as u64));
        let secs = load.wall.as_secs_f64().max(f64::MIN_POSITIVE);
        eprintln!(
            "  LOAD M={m:>4}: cpu={:.1}% threads_hw={} timer_threads={} (~{:.0}/s) \
             sched_yield={} parks={} unparks={} fired={} p50={}us p99={}us p999={}us",
            cpu_percent(load.cpu_ticks, load.wall),
            load.thread_high_water,
            load.metrics_delta.timer_threads_spawned,
            load.metrics_delta.timer_threads_spawned as f64 / secs,
            load.metrics_delta.sched_yield_calls,
            load.metrics_delta.worker_parks,
            load.metrics_delta.worker_unparks,
            load.metrics_delta.timers_fired,
            percentile(&lat, 500) / 1000,
            percentile(&lat, 990) / 1000,
            percentile(&lat, 999) / 1000,
        );
        rows.push(phase_json("load", m, &load, &lat));
    }

    let report = serde_json::json!({
        "harness": "scheduler_cpu_churn",
        "bead": "asupersync-runtime-cpu-overhaul-5vt09v.2",
        "runtime_metrics_enabled": metrics_enabled(),
        "config": {
            "workers": workers,
            "idle_secs": idle_secs,
            "load_secs": load_secs,
            "m_sweep": m_sweep,
            "durs_ms": DURS_MS,
            "user_hz": USER_HZ,
        },
        "phases": rows,
    });

    let pretty = serde_json::to_string_pretty(&report).unwrap_or_default();
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&out_path, &pretty) {
        Ok(()) => eprintln!("wrote baseline report -> {out_path}"),
        Err(e) => eprintln!("FAILED to write {out_path}: {e}"),
    }
    // Also emit to stdout so the report is captured even when the harness runs
    // on a remote worker whose filesystem is not retrieved (e.g. under RCH).
    println!("{pretty}");
}

/// Whether the `runtime-metrics` feature is compiled in (counters are live).
fn metrics_enabled() -> bool {
    cfg!(feature = "runtime-metrics")
}

fn phase_json(phase: &str, m: usize, r: &PhaseResult, lat: &[u64]) -> serde_json::Value {
    serde_json::json!({
        "phase": phase,
        "m": m,
        "wall_ms": r.wall.as_millis(),
        "cpu_ticks": r.cpu_ticks,
        "cpu_percent": cpu_percent(r.cpu_ticks, r.wall),
        "thread_high_water": r.thread_high_water,
        "timer_threads_spawned": r.metrics_delta.timer_threads_spawned,
        "sched_yield_calls": r.metrics_delta.sched_yield_calls,
        "worker_spins": r.metrics_delta.worker_spins,
        "worker_parks": r.metrics_delta.worker_parks,
        "worker_unparks": r.metrics_delta.worker_unparks,
        "timers_registered": r.metrics_delta.timers_registered,
        "timers_fired": r.metrics_delta.timers_fired,
        "timers_cancelled": r.metrics_delta.timers_cancelled,
        "active_timers_end": r.metrics_delta.active_timers_end,
        "latency_samples": lat.len(),
        "latency_p50_us": percentile(lat, 500) / 1000,
        "latency_p99_us": percentile(lat, 990) / 1000,
        "latency_p999_us": percentile(lat, 999) / 1000,
    })
}
