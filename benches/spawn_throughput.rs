#![cfg(feature = "test-internals")]
//! Spawn-throughput and join-completion benchmarks: direct vs mailbox admission
//! (br-asupersync-dx-core-api-v2-u1z5hn.1.3, parent AC 4).
//!
//! Measures the full runtime spawn path — `RuntimeHandle::spawn` through
//! task completion — under single-producer and contended multi-producer
//! loads, in both `SpawnAdmissionMode::Direct` (state lock per spawn) and
//! `SpawnAdmissionMode::Mailbox` (lock-free enqueue, worker-side batch
//! admission). The contended case is the one the mailbox exists for: the
//! direct path serializes every producer on the `RuntimeState` lock.
//! The join-completion group measures the caller-visible cost of collecting
//! completed [`TaskHandle`](asupersync::runtime::TaskHandle) values in the same
//! deterministic batch shape.
//! The spawn-throughput groups stop when every task body has executed. Runtime
//! task-record teardown may trail a body counter: repeated iterations amortize
//! most cleanup into later samples, while the final cleanup tail can fall
//! outside the measurement.
//! The adversarial overdrive rows instead gate every body until all submissions
//! return, then measure submit through full runtime quiescence. Global-ready
//! depth is only an observation; it excludes local, in-flight, and mailbox work.
//! Deferred quota and cancel request-tail reports are ordered-join observations,
//! not first-terminal timestamps. Runtime teardown rows measure destructor-driven
//! destruction of polled pending futures, not structured region close or drain.
//!
//! Deterministic inputs; throughput in spawned tasks per second.

#![allow(missing_docs)]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::runtime::builder::{Runtime, RuntimeBuilder, RuntimeHandle};
use asupersync::runtime::config::SpawnAdmissionMode;
use asupersync::runtime::{JoinError, RegionLimits, SpawnError, TaskHandle};
use asupersync::types::{CancelKind, CancelReason};

const SPAWNS_PER_ITER: usize = 1_000;
const ADVERSARIAL_REQUESTS: usize = 256;

struct CompletionLatch {
    completed: AtomicUsize,
    wait_lock: Mutex<()>,
    ready: Condvar,
}

impl CompletionLatch {
    fn new() -> Self {
        Self {
            completed: AtomicUsize::new(0),
            wait_lock: Mutex::new(()),
            ready: Condvar::new(),
        }
    }

    fn reset(&self) {
        self.completed.store(0, Ordering::SeqCst);
    }

    fn count(&self) -> usize {
        self.completed.load(Ordering::Acquire)
    }

    fn complete(&self, expected: usize) {
        let completed = self.completed.fetch_add(1, Ordering::Release) + 1;
        if completed == expected {
            let _guard = self
                .wait_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.ready.notify_one();
        }
    }

    fn wait(&self, expected: usize) {
        let guard = self
            .wait_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_guard, timeout) = self
            .ready
            .wait_timeout_while(guard, Duration::from_secs(30), |_| {
                self.completed.load(Ordering::Acquire) < expected
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let completed = self.completed.load(Ordering::Acquire);
        assert_eq!(
            completed,
            expected,
            "benchmark task-body completion mismatch (timed_out={})",
            timeout.timed_out()
        );
    }
}

struct ProducerStopGuard<'a> {
    stop: &'a AtomicBool,
    start: &'a Barrier,
}

impl Drop for ProducerStopGuard<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.start.wait();
    }
}

fn build_runtime(mode: SpawnAdmissionMode, workers: usize) -> Runtime {
    RuntimeBuilder::new()
        .worker_threads(workers)
        .spawn_admission(mode)
        .build()
        .expect("build benchmark runtime")
}

/// Spawn `SPAWNS_PER_ITER` trivial tasks from one producer thread and wait
/// for all of them to finish (completion observed via a shared counter so
/// the measurement covers admission + execution, not just enqueue).
fn spawn_burst_single(runtime: &Runtime, completion: &Arc<CompletionLatch>) {
    let handle = runtime.handle();
    completion.reset();
    for _ in 0..SPAWNS_PER_ITER {
        let completion = Arc::clone(completion);
        drop(handle.spawn(async move {
            completion.complete(SPAWNS_PER_ITER);
        }));
    }
    completion.wait(SPAWNS_PER_ITER);
}

/// Release persistent producer threads for one exact burst, wait until every
/// spawn call has returned, then wait for every task body to execute.
fn run_contended_iteration(
    runtime: &Runtime,
    completion: &CompletionLatch,
    release: &AtomicBool,
    start: &Barrier,
    submitted: &Barrier,
    producer_failed: &AtomicBool,
    expected: usize,
) -> (usize, usize) {
    completion.reset();
    release.store(false, Ordering::Release);
    start.wait();
    submitted.wait();
    assert!(
        !producer_failed.load(Ordering::Acquire),
        "a persistent producer panicked while submitting its burst"
    );
    assert_eq!(completion.count(), 0, "release gate leaked task completion");
    let unfinished_at_submit = expected;
    let global_ready_at_submit = runtime.scheduler_global_ready_depth();
    release.store(true, Ordering::Release);
    completion.wait(expected);
    wait_for_quiescence(runtime);
    (unfinished_at_submit, global_ready_at_submit)
}

/// Spawn `SPAWNS_PER_ITER` trivial tasks and await every returned handle.
///
/// This isolates the handle-completion collection path that higher-level
/// fan-out helpers build on, while keeping the task body itself constant and
/// deterministic.
fn join_handle_completion_batch(runtime: &Runtime) {
    runtime.block_on(async {
        let handle = Runtime::current_handle().expect("block_on installs runtime handle");
        let mut joins = Vec::with_capacity(SPAWNS_PER_ITER);
        for value in 0..SPAWNS_PER_ITER {
            joins.push(handle.spawn(async move { value }));
        }

        let mut checksum = 0usize;
        for join in joins {
            checksum = checksum.wrapping_add(join.await);
        }
        black_box(checksum);
    });
}

fn acquire_root_cx(runtime: &Runtime, keep_task_live: bool) -> Cx {
    let (sender, receiver) = mpsc::sync_channel(1);
    runtime
        .handle()
        .try_spawn_with_cx(move |cx| {
            sender
                .send(cx.clone())
                .expect("root-Cx receiver remains live during setup");
            async move {
                if keep_task_live {
                    std::future::pending::<()>().await;
                }
            }
        })
        .expect("admit root-Cx benchmark task");
    receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("root-Cx setup watchdog expired")
}

struct QuotaScenario {
    runtime: Runtime,
    handle: RuntimeHandle,
    cx: Cx,
}

fn quota_scenario(mode: SpawnAdmissionMode) -> QuotaScenario {
    let runtime = RuntimeBuilder::new()
        .worker_threads(4)
        .spawn_admission(mode)
        .root_region_limits(RegionLimits {
            max_tasks: Some(1),
            ..RegionLimits::unlimited()
        })
        .build()
        .expect("build quota benchmark runtime");
    let cx = acquire_root_cx(&runtime, true);
    let handle = runtime.handle();
    QuotaScenario {
        runtime,
        handle,
        cx,
    }
}

fn direct_quota_denial(scenario: &QuotaScenario, collect_tails: bool) -> Vec<Duration> {
    let mut tails = collect_tails
        .then(|| Vec::with_capacity(ADVERSARIAL_REQUESTS))
        .unwrap_or_default();
    for _ in 0..ADVERSARIAL_REQUESTS {
        let started = collect_tails.then(Instant::now);
        let result = scenario.handle.try_spawn(async {});
        assert!(
            matches!(
                result,
                Err(SpawnError::RegionAtCapacity {
                    limit: 1,
                    live: 1,
                    ..
                })
            ),
            "direct quota cell must return the exact typed capacity denial"
        );
        if let Some(started) = started {
            tails.push(started.elapsed());
        }
    }
    tails
}

fn deferred_gateway_quota_denial(scenario: &QuotaScenario, collect_tails: bool) -> Vec<Duration> {
    let mut pending = Vec::with_capacity(ADVERSARIAL_REQUESTS);
    for _ in 0..ADVERSARIAL_REQUESTS {
        let started = collect_tails.then(Instant::now);
        let task = scenario
            .cx
            .spawn(|_child| async {})
            .expect("gateway enqueue remains available");
        pending.push((task, started));
    }

    let mut tails = collect_tails
        .then(|| Vec::with_capacity(ADVERSARIAL_REQUESTS))
        .unwrap_or_default();
    scenario.runtime.block_on(async {
        for (mut task, started) in pending {
            let result = task.join(&scenario.cx).await;
            match result {
                Err(JoinError::Cancelled(reason)) => assert!(
                    reason
                        .message
                        .as_deref()
                        .is_some_and(|message| message.starts_with("[ASUP-E006]")),
                    "deferred quota denial must retain the ASUP-E006 diagnostic: {reason:?}"
                ),
                other => panic!("expected deferred capacity cancellation, got {other:?}"),
            }
            if let Some(started) = started {
                tails.push(started.elapsed());
            }
        }
    });
    tails
}

struct CompletionGuard {
    completion: Arc<CompletionLatch>,
    expected: usize,
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.completion.complete(self.expected);
    }
}

struct CancelStormScenario {
    runtime: Runtime,
    cx: Cx,
    tasks: Vec<TaskHandle<Result<(), asupersync::Error>>>,
    finalized: Arc<CompletionLatch>,
}

fn cancel_storm_scenario() -> CancelStormScenario {
    let runtime = build_runtime(SpawnAdmissionMode::Mailbox, 4);
    let cx = acquire_root_cx(&runtime, false);
    let started = Arc::new(CompletionLatch::new());
    let finalized = Arc::new(CompletionLatch::new());
    let mut tasks = Vec::with_capacity(ADVERSARIAL_REQUESTS);
    for _ in 0..ADVERSARIAL_REQUESTS {
        let started = Arc::clone(&started);
        let finalized = Arc::clone(&finalized);
        tasks.push(
            cx.spawn(move |child| async move {
                let _guard = CompletionGuard {
                    completion: finalized,
                    expected: ADVERSARIAL_REQUESTS,
                };
                started.complete(ADVERSARIAL_REQUESTS);
                loop {
                    if let Err(error) = child.checkpoint() {
                        break Err(error);
                    }
                    asupersync::runtime::yield_now().await;
                }
            })
            .expect("enqueue cancel-storm task"),
        );
    }
    started.wait(ADVERSARIAL_REQUESTS);
    CancelStormScenario {
        runtime,
        cx,
        tasks,
        finalized,
    }
}

fn cancel_storm(scenario: &mut CancelStormScenario, collect_tails: bool) -> Vec<Duration> {
    let storm_started = Instant::now();
    for task in &scenario.tasks {
        task.abort_with_reason(CancelReason::user("adversarial cancel storm"));
    }
    let mut tails = collect_tails
        .then(|| Vec::with_capacity(ADVERSARIAL_REQUESTS))
        .unwrap_or_default();
    scenario.runtime.block_on(async {
        for task in &mut scenario.tasks {
            match task.join(&scenario.cx).await {
                Err(JoinError::Cancelled(reason)) => {
                    assert_eq!(reason.kind, CancelKind::User);
                    assert_eq!(reason.message.as_deref(), Some("adversarial cancel storm"));
                }
                other => panic!("cancel storm task did not observe cancellation: {other:?}"),
            }
            if collect_tails {
                tails.push(storm_started.elapsed());
            }
        }
    });
    assert_eq!(scenario.finalized.count(), ADVERSARIAL_REQUESTS);
    tails
}

fn wait_for_quiescence(runtime: &Runtime) {
    let watchdog = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            watchdog.elapsed() < Duration::from_secs(30),
            "runtime quiescence watchdog expired"
        );
        std::thread::yield_now();
    }
}

struct RuntimeTeardownScenario {
    runtime: Option<Runtime>,
    finalized: Arc<CompletionLatch>,
}

fn runtime_teardown_scenario(mode: SpawnAdmissionMode) -> RuntimeTeardownScenario {
    let runtime = build_runtime(mode, 4);
    let handle = runtime.handle();
    let started = Arc::new(CompletionLatch::new());
    let finalized = Arc::new(CompletionLatch::new());
    for _ in 0..ADVERSARIAL_REQUESTS {
        let started = Arc::clone(&started);
        let finalized = Arc::clone(&finalized);
        drop(handle.spawn(async move {
            let _guard = CompletionGuard {
                completion: finalized,
                expected: ADVERSARIAL_REQUESTS,
            };
            started.complete(ADVERSARIAL_REQUESTS);
            std::future::pending::<()>().await;
        }));
    }
    drop(handle);
    started.wait(ADVERSARIAL_REQUESTS);
    RuntimeTeardownScenario {
        runtime: Some(runtime),
        finalized,
    }
}

fn runtime_teardown(scenario: &mut RuntimeTeardownScenario) {
    drop(
        scenario
            .runtime
            .take()
            .expect("runtime teardown scenario is single-use"),
    );
    scenario.finalized.wait(ADVERSARIAL_REQUESTS);
}

fn emit_request_tail_report(cell: &str, scope: &str, tails: &mut [Duration], total: Duration) {
    assert_eq!(tails.len(), ADVERSARIAL_REQUESTS);
    tails.sort_unstable();
    let quantile = |percent: usize| tails[(tails.len() - 1) * percent / 100].as_nanos();
    eprintln!(
        "adversarial_tail_report cell={cell} scope={scope} count={} p50_ns={} p95_ns={} p99_ns={} total_ns={} throughput_per_s={:.3}",
        tails.len(),
        quantile(50),
        quantile(95),
        quantile(99),
        total.as_nanos(),
        tails.len() as f64 / total.as_secs_f64()
    );
}

fn adversarial_reports_enabled() -> bool {
    std::env::var_os("ASUPERSYNC_ADVERSARIAL_REPORT").is_some()
}

fn bench_spawn_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn_throughput");
    group.throughput(Throughput::Elements(SPAWNS_PER_ITER as u64));
    group.sample_size(20);

    for (label, mode) in [
        ("direct", SpawnAdmissionMode::Direct),
        ("mailbox", SpawnAdmissionMode::Mailbox),
    ] {
        let runtime = build_runtime(mode, 4);
        let completion = Arc::new(CompletionLatch::new());
        group.bench_function(BenchmarkId::new("single_producer_latched", label), |b| {
            b.iter(|| spawn_burst_single(black_box(&runtime), &completion));
        });
        drop(runtime);

        for producers in [4usize, 8] {
            assert_eq!(
                SPAWNS_PER_ITER % producers,
                0,
                "the benchmark must divide work evenly across producers"
            );
            let per_producer = SPAWNS_PER_ITER / producers;
            let runtime = build_runtime(mode, 4);
            let completion = Arc::new(CompletionLatch::new());
            let ready = Arc::new(Barrier::new(producers + 1));
            let start = Arc::new(Barrier::new(producers + 1));
            let submitted = Arc::new(Barrier::new(producers + 1));
            let stop = Arc::new(AtomicBool::new(false));
            let producer_failed = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(true));

            std::thread::scope(|scope| {
                for _ in 0..producers {
                    let handle = runtime.handle();
                    let completion = Arc::clone(&completion);
                    let ready = Arc::clone(&ready);
                    let start = Arc::clone(&start);
                    let submitted = Arc::clone(&submitted);
                    let stop = Arc::clone(&stop);
                    let producer_failed = Arc::clone(&producer_failed);
                    let release = Arc::clone(&release);

                    scope.spawn(move || {
                        ready.wait();
                        loop {
                            start.wait();
                            if stop.load(Ordering::Acquire) {
                                break;
                            }

                            let submitted_without_panic = catch_unwind(AssertUnwindSafe(|| {
                                for _ in 0..per_producer {
                                    let completion = Arc::clone(&completion);
                                    let release = Arc::clone(&release);
                                    drop(handle.spawn(async move {
                                        while !release.load(Ordering::Acquire) {
                                            asupersync::runtime::yield_now().await;
                                        }
                                        completion.complete(SPAWNS_PER_ITER);
                                    }));
                                }
                            }))
                            .is_ok();
                            if !submitted_without_panic {
                                producer_failed.store(true, Ordering::Release);
                            }
                            submitted.wait();
                        }
                    });
                }

                ready.wait();
                let _stop_guard = ProducerStopGuard {
                    stop: &stop,
                    start: &start,
                };

                if adversarial_reports_enabled() {
                    let preflight_started = Instant::now();
                    let (unfinished, global_ready) = run_contended_iteration(
                        &runtime,
                        &completion,
                        &release,
                        &start,
                        &submitted,
                        &producer_failed,
                        SPAWNS_PER_ITER,
                    );
                    eprintln!(
                        "adversarial_backlog_report cell=producer_overdrive_{producers}P_{label} scope=iteration requests={} total_ns={} unfinished_at_submit={} global_ready_observation={} global_ready_excludes=local,in_flight,mailbox",
                        SPAWNS_PER_ITER,
                        preflight_started.elapsed().as_nanos(),
                        unfinished,
                        global_ready
                    );
                }

                group.bench_function(
                    BenchmarkId::new(
                        format!("contended_persistent_latched_{producers}_producers"),
                        label,
                    ),
                    |b| {
                        b.iter(|| {
                            black_box(run_contended_iteration(
                                &runtime,
                                &completion,
                                &release,
                                &start,
                                &submitted,
                                &producer_failed,
                                SPAWNS_PER_ITER,
                            ));
                        });
                    },
                );
            });
            drop(runtime);
        }
    }

    group.finish();
}

fn bench_join_handle_completion(c: &mut Criterion) {
    let mut group = c.benchmark_group("join_handle_completion");
    group.throughput(Throughput::Elements(SPAWNS_PER_ITER as u64));
    group.sample_size(20);

    for (label, mode) in [
        ("direct", SpawnAdmissionMode::Direct),
        ("mailbox", SpawnAdmissionMode::Mailbox),
    ] {
        let runtime = build_runtime(mode, 4);
        group.bench_function(BenchmarkId::new("spawn_then_await_all", label), |b| {
            b.iter(|| join_handle_completion_batch(black_box(&runtime)));
        });
        drop(runtime);
    }

    group.finish();
}

fn bench_adversarial_tails(c: &mut Criterion) {
    if adversarial_reports_enabled() {
        {
            let scenario = quota_scenario(SpawnAdmissionMode::Direct);
            let started = Instant::now();
            let mut tails = direct_quota_denial(&scenario, true);
            emit_request_tail_report(
                "quota_direct_typed",
                "request_call",
                &mut tails,
                started.elapsed(),
            );
        }
        {
            let scenario = quota_scenario(SpawnAdmissionMode::Mailbox);
            let started = Instant::now();
            let mut tails = deferred_gateway_quota_denial(&scenario, true);
            emit_request_tail_report(
                "quota_gateway_deferred",
                "enqueue_to_ordered_join_observation",
                &mut tails,
                started.elapsed(),
            );
        }
        {
            let mut scenario = cancel_storm_scenario();
            let started = Instant::now();
            let mut tails = cancel_storm(&mut scenario, true);
            let total = started.elapsed();
            wait_for_quiescence(&scenario.runtime);
            emit_request_tail_report(
                "cancel_storm_gateway",
                "batch_abort_epoch_to_ordered_join_observation",
                &mut tails,
                total,
            );
        }
    }

    let mut group = c.benchmark_group("spawn_adversarial_tails");
    group.throughput(Throughput::Elements(ADVERSARIAL_REQUESTS as u64));
    group.sample_size(20);

    group.bench_function("quota_direct_typed_batch", |b| {
        b.iter_batched_ref(
            || quota_scenario(SpawnAdmissionMode::Direct),
            |scenario| black_box(direct_quota_denial(scenario, false)),
            BatchSize::PerIteration,
        );
    });
    group.bench_function("quota_gateway_deferred_batch", |b| {
        b.iter_batched_ref(
            || quota_scenario(SpawnAdmissionMode::Mailbox),
            |scenario| black_box(deferred_gateway_quota_denial(scenario, false)),
            BatchSize::PerIteration,
        );
    });
    group.bench_function("cancel_storm_gateway_abort_to_terminal", |b| {
        b.iter_batched_ref(
            cancel_storm_scenario,
            |scenario| black_box(cancel_storm(scenario, false)),
            BatchSize::PerIteration,
        );
    });
    for (label, mode) in [
        ("direct", SpawnAdmissionMode::Direct),
        ("mailbox", SpawnAdmissionMode::Mailbox),
    ] {
        group.bench_function(
            BenchmarkId::new("runtime_teardown_polled_pending_tasks", label),
            |b| {
                b.iter_batched_ref(
                    || runtime_teardown_scenario(mode),
                    |scenario| runtime_teardown(black_box(scenario)),
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_spawn_throughput,
    bench_join_handle_completion,
    bench_adversarial_tails
);
criterion_main!(benches);
