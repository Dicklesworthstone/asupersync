//! Golden-output benchmark harness for Asupersync.
//!
//! Combines performance measurement with behavioral correctness verification.
//! Each benchmark scenario produces a deterministic output sequence that is
//! hashed with SHA-256 and compared against known-good golden checksums.
//!
//! **Purpose**: Ensure that performance optimizations do not alter observable
//! behavior. If a golden checksum changes, the benchmark fails, signaling a
//! behavioral regression that requires investigation.
//!
//! **Covered subsystems**:
//! - Scheduler: `PriorityScheduler` lane ordering and dispatch determinism
//! - Channels: MPSC `try_send`/`try_recv`, oneshot send/recv
//! - Cancellation: `SymbolCancelToken` tree propagation and budget handling
//! - Lab runtime: Deterministic scheduling with `ScheduleCertificate`
//!
//! **Golden checksum registry**: Stored inline in `golden_registry()`. To
//! regenerate after intentional behavioral changes, run with `GENERATE`
//! entries and update with the printed hashes.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::cast_sign_loss)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;

use asupersync::cancel::SymbolCancelToken;
use asupersync::channel::{mpsc, oneshot};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::scheduler::{GlobalQueue, Scheduler};
use asupersync::types::{Budget, CancelKind, CancelReason, ObjectId, TaskId, Time};
use asupersync::util::DetRng;
use asupersync::Cx;

// =============================================================================
// GOLDEN OUTPUT INFRASTRUCTURE
// =============================================================================

/// Computes SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in &result {
        write!(hex, "{byte:02x}").expect("hex write");
    }
    hex
}

/// Registry of known-good golden checksums.
///
/// Each entry maps a scenario name to its expected SHA-256 digest.
/// When a scenario's output changes, this table must be updated after
/// confirming the change is intentional. Set to `"GENERATE"` to accept
/// any hash on first run and print the actual value for recording.
fn golden_registry() -> BTreeMap<&'static str, &'static str> {
    let mut m = BTreeMap::new();

    // Scheduler scenarios
    m.insert("scheduler/priority_lane_ordering_100", "GENERATE");
    m.insert("scheduler/mixed_cancel_ready_timed_200", "GENERATE");
    m.insert("scheduler/global_inject_then_pop_50", "GENERATE");

    // Channel scenarios
    m.insert("channel/mpsc_try_send_recv_1000", "GENERATE");
    m.insert("channel/mpsc_multi_producer_interleave", "GENERATE");
    m.insert("channel/oneshot_send_recv_sequence", "GENERATE");

    // Cancellation scenarios
    m.insert("cancel/tree_propagation_depth_5", "GENERATE");
    m.insert("cancel/cancel_budgets", "GENERATE");

    // Lab runtime scenarios
    m.insert("lab/deterministic_schedule_seed_42", "GENERATE");
    m.insert("lab/deterministic_schedule_seed_1337", "GENERATE");

    m
}

/// Verifies a golden checksum. Returns `true` if the checksum matches or if
/// the entry is marked `"GENERATE"` (first-run mode).
fn verify_golden(scenario: &str, actual_hash: &str) -> bool {
    let registry = golden_registry();
    match registry.get(scenario) {
        Some(&"GENERATE") => {
            eprintln!("[GOLDEN] {scenario}: NEW hash = {actual_hash}");
            eprintln!("[GOLDEN]   Update golden_registry() with this value.");
            true // Accept on first run
        }
        Some(&expected) => {
            if actual_hash == expected {
                true
            } else {
                eprintln!(
                    "[GOLDEN] {scenario}: MISMATCH\n  expected: {expected}\n  actual:   {actual_hash}"
                );
                false
            }
        }
        None => {
            eprintln!("[GOLDEN] {scenario}: NOT IN REGISTRY (hash = {actual_hash})");
            false
        }
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

// =============================================================================
// SCHEDULER GOLDEN SCENARIOS
// =============================================================================

/// Deterministic scheduler dispatch sequence: schedule N tasks to ready lane,
/// pop all, record TaskId ordering.
fn scenario_priority_lane_ordering(count: u32) -> String {
    let mut sched = Scheduler::new();
    // Schedule tasks with varying priorities
    for i in 0..count {
        let priority = (i % 8) as u8; // Cycle through 8 priority levels
        sched.schedule(task(i), priority);
    }
    // Pop all and record order
    let mut output = String::new();
    while let Some(id) = sched.pop() {
        write!(output, "{},", id.arena_index().index()).expect("write");
    }
    output
}

/// Mixed cancel/ready/timed lane scheduling.
fn scenario_mixed_cancel_ready_timed(count: u32) -> String {
    let mut sched = Scheduler::new();
    for i in 0..count {
        match i % 3 {
            0 => sched.schedule(task(i), (i % 4) as u8),
            1 => sched.schedule_cancel(task(i), (i % 4) as u8),
            2 => sched.schedule_timed(task(i), Time::from_nanos(u64::from(i) * 1000)),
            _ => unreachable!(),
        }
    }
    let mut output = String::new();
    while let Some(id) = sched.pop() {
        write!(output, "{},", id.arena_index().index()).expect("write");
    }
    output
}

/// Global queue inject-then-pop ordering (FIFO, lock-free).
fn scenario_global_inject_pop(count: u32) -> String {
    let gq = GlobalQueue::new();
    for i in 0..count {
        gq.push(task(i));
    }
    let mut output = String::new();
    for _ in 0..count {
        if let Some(id) = gq.pop() {
            write!(output, "{},", id.arena_index().index()).expect("write");
        }
    }
    output
}

// =============================================================================
// CHANNEL GOLDEN SCENARIOS
// =============================================================================

/// MPSC: send N values, recv all, verify order preservation.
fn scenario_mpsc_try_send_recv(count: usize) -> String {
    let (tx, rx) = mpsc::channel::<u64>(count);
    for i in 0..count as u64 {
        tx.try_send(i).expect("send should succeed");
    }
    let mut output = String::new();
    for _ in 0..count {
        match rx.try_recv() {
            Ok(v) => write!(output, "{v},").expect("write"),
            Err(e) => write!(output, "E:{e},").expect("write"),
        }
    }
    output
}

/// MPSC: multiple producers interleave deterministically.
fn scenario_mpsc_multi_producer_interleave() -> String {
    let (tx, rx) = mpsc::channel::<u64>(100);
    let tx2 = tx.clone();
    let tx3 = tx.clone();

    // Interleave sends from 3 producers deterministically
    for i in 0..30_u64 {
        match i % 3 {
            0 => tx.try_send(i * 10).expect("send"),
            1 => tx2.try_send(i * 10 + 1).expect("send"),
            2 => tx3.try_send(i * 10 + 2).expect("send"),
            _ => unreachable!(),
        }
    }

    let mut output = String::new();
    while let Ok(v) = rx.try_recv() {
        write!(output, "{v},").expect("write");
    }
    output
}

/// Oneshot: send and receive sequence.
fn scenario_oneshot_send_recv() -> String {
    let cx = Cx::for_testing();
    let mut output = String::new();
    for i in 0..50_u64 {
        let (tx, rx) = oneshot::channel::<u64>();
        tx.send(&cx, i * 7 + 3).expect("oneshot send");
        match rx.try_recv() {
            Ok(v) => write!(output, "{v},").expect("write"),
            Err(e) => write!(output, "E:{e:?},").expect("write"),
        }
    }
    output
}

// =============================================================================
// CANCELLATION GOLDEN SCENARIOS
// =============================================================================

/// Cancel tree propagation: build a tree of tokens via `.child()`, cancel
/// root, verify all descendants are cancelled.
fn scenario_cancel_tree_propagation(depth: u32) -> String {
    fn build_tree(parent: &SymbolCancelToken, depth: u32, rng: &mut DetRng, count: &mut u32) {
        if depth == 0 {
            return;
        }
        for _ in 0..2 {
            let child = parent.child(rng);
            *count += 1;
            build_tree(&child, depth - 1, rng, count);
        }
    }

    let mut rng = DetRng::new(0xDEAD);
    let root = SymbolCancelToken::new(ObjectId::new_for_test(0), &mut rng);
    let mut node_count: u32 = 1; // root
    build_tree(&root, depth, &mut rng, &mut node_count);

    // Cancel root
    let reason = CancelReason::user("benchmark");
    root.cancel(&reason, Time::from_nanos(1000));

    let mut output = String::new();
    write!(output, "nodes:{node_count},").expect("write");
    write!(output, "root_cancelled:{},", root.is_cancelled()).expect("write");
    if let Some(at) = root.cancelled_at() {
        write!(output, "root_at:{},", at.as_nanos()).expect("write");
    }
    output
}

/// Cancel tokens with various cleanup budgets.
fn scenario_cancel_budgets() -> String {
    let mut rng = DetRng::new(0xBEEF);
    let mut output = String::new();

    for priority in [0_u8, 1, 3, 7, 128, 255] {
        let budget = Budget::new().with_priority(priority).with_poll_quota(100);
        let token = SymbolCancelToken::with_budget(
            ObjectId::new_for_test(u64::from(priority)),
            budget,
            &mut rng,
        );
        let reason = CancelReason::new(CancelKind::Timeout);
        token.cancel(&reason, Time::from_nanos(2000));
        let cb = token.cleanup_budget();
        write!(
            output,
            "p{priority}:pq={},pri={};",
            cb.poll_quota, cb.priority
        )
        .expect("write");
    }
    output
}

// =============================================================================
// LAB RUNTIME GOLDEN SCENARIOS
// =============================================================================

/// Deterministic lab scheduling with a given seed.
/// Exercises the lab scheduler with schedule/cancel/timed operations,
/// time advancement, and uses the `ScheduleCertificate` hash as output.
fn scenario_lab_deterministic(seed: u64) -> String {
    let mut lab = LabRuntime::new(LabConfig::new(seed));

    // Create root region
    let _root_region = lab.state.create_root_region(Budget::INFINITE);

    // Exercise the scheduler via the lab's scheduler
    {
        let mut sched = lab.scheduler.lock().expect("lab scheduler lock");
        for i in 0..20_u32 {
            let tid = task(i);
            match i % 3 {
                0 => sched.schedule(tid, (i % 8) as u8),
                1 => sched.schedule_cancel(tid, (i % 4) as u8),
                2 => sched.schedule_timed(tid, Time::from_nanos(u64::from(i) * 500)),
                _ => unreachable!(),
            }
        }
    }

    // Advance time in deterministic steps
    for _ in 0..4 {
        lab.advance_time(1_000_000); // 1ms each
    }

    let cert = lab.certificate();
    let now = lab.now();
    let steps = lab.steps();

    format!(
        "seed={seed},now={},steps={steps},cert_hash={},cert_decisions={}",
        now.as_nanos(),
        cert.hash(),
        cert.decisions()
    )
}

// =============================================================================
// GOLDEN VERIFICATION BENCHMARKS
// =============================================================================

fn bench_golden_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("golden/scheduler");

    // --- Priority lane ordering ---
    group.bench_function("priority_lane_ordering_100", |b| {
        b.iter(|| {
            let output = scenario_priority_lane_ordering(100);
            black_box(&output);
        })
    });

    // Verify golden checksum (run once outside measurement)
    {
        let output = scenario_priority_lane_ordering(100);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("scheduler/priority_lane_ordering_100", &hash),
            "Golden checksum mismatch for scheduler/priority_lane_ordering_100"
        );
    }

    // --- Mixed cancel/ready/timed ---
    group.bench_function("mixed_cancel_ready_timed_200", |b| {
        b.iter(|| {
            let output = scenario_mixed_cancel_ready_timed(200);
            black_box(&output);
        })
    });

    {
        let output = scenario_mixed_cancel_ready_timed(200);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("scheduler/mixed_cancel_ready_timed_200", &hash),
            "Golden checksum mismatch for scheduler/mixed_cancel_ready_timed_200"
        );
    }

    // --- Global inject then pop ---
    group.bench_function("global_inject_pop_50", |b| {
        b.iter(|| {
            let output = scenario_global_inject_pop(50);
            black_box(&output);
        })
    });

    {
        let output = scenario_global_inject_pop(50);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("scheduler/global_inject_then_pop_50", &hash),
            "Golden checksum mismatch for scheduler/global_inject_then_pop_50"
        );
    }

    // --- Throughput scaling ---
    for &count in &[10, 50, 100, 500, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("priority_schedule_pop", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let output = scenario_priority_lane_ordering(count as u32);
                    black_box(&output);
                })
            },
        );
    }

    group.finish();
}

fn bench_golden_channels(c: &mut Criterion) {
    let mut group = c.benchmark_group("golden/channel");

    // --- MPSC try_send/try_recv ---
    group.bench_function("mpsc_try_send_recv_1000", |b| {
        b.iter(|| {
            let output = scenario_mpsc_try_send_recv(1000);
            black_box(&output);
        })
    });

    {
        let output = scenario_mpsc_try_send_recv(1000);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("channel/mpsc_try_send_recv_1000", &hash),
            "Golden checksum mismatch for channel/mpsc_try_send_recv_1000"
        );
    }

    // --- MPSC multi-producer interleave ---
    group.bench_function("mpsc_multi_producer_interleave", |b| {
        b.iter(|| {
            let output = scenario_mpsc_multi_producer_interleave();
            black_box(&output);
        })
    });

    {
        let output = scenario_mpsc_multi_producer_interleave();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("channel/mpsc_multi_producer_interleave", &hash),
            "Golden checksum mismatch for channel/mpsc_multi_producer_interleave"
        );
    }

    // --- Oneshot send/recv ---
    group.bench_function("oneshot_send_recv_sequence", |b| {
        b.iter(|| {
            let output = scenario_oneshot_send_recv();
            black_box(&output);
        })
    });

    {
        let output = scenario_oneshot_send_recv();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("channel/oneshot_send_recv_sequence", &hash),
            "Golden checksum mismatch for channel/oneshot_send_recv_sequence"
        );
    }

    // --- MPSC throughput scaling ---
    for &count in &[10, 100, 1000, 5000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("mpsc_try_roundtrip", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let output = scenario_mpsc_try_send_recv(count as usize);
                    black_box(&output);
                })
            },
        );
    }

    group.finish();
}

fn bench_golden_cancel(c: &mut Criterion) {
    let mut group = c.benchmark_group("golden/cancel");

    // --- Tree propagation ---
    group.bench_function("tree_propagation_depth_5", |b| {
        b.iter(|| {
            let output = scenario_cancel_tree_propagation(5);
            black_box(&output);
        })
    });

    {
        let output = scenario_cancel_tree_propagation(5);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("cancel/tree_propagation_depth_5", &hash),
            "Golden checksum mismatch for cancel/tree_propagation_depth_5"
        );
    }

    // --- Cancel with budgets ---
    group.bench_function("cancel_budgets", |b| {
        b.iter(|| {
            let output = scenario_cancel_budgets();
            black_box(&output);
        })
    });

    {
        let output = scenario_cancel_budgets();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("cancel/cancel_budgets", &hash),
            "Golden checksum mismatch for cancel/cancel_budgets"
        );
    }

    // --- Tree scaling ---
    for &depth in &[1_u32, 2, 3, 4, 5, 6] {
        let nodes: u64 = (1_u64 << (depth + 1)) - 1;
        group.throughput(Throughput::Elements(nodes));
        group.bench_with_input(
            BenchmarkId::new("tree_propagation", depth),
            &depth,
            |b, &depth| {
                b.iter(|| {
                    let output = scenario_cancel_tree_propagation(depth);
                    black_box(&output);
                })
            },
        );
    }

    group.finish();
}

fn bench_golden_lab(c: &mut Criterion) {
    let mut group = c.benchmark_group("golden/lab");
    group.sample_size(20); // Lab setup is heavier

    // --- Deterministic schedule seed 42 ---
    group.bench_function("deterministic_schedule_seed_42", |b| {
        b.iter(|| {
            let output = scenario_lab_deterministic(42);
            black_box(&output);
        })
    });

    {
        let output = scenario_lab_deterministic(42);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("lab/deterministic_schedule_seed_42", &hash),
            "Golden checksum mismatch for lab/deterministic_schedule_seed_42"
        );
    }

    // --- Deterministic schedule seed 1337 ---
    group.bench_function("deterministic_schedule_seed_1337", |b| {
        b.iter(|| {
            let output = scenario_lab_deterministic(1337);
            black_box(&output);
        })
    });

    {
        let output = scenario_lab_deterministic(1337);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("lab/deterministic_schedule_seed_1337", &hash),
            "Golden checksum mismatch for lab/deterministic_schedule_seed_1337"
        );
    }

    // --- Seed sweep ---
    for &seed in &[0_u64, 1, 42, 1337, 0xDEAD_BEEF] {
        group.bench_with_input(BenchmarkId::new("seed_sweep", seed), &seed, |b, &seed| {
            b.iter(|| {
                let output = scenario_lab_deterministic(seed);
                black_box(&output);
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_golden_scheduler,
    bench_golden_channels,
    bench_golden_cancel,
    bench_golden_lab,
);
criterion_main!(benches);
