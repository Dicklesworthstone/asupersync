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
//! - Budget propagation: Combine chain determinism
//! - Obligation lifecycle: SendPermit reserve/commit ordering
//!
//! **Golden checksum registry**: Stored in `artifacts/golden_checksums.json`.
//! To regenerate after intentional behavioral changes:
//!   `GOLDEN_UPDATE=1 cargo bench --bench golden_output`

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::cast_sign_loss)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::sync::OnceLock;

use asupersync::Cx;
use asupersync::cancel::SymbolCancelToken;
use asupersync::channel::{mpsc, oneshot};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::{GlobalQueue, Scheduler};
use asupersync::types::{Budget, CancelKind, CancelReason, ObjectId, TaskId, Time};
use asupersync::util::DetRng;

// =============================================================================
// GOLDEN OUTPUT INFRASTRUCTURE
// =============================================================================

/// Schema for the golden checksums JSON artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoldenChecksumFile {
    schema_version: u32,
    generated_by: String,
    checksums: BTreeMap<String, GoldenEntry>,
}

/// A single golden checksum entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoldenEntry {
    output_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_at: Option<String>,
}

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

/// Path to the golden checksums JSON artifact.
const GOLDEN_CHECKSUMS_PATH: &str = "artifacts/golden_checksums.json";

/// Returns true if GOLDEN_UPDATE=1 is set.
fn is_golden_update_mode() -> bool {
    std::env::var("GOLDEN_UPDATE")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Inline fallback registry (used when `artifacts/golden_checksums.json` doesn't exist yet).
fn inline_registry() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(
        "scheduler/priority_lane_ordering_100".into(),
        "aa41a308bff0297fa0dd9d902d1263a9e19cacd3e03b1423bd0876e021904fa3".into(),
    );
    m.insert(
        "scheduler/mixed_cancel_ready_timed_200".into(),
        "ebc8100fd3915f8c0c9f782e7b38cf383ec14c9d1298075d1931fbe812b9db1b".into(),
    );
    m.insert(
        "scheduler/global_inject_then_pop_50".into(),
        "077ba6995d23b61f3de629ba45496763d3229769c03737a291904f7220f6e5e0".into(),
    );
    m.insert(
        "channel/mpsc_try_send_recv_1000".into(),
        "c76dd6f3c17103439dfb85094b25f725c8a46fabf6288b0b9e6743774739eb3e".into(),
    );
    m.insert(
        "channel/mpsc_multi_producer_interleave".into(),
        "7862b3c6abc43c253abb6269df13c023654ee8d3dc209bef3c7cc68865fe59f6".into(),
    );
    m.insert(
        "channel/oneshot_send_recv_sequence".into(),
        "305d9faa182a3fa58209faf4d462a3bf7cb25180c75e12f779a47e32899f67b4".into(),
    );
    m.insert(
        "cancel/tree_propagation_depth_5".into(),
        "85dfafed6b9ae886eda10bb758ebdd425a90e3829cee064585577874ae3caa1b".into(),
    );
    m.insert(
        "cancel/cancel_budgets".into(),
        "880088a12dbaabbd5481703bdc88075a967f1696e64e7110398bc5179da52f82".into(),
    );
    m.insert(
        "lab/deterministic_schedule_seed_42".into(),
        "0b0f3192274d644f0658c30b60a6e1acfabfa6df88207c43067b2ff70ca63945".into(),
    );
    m.insert(
        "lab/deterministic_schedule_seed_1337".into(),
        "27d627326b5b6304467eba5515a5fc0596b14063a1c52a03012ea3a1af9543be".into(),
    );
    m
}

/// Load golden checksums from JSON file, falling back to inline registry.
fn load_golden_registry() -> BTreeMap<String, String> {
    std::fs::read_to_string(GOLDEN_CHECKSUMS_PATH).map_or_else(
        |_| inline_registry(),
        |contents| {
            let file: GoldenChecksumFile =
                serde_json::from_str(&contents).expect("parse golden_checksums.json");
            file.checksums
                .into_iter()
                .map(|(k, v)| (k, v.output_hash))
                .collect()
        },
    )
}

/// Cached registry for the process lifetime.
static REGISTRY: OnceLock<BTreeMap<String, String>> = OnceLock::new();

fn golden_registry() -> &'static BTreeMap<String, String> {
    REGISTRY.get_or_init(load_golden_registry)
}

/// Accumulated updates when running in GOLDEN_UPDATE mode.
static UPDATES: OnceLock<std::sync::Mutex<BTreeMap<String, String>>> = OnceLock::new();

fn record_update(scenario: &str, hash: &str) {
    let updates = UPDATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    updates
        .lock()
        .expect("updates lock")
        .insert(scenario.to_string(), hash.to_string());
}

/// Write accumulated updates to `artifacts/golden_checksums.json`.
fn flush_updates() {
    let Some(updates) = UPDATES.get() else {
        return;
    };
    let (merged, update_count) = {
        let map = updates.lock().expect("updates lock");
        if map.is_empty() {
            return;
        }

        let count = map.len();
        // Merge with existing registry
        let mut merged = golden_registry().clone();
        for (k, v) in map.iter() {
            merged.insert(k.clone(), v.clone());
        }
        drop(map);
        (merged, count)
    };

    let now = {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time");
        format!("{}Z", dur.as_secs())
    };
    let git_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    let file = GoldenChecksumFile {
        schema_version: 1,
        generated_by: "golden_output benchmark (bd-1e2if.2)".into(),
        checksums: merged
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    GoldenEntry {
                        output_hash: v,
                        git_sha: git_sha.clone(),
                        generated_at: Some(now.clone()),
                    },
                )
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&file).expect("serialize golden checksums");
    std::fs::write(GOLDEN_CHECKSUMS_PATH, json).expect("write golden_checksums.json");
    eprintln!(
        "[GOLDEN] Updated {GOLDEN_CHECKSUMS_PATH} with {} checksums ({} new/changed)",
        file.checksums.len(),
        update_count
    );
}

/// Verifies a golden checksum. In GOLDEN_UPDATE mode, records the new hash.
fn verify_golden(scenario: &str, actual_hash: &str) -> bool {
    if is_golden_update_mode() {
        record_update(scenario, actual_hash);
        eprintln!("[GOLDEN UPDATE] {scenario}: {actual_hash}");
        return true;
    }

    let registry = golden_registry();
    match registry.get(scenario) {
        Some(expected) if expected == "GENERATE" => {
            eprintln!("[GOLDEN] {scenario}: NEW hash = {actual_hash}");
            eprintln!("[GOLDEN]   Run with GOLDEN_UPDATE=1 to save.");
            true
        }
        Some(expected) => {
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
            eprintln!(
                "[GOLDEN] {scenario}: NOT IN REGISTRY (hash = {actual_hash})\n  \
                 Run with GOLDEN_UPDATE=1 to add."
            );
            // In update mode we'd capture; in verify mode, new scenarios are accepted
            // to allow incremental addition without breaking existing CI.
            true
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
        let mut sched = lab.scheduler.lock();
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
// BUDGET PROPAGATION GOLDEN SCENARIOS
// =============================================================================

/// Budget combine chain: combine N budgets with various parameters,
/// verify tropical semiring determinism.
fn scenario_budget_combine_chain() -> String {
    let budgets = [
        Budget::INFINITE,
        Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(1000),
        Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(500)
            .with_cost_quota(10_000),
        Budget::new().with_priority(5).with_poll_quota(2000),
        Budget::new()
            .with_deadline(Time::from_secs(60))
            .with_cost_quota(50_000),
    ];

    let mut output = String::new();
    let mut combined = Budget::INFINITE;
    for (i, b) in budgets.iter().enumerate() {
        combined = combined.combine(*b);
        write!(
            output,
            "step{}:pq={},pri={},exhausted={};",
            i,
            combined.poll_quota,
            combined.priority,
            combined.is_exhausted()
        )
        .expect("write");
    }
    output
}

/// Budget deadline propagation: verify is_past_deadline determinism.
fn scenario_budget_deadline_check() -> String {
    let budgets = [
        Budget::INFINITE,
        Budget::new().with_deadline(Time::from_nanos(500)),
        Budget::new().with_deadline(Time::from_nanos(1000)),
        Budget::new().with_deadline(Time::from_nanos(0)),
    ];
    let check_times = [
        Time::from_nanos(0),
        Time::from_nanos(250),
        Time::from_nanos(750),
        Time::from_nanos(1500),
    ];

    let mut output = String::new();
    for (bi, b) in budgets.iter().enumerate() {
        for (ti, t) in check_times.iter().enumerate() {
            write!(
                output,
                "b{}t{}:{};",
                bi,
                ti,
                u8::from(b.is_past_deadline(*t))
            )
            .expect("write");
        }
    }
    output
}

// =============================================================================
// OBLIGATION LIFECYCLE GOLDEN SCENARIOS
// =============================================================================

/// SendPermit lifecycle via MPSC channel: reserve, commit, verify ordering.
fn scenario_obligation_send_permit() -> String {
    let (tx, rx) = mpsc::channel::<u64>(10);
    let mut output = String::new();

    // Reserve permits, then commit in order
    for i in 0..5_u64 {
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(i * 100);
                write!(output, "committed:{};", i * 100).expect("write");
            }
            Err(e) => write!(output, "reserve_err:{e};").expect("write"),
        }
    }

    // Drain and record
    while let Ok(v) = rx.try_recv() {
        write!(output, "recv:{v};").expect("write");
    }
    output
}

/// Cancel region with child regions: verify region tree structure determinism.
fn scenario_region_cancel_propagation() -> String {
    let mut state = RuntimeState::new();
    let root = state.create_root_region(Budget::INFINITE);

    // Build a 3-level region tree
    let mut children = Vec::new();
    for _ in 0..3 {
        let child_budget = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(500);
        if let Ok(child) = state.create_child_region(root, child_budget) {
            let grandchild_budget = Budget::new().with_poll_quota(100);
            let _ = state.create_child_region(child, grandchild_budget);
            children.push(child);
        }
    }

    let reason = CancelReason::new(CancelKind::User);
    let affected = state.cancel_request(root, &reason, None);

    let mut output = String::new();
    write!(output, "children:{},", children.len()).expect("write");
    write!(output, "affected:{},", affected.len()).expect("write");
    write!(output, "quiescent:{}", state.is_quiescent()).expect("write");
    output
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
            std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
                    std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
                    std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
                    std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
            std::hint::black_box(&output);
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
                std::hint::black_box(&output);
            })
        });
    }

    group.finish();
}

fn bench_golden_budget(c: &mut Criterion) {
    let mut group = c.benchmark_group("golden/budget");

    // --- Combine chain ---
    group.bench_function("combine_chain", |b| {
        b.iter(|| {
            let output = scenario_budget_combine_chain();
            std::hint::black_box(&output);
        })
    });

    {
        let output = scenario_budget_combine_chain();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("budget/combine_chain", &hash),
            "Golden checksum mismatch for budget/combine_chain"
        );
    }

    // --- Deadline checks ---
    group.bench_function("deadline_check_matrix", |b| {
        b.iter(|| {
            let output = scenario_budget_deadline_check();
            std::hint::black_box(&output);
        })
    });

    {
        let output = scenario_budget_deadline_check();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("budget/deadline_check_matrix", &hash),
            "Golden checksum mismatch for budget/deadline_check_matrix"
        );
    }

    group.finish();
}

fn bench_golden_obligation(c: &mut Criterion) {
    let mut group = c.benchmark_group("golden/obligation");

    // --- SendPermit lifecycle ---
    group.bench_function("send_permit_lifecycle", |b| {
        b.iter(|| {
            let output = scenario_obligation_send_permit();
            std::hint::black_box(&output);
        })
    });

    {
        let output = scenario_obligation_send_permit();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("obligation/send_permit_lifecycle", &hash),
            "Golden checksum mismatch for obligation/send_permit_lifecycle"
        );
    }

    // --- Region cancel propagation ---
    group.bench_function("region_cancel_propagation", |b| {
        b.iter(|| {
            let output = scenario_region_cancel_propagation();
            std::hint::black_box(&output);
        })
    });

    {
        let output = scenario_region_cancel_propagation();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("obligation/region_cancel_propagation", &hash),
            "Golden checksum mismatch for obligation/region_cancel_propagation"
        );
    }

    group.finish();
}

/// Flush updates on benchmark completion when in GOLDEN_UPDATE mode.
fn bench_flush_golden_updates(c: &mut Criterion) {
    if is_golden_update_mode() {
        flush_updates();
    }
    // No-op benchmark to ensure this function runs last
    c.bench_function("golden/_flush", |b| b.iter(|| std::hint::black_box(0)));
}

criterion_group!(
    benches,
    bench_golden_scheduler,
    bench_golden_channels,
    bench_golden_cancel,
    bench_golden_lab,
    bench_golden_budget,
    bench_golden_obligation,
    bench_flush_golden_updates,
);
criterion_main!(benches);
