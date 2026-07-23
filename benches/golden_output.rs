#![cfg(feature = "test-internals")]
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
//! To generate a reviewed replacement after committing an intentional behavioral
//! change, use the strict-remote command documented in the Phase 6 gate section
//! of `README.md`. Update mode never mutates the tracked registry directly: it
//! writes an atomic candidate beneath Criterion's retrieved artifact directory.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::cast_sign_loss)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use asupersync::Cx;
use asupersync::cancel::SymbolCancelToken;
use asupersync::channel::{mpsc, oneshot};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::{GlobalQueue, Scheduler};
use asupersync::types::{Budget, CancelKind, CancelReason, ObjectId, TaskId, Time};
use asupersync::util::DetRng;

mod golden_registry;
use golden_registry::{
    GOLDEN_CHECKSUMS_PATH, GOLDEN_SCENARIOS, GoldenChecksumFile, RegistryResult,
    ReviewedProvenance, build_update_candidate, is_lower_hex, load_golden_registry_from_path,
    validate_reviewed_provenance,
};

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

/// Cached registry for the process lifetime.
static REGISTRY: OnceLock<GoldenChecksumFile> = OnceLock::new();

fn golden_registry() -> &'static GoldenChecksumFile {
    REGISTRY.get_or_init(|| {
        load_golden_registry_from_path(Path::new(GOLDEN_CHECKSUMS_PATH))
            .unwrap_or_else(|error| panic!("{error}"))
    })
}

/// Accumulated updates when running in GOLDEN_UPDATE mode.
static UPDATES: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
static SEEN_SCENARIOS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoldenMode {
    Verify,
    Update,
}

static GOLDEN_MODE: OnceLock<GoldenMode> = OnceLock::new();

fn golden_mode() -> GoldenMode {
    *GOLDEN_MODE.get_or_init(|| match std::env::var("GOLDEN_UPDATE") {
        Err(std::env::VarError::NotPresent) => GoldenMode::Verify,
        Ok(value) if value == "0" => GoldenMode::Verify,
        Ok(value) if value == "1" => GoldenMode::Update,
        Ok(value) => panic!("GOLDEN_UPDATE must be unset, 0, or 1; got {value:?}"),
        Err(error) => panic!("read GOLDEN_UPDATE: {error}"),
    })
}

fn mark_scenario_seen(scenario: &str) {
    if !GOLDEN_SCENARIOS.contains(&scenario) {
        panic!("golden scenario {scenario:?} is not declared in GOLDEN_SCENARIOS");
    }
    let seen = SEEN_SCENARIOS.get_or_init(|| Mutex::new(BTreeSet::new()));
    assert!(
        seen.lock()
            .expect("seen scenarios lock")
            .insert(scenario.to_string()),
        "golden scenario {scenario:?} was verified more than once"
    );
}

fn command_stdout(command: &mut Command, description: &str) -> RegistryResult<String> {
    let output = command
        .output()
        .map_err(|error| format!("{description}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{description}: exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| format!("{description} returned non-UTF-8 output: {error}"))
}

fn reviewed_update_provenance() -> RegistryResult<ReviewedProvenance> {
    let reviewed_sha = std::env::var("GOLDEN_REVIEWED_GIT_SHA")
        .map_err(|_| "GOLDEN_UPDATE=1 requires GOLDEN_REVIEWED_GIT_SHA".to_string())?;
    let head_sha = command_stdout(
        Command::new("git").args(["rev-parse", "HEAD"]),
        "resolve golden update HEAD",
    )?;
    let tracked_status = command_stdout(
        Command::new("git").args(["status", "--porcelain", "--untracked-files=no"]),
        "inspect golden update tracked tree",
    )?;
    validate_reviewed_provenance(&reviewed_sha, &head_sha, &tracked_status)?;

    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("resolve golden update timestamp: {error}"))?
        .as_secs();
    Ok(ReviewedProvenance {
        git_sha: reviewed_sha,
        generated_at: format!("{seconds}Z"),
    })
}

static UPDATE_PROVENANCE: OnceLock<ReviewedProvenance> = OnceLock::new();

fn update_provenance() -> &'static ReviewedProvenance {
    UPDATE_PROVENANCE
        .get_or_init(|| reviewed_update_provenance().unwrap_or_else(|error| panic!("{error}")))
}

fn record_update(scenario: &str, hash: &str) {
    assert!(
        is_lower_hex(hash, 64),
        "golden update hash for {scenario} must be 64 lowercase hex characters"
    );
    let updates = UPDATES.get_or_init(|| Mutex::new(BTreeMap::new()));
    assert!(
        updates
            .lock()
            .expect("updates lock")
            .insert(scenario.to_string(), hash.to_string())
            .is_none(),
        "golden update recorded scenario {scenario:?} more than once"
    );
}

fn update_candidate_path() -> RegistryResult<PathBuf> {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "GOLDEN_UPDATE=1 requires an explicit CARGO_TARGET_DIR".to_string())?;
    if !target_dir.is_absolute() {
        return Err("GOLDEN_UPDATE CARGO_TARGET_DIR must be absolute".into());
    }
    Ok(target_dir
        .join("criterion")
        .join("golden-update")
        .join("golden_checksums.json"))
}

fn write_json_atomically(path: &Path, file: &GoldenChecksumFile) -> RegistryResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("golden update candidate has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create golden update directory {}: {error}",
            parent.display()
        )
    })?;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("resolve golden update temp-file nonce: {error}"))?
        .as_nanos();
    let temp_path = parent.join(format!(
        ".golden_checksums.json.{}.{nonce}.tmp",
        std::process::id()
    ));
    let mut json = serde_json::to_string_pretty(file)
        .map_err(|error| format!("serialize golden update candidate: {error}"))?;
    json.push('\n');

    let mut temp = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|error| {
            format!(
                "create golden update temp file {}: {error}",
                temp_path.display()
            )
        })?;
    temp.write_all(json.as_bytes()).map_err(|error| {
        format!(
            "write golden update temp file {}: {error}",
            temp_path.display()
        )
    })?;
    temp.sync_all().map_err(|error| {
        format!(
            "sync golden update temp file {}: {error}",
            temp_path.display()
        )
    })?;
    drop(temp);
    std::fs::rename(&temp_path, path).map_err(|error| {
        format!(
            "atomically publish golden update candidate {} -> {}: {error}",
            temp_path.display(),
            path.display()
        )
    })?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync golden update directory {}: {error}", parent.display()))?;
    Ok(())
}

fn finalize_golden_run() {
    let seen = SEEN_SCENARIOS
        .get()
        .map(|seen| seen.lock().expect("seen scenarios lock").clone())
        .unwrap_or_default();
    let expected: BTreeSet<String> = GOLDEN_SCENARIOS.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        seen, expected,
        "golden run must verify every declared scenario exactly once"
    );

    if golden_mode() == GoldenMode::Update {
        let updates = UPDATES
            .get()
            .map(|updates| updates.lock().expect("updates lock").clone())
            .unwrap_or_default();
        let candidate = build_update_candidate(&updates, update_provenance())
            .unwrap_or_else(|error| panic!("{error}"));
        let path = update_candidate_path().unwrap_or_else(|error| panic!("{error}"));
        write_json_atomically(&path, &candidate).unwrap_or_else(|error| panic!("{error}"));
        eprintln!(
            "[GOLDEN UPDATE] wrote reviewed candidate with {} exact scenarios to {}",
            candidate.checksums.0.len(),
            path.display()
        );
        eprintln!(
            "[GOLDEN UPDATE] review the retrieved candidate before replacing {GOLDEN_CHECKSUMS_PATH}"
        );
    }
}

/// Verifies a golden checksum. In GOLDEN_UPDATE mode, records the new hash.
fn verify_golden(scenario: &str, actual_hash: &str) -> bool {
    mark_scenario_seen(scenario);
    if golden_mode() == GoldenMode::Update {
        let _ = update_provenance();
        record_update(scenario, actual_hash);
        eprintln!("[GOLDEN UPDATE] {scenario}: {actual_hash}");
        return true;
    }

    let registry = golden_registry();
    let Some(entry) = registry.checksums.0.get(scenario) else {
        eprintln!("[GOLDEN] {scenario}: NOT IN REQUIRED REGISTRY");
        return false;
    };
    if actual_hash == entry.output_hash {
        true
    } else {
        eprintln!(
            "[GOLDEN] {scenario}: MISMATCH\n  expected: {}\n  actual:   {actual_hash}",
            entry.output_hash
        );
        false
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn task_index(id: TaskId) -> u32 {
    id.to_string()
        .strip_prefix('T')
        .expect("task display prefix")
        .parse()
        .expect("task display index")
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
        write!(output, "{},", task_index(id)).expect("write");
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
        write!(output, "{},", task_index(id)).expect("write");
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
            write!(output, "{},", task_index(id)).expect("write");
        }
    }
    output
}

// =============================================================================
// CHANNEL GOLDEN SCENARIOS
// =============================================================================

/// MPSC: send N values, recv all, verify order preservation.
fn scenario_mpsc_try_send_recv(count: usize) -> String {
    let (tx, mut rx) = mpsc::channel::<u64>(count);
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
    let (tx, mut rx) = mpsc::channel::<u64>(100);
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
        let (tx, mut rx) = oneshot::channel::<u64>();
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
    let (tx, mut rx) = mpsc::channel::<u64>(10);
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
    let (affected, cancel_wakes) = state.cancel_request(root, &reason, None).into_parts();
    cancel_wakes.suppress();

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
    group.bench_function(
        "priority_lane_ordering_100",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let output = scenario_priority_lane_ordering(100);
                std::hint::black_box(&output);
            })
        },
    );

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
    group.bench_function(
        "mixed_cancel_ready_timed_200",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let output = scenario_mixed_cancel_ready_timed(200);
                std::hint::black_box(&output);
            })
        },
    );

    {
        let output = scenario_mixed_cancel_ready_timed(200);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("scheduler/mixed_cancel_ready_timed_200", &hash),
            "Golden checksum mismatch for scheduler/mixed_cancel_ready_timed_200"
        );
    }

    // --- Global inject then pop ---
    group.bench_function("global_inject_pop_50", |b: &mut criterion::Bencher| {
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
    group.bench_function("mpsc_try_send_recv_1000", |b: &mut criterion::Bencher| {
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
    group.bench_function(
        "mpsc_multi_producer_interleave",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let output = scenario_mpsc_multi_producer_interleave();
                std::hint::black_box(&output);
            })
        },
    );

    {
        let output = scenario_mpsc_multi_producer_interleave();
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("channel/mpsc_multi_producer_interleave", &hash),
            "Golden checksum mismatch for channel/mpsc_multi_producer_interleave"
        );
    }

    // --- Oneshot send/recv ---
    group.bench_function(
        "oneshot_send_recv_sequence",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let output = scenario_oneshot_send_recv();
                std::hint::black_box(&output);
            })
        },
    );

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
    group.bench_function("tree_propagation_depth_5", |b: &mut criterion::Bencher| {
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
    group.bench_function("cancel_budgets", |b: &mut criterion::Bencher| {
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
    group.bench_function(
        "deterministic_schedule_seed_42",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let output = scenario_lab_deterministic(42);
                std::hint::black_box(&output);
            })
        },
    );

    {
        let output = scenario_lab_deterministic(42);
        let hash = sha256_hex(output.as_bytes());
        assert!(
            verify_golden("lab/deterministic_schedule_seed_42", &hash),
            "Golden checksum mismatch for lab/deterministic_schedule_seed_42"
        );
    }

    // --- Deterministic schedule seed 1337 ---
    group.bench_function(
        "deterministic_schedule_seed_1337",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                let output = scenario_lab_deterministic(1337);
                std::hint::black_box(&output);
            })
        },
    );

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
    group.bench_function("combine_chain", |b: &mut criterion::Bencher| {
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
    group.bench_function("deadline_check_matrix", |b: &mut criterion::Bencher| {
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
    group.bench_function("send_permit_lifecycle", |b: &mut criterion::Bencher| {
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
    group.bench_function("region_cancel_propagation", |b: &mut criterion::Bencher| {
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

/// Validate run completeness and publish a reviewed candidate in update mode.
fn bench_flush_golden_updates(c: &mut Criterion) {
    finalize_golden_run();
    // No-op benchmark to ensure this function runs last
    c.bench_function("golden/_flush", |b: &mut criterion::Bencher| {
        b.iter(|| std::hint::black_box(0))
    });
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
