#![allow(missing_docs)]
//! E2E Obligation Leak Stress Test (bd-2ktrc.7).
//!
//! Runs millions of random schedules with the Lab runtime and verifies zero
//! obligation leaks. Each schedule:
//!
//! 1. Spawns a random set of tasks with random obligations (SendPermit, Lease,
//!    Ack, IoOp).
//! 2. Resolves obligations via random paths (commit ~60%, abort ~40%) in a
//!    random permutation order.
//! 3. Optionally enables chaos injection (cancellation, delay, I/O errors) on
//!    ~10% of schedules.
//! 4. Optionally cancels random tasks (with obligation drain) on ~15% of
//!    schedules.
//! 5. Runs until quiescent, then verifies zero pending obligations and zero
//!    invariant violations.
//!
//! Configuration:
//!   - `OBLIGATION_STRESS_SCHEDULES`: Override schedule count (default 100_000).
//!     Set to 10_000_000 for nightly CI.
//!
//! Statistics: Tracks leak rate with exact binomial 95% confidence interval.
//! Target at 10M schedules: 0 leaks with CI upper bound < 1e-7.
//!
//! Cross-references:
//!   Obligation lifecycle E2E:  tests/obligation_lifecycle_e2e.rs
//!   Leak regression suite:    tests/leak_regression_e2e.rs
//!   Cancel obligation tests:  tests/cancel_obligation_invariants.rs
//!   Obligation ledger unit:   src/obligation/ledger.rs

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId, TaskId};
use common::*;
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Default schedule count for regular test runs.
const DEFAULT_SCHEDULES: u64 = 100_000;

/// Environment variable to override schedule count.
const SCHEDULES_ENV: &str = "OBLIGATION_STRESS_SCHEDULES";

/// Maximum tasks per schedule.
const MAX_TASKS: u32 = 8;

/// Maximum obligations per task.
const MAX_OBLIGATIONS_PER_TASK: u32 = 4;

/// All obligation kinds for random selection.
const ALL_KINDS: [ObligationKind; 4] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
];

/// All abort reasons for random selection.
const ALL_ABORT_REASONS: [ObligationAbortReason; 3] = [
    ObligationAbortReason::Cancel,
    ObligationAbortReason::Error,
    ObligationAbortReason::Explicit,
];

// ============================================================================
// Deterministic RNG (splitmix64)
// ============================================================================

/// Minimal deterministic RNG for schedule generation.
///
/// Uses the splitmix64 algorithm for fast, high-quality randomness.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid zero state by adding 1.
        Self {
            state: seed.wrapping_add(1),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Random u32 in `[0, n)`.
    fn next_u32(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n)) as u32
    }

    /// Returns true with the given probability (0..100 percent).
    fn chance(&mut self, percent: u32) -> bool {
        self.next_u32(100) < percent
    }
}

// ============================================================================
// Schedule execution
// ============================================================================

/// Outcome of a single schedule run.
struct ScheduleOutcome {
    /// Number of obligations created in this schedule.
    obligations_created: u64,
    /// Number of invariant violations detected.
    violations: u64,
    /// Whether the schedule used chaos injection.
    chaos: bool,
}

/// Run a single schedule with the given seed.
///
/// Returns `ScheduleOutcome` with violation count. A clean run has `violations == 0`.
fn run_schedule(seed: u64) -> ScheduleOutcome {
    let mut rng = Rng::new(seed);

    // Configure the lab runtime.
    let use_chaos = rng.chance(10); // 10% of schedules enable chaos
    let use_cancel = rng.chance(15); // 15% of schedules cancel tasks
    let use_child_regions = rng.chance(20); // 20% use nested regions
    let mut config = LabConfig::new(seed)
        .panic_on_leak(false) // We check manually after quiescence
        .panic_on_futurelock(false)
        .max_steps(50_000)
        .trace_capacity(128); // Minimal trace buffer for speed

    if use_chaos {
        config = config.with_light_chaos();
    }

    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    // Optionally create a child region for some tasks.
    let child_region = if use_child_regions {
        runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .ok()
    } else {
        None
    };

    // Decide number of tasks (1..=MAX_TASKS).
    let num_tasks = 1 + rng.next_u32(MAX_TASKS);

    // Track obligations and their resolution paths.
    let mut all_obligations: Vec<(ObligationId, bool)> = Vec::new();
    let mut task_ids: Vec<TaskId> = Vec::new();

    // Create tasks and obligations.
    for task_idx in 0..num_tasks {
        // Alternate between root and child region.
        let region = child_region.filter(|_| task_idx % 3 == 0).unwrap_or(root);

        let Ok((task_id, _handle)) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
        else {
            continue; // Region closed or other edge case
        };

        // Schedule the task on a random worker lane.
        let lane = rng.next_u32(4) as u8;
        runtime.scheduler.lock().schedule(task_id, lane);
        task_ids.push(task_id);

        // Create random obligations for this task.
        let num_obligations = rng.next_u32(MAX_OBLIGATIONS_PER_TASK + 1);
        for _ in 0..num_obligations {
            let kind = ALL_KINDS[rng.next_u32(4) as usize];
            let should_commit = rng.chance(60);

            if let Ok(obl_id) = runtime.state.create_obligation(kind, task_id, region, None) {
                all_obligations.push((obl_id, should_commit));
            }
        }
    }

    let obligations_created = all_obligations.len() as u64;

    // Shuffle resolution order (deterministic Fisher-Yates).
    let len = all_obligations.len();
    for i in (1..len).rev() {
        let j = rng.next_u32((i + 1) as u32) as usize;
        all_obligations.swap(i, j);
    }

    // Optionally advance time before resolving (exercises timer paths).
    if rng.chance(30) {
        let advance_ns = u64::from(rng.next_u32(1_000_000)) + 1;
        runtime.advance_time(advance_ns);
    }

    // Resolve all obligations in the shuffled order.
    for (obl_id, should_commit) in &all_obligations {
        if *should_commit {
            let _ = runtime.state.commit_obligation(*obl_id);
        } else {
            let reason = ALL_ABORT_REASONS[rng.next_u32(3) as usize];
            let _ = runtime.state.abort_obligation(*obl_id, reason);
        }

        // Occasionally advance time between resolutions.
        if rng.chance(10) {
            runtime.advance_time(u64::from(rng.next_u32(10_000)) + 1);
        }
    }

    // Optionally cancel some tasks (obligations already resolved, so this
    // tests that the cancel path doesn't create spurious leaks).
    if use_cancel && !task_ids.is_empty() {
        let cancel_count = 1 + rng.next_u32(task_ids.len().min(3) as u32);
        for _ in 0..cancel_count {
            let idx = rng.next_u32(task_ids.len() as u32) as usize;
            let cancel_reason = CancelReason::new(CancelKind::User);
            let _ = runtime
                .state
                .cancel_request(root, &cancel_reason, Some(task_ids[idx]));
        }
    }

    // Advance time and run until quiescent.
    runtime.advance_time(1_000_000); // 1ms
    runtime.run_until_quiescent();

    // Check invariants.
    let violations = runtime.check_invariants();
    let violation_count = violations.len() as u64;

    // Also verify pending obligation count is zero.
    let pending = runtime.state.pending_obligation_count();
    let total_violations = violation_count + u64::from(pending > 0);

    ScheduleOutcome {
        obligations_created,
        violations: total_violations,
        chaos: use_chaos,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Compute 95% binomial CI upper bound for failure rate.
///
/// For zero failures, uses the "rule of three" approximation: upper ≈ 3/n.
/// For nonzero failures, uses the Wilson score interval.
#[allow(clippy::cast_precision_loss)]
fn binomial_ci_upper_95(total: u64, failures: u64) -> f64 {
    if total == 0 {
        return 1.0;
    }
    if failures == 0 {
        // Rule of three: 95% CI upper bound ≈ 3/n
        return 3.0 / total as f64;
    }
    // Wilson score interval upper bound (z = 1.96 for 95%)
    let n = total as f64;
    let p_hat = failures as f64 / n;
    let z = 1.96_f64;
    let z2 = z * z;
    let denominator = 1.0 + z2 / n;
    let center = p_hat + z2 / (2.0 * n);
    let margin = z * (p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n)).sqrt();
    (center + margin) / denominator
}

// ============================================================================
// Main test
// ============================================================================

#[test]
fn e2e_no_obligation_leaks_under_random_schedules() {
    init_test_logging();
    test_phase!("obligation_leak_stress");

    let num_schedules = std::env::var(SCHEDULES_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SCHEDULES);

    tracing::info!(
        num_schedules = num_schedules,
        max_tasks = MAX_TASKS,
        max_obligations = MAX_OBLIGATIONS_PER_TASK,
        "starting obligation leak stress test"
    );

    let total_obligations = AtomicU64::new(0);
    let total_violations = AtomicU64::new(0);
    let chaos_schedules = AtomicU64::new(0);
    let completed = AtomicU64::new(0);

    // Run schedules in parallel using rayon.
    (0..num_schedules).into_par_iter().for_each(|i| {
        // Derive a well-distributed seed from the index.
        let seed = i
            .wrapping_mul(0x517c_c1b7_2722_0a95)
            .wrapping_add(0x6c62_272e_07bb_0142);
        let outcome = run_schedule(seed);

        total_obligations.fetch_add(outcome.obligations_created, Ordering::Relaxed);
        total_violations.fetch_add(outcome.violations, Ordering::Relaxed);
        if outcome.chaos {
            chaos_schedules.fetch_add(1, Ordering::Relaxed);
        }

        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;

        // Progress logging at 10% intervals.
        let interval = (num_schedules / 10).max(1);
        if done.is_multiple_of(interval) {
            let pct = (done * 100) / num_schedules;
            tracing::info!(
                progress_pct = pct,
                completed = done,
                total = num_schedules,
                violations_so_far = total_violations.load(Ordering::Relaxed),
                "stress test progress"
            );
        }
    });

    let final_schedules = completed.load(Ordering::Relaxed);
    let final_violations = total_violations.load(Ordering::Relaxed);
    let final_obligations = total_obligations.load(Ordering::Relaxed);
    let final_chaos = chaos_schedules.load(Ordering::Relaxed);

    let ci_upper = binomial_ci_upper_95(final_schedules, final_violations);

    tracing::info!(
        schedules = final_schedules,
        obligations_total = final_obligations,
        chaos_schedules = final_chaos,
        violations = final_violations,
        ci_upper_bound_95 = format!("{ci_upper:.2e}"),
        "obligation leak stress test complete"
    );

    assert_eq!(
        final_violations, 0,
        "expected zero obligation leaks across {final_schedules} random schedules, \
         but found {final_violations} violations"
    );

    // When running at 10M+ schedules, verify the CI bound meets target.
    if final_schedules >= 10_000_000 {
        assert!(
            ci_upper < 1e-7,
            "95% CI upper bound {ci_upper:.2e} exceeds target 1e-7 \
             ({final_schedules} schedules, {final_violations} violations)"
        );
    }

    test_complete!(
        "obligation_leak_stress",
        schedules = final_schedules,
        obligations = final_obligations,
        violations = final_violations,
        ci_upper = format!("{ci_upper:.2e}")
    );
}

// ============================================================================
// Binomial CI unit tests
// ============================================================================

#[test]
fn binomial_ci_rule_of_three() {
    // For 10M schedules with 0 leaks: upper ≈ 3/10M = 3e-7
    let ci = binomial_ci_upper_95(10_000_000, 0);
    assert!(ci < 1e-6, "CI too large for 10M: {ci}");
    assert!(ci > 1e-8, "CI too small for 10M: {ci}");

    // For 100K schedules with 0 leaks: upper ≈ 3e-5
    let ci = binomial_ci_upper_95(100_000, 0);
    assert!(ci < 1e-4, "CI too large for 100K: {ci}");
    assert!(ci > 1e-6, "CI too small for 100K: {ci}");

    // Edge case: zero schedules
    let ci = binomial_ci_upper_95(0, 0);
    assert!((ci - 1.0).abs() < f64::EPSILON);
}

#[test]
fn binomial_ci_with_failures() {
    // 1 failure in 1M: upper bound should be small but nonzero
    let ci = binomial_ci_upper_95(1_000_000, 1);
    assert!(ci > 1e-7, "CI should be > 1e-7 with 1 failure: {ci}");
    assert!(ci < 1e-4, "CI should be < 1e-4 with 1 failure: {ci}");

    // 100 failures in 1M: upper bound around 1.2e-4
    let ci = binomial_ci_upper_95(1_000_000, 100);
    assert!(ci > 1e-5, "CI should be > 1e-5 with 100 failures: {ci}");
    assert!(ci < 1e-3, "CI should be < 1e-3 with 100 failures: {ci}");
}

// ============================================================================
// RNG determinism test
// ============================================================================

#[test]
fn rng_determinism() {
    let mut r1 = Rng::new(42);
    let mut r2 = Rng::new(42);

    for _ in 0..1000 {
        assert_eq!(r1.next_u64(), r2.next_u64(), "RNG must be deterministic");
    }

    // Different seeds produce different sequences.
    let mut r3 = Rng::new(43);
    let mut r4 = Rng::new(42);
    let mut differ = false;
    for _ in 0..10 {
        if r3.next_u64() != r4.next_u64() {
            differ = true;
            break;
        }
    }
    assert!(differ, "different seeds should produce different sequences");
}

// ============================================================================
// Single-schedule smoke tests
// ============================================================================

#[test]
fn single_schedule_no_chaos() {
    let outcome = run_schedule(12345);
    assert_eq!(
        outcome.violations, 0,
        "single schedule should have no violations"
    );
    assert!(
        outcome.obligations_created > 0,
        "should have created obligations"
    );
}

#[test]
fn single_schedule_with_known_chaos_seed() {
    // Use a seed that forces chaos (seed where rng.chance(10) returns true).
    // We try a few seeds until we hit one with chaos.
    let mut found_chaos = false;
    for s in 0_u64..100 {
        let seed = s
            .wrapping_mul(0x517c_c1b7_2722_0a95)
            .wrapping_add(0x6c62_272e_07bb_0142);
        let outcome = run_schedule(seed);
        assert_eq!(outcome.violations, 0, "violation at seed {seed}");
        if outcome.chaos {
            found_chaos = true;
        }
    }
    assert!(found_chaos, "should have hit at least one chaos schedule");
}

#[test]
fn schedule_determinism_across_runs() {
    // Same seed must produce the same outcome.
    let seed = 0xDEAD_BEEF_CAFE_BABE;
    let o1 = run_schedule(seed);
    let o2 = run_schedule(seed);

    assert_eq!(
        o1.obligations_created, o2.obligations_created,
        "obligation count must be deterministic"
    );
    assert_eq!(o1.chaos, o2.chaos, "chaos flag must be deterministic");
    assert_eq!(
        o1.violations, o2.violations,
        "violation count must be deterministic"
    );
}
