#![allow(missing_docs)]
//! Nondeterministic failure demo: cancel/obligation race condition (bd-77g6j.1).
//!
//! This demo sweeps seeds to find a schedule where the race between cancel
//! propagation and obligation resolution produces an obligation leak.
//! When a failure seed is found, the execution trace is recorded to an .ftrace
//! file for deterministic replay and time-travel debugging.
//!
//! The race window: when cancel is requested on a region, tasks in that region
//! may hold unresolved obligations (SendPermit, Ack, Lease). The cancel path
//! marks the region Closing and tasks for cancel, but does NOT abort in-flight
//! obligations. If a task acquires an obligation just before cancel propagates
//! and the obligation is not resolved before the region fully closes, the
//! obligation leaks in Reserved state.
//!
//! In the lab runtime (single-threaded, deterministic), we simulate this race
//! by varying the obligation resolution order per seed. For most seeds, all
//! obligations resolve cleanly. For rare seeds, the resolution order leaves
//! an obligation in Reserved state at region close — a genuine leak.
//!
//! Usage:
//!   cargo run --example demo_record_nondeterministic
//!
//! Environment variables:
//!   DEMO_SEED_START   - First seed to try (default: 0)
//!   DEMO_SEED_COUNT   - Number of seeds to sweep (default: 50_000)
//!   DEMO_TRACE_DIR    - Directory for .ftrace output (default: ".")

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::{write_trace, TraceMetadata};
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId};
use std::time::Instant;

// ============================================================================
// Configuration
// ============================================================================

/// Number of concurrent tasks per scenario.
const NUM_TASKS: u32 = 8;

/// Obligation kinds to cycle through.
const OBLIGATION_KINDS: [ObligationKind; 4] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
];

// ============================================================================
// Deterministic RNG (splitmix64)
// ============================================================================

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
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

    fn next_u32(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n)) as u32
    }

    fn chance(&mut self, percent: u32) -> bool {
        self.next_u32(100) < percent
    }

    /// Returns true with probability approx 1/n.
    fn rare(&mut self, one_in_n: u32) -> bool {
        self.next_u32(one_in_n) == 0
    }
}

// ============================================================================
// Obligation tracking
// ============================================================================

struct TrackedObligation {
    id: ObligationId,
    commit: bool,
    /// If true, this obligation is "late" — it simulates the race window
    /// where the obligation is acquired just before cancel propagates.
    /// Late obligations are not resolved before the region closes.
    is_late: bool,
}

// ============================================================================
// Scenario construction
// ============================================================================

struct SeedOutcome {
    leak_count: u64,
    event_count: usize,
    wall_ms: u64,
}

/// Build and run the cancel/obligation race scenario for a single seed.
///
/// The scenario creates 8 tasks split between a cancel-target region and a
/// survivor region. Each task acquires 1-3 obligations. For most seeds, all
/// obligations are resolved before the cancel-target region closes. For rare
/// seeds (~1/10000 per obligation, ~1/1000 per seed), an obligation is marked "late" — it is not
/// resolved before cancel, simulating the race window. If a late obligation
/// belongs to the cancel-target region, it leaks.
fn run_scenario(seed: u64, record: bool) -> SeedOutcome {
    let start = Instant::now();
    let mut rng = Rng::new(seed);

    let config = LabConfig::new(seed)
        .panic_on_leak(false)
        .panic_on_futurelock(false)
        .max_steps(50_000)
        .trace_capacity(if record { 4096 } else { 256 });

    let config = if record {
        config.with_default_replay_recording()
    } else {
        config
    };

    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let cancel_target = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create cancel target region");

    let survivor = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create survivor region");

    let mut obligations: Vec<TrackedObligation> = Vec::new();

    // Spawn tasks and create obligations.
    for i in 0..NUM_TASKS {
        // ~2/3 of tasks go to cancel_target, ~1/3 to survivor.
        let region = if i % 3 != 0 { cancel_target } else { survivor };

        let Ok((task_id, _handle)) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
        else {
            continue;
        };

        let lane = rng.next_u32(4) as u8;
        runtime.scheduler.lock().unwrap().schedule(task_id, lane);

        let num_obligations = 1 + rng.next_u32(3);
        for j in 0..num_obligations {
            let kind = OBLIGATION_KINDS[(i as usize + j as usize) % OBLIGATION_KINDS.len()];
            let commit = rng.chance(60);

            if let Ok(obl_id) = runtime.state.create_obligation(kind, task_id, region, None) {
                // An obligation is "late" with small probability (~1/500).
                // This simulates the race window where the task acquires an
                // obligation just before cancel propagates to it.
                let is_late = region == cancel_target && rng.rare(10_000);

                obligations.push(TrackedObligation {
                    id: obl_id,
                    commit,
                    is_late,
                });
            }
        }
    }

    // Optionally advance time.
    if rng.chance(50) {
        runtime.advance_time(u64::from(rng.next_u32(100_000)) + 1);
    }

    // Resolve non-late obligations before cancel.
    resolve_batch(&mut runtime, &obligations);

    // Cancel the target region.
    let cancel_reason = CancelReason::new(CancelKind::User);
    let _ = runtime
        .state
        .cancel_request(cancel_target, &cancel_reason, None);

    // Optionally advance time after cancel.
    if rng.chance(30) {
        runtime.advance_time(u64::from(rng.next_u32(50_000)) + 1);
    }

    // Late obligations are NOT resolved — they simulate the race window
    // where a task acquires an obligation just before cancel propagates.
    // The obligation stays in Reserved state when the region closes = leak.

    runtime.advance_time(1_000_000);
    runtime.run_until_quiescent();

    let leak_count = detected_leak_count(&runtime);
    let event_count = runtime.replay_recorder().event_count();
    let wall_ms = start.elapsed().as_millis() as u64;

    SeedOutcome {
        leak_count,
        event_count,
        wall_ms,
    }
}

/// Resolve all non-late obligations (commit or abort).
/// Late obligations are deliberately left unresolved to simulate the race window.
fn resolve_batch(runtime: &mut LabRuntime, obligations: &[TrackedObligation]) {
    for obl in obligations {
        if obl.is_late {
            continue;
        }

        if obl.commit {
            let _ = runtime.state.commit_obligation(obl.id);
        } else {
            let _ = runtime
                .state
                .abort_obligation(obl.id, ObligationAbortReason::Explicit);
        }
    }
}

/// Check if any obligation leaks were detected during execution.
///
/// The runtime handles leaks during `run_until_quiescent()` via the
/// obligation leak response handler (mark_obligation_leaked / abort).
/// So `check_invariants()` would find nothing — the obligations are
/// already resolved. Instead, check the cumulative leak counter.
fn detected_leak_count(runtime: &LabRuntime) -> u64 {
    runtime.state.leak_count()
}

/// Re-run the failing seed with recording and save to .ftrace.
fn record_failing_trace(seed: u64, trace_dir: &str) {
    eprintln!("  demo::record  seed={seed}");

    let outcome = run_scenario(seed, true);
    assert!(
        outcome.leak_count > 0,
        "expected leak to reproduce for seed {seed}"
    );

    // We need to re-run to get the trace since run_scenario consumed the runtime.
    // Create a fresh runtime just for trace extraction.
    let config = LabConfig::new(seed)
        .panic_on_leak(false)
        .panic_on_futurelock(false)
        .max_steps(50_000)
        .trace_capacity(4096)
        .with_default_replay_recording();

    let mut runtime = LabRuntime::new(config);
    replay_scenario_for_trace(&mut runtime, seed);

    let trace_file = format!("{trace_dir}/demo_obligation_leak_seed_{seed}.ftrace");
    if let Some(trace) = runtime.finish_replay_trace() {
        let metadata = TraceMetadata::new(seed);
        match write_trace(&trace_file, &metadata, &trace.events) {
            Ok(()) => {
                let size = std::fs::metadata(&trace_file).map_or(0, |m| m.len());
                eprintln!(
                    "  trace recorded: file={trace_file}, size_bytes={size}, events={}",
                    trace.events.len()
                );
                eprintln!("  demo_trace_size_bytes={size}");
            }
            Err(e) => {
                eprintln!("  ERROR: recording failed: seed={seed}, error={e}");
                std::process::exit(2);
            }
        }
    } else {
        eprintln!("  ERROR: recording failed: seed={seed}, error=no replay trace captured");
        std::process::exit(2);
    }

    println!("  Trace file:    {trace_file}");
}

/// Replay the scenario identically for trace capture.
fn replay_scenario_for_trace(runtime: &mut LabRuntime, seed: u64) {
    let mut rng = Rng::new(seed);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let cancel_target = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create cancel target region");
    let survivor = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create survivor region");

    let mut obligations: Vec<TrackedObligation> = Vec::new();

    for i in 0..NUM_TASKS {
        let region = if i % 3 != 0 { cancel_target } else { survivor };
        let Ok((task_id, _handle)) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
        else {
            continue;
        };
        let lane = rng.next_u32(4) as u8;
        runtime.scheduler.lock().unwrap().schedule(task_id, lane);

        let num_obligations = 1 + rng.next_u32(3);
        for j in 0..num_obligations {
            let kind = OBLIGATION_KINDS[(i as usize + j as usize) % OBLIGATION_KINDS.len()];
            let commit = rng.chance(60);
            if let Ok(obl_id) = runtime.state.create_obligation(kind, task_id, region, None) {
                let is_late = region == cancel_target && rng.rare(10_000);
                obligations.push(TrackedObligation {
                    id: obl_id,
                    commit,
                    is_late,
                });
            }
        }
    }

    if rng.chance(50) {
        runtime.advance_time(u64::from(rng.next_u32(100_000)) + 1);
    }

    resolve_batch(runtime, &obligations);

    let cancel_reason = CancelReason::new(CancelKind::User);
    let _ = runtime
        .state
        .cancel_request(cancel_target, &cancel_reason, None);

    if rng.chance(30) {
        runtime.advance_time(u64::from(rng.next_u32(50_000)) + 1);
    }

    runtime.advance_time(1_000_000);
    runtime.run_until_quiescent();
}

// ============================================================================
// Main
// ============================================================================

#[allow(clippy::cast_precision_loss)]
fn main() {
    let seed_start: u64 = std::env::var("DEMO_SEED_START")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let seed_count: u64 = std::env::var("DEMO_SEED_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    let trace_dir = std::env::var("DEMO_TRACE_DIR").unwrap_or_else(|_| ".".to_string());

    eprintln!(
        "demo::search  seed_range=[{seed_start}..{}), target_failure_type=obligation_leak",
        seed_start + seed_count
    );

    let search_start = Instant::now();
    let mut attempts: u64 = 0;
    let mut failure_seed: Option<u64> = None;
    let mut failure_leak_count: u64 = 0;
    let mut failure_events: usize = 0;

    for seed in seed_start..(seed_start + seed_count) {
        attempts += 1;
        let outcome = run_scenario(seed, false);

        if outcome.leak_count == 0 {
            if attempts.is_multiple_of(1000) {
                eprintln!(
                    "  scenario attempt: seed={seed}, outcome=pass, event_count={}, wall_time_ms={}",
                    outcome.event_count, outcome.wall_ms
                );
            }
        } else {
            eprintln!(
                "  failure found: seed={seed}, failure_type=obligation_leak, \
                 event_count={}, leak_count={}",
                outcome.event_count, outcome.leak_count
            );
            failure_seed = Some(seed);
            failure_leak_count = outcome.leak_count;
            failure_events = outcome.event_count;
            break;
        }
    }

    let search_ms = search_start.elapsed().as_millis() as u64;
    eprintln!("  demo_search_attempts_total={attempts}");
    eprintln!("  demo_search_duration_ms={search_ms}");

    let Some(seed) = failure_seed else {
        eprintln!(
            "  WARN: scenario search exhausted {attempts} seeds \
             without finding failure -- check scenario parameters"
        );
        eprintln!("  demo_failure_rate=0");
        std::process::exit(1);
    };

    let rate = 1.0 / attempts as f64;
    eprintln!("  demo_failure_rate={rate:.6}");

    record_failing_trace(seed, &trace_dir);

    println!("Nondeterministic failure demo complete.");
    println!("  Failure seed:  {seed}");
    println!("  Leak count:    {failure_leak_count}");
    println!("  Events:        {failure_events}");
    println!("  Attempts:      {attempts}/{seed_count}");
}
