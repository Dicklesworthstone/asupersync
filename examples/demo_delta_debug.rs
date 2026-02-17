#![allow(missing_docs)]
//! Hierarchical delta debugging demo (bd-77g6j.2).
//!
//! This demo:
//! 1. Sweeps seeds to find a cancel/obligation race condition.
//! 2. Extracts the scenario as [`ScenarioElement`]s.
//! 3. Runs [`TraceMinimizer::minimize`] to find the minimal failing subset.
//! 4. Generates a Markdown narrative explaining the root cause.
//!
//! The minimizer exploits the structured concurrency tree to prune entire
//! region subtrees before falling back to fine-grained ddmin, yielding
//! sub-linear replay counts for hierarchical scenarios.
//!
//! Usage:
//!   cargo run --example demo_delta_debug --features test-internals
//!
//! Environment variables:
//!   DEMO_SEED_START   - First seed to try (default: 0)
//!   DEMO_SEED_COUNT   - Number of seeds to sweep (default: 50_000)
//!   DEMO_NARRATIVE    - Output path for narrative .md (default: narrative.md)

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::minimizer::{generate_narrative, ScenarioElement, TraceMinimizer};
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId};
use std::collections::HashMap;
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
// Deterministic RNG (splitmix64) — same as demo_record_nondeterministic
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
    is_late: bool,
}

// ============================================================================
// Scenario element extraction
// ============================================================================

/// Extract `ScenarioElement`s from a seed, mirroring the construction
/// in `demo_record_nondeterministic::run_scenario`.
///
/// The RNG call sequence is identical, so `extract_elements(seed)` produces
/// elements whose failure/pass behavior matches `run_scenario(seed, false)`.
fn extract_elements(seed: u64) -> Vec<ScenarioElement> {
    let mut rng = Rng::new(seed);
    let mut elems = Vec::new();

    // Region 1 = cancel_target, Region 2 = survivor.
    elems.push(ScenarioElement::CreateRegion {
        region_idx: 1,
        parent_idx: 0,
    });
    elems.push(ScenarioElement::CreateRegion {
        region_idx: 2,
        parent_idx: 0,
    });

    for i in 0..NUM_TASKS {
        let region_idx = if i % 3 != 0 { 1 } else { 2 };
        let lane = rng.next_u32(4) as u8;
        elems.push(ScenarioElement::SpawnTask {
            task_idx: i as usize,
            region_idx,
            lane,
        });

        let num_obligations = 1 + rng.next_u32(3);
        for j in 0..num_obligations {
            let kind = OBLIGATION_KINDS[(i as usize + j as usize) % OBLIGATION_KINDS.len()];
            let commit = rng.chance(60);
            // Short-circuit: rng.rare() is only called when region == cancel_target.
            let is_late = region_idx == 1 && rng.rare(10_000);

            elems.push(ScenarioElement::CreateObligation {
                task_idx: i as usize,
                region_idx,
                kind,
                commit,
                is_late,
            });
        }
    }

    if rng.chance(50) {
        elems.push(ScenarioElement::AdvanceTime {
            nanos: u64::from(rng.next_u32(100_000)) + 1,
        });
    }

    elems.push(ScenarioElement::CancelRegion { region_idx: 1 });

    if rng.chance(30) {
        elems.push(ScenarioElement::AdvanceTime {
            nanos: u64::from(rng.next_u32(50_000)) + 1,
        });
    }

    elems
}

// ============================================================================
// Checker: build LabRuntime from ScenarioElements and detect leaks
// ============================================================================

/// Construct a `LabRuntime` from a subset of `ScenarioElement`s and check
/// whether the resulting execution produces an obligation leak.
///
/// Elements that reference missing regions or tasks (pruned by the minimizer)
/// are silently skipped.  Non-late obligations are resolved before the first
/// `CancelRegion` element, matching the resolution order of the original
/// scenario.
fn check_for_leak(elements: &[ScenarioElement]) -> bool {
    let config = LabConfig::new(0)
        .panic_on_leak(false)
        .panic_on_futurelock(false)
        .max_steps(50_000)
        .trace_capacity(256);

    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let mut regions = HashMap::new();
    regions.insert(0usize, root);

    let mut tasks = HashMap::new();
    let mut obligations: Vec<TrackedObligation> = Vec::new();
    let mut resolved = false;

    for elem in elements {
        match elem {
            ScenarioElement::CreateRegion {
                region_idx,
                parent_idx,
            } => {
                if let Some(&parent) = regions.get(parent_idx) {
                    if let Ok(rid) = runtime.state.create_child_region(parent, Budget::INFINITE) {
                        regions.insert(*region_idx, rid);
                    }
                }
            }
            ScenarioElement::SpawnTask {
                task_idx,
                region_idx,
                lane,
            } => {
                if let Some(&rid) = regions.get(region_idx) {
                    if let Ok((tid, _)) = runtime.state.create_task(rid, Budget::INFINITE, async {})
                    {
                        runtime.scheduler.lock().schedule(tid, *lane);
                        tasks.insert(*task_idx, tid);
                    }
                }
            }
            ScenarioElement::CreateObligation {
                task_idx,
                region_idx,
                kind,
                commit,
                is_late,
            } => {
                if let (Some(&tid), Some(&rid)) = (tasks.get(task_idx), regions.get(region_idx)) {
                    if let Ok(obl_id) = runtime.state.create_obligation(*kind, tid, rid, None) {
                        obligations.push(TrackedObligation {
                            id: obl_id,
                            commit: *commit,
                            is_late: *is_late,
                        });
                    }
                }
            }
            ScenarioElement::CancelRegion { region_idx } => {
                // Resolve non-late obligations before the first cancel.
                if !resolved {
                    resolve_obligations(&mut runtime, &obligations);
                    resolved = true;
                }
                if let Some(&rid) = regions.get(region_idx) {
                    let reason = CancelReason::new(CancelKind::User);
                    let _ = runtime.state.cancel_request(rid, &reason, None);
                }
            }
            ScenarioElement::AdvanceTime { nanos } => {
                runtime.advance_time(*nanos);
            }
        }
    }

    if !resolved {
        resolve_obligations(&mut runtime, &obligations);
    }

    runtime.advance_time(1_000_000);
    runtime.run_until_quiescent();

    runtime.state.leak_count() > 0
}

fn resolve_obligations(runtime: &mut LabRuntime, obligations: &[TrackedObligation]) {
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

    let narrative_path =
        std::env::var("DEMO_NARRATIVE").unwrap_or_else(|_| "narrative.md".to_string());

    // Phase 1: find a failing seed.
    eprintln!(
        "demo::search  seed_range=[{seed_start}..{}), target=obligation_leak",
        seed_start + seed_count,
    );

    let search_start = Instant::now();
    let mut attempts: u64 = 0;
    let mut failure_seed: Option<u64> = None;

    for seed in seed_start..(seed_start + seed_count) {
        attempts += 1;
        let elements = extract_elements(seed);
        if check_for_leak(&elements) {
            eprintln!(
                "  failure found: seed={seed}, elements={}, search_attempts={attempts}",
                elements.len(),
            );
            failure_seed = Some(seed);
            break;
        }
        if attempts.is_multiple_of(1000) {
            eprintln!("  searching: seed={seed}, attempts={attempts}");
        }
    }

    let search_ms = search_start.elapsed().as_millis() as u64;
    eprintln!("  demo_search_duration_ms={search_ms}");

    let Some(seed) = failure_seed else {
        eprintln!(
            "  WARN: no failing seed found in {attempts} attempts — \
             check scenario parameters"
        );
        std::process::exit(1);
    };

    // Phase 2: minimize.
    let elements = extract_elements(seed);
    eprintln!("demo::minimize  seed={seed}, elements={}", elements.len(),);

    let minimize_start = Instant::now();
    let report = TraceMinimizer::minimize(&elements, check_for_leak);
    let minimize_ms = minimize_start.elapsed().as_millis() as u64;

    eprintln!(
        "  minimized: {}/{} elements ({:.1}% reduction), replays={}, \
         wall_time={}ms, 1-minimal={}",
        report.minimized_count,
        report.original_count,
        report.reduction_ratio * 100.0,
        report.replay_attempts,
        minimize_ms,
        report.is_minimal,
    );

    // Phase 3: generate narrative.
    let narrative = generate_narrative(&report);
    match std::fs::write(&narrative_path, &narrative) {
        Ok(()) => eprintln!("  narrative written: {narrative_path}"),
        Err(e) => eprintln!("  ERROR: failed to write narrative: {e}"),
    }

    // Print summary.
    println!("Hierarchical delta debugging complete.");
    println!("  Seed:          {seed}");
    println!("  Original:      {} elements", report.original_count);
    println!("  Minimized:     {} elements", report.minimized_count);
    println!("  Reduction:     {:.1}%", report.reduction_ratio * 100.0,);
    println!("  Replays:       {}", report.replay_attempts);
    println!("  1-minimal:     {}", report.is_minimal);
    println!("  Narrative:     {narrative_path}");
    println!("\nMinimal failure scenario:");
    for (i, elem) in report.minimized_elements().iter().enumerate() {
        println!("  {}. {elem}", i + 1);
    }
}
