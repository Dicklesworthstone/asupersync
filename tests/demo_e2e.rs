#![allow(missing_docs)]
//! E2E test suite for the time-travel demo pipeline (bd-77g6j.4).
//!
//! Validates that the full pipeline (seed search -> trace recording ->
//! delta debugging -> minimality verification) produces correct,
//! deterministic, reproducible results.

mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::minimizer::{ScenarioElement, TraceMinimizer, generate_narrative};
use asupersync::trace::{TraceMetadata, read_trace, write_trace};
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::time::Instant;

// ============================================================================
// Shared scenario infrastructure
// ============================================================================

const NUM_TASKS: u32 = 8;
const OBLIGATION_KINDS: [ObligationKind; 4] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
];

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

struct TrackedObligation {
    id: ObligationId,
    commit: bool,
    is_late: bool,
}

fn extract_elements(seed: u64) -> Vec<ScenarioElement> {
    let mut rng = Rng::new(seed);
    let mut elems = Vec::new();

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
                        runtime.scheduler.lock().unwrap().schedule(tid, *lane);
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

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in &result {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Find the first failing seed in the given range.
fn find_failing_seed(start: u64, count: u64) -> Option<(u64, u64)> {
    for seed in start..(start + count) {
        let elements = extract_elements(seed);
        if check_for_leak(&elements) {
            return Some((seed, seed - start + 1));
        }
    }
    None
}

// ============================================================================
// E2E tests
// ============================================================================

/// (1) Full demo pipeline — verify each stage completes successfully.
#[test]
fn full_pipeline_completes() {
    // Stage 1: find a failing seed.
    let (seed, attempts) = find_failing_seed(0, 50_000).expect("must find a failing seed");
    assert!(attempts < 50_000, "seed search should not exhaust budget");

    // Stage 2: extract and verify elements.
    let elements = extract_elements(seed);
    assert!(
        check_for_leak(&elements),
        "extracted elements must reproduce the failure"
    );

    // Stage 3: minimize.
    let report = TraceMinimizer::minimize(&elements, check_for_leak);
    assert!(report.minimized_count <= report.original_count);
    assert!(report.reduction_ratio > 0.0);

    // Stage 4: verify minimized set still fails.
    let minimized = report.minimized_elements();
    assert!(
        check_for_leak(&minimized),
        "minimized set must still reproduce the failure"
    );

    // Stage 5: narrative generation.
    let narrative = generate_narrative(&report);
    assert!(narrative.contains("Minimized Failure Narrative"));
}

/// (2) Artifact hash stability — verify checksums match golden values.
#[test]
fn artifact_hash_stability() {
    let (seed, _) = find_failing_seed(0, 50_000).expect("must find a failing seed");

    // Compute hashes.
    let elements = extract_elements(seed);
    let elements_str = elements.iter().fold(String::new(), |mut acc, e| {
        use std::fmt::Write;
        writeln!(acc, "{e}").ok();
        acc
    });
    let elements_hash = sha256_hex(elements_str.as_bytes());

    let report = TraceMinimizer::minimize(&elements, check_for_leak);
    let minimized_str = report
        .minimized_elements()
        .iter()
        .fold(String::new(), |mut acc, e| {
            use std::fmt::Write;
            writeln!(acc, "{e}").ok();
            acc
        });
    let minimized_hash = sha256_hex(minimized_str.as_bytes());

    // Verify against golden values from demo_benchmark run.
    assert_eq!(
        sha256_hex(seed.to_le_bytes().as_slice()),
        "6abe2f4b2df1474a569e776779d9b190ae69061287207937e19af225a56d8721",
        "failing seed hash mismatch"
    );
    assert_eq!(
        elements_hash, "2b5765734900cb8ffd1e3945c15a594d8e7d50f36072ab46672456cfeca97a64",
        "original elements hash mismatch"
    );
    assert_eq!(
        minimized_hash, "0cd76c88cc6cee445f11ec7294ac4b9fef197998169cd43c4d9bf60f040d1dd6",
        "minimized elements hash mismatch"
    );
}

/// (4) Minimized trace validity — removing any single element from the
/// minimized set causes the failure to disappear.
#[test]
fn minimality_property() {
    let (seed, _) = find_failing_seed(0, 50_000).expect("must find a failing seed");
    let elements = extract_elements(seed);
    let report = TraceMinimizer::minimize(&elements, check_for_leak);
    let minimized = report.minimized_elements();

    assert!(report.is_minimal, "minimizer should report 1-minimal");

    for skip in 0..minimized.len() {
        let without: Vec<ScenarioElement> = minimized
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, e)| e.clone())
            .collect();

        assert!(
            !check_for_leak(&without),
            "removing element {skip} ({}) should eliminate the failure",
            minimized[skip]
        );
    }
}

/// Hash stability across 10 consecutive runs — the minimizer must produce
/// identical output every time.
#[test]
fn hash_stability_10_runs() {
    let (seed, _) = find_failing_seed(0, 50_000).expect("must find a failing seed");
    let elements = extract_elements(seed);

    let first = TraceMinimizer::minimize(&elements, check_for_leak);
    let first_hash = {
        let s = first
            .minimized_elements()
            .iter()
            .fold(String::new(), |mut acc, e| {
                use std::fmt::Write;
                writeln!(acc, "{e}").ok();
                acc
            });
        sha256_hex(s.as_bytes())
    };

    for run in 1..10 {
        let report = TraceMinimizer::minimize(&elements, check_for_leak);
        let hash = {
            let s = report
                .minimized_elements()
                .iter()
                .fold(String::new(), |mut acc, e| {
                    use std::fmt::Write;
                    writeln!(acc, "{e}").ok();
                    acc
                });
            sha256_hex(s.as_bytes())
        };
        assert_eq!(
            hash, first_hash,
            "run {run} produced different hash: {hash} != {first_hash}"
        );
        assert_eq!(
            report.minimized_indices, first.minimized_indices,
            "run {run} produced different minimized indices"
        );
    }
}

/// Seed search is itself reproducible — running twice gives the same seed.
#[test]
fn seed_search_reproducible() {
    let (seed1, attempts1) = find_failing_seed(0, 50_000).expect("run 1");
    let (seed2, attempts2) = find_failing_seed(0, 50_000).expect("run 2");

    assert_eq!(seed1, seed2, "seed search must be deterministic");
    assert_eq!(attempts1, attempts2, "attempt count must be deterministic");
}

/// (6) Performance regression — the full pipeline must complete within
/// the timeout budget (5 minutes for CI, we use 60s for the test).
#[test]
fn pipeline_within_timeout() {
    let start = Instant::now();

    let (seed, _) = find_failing_seed(0, 50_000).expect("must find seed");
    let elements = extract_elements(seed);
    let _report = TraceMinimizer::minimize(&elements, check_for_leak);

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "pipeline took {elapsed:?}, exceeds 60s timeout"
    );
}

/// Trace file round-trip — write a trace, read it back, verify identical events.
#[test]
fn trace_file_roundtrip() {
    let (seed, _) = find_failing_seed(0, 50_000).expect("must find seed");

    // Record a trace.
    let config = LabConfig::new(seed)
        .panic_on_leak(false)
        .panic_on_futurelock(false)
        .max_steps(50_000)
        .trace_capacity(4096)
        .with_default_replay_recording();

    let mut runtime = LabRuntime::new(config);
    replay_scenario_for_trace(&mut runtime, seed);

    let trace = runtime
        .finish_replay_trace()
        .expect("must capture replay trace");

    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("test.ftrace");
    let path_str = path.to_string_lossy();

    let mut metadata = TraceMetadata::new(seed);
    metadata.recorded_at = 0; // Fixed timestamp for determinism.
    write_trace(&*path_str, &metadata, &trace.events).expect("write trace");

    // Read it back.
    let (read_meta, read_events) = read_trace(&*path_str).expect("read trace");

    assert_eq!(read_meta.seed, seed);
    assert_eq!(read_events.len(), trace.events.len());
    assert_eq!(read_meta.recorded_at, 0);

    // Verify the file is byte-stable.
    let bytes1 = std::fs::read(&path).expect("read file");
    write_trace(&*path_str, &metadata, &trace.events).expect("write trace again");
    let bytes2 = std::fs::read(&path).expect("read file again");
    assert_eq!(
        bytes1, bytes2,
        "trace file must be byte-identical on re-write"
    );
}

fn replay_scenario_for_trace(runtime: &mut LabRuntime, seed: u64) {
    let mut rng = Rng::new(seed);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let cancel_target = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create cancel target");
    let survivor = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create survivor");

    let mut obligations: Vec<TrackedObligation> = Vec::new();

    for i in 0..NUM_TASKS {
        let region = if i % 3 != 0 { cancel_target } else { survivor };
        let Ok((task_id, _)) = runtime
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

    resolve_obligations(runtime, &obligations);

    let reason = CancelReason::new(CancelKind::User);
    let _ = runtime.state.cancel_request(cancel_target, &reason, None);

    if rng.chance(30) {
        runtime.advance_time(u64::from(rng.next_u32(50_000)) + 1);
    }

    runtime.advance_time(1_000_000);
    runtime.run_until_quiescent();
}
