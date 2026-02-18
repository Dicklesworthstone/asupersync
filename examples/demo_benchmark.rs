#![allow(missing_docs)]
//! Reproducible benchmark harness for the time-travel demo (bd-77g6j.3).
//!
//! Runs the full time-travel demo pipeline and validates that all outputs
//! match golden SHA-256 checksums, proving cross-machine reproducibility.
//!
//! Pipeline stages:
//! 1. **Seed search** — sweep seeds to find a failing schedule.
//! 2. **Trace recording** — record the failing execution to .ftrace.
//! 3. **Delta debugging** — minimize to the smallest reproducing subset.
//! 4. **Checksum validation** — SHA-256 of all deterministic outputs.
//!
//! All outputs are deterministic for a given seed range because:
//! - The Lab runtime is single-threaded and deterministic.
//! - The RNG (splitmix64) is deterministic for a given seed.
//! - The minimizer algorithm is deterministic.
//!
//! Usage:
//!   cargo run --example demo_benchmark --features test-internals
//!
//! Update golden checksums:
//!   GOLDEN_UPDATE=1 cargo run --example demo_benchmark --features test-internals
//!
//! Environment variables:
//!   GOLDEN_UPDATE  - Set to "1" to regenerate golden checksums.
//!   DEMO_TRACE_DIR - Output directory for artifacts (default: tempdir).

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::minimizer::{
    MinimizationReport, ScenarioElement, TraceMinimizer, generate_narrative,
};
use asupersync::trace::{TraceMetadata, write_trace};
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as FmtWrite;
use std::time::Instant;

// ============================================================================
// Configuration
// ============================================================================

const NUM_TASKS: u32 = 8;
const SEED_START: u64 = 0;
const SEED_COUNT: u64 = 50_000;
const GOLDEN_PATH: &str = "artifacts/demo_golden_checksums.json";

const OBLIGATION_KINDS: [ObligationKind; 4] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
];

// ============================================================================
// Golden checksum infrastructure
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct GoldenFile {
    schema_version: u32,
    generated_by: String,
    checksums: BTreeMap<String, GoldenEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoldenEntry {
    output_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
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

fn is_golden_update_mode() -> bool {
    std::env::var("GOLDEN_UPDATE")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn load_golden() -> Option<GoldenFile> {
    let data = std::fs::read_to_string(GOLDEN_PATH).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_golden(file: &GoldenFile) {
    let json = serde_json::to_string_pretty(file).expect("serialize golden checksums");
    std::fs::write(GOLDEN_PATH, json).expect("write golden checksums");
}

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
// Scenario element extraction (same as demo_delta_debug)
// ============================================================================

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

// ============================================================================
// Checker
// ============================================================================

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
// Trace recording
// ============================================================================

fn record_trace(seed: u64, trace_path: &str) -> Vec<u8> {
    let config = LabConfig::new(seed)
        .panic_on_leak(false)
        .panic_on_futurelock(false)
        .max_steps(50_000)
        .trace_capacity(4096)
        .with_default_replay_recording();

    let mut runtime = LabRuntime::new(config);
    replay_scenario(&mut runtime, seed);

    if let Some(trace) = runtime.finish_replay_trace() {
        // Use a fixed timestamp (0) for deterministic output.
        let mut metadata = TraceMetadata::new(seed);
        metadata.recorded_at = 0;

        write_trace(trace_path, &metadata, &trace.events).expect("write trace");

        // Return raw file bytes for hashing.
        std::fs::read(trace_path).expect("read trace file")
    } else {
        panic!("no replay trace captured for seed {seed}");
    }
}

fn replay_scenario(runtime: &mut LabRuntime, seed: u64) {
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
        runtime.scheduler.lock().schedule(task_id, lane);

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
// Pipeline
// ============================================================================

#[allow(dead_code)]
struct BenchmarkResult {
    failing_seed: u64,
    search_attempts: u64,
    search_ms: u64,
    original_count: usize,
    minimized_count: usize,
    reduction_ratio: f64,
    replay_attempts: usize,
    minimize_ms: u64,
    is_minimal: bool,
    checksums: BTreeMap<String, String>,
}

fn run_consistency_checks(
    elements: &[ScenarioElement],
    report: &MinimizationReport,
    checksums: &mut BTreeMap<String, String>,
) -> (bool, bool) {
    eprintln!("  phase 4: consistency checks");

    let elements_str = elements.iter().fold(String::new(), |mut acc, e| {
        use std::fmt::Write;
        writeln!(acc, "{e}").ok();
        acc
    });
    checksums.insert(
        "demo/original_elements".into(),
        sha256_hex(elements_str.as_bytes()),
    );

    let minimized = report.minimized_elements();
    let mut minimality_ok = true;
    for skip in 0..minimized.len() {
        let without: Vec<ScenarioElement> = minimized
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, e): (usize, &ScenarioElement)| e.clone())
            .collect();
        if check_for_leak(&without) {
            minimality_ok = false;
            eprintln!("    WARN: removing element {skip} still reproduces failure");
        }
    }
    eprintln!(
        "    minimality: {}",
        if minimality_ok { "PASS" } else { "FAIL" }
    );

    let report2 = TraceMinimizer::minimize(elements, check_for_leak);
    let stable = report2.minimized_indices == report.minimized_indices;
    eprintln!("    stability: {}", if stable { "PASS" } else { "FAIL" });

    (minimality_ok, stable)
}

#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
fn run_pipeline(trace_dir: &str) -> BenchmarkResult {
    let mut checksums = BTreeMap::new();

    // Phase 1: seed search.
    eprintln!(
        "  phase 1: seed search [{SEED_START}..{})",
        SEED_START + SEED_COUNT
    );
    let search_start = Instant::now();
    let mut attempts: u64 = 0;
    let mut failing_seed: Option<u64> = None;

    for seed in SEED_START..(SEED_START + SEED_COUNT) {
        attempts += 1;
        let elements = extract_elements(seed);
        if check_for_leak(&elements) {
            failing_seed = Some(seed);
            break;
        }
    }
    let search_ms = search_start.elapsed().as_millis() as u64;

    let seed = failing_seed.expect("no failing seed found");
    eprintln!("    seed={seed}, attempts={attempts}, time={search_ms}ms");
    checksums.insert(
        "demo/failing_seed".into(),
        sha256_hex(seed.to_le_bytes().as_slice()),
    );

    // Phase 2: trace recording.
    eprintln!("  phase 2: trace recording");
    let trace_path = format!("{trace_dir}/benchmark_seed_{seed}.ftrace");
    let trace_bytes = record_trace(seed, &trace_path);
    let trace_hash = sha256_hex(&trace_bytes);
    eprintln!(
        "    trace: {} bytes, hash={}...",
        trace_bytes.len(),
        &trace_hash[..16]
    );
    checksums.insert("demo/trace_file".into(), trace_hash);

    // Phase 3: delta debugging.
    eprintln!("  phase 3: delta debugging");
    let elements = extract_elements(seed);
    let minimize_start = Instant::now();
    let report = TraceMinimizer::minimize(&elements, check_for_leak);
    let minimize_ms = minimize_start.elapsed().as_millis() as u64;

    // Hash the minimized elements (canonical string representation).
    let minimized_str = report
        .minimized_elements()
        .iter()
        .fold(String::new(), |mut acc, e| {
            use std::fmt::Write;
            writeln!(acc, "{e}").ok();
            acc
        });
    let minimized_hash = sha256_hex(minimized_str.as_bytes());
    eprintln!(
        "    minimized: {}/{} elements, hash={}...",
        report.minimized_count,
        report.original_count,
        &minimized_hash[..16]
    );
    checksums.insert("demo/minimized_elements".into(), minimized_hash);

    // Hash the narrative (deterministic parts only — exclude wall time).
    let narrative = generate_narrative(&report);
    // Strip the wall-time line from the narrative for deterministic hashing.
    let narrative_deterministic: String = narrative
        .lines()
        .filter(|line| !line.contains("Wall time"))
        .collect::<Vec<_>>()
        .join("\n");
    let narrative_hash = sha256_hex(narrative_deterministic.as_bytes());
    checksums.insert("demo/narrative".into(), narrative_hash);

    let (minimality_ok, _stable) = run_consistency_checks(&elements, &report, &mut checksums);

    BenchmarkResult {
        failing_seed: seed,
        search_attempts: attempts,
        search_ms,
        original_count: report.original_count,
        minimized_count: report.minimized_count,
        reduction_ratio: report.reduction_ratio,
        replay_attempts: report.replay_attempts,
        minimize_ms,
        is_minimal: report.is_minimal && minimality_ok,
        checksums,
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    eprintln!("demo_benchmark: reproducible time-travel demo harness");

    let trace_dir = std::env::var("DEMO_TRACE_DIR").unwrap_or_else(|_| {
        let dir = std::env::temp_dir().join("asupersync_benchmark");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.to_string_lossy().into_owned()
    });

    let total_start = Instant::now();
    let result = run_pipeline(&trace_dir);
    let total_ms = total_start.elapsed().as_millis() as u64;

    eprintln!("  total_wall_time_ms={total_ms}");

    // Checksum validation.
    let update_mode = is_golden_update_mode();
    let golden = load_golden();
    let mut all_pass = true;
    let mut updated_checksums = BTreeMap::new();

    eprintln!("\n--- Checksum Report ---");
    for (key, actual_hash) in &result.checksums {
        let expected = golden
            .as_ref()
            .and_then(|g| g.checksums.get(key))
            .map(|e| e.output_hash.as_str());

        let status = match expected {
            Some(exp) if exp == actual_hash => "PASS",
            Some("GENERATE") => {
                if update_mode {
                    "GENERATED"
                } else {
                    all_pass = false;
                    "MISSING"
                }
            }
            Some(_) => {
                if update_mode {
                    "UPDATED"
                } else {
                    all_pass = false;
                    "FAIL"
                }
            }
            None => {
                if update_mode {
                    "NEW"
                } else {
                    // New checksums are informational, not failures.
                    "INFO"
                }
            }
        };

        eprintln!("  {status:10}  {key}  {}", &actual_hash[..16]);

        if let (Some(exp), false) = (expected, update_mode) {
            if exp != actual_hash && exp != "GENERATE" {
                eprintln!("             expected: {exp}");
                eprintln!("             actual:   {actual_hash}");
            }
        }

        updated_checksums.insert(
            key.clone(),
            GoldenEntry {
                output_hash: actual_hash.clone(),
                description: None,
            },
        );
    }

    if update_mode {
        let golden_file = GoldenFile {
            schema_version: 1,
            generated_by: "demo_benchmark (bd-77g6j.3)".into(),
            checksums: updated_checksums,
        };
        save_golden(&golden_file);
        eprintln!("\n  Golden checksums written to {GOLDEN_PATH}");
    }

    // Summary.
    println!("\nReproducible benchmark complete.");
    println!("  Failing seed:     {}", result.failing_seed);
    println!("  Search attempts:  {}", result.search_attempts);
    println!("  Original:         {} elements", result.original_count);
    println!("  Minimized:        {} elements", result.minimized_count);
    println!("  Reduction:        {:.1}%", result.reduction_ratio * 100.0);
    println!("  Replays:          {}", result.replay_attempts);
    println!("  1-minimal:        {}", result.is_minimal);
    println!("  Pipeline time:    {total_ms}ms");
    println!(
        "  Checksum status:  {}",
        if all_pass { "ALL PASS" } else { "MISMATCH" }
    );

    if !all_pass && !update_mode {
        eprintln!("\nFAILED: checksum mismatch. Run with GOLDEN_UPDATE=1 to regenerate.");
        std::process::exit(1);
    }
}
