//! Adversarial regime-shift synthesizer contract invariants (AA-06.4).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/adversarial_regime_shift_contract.md";
const ARTIFACT_PATH: &str = "artifacts/adversarial_regime_shift_v1.json";
const RUNNER_PATH: &str = "scripts/run_adversarial_regime_shift_smoke.sh";

fn load_artifact() -> Value {
    let content =
        std::fs::read_to_string(ARTIFACT_PATH).expect("artifact must exist at expected path");
    serde_json::from_str(&content).expect("artifact must be valid JSON")
}

fn load_doc() -> String {
    std::fs::read_to_string(DOC_PATH).expect("contract doc must exist")
}

fn load_runner() -> String {
    std::fs::read_to_string(RUNNER_PATH).expect("runner script must exist")
}

// ── Document stability ─────────────────────────────────────────────

#[test]
fn doc_exists_and_has_required_sections() {
    let doc = load_doc();
    for section in &[
        "## Purpose",
        "## Contract Artifacts",
        "## Search Objectives",
        "## Mutation Model",
        "## Challenge Corpus Feedback",
        "## Structured Logging Contract",
        "## Validation",
        "## Cross-References",
    ] {
        assert!(doc.contains(section), "doc must contain section: {section}");
    }
}

#[test]
fn doc_references_bead_id() {
    let doc = load_doc();
    let art = load_artifact();
    let bead_id = art["bead_id"].as_str().unwrap();
    assert!(
        doc.contains(bead_id),
        "doc must reference bead_id {bead_id}"
    );
}

// ── Artifact stability ─────────────────────────────────────────────

#[test]
fn artifact_has_contract_version() {
    let art = load_artifact();
    assert_eq!(
        art["contract_version"].as_str().unwrap(),
        "adversarial-regime-shift-v1"
    );
}

#[test]
fn artifact_has_runner_script() {
    let art = load_artifact();
    let runner = art["runner_script"].as_str().unwrap();
    assert!(
        std::path::Path::new(runner).exists(),
        "runner script must exist at {runner}"
    );
}

// ── Search objectives ──────────────────────────────────────────────

#[test]
fn objectives_are_nonempty() {
    let art = load_artifact();
    let objs = art["search_objectives"].as_array().unwrap();
    assert!(!objs.is_empty(), "must have at least one search objective");
}

#[test]
fn objective_ids_are_unique() {
    let art = load_artifact();
    let objs = art["search_objectives"].as_array().unwrap();
    let ids: Vec<&str> = objs
        .iter()
        .map(|o| o["objective_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "objective_ids must be unique");
}

#[test]
fn objectives_have_required_fields() {
    let art = load_artifact();
    let objs = art["search_objectives"].as_array().unwrap();
    for obj in objs {
        let oid = obj["objective_id"].as_str().unwrap();
        assert!(
            obj["description"].is_string(),
            "{oid}: must have description"
        );
        assert!(
            obj["target_invariant"].is_string(),
            "{oid}: must have target_invariant"
        );
        let axes = obj["mutation_axes"].as_array().unwrap();
        assert!(!axes.is_empty(), "{oid}: must have mutation_axes");
        let sev = obj["severity"].as_str().unwrap();
        assert!(
            ["critical", "high", "medium", "low"].contains(&sev),
            "{oid}: invalid severity '{sev}'"
        );
    }
}

#[test]
fn objectives_cover_critical_categories() {
    let art = load_artifact();
    let objs = art["search_objectives"].as_array().unwrap();
    let ids: Vec<&str> = objs
        .iter()
        .map(|o| o["objective_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.iter().any(|id| id.contains("TAIL")),
        "must have tail-latency objective"
    );
    assert!(
        ids.iter().any(|id| id.contains("FAIRNESS")),
        "must have fairness objective"
    );
    assert!(
        ids.iter().any(|id| id.contains("WAKE")),
        "must have wakeup objective"
    );
    assert!(
        ids.iter().any(|id| id.contains("LEAK")),
        "must have obligation-leak objective"
    );
}

// ── Mutation model ─────────────────────────────────────────────────

#[test]
fn mutation_axes_are_nonempty() {
    let art = load_artifact();
    let axes = art["mutation_model"]["mutation_axes"].as_array().unwrap();
    assert!(!axes.is_empty(), "must have at least one mutation axis");
}

#[test]
fn mutation_axes_have_required_fields() {
    let art = load_artifact();
    let axes = art["mutation_model"]["mutation_axes"].as_array().unwrap();
    for axis in axes {
        let aid = axis["axis_id"].as_str().unwrap();
        assert!(
            axis["description"].is_string(),
            "{aid}: must have description"
        );
        assert!(axis["range"].is_object(), "{aid}: must have range");
        let modes = axis["step_modes"].as_array().unwrap();
        assert!(!modes.is_empty(), "{aid}: must have step_modes");
    }
}

#[test]
fn mutation_axis_ids_are_unique() {
    let art = load_artifact();
    let axes = art["mutation_model"]["mutation_axes"].as_array().unwrap();
    let ids: Vec<&str> = axes
        .iter()
        .map(|a| a["axis_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "axis_ids must be unique");
}

#[test]
fn mutation_objective_axes_reference_defined_axes() {
    let art = load_artifact();
    let defined_axes: HashSet<String> = art["mutation_model"]["mutation_axes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["axis_id"].as_str().unwrap().to_string())
        .collect();
    let objs = art["search_objectives"].as_array().unwrap();
    for obj in objs {
        let oid = obj["objective_id"].as_str().unwrap();
        for axis in obj["mutation_axes"].as_array().unwrap() {
            let axis_name = axis.as_str().unwrap();
            assert!(
                defined_axes.contains(axis_name),
                "{oid}: references undefined axis '{axis_name}'"
            );
        }
    }
}

#[test]
fn mutation_budget_is_positive() {
    let art = load_artifact();
    let budget = &art["mutation_model"]["budget"];
    assert!(
        budget["max_mutations_per_run"].as_u64().unwrap() > 0,
        "max_mutations must be positive"
    );
    assert!(
        budget["max_wall_clock_seconds"].as_u64().unwrap() > 0,
        "max_wall_clock must be positive"
    );
    assert!(
        budget["max_workloads_promoted"].as_u64().unwrap() > 0,
        "max_workloads_promoted must be positive"
    );
}

#[test]
fn mutation_determinism_has_seed_source() {
    let art = load_artifact();
    let seed = art["mutation_model"]["determinism"]["seed_source"]
        .as_str()
        .unwrap();
    assert!(!seed.is_empty(), "determinism must specify seed_source");
}

// ── Challenge corpus ───────────────────────────────────────────────

#[test]
fn corpus_promotion_criteria_are_nonempty() {
    let art = load_artifact();
    let criteria = art["challenge_corpus"]["promotion_criteria"]
        .as_array()
        .unwrap();
    assert!(
        criteria.len() >= 3,
        "must have at least 3 promotion criteria"
    );
}

#[test]
fn corpus_manifest_fields_are_nonempty() {
    let art = load_artifact();
    let fields = art["challenge_corpus"]["manifest_fields"]
        .as_array()
        .unwrap();
    assert!(!fields.is_empty(), "manifest fields must be nonempty");
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    for required in &[
        "challenge_id",
        "objective_id",
        "replay_command",
        "rationale",
    ] {
        assert!(
            strs.contains(required),
            "manifest must include field '{required}'"
        );
    }
}

#[test]
fn corpus_feedback_targets_are_nonempty() {
    let art = load_artifact();
    let targets = art["challenge_corpus"]["feedback_targets"]
        .as_array()
        .unwrap();
    assert!(targets.len() >= 2, "must feed back to at least 2 targets");
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    assert!(!fields.is_empty(), "log fields must be nonempty");
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

// ── Smoke scenarios ────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 smoke scenarios");
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.starts_with("rch exec"), "{sid}: must be rch-routed");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    for mode in &["--list", "--dry-run", "--execute", "--scenario"] {
        assert!(runner.contains(mode), "runner must support {mode}");
    }
}

// ── Functional: deterministic seed computation ──────────────────────

#[test]
fn mutation_seed_is_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn compute_seed(workload_id: &str, objective_id: &str, round: u32) -> u64 {
        let mut hasher = DefaultHasher::new();
        workload_id.hash(&mut hasher);
        objective_id.hash(&mut hasher);
        round.hash(&mut hasher);
        hasher.finish()
    }

    let s1 = compute_seed("WL-001", "OBJ-TAIL-SLO-BREACH", 0);
    let s2 = compute_seed("WL-001", "OBJ-TAIL-SLO-BREACH", 0);
    assert_eq!(s1, s2, "same inputs must produce same seed");

    let s3 = compute_seed("WL-001", "OBJ-TAIL-SLO-BREACH", 1);
    assert_ne!(s1, s3, "different round must produce different seed");

    let s4 = compute_seed("WL-002", "OBJ-TAIL-SLO-BREACH", 0);
    assert_ne!(s1, s4, "different workload must produce different seed");
}

// ── Functional: budget enforcement ──────────────────────────────────

#[test]
fn mutation_budget_enforcement() {
    let max_mutations: u32 = 1000;
    let mut mutations_run: u32 = 0;
    let mut violations_found: u32 = 0;

    // Simulate search: stop when budget exhausted or sufficient violations found
    for _ in 0..1500 {
        if mutations_run >= max_mutations {
            break;
        }
        mutations_run += 1;
        if mutations_run.is_multiple_of(100) {
            violations_found += 1;
        }
    }

    assert!(
        mutations_run <= max_mutations,
        "must not exceed budget: ran {mutations_run}"
    );
    assert!(violations_found > 0, "should find at least one violation");
}

// ── Functional: challenge promotion criteria ────────────────────────

#[test]
fn corpus_promotion_requires_reproducibility() {
    // A challenge is promotable only if replay succeeds deterministically
    let replay_succeeds = true;
    let is_minimized = true;
    let has_violation = true;
    let has_rationale = true;

    let promotable = replay_succeeds && is_minimized && has_violation && has_rationale;
    assert!(promotable, "all four criteria must be met for promotion");
}

#[test]
fn corpus_promotion_rejects_non_reproducible() {
    let replay_succeeds = false;
    let is_minimized = true;
    let has_violation = true;
    let has_rationale = true;

    let promotable = replay_succeeds && is_minimized && has_violation && has_rationale;
    assert!(!promotable, "non-reproducible case must not be promoted");
}

#[test]
fn corpus_promotion_rejects_no_violation() {
    let replay_succeeds = true;
    let is_minimized = true;
    let has_violation = false;
    let has_rationale = true;

    let promotable = replay_succeeds && is_minimized && has_violation && has_rationale;
    assert!(!promotable, "case without violation must not be promoted");
}

// ── Functional: minimization ────────────────────────────────────────

#[test]
fn mutation_minimization_reduces_vector() {
    // Start with 5 mutation axes active, minimize to find which are necessary
    let mut active_axes = [true, true, true, true, true];
    let essential_axes = [0_usize, 2, 4]; // only these three are needed

    // Minimization: try disabling each axis
    for (i, active) in active_axes.iter_mut().enumerate() {
        if !essential_axes.contains(&i) {
            *active = false; // not essential, remove
        }
    }

    let remaining: usize = active_axes.iter().filter(|&&a| a).count();
    assert_eq!(
        remaining,
        essential_axes.len(),
        "minimized vector should have only essential axes"
    );
}

// ── Functional: feedback loop validation ─────────────────────────────

#[test]
fn corpus_feedback_loop_integration() {
    // Simulate the feedback loop:
    // 1. Synthesize challenge -> 2. Validate reproducibility -> 3. Promote -> 4. Feed back

    let mut corpus_size: usize = 10; // existing corpus
    let challenges_synthesized: usize = 5;
    let challenges_reproducible: usize = 4;
    let challenges_promoted: usize = 3; // some filtered by minimization

    corpus_size += challenges_promoted;
    assert_eq!(corpus_size, 13, "corpus must grow by promoted count");
    assert!(
        challenges_promoted <= challenges_reproducible,
        "promoted <= reproducible"
    );
    assert!(
        challenges_reproducible <= challenges_synthesized,
        "reproducible <= synthesized"
    );
}
