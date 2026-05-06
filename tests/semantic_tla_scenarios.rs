//! TLA+ Scenario-Based Model Check Validation (SEM-12.4)
//!
//! Validates that the TLA+ scenario runner script exists and is well-formed,
//! and that the TLA+ spec defines the expected invariants and properties.
//! Actual TLC execution is deferred to CI (requires TLA+ toolchain).
//!
//! Bead: asupersync-3cddg.12.4

use std::path::Path;

fn load_tla_spec() -> String {
    std::fs::read_to_string("formal/tla/Asupersync.tla").expect("failed to load TLA+ spec")
}

fn load_tla_config() -> String {
    std::fs::read_to_string("formal/tla/Asupersync_MC.cfg").expect("failed to load TLA+ config")
}

fn load_runner_script() -> String {
    std::fs::read_to_string("scripts/run_tla_scenarios.sh")
        .expect("failed to load TLA+ scenario script")
}

// ─── Script infrastructure ───────────────────────────────────────

#[test]
fn tla_scenario_script_exists() {
    assert!(
        Path::new("scripts/run_tla_scenarios.sh").exists(),
        "TLA+ scenario runner script must exist"
    );
}

#[test]
fn tla_scenario_script_is_bash() {
    let script = load_runner_script();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "Script must use /usr/bin/env bash shebang"
    );
}

#[test]
fn tla_scenario_script_supports_scenarios() {
    let script = load_runner_script();

    let scenarios = ["minimal", "standard", "full"];
    for scenario in &scenarios {
        assert!(
            script.contains(scenario),
            "Script must support scenario: {scenario}"
        );
    }
}

#[test]
fn tla_scenario_script_supports_json_output() {
    let script = load_runner_script();

    assert!(script.contains("--json"), "Script must support --json flag");
    assert!(
        script.contains("scenario_report.json"),
        "Script must write JSON scenario report"
    );
}

#[test]
fn tla_scenario_script_report_schema() {
    let script = load_runner_script();

    let required_fields = [
        "tla-scenario-report-v1",
        "status",
        "tlc_available",
        "scenario",
        "invariants_checked",
        "invariants_passed",
        "invariants_violated",
        "violations",
        "states_found",
        "states_distinct",
    ];

    for field in &required_fields {
        assert!(
            script.contains(field),
            "Script report schema must include field: {field}"
        );
    }
}

#[test]
fn tla_scenario_script_graceful_skip() {
    let script = load_runner_script();

    assert!(
        script.contains("SKIP") && script.contains("TLC"),
        "Script must skip gracefully when TLC is unavailable"
    );
}

// ─── TLA+ spec structure ─────────────────────────────────────────

#[test]
fn tla_spec_defines_state_machines() {
    let spec = load_tla_spec();

    // TLA+ spec uses abbreviated names (ObStates, not ObligationStates)
    let state_sets = ["TaskStates", "RegionStates", "ObStates"];

    let expected_task_states = [
        "Spawned",
        "Running",
        "CancelRequested",
        "CancelMasked",
        "CancelAcknowledged",
        "Finalizing",
        "Completed",
    ];

    let expected_region_states = [
        "Open",
        "Closing",
        "ChildrenDone",
        "Finalizing",
        "Quiescent",
        "Closed",
    ];

    for state_set in &state_sets {
        assert!(
            spec.contains(state_set),
            "TLA+ spec must define state set: {state_set}"
        );
    }

    for state in &expected_task_states {
        assert!(
            spec.contains(&format!("\"{state}\"")),
            "TLA+ spec must define task state: {state}"
        );
    }

    for state in &expected_region_states {
        assert!(
            spec.contains(&format!("\"{state}\"")),
            "TLA+ spec must define region state: {state}"
        );
    }
}

#[test]
fn tla_spec_aligns_close_cancel_children_with_canonical_rules() {
    let spec = load_tla_spec();

    assert!(
        spec.contains(r"CloseCancelChildren(r) =="),
        "TLA+ spec must define CloseCancelChildren action"
    );
    assert!(
        spec.contains(r#"taskState[t] \in {"Spawned", "Running"}"#),
        "CloseCancelChildren must only re-request cancel for Spawned/Running tasks"
    );
    assert!(
        spec.contains(r"ELSE taskMask[t]"),
        "CloseCancelChildren must preserve existing mask depth for in-flight cancel states"
    );
}

#[test]
fn tla_spec_aligns_reserve_obligation_guards_with_canonical_rules() {
    let spec = load_tla_spec();

    assert!(
        spec.contains(r"ReserveObligation(o, t, r) =="),
        "TLA+ spec must define ReserveObligation action"
    );
    assert!(
        spec.contains(r#"taskState[t] \in {"Running", "CancelRequested", "CancelMasked"}"#),
        "ReserveObligation must allow Running/CancelRequested/CancelMasked holders"
    );
    assert!(
        spec.contains(r"taskRegion[t] = r"),
        "ReserveObligation must bind obligation region to holder task region"
    );
    assert!(
        spec.contains(r#"regionState[r] \in {"Open", "Closing"}"#),
        "ReserveObligation must allow Open/Closing region states"
    );
}

#[test]
fn tla_spec_defines_invariants() {
    let spec = load_tla_spec();

    let invariants = [
        "TypeInvariant",
        "WellFormedInvariant",
        "NoOrphanTasks",
        "NoLeakedObligations",
        "CloseImpliesQuiescent",
        "MaskBoundedInvariant",
        "MaskMonotoneInvariant",
        "CancelIdempotenceStructural",
        "AssumptionEnvelopeInvariant",
        "SafetyGuaranteesInvariant",
    ];

    let mut missing = Vec::new();
    for inv in &invariants {
        if !spec.contains(inv) {
            missing.push(*inv);
        }
    }

    assert!(
        missing.is_empty(),
        "TLA+ spec missing invariant definitions:\n{}",
        missing
            .iter()
            .map(|i| format!("  - {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn tla_spec_defines_liveness() {
    let spec = load_tla_spec();

    assert!(
        spec.contains("CancelTerminates") || spec.contains("Liveness") || spec.contains("TEMPORAL"),
        "TLA+ spec must define at least one liveness property"
    );
}

#[test]
fn tla_spec_splits_safety_guarantees_from_assumptions() {
    let spec = load_tla_spec();

    assert!(
        spec.contains("SafetyGuaranteesInvariant == Inv"),
        "TLA+ spec must explicitly alias safety guarantees"
    );
    assert!(
        spec.contains("AssumptionEnvelopeInvariant =="),
        "TLA+ spec must define explicit bounded assumption envelope"
    );
}

#[test]
fn tla_spec_declares_fairness_assumptions_for_liveness() {
    let spec = load_tla_spec();

    assert!(
        spec.contains("LivenessFairnessAssumptions"),
        "TLA+ spec must name fairness assumptions for liveness checks"
    );
    assert!(
        spec.contains("LiveSpec"),
        "TLA+ spec must define LiveSpec with fairness assumptions"
    );
}

#[test]
fn tla_spec_references_fos() {
    let spec = load_tla_spec();

    // Should cross-reference Lean and Rust implementations
    assert!(
        spec.contains("formal/lean") || spec.contains("Asupersync.lean"),
        "TLA+ spec should cross-reference Lean formalization"
    );
    assert!(
        spec.contains("src/record") || spec.contains("task.rs") || spec.contains("region.rs"),
        "TLA+ spec should cross-reference Rust implementation"
    );
}

#[test]
fn tla_config_exists_and_valid() {
    let config = load_tla_config();

    // Config must specify the spec
    assert!(
        config.contains("SPECIFICATION") || config.contains("INIT") || config.contains("NEXT"),
        "TLA+ config must specify SPECIFICATION or INIT/NEXT"
    );
    assert!(
        config.contains("INVARIANT") || config.contains("PROPERTY"),
        "TLA+ config must specify at least one INVARIANT or PROPERTY"
    );
    assert!(
        config.contains("AssumptionEnvelopeInvariant"),
        "TLA+ config must check bounded assumption envelope explicitly"
    );
    assert!(
        config.contains("SPECIFICATION") && config.contains("Spec"),
        "TLA+ safety config must use Spec as specification"
    );
}

// ─── Scenario parameter validation ───────────────────────────────

#[test]
fn tla_spec_parameterized_by_constants() {
    let spec = load_tla_spec();

    let required_constants = ["TaskIds", "RegionIds", "RootRegion", "MAX_MASK"];

    let mut missing = Vec::new();
    for constant in &required_constants {
        if !spec.contains(constant) {
            missing.push(*constant);
        }
    }

    assert!(
        missing.is_empty(),
        "TLA+ spec missing parameterized constants:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
