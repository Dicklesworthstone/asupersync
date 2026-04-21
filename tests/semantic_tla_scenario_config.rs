#![allow(clippy::all)]
//! TLA+ Bounded Model-Check Scenario Configuration Validation (SEM-07.4)
//!
//! Validates that the scenario configuration document exists, defines
//! bounded scenarios with reproducible parameters, maps invariants to
//! canonical rule IDs, and documents assumption envelope.
//!
//! Bead: asupersync-3cddg.7.4

use std::path::Path;

fn load_config() -> String {
    std::fs::read_to_string("docs/semantic_tla_scenario_config.md")
        .expect("failed to load TLA scenario config")
}

fn load_mc_cfg() -> String {
    std::fs::read_to_string("formal/tla/Asupersync_MC.cfg").expect("failed to load TLC config file")
}

// ─── Document infrastructure ──────────────────────────────────────

#[test]
fn config_exists() {
    assert!(
        Path::new("docs/semantic_tla_scenario_config.md").exists(),
        "TLA scenario config document must exist"
    );
}

#[test]
fn config_references_bead() {
    let config = load_config();
    assert!(
        config.contains("asupersync-3cddg.7.4"),
        "Config must reference its own bead ID"
    );
}

// ─── Model overview ───────────────────────────────────────────────

#[test]
fn config_references_spec_file() {
    let config = load_config();
    assert!(
        config.contains("formal/tla/Asupersync.tla"),
        "Must reference the TLA+ spec file"
    );
}

#[test]
fn config_references_mc_cfg() {
    let config = load_config();
    assert!(
        config.contains("Asupersync_MC.cfg"),
        "Must reference the TLC config file"
    );
}

#[test]
fn config_references_runner_script() {
    let config = load_config();
    assert!(
        config.contains("run_model_check.sh"),
        "Must reference model check runner script"
    );
}

#[test]
fn config_documents_state_machines() {
    let config = load_config();
    assert!(
        config.contains("Task lifecycle"),
        "Must document task lifecycle state machine"
    );
    assert!(
        config.contains("Region lifecycle"),
        "Must document region lifecycle state machine"
    );
    assert!(
        config.contains("Obligation lifecycle"),
        "Must document obligation lifecycle state machine"
    );
}

// ─── Scenario definitions ─────────────────────────────────────────

#[test]
fn config_defines_multiple_scenarios() {
    let config = load_config();
    let scenarios = ["S1", "S2", "S3", "S4", "S5", "S6"];
    let mut missing = Vec::new();
    for s in &scenarios {
        if !config.contains(s) {
            missing.push(*s);
        }
    }
    assert!(
        missing.is_empty(),
        "Config missing scenario definitions:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn config_scenarios_have_parameters() {
    let config = load_config();
    let params = [
        "TaskIds",
        "RegionIds",
        "ObligationIds",
        "RootRegion",
        "MAX_MASK",
    ];
    let mut missing = Vec::new();
    for p in &params {
        if !config.contains(p) {
            missing.push(*p);
        }
    }
    assert!(
        missing.is_empty(),
        "Config missing parameter definitions:\n{}",
        missing
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn config_scenarios_have_expected_outcomes() {
    let config = load_config();
    assert!(
        config.contains("Expected outcome"),
        "Scenarios must document expected outcomes"
    );
    assert!(
        config.contains("PASS"),
        "Expected outcomes must indicate PASS status"
    );
    assert!(
        config.contains("0 violations"),
        "Expected outcomes must state zero violations"
    );
}

#[test]
fn config_scenarios_have_reproduction_commands() {
    let config = load_config();
    assert!(
        config.contains("Reproduction") || config.contains("reproduction"),
        "Scenarios must include reproduction commands"
    );
    assert!(
        config.contains("run_model_check.sh"),
        "Reproduction must reference model check script"
    );
}

// ─── Invariant mapping ────────────────────────────────────────────

#[test]
fn config_maps_invariants_to_rules() {
    let config = load_config();
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
    ];
    let mut missing = Vec::new();
    for inv in &invariants {
        if !config.contains(inv) {
            missing.push(*inv);
        }
    }
    assert!(
        missing.is_empty(),
        "Config missing invariant references:\n{}",
        missing
            .iter()
            .map(|i| format!("  - {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn config_maps_canonical_rule_ids() {
    let config = load_config();
    let rule_ids = ["#5", "#11", "#12", "#17", "#20", "#27", "#34"];
    let mut missing = Vec::new();
    for id in &rule_ids {
        if !config.contains(id) {
            missing.push(*id);
        }
    }
    assert!(
        missing.is_empty(),
        "Config missing canonical rule ID mappings:\n{}",
        missing
            .iter()
            .map(|id| format!("  - {id}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn config_documents_liveness_property() {
    let config = load_config();
    assert!(
        config.contains("CancelTerminates"),
        "Must document CancelTerminates liveness property"
    );
    assert!(
        config.contains("LiveSpec"),
        "Must document LiveSpec for liveness checking"
    );
}

// ─── Assumption envelope ──────────────────────────────────────────

#[test]
fn config_documents_assumption_envelope() {
    let config = load_config();
    assert!(
        config.contains("Assumption Envelope") || config.contains("assumption envelope"),
        "Must document assumption envelope"
    );
}

#[test]
fn config_lists_bounded_assumptions() {
    let config = load_config();
    assert!(
        config.contains("Finite task set"),
        "Must document finite task assumption"
    );
    assert!(
        config.contains("Mask depth bounded"),
        "Must document mask depth bound assumption"
    );
}

// ─── ADR cross-references ─────────────────────────────────────────

#[test]
fn config_references_adr_decisions() {
    let config = load_config();
    let adrs = ["ADR-003", "ADR-004", "ADR-005", "ADR-007", "ADR-008"];
    let mut missing = Vec::new();
    for adr in &adrs {
        if !config.contains(adr) {
            missing.push(*adr);
        }
    }
    assert!(
        missing.is_empty(),
        "Config missing ADR references:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Reproduction guide ───────────────────────────────────────────

#[test]
fn config_has_reproduction_guide() {
    let config = load_config();
    assert!(
        config.contains("Reproduction Guide") || config.contains("reproduction guide"),
        "Must include reproduction guide"
    );
}

#[test]
fn config_documents_output_validation() {
    let config = load_config();
    assert!(
        config.contains("result.json"),
        "Must reference result.json output validation"
    );
}

#[test]
fn config_has_failure_diagnosis() {
    let config = load_config();
    assert!(
        config.contains("Failure Diagnosis") || config.contains("failure diagnosis"),
        "Must include failure diagnosis section"
    );
    assert!(
        config.contains("semantic_failure_replay_cookbook.md"),
        "Must reference failure-replay cookbook for TLA failures"
    );
}

// ─── Coverage matrix ──────────────────────────────────────────────

#[test]
fn config_has_coverage_matrix() {
    let config = load_config();
    assert!(
        config.contains("Scenario Coverage Matrix") || config.contains("scenario coverage"),
        "Must include scenario-to-rule coverage matrix"
    );
}

// ─── MC config file alignment ─────────────────────────────────────

#[test]
fn mc_cfg_matches_s1_parameters() {
    let cfg = load_mc_cfg();
    assert!(
        cfg.contains("TaskIds = {1, 2}"),
        "MC cfg must define TaskIds matching S1"
    );
    assert!(
        cfg.contains("RegionIds = {1, 2}"),
        "MC cfg must define RegionIds matching S1"
    );
    assert!(
        cfg.contains("ObligationIds = {1}"),
        "MC cfg must define ObligationIds matching S1"
    );
    assert!(
        cfg.contains("RootRegion = 1"),
        "MC cfg must define RootRegion matching S1"
    );
    assert!(
        cfg.contains("MAX_MASK = 2"),
        "MC cfg must define MAX_MASK matching S1"
    );
}

#[test]
fn mc_cfg_checks_invariants() {
    let cfg = load_mc_cfg();
    assert!(cfg.contains("INVARIANT"), "MC cfg must declare invariants");
    assert!(
        cfg.contains("SPECIFICATION"),
        "MC cfg must declare specification"
    );
}
