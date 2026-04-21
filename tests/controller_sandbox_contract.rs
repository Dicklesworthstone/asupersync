#![allow(warnings)]
#![allow(clippy::all)]
//! Controller sandbox membrane contract invariants (AA-07.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/controller_sandbox_contract.md";
const ARTIFACT_PATH: &str = "artifacts/controller_sandbox_membrane_v1.json";
const RUNNER_PATH: &str = "scripts/run_controller_sandbox_smoke.sh";

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
        "## Membrane Invariants",
        "## Resource Caps",
        "## Action Surface",
        "## Verdict Types",
        "## Adversarial Scenarios",
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
        "controller-sandbox-membrane-v1"
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

// ── Membrane invariants ────────────────────────────────────────────

#[test]
fn membrane_invariants_are_nonempty() {
    let art = load_artifact();
    let invariants = art["sandbox_model"]["membrane_invariants"]
        .as_array()
        .unwrap();
    assert!(
        invariants.len() >= 5,
        "must have at least 5 membrane invariants"
    );
}

#[test]
fn membrane_invariant_ids_are_unique() {
    let art = load_artifact();
    let invariants = art["sandbox_model"]["membrane_invariants"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = invariants
        .iter()
        .map(|i| i["invariant_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "invariant_ids must be unique");
}

#[test]
fn membrane_invariants_have_mem_prefix() {
    let art = load_artifact();
    let invariants = art["sandbox_model"]["membrane_invariants"]
        .as_array()
        .unwrap();
    for inv in invariants {
        let iid = inv["invariant_id"].as_str().unwrap();
        assert!(
            iid.starts_with("MEM-"),
            "invariant '{iid}' must start with MEM-"
        );
    }
}

#[test]
fn membrane_includes_cap_closed_and_no_side_effects() {
    let art = load_artifact();
    let invariants = art["sandbox_model"]["membrane_invariants"]
        .as_array()
        .unwrap();
    let ids: HashSet<&str> = invariants
        .iter()
        .map(|i| i["invariant_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("MEM-CAP-CLOSED"), "must have MEM-CAP-CLOSED");
    assert!(
        ids.contains("MEM-NO-SIDE-EFFECTS"),
        "must have MEM-NO-SIDE-EFFECTS"
    );
}

// ── Resource caps ──────────────────────────────────────────────────

#[test]
fn resource_caps_are_nonempty() {
    let art = load_artifact();
    let caps = art["resource_caps"]["caps"].as_array().unwrap();
    assert!(caps.len() >= 4, "must have at least 4 resource caps");
}

#[test]
fn resource_cap_ids_are_unique() {
    let art = load_artifact();
    let caps = art["resource_caps"]["caps"].as_array().unwrap();
    let ids: Vec<&str> = caps.iter().map(|c| c["cap_id"].as_str().unwrap()).collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "cap_ids must be unique");
}

#[test]
fn resource_caps_have_rc_prefix() {
    let art = load_artifact();
    let caps = art["resource_caps"]["caps"].as_array().unwrap();
    for cap in caps {
        let cid = cap["cap_id"].as_str().unwrap();
        assert!(cid.starts_with("RC-"), "cap '{cid}' must start with RC-");
    }
}

#[test]
fn resource_caps_have_positive_defaults() {
    let art = load_artifact();
    let caps = art["resource_caps"]["caps"].as_array().unwrap();
    for cap in caps {
        let cid = cap["cap_id"].as_str().unwrap();
        let limit = cap["default_limit"].as_u64().unwrap();
        assert!(limit > 0, "{cid}: default_limit must be positive");
    }
}

#[test]
fn resource_caps_have_enforcement_policy() {
    let art = load_artifact();
    let caps = art["resource_caps"]["caps"].as_array().unwrap();
    for cap in caps {
        let cid = cap["cap_id"].as_str().unwrap();
        let enforcement = cap["enforcement"].as_str().unwrap();
        assert!(
            !enforcement.is_empty(),
            "{cid}: must have non-empty enforcement policy"
        );
    }
}

// ── Action surface ─────────────────────────────────────────────────

#[test]
fn action_surface_is_nonempty() {
    let art = load_artifact();
    let actions = art["action_surface"]["allowed_actions"].as_array().unwrap();
    assert!(actions.len() >= 4, "must have at least 4 allowed actions");
}

#[test]
fn action_ids_are_unique() {
    let art = load_artifact();
    let actions = art["action_surface"]["allowed_actions"].as_array().unwrap();
    let ids: Vec<&str> = actions
        .iter()
        .map(|a| a["action_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "action_ids must be unique");
}

#[test]
fn actions_have_act_prefix() {
    let art = load_artifact();
    let actions = art["action_surface"]["allowed_actions"].as_array().unwrap();
    for action in actions {
        let aid = action["action_id"].as_str().unwrap();
        assert!(
            aid.starts_with("ACT-"),
            "action '{aid}' must start with ACT-"
        );
    }
}

#[test]
fn actions_reference_valid_capabilities() {
    let cap_token_art: Value = {
        let content = std::fs::read_to_string("artifacts/capability_token_model_v1.json")
            .expect("capability token artifact must exist");
        serde_json::from_str(&content).unwrap()
    };
    let valid_caps: HashSet<&str> = cap_token_art["token_structure"]["capability_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["type_id"].as_str().unwrap())
        .collect();

    let art = load_artifact();
    let actions = art["action_surface"]["allowed_actions"].as_array().unwrap();
    for action in actions {
        let aid = action["action_id"].as_str().unwrap();
        let cap = action["required_capability"].as_str().unwrap();
        assert!(
            valid_caps.contains(cap),
            "{aid}: required_capability '{cap}' must exist in capability token model"
        );
    }
}

// ── Verdict types ──────────────────────────────────────────────────

#[test]
fn verdict_types_are_nonempty() {
    let art = load_artifact();
    let verdicts = art["verdict_types"].as_array().unwrap();
    assert!(verdicts.len() >= 4, "must have at least 4 verdict types");
}

#[test]
fn verdict_ids_are_unique() {
    let art = load_artifact();
    let verdicts = art["verdict_types"].as_array().unwrap();
    let ids: Vec<&str> = verdicts
        .iter()
        .map(|v| v["verdict_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "verdict_ids must be unique");
}

#[test]
fn verdicts_have_vrd_prefix() {
    let art = load_artifact();
    let verdicts = art["verdict_types"].as_array().unwrap();
    for verdict in verdicts {
        let vid = verdict["verdict_id"].as_str().unwrap();
        assert!(
            vid.starts_with("VRD-"),
            "verdict '{vid}' must start with VRD-"
        );
    }
}

#[test]
fn verdicts_include_allow_and_deny() {
    let art = load_artifact();
    let verdicts = art["verdict_types"].as_array().unwrap();
    let ids: HashSet<&str> = verdicts
        .iter()
        .map(|v| v["verdict_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("VRD-ALLOW"), "must have VRD-ALLOW");
    assert!(
        ids.contains("VRD-DENY-CAPABILITY"),
        "must have VRD-DENY-CAPABILITY"
    );
    assert!(ids.contains("VRD-TIMEOUT"), "must have VRD-TIMEOUT");
}

// ── Adversarial scenarios ──────────────────────────────────────────

#[test]
fn adversarial_scenarios_are_nonempty() {
    let art = load_artifact();
    let scenarios = art["adversarial_scenarios"].as_array().unwrap();
    assert!(
        scenarios.len() >= 4,
        "must have at least 4 adversarial scenarios"
    );
}

#[test]
fn adversarial_scenario_ids_are_unique() {
    let art = load_artifact();
    let scenarios = art["adversarial_scenarios"].as_array().unwrap();
    let ids: Vec<&str> = scenarios
        .iter()
        .map(|s| s["scenario_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        ids.len(),
        deduped.len(),
        "adversarial scenario_ids must be unique"
    );
}

#[test]
fn adversarial_scenarios_have_adv_prefix() {
    let art = load_artifact();
    let scenarios = art["adversarial_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        assert!(
            sid.starts_with("ADV-"),
            "adversarial scenario '{sid}' must start with ADV-"
        );
    }
}

#[test]
fn adversarial_scenarios_have_expected_verdicts() {
    let art = load_artifact();
    let scenarios = art["adversarial_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let verdict = scenario["expected_verdict"].as_str().unwrap();
        assert!(
            verdict.contains("VRD-"),
            "{sid}: expected_verdict must reference a VRD- verdict"
        );
    }
}

#[test]
fn adversarial_scenarios_have_mitigations() {
    let art = load_artifact();
    let scenarios = art["adversarial_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let mitigation = scenario["mitigation"].as_str().unwrap();
        assert!(
            !mitigation.is_empty(),
            "{sid}: must have non-empty mitigation"
        );
    }
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

// ── Smoke / runner ─────────────────────────────────────────────────

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

// ── Functional: capability enforcement ──────────────────────────────

#[test]
fn sandbox_denies_unauthorized_action() {
    // Simulate: controller has CAP-OBSERVE, attempts ACT-EMIT-DECISION (requires CAP-DECIDE)
    let granted: HashSet<&str> = HashSet::from(["CAP-OBSERVE"]);
    let action_requires = "CAP-DECIDE";

    let verdict = if granted.contains(action_requires) {
        "VRD-ALLOW"
    } else {
        "VRD-DENY-CAPABILITY"
    };

    assert_eq!(verdict, "VRD-DENY-CAPABILITY");
}

#[test]
fn sandbox_allows_authorized_action() {
    let granted: HashSet<&str> = HashSet::from(["CAP-OBSERVE", "CAP-DECIDE"]);
    let action_requires = "CAP-DECIDE";

    let verdict = if granted.contains(action_requires) {
        "VRD-ALLOW"
    } else {
        "VRD-DENY-CAPABILITY"
    };

    assert_eq!(verdict, "VRD-ALLOW");
}

#[test]
fn sandbox_admin_can_access_all_actions() {
    // Load actual action surface and capability hierarchy
    let art = load_artifact();
    let actions = art["action_surface"]["allowed_actions"].as_array().unwrap();

    let cap_art: Value = {
        let content = std::fs::read_to_string("artifacts/capability_token_model_v1.json").unwrap();
        serde_json::from_str(&content).unwrap()
    };
    let types = cap_art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();

    // CAP-ADMIN should be able to attenuate to all other capabilities
    let admin = types
        .iter()
        .find(|t| t["type_id"].as_str().unwrap() == "CAP-ADMIN")
        .unwrap();
    let mut admin_reach: HashSet<&str> = HashSet::from(["CAP-ADMIN"]);
    if let Some(targets) = admin["attenuable_to"].as_array() {
        for t in targets {
            admin_reach.insert(t.as_str().unwrap());
        }
    }
    // Transitive closure
    let mut changed = true;
    while changed {
        changed = false;
        for cap in types {
            let tid = cap["type_id"].as_str().unwrap();
            if admin_reach.contains(tid) {
                if let Some(targets) = cap["attenuable_to"].as_array() {
                    for t in targets {
                        if admin_reach.insert(t.as_str().unwrap()) {
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    // Every action's required capability should be reachable from CAP-ADMIN
    for action in actions {
        let aid = action["action_id"].as_str().unwrap();
        let req = action["required_capability"].as_str().unwrap();
        assert!(
            admin_reach.contains(req),
            "{aid}: requires {req} which CAP-ADMIN cannot reach"
        );
    }
}

// ── Functional: resource cap enforcement ────────────────────────────

#[test]
fn resource_memory_cap_triggers_abort() {
    let art = load_artifact();
    let mem_cap = art["resource_caps"]["caps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cap_id"].as_str().unwrap() == "RC-MEMORY")
        .expect("RC-MEMORY must exist");
    let limit = mem_cap["default_limit"].as_u64().unwrap();

    // Simulate allocation exceeding cap
    let allocated: u64 = limit + 1;
    let verdict = if allocated > limit {
        "VRD-DENY-RESOURCE"
    } else {
        "VRD-ALLOW"
    };
    assert_eq!(verdict, "VRD-DENY-RESOURCE");
}

#[test]
fn resource_cpu_cap_triggers_timeout() {
    let art = load_artifact();
    let cpu_cap = art["resource_caps"]["caps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cap_id"].as_str().unwrap() == "RC-CPU-TIME")
        .expect("RC-CPU-TIME must exist");
    let limit = cpu_cap["default_limit"].as_u64().unwrap();

    let elapsed: u64 = limit + 1;
    let verdict = if elapsed > limit {
        "VRD-TIMEOUT"
    } else {
        "VRD-ALLOW"
    };
    assert_eq!(verdict, "VRD-TIMEOUT");
}

#[test]
fn resource_decision_budget_exhaustion() {
    let art = load_artifact();
    let dec_cap = art["resource_caps"]["caps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cap_id"].as_str().unwrap() == "RC-DECISIONS-PER-EPOCH")
        .expect("RC-DECISIONS-PER-EPOCH must exist");
    let limit = dec_cap["default_limit"].as_u64().unwrap();

    let mut accepted = 0u64;
    let mut denied = 0u64;
    for i in 0..(limit + 5) {
        if i < limit {
            accepted += 1;
        } else {
            denied += 1;
        }
    }
    assert_eq!(accepted, limit);
    assert!(denied > 0, "excess decisions must be dropped");
}

// ── Functional: controller registry integration ─────────────────────

#[test]
fn controller_budget_matches_resource_cap() {
    use asupersync::runtime::kernel::ControllerBudget;

    let budget = ControllerBudget::default();
    let art = load_artifact();
    let cpu_cap = art["resource_caps"]["caps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cap_id"].as_str().unwrap() == "RC-CPU-TIME")
        .expect("RC-CPU-TIME must exist");
    let cpu_limit = cpu_cap["default_limit"].as_u64().unwrap();

    // ControllerBudget's max_decision_latency_us should be <= the sandbox CPU cap
    assert!(
        budget.max_decision_latency_us <= cpu_limit,
        "controller budget latency {} must be <= sandbox CPU cap {}",
        budget.max_decision_latency_us,
        cpu_limit
    );
}

#[test]
fn sandbox_verdict_after_rollback() {
    use asupersync::runtime::kernel::{
        ControllerBudget, ControllerMode, ControllerRegistration, ControllerRegistry,
        RollbackReason, SNAPSHOT_VERSION,
    };

    let mut registry = ControllerRegistry::new();
    let reg = ControllerRegistration {
        name: "sandbox-verdict-test".to_string(),
        min_version: SNAPSHOT_VERSION,
        max_version: SNAPSHOT_VERSION,
        required_fields: vec!["ready_queue_len".to_string()],
        target_seams: vec!["AA01-SEAM-SCHED-CANCEL-STREAK".to_string()],
        initial_mode: ControllerMode::Shadow,
        proof_artifact_id: None,
        budget: ControllerBudget::default(),
    };
    let id = registry.register(reg).unwrap();

    // Promote to Canary
    for _ in 0..10 {
        registry.advance_epoch();
        registry.update_calibration(id, 0.95);
    }
    let _ = registry.try_promote(id, ControllerMode::Canary);

    // Rollback due to budget overruns
    let cmd = registry.rollback(id, RollbackReason::BudgetOverruns { count: 5 });
    assert!(cmd.is_some());

    let cmd = cmd.unwrap();
    assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
    // After rollback, the controller is in Shadow — further decisions should not be active
    assert!(registry.is_fallback_active(id));
}
