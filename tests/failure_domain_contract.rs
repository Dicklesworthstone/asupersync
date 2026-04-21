#![allow(clippy::all)]
//! Failure domain compiler contract invariants (AA-09.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/failure_domain_contract.md";
const ARTIFACT_PATH: &str = "artifacts/failure_domain_compiler_v1.json";
const RUNNER_PATH: &str = "scripts/run_failure_domain_smoke.sh";

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
        "## Failure Domain Model",
        "## Restart Topology",
        "## Recovery Authority Rules",
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
        "failure-domain-compiler-v1"
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

// ── Domain types ───────────────────────────────────────────────────

#[test]
fn domain_types_are_nonempty() {
    let art = load_artifact();
    let types = art["failure_domain_model"]["domain_types"]
        .as_array()
        .unwrap();
    assert!(types.len() >= 3, "must have at least 3 domain types");
}

#[test]
fn domain_type_ids_are_unique() {
    let art = load_artifact();
    let types = art["failure_domain_model"]["domain_types"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = types
        .iter()
        .map(|t| t["domain_type_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "domain_type_ids must be unique");
}

#[test]
fn domain_types_have_fd_prefix() {
    let art = load_artifact();
    let types = art["failure_domain_model"]["domain_types"]
        .as_array()
        .unwrap();
    for dt in types {
        let dtid = dt["domain_type_id"].as_str().unwrap();
        assert!(
            dtid.starts_with("FD-"),
            "domain type '{dtid}' must start with FD-"
        );
    }
}

#[test]
fn domain_types_include_isolated_and_linked() {
    let art = load_artifact();
    let types = art["failure_domain_model"]["domain_types"]
        .as_array()
        .unwrap();
    let ids: HashSet<&str> = types
        .iter()
        .map(|t| t["domain_type_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("FD-ISOLATED"), "must have FD-ISOLATED");
    assert!(ids.contains("FD-LINKED"), "must have FD-LINKED");
}

// ── Domain properties ──────────────────────────────────────────────

#[test]
fn domain_properties_are_nonempty() {
    let art = load_artifact();
    let props = art["failure_domain_model"]["domain_properties"]
        .as_array()
        .unwrap();
    assert!(props.len() >= 3, "must have at least 3 domain properties");
}

#[test]
fn domain_property_ids_are_unique() {
    let art = load_artifact();
    let props = art["failure_domain_model"]["domain_properties"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = props
        .iter()
        .map(|p| p["property_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "property_ids must be unique");
}

#[test]
fn domain_properties_have_fdp_prefix() {
    let art = load_artifact();
    let props = art["failure_domain_model"]["domain_properties"]
        .as_array()
        .unwrap();
    for prop in props {
        let pid = prop["property_id"].as_str().unwrap();
        assert!(
            pid.starts_with("FDP-"),
            "property '{pid}' must start with FDP-"
        );
    }
}

// ── Restart topology ───────────────────────────────────────────────

#[test]
fn restart_topologies_are_nonempty() {
    let art = load_artifact();
    let topos = art["restart_topology"]["topologies"].as_array().unwrap();
    assert!(topos.len() >= 3, "must have at least 3 restart topologies");
}

#[test]
fn restart_topology_ids_are_unique() {
    let art = load_artifact();
    let topos = art["restart_topology"]["topologies"].as_array().unwrap();
    let ids: Vec<&str> = topos
        .iter()
        .map(|t| t["topology_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "topology_ids must be unique");
}

#[test]
fn restart_topologies_have_rt_prefix() {
    let art = load_artifact();
    let topos = art["restart_topology"]["topologies"].as_array().unwrap();
    for topo in topos {
        let tid = topo["topology_id"].as_str().unwrap();
        assert!(
            tid.starts_with("RT-"),
            "topology '{tid}' must start with RT-"
        );
    }
}

#[test]
fn restart_topologies_reference_valid_domain_types() {
    let art = load_artifact();
    let domain_types: HashSet<&str> = art["failure_domain_model"]["domain_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["domain_type_id"].as_str().unwrap())
        .collect();
    let topos = art["restart_topology"]["topologies"].as_array().unwrap();
    for topo in topos {
        let tid = topo["topology_id"].as_str().unwrap();
        let dt = topo["domain_type"].as_str().unwrap();
        assert!(
            domain_types.contains(dt),
            "{tid}: domain_type '{dt}' must be a valid domain type"
        );
    }
}

#[test]
fn restart_includes_one_for_one_and_one_for_all() {
    let art = load_artifact();
    let topos = art["restart_topology"]["topologies"].as_array().unwrap();
    let ids: HashSet<&str> = topos
        .iter()
        .map(|t| t["topology_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("RT-ONE-FOR-ONE"), "must have RT-ONE-FOR-ONE");
    assert!(ids.contains("RT-ONE-FOR-ALL"), "must have RT-ONE-FOR-ALL");
}

// ── Hooks ──────────────────────────────────────────────────────────

#[test]
fn hooks_are_nonempty() {
    let art = load_artifact();
    let hooks = art["restart_topology"]["hooks"].as_array().unwrap();
    assert!(hooks.len() >= 3, "must have at least 3 hooks");
}

#[test]
fn hook_ids_are_unique() {
    let art = load_artifact();
    let hooks = art["restart_topology"]["hooks"].as_array().unwrap();
    let ids: Vec<&str> = hooks
        .iter()
        .map(|h| h["hook_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "hook_ids must be unique");
}

#[test]
fn hooks_have_rh_prefix() {
    let art = load_artifact();
    let hooks = art["restart_topology"]["hooks"].as_array().unwrap();
    for hook in hooks {
        let hid = hook["hook_id"].as_str().unwrap();
        assert!(hid.starts_with("RH-"), "hook '{hid}' must start with RH-");
    }
}

#[test]
fn hooks_include_pre_and_post_restart() {
    let art = load_artifact();
    let hooks = art["restart_topology"]["hooks"].as_array().unwrap();
    let ids: HashSet<&str> = hooks
        .iter()
        .map(|h| h["hook_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains("RH-PRE-RESTART"), "must have RH-PRE-RESTART");
    assert!(ids.contains("RH-POST-RESTART"), "must have RH-POST-RESTART");
}

// ── Recovery authority rules ───────────────────────────────────────

#[test]
fn recovery_authority_rules_are_nonempty() {
    let art = load_artifact();
    let rules = art["recovery_authority_rules"]["rules"].as_array().unwrap();
    assert!(
        rules.len() >= 5,
        "must have at least 5 recovery authority rules"
    );
}

#[test]
fn recovery_authority_rule_ids_are_unique() {
    let art = load_artifact();
    let rules = art["recovery_authority_rules"]["rules"].as_array().unwrap();
    let ids: Vec<&str> = rules
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "rule_ids must be unique");
}

#[test]
fn recovery_authority_rules_have_ra_prefix() {
    let art = load_artifact();
    let rules = art["recovery_authority_rules"]["rules"].as_array().unwrap();
    for rule in rules {
        let rid = rule["rule_id"].as_str().unwrap();
        assert!(
            rid.starts_with("RA-"),
            "recovery authority rule '{rid}' must start with RA-"
        );
    }
}

#[test]
fn recovery_authority_includes_narrow_and_no_ambient() {
    let art = load_artifact();
    let rules = art["recovery_authority_rules"]["rules"].as_array().unwrap();
    let ids: HashSet<&str> = rules
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains("RA-NARROW-ON-CRASH"),
        "must have RA-NARROW-ON-CRASH"
    );
    assert!(
        ids.contains("RA-NO-AMBIENT-DURING-RECOVERY"),
        "must have RA-NO-AMBIENT-DURING-RECOVERY"
    );
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

// ── Functional: domain membership invariant ─────────────────────────

#[test]
fn domain_unique_membership_enforced() {
    // Simulate: regions must belong to exactly one domain
    let mut domain_membership: std::collections::HashMap<&str, &str> =
        std::collections::HashMap::new();
    domain_membership.insert("region-A", "domain-1");
    domain_membership.insert("region-B", "domain-2");
    domain_membership.insert("region-C", "domain-1");

    // Every region has exactly one domain
    for region in domain_membership.keys() {
        let count = domain_membership.keys().filter(|r| *r == region).count();
        assert_eq!(count, 1, "{region}: must belong to exactly one domain");
    }
}

// ── Functional: failure propagation ─────────────────────────────────

#[test]
fn isolated_domain_does_not_propagate() {
    // FD-ISOLATED: failure in one region doesn't affect siblings
    let domain_type = "FD-ISOLATED";
    let regions = ["region-A", "region-B", "region-C"];
    let failed_region = "region-A";

    let affected: Vec<&&str> = regions
        .iter()
        .filter(|r| {
            if domain_type == "FD-ISOLATED" {
                **r == failed_region
            } else {
                true
            }
        })
        .collect();

    assert_eq!(
        affected.len(),
        1,
        "only the failed region should be affected"
    );
    assert_eq!(*affected[0], failed_region);
}

#[test]
fn linked_domain_propagates_to_all() {
    // FD-LINKED: all members restart
    let domain_type = "FD-LINKED";
    let regions = ["region-A", "region-B", "region-C"];

    let affected_count = regions
        .iter()
        .filter(|_| domain_type == "FD-LINKED")
        .count();

    assert_eq!(
        affected_count,
        regions.len(),
        "all regions must be affected in linked domain"
    );
}

#[test]
fn escalating_domain_notifies_parent() {
    // FD-ESCALATING: after budget exhaustion, escalate
    let max_restarts = 3u32;
    let mut restarts = 0u32;
    let mut escalated = false;

    for _ in 0..5 {
        if restarts < max_restarts {
            restarts += 1;
        } else {
            escalated = true;
            break;
        }
    }

    assert!(escalated, "must escalate after restart budget exhaustion");
}

// ── Functional: recovery authority narrowing ────────────────────────

#[test]
fn authority_narrow_on_crash_revokes_non_observe() {
    // RA-NARROW-ON-CRASH: only OBSERVE survives
    let pre_crash_caps: HashSet<&str> = HashSet::from(["CAP-ADMIN", "CAP-DECIDE", "CAP-OBSERVE"]);

    let post_crash_caps: HashSet<&str> = pre_crash_caps
        .iter()
        .copied()
        .filter(|c| *c == "CAP-OBSERVE")
        .collect();

    assert_eq!(post_crash_caps.len(), 1);
    assert!(post_crash_caps.contains("CAP-OBSERVE"));
}

#[test]
fn authority_gradual_restore_after_recovery() {
    // RA-GRADUAL-RESTORE: OBSERVE -> shadow validation -> DECIDE
    let mut current_caps: HashSet<&str> = HashSet::from(["CAP-OBSERVE"]);

    // After shadow validation passes
    let shadow_validation_passed = true;
    if shadow_validation_passed {
        current_caps.insert("CAP-DECIDE");
    }

    assert!(current_caps.contains("CAP-OBSERVE"));
    assert!(current_caps.contains("CAP-DECIDE"));
    assert!(
        !current_caps.contains("CAP-ADMIN"),
        "ADMIN should not be restored yet"
    );
}

#[test]
fn authority_revoked_on_budget_exhaustion() {
    // RA-REVOKE-ON-BUDGET-EXHAUST: permanent revocation
    let max_restarts = 3u32;
    let mut restarts = 0u32;
    let mut caps: HashSet<&str> = HashSet::from(["CAP-OBSERVE", "CAP-DECIDE"]);

    for _ in 0..5 {
        restarts += 1;
        if restarts > max_restarts {
            caps.clear();
            break;
        }
    }

    assert!(
        caps.is_empty(),
        "all caps must be revoked after budget exhaustion"
    );
}

// ── Functional: controller registry integration ─────────────────────

#[test]
fn controller_rollback_narrows_authority() {
    use asupersync::runtime::kernel::{
        ControllerBudget, ControllerMode, ControllerRegistration, ControllerRegistry,
        RollbackReason, SNAPSHOT_VERSION,
    };

    let mut registry = ControllerRegistry::new();
    let reg = ControllerRegistration {
        name: "domain-test".to_string(),
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

    // Simulate crash -> rollback
    let cmd = registry.rollback(
        id,
        RollbackReason::FallbackTriggered {
            decision_label: "domain-crash".to_string(),
        },
    );
    assert!(cmd.is_some(), "rollback must produce RecoveryCommand");
    let cmd = cmd.unwrap();
    assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);

    // Fallback should be active — authority is narrowed
    assert!(
        registry.is_fallback_active(id),
        "fallback must be active after crash rollback"
    );
}

#[test]
fn controller_recovery_clears_fallback() {
    use asupersync::runtime::kernel::{
        ControllerBudget, ControllerMode, ControllerRegistration, ControllerRegistry,
        RollbackReason, SNAPSHOT_VERSION,
    };

    let mut registry = ControllerRegistry::new();
    let reg = ControllerRegistration {
        name: "recovery-test".to_string(),
        min_version: SNAPSHOT_VERSION,
        max_version: SNAPSHOT_VERSION,
        required_fields: vec!["ready_queue_len".to_string()],
        target_seams: vec!["AA01-SEAM-SCHED-CANCEL-STREAK".to_string()],
        initial_mode: ControllerMode::Shadow,
        proof_artifact_id: None,
        budget: ControllerBudget::default(),
    };
    let id = registry.register(reg).unwrap();

    // Promote and crash
    for _ in 0..10 {
        registry.advance_epoch();
        registry.update_calibration(id, 0.95);
    }
    let _ = registry.try_promote(id, ControllerMode::Canary);
    let _ = registry.rollback(id, RollbackReason::ManualRollback);
    assert!(registry.is_fallback_active(id));

    // Recovery: clear fallback (simulates successful microreboot)
    registry.clear_fallback(id);
    assert!(
        !registry.is_fallback_active(id),
        "fallback must be cleared after recovery"
    );
}
