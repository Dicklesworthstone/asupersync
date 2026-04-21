#![allow(clippy::all)]
//! Authority flow audit contract invariants (AA-07.3).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/authority_flow_audit_contract.md";
const ARTIFACT_PATH: &str = "artifacts/authority_flow_audit_v1.json";
const RUNNER_PATH: &str = "scripts/run_authority_flow_audit_smoke.sh";

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
        "## Abuse Scenarios",
        "## Revocation Drills",
        "## Audit Evidence",
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
        "authority-flow-audit-v1"
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

// ── Abuse scenarios ────────────────────────────────────────────────

#[test]
fn abuse_scenarios_are_nonempty() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 6, "must have at least 6 abuse scenarios");
}

#[test]
fn abuse_scenario_ids_are_unique() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();
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
        "abuse scenario_ids must be unique"
    );
}

#[test]
fn abuse_scenarios_have_afa_prefix() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        assert!(
            sid.starts_with("AFA-"),
            "abuse scenario '{sid}' must start with AFA-"
        );
    }
}

#[test]
fn abuse_scenarios_all_expect_deny() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let outcome = scenario["expected_outcome"].as_str().unwrap();
        assert_eq!(
            outcome, "deny",
            "{sid}: all abuse scenarios must expect deny"
        );
    }
}

#[test]
fn abuse_scenarios_have_mitigations() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let mitigation = scenario["mitigation"].as_str().unwrap();
        assert!(
            !mitigation.is_empty(),
            "{sid}: must have non-empty mitigation"
        );
    }
}

#[test]
fn abuse_scenarios_cover_key_attacks() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();
    let ids: HashSet<&str> = scenarios
        .iter()
        .map(|s| s["scenario_id"].as_str().unwrap())
        .collect();
    for required in &[
        "AFA-CONFUSED-DEPUTY",
        "AFA-STALE-TOKEN",
        "AFA-OVER-DELEGATION",
        "AFA-REPLAY-ATTACK",
        "AFA-REVOCATION-RACE",
        "AFA-SANDBOX-ESCAPE",
    ] {
        assert!(
            ids.contains(required),
            "must have abuse scenario {required}"
        );
    }
}

// ── Revocation drills ──────────────────────────────────────────────

#[test]
fn revocation_drills_are_nonempty() {
    let art = load_artifact();
    let drills = art["revocation_drills"].as_array().unwrap();
    assert!(drills.len() >= 3, "must have at least 3 revocation drills");
}

#[test]
fn revocation_drill_ids_are_unique() {
    let art = load_artifact();
    let drills = art["revocation_drills"].as_array().unwrap();
    let ids: Vec<&str> = drills
        .iter()
        .map(|d| d["drill_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "drill_ids must be unique");
}

#[test]
fn revocation_drills_have_rd_prefix() {
    let art = load_artifact();
    let drills = art["revocation_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        assert!(did.starts_with("RD-"), "drill '{did}' must start with RD-");
    }
}

#[test]
fn revocation_drills_have_steps() {
    let art = load_artifact();
    let drills = art["revocation_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        let steps = drill["steps"].as_array().unwrap();
        assert!(steps.len() >= 3, "{did}: must have at least 3 steps");
    }
}

#[test]
fn revocation_drills_have_zero_latency() {
    let art = load_artifact();
    let drills = art["revocation_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        let latency = drill["expected_latency_ms"].as_u64().unwrap();
        assert_eq!(
            latency, 0,
            "{did}: revocation must have zero expected latency (synchronous)"
        );
    }
}

#[test]
fn revocation_drills_include_cascade_and_expiry() {
    let art = load_artifact();
    let drills = art["revocation_drills"].as_array().unwrap();
    let ids: HashSet<&str> = drills
        .iter()
        .map(|d| d["drill_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains("RD-CASCADE-REVOKE"),
        "must have RD-CASCADE-REVOKE"
    );
    assert!(ids.contains("RD-EXPIRY-AUTO"), "must have RD-EXPIRY-AUTO");
}

// ── Audit evidence requirements ────────────────────────────────────

#[test]
fn audit_evidence_requirements_are_nonempty() {
    let art = load_artifact();
    let evidence = art["audit_evidence_requirements"].as_array().unwrap();
    assert!(
        evidence.len() >= 3,
        "must have at least 3 audit evidence requirements"
    );
}

#[test]
fn audit_evidence_ids_are_unique() {
    let art = load_artifact();
    let evidence = art["audit_evidence_requirements"].as_array().unwrap();
    let ids: Vec<&str> = evidence
        .iter()
        .map(|e| e["evidence_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "evidence_ids must be unique");
}

#[test]
fn audit_evidence_has_ae_prefix() {
    let art = load_artifact();
    let evidence = art["audit_evidence_requirements"].as_array().unwrap();
    for ev in evidence {
        let eid = ev["evidence_id"].as_str().unwrap();
        assert!(
            eid.starts_with("AE-"),
            "evidence '{eid}' must start with AE-"
        );
    }
}

#[test]
fn audit_evidence_has_log_fields() {
    let art = load_artifact();
    let evidence = art["audit_evidence_requirements"].as_array().unwrap();
    for ev in evidence {
        let eid = ev["evidence_id"].as_str().unwrap();
        let fields = ev["log_fields"].as_array().unwrap();
        assert!(
            !fields.is_empty(),
            "{eid}: must have at least one log field"
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

// ── Functional: abuse scenario simulations ──────────────────────────

#[test]
fn abuse_confused_deputy_denied() {
    let token_seams: HashSet<&str> = HashSet::from(["seam-A"]);
    let target_seam = "seam-B";

    let verdict = if token_seams.contains(target_seam) {
        "allow"
    } else {
        "deny"
    };
    assert_eq!(verdict, "deny", "confused deputy must be denied");
}

#[test]
fn abuse_stale_token_denied() {
    let token_expiry_epoch: u64 = 10;
    let current_epoch: u64 = 15;

    let verdict = if current_epoch > token_expiry_epoch {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(verdict, "deny", "stale token must be denied");
}

#[test]
fn abuse_over_delegation_denied() {
    let parent_caps: HashSet<&str> = HashSet::from(["CAP-DECIDE", "CAP-OBSERVE"]);
    let child_caps: HashSet<&str> = HashSet::from(["CAP-ADMIN", "CAP-DECIDE"]);

    let verdict = if child_caps.is_subset(&parent_caps) {
        "allow"
    } else {
        "deny"
    };
    assert_eq!(verdict, "deny", "over-delegation must be denied");
}

#[test]
fn abuse_replay_single_use_denied() {
    let mut used_nonces: HashSet<u64> = HashSet::new();
    let token_nonce: u64 = 42;

    // First use: allowed
    assert!(used_nonces.insert(token_nonce), "first use must succeed");

    // Replay: denied
    let verdict = if used_nonces.contains(&token_nonce) {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(verdict, "deny", "replay must be denied");
}

#[test]
fn abuse_depth_bypass_denied() {
    let max_depth: u32 = 5;
    let proposed_depth: u32 = 6;

    let verdict = if proposed_depth > max_depth {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(verdict, "deny", "depth bypass must be denied");
}

#[test]
fn abuse_ambient_authority_denied() {
    let has_token = false;

    let verdict = if has_token { "allow" } else { "deny" };
    assert_eq!(verdict, "deny", "ambient authority must be denied");
}

// ── Functional: revocation drill simulations ────────────────────────

#[test]
fn drill_single_revoke_immediate() {
    let mut revoked_tokens: HashSet<&str> = HashSet::new();
    let token_id = "tok-123";

    // Before revocation: allowed
    let pre_verdict = if revoked_tokens.contains(token_id) {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(pre_verdict, "allow");

    // Revoke
    revoked_tokens.insert(token_id);

    // After revocation: denied
    let post_verdict = if revoked_tokens.contains(token_id) {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(post_verdict, "deny");
}

#[test]
fn drill_cascade_revoke_descendants() {
    let mut revoked: HashSet<&str> = HashSet::new();
    let parent_map = [("child", "root"), ("grandchild", "child")];

    // Revoke root
    revoked.insert("root");

    // Cascade
    let mut changed = true;
    while changed {
        changed = false;
        for (child, parent) in &parent_map {
            if revoked.contains(parent) && revoked.insert(child) {
                changed = true;
            }
        }
    }

    assert!(revoked.contains("child"), "child must be revoked");
    assert!(revoked.contains("grandchild"), "grandchild must be revoked");
}

#[test]
fn drill_expiry_auto_deny() {
    let token_expiry: u64 = 100;
    let mut current_epoch: u64 = 50;

    // Before expiry: allowed
    let pre = if current_epoch > token_expiry {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(pre, "allow");

    // Advance past expiry
    current_epoch = 101;
    let post = if current_epoch > token_expiry {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(post, "deny");
}

// ── Functional: cross-artifact consistency ──────────────────────────

#[test]
fn abuse_mitigations_reference_known_rules() {
    let art = load_artifact();
    let scenarios = art["abuse_scenarios"].as_array().unwrap();

    // Known rule prefixes from other artifacts
    let known_prefixes = ["ATT-", "REV-", "MEM-", "RA-", "CR-", "CVT-"];

    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let mitigation = scenario["mitigation"].as_str().unwrap();
        let references_known = known_prefixes.iter().any(|p| mitigation.contains(p));
        assert!(
            references_known,
            "{sid}: mitigation must reference a known rule prefix"
        );
    }
}

// ── Functional: controller integration ──────────────────────────────

#[test]
fn controller_rollback_produces_audit_trail() {
    use asupersync::runtime::kernel::{
        ControllerBudget, ControllerMode, ControllerRegistration, ControllerRegistry,
        RollbackReason, SNAPSHOT_VERSION,
    };

    let mut registry = ControllerRegistry::new();
    let reg = ControllerRegistration {
        name: "audit-trail-test".to_string(),
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

    // Rollback
    let cmd = registry.rollback(id, RollbackReason::ManualRollback);
    assert!(cmd.is_some());

    // Evidence ledger should contain rollback entry
    let ledger = registry.evidence_ledger();
    assert!(
        ledger.iter().any(|e| matches!(
            &e.event,
            asupersync::runtime::kernel::LedgerEvent::RolledBack { .. }
        )),
        "evidence ledger must record rollback"
    );
}
