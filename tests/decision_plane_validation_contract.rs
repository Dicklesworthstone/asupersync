#![allow(warnings)]
#![allow(clippy::all)]
//! Decision plane validation contract invariants (AA-02.3).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/decision_plane_validation_contract.md";
const ARTIFACT_PATH: &str = "artifacts/decision_plane_validation_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_decision_plane_validation_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load decision plane validation doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load decision plane validation artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// ── Doc existence and structure ─────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "decision plane validation doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.2.6"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "State Transition Model",
        "Rollback Contract",
        "Evidence Ledger Contract",
        "Structured Logging Contract",
        "Comparator-Smoke Runner",
        "Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }
    assert!(
        missing.is_empty(),
        "doc missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_runner_and_test() {
    let doc = load_doc();
    for reference in [
        "artifacts/decision_plane_validation_v1.json",
        "scripts/run_decision_plane_validation_smoke.sh",
        "tests/decision_plane_validation_contract.rs",
        "src/runtime/kernel.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa023 cargo test --test decision_plane_validation_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

// ── Artifact schema and version stability ────────────────────────────

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("decision-plane-validation-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("decision-plane-validation-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("decision-plane-validation-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_decision_plane_validation_smoke.sh")
    );
}

#[test]
fn controller_snapshot_ledger_schema_is_stable() {
    let artifact = load_artifact();
    let schema = &artifact["controller_snapshot_ledger"];
    assert_eq!(
        schema["schema_version"].as_str(),
        Some("controller-snapshot-ledger-v1")
    );
    let top_level_fields: Vec<String> = schema["top_level_fields"]
        .as_array()
        .expect("top_level_fields must be array")
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        top_level_fields,
        vec![
            "schema_version",
            "registered_controllers",
            "shadow_controllers",
            "controllers",
        ]
    );
    let planner_render_order: Vec<String> = schema["planner_render_order"]
        .as_array()
        .expect("planner_render_order must be array")
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        planner_render_order,
        vec![
            "controller_name",
            "mode",
            "calibration_score",
            "last_decision_confidence",
            "decisions_this_epoch",
            "fallback_active",
            "last_action_label",
            "last_evidence_tick",
            "last_snapshot_id",
            "epochs_in_current_mode",
            "budget_overruns",
            "proof_artifact_id",
        ]
    );
}

#[test]
fn controller_snapshot_ledger_field_units_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<(String, String)> =
        artifact["controller_snapshot_ledger"]["controller_fields"]
            .as_array()
            .expect("controller_fields must be array")
            .iter()
            .map(|field| {
                (
                    field["name"].as_str().unwrap().to_string(),
                    field["units"].as_str().unwrap().to_string(),
                )
            })
            .collect();
    let expected: BTreeSet<(String, String)> = [
        ("controller_id", "controller id"),
        ("controller_name", "string"),
        ("mode", "enum"),
        ("decisions_this_epoch", "decisions"),
        ("fallback_active", "flag"),
        ("calibration_score", "unit interval [0,1]"),
        ("last_decision_confidence", "unit interval [0,1] or null"),
        ("last_action_label", "string or null"),
        ("last_evidence_tick", "ledger entry id or null"),
        ("last_snapshot_id", "SnapshotId(u64) or null"),
        ("epochs_in_current_mode", "epochs"),
        ("budget_overruns", "count"),
        ("proof_artifact_id", "artifact id or null"),
    ]
    .into_iter()
    .map(|(name, units)| (name.to_string(), units.to_string()))
    .collect();
    assert_eq!(
        actual, expected,
        "controller snapshot field units must remain stable"
    );
}

// ── Promotion pipeline stability ─────────────────────────────────────

#[test]
fn promotion_pipeline_is_stable() {
    let artifact = load_artifact();
    let pipeline: Vec<String> = artifact["promotion_pipeline"]
        .as_array()
        .expect("promotion_pipeline must be array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(pipeline, vec!["Shadow", "Canary", "Active"]);
}

#[test]
fn hold_semantics_are_stable() {
    let artifact = load_artifact();
    let hold = &artifact["hold_semantics"];
    assert_eq!(hold["blocks_promotion"].as_bool(), Some(true));
    assert_eq!(hold["preserves_prior_mode"].as_bool(), Some(true));
    assert_eq!(hold["release_restores_mode"].as_bool(), Some(true));
}

#[test]
fn rollback_reasons_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["rollback_reasons"]
        .as_array()
        .expect("rollback_reasons must be array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "CalibrationRegression",
        "BudgetOverruns",
        "ManualRollback",
        "FallbackTriggered",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "rollback reasons must remain stable");
}

// ── Validation scenario catalog ──────────────────────────────────────

#[test]
fn validation_scenario_ids_are_complete() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["validation_scenarios"]
        .as_array()
        .expect("validation_scenarios must be array")
        .iter()
        .map(|s| s["scenario_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "AA023-SHADOW-OBSERVE",
        "AA023-PROMOTE-SHADOW-CANARY",
        "AA023-PROMOTE-CANARY-ACTIVE",
        "AA023-REJECT-SKIP-SHADOW-ACTIVE",
        "AA023-REJECT-LOW-CALIBRATION",
        "AA023-REJECT-INSUFFICIENT-EPOCHS",
        "AA023-HOLD-BLOCKS-PROMOTE",
        "AA023-HOLD-RELEASE-RESTORES",
        "AA023-ROLLBACK-CALIBRATION",
        "AA023-ROLLBACK-BUDGET",
        "AA023-ROLLBACK-MANUAL",
        "AA023-ROLLBACK-FALLBACK-TRIGGERED",
        "AA023-ROLLBACK-SHADOW-NOOP",
        "AA023-EVIDENCE-COMPLETENESS",
        "AA023-EVIDENCE-DECISION-BUDGET",
        "AA023-RECOVERY-REMEDIATION",
        "AA023-CONTROLLER-LEDGER-DEFAULTS",
        "AA023-CONTROLLER-LEDGER-MULTI-CONTROLLER",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "validation scenario IDs must remain stable"
    );
}

#[test]
fn each_validation_scenario_has_required_fields() {
    let artifact = load_artifact();
    for scenario in artifact["validation_scenarios"].as_array().unwrap() {
        let sid = scenario["scenario_id"].as_str().unwrap_or("<missing>");
        for field in ["scenario_id", "description", "category"] {
            assert!(
                scenario.get(field).is_some(),
                "scenario {sid} missing field: {field}"
            );
        }
    }
}

// ── Evidence ledger event types ──────────────────────────────────────

#[test]
fn evidence_ledger_event_types_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["evidence_ledger_event_types"]
        .as_array()
        .expect("evidence_ledger_event_types must be array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "Registered",
        "Promoted",
        "RolledBack",
        "Held",
        "Released",
        "Deregistered",
        "PromotionRejected",
        "DecisionRecorded",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "ledger event types must remain stable");
}

// ── Structured log fields ────────────────────────────────────────────

#[test]
fn structured_log_fields_are_unique_and_nonempty() {
    let artifact = load_artifact();
    let fields = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array");
    assert!(!fields.is_empty());
    let mut set = BTreeSet::new();
    for field in fields {
        let f = field.as_str().expect("field must be string").to_string();
        assert!(!f.is_empty());
        assert!(set.insert(f.clone()), "duplicate field: {f}");
    }
}

// ── Smoke runner ─────────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    assert!(!scenarios.is_empty());
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.contains("rch exec --"), "scenario {sid} must use rch");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists(), "runner script must exist");
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "decision-plane-validation-smoke-bundle-v1",
        "decision-plane-validation-smoke-run-report-v1",
        "controller_snapshot_ledger_schema_version",
        "controller_snapshot_ledger_top_level_fields",
        "controller_snapshot_ledger_controller_fields",
        "controller_snapshot_ledger_planner_render_order",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

// ── Downstream beads ─────────────────────────────────────────────────

#[test]
fn downstream_beads_are_in_aa_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(
            bead.starts_with("asupersync-1508v."),
            "must be AA namespace: {bead}"
        );
    }
}

// ── Functional: State transition tests ───────────────────────────────

use asupersync::runtime::kernel::{
    CONTROLLER_SNAPSHOT_LEDGER_SCHEMA_VERSION, ControllerBudget, ControllerDecision,
    ControllerMode, ControllerRegistration, ControllerRegistry, LedgerEvent, PromotionPolicy,
    PromotionRejection, RollbackReason, SnapshotId, SnapshotVersion,
};

fn test_registration(name: &str) -> ControllerRegistration {
    ControllerRegistration {
        name: name.to_string(),
        min_version: SnapshotVersion { major: 1, minor: 0 },
        max_version: SnapshotVersion { major: 1, minor: 0 },
        required_fields: vec!["ready_queue_len".to_string()],
        target_seams: vec!["AA01-SEAM-SCHED-GOVERNOR".to_string()],
        initial_mode: ControllerMode::Shadow,
        proof_artifact_id: None,
        budget: ControllerBudget::default(),
    }
}

fn fast_policy() -> PromotionPolicy {
    PromotionPolicy {
        min_calibration_score: 0.8,
        min_shadow_epochs: 2,
        min_canary_epochs: 1,
        max_budget_overruns: 3,
        policy_id: "test-fast-policy-v1".to_string(),
    }
}

fn promote_through_shadow(
    registry: &mut ControllerRegistry,
    id: asupersync::runtime::kernel::ControllerId,
) {
    registry.update_calibration(id, 0.95);
    for _ in 0..2 {
        registry.advance_epoch();
    }
    registry
        .try_promote(id, ControllerMode::Canary)
        .expect("shadow->canary must succeed");
}

fn promote_through_canary(
    registry: &mut ControllerRegistry,
    id: asupersync::runtime::kernel::ControllerId,
) {
    registry.update_calibration(id, 0.95);
    registry.advance_epoch();
    registry
        .try_promote(id, ControllerMode::Active)
        .expect("canary->active must succeed");
}

fn controller_snapshot_planner_render_order() -> Vec<String> {
    load_artifact()["controller_snapshot_ledger"]["planner_render_order"]
        .as_array()
        .expect("planner_render_order must be array")
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

fn planner_row(controller_json: &Value, fields: &[String]) -> Vec<String> {
    fields
        .iter()
        .map(
            |field| match controller_json.get(field).unwrap_or(&Value::Null) {
                Value::Null => "null".to_string(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                Value::String(value) => value.clone(),
                other => panic!("unexpected planner value for {field}: {other:?}"),
            },
        )
        .collect()
}

#[test]
fn transition_shadow_observe() {
    let mut registry = ControllerRegistry::new();
    let id = registry.register(test_registration("shadow-ctrl")).unwrap();
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));

    let decision = ControllerDecision {
        controller_id: id,
        snapshot_id: SnapshotId(1),
        label: "test-decision".to_string(),
        payload: serde_json::json!({}),
        confidence: 0.9,
        fallback_label: "no-op".to_string(),
    };
    let within_budget = registry.record_decision(&decision);
    assert!(within_budget, "first decision must be within budget");
    assert_eq!(
        registry.mode(id),
        Some(ControllerMode::Shadow),
        "mode must remain Shadow after decision"
    );

    let ledger = registry.controller_ledger(id);
    assert!(ledger.len() >= 2, "must have Registered + DecisionRecorded");
    assert!(
        matches!(ledger[0].event, LedgerEvent::Registered { .. }),
        "first entry must be Registered"
    );
    assert!(
        matches!(ledger[1].event, LedgerEvent::DecisionRecorded { .. }),
        "second entry must be DecisionRecorded"
    );
}

#[test]
fn transition_promote_shadow_canary() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("promote-ctrl"))
        .unwrap();

    registry.update_calibration(id, 0.95);
    for _ in 0..2 {
        registry.advance_epoch();
    }

    let result = registry.try_promote(id, ControllerMode::Canary);
    assert!(result.is_ok(), "shadow->canary must succeed");
    assert_eq!(registry.mode(id), Some(ControllerMode::Canary));

    let ledger = registry.controller_ledger(id);
    let promoted = ledger
        .iter()
        .any(|e| matches!(e.event, LedgerEvent::Promoted { .. }));
    assert!(promoted, "ledger must contain Promoted event");
}

#[test]
fn transition_promote_canary_active() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("active-ctrl")).unwrap();

    promote_through_shadow(&mut registry, id);
    promote_through_canary(&mut registry, id);

    assert_eq!(registry.mode(id), Some(ControllerMode::Active));

    let ledger = registry.controller_ledger(id);
    let promotion_count = ledger
        .iter()
        .filter(|e| matches!(e.event, LedgerEvent::Promoted { .. }))
        .count();
    assert_eq!(promotion_count, 2, "must have two Promoted events");
}

#[test]
fn transition_reject_skip_shadow_active() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("skip-ctrl")).unwrap();

    registry.update_calibration(id, 0.99);
    for _ in 0..10 {
        registry.advance_epoch();
    }

    let result = registry.try_promote(id, ControllerMode::Active);
    assert!(
        matches!(result, Err(PromotionRejection::InvalidTransition { .. })),
        "shadow->active must be rejected as invalid transition"
    );
    assert_eq!(
        registry.mode(id),
        Some(ControllerMode::Shadow),
        "mode must remain Shadow"
    );

    let ledger = registry.controller_ledger(id);
    let rejected = ledger
        .iter()
        .any(|e| matches!(e.event, LedgerEvent::PromotionRejected { .. }));
    assert!(rejected, "ledger must record PromotionRejected");
}

#[test]
fn transition_reject_low_calibration() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("low-cal-ctrl"))
        .unwrap();

    registry.update_calibration(id, 0.5); // below 0.8 threshold
    for _ in 0..5 {
        registry.advance_epoch();
    }

    let result = registry.try_promote(id, ControllerMode::Canary);
    assert!(
        matches!(result, Err(PromotionRejection::CalibrationTooLow { .. })),
        "low calibration must be rejected"
    );
}

#[test]
fn transition_reject_insufficient_epochs() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("epoch-ctrl")).unwrap();

    registry.update_calibration(id, 0.95);
    // Only 1 epoch, need 2
    registry.advance_epoch();

    let result = registry.try_promote(id, ControllerMode::Canary);
    assert!(
        matches!(result, Err(PromotionRejection::InsufficientEpochs { .. })),
        "insufficient epochs must be rejected"
    );
}

#[test]
fn transition_hold_blocks_promote() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("hold-ctrl")).unwrap();

    registry.hold(id);
    assert_eq!(registry.mode(id), Some(ControllerMode::Hold));

    let result = registry.try_promote(id, ControllerMode::Canary);
    assert!(
        matches!(result, Err(PromotionRejection::HeldForInvestigation)),
        "hold must block promotion"
    );
}

#[test]
fn transition_hold_release_restores() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("restore-ctrl"))
        .unwrap();

    promote_through_shadow(&mut registry, id);
    assert_eq!(registry.mode(id), Some(ControllerMode::Canary));

    registry.hold(id);
    assert_eq!(registry.mode(id), Some(ControllerMode::Hold));

    let restored = registry.release_hold(id);
    assert_eq!(restored, Some(ControllerMode::Canary));
    assert_eq!(registry.mode(id), Some(ControllerMode::Canary));

    let ledger = registry.controller_ledger(id);
    let has_held = ledger
        .iter()
        .any(|e| matches!(e.event, LedgerEvent::Held { .. }));
    let has_released = ledger
        .iter()
        .any(|e| matches!(e.event, LedgerEvent::Released { .. }));
    assert!(has_held, "ledger must contain Held event");
    assert!(has_released, "ledger must contain Released event");
}

// ── Functional: Rollback tests ───────────────────────────────────────

#[test]
fn rollback_calibration_regression() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("cal-reg-ctrl"))
        .unwrap();
    promote_through_shadow(&mut registry, id);
    promote_through_canary(&mut registry, id);

    let cmd = registry.rollback(id, RollbackReason::CalibrationRegression { score: 0.3 });
    assert!(cmd.is_some(), "rollback must produce recovery command");
    let cmd = cmd.unwrap();
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(id));
    assert_eq!(cmd.rolled_back_from, ControllerMode::Active);
    assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
    assert!(!cmd.remediation.is_empty(), "remediation must be nonempty");
    assert!(
        cmd.policy_id.contains("test-fast-policy"),
        "recovery must include policy ID"
    );
}

#[test]
fn rollback_budget_overruns() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("budget-ctrl")).unwrap();
    promote_through_shadow(&mut registry, id);

    let cmd = registry.rollback(id, RollbackReason::BudgetOverruns { count: 5 });
    assert!(cmd.is_some());
    let cmd = cmd.unwrap();
    assert_eq!(cmd.rolled_back_from, ControllerMode::Canary);
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(id));
}

#[test]
fn rollback_manual() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("manual-ctrl")).unwrap();
    promote_through_shadow(&mut registry, id);

    let cmd = registry.rollback(id, RollbackReason::ManualRollback);
    assert!(cmd.is_some());
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(id));
}

#[test]
fn rollback_fallback_triggered() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("fallback-ctrl"))
        .unwrap();
    promote_through_shadow(&mut registry, id);
    promote_through_canary(&mut registry, id);

    let cmd = registry.rollback(
        id,
        RollbackReason::FallbackTriggered {
            decision_label: "bad-decision".to_string(),
        },
    );
    assert!(cmd.is_some());
    let cmd = cmd.unwrap();
    assert_eq!(cmd.rolled_back_from, ControllerMode::Active);
    assert!(cmd.remediation.iter().any(|r| r.contains("bad-decision")));
}

#[test]
fn rollback_shadow_is_noop() {
    let mut registry = ControllerRegistry::new();
    let id = registry.register(test_registration("shadow-noop")).unwrap();
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));

    let cmd = registry.rollback(id, RollbackReason::ManualRollback);
    assert!(cmd.is_none(), "rollback of Shadow controller must be no-op");
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
}

// ── Functional: Evidence ledger tests ────────────────────────────────

#[test]
fn evidence_completeness_full_lifecycle() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("lifecycle-ctrl"))
        .unwrap();

    // Shadow -> Canary
    promote_through_shadow(&mut registry, id);
    // Canary -> Active
    promote_through_canary(&mut registry, id);
    // Hold
    registry.hold(id);
    // Release
    registry.release_hold(id);
    // Rollback
    registry.rollback(id, RollbackReason::ManualRollback);
    // Deregister
    registry.deregister(id);

    let ledger = registry.evidence_ledger();
    let controller_entries: Vec<_> = ledger.iter().filter(|e| e.controller_id == id).collect();

    // Must have: Registered, Promoted(S->C), Promoted(C->A), Held, Released, RolledBack, Deregistered
    assert!(
        controller_entries.len() >= 7,
        "full lifecycle must produce at least 7 ledger entries, got {}",
        controller_entries.len()
    );

    // Every entry must have a policy_id
    for entry in &controller_entries {
        assert!(
            !entry.policy_id.is_empty(),
            "entry {} must have policy_id",
            entry.entry_id
        );
    }

    // Entry IDs must be monotonically increasing
    for window in controller_entries.windows(2) {
        assert!(
            window[1].entry_id > window[0].entry_id,
            "entry IDs must be monotonically increasing"
        );
    }
}

#[test]
fn evidence_decision_budget_tracking() {
    let mut registry = ControllerRegistry::new();
    let id = registry
        .register(test_registration("budget-track"))
        .unwrap();

    // Record 2 decisions (budget is 1 per epoch)
    let decision = ControllerDecision {
        controller_id: id,
        snapshot_id: SnapshotId(1),
        label: "d1".to_string(),
        payload: serde_json::json!({}),
        confidence: 0.9,
        fallback_label: "no-op".to_string(),
    };
    let first = registry.record_decision(&decision);
    assert!(first, "first decision must be within budget");

    let decision2 = ControllerDecision {
        controller_id: id,
        snapshot_id: SnapshotId(2),
        label: "d2".to_string(),
        payload: serde_json::json!({}),
        confidence: 0.9,
        fallback_label: "no-op".to_string(),
    };
    let second = registry.record_decision(&decision2);
    assert!(!second, "second decision must exceed budget");

    // Verify budget overruns tracked
    assert_eq!(registry.budget_overruns(id), Some(1));

    // Verify ledger has both decisions
    let ledger = registry.controller_ledger(id);
    let decision_events: Vec<_> = ledger
        .iter()
        .filter(|e| matches!(e.event, LedgerEvent::DecisionRecorded { .. }))
        .collect();
    assert_eq!(decision_events.len(), 2, "both decisions must be in ledger");

    // Check budget tracking in events
    if let LedgerEvent::DecisionRecorded { within_budget, .. } = &decision_events[0].event {
        assert!(within_budget, "first must be within budget");
    }
    if let LedgerEvent::DecisionRecorded { within_budget, .. } = &decision_events[1].event {
        assert!(!within_budget, "second must be over budget");
    }
}

#[test]
fn evidence_recovery_remediation_nonempty() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());

    for (name, reason) in [
        (
            "cal-ctrl",
            RollbackReason::CalibrationRegression { score: 0.2 },
        ),
        ("budget-ctrl", RollbackReason::BudgetOverruns { count: 4 }),
        ("manual-ctrl", RollbackReason::ManualRollback),
        (
            "fallback-ctrl",
            RollbackReason::FallbackTriggered {
                decision_label: "bad".to_string(),
            },
        ),
    ] {
        let id = registry.register(test_registration(name)).unwrap();
        promote_through_shadow(&mut registry, id);

        let cmd = registry.rollback(id, reason);
        let cmd = cmd.expect("rollback of Canary must produce command");
        assert!(
            !cmd.remediation.is_empty(),
            "recovery for {name} must have remediation steps"
        );
        assert!(
            !cmd.policy_id.is_empty(),
            "recovery for {name} must have policy_id"
        );
    }
}

#[test]
fn evidence_rejection_recorded_in_ledger() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry.register(test_registration("rej-ctrl")).unwrap();

    // Try invalid promotion (Shadow -> Active)
    let _ = registry.try_promote(id, ControllerMode::Active);

    // Try low calibration
    registry.update_calibration(id, 0.1);
    for _ in 0..5 {
        registry.advance_epoch();
    }
    let _ = registry.try_promote(id, ControllerMode::Canary);

    let ledger = registry.controller_ledger(id);
    let rejection_count = ledger
        .iter()
        .filter(|e| matches!(e.event, LedgerEvent::PromotionRejected { .. }))
        .count();
    assert_eq!(rejection_count, 2, "both rejections must be in ledger");
}

#[test]
fn evidence_rollback_leaves_conservative_state() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("conservative-ctrl"))
        .unwrap();
    promote_through_shadow(&mut registry, id);
    promote_through_canary(&mut registry, id);

    // Rollback from Active
    let cmd = registry
        .rollback(id, RollbackReason::ManualRollback)
        .expect("must produce command");

    // Verify conservative state
    assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(id));
    assert_eq!(registry.epochs_in_current_mode(id), Some(0));
    assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);

    // Cannot promote immediately (needs new calibration + epochs)
    let result = registry.try_promote(id, ControllerMode::Canary);
    assert!(result.is_err(), "cannot promote immediately after rollback");
}

#[test]
fn evidence_fallback_clear_after_recovery() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());
    let id = registry
        .register(test_registration("clear-fb-ctrl"))
        .unwrap();
    promote_through_shadow(&mut registry, id);

    registry.rollback(id, RollbackReason::ManualRollback);
    assert!(registry.is_fallback_active(id));

    registry.clear_fallback(id);
    assert!(
        !registry.is_fallback_active(id),
        "fallback must be clearable after recovery"
    );
}

#[test]
fn controller_snapshot_ledger_defaults_when_registry_is_empty() {
    let registry = ControllerRegistry::new();
    let ledger = registry.controller_snapshot_ledger();
    assert_eq!(
        ledger.schema_version,
        CONTROLLER_SNAPSHOT_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(ledger.registered_controllers, 0);
    assert_eq!(ledger.shadow_controllers, 0);
    assert!(ledger.controllers.is_empty());
}

#[test]
fn controller_snapshot_ledger_defaults_for_new_controller() {
    let mut registry = ControllerRegistry::new();
    let id = registry
        .register(test_registration("controller-ledger-defaults"))
        .unwrap();
    let ledger = registry.controller_snapshot_ledger();
    assert_eq!(ledger.registered_controllers, 1);
    assert_eq!(ledger.shadow_controllers, 1);
    let controller = ledger
        .controllers
        .iter()
        .find(|controller| controller.controller_id == id)
        .expect("registered controller must appear in snapshot ledger");
    assert_eq!(controller.controller_name, "controller-ledger-defaults");
    assert_eq!(controller.mode, ControllerMode::Shadow);
    assert_eq!(controller.decisions_this_epoch, 0);
    assert!(!controller.fallback_active);
    assert_eq!(controller.calibration_score, 0.0);
    assert_eq!(controller.last_decision_confidence, None);
    assert_eq!(controller.last_action_label.as_deref(), Some("registered"));
    assert_eq!(controller.last_evidence_tick, Some(1));
    assert_eq!(controller.last_snapshot_id, None);
    assert_eq!(controller.epochs_in_current_mode, 0);
    assert_eq!(controller.budget_overruns, 0);
    assert_eq!(controller.proof_artifact_id, None);
}

#[test]
fn controller_snapshot_ledger_decision_counters_and_ticks_are_monotone() {
    let mut registry = ControllerRegistry::new();
    let id = registry
        .register(test_registration("controller-ledger-monotone"))
        .unwrap();

    let first_decision = ControllerDecision {
        controller_id: id,
        snapshot_id: SnapshotId(11),
        label: "raise-limit".to_string(),
        payload: serde_json::json!({ "cancel_streak_limit": 12 }),
        confidence: 0.71,
        fallback_label: "hold".to_string(),
    };
    registry.record_decision(&first_decision);
    let first = registry
        .controller_snapshot_ledger()
        .controllers
        .into_iter()
        .find(|controller| controller.controller_id == id)
        .expect("controller state after first decision");

    let second_decision = ControllerDecision {
        controller_id: id,
        snapshot_id: SnapshotId(13),
        label: "tighten-budget".to_string(),
        payload: serde_json::json!({ "budget_us": 800 }),
        confidence: 0.83,
        fallback_label: "rollback".to_string(),
    };
    registry.record_decision(&second_decision);
    let second = registry
        .controller_snapshot_ledger()
        .controllers
        .into_iter()
        .find(|controller| controller.controller_id == id)
        .expect("controller state after second decision");

    assert_eq!(first.decisions_this_epoch, 1);
    assert_eq!(second.decisions_this_epoch, 2);
    assert!(second.last_evidence_tick.unwrap() > first.last_evidence_tick.unwrap());
    assert_eq!(first.last_snapshot_id, Some(SnapshotId(11)));
    assert_eq!(second.last_snapshot_id, Some(SnapshotId(13)));
    assert_eq!(second.last_decision_confidence, Some(0.83));
    assert_eq!(
        second.last_action_label.as_deref(),
        Some("decision:tighten-budget")
    );
}

#[test]
fn controller_snapshot_ledger_multi_controller_rendering_is_stable() {
    let mut registry = ControllerRegistry::new();
    registry.set_promotion_policy(fast_policy());

    let primary = registry
        .register(test_registration("primary-ledger"))
        .unwrap();
    let secondary = registry
        .register(test_registration("secondary-ledger"))
        .unwrap();

    promote_through_shadow(&mut registry, primary);
    promote_through_canary(&mut registry, primary);
    registry.update_calibration(primary, 0.42);
    let primary_decision = ControllerDecision {
        controller_id: primary,
        snapshot_id: SnapshotId(10),
        label: "primary-steer".to_string(),
        payload: serde_json::json!({ "cancel_streak_limit": 8 }),
        confidence: 0.91,
        fallback_label: "shadow".to_string(),
    };
    registry.record_decision(&primary_decision);
    registry
        .rollback(
            primary,
            RollbackReason::CalibrationRegression { score: 0.42 },
        )
        .expect("primary rollback should produce a recovery command");

    let secondary_decision = ControllerDecision {
        controller_id: secondary,
        snapshot_id: SnapshotId(11),
        label: "secondary-observe".to_string(),
        payload: serde_json::json!({ "sample": "keep" }),
        confidence: 0.73,
        fallback_label: "noop".to_string(),
    };
    registry.record_decision(&secondary_decision);
    assert!(registry.hold(secondary));

    let ledger = registry.controller_snapshot_ledger();
    assert_eq!(
        ledger.schema_version,
        CONTROLLER_SNAPSHOT_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(ledger.registered_controllers, 2);
    assert_eq!(ledger.shadow_controllers, 1);
    assert_eq!(ledger.controllers.len(), 2);

    let primary_state = &ledger.controllers[0];
    let secondary_state = &ledger.controllers[1];
    assert_eq!(primary_state.controller_name, "primary-ledger");
    assert_eq!(primary_state.mode, ControllerMode::Shadow);
    assert!(primary_state.fallback_active);
    assert_eq!(primary_state.calibration_score, 0.42);
    assert_eq!(primary_state.last_decision_confidence, Some(0.91));
    assert_eq!(
        primary_state.last_action_label.as_deref(),
        Some("rolled_back:calibration_regression")
    );
    assert_eq!(primary_state.last_evidence_tick, Some(6));
    assert_eq!(primary_state.last_snapshot_id, Some(SnapshotId(10)));
    assert_eq!(primary_state.decisions_this_epoch, 1);
    assert_eq!(primary_state.epochs_in_current_mode, 0);

    assert_eq!(secondary_state.controller_name, "secondary-ledger");
    assert_eq!(secondary_state.mode, ControllerMode::Hold);
    assert!(!secondary_state.fallback_active);
    assert_eq!(secondary_state.last_decision_confidence, Some(0.73));
    assert_eq!(secondary_state.last_action_label.as_deref(), Some("held"));
    assert_eq!(secondary_state.last_evidence_tick, Some(8));
    assert_eq!(secondary_state.last_snapshot_id, Some(SnapshotId(11)));

    let render_order = controller_snapshot_planner_render_order();
    let ledger_json = serde_json::to_value(&ledger).expect("ledger must serialize");
    let primary_row = planner_row(&ledger_json["controllers"][0], &render_order);
    assert_eq!(
        primary_row,
        vec![
            "primary-ledger",
            "Shadow",
            "0.42",
            "0.91",
            "1",
            "true",
            "rolled_back:calibration_regression",
            "6",
            "10",
            "0",
            "0",
            "null",
        ]
    );
}
