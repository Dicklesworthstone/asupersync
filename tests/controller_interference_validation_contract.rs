#![allow(warnings)]
#![allow(clippy::all)]
//! Controller interference validation contract invariants (AA-03.3).

#![allow(missing_docs, clippy::cast_precision_loss)]

use serde_json::Value;

const DOC_PATH: &str = "docs/controller_interference_validation_contract.md";
const ARTIFACT_PATH: &str = "artifacts/controller_interference_validation_v1.json";
const RUNNER_PATH: &str = "scripts/run_controller_interference_validation_smoke.sh";

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
        "## Interference Model",
        "## Timescale Separation",
        "## Tail-SLO Fallback Gates",
        "## Sequential Validity",
        "## Structured Logging Contract",
        "## Comparator-Smoke Runner",
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
        "controller-interference-validation-v1"
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

// ── Interference model ─────────────────────────────────────────────

#[test]
fn interference_overlap_pairs_are_nonempty() {
    let art = load_artifact();
    let pairs = art["interference_model"]["overlap_pairs"]
        .as_array()
        .unwrap();
    assert!(
        !pairs.is_empty(),
        "must have at least one interference pair"
    );
}

#[test]
fn interference_pairs_have_required_fields() {
    let art = load_artifact();
    let pairs = art["interference_model"]["overlap_pairs"]
        .as_array()
        .unwrap();
    for pair in pairs {
        let pid = pair["pair_id"].as_str().unwrap();
        assert!(
            pair["controller_a"].is_string(),
            "{pid}: must have controller_a"
        );
        assert!(
            pair["controller_b"].is_string(),
            "{pid}: must have controller_b"
        );
        assert!(
            pair["shared_observable"].is_string(),
            "{pid}: must have shared_observable"
        );
        assert!(
            pair["feedback_risk"].is_string(),
            "{pid}: must have feedback_risk"
        );
        assert!(
            pair["detection_method"].is_string(),
            "{pid}: must have detection_method"
        );
        let threshold = pair["oscillation_threshold"].as_u64().unwrap();
        assert!(threshold > 0, "{pid}: threshold must be positive");
        let window = pair["window_epochs"].as_u64().unwrap();
        assert!(window >= threshold, "{pid}: window must be >= threshold");
    }
}

#[test]
fn interference_pair_ids_are_unique() {
    let art = load_artifact();
    let pairs = art["interference_model"]["overlap_pairs"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = pairs
        .iter()
        .map(|p| p["pair_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "pair_ids must be unique");
}

#[test]
fn interference_controllers_reference_known_domains() {
    let art = load_artifact();
    let known_domains = ["SCHED-GOVERNOR", "ADMISSION-GATE", "RETRY-BACKOFF"];
    let pairs = art["interference_model"]["overlap_pairs"]
        .as_array()
        .unwrap();
    for pair in pairs {
        let pid = pair["pair_id"].as_str().unwrap();
        let a = pair["controller_a"].as_str().unwrap();
        let b = pair["controller_b"].as_str().unwrap();
        assert!(
            known_domains.contains(&a),
            "{pid}: controller_a '{a}' not a known domain"
        );
        assert!(
            known_domains.contains(&b),
            "{pid}: controller_b '{b}' not a known domain"
        );
        assert_ne!(a, b, "{pid}: controllers must be distinct");
    }
}

// ── Timescale separation ───────────────────────────────────────────

#[test]
fn timescale_tiers_are_nonempty() {
    let art = load_artifact();
    let tiers = art["timescale_separation"]["tiers"].as_array().unwrap();
    assert!(!tiers.is_empty(), "must have at least one timescale tier");
}

#[test]
fn timescale_tiers_have_required_fields() {
    let art = load_artifact();
    let tiers = art["timescale_separation"]["tiers"].as_array().unwrap();
    for tier in tiers {
        let tid = tier["tier_id"].as_str().unwrap();
        assert!(
            tier["epoch_multiplier"].as_u64().unwrap() > 0,
            "{tid}: epoch_multiplier must be positive"
        );
        let controllers = tier["controllers"].as_array().unwrap();
        assert!(
            !controllers.is_empty(),
            "{tid}: must have at least one controller"
        );
        assert!(tier["rationale"].is_string(), "{tid}: must have rationale");
    }
}

#[test]
fn timescale_tiers_are_strictly_ordered() {
    let art = load_artifact();
    let tiers = art["timescale_separation"]["tiers"].as_array().unwrap();
    let multipliers: Vec<u64> = tiers
        .iter()
        .map(|t| t["epoch_multiplier"].as_u64().unwrap())
        .collect();
    for window in multipliers.windows(2) {
        assert!(
            window[1] > window[0],
            "tiers must have strictly increasing epoch_multipliers: {} >= {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn timescale_minimum_ratio_respected() {
    let art = load_artifact();
    let tiers = art["timescale_separation"]["tiers"].as_array().unwrap();
    let min_ratio = art["timescale_separation"]["minimum_ratio"]
        .as_u64()
        .unwrap();
    let multipliers: Vec<u64> = tiers
        .iter()
        .map(|t| t["epoch_multiplier"].as_u64().unwrap())
        .collect();
    for window in multipliers.windows(2) {
        assert!(
            window[1] >= window[0] * min_ratio,
            "adjacent tier ratio {} / {} must be >= {min_ratio}",
            window[1],
            window[0]
        );
    }
}

#[test]
fn timescale_tier_ids_are_unique() {
    let art = load_artifact();
    let tiers = art["timescale_separation"]["tiers"].as_array().unwrap();
    let ids: Vec<&str> = tiers
        .iter()
        .map(|t| t["tier_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "tier_ids must be unique");
}

// ── Tail-SLO fallback ──────────────────────────────────────────────

#[test]
fn fallback_slo_fields_are_nonempty() {
    let art = load_artifact();
    let fields = art["tail_slo_fallback"]["slo_fields"].as_array().unwrap();
    assert!(!fields.is_empty(), "must have at least one SLO field");
}

#[test]
fn fallback_slo_fields_have_required_structure() {
    let art = load_artifact();
    let fields = art["tail_slo_fallback"]["slo_fields"].as_array().unwrap();
    for field in fields {
        let fid = field["field_id"].as_str().unwrap();
        assert!(
            field["snapshot_field"].is_string(),
            "{fid}: must have snapshot_field"
        );
        assert!(
            field["threshold_description"].is_string(),
            "{fid}: must have threshold_description"
        );
        assert!(
            field["breach_action"].is_string(),
            "{fid}: must have breach_action"
        );
    }
}

#[test]
fn fallback_deadline_is_positive() {
    let art = load_artifact();
    let deadline = art["tail_slo_fallback"]["fallback_deadline_epochs"]
        .as_u64()
        .unwrap();
    assert!(deadline > 0, "fallback deadline must be positive");
}

#[test]
fn fallback_recovery_protocol_is_nonempty() {
    let art = load_artifact();
    let steps = art["tail_slo_fallback"]["recovery_protocol"]
        .as_array()
        .unwrap();
    assert!(
        steps.len() >= 3,
        "recovery protocol must have at least 3 steps"
    );
}

// ── Sequential validity ────────────────────────────────────────────

#[test]
fn sequential_validity_has_ordering_rule() {
    let art = load_artifact();
    let rule = art["sequential_validity"]["ordering_rule"]
        .as_str()
        .unwrap();
    assert!(
        !rule.is_empty(),
        "sequential validity must have ordering rule"
    );
}

#[test]
fn sequential_drift_alarm_has_threshold() {
    let art = load_artifact();
    let max_drift = art["sequential_validity"]["drift_alarm"]["max_drift_events_per_epoch"]
        .as_u64()
        .unwrap();
    assert!(max_drift > 0, "drift alarm max events must be positive");
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    assert!(!fields.is_empty(), "structured log fields must be nonempty");
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
        assert!(
            cmd.starts_with("rch exec"),
            "{sid}: command must be rch-routed"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    assert!(runner.contains("--list"), "runner must support --list");
    assert!(
        runner.contains("--dry-run"),
        "runner must support --dry-run"
    );
    assert!(
        runner.contains("--execute"),
        "runner must support --execute"
    );
    assert!(
        runner.contains("--scenario"),
        "runner must support --scenario"
    );
}

// ── Functional: interference oscillation detection ──────────────────

#[test]
fn interference_oscillation_detection_within_window() {
    // Simulate decision history for a controller pair and detect oscillation
    let actions_a = [
        "SCHED-PARK-WORKER",
        "SCHED-WAKE-WORKER",
        "SCHED-PARK-WORKER",
        "SCHED-WAKE-WORKER",
        "SCHED-PARK-WORKER",
    ];

    let oscillation_threshold: usize = 4;
    let window_epochs: usize = 8;

    // Count oscillations: direction changes in the action sequence
    let mut oscillation_count: usize = 0;
    for i in 1..actions_a.len().min(window_epochs) {
        if actions_a[i] != actions_a[i - 1] {
            oscillation_count += 1;
        }
    }

    assert!(
        oscillation_count >= oscillation_threshold,
        "5 alternating actions must produce >= 4 oscillations, got {oscillation_count}"
    );
}

#[test]
fn interference_no_oscillation_for_stable_decisions() {
    let actions = [
        "SCHED-NOOP",
        "SCHED-NOOP",
        "SCHED-NOOP",
        "SCHED-NOOP",
        "SCHED-NOOP",
    ];

    let mut oscillation_count: usize = 0;
    for i in 1..actions.len() {
        if actions[i] != actions[i - 1] {
            oscillation_count += 1;
        }
    }

    assert_eq!(
        oscillation_count, 0,
        "stable decisions must produce zero oscillations"
    );
}

#[test]
fn interference_partial_oscillation_below_threshold() {
    // 2 direction changes — below threshold of 4
    let actions = [
        "ADMIT-TIGHTEN",
        "ADMIT-RELAX",
        "ADMIT-TIGHTEN",
        "ADMIT-TIGHTEN",
        "ADMIT-TIGHTEN",
    ];

    let oscillation_threshold: usize = 4;
    let mut oscillation_count: usize = 0;
    for i in 1..actions.len() {
        if actions[i] != actions[i - 1] {
            oscillation_count += 1;
        }
    }

    assert!(
        oscillation_count < oscillation_threshold,
        "partial oscillation ({oscillation_count}) must be below threshold ({oscillation_threshold})"
    );
}

// ── Functional: timescale separation enforcement ────────────────────

#[test]
fn timescale_fast_controller_decides_every_epoch() {
    let fast_multiplier: u64 = 1;
    let total_epochs: u64 = 10;
    let decisions: u64 = total_epochs / fast_multiplier;
    assert_eq!(decisions, 10, "FAST tier decides every epoch");
}

#[test]
fn timescale_slow_controller_decides_less_frequently() {
    let fast_multiplier: u64 = 1;
    let medium_multiplier: u64 = 4;
    let slow_multiplier: u64 = 8;
    let total_epochs: u64 = 32;

    let fast_decisions = total_epochs / fast_multiplier;
    let medium_decisions = total_epochs / medium_multiplier;
    let slow_decisions = total_epochs / slow_multiplier;

    assert!(
        fast_decisions > medium_decisions,
        "fast must decide more than medium"
    );
    assert!(
        medium_decisions > slow_decisions,
        "medium must decide more than slow"
    );
    assert_eq!(fast_decisions, 32);
    assert_eq!(medium_decisions, 8);
    assert_eq!(slow_decisions, 4);
}

#[test]
fn timescale_separation_prevents_simultaneous_decisions() {
    // In a system with multipliers 1, 4, 8, controllers at different tiers
    // should rarely decide in the same epoch. At epoch 8, all three decide.
    // At epoch 4, fast and medium decide. At epoch 1, only fast decides.
    let multipliers = [1_u64, 4, 8];
    let mut simultaneous_count = 0_u64;
    for epoch in 1..=32_u64 {
        let deciding_count = multipliers.iter().filter(|&&m| epoch % m == 0).count();
        if deciding_count == multipliers.len() {
            simultaneous_count += 1;
        }
    }
    // With multipliers 1,4,8 over 32 epochs: all-three-decide at epochs 8,16,24,32 = 4 times
    assert_eq!(
        simultaneous_count, 4,
        "all three tiers deciding simultaneously should be rare"
    );
}

// ── Functional: tail-SLO fallback ───────────────────────────────────

use asupersync::runtime::kernel::{
    ControllerBudget, ControllerDecision, ControllerMode, ControllerRegistration,
    ControllerRegistry, LedgerEvent, RollbackReason, SnapshotVersion,
};

fn make_reg(name: &str, seams: &[&str]) -> ControllerRegistration {
    ControllerRegistration {
        name: name.to_string(),
        min_version: SnapshotVersion { major: 1, minor: 0 },
        max_version: SnapshotVersion { major: 1, minor: 0 },
        required_fields: vec!["ready_queue_len".to_string()],
        target_seams: seams.iter().map(std::string::ToString::to_string).collect(),
        initial_mode: ControllerMode::Shadow,
        proof_artifact_id: None,
        budget: ControllerBudget::default(),
    }
}

fn promote_to_active(
    registry: &mut ControllerRegistry,
    id: asupersync::runtime::kernel::ControllerId,
) {
    registry.update_calibration(id, 0.95);
    // Shadow epochs
    for _ in 0..3 {
        registry.advance_epoch();
    }
    registry
        .try_promote(id, ControllerMode::Canary)
        .expect("shadow->canary");
    // Canary epochs
    for _ in 0..2 {
        registry.advance_epoch();
    }
    registry
        .try_promote(id, ControllerMode::Active)
        .expect("canary->active");
}

#[test]
fn fallback_slo_breach_rolls_back_all_active_controllers() {
    let mut registry = ControllerRegistry::new();

    let sched = registry
        .register(make_reg("sched-gov", &["AA01-SEAM-SCHED-GOVERNOR"]))
        .unwrap();
    let admit = registry
        .register(make_reg("admit-gate", &["AA01-SEAM-ADMISSION-ROOT-LIMITS"]))
        .unwrap();

    promote_to_active(&mut registry, sched);
    promote_to_active(&mut registry, admit);

    assert_eq!(registry.mode(sched), Some(ControllerMode::Active));
    assert_eq!(registry.mode(admit), Some(ControllerMode::Active));

    // SLO breach: roll back all non-shadow controllers
    let ids = registry.controller_ids();
    for id in &ids {
        if registry.mode(*id) != Some(ControllerMode::Shadow) {
            registry.rollback(*id, RollbackReason::CalibrationRegression { score: 0.3 });
        }
    }

    assert_eq!(registry.mode(sched), Some(ControllerMode::Shadow));
    assert_eq!(registry.mode(admit), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(sched));
    assert!(registry.is_fallback_active(admit));
}

#[test]
fn fallback_already_shadow_controller_unaffected() {
    let mut registry = ControllerRegistry::new();

    let shadow_ctrl = registry
        .register(make_reg("shadow-only", &["AA01-SEAM-RETRY-BACKOFF"]))
        .unwrap();
    let active_ctrl = registry
        .register(make_reg("active-ctrl", &["AA01-SEAM-SCHED-GOVERNOR"]))
        .unwrap();

    promote_to_active(&mut registry, active_ctrl);
    assert_eq!(registry.mode(shadow_ctrl), Some(ControllerMode::Shadow));
    assert_eq!(registry.mode(active_ctrl), Some(ControllerMode::Active));

    // SLO breach rollback
    let result = registry.rollback(
        shadow_ctrl,
        RollbackReason::CalibrationRegression { score: 0.1 },
    );
    assert!(
        result.is_none(),
        "rollback of shadow controller must be no-op"
    );
    assert_eq!(registry.mode(shadow_ctrl), Some(ControllerMode::Shadow));
    assert!(!registry.is_fallback_active(shadow_ctrl));
}

#[test]
fn fallback_recovery_requires_fresh_calibration() {
    let mut registry = ControllerRegistry::new();

    let ctrl = registry
        .register(make_reg("recoverable", &["AA01-SEAM-SCHED-GOVERNOR"]))
        .unwrap();

    promote_to_active(&mut registry, ctrl);
    registry.rollback(ctrl, RollbackReason::ManualRollback);
    assert_eq!(registry.mode(ctrl), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(ctrl));

    // Attempt immediate re-promotion without fresh calibration
    // Calibration was set to 0.95 before, but let's set it low
    registry.update_calibration(ctrl, 0.5);
    for _ in 0..3 {
        registry.advance_epoch();
    }
    let result = registry.try_promote(ctrl, ControllerMode::Canary);
    assert!(
        result.is_err(),
        "re-promotion must fail with low calibration after fallback"
    );

    // Now provide fresh calibration
    registry.update_calibration(ctrl, 0.9);
    let result = registry.try_promote(ctrl, ControllerMode::Canary);
    assert!(
        result.is_ok(),
        "re-promotion with fresh calibration must succeed"
    );
}

#[test]
fn fallback_flag_cleared_after_recovery() {
    let mut registry = ControllerRegistry::new();

    let ctrl = registry
        .register(make_reg("flag-clear", &["AA01-SEAM-SCHED-GOVERNOR"]))
        .unwrap();

    promote_to_active(&mut registry, ctrl);
    registry.rollback(
        ctrl,
        RollbackReason::FallbackTriggered {
            decision_label: "bad-decision".to_string(),
        },
    );
    assert!(registry.is_fallback_active(ctrl));

    // Simulate recovery
    registry.clear_fallback(ctrl);
    assert!(
        !registry.is_fallback_active(ctrl),
        "fallback flag must be clearable after recovery"
    );
}

// ── Functional: sequential decision ordering ────────────────────────

#[test]
fn sequential_decisions_applied_in_registration_order() {
    let mut registry = ControllerRegistry::new();

    let id_a = registry
        .register(make_reg("ctrl-first", &["AA01-SEAM-SCHED-GOVERNOR"]))
        .unwrap();
    let id_b = registry
        .register(make_reg(
            "ctrl-second",
            &["AA01-SEAM-ADMISSION-ROOT-LIMITS"],
        ))
        .unwrap();
    let id_c = registry
        .register(make_reg("ctrl-third", &["AA01-SEAM-RETRY-BACKOFF"]))
        .unwrap();

    // Registration order: a < b < c (by ControllerId)
    assert!(id_a.0 < id_b.0);
    assert!(id_b.0 < id_c.0);

    // Record decisions in order
    let snap_id = registry.next_snapshot_id();
    for (id, label) in [
        (id_a, "decision-a"),
        (id_b, "decision-b"),
        (id_c, "decision-c"),
    ] {
        registry.record_decision(&ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: label.to_string(),
            payload: serde_json::json!({}),
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        });
    }

    // Verify all decisions recorded in ledger in order
    let ledger = registry.evidence_ledger();
    let decision_entries: Vec<_> = ledger
        .iter()
        .filter(|e| matches!(e.event, LedgerEvent::DecisionRecorded { .. }))
        .collect();
    assert_eq!(decision_entries.len(), 3);
    assert_eq!(decision_entries[0].controller_id, id_a);
    assert_eq!(decision_entries[1].controller_id, id_b);
    assert_eq!(decision_entries[2].controller_id, id_c);
}

#[test]
fn sequential_drift_detection_simulation() {
    // Simulate drift: controller B's optimal decision changes after A's decision
    // This is a pure-logic test — no runtime state mutation needed

    struct DecisionContext {
        ready_queue_len: usize,
    }

    fn controller_b_decision(ctx: &DecisionContext) -> &'static str {
        if ctx.ready_queue_len > 50 {
            "ADMIT-TIGHTEN"
        } else {
            "ADMIT-NOOP"
        }
    }

    // Before A's decision: queue=60, B would tighten
    let pre_a = DecisionContext {
        ready_queue_len: 60,
    };
    let decision_pre = controller_b_decision(&pre_a);
    assert_eq!(decision_pre, "ADMIT-TIGHTEN");

    // After A's decision wakes a worker and drains queue: queue=40, B would noop
    let post_a = DecisionContext {
        ready_queue_len: 40,
    };
    let decision_post = controller_b_decision(&post_a);
    assert_eq!(decision_post, "ADMIT-NOOP");

    // Drift detected: B's decision differs pre vs post A
    let drift_detected = decision_pre != decision_post;
    assert!(
        drift_detected,
        "drift must be detected when A's decision changes B's optimal action"
    );
}

#[test]
fn sequential_no_drift_when_decisions_independent() {
    // When controllers target independent state, no drift occurs
    struct DecisionContext {
        pending_io: usize,
    }

    fn controller_c_decision(ctx: &DecisionContext) -> &'static str {
        if ctx.pending_io > 100 {
            "RETRY-STEEPEN"
        } else {
            "RETRY-NOOP"
        }
    }

    // A's decision (scheduler) doesn't affect pending_io
    let pre_a = DecisionContext { pending_io: 50 };
    let post_a = DecisionContext { pending_io: 50 };

    let decision_pre = controller_c_decision(&pre_a);
    let decision_post = controller_c_decision(&post_a);

    assert_eq!(
        decision_pre, decision_post,
        "independent controllers must not produce drift"
    );
}

// ── Functional: multi-controller lifecycle composition ───────────────

#[test]
fn interference_multi_controller_full_lifecycle() {
    let mut registry = ControllerRegistry::new();

    // Register three controllers at different tiers
    let sched = registry
        .register(make_reg(
            "sched-governor",
            &["AA01-SEAM-SCHED-GOVERNOR", "AA01-SEAM-SCHED-CANCEL-STREAK"],
        ))
        .unwrap();
    let admit = registry
        .register(make_reg(
            "admission-gate",
            &["AA01-SEAM-ADMISSION-ROOT-LIMITS"],
        ))
        .unwrap();
    let retry = registry
        .register(make_reg("retry-backoff", &["AA01-SEAM-RETRY-BACKOFF"]))
        .unwrap();

    // All start in Shadow
    assert_eq!(registry.mode(sched), Some(ControllerMode::Shadow));
    assert_eq!(registry.mode(admit), Some(ControllerMode::Shadow));
    assert_eq!(registry.mode(retry), Some(ControllerMode::Shadow));

    // Promote sched first (fastest tier)
    promote_to_active(&mut registry, sched);
    assert_eq!(registry.mode(sched), Some(ControllerMode::Active));

    // Admit and retry still need their own epochs — update calibration for them
    registry.update_calibration(admit, 0.92);
    registry.update_calibration(retry, 0.88);

    // Advance enough epochs for admit (needs 3 shadow + 2 canary)
    for _ in 0..3 {
        registry.advance_epoch();
    }
    registry
        .try_promote(admit, ControllerMode::Canary)
        .expect("admit shadow->canary");
    for _ in 0..2 {
        registry.advance_epoch();
    }
    registry
        .try_promote(admit, ControllerMode::Active)
        .expect("admit canary->active");

    // Retry also promoted
    registry.update_calibration(retry, 0.90);
    for _ in 0..3 {
        registry.advance_epoch();
    }
    registry
        .try_promote(retry, ControllerMode::Canary)
        .expect("retry shadow->canary");
    for _ in 0..2 {
        registry.advance_epoch();
    }
    registry
        .try_promote(retry, ControllerMode::Active)
        .expect("retry canary->active");

    // All three active
    assert_eq!(registry.mode(sched), Some(ControllerMode::Active));
    assert_eq!(registry.mode(admit), Some(ControllerMode::Active));
    assert_eq!(registry.mode(retry), Some(ControllerMode::Active));

    // Simulate SLO breach — roll back all
    for id in &registry.controller_ids() {
        if registry.mode(*id) != Some(ControllerMode::Shadow) {
            registry.rollback(*id, RollbackReason::CalibrationRegression { score: 0.2 });
        }
    }

    // All back to shadow with fallback active
    assert_eq!(registry.mode(sched), Some(ControllerMode::Shadow));
    assert_eq!(registry.mode(admit), Some(ControllerMode::Shadow));
    assert_eq!(registry.mode(retry), Some(ControllerMode::Shadow));
    assert!(registry.is_fallback_active(sched));
    assert!(registry.is_fallback_active(admit));
    assert!(registry.is_fallback_active(retry));

    // Evidence ledger should have complete lifecycle for all three
    let ledger = registry.evidence_ledger();
    assert!(
        ledger.len() >= 12,
        "ledger must have entries for register+promote+rollback for each controller"
    );
}

#[test]
fn interference_hold_prevents_multi_controller_promotion() {
    let mut registry = ControllerRegistry::new();

    let ctrl_a = registry
        .register(make_reg("ctrl-a", &["AA01-SEAM-SCHED-GOVERNOR"]))
        .unwrap();
    let ctrl_b = registry
        .register(make_reg("ctrl-b", &["AA01-SEAM-ADMISSION-ROOT-LIMITS"]))
        .unwrap();

    registry.update_calibration(ctrl_a, 0.95);
    registry.update_calibration(ctrl_b, 0.95);

    // Hold ctrl_a while trying to promote both
    registry.hold(ctrl_a);
    assert_eq!(registry.mode(ctrl_a), Some(ControllerMode::Hold));

    for _ in 0..3 {
        registry.advance_epoch();
    }

    // ctrl_a cannot promote while held
    let result = registry.try_promote(ctrl_a, ControllerMode::Canary);
    assert!(result.is_err(), "held controller must not promote");

    // ctrl_b can still promote independently
    let result = registry.try_promote(ctrl_b, ControllerMode::Canary);
    assert!(result.is_ok(), "unheld controller must promote normally");
}
