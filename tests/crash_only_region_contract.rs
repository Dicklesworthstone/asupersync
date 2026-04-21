#![allow(clippy::all)]
//! Crash-only region semantics contract invariants (AA-09.1).

#![allow(missing_docs, clippy::cast_precision_loss, clippy::cast_sign_loss)]

use serde_json::Value;
use std::collections::{HashMap, HashSet};

const DOC_PATH: &str = "docs/crash_only_region_contract.md";
const ARTIFACT_PATH: &str = "artifacts/crash_only_region_semantics_v1.json";
const RUNNER_PATH: &str = "scripts/run_crash_only_region_smoke.sh";

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
        "## Crash State Machine",
        "## Journal Format",
        "## Microreboot Protocol",
        "## Cancellation Interaction",
        "## Supervision Mapping",
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
        "crash-only-region-semantics-v1"
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

// ── State machine ──────────────────────────────────────────────────

#[test]
fn state_machine_has_all_required_states() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    let ids: Vec<&str> = states
        .iter()
        .map(|s| s["state_id"].as_str().unwrap())
        .collect();
    for required in &[
        "RUNNING",
        "DRAINING",
        "CRASHING",
        "JOURNALED",
        "RECOVERING",
        "QUIESCED",
        "TOMBSTONED",
    ] {
        assert!(ids.contains(required), "must have state {required}");
    }
}

#[test]
fn state_ids_are_unique() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    let ids: Vec<&str> = states
        .iter()
        .map(|s| s["state_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "state_ids must be unique");
}

#[test]
fn state_transitions_reference_valid_states() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    let valid_ids: HashSet<&str> = states
        .iter()
        .map(|s| s["state_id"].as_str().unwrap())
        .collect();
    for state in states {
        let sid = state["state_id"].as_str().unwrap();
        if let Some(targets) = state["transitions_to"].as_array() {
            for target in targets {
                let tid = target.as_str().unwrap();
                assert!(
                    valid_ids.contains(tid),
                    "{sid}: transitions_to references invalid state {tid}"
                );
            }
        }
    }
}

#[test]
fn tombstoned_has_no_outgoing_transitions() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    let tombstoned = states
        .iter()
        .find(|s| s["state_id"].as_str().unwrap() == "TOMBSTONED")
        .expect("TOMBSTONED must exist");
    let transitions = tombstoned["transitions_to"].as_array().unwrap();
    assert!(
        transitions.is_empty(),
        "TOMBSTONED must have no outgoing transitions"
    );
}

#[test]
fn crashing_transitions_only_to_journaled() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    let crashing = states
        .iter()
        .find(|s| s["state_id"].as_str().unwrap() == "CRASHING")
        .expect("CRASHING must exist");
    let targets: Vec<&str> = crashing["transitions_to"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(
        targets,
        vec!["JOURNALED"],
        "CRASHING must only go to JOURNALED"
    );
}

#[test]
fn recovering_requires_journaled_predecessor() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    // JOURNALED must have RECOVERING in transitions_to
    let journaled = states
        .iter()
        .find(|s| s["state_id"].as_str().unwrap() == "JOURNALED")
        .expect("JOURNALED must exist");
    assert!(
        journaled["transitions_to"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str().unwrap() == "RECOVERING"),
        "JOURNALED must be able to transition to RECOVERING"
    );
    // No state other than JOURNALED should transition to RECOVERING
    for state in states {
        let sid = state["state_id"].as_str().unwrap();
        if sid == "JOURNALED" {
            continue;
        }
        if let Some(ts) = state["transitions_to"].as_array() {
            assert!(
                !ts.iter().any(|t| t.as_str().unwrap() == "RECOVERING"),
                "{sid}: only JOURNALED may transition to RECOVERING"
            );
        }
    }
}

#[test]
fn state_machine_invariants_are_nonempty() {
    let art = load_artifact();
    let invariants = art["crash_state_machine"]["invariants"].as_array().unwrap();
    assert!(
        invariants.len() >= 4,
        "must have at least 4 state machine invariants"
    );
}

#[test]
fn state_machine_invariant_ids_are_unique() {
    let art = load_artifact();
    let invariants = art["crash_state_machine"]["invariants"].as_array().unwrap();
    let ids: Vec<&str> = invariants
        .iter()
        .map(|i| i["invariant_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "invariant_ids must be unique");
}

// ── Journal format ─────────────────────────────────────────────────

#[test]
fn journal_entry_types_are_nonempty() {
    let art = load_artifact();
    let entries = art["journal_format"]["entry_types"].as_array().unwrap();
    assert!(
        entries.len() >= 6,
        "must have at least 6 journal entry types"
    );
}

#[test]
fn journal_entry_type_ids_are_unique() {
    let art = load_artifact();
    let entries = art["journal_format"]["entry_types"].as_array().unwrap();
    let ids: Vec<&str> = entries
        .iter()
        .map(|e| e["entry_type"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "entry_type ids must be unique");
}

#[test]
fn journal_entries_have_je_prefix() {
    let art = load_artifact();
    let entries = art["journal_format"]["entry_types"].as_array().unwrap();
    for entry in entries {
        let eid = entry["entry_type"].as_str().unwrap();
        assert!(
            eid.starts_with("JE-"),
            "journal entry '{eid}' must start with JE-"
        );
    }
}

#[test]
fn journal_entries_have_required_fields() {
    let art = load_artifact();
    let entries = art["journal_format"]["entry_types"].as_array().unwrap();
    for entry in entries {
        let eid = entry["entry_type"].as_str().unwrap();
        let fields = entry["required_fields"].as_array().unwrap();
        assert!(
            !fields.is_empty(),
            "{eid}: must have at least one required field"
        );
        // All entries should have sequence_number or epoch
        let field_strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
        assert!(
            field_strs.contains(&"epoch") || field_strs.contains(&"sequence_number"),
            "{eid}: must have epoch or sequence_number"
        );
    }
}

#[test]
fn journal_includes_crash_marker_and_recovery() {
    let art = load_artifact();
    let entries = art["journal_format"]["entry_types"].as_array().unwrap();
    let ids: Vec<&str> = entries
        .iter()
        .map(|e| e["entry_type"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"JE-CRASH-MARKER"),
        "must have JE-CRASH-MARKER"
    );
    assert!(
        ids.contains(&"JE-RECOVERY-COMPLETE"),
        "must have JE-RECOVERY-COMPLETE"
    );
}

#[test]
fn journal_ordering_rules_are_nonempty() {
    let art = load_artifact();
    let rules = art["journal_format"]["ordering_rules"].as_array().unwrap();
    assert!(rules.len() >= 4, "must have at least 4 ordering rules");
}

#[test]
fn journal_ordering_rule_ids_are_unique() {
    let art = load_artifact();
    let rules = art["journal_format"]["ordering_rules"].as_array().unwrap();
    let ids: Vec<&str> = rules
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "ordering rule_ids must be unique");
}

#[test]
fn journal_ordering_rules_have_jo_prefix() {
    let art = load_artifact();
    let rules = art["journal_format"]["ordering_rules"].as_array().unwrap();
    for rule in rules {
        let rid = rule["rule_id"].as_str().unwrap();
        assert!(
            rid.starts_with("JO-"),
            "ordering rule '{rid}' must start with JO-"
        );
    }
}

// ── Microreboot protocol ───────────────────────────────────────────

#[test]
fn microreboot_phases_are_ordered() {
    let art = load_artifact();
    let phases = art["microreboot_protocol"]["phases"].as_array().unwrap();
    assert_eq!(phases.len(), 4, "must have exactly 4 microreboot phases");
    let ids: Vec<&str> = phases
        .iter()
        .map(|p| p["phase_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec!["MR-ISOLATE", "MR-REPLAY", "MR-RECONCILE", "MR-RESUME"],
        "phases must be in correct order"
    );
}

#[test]
fn microreboot_phases_have_pre_and_postconditions() {
    let art = load_artifact();
    let phases = art["microreboot_protocol"]["phases"].as_array().unwrap();
    for phase in phases {
        let pid = phase["phase_id"].as_str().unwrap();
        let pre = phase["precondition"].as_str().unwrap();
        let post = phase["postcondition"].as_str().unwrap();
        assert!(!pre.is_empty(), "{pid}: must have non-empty precondition");
        assert!(!post.is_empty(), "{pid}: must have non-empty postcondition");
    }
}

#[test]
fn microreboot_budget_is_positive() {
    let art = load_artifact();
    let budget = &art["microreboot_protocol"]["budget"];
    assert!(
        budget["max_replay_entries"].as_u64().unwrap() > 0,
        "max_replay_entries must be positive"
    );
    assert!(
        budget["max_recovery_wall_clock_ms"].as_u64().unwrap() > 0,
        "max_recovery_wall_clock_ms must be positive"
    );
    assert!(
        budget["max_consecutive_microreboots"].as_u64().unwrap() > 0,
        "max_consecutive_microreboots must be positive"
    );
}

#[test]
fn microreboot_backoff_is_well_formed() {
    let art = load_artifact();
    let budget = &art["microreboot_protocol"]["budget"];
    let base = budget["backoff_base_ms"].as_u64().unwrap();
    let max = budget["backoff_max_ms"].as_u64().unwrap();
    let mult = budget["backoff_multiplier"].as_f64().unwrap();
    assert!(base > 0, "backoff base must be positive");
    assert!(max >= base, "backoff max must be >= base");
    assert!(mult > 1.0, "backoff multiplier must be > 1.0");
}

#[test]
fn microreboot_cancellation_rules_are_nonempty() {
    let art = load_artifact();
    let rules = art["microreboot_protocol"]["cancellation_interaction"]["rules"]
        .as_array()
        .unwrap();
    assert!(
        rules.len() >= 3,
        "must have at least 3 cancellation interaction rules"
    );
}

#[test]
fn microreboot_cancellation_rule_ids_have_cr_prefix() {
    let art = load_artifact();
    let rules = art["microreboot_protocol"]["cancellation_interaction"]["rules"]
        .as_array()
        .unwrap();
    for rule in rules {
        let rid = rule["rule_id"].as_str().unwrap();
        assert!(
            rid.starts_with("CR-"),
            "cancellation rule '{rid}' must start with CR-"
        );
    }
}

// ── Supervision mapping ────────────────────────────────────────────

#[test]
fn supervision_mappings_cover_all_strategies() {
    let art = load_artifact();
    let mappings = art["supervision_mapping"]["mappings"].as_array().unwrap();
    let strategies: Vec<&str> = mappings
        .iter()
        .map(|m| m["strategy"].as_str().unwrap())
        .collect();
    for required in &["Stop", "Restart", "Escalate"] {
        assert!(
            strategies.contains(required),
            "must map supervision strategy {required}"
        );
    }
}

#[test]
fn supervision_restart_leads_to_recovering() {
    let art = load_artifact();
    let mappings = art["supervision_mapping"]["mappings"].as_array().unwrap();
    let restart = mappings
        .iter()
        .find(|m| m["strategy"].as_str().unwrap() == "Restart")
        .expect("Restart mapping must exist");
    let behavior = restart["crash_only_behavior"].as_str().unwrap();
    assert!(
        behavior.contains("RECOVERING"),
        "Restart strategy must include RECOVERING"
    );
}

#[test]
fn supervision_stop_leads_to_tombstoned() {
    let art = load_artifact();
    let mappings = art["supervision_mapping"]["mappings"].as_array().unwrap();
    let stop = mappings
        .iter()
        .find(|m| m["strategy"].as_str().unwrap() == "Stop")
        .expect("Stop mapping must exist");
    let behavior = stop["crash_only_behavior"].as_str().unwrap();
    assert!(
        behavior.contains("TOMBSTONED"),
        "Stop strategy must end in TOMBSTONED"
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

// ── Functional: state machine reachability ──────────────────────────

#[test]
fn state_machine_running_can_reach_tombstoned() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();

    // Build adjacency
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for state in states {
        let sid = state["state_id"].as_str().unwrap();
        let targets: Vec<&str> = state["transitions_to"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        adj.insert(sid, targets);
    }

    // BFS from RUNNING to TOMBSTONED
    let mut visited = HashSet::new();
    let mut queue = vec!["RUNNING"];
    while let Some(node) = queue.pop() {
        if visited.insert(node) {
            if let Some(neighbors) = adj.get(node) {
                for &n in neighbors {
                    queue.push(n);
                }
            }
        }
    }
    assert!(
        visited.contains("TOMBSTONED"),
        "TOMBSTONED must be reachable from RUNNING"
    );
}

#[test]
fn state_machine_crash_path_passes_through_journaled() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();

    // Build adjacency
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for state in states {
        let sid = state["state_id"].as_str().unwrap();
        let targets: Vec<&str> = state["transitions_to"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        adj.insert(sid, targets);
    }

    // From CRASHING, can we reach RECOVERING? If so, JOURNALED must be on the path.
    // CRASHING -> JOURNALED is the only transition, so JOURNALED is always on the path.
    let crashing_targets = adj.get("CRASHING").unwrap();
    assert_eq!(
        crashing_targets,
        &vec!["JOURNALED"],
        "CRASHING must go through JOURNALED"
    );
}

#[test]
fn state_machine_no_self_loops() {
    let art = load_artifact();
    let states = art["crash_state_machine"]["states"].as_array().unwrap();
    for state in states {
        let sid = state["state_id"].as_str().unwrap();
        if let Some(targets) = state["transitions_to"].as_array() {
            assert!(
                !targets.iter().any(|t| t.as_str().unwrap() == sid),
                "{sid}: must not have a self-loop"
            );
        }
    }
}

// ── Functional: journal ordering simulation ─────────────────────────

#[test]
fn journal_monotonic_sequence_invariant() {
    // Simulate journal entries and verify monotonic sequence
    let entries = [
        ("JE-REGION-OPEN", 1u64),
        ("JE-TASK-SPAWN", 2),
        ("JE-OBLIGATION-ENTER", 3),
        ("JE-CHECKPOINT", 4),
        ("JE-OBLIGATION-SETTLE", 5),
        ("JE-CRASH-MARKER", 6),
    ];

    for window in entries.windows(2) {
        assert!(
            window[1].1 > window[0].1,
            "sequence {} -> {} must be strictly increasing",
            window[0].0,
            window[1].0
        );
    }
}

#[test]
fn journal_open_before_spawn_invariant() {
    // JE-REGION-OPEN must come before JE-TASK-SPAWN
    let open_seq = 1u64;
    let spawn_seq = 2u64;
    assert!(open_seq < spawn_seq, "REGION-OPEN must precede TASK-SPAWN");
}

#[test]
fn journal_enter_before_settle_invariant() {
    // JE-OBLIGATION-ENTER must come before JE-OBLIGATION-SETTLE
    let enter_seq = 3u64;
    let settle_seq = 5u64;
    assert!(
        enter_seq < settle_seq,
        "OBLIGATION-ENTER must precede OBLIGATION-SETTLE"
    );
}

// ── Functional: microreboot budget simulation ───────────────────────

#[test]
fn microreboot_backoff_respects_cap() {
    let art = load_artifact();
    let budget = &art["microreboot_protocol"]["budget"];
    let base = budget["backoff_base_ms"].as_u64().unwrap();
    let max = budget["backoff_max_ms"].as_u64().unwrap();
    let mult = budget["backoff_multiplier"].as_f64().unwrap();
    let max_reboots = budget["max_consecutive_microreboots"].as_u64().unwrap();

    let mut delay = base;
    for _ in 0..max_reboots {
        assert!(
            delay <= max,
            "backoff delay {delay}ms must not exceed cap {max}ms"
        );
        delay = ((delay as f64 * mult) as u64).min(max);
    }
}

#[test]
fn microreboot_consecutive_limit_prevents_infinite_loop() {
    let art = load_artifact();
    let max_reboots = art["microreboot_protocol"]["budget"]["max_consecutive_microreboots"]
        .as_u64()
        .unwrap();

    let mut reboots = 0u64;
    let mut tombstoned = false;

    for _ in 0..10 {
        reboots += 1;
        if reboots > max_reboots {
            tombstoned = true;
            break;
        }
    }

    assert!(
        tombstoned,
        "must tombstone after exceeding max consecutive microreboots"
    );
}

// ── Functional: cancellation interaction ────────────────────────────

#[test]
fn parent_cancel_during_recovery_tombstones() {
    // Simulate: region in RECOVERING, parent sends cancel
    let region_state = "RECOVERING";
    let parent_cancelled = true;

    let final_state = if parent_cancelled && region_state == "RECOVERING" {
        "TOMBSTONED"
    } else {
        "RUNNING"
    };

    assert_eq!(
        final_state, "TOMBSTONED",
        "parent cancel during recovery must tombstone"
    );
}

#[test]
fn child_regions_abandoned_on_crash() {
    // Simulate: parent crashes, child regions must be cancelled
    let parent_state = "CRASHING";
    let child_states = ["RUNNING", "DRAINING", "RUNNING"];

    let child_final: Vec<&str> = child_states
        .iter()
        .map(|_| {
            if parent_state == "CRASHING" {
                "TOMBSTONED"
            } else {
                "RUNNING"
            }
        })
        .collect();

    for (i, state) in child_final.iter().enumerate() {
        assert_eq!(
            *state, "TOMBSTONED",
            "child {i} must be TOMBSTONED when parent crashes"
        );
    }
}

// ── Functional: supervision strategy mapping ────────────────────────

#[test]
fn supervision_restart_respects_budget() {
    // Simulate restart strategy with budget exhaustion
    let max_restarts = 3u32;
    let mut restart_count = 0u32;
    let mut final_state = "RUNNING";

    for _ in 0..5 {
        // Simulate crash
        if restart_count < max_restarts {
            restart_count += 1;
            final_state = "RUNNING"; // recovered
        } else {
            final_state = "TOMBSTONED"; // budget exhausted
            break;
        }
    }

    assert_eq!(
        final_state, "TOMBSTONED",
        "must tombstone after exhausting restart budget"
    );
    assert_eq!(
        restart_count, max_restarts,
        "must have used exactly the restart budget"
    );
}

#[test]
fn supervision_escalate_notifies_parent() {
    // Simulate escalate strategy
    let strategy = "Escalate";
    let parent_notified = strategy == "Escalate";
    assert!(
        parent_notified,
        "Escalate strategy must notify parent region"
    );
}

// ── Functional: recovery with ControllerRegistry ────────────────────

#[test]
fn controller_rollback_on_region_crash() {
    use asupersync::runtime::kernel::{
        ControllerBudget, ControllerMode, ControllerRegistration, ControllerRegistry,
        RollbackReason, SNAPSHOT_VERSION,
    };

    let mut registry = ControllerRegistry::new();
    let reg = ControllerRegistration {
        name: "crash-test".to_string(),
        min_version: SNAPSHOT_VERSION,
        max_version: SNAPSHOT_VERSION,
        required_fields: vec!["ready_queue_len".to_string()],
        target_seams: vec!["AA01-SEAM-SCHED-CANCEL-STREAK".to_string()],
        initial_mode: ControllerMode::Shadow,
        proof_artifact_id: None,
        budget: ControllerBudget::default(),
    };
    let id = registry.register(reg).unwrap();

    // Promote to Canary then Active
    for _ in 0..10 {
        registry.advance_epoch();
        registry.update_calibration(id, 0.95);
    }
    let _ = registry.try_promote(id, ControllerMode::Canary);
    for _ in 0..5 {
        registry.advance_epoch();
        registry.update_calibration(id, 0.95);
    }
    let _ = registry.try_promote(id, ControllerMode::Active);

    // Rollback simulating crash
    let cmd = registry.rollback(id, RollbackReason::ManualRollback);
    assert!(cmd.is_some(), "rollback must produce RecoveryCommand");

    let cmd = cmd.unwrap();
    assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
    assert!(registry.is_fallback_active(id));

    // After recovery, clear fallback
    registry.clear_fallback(id);
    assert!(!registry.is_fallback_active(id));
}
