//! Active conformance tests for runtime diagnostics introspection endpoints.
//!
//! The previous file was a permanently disabled historical archive. These tests
//! exercise the current public diagnostics surface against real `RuntimeState`
//! records and stable observability taxonomy contracts.

use asupersync::observability::diagnostics::{
    ADVANCED_OBSERVABILITY_BASELINE_VERSION, ADVANCED_OBSERVABILITY_CONTRACT_VERSION, BlockReason,
    DeadlockSeverity, Diagnostics, Reason, advanced_observability_contract,
};
use asupersync::observability::spectral_health::HealthClassification;
use asupersync::record::ObligationKind;
use asupersync::runtime::state::RuntimeState;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::collections::BTreeSet;
use std::time::Duration;

// Diagnostics intentionally accepts `Arc<RuntimeState>` in the public API even
// though direct conformance tests do not cross thread boundaries.
#[allow(clippy::arc_with_non_send_sync)]
fn diagnostics_for_state(state: RuntimeState) -> Diagnostics {
    Diagnostics::new(std::sync::Arc::new(state))
}

fn populated_runtime() -> (Diagnostics, RegionId, RegionId, TaskId) {
    let mut state = RuntimeState::new();
    let root = state.create_root_region(Budget::INFINITE);
    let child = state
        .create_child_region(root, Budget::with_deadline_at_ns(500_000_000))
        .expect("child region should be admitted");
    let (task, _handle) = state
        .create_task(child, Budget::with_deadline_at_ns(50_000_000), async {})
        .expect("task should be admitted");

    state
        .create_obligation(
            ObligationKind::SendPermit,
            task,
            child,
            Some("diagnostics-conformance-send-permit".to_string()),
        )
        .expect("obligation should be admitted");
    state.now = state.now + Duration::from_millis(25);

    (diagnostics_for_state(state), root, child, task)
}

#[test]
fn diagnostics_reports_live_region_task_and_obligation_reasons() {
    let (diagnostics, root, child, task) = populated_runtime();

    let root_explanation = diagnostics.explain_region_open(root);
    assert_eq!(root_explanation.region_id, root);
    assert!(root_explanation.reasons.iter().any(|reason| matches!(
        reason,
        Reason::ChildRegionOpen { child_id, .. } if *child_id == child
    )));
    assert!(
        root_explanation
            .recommendations
            .iter()
            .any(|rec| rec.contains("child regions"))
    );

    let child_explanation = diagnostics.explain_region_open(child);
    assert!(child_explanation.reasons.iter().any(|reason| matches!(
        reason,
        Reason::TaskRunning { task_id, .. } if *task_id == task
    )));
    assert!(child_explanation.reasons.iter().any(|reason| matches!(
        reason,
        Reason::ObligationHeld {
            obligation_type,
            holder_task,
            ..
        } if obligation_type == "SendPermit" && *holder_task == task
    )));

    let task_explanation = diagnostics.explain_task_blocked(task);
    assert!(matches!(
        task_explanation.block_reason,
        BlockReason::NotStarted
    ));
    assert!(
        task_explanation
            .recommendations
            .iter()
            .any(|rec| rec.contains("not started"))
    );

    let leaks = diagnostics.find_leaked_obligations();
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].holder_task, Some(task));
    assert_eq!(leaks[0].region_id, child);
    assert_eq!(leaks[0].obligation_type, "SendPermit");
    assert!(leaks[0].age >= Duration::from_millis(25));
}

#[test]
fn diagnostics_handles_missing_ids_and_empty_wait_graphs_deterministically() {
    let diagnostics = diagnostics_for_state(RuntimeState::new());

    let missing_region = RegionId::from_arena(ArenaIndex::new(9_999, 0));
    let missing_task = TaskId::from_arena(ArenaIndex::new(9_999, 0));

    let region_explanation = diagnostics.explain_region_open(missing_region);
    assert_eq!(region_explanation.region_id, missing_region);
    assert!(matches!(
        region_explanation.reasons.as_slice(),
        [Reason::RegionNotFound]
    ));
    assert_eq!(region_explanation.recommendations.len(), 1);

    let task_explanation = diagnostics.explain_task_blocked(missing_task);
    assert!(matches!(
        task_explanation.block_reason,
        BlockReason::TaskNotFound
    ));
    assert_eq!(task_explanation.recommendations.len(), 1);

    let health = diagnostics.analyze_structural_health();
    assert!(matches!(
        health.classification,
        HealthClassification::Healthy { margin } if margin == 0.0
    ));

    let deadlock = diagnostics.analyze_directional_deadlock();
    assert!(matches!(deadlock.severity, DeadlockSeverity::None));
    assert_eq!(deadlock.risk_score, 0.0);
    assert!(deadlock.cycles.is_empty());
    assert!(diagnostics.find_leaked_obligations().is_empty());
}

#[test]
fn advanced_diagnostics_taxonomy_contract_is_stable_and_unique() {
    let contract = advanced_observability_contract();
    assert_eq!(
        contract.contract_version,
        ADVANCED_OBSERVABILITY_CONTRACT_VERSION
    );
    assert_eq!(
        contract.baseline_contract_version,
        ADVANCED_OBSERVABILITY_BASELINE_VERSION
    );
    assert!(!contract.compatibility_notes.is_empty());

    let class_ids = contract
        .event_classes
        .iter()
        .map(|spec| spec.class_id.as_str())
        .collect::<Vec<_>>();
    let unique_class_ids = class_ids.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(class_ids.len(), unique_class_ids.len());
    assert!(unique_class_ids.contains("command_lifecycle"));
    assert!(unique_class_ids.contains("verification_governance"));

    let severity_ids = contract
        .severity_semantics
        .iter()
        .map(|spec| spec.severity.as_str())
        .collect::<Vec<_>>();
    let unique_severity_ids = severity_ids.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(severity_ids.len(), unique_severity_ids.len());
    assert!(unique_severity_ids.contains("critical"));

    let dimensions = contract
        .troubleshooting_dimensions
        .iter()
        .map(|spec| spec.dimension.as_str())
        .collect::<BTreeSet<_>>();
    assert!(dimensions.contains("runtime_invariant"));
    assert!(dimensions.contains("contract_compliance"));
}
