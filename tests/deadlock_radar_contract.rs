#![allow(missing_docs)]

use asupersync::lab::{
    DEADLOCK_RADAR_SCHEMA_VERSION, DeadlockRadarCandidate, DeadlockRadarEvidence,
    DeadlockRadarHazardClass, DeadlockRadarInterleavingStep, DeadlockRadarLockRank,
    DeadlockRadarProofStatus, DeadlockRadarVerdict, run_deadlock_radar,
};

fn lock_order_inversion_candidate() -> DeadlockRadarCandidate {
    DeadlockRadarCandidate::new(
        "lock-order-runtime-tasks-to-regions",
        "src/runtime/state.rs",
        DeadlockRadarEvidence::LockOrder {
            acquisitions: vec![DeadlockRadarLockRank::Tasks, DeadlockRadarLockRank::Regions],
        },
    )
    .with_source_refs(["src/runtime/state.rs:lock-order-fixture"])
    .with_interleaving([
        DeadlockRadarInterleavingStep::new(
            "task-a",
            "holds tasks_scheduler and waits for regions_table",
            ["tasks_scheduler"],
            Some("regions_table"),
            "A-rank task lock is held before attempting B-rank region lock",
        ),
        DeadlockRadarInterleavingStep::new(
            "task-b",
            "holds regions_table and waits for tasks_scheduler",
            ["regions_table"],
            Some("tasks_scheduler"),
            "opposite wait edge completes the concrete cycle",
        ),
    ])
    .with_suggested_owner_bead("asupersync-vssefs.5")
}

#[test]
fn deadlock_radar_reports_finding_only_with_concrete_interleaving() {
    let report = run_deadlock_radar(&[lock_order_inversion_candidate()]);

    assert_eq!(report.schema_version, DEADLOCK_RADAR_SCHEMA_VERSION);
    assert_eq!(report.candidates_examined, 1);
    assert_eq!(report.verdict, DeadlockRadarVerdict::Finding);
    assert_eq!(report.findings.len(), 1);
    assert!(report.false_positives.is_empty());
    assert!(report.incomplete.is_empty());

    let finding = &report.findings[0];
    assert_eq!(
        finding.hazard_class,
        DeadlockRadarHazardClass::LockOrderInversion
    );
    assert_eq!(
        finding.proof_status,
        DeadlockRadarProofStatus::ProvenInterleaving
    );
    assert_eq!(finding.interleaving.len(), 2);
    assert_eq!(
        finding.suggested_owner_bead.as_deref(),
        Some("asupersync-vssefs.5")
    );
}

#[test]
fn deadlock_radar_does_not_report_pattern_match_without_interleaving() {
    let candidate = DeadlockRadarCandidate::new(
        "counter-underflow-pattern-only",
        "src/runtime/scheduler/global_queue.rs",
        DeadlockRadarEvidence::CounterUnderflow {
            checked_decrement: false,
            saturating_decrement: false,
        },
    )
    .with_source_refs(["src/runtime/scheduler/global_queue.rs:counter-fixture"]);

    let report = run_deadlock_radar(&[candidate]);

    assert_eq!(report.verdict, DeadlockRadarVerdict::Incomplete);
    assert!(report.findings.is_empty());
    assert!(report.false_positives.is_empty());
    assert_eq!(report.incomplete.len(), 1);
    assert_eq!(
        report.incomplete[0].proof_status,
        DeadlockRadarProofStatus::Incomplete
    );
    assert!(
        report.incomplete[0]
            .reason
            .contains("lacks concrete interleaving")
    );
}

#[test]
fn deadlock_radar_classifies_consistent_lock_order_as_false_positive() {
    let candidate = DeadlockRadarCandidate::new(
        "canonical-lock-order",
        "src/sync/lock_ordering.rs",
        DeadlockRadarEvidence::LockOrder {
            acquisitions: vec![
                DeadlockRadarLockRank::Config,
                DeadlockRadarLockRank::Instrumentation,
                DeadlockRadarLockRank::Regions,
                DeadlockRadarLockRank::Tasks,
                DeadlockRadarLockRank::Obligations,
            ],
        },
    )
    .with_source_refs(["src/sync/lock_ordering.rs:LockRank"]);

    let report = run_deadlock_radar(&[candidate]);

    assert_eq!(report.verdict, DeadlockRadarVerdict::Pass);
    assert!(report.findings.is_empty());
    assert!(report.incomplete.is_empty());
    assert_eq!(report.false_positives.len(), 1);
    assert_eq!(
        report.false_positives[0].proof_status,
        DeadlockRadarProofStatus::FalsePositive
    );
    assert!(report.false_positives[0].reason.contains("E-D-B-A-C"));
}

#[test]
fn deadlock_radar_classifies_scoped_guard_drop_as_false_positive() {
    let candidate = DeadlockRadarCandidate::new(
        "scoped-guard-drop-before-await",
        "tests/runtime_no_await_while_holding_lock_audit.rs",
        DeadlockRadarEvidence::AwaitHoldingLock {
            guard_dropped_before_await: true,
        },
    )
    .with_source_refs(["tests/runtime_no_await_while_holding_lock_audit.rs"]);

    let report = run_deadlock_radar(&[candidate]);

    assert_eq!(report.verdict, DeadlockRadarVerdict::Pass);
    assert!(report.findings.is_empty());
    assert_eq!(report.false_positives.len(), 1);
    assert_eq!(
        report.false_positives[0].hazard_class,
        DeadlockRadarHazardClass::AwaitHoldingLock
    );
    assert!(report.false_positives[0].reason.contains("dropped"));
}

#[test]
fn deadlock_radar_classifies_optimistic_flag_pessimistic_lock_as_false_positive() {
    let candidate = DeadlockRadarCandidate::new(
        "optimistic-flag-pessimistic-lock",
        "src/runtime/scheduler/global_injector.rs",
        DeadlockRadarEvidence::OptimisticFlag {
            writer_requires_mut: true,
            lock_rechecks_condition: true,
            stale_false_is_safe: true,
        },
    )
    .with_source_refs(["src/runtime/scheduler/global_injector.rs:advisory-count"]);

    let report = run_deadlock_radar(&[candidate]);

    assert_eq!(report.verdict, DeadlockRadarVerdict::Pass);
    assert_eq!(report.false_positives.len(), 1);
    assert_eq!(
        report.false_positives[0].hazard_class,
        DeadlockRadarHazardClass::OptimisticFlagToctou
    );
    assert!(
        report.false_positives[0]
            .reason
            .contains("locked path is authoritative")
    );
}

#[test]
fn deadlock_radar_covers_lost_notification_true_positive_fixture() {
    let candidate = DeadlockRadarCandidate::new(
        "lost-notification-no-level-state",
        "src/sync/notify.rs",
        DeadlockRadarEvidence::LostNotification {
            level_triggered_state: false,
            waiter_registered_before_notify: false,
        },
    )
    .with_source_refs(["src/sync/notify.rs:lost-wakeup-fixture"])
    .with_interleaving([
        DeadlockRadarInterleavingStep::new(
            "producer",
            "notifies before waiter registration",
            std::iter::empty::<&str>(),
            None::<&str>,
            "notification has no stored flag",
        ),
        DeadlockRadarInterleavingStep::new(
            "consumer",
            "registers after notification and parks",
            std::iter::empty::<&str>(),
            Some("stored_notification"),
            "consumer can wait forever without level-triggered state",
        ),
    ])
    .with_suggested_owner_bead("asupersync-vssefs.5");

    let report = run_deadlock_radar(&[candidate]);

    assert_eq!(report.verdict, DeadlockRadarVerdict::Finding);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].hazard_class,
        DeadlockRadarHazardClass::LostNotification
    );
    assert_eq!(report.findings[0].interleaving.len(), 2);
}

#[test]
fn deadlock_radar_report_serializes_stable_artifact_shape() {
    let candidates = [
        lock_order_inversion_candidate(),
        DeadlockRadarCandidate::new(
            "reader-upgrade-dropped-read",
            "src/sync/rwlock.rs",
            DeadlockRadarEvidence::ReaderUpgrade {
                read_guard_dropped_before_write: true,
            },
        )
        .with_source_refs(["src/sync/rwlock.rs:try_write-fixture"]),
        DeadlockRadarCandidate::new(
            "queue-count-pattern-only",
            "src/runtime/scheduler/global_queue.rs",
            DeadlockRadarEvidence::QueuePublication {
                enqueue_before_count_publish: false,
                cancel_rolls_back_count: false,
            },
        )
        .with_source_refs(["src/runtime/scheduler/global_queue.rs:queue-count-fixture"]),
    ];

    let report = run_deadlock_radar(&candidates);
    let artifact = serde_json::to_value(&report).expect("serialize deadlock radar report");

    assert_eq!(
        artifact["schema_version"],
        serde_json::json!(DEADLOCK_RADAR_SCHEMA_VERSION)
    );
    assert_eq!(artifact["candidates_examined"], serde_json::json!(3));
    assert_eq!(artifact["verdict"], serde_json::json!("finding"));
    assert_eq!(
        artifact["findings"][0]["proof_status"],
        serde_json::json!("proven_interleaving")
    );
    assert_eq!(
        artifact["false_positives"][0]["proof_status"],
        serde_json::json!("false_positive")
    );
    assert_eq!(
        artifact["incomplete"][0]["proof_status"],
        serde_json::json!("incomplete")
    );
}
