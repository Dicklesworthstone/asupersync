#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::types::{
    ReactHookDiagnosticEvent, ReactHookKind, ReactHookPhase, ReactProviderConfig,
    ReactProviderPhase, ReactProviderState, WasmAbiCancellation, WasmAbiErrorCode, WasmAbiFailure,
    WasmAbiOutcomeEnvelope, WasmAbiRecoverability, WasmAbiSymbol, WasmAbiValue, WasmBoundaryState,
    WasmExportDispatcher, WasmHandleRef, WasmOutcomeExt, WasmScopeEnterBuilder,
    WasmTaskCancelRequest, WasmTaskSpawnBuilder, validate_hook_transition,
};
use std::{collections::BTreeMap, path::Path};

#[test]
fn strict_mode_double_invocation_is_leak_free_and_cancel_correct() {
    let mut provider = ReactProviderState::new(ReactProviderConfig {
        strict_mode_resilient: true,
        devtools_diagnostics: true,
        ..Default::default()
    });

    let mut expected_cancel_events = 0usize;
    let mut expected_join_events = 0usize;

    for cycle in 0..2 {
        provider.mount().expect("mount should succeed");
        let root_scope = provider
            .root_scope_handle()
            .expect("root scope must exist after mount");
        let child_scope = provider
            .create_child_scope(Some("strict-child"))
            .expect("child scope must be creatable when ready");

        let root_task = provider
            .spawn_task(root_scope, Some("strict-root-task"))
            .expect("root task spawn should succeed");
        let child_task = provider
            .spawn_task(child_scope, Some("strict-child-task"))
            .expect("child task spawn should succeed");

        // Mixed outcomes: one task completes normally before cleanup.
        provider
            .complete_task(
                &root_task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::Unit,
                },
            )
            .expect("task completion should succeed");
        expected_join_events += 1;

        // The remaining task should be cancelled and drained during unmount.
        let _ = child_task;
        expected_cancel_events += 1;
        expected_join_events += 1;

        provider.unmount().expect("unmount should succeed");
        let snapshot = provider.snapshot();
        assert_eq!(snapshot.phase, ReactProviderPhase::Disposed);
        assert_eq!(snapshot.child_scope_count, 0);
        assert_eq!(snapshot.active_task_count, 0);

        let diagnostics = snapshot
            .dispatcher_diagnostics
            .expect("provider snapshot must include diagnostics");
        assert!(
            diagnostics.is_clean(),
            "strict mode cycle {cycle} must be leak-free: {:?}",
            diagnostics.as_log_fields()
        );
    }

    let events = provider.dispatcher().event_log().events();
    let cancel_events = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
        .collect::<Vec<_>>();
    assert_eq!(
        cancel_events.len(),
        expected_cancel_events,
        "each unmount should emit one cancel for the unfinished task"
    );
    assert!(cancel_events.iter().all(|event| {
        event.state_from == WasmBoundaryState::Active
            && event.state_to == WasmBoundaryState::Cancelling
    }));

    let join_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskJoin)
        .count();
    assert_eq!(join_count, expected_join_events);
}

#[test]
fn concurrent_render_restart_pattern_cancels_and_drains_losers() {
    let mut dispatcher = WasmExportDispatcher::new();
    let (runtime, scope) = dispatcher
        .create_scoped_runtime(Some("react-concurrent-render"), None)
        .expect("runtime/scope creation should succeed");

    let restart_count = 3usize;
    let mut current = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(scope).label("render-attempt-0"),
            None,
        )
        .expect("initial task spawn should succeed");

    for attempt in 1..=restart_count {
        dispatcher
            .task_cancel(
                &WasmTaskCancelRequest {
                    task: current,
                    kind: "dep_change".to_string(),
                    message: Some(format!("restart-{attempt}")),
                },
                None,
            )
            .expect("dep-change cancellation should succeed");

        let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
            cancellation: WasmAbiCancellation {
                kind: "dep_change".to_string(),
                phase: "completed".to_string(),
                origin_region: "react-use-task".to_string(),
                origin_task: None,
                timestamp_nanos: attempt as u64,
                message: Some(format!("restart-{attempt}")),
                truncated: false,
            },
        };

        let loser_outcome = dispatcher
            .task_join(&current, cancelled, None)
            .expect("cancelled task should join cleanly");
        assert!(loser_outcome.is_cancelled());

        current = dispatcher
            .spawn(
                WasmTaskSpawnBuilder::new(scope).label(format!("render-attempt-{attempt}")),
                None,
            )
            .expect("replacement task spawn should succeed");
    }

    let winner_outcome = dispatcher
        .task_join(
            &current,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("winner".to_string()),
            },
            None,
        )
        .expect("winner join should succeed");
    assert!(winner_outcome.is_ok());

    dispatcher
        .close_scoped_runtime(&scope, &runtime, None)
        .expect("structured teardown should succeed");
    let diagnostics = dispatcher.diagnostic_snapshot();
    assert!(
        diagnostics.is_clean(),
        "concurrent restart harness must leave no leaks: {:?}",
        diagnostics.as_log_fields()
    );

    let events = dispatcher.event_log().events();
    let spawn_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskSpawn)
        .count();
    let cancel_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
        .count();
    let join_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskJoin)
        .count();

    assert_eq!(spawn_count, restart_count + 1);
    assert_eq!(cancel_count, restart_count);
    assert_eq!(join_count, restart_count + 1);

    assert!(
        events
            .iter()
            .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
            .all(|event| {
                event.state_from == WasmBoundaryState::Active
                    && event.state_to == WasmBoundaryState::Cancelling
            })
    );
}

#[test]
fn rapid_restart_churn_keeps_event_sequence_balanced() {
    let mut dispatcher = WasmExportDispatcher::new();
    let (runtime, scope) = dispatcher
        .create_scoped_runtime(Some("react-restart-churn"), None)
        .expect("runtime/scope creation should succeed");

    let restart_count = 12usize;
    let mut current = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(scope).label("restart-churn-attempt-0"),
            None,
        )
        .expect("initial task spawn should succeed");

    for attempt in 1..=restart_count {
        dispatcher
            .task_cancel(
                &WasmTaskCancelRequest {
                    task: current,
                    kind: "render_churn".to_string(),
                    message: Some(format!("restart-churn-{attempt}")),
                },
                None,
            )
            .expect("restart-churn cancellation should succeed");

        let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
            cancellation: WasmAbiCancellation {
                kind: "render_churn".to_string(),
                phase: "completed".to_string(),
                origin_region: "react-use-task".to_string(),
                origin_task: None,
                timestamp_nanos: attempt as u64,
                message: Some(format!("restart-churn-{attempt}")),
                truncated: false,
            },
        };

        let outcome = dispatcher
            .task_join(&current, cancelled, None)
            .expect("cancelled restart-churn task should join cleanly");
        assert!(outcome.is_cancelled());

        current = dispatcher
            .spawn(
                WasmTaskSpawnBuilder::new(scope).label(format!("restart-churn-attempt-{attempt}")),
                None,
            )
            .expect("replacement task spawn should succeed");
    }

    let winner = dispatcher
        .task_join(
            &current,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("stable-winner".to_string()),
            },
            None,
        )
        .expect("final winner join should succeed");
    assert!(winner.is_ok());

    dispatcher
        .close_scoped_runtime(&scope, &runtime, None)
        .expect("structured teardown should succeed");

    let diagnostics = dispatcher.diagnostic_snapshot();
    assert!(
        diagnostics.is_clean(),
        "restart churn must leave no leaks: {:?}",
        diagnostics.as_log_fields()
    );

    let events = dispatcher.event_log().events();
    let spawn_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskSpawn)
        .count();
    let cancel_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
        .count();
    let join_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskJoin)
        .count();

    assert_eq!(spawn_count, restart_count + 1);
    assert_eq!(cancel_count, restart_count);
    assert_eq!(join_count, restart_count + 1);

    let mut pending_cancelled_joins = 0usize;
    for event in events {
        if event.symbol == WasmAbiSymbol::TaskCancel {
            pending_cancelled_joins += 1;
        } else if event.symbol == WasmAbiSymbol::TaskJoin && pending_cancelled_joins > 0 {
            pending_cancelled_joins -= 1;
        }
    }
    assert_eq!(
        pending_cancelled_joins, 0,
        "every cancel event should be balanced by a join during restart churn"
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleChaosSnapshot {
    event_signatures: Vec<String>,
    spawn_count: usize,
    cancel_count: usize,
    join_count: usize,
    pending_cancelled_joins: usize,
}

fn spawn_lifecycle_task(
    dispatcher: &mut WasmExportDispatcher,
    scope: WasmHandleRef,
    label: String,
) -> WasmHandleRef {
    dispatcher
        .spawn(WasmTaskSpawnBuilder::new(scope).label(label), None)
        .expect("lifecycle-chaos task spawn should succeed")
}

fn cancel_and_join_lifecycle_task(
    dispatcher: &mut WasmExportDispatcher,
    task: WasmHandleRef,
    phase: &str,
    correlation: &str,
) {
    dispatcher
        .task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: phase.to_string(),
                message: Some(correlation.to_string()),
            },
            None,
        )
        .expect("lifecycle chaos cancellation should succeed");

    let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: WasmAbiCancellation {
            kind: phase.to_string(),
            phase: "completed".to_string(),
            origin_region: "react-use-task".to_string(),
            origin_task: None,
            timestamp_nanos: 0,
            message: Some(correlation.to_string()),
            truncated: false,
        },
    };
    let outcome = dispatcher
        .task_join(&task, cancelled, None)
        .expect("cancelled lifecycle-chaos task should join cleanly");
    assert!(outcome.is_cancelled());
}

fn lifecycle_event_signatures(dispatcher: &WasmExportDispatcher) -> Vec<String> {
    dispatcher
        .event_log()
        .events()
        .iter()
        .map(|event| {
            format!(
                "{}:{:?}->{:?}",
                event.symbol.as_str(),
                event.state_from,
                event.state_to
            )
        })
        .collect()
}

fn lifecycle_event_counts(dispatcher: &WasmExportDispatcher) -> (usize, usize, usize, usize) {
    let events = dispatcher.event_log().events();
    let spawn_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskSpawn)
        .count();
    let cancel_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
        .count();
    let join_count = events
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskJoin)
        .count();

    let mut pending_cancelled_joins = 0usize;
    for event in events {
        if event.symbol == WasmAbiSymbol::TaskCancel {
            pending_cancelled_joins += 1;
        } else if event.symbol == WasmAbiSymbol::TaskJoin && pending_cancelled_joins > 0 {
            pending_cancelled_joins -= 1;
        }
    }
    (
        spawn_count,
        cancel_count,
        join_count,
        pending_cancelled_joins,
    )
}

fn run_lifecycle_chaos_scenario() -> LifecycleChaosSnapshot {
    let mut dispatcher = WasmExportDispatcher::new();

    let (runtime_a, scope_a) = dispatcher
        .create_scoped_runtime(Some("react-lifecycle-chaos-a"), None)
        .expect("runtime/scope A creation should succeed");

    let mut current = spawn_lifecycle_task(
        &mut dispatcher,
        scope_a,
        "lifecycle-chaos-initial".to_string(),
    );

    for (phase, kind) in [
        (
            "background_throttle",
            "react.lifecycle.background_throttle.1",
        ),
        (
            "foreground_resume_soft_nav",
            "react.lifecycle.soft_navigation.2",
        ),
        ("tab_suspend_resume", "react.lifecycle.suspend_resume.3"),
        ("hard_navigation_reset", "react.lifecycle.hard_navigation.4"),
    ] {
        cancel_and_join_lifecycle_task(&mut dispatcher, current, phase, kind);
        current =
            spawn_lifecycle_task(&mut dispatcher, scope_a, format!("lifecycle-chaos-{phase}"));
    }

    let final_cancel = WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: WasmAbiCancellation {
            kind: "hard_navigation_reset".to_string(),
            phase: "completed".to_string(),
            origin_region: "react-use-task".to_string(),
            origin_task: None,
            timestamp_nanos: 0,
            message: Some("react.lifecycle.hard_navigation.final".to_string()),
            truncated: false,
        },
    };
    let final_cancelled = dispatcher
        .task_join(&current, final_cancel, None)
        .expect("final hard-navigation cancellation should join");
    assert!(final_cancelled.is_cancelled());

    dispatcher
        .close_scoped_runtime(&scope_a, &runtime_a, None)
        .expect("structured teardown for runtime A should succeed");

    let (runtime_b, scope_b) = dispatcher
        .create_scoped_runtime(Some("react-lifecycle-chaos-b"), None)
        .expect("runtime/scope B creation should succeed");
    let resumed = spawn_lifecycle_task(&mut dispatcher, scope_b, "lifecycle-chaos-resumed".into());

    let resumed_outcome = dispatcher
        .task_join(
            &resumed,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("resumed-winner".to_string()),
            },
            None,
        )
        .expect("resumed winner should join cleanly");
    assert!(resumed_outcome.is_ok());

    dispatcher
        .close_scoped_runtime(&scope_b, &runtime_b, None)
        .expect("structured teardown for runtime B should succeed");

    let diagnostics = dispatcher.diagnostic_snapshot();
    assert!(
        diagnostics.is_clean(),
        "lifecycle chaos scenario must leave no leaks: {:?}",
        diagnostics.as_log_fields()
    );

    let (spawn_count, cancel_count, join_count, pending_cancelled_joins) =
        lifecycle_event_counts(&dispatcher);

    LifecycleChaosSnapshot {
        event_signatures: lifecycle_event_signatures(&dispatcher),
        spawn_count,
        cancel_count,
        join_count,
        pending_cancelled_joins,
    }
}

#[test]
fn lifecycle_background_throttle_suspend_resume_navigation_churn_is_deterministic() {
    let first = run_lifecycle_chaos_scenario();
    let second = run_lifecycle_chaos_scenario();

    assert_eq!(
        first, second,
        "lifecycle chaos scenario should emit deterministic event signatures"
    );
    assert_eq!(first.cancel_count, 4);
    assert_eq!(first.spawn_count, 6);
    assert_eq!(first.join_count, 6);
    assert_eq!(
        first.pending_cancelled_joins, 0,
        "every lifecycle-chaos cancellation must be drained by a join"
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactReferencePatternSnapshot {
    scenario_logs: Vec<BTreeMap<&'static str, String>>,
    event_signatures: Vec<String>,
    spawn_count: usize,
    cancel_count: usize,
    join_count: usize,
    pending_cancelled_joins: usize,
    hook_event: ReactHookDiagnosticEvent,
    hook_log: BTreeMap<&'static str, String>,
}

fn hook_kind_name(kind: ReactHookKind) -> &'static str {
    match kind {
        ReactHookKind::Scope => "scope",
        ReactHookKind::Task => "task",
        ReactHookKind::Race => "race",
        ReactHookKind::Cancellation => "cancellation",
    }
}

fn hook_phase_name(phase: ReactHookPhase) -> &'static str {
    match phase {
        ReactHookPhase::Idle => "idle",
        ReactHookPhase::Active => "active",
        ReactHookPhase::Cleanup => "cleanup",
        ReactHookPhase::Unmounted => "unmounted",
        ReactHookPhase::Error => "error",
    }
}

#[derive(Debug, Clone, Copy)]
struct PatternLogInput {
    scenario_id: &'static str,
    pattern: &'static str,
    outcome: &'static str,
    retry_attempts: u32,
    recoverable_failures: u32,
    cancel_count: usize,
    join_count: usize,
    notes: &'static str,
}

fn reference_pattern_log_fields(input: PatternLogInput) -> BTreeMap<&'static str, String> {
    let mut fields = BTreeMap::new();
    fields.insert("scenario_id", input.scenario_id.to_string());
    fields.insert("pattern", input.pattern.to_string());
    fields.insert("outcome", input.outcome.to_string());
    fields.insert("retry_attempts", input.retry_attempts.to_string());
    fields.insert(
        "recoverable_failures",
        input.recoverable_failures.to_string(),
    );
    fields.insert("cancel_count", input.cancel_count.to_string());
    fields.insert("join_count", input.join_count.to_string());
    fields.insert("notes", input.notes.to_string());
    fields
}

fn hook_event_log_fields(
    scenario_id: &'static str,
    event: &ReactHookDiagnosticEvent,
) -> BTreeMap<&'static str, String> {
    let mut fields = BTreeMap::new();
    fields.insert("scenario_id", scenario_id.to_string());
    fields.insert("pattern", "tracing_hook".to_string());
    fields.insert("hook_kind", hook_kind_name(event.hook_kind).to_string());
    fields.insert("from_phase", hook_phase_name(event.from_phase).to_string());
    fields.insert("to_phase", hook_phase_name(event.to_phase).to_string());
    fields.insert("label", event.label.clone());
    fields.insert("handles_count", event.handles.len().to_string());
    fields.insert(
        "detail",
        event.detail.clone().unwrap_or_else(|| "none".to_string()),
    );
    fields
}

fn run_task_group_cancel_pattern(
    dispatcher: &mut WasmExportDispatcher,
    root_scope: WasmHandleRef,
) -> BTreeMap<&'static str, String> {
    let task_group_scope = dispatcher
        .scope_enter(
            &WasmScopeEnterBuilder::new(root_scope)
                .label("task-group-users")
                .build(),
            None,
        )
        .expect("task-group scope should be creatable");
    let group_fast = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(task_group_scope).label("task-group-fast"),
            None,
        )
        .expect("fast task-group task should spawn");
    let group_slow = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(task_group_scope).label("task-group-slow"),
            None,
        )
        .expect("slow task-group task should spawn");
    dispatcher
        .task_cancel(
            &WasmTaskCancelRequest {
                task: group_slow,
                kind: "user_cancel".to_string(),
                message: Some("cancel_button".to_string()),
            },
            None,
        )
        .expect("task-group cancellation should succeed");
    let cancelled = dispatcher
        .task_join(
            &group_slow,
            WasmAbiOutcomeEnvelope::Cancelled {
                cancellation: WasmAbiCancellation {
                    kind: "user_cancel".to_string(),
                    phase: "completed".to_string(),
                    origin_region: "react-task-group".to_string(),
                    origin_task: None,
                    timestamp_nanos: 1,
                    message: Some("cancel_button".to_string()),
                    truncated: false,
                },
            },
            None,
        )
        .expect("task-group cancelled task should join");
    assert!(cancelled.is_cancelled());
    let completed = dispatcher
        .task_join(
            &group_fast,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("users-loaded".to_string()),
            },
            None,
        )
        .expect("task-group winner should join");
    assert!(completed.is_ok());
    dispatcher
        .scope_close(&task_group_scope, None)
        .expect("task-group scope should close cleanly");
    reference_pattern_log_fields(PatternLogInput {
        scenario_id: "react_ref.task_group_cancel",
        pattern: "task_group",
        outcome: "cancelled_task_drained",
        retry_attempts: 0,
        recoverable_failures: 0,
        cancel_count: 1,
        join_count: 2,
        notes: "cancel_ux_emits_task_cancel_and_drains_before_scope_close",
    })
}

fn run_retry_pattern(
    dispatcher: &mut WasmExportDispatcher,
    root_scope: WasmHandleRef,
) -> BTreeMap<&'static str, String> {
    let mut recoverable_failures = 0u32;
    for attempt in 1..=3u32 {
        let task = dispatcher
            .spawn(
                WasmTaskSpawnBuilder::new(root_scope).label(format!("retry-attempt-{attempt}")),
                None,
            )
            .expect("retry task should spawn");
        if attempt < 3 {
            recoverable_failures += 1;
            let transient = dispatcher
                .task_join(
                    &task,
                    WasmAbiOutcomeEnvelope::Err {
                        failure: WasmAbiFailure {
                            code: WasmAbiErrorCode::InternalFailure,
                            recoverability: WasmAbiRecoverability::Transient,
                            message: format!("transient-attempt-{attempt}"),
                        },
                    },
                    None,
                )
                .expect("retry attempt should resolve with transient failure");
            assert!(transient.is_err());
        } else {
            let resolved = dispatcher
                .task_join(
                    &task,
                    WasmAbiOutcomeEnvelope::Ok {
                        value: WasmAbiValue::String("resolved-after-retry".to_string()),
                    },
                    None,
                )
                .expect("final retry attempt should succeed");
            assert!(resolved.is_ok());
        }
    }
    reference_pattern_log_fields(PatternLogInput {
        scenario_id: "react_ref.retry_after_transient_failure",
        pattern: "retry",
        outcome: "resolved_after_retry",
        retry_attempts: 3,
        recoverable_failures,
        cancel_count: 0,
        join_count: 3,
        notes: "two_transient_failures_then_success",
    })
}

fn run_bulkhead_isolation_pattern(
    dispatcher: &mut WasmExportDispatcher,
    root_scope: WasmHandleRef,
) -> BTreeMap<&'static str, String> {
    let bulkhead_a = dispatcher
        .scope_enter(
            &WasmScopeEnterBuilder::new(root_scope)
                .label("bulkhead-a")
                .build(),
            None,
        )
        .expect("bulkhead A scope should be creatable");
    let bulkhead_b = dispatcher
        .scope_enter(
            &WasmScopeEnterBuilder::new(root_scope)
                .label("bulkhead-b")
                .build(),
            None,
        )
        .expect("bulkhead B scope should be creatable");
    let task_a = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(bulkhead_a).label("bulkhead-a-task"),
            None,
        )
        .expect("bulkhead A task should spawn");
    let task_b = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(bulkhead_b).label("bulkhead-b-task"),
            None,
        )
        .expect("bulkhead B task should spawn");
    dispatcher
        .task_cancel(
            &WasmTaskCancelRequest {
                task: task_a,
                kind: "bulkhead_overload".to_string(),
                message: Some("shed-a".to_string()),
            },
            None,
        )
        .expect("bulkhead A cancellation should succeed");
    let cancelled_a = dispatcher
        .task_join(
            &task_a,
            WasmAbiOutcomeEnvelope::Cancelled {
                cancellation: WasmAbiCancellation {
                    kind: "bulkhead_overload".to_string(),
                    phase: "completed".to_string(),
                    origin_region: "react-bulkhead-a".to_string(),
                    origin_task: None,
                    timestamp_nanos: 2,
                    message: Some("shed-a".to_string()),
                    truncated: false,
                },
            },
            None,
        )
        .expect("bulkhead A cancelled task should join");
    assert!(cancelled_a.is_cancelled());
    let completed_b = dispatcher
        .task_join(
            &task_b,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("bulkhead-b-complete".to_string()),
            },
            None,
        )
        .expect("bulkhead B task should complete");
    assert!(completed_b.is_ok());
    dispatcher
        .scope_close(&bulkhead_a, None)
        .expect("bulkhead A scope should close");
    dispatcher
        .scope_close(&bulkhead_b, None)
        .expect("bulkhead B scope should close");
    reference_pattern_log_fields(PatternLogInput {
        scenario_id: "react_ref.bulkhead_isolation",
        pattern: "bulkhead",
        outcome: "isolation_preserved",
        retry_attempts: 0,
        recoverable_failures: 0,
        cancel_count: 1,
        join_count: 2,
        notes: "bulkhead_a_cancel_does_not_block_bulkhead_b_success",
    })
}

fn build_tracing_hook_pattern(
    root_scope: WasmHandleRef,
) -> (
    ReactHookDiagnosticEvent,
    BTreeMap<&'static str, String>,
    BTreeMap<&'static str, String>,
) {
    let hook_event = ReactHookDiagnosticEvent {
        hook_kind: ReactHookKind::Task,
        label: "useTask(users.fetch)".to_string(),
        from_phase: ReactHookPhase::Active,
        to_phase: ReactHookPhase::Cleanup,
        handles: vec![root_scope],
        detail: Some("retry_after_transient_failure".to_string()),
    };
    assert!(
        validate_hook_transition(hook_event.from_phase, hook_event.to_phase).is_ok(),
        "reference tracing hook must describe a legal lifecycle transition"
    );
    let hook_log = hook_event_log_fields("react_ref.tracing_hook_transition", &hook_event);
    let scenario_log = reference_pattern_log_fields(PatternLogInput {
        scenario_id: "react_ref.tracing_hook_transition",
        pattern: "tracing_hook",
        outcome: "transition_emitted",
        retry_attempts: 0,
        recoverable_failures: 0,
        cancel_count: 0,
        join_count: 0,
        notes: "hook_event_fields_ready_for_structured_diagnostics",
    });
    (hook_event, hook_log, scenario_log)
}

fn run_reference_pattern_catalog_scenario() -> ReactReferencePatternSnapshot {
    let mut dispatcher = WasmExportDispatcher::new();
    let (runtime, root_scope) = dispatcher
        .create_scoped_runtime(Some("react-reference-catalog"), None)
        .expect("runtime/scope creation should succeed");

    let mut scenario_logs = vec![
        run_task_group_cancel_pattern(&mut dispatcher, root_scope),
        run_retry_pattern(&mut dispatcher, root_scope),
        run_bulkhead_isolation_pattern(&mut dispatcher, root_scope),
    ];
    let (hook_event, hook_log, hook_scenario_log) = build_tracing_hook_pattern(root_scope);
    scenario_logs.push(hook_scenario_log);

    dispatcher
        .close_scoped_runtime(&root_scope, &runtime, None)
        .expect("structured teardown should succeed");
    let diagnostics = dispatcher.diagnostic_snapshot();
    assert!(
        diagnostics.is_clean(),
        "reference pattern scenario must leave no leaks: {:?}",
        diagnostics.as_log_fields()
    );

    let (spawn_count, cancel_count, join_count, pending_cancelled_joins) =
        lifecycle_event_counts(&dispatcher);

    ReactReferencePatternSnapshot {
        scenario_logs,
        event_signatures: lifecycle_event_signatures(&dispatcher),
        spawn_count,
        cancel_count,
        join_count,
        pending_cancelled_joins,
        hook_event,
        hook_log,
    }
}

#[test]
fn reference_pattern_catalog_scenarios_are_deterministic_and_leak_free() {
    let first = run_reference_pattern_catalog_scenario();
    let second = run_reference_pattern_catalog_scenario();

    assert_eq!(
        first, second,
        "reference pattern catalog scenarios should be deterministic"
    );
    assert_eq!(first.spawn_count, 7);
    assert_eq!(first.cancel_count, 2);
    assert_eq!(first.join_count, 7);
    assert_eq!(
        first.pending_cancelled_joins, 0,
        "every cancellation in the reference patterns must be drained by a join"
    );

    let scenario_ids: Vec<&str> = first
        .scenario_logs
        .iter()
        .map(|fields| fields["scenario_id"].as_str())
        .collect();
    assert_eq!(
        scenario_ids,
        vec![
            "react_ref.task_group_cancel",
            "react_ref.retry_after_transient_failure",
            "react_ref.bulkhead_isolation",
            "react_ref.tracing_hook_transition"
        ]
    );
}

#[test]
fn reference_pattern_retry_metadata_tracks_failure_and_recovery_counts() {
    let snapshot = run_reference_pattern_catalog_scenario();
    let retry_log = snapshot
        .scenario_logs
        .iter()
        .find(|fields| fields["scenario_id"] == "react_ref.retry_after_transient_failure")
        .expect("retry scenario log fields should exist");
    assert_eq!(retry_log["pattern"], "retry");
    assert_eq!(retry_log["outcome"], "resolved_after_retry");
    assert_eq!(retry_log["retry_attempts"], "3");
    assert_eq!(retry_log["recoverable_failures"], "2");
    assert_eq!(retry_log["join_count"], "3");
}

#[test]
fn reference_pattern_catalog_doc_lists_scenarios_and_repro_commands() {
    let path = Path::new("docs/wasm_react_reference_patterns.md");
    assert!(path.exists(), "reference pattern catalog doc must exist");
    let doc = std::fs::read_to_string(path).expect("failed to load pattern catalog doc");
    for expected in [
        "asupersync-umelq.10.5",
        "react_ref.task_group_cancel",
        "react_ref.retry_after_transient_failure",
        "react_ref.bulkhead_isolation",
        "react_ref.tracing_hook_transition",
        "cargo test --test react_wasm_strictmode_harness -- --nocapture",
    ] {
        assert!(
            doc.contains(expected),
            "pattern catalog doc missing required token: {expected}"
        );
    }
}
