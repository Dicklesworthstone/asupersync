#![allow(missing_docs)]

use asupersync::types::wasm_abi::ErrorBoundaryAction;
use asupersync::types::{
    NextjsBootstrapPhase, NextjsNavigationType, ReactProviderConfig, ReactProviderPhase,
    ReactProviderState, SuspenseBoundaryState, TransitionTaskState, WasmAbiCancellation,
    WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope, WasmAbiRecoverability, WasmAbiSymbol,
    WasmAbiValue, WasmBoundaryState, WasmExportDispatcher, WasmTaskCancelRequest,
    WasmTaskSpawnBuilder, outcome_to_error_boundary_action, outcome_to_suspense_state,
    outcome_to_transition_state,
};
use asupersync::web::{
    BootstrapCommand, BootstrapRecoveryAction, NextjsBootstrapError, NextjsBootstrapState,
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
struct VanillaExampleSnapshot {
    spawn_count: usize,
    cancel_count: usize,
    join_count: usize,
    clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeScriptOutcomeMapping {
    case_id: &'static str,
    suspense: SuspenseBoundaryState,
    boundary: ErrorBoundaryAction,
    transition: TransitionTaskState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactExampleSnapshot {
    phase: ReactProviderPhase,
    child_scope_count: usize,
    active_task_count: usize,
    cancel_count: usize,
    join_count: usize,
    clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NextjsExampleSnapshot {
    phase: NextjsBootstrapPhase,
    runtime_init_attempts: u32,
    runtime_init_successes: u32,
    cancellation_count: u32,
    hard_navigation_count: u32,
    cache_revalidation_count: u32,
}

fn cancelled_outcome(kind: &str, message: &str) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Cancelled {
        cancellation: WasmAbiCancellation {
            kind: kind.to_string(),
            phase: "completed".to_string(),
            origin_region: "canonical-example".to_string(),
            origin_task: None,
            timestamp_nanos: 1,
            message: Some(message.to_string()),
            truncated: false,
        },
    }
}

fn transient_failure(message: &str) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::InternalFailure,
            recoverability: WasmAbiRecoverability::Transient,
            message: message.to_string(),
        },
    }
}

fn permanent_failure(message: &str) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Err {
        failure: WasmAbiFailure {
            code: WasmAbiErrorCode::CompatibilityRejected,
            recoverability: WasmAbiRecoverability::Permanent,
            message: message.to_string(),
        },
    }
}

fn run_vanilla_example_scenario() -> VanillaExampleSnapshot {
    let mut dispatcher = WasmExportDispatcher::new();
    let (runtime, scope) = dispatcher
        .create_scoped_runtime(Some("canonical-vanilla"), None)
        .expect("runtime/scope creation should succeed");

    let success_task = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(scope).label("vanilla-success"),
            None,
        )
        .expect("success task spawn should succeed");
    let success = dispatcher
        .task_join(
            &success_task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("ready".to_string()),
            },
            None,
        )
        .expect("success task join should succeed");
    assert!(matches!(success, WasmAbiOutcomeEnvelope::Ok { .. }));

    let cancelled_task = dispatcher
        .spawn(
            WasmTaskSpawnBuilder::new(scope).label("vanilla-cancel"),
            None,
        )
        .expect("cancelled task spawn should succeed");
    dispatcher
        .task_cancel(
            &WasmTaskCancelRequest {
                task: cancelled_task,
                kind: "user_abort".to_string(),
                message: Some("user cancelled example".to_string()),
            },
            None,
        )
        .expect("cancel request should succeed");

    let cancelled = dispatcher
        .task_join(
            &cancelled_task,
            cancelled_outcome("user_abort", "user cancelled example"),
            None,
        )
        .expect("cancelled task join should succeed");
    assert!(matches!(
        cancelled,
        WasmAbiOutcomeEnvelope::Cancelled { .. }
    ));

    dispatcher
        .close_scoped_runtime(&scope, &runtime, None)
        .expect("structured teardown should succeed");

    let diagnostics = dispatcher.diagnostic_snapshot();
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

    VanillaExampleSnapshot {
        spawn_count,
        cancel_count,
        join_count,
        clean: diagnostics.is_clean(),
    }
}

fn run_typescript_example_mappings() -> Vec<TypeScriptOutcomeMapping> {
    let ok = WasmAbiOutcomeEnvelope::Ok {
        value: WasmAbiValue::Unit,
    };
    let cancel = cancelled_outcome("scope_close", "scope closed by owner");
    let transient = transient_failure("transient network stall");
    let permanent = permanent_failure("incompatible ABI version");

    vec![
        TypeScriptOutcomeMapping {
            case_id: "TS-TYPE-VANILLA",
            suspense: outcome_to_suspense_state(&ok),
            boundary: outcome_to_error_boundary_action(&ok),
            transition: outcome_to_transition_state(&ok),
        },
        TypeScriptOutcomeMapping {
            case_id: "TS-TYPE-REACT",
            suspense: outcome_to_suspense_state(&transient),
            boundary: outcome_to_error_boundary_action(&transient),
            transition: outcome_to_transition_state(&transient),
        },
        TypeScriptOutcomeMapping {
            case_id: "TS-TYPE-NEXT",
            suspense: outcome_to_suspense_state(&cancel),
            boundary: outcome_to_error_boundary_action(&cancel),
            transition: outcome_to_transition_state(&cancel),
        },
        TypeScriptOutcomeMapping {
            case_id: "TS-TYPE-NEXT-FATAL",
            suspense: outcome_to_suspense_state(&permanent),
            boundary: outcome_to_error_boundary_action(&permanent),
            transition: outcome_to_transition_state(&permanent),
        },
    ]
}

fn run_react_example_scenario() -> ReactExampleSnapshot {
    let mut provider = ReactProviderState::new(ReactProviderConfig {
        strict_mode_resilient: true,
        devtools_diagnostics: true,
        ..Default::default()
    });

    provider.mount().expect("mount should succeed");
    let root_scope = provider
        .root_scope_handle()
        .expect("root scope must exist after mount");
    let child_scope = provider
        .create_child_scope(Some("canonical-react-child"))
        .expect("child scope should be creatable");

    let root_task = provider
        .spawn_task(root_scope, Some("react-success"))
        .expect("root task spawn should succeed");
    let child_task = provider
        .spawn_task(child_scope, Some("react-cancelled-on-unmount"))
        .expect("child task spawn should succeed");

    provider
        .complete_task(
            &root_task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::String("render-committed".to_string()),
            },
        )
        .expect("root task completion should succeed");

    let _ = child_task;
    provider.unmount().expect("unmount should succeed");

    let snapshot = provider.snapshot();
    let diagnostics = snapshot
        .dispatcher_diagnostics
        .expect("provider snapshot must include diagnostics");
    let events = provider.dispatcher().event_log().events();

    ReactExampleSnapshot {
        phase: snapshot.phase,
        child_scope_count: snapshot.child_scope_count,
        active_task_count: snapshot.active_task_count,
        cancel_count: events
            .iter()
            .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
            .count(),
        join_count: events
            .iter()
            .filter(|event| event.symbol == WasmAbiSymbol::TaskJoin)
            .count(),
        clean: diagnostics.is_clean(),
    }
}

fn run_nextjs_example_scenario() -> NextjsExampleSnapshot {
    let mut state = NextjsBootstrapState::new();

    state
        .apply(BootstrapCommand::BeginHydration)
        .expect("begin hydration should succeed");
    state
        .apply(BootstrapCommand::CompleteHydration)
        .expect("complete hydration should succeed");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("initial runtime init should succeed");
    state
        .apply(BootstrapCommand::Navigate {
            nav: NextjsNavigationType::SoftNavigation,
            route_segment: "/dashboard".to_string(),
        })
        .expect("soft navigation should succeed");
    state
        .apply(BootstrapCommand::CacheRevalidated)
        .expect("cache revalidation should succeed");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("runtime re-init after cache revalidation should succeed");
    state
        .apply(BootstrapCommand::Navigate {
            nav: NextjsNavigationType::HardNavigation,
            route_segment: "/checkout".to_string(),
        })
        .expect("hard navigation should succeed");
    state
        .apply(BootstrapCommand::BeginHydration)
        .expect("begin hydration after hard navigation should succeed");
    state
        .apply(BootstrapCommand::CompleteHydration)
        .expect("complete hydration after hard navigation should succeed");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("runtime init after hard navigation should succeed");
    state
        .apply(BootstrapCommand::CancelBootstrap {
            reason: "cancel-before-route-settle".to_string(),
        })
        .expect("cancel bootstrap should succeed");
    state
        .apply(BootstrapCommand::Recover {
            action: BootstrapRecoveryAction::RetryRuntimeInit,
        })
        .expect("retry recovery should succeed");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("runtime init after retry should succeed");

    let snapshot = state.snapshot().clone();
    NextjsExampleSnapshot {
        phase: snapshot.phase,
        runtime_init_attempts: snapshot.runtime_init_attempts,
        runtime_init_successes: snapshot.runtime_init_successes,
        cancellation_count: snapshot.cancellation_count,
        hard_navigation_count: snapshot.hard_navigation_count,
        cache_revalidation_count: snapshot.cache_revalidation_count,
    }
}

#[test]
fn canonical_vanilla_example_is_deterministic_and_leak_free() {
    let first = run_vanilla_example_scenario();
    let second = run_vanilla_example_scenario();
    assert_eq!(first, second);
    assert_eq!(first.spawn_count, 2);
    assert_eq!(first.cancel_count, 1);
    assert_eq!(first.join_count, 2);
    assert!(first.clean);
}

#[test]
fn canonical_typescript_example_maps_success_failure_and_cancel_paths() {
    let first = run_typescript_example_mappings();
    let second = run_typescript_example_mappings();
    assert_eq!(first, second);

    assert_eq!(first[0].case_id, "TS-TYPE-VANILLA");
    assert_eq!(first[0].suspense, SuspenseBoundaryState::Resolved);
    assert_eq!(first[0].boundary, ErrorBoundaryAction::None);
    assert_eq!(first[0].transition, TransitionTaskState::Committed);

    assert_eq!(first[1].case_id, "TS-TYPE-REACT");
    assert_eq!(first[1].suspense, SuspenseBoundaryState::ErrorRecoverable);
    assert_eq!(first[1].boundary, ErrorBoundaryAction::ShowWithRetry);
    assert_eq!(first[1].transition, TransitionTaskState::Reverted);

    assert_eq!(first[2].case_id, "TS-TYPE-NEXT");
    assert_eq!(first[2].suspense, SuspenseBoundaryState::Cancelled);
    assert_eq!(first[2].boundary, ErrorBoundaryAction::None);
    assert_eq!(first[2].transition, TransitionTaskState::Cancelled);

    assert_eq!(first[3].case_id, "TS-TYPE-NEXT-FATAL");
    assert_eq!(first[3].suspense, SuspenseBoundaryState::ErrorFatal);
    assert_eq!(first[3].boundary, ErrorBoundaryAction::ShowFatal);
    assert_eq!(first[3].transition, TransitionTaskState::Reverted);
}

#[test]
fn canonical_react_example_is_deterministic_and_cancel_correct() {
    let first = run_react_example_scenario();
    let second = run_react_example_scenario();
    assert_eq!(first, second);
    assert_eq!(first.phase, ReactProviderPhase::Disposed);
    assert_eq!(first.child_scope_count, 0);
    assert_eq!(first.active_task_count, 0);
    assert!(first.cancel_count >= 1);
    assert!(first.join_count >= 2);
    assert!(first.clean);
}

#[test]
fn canonical_nextjs_example_is_deterministic_and_recovery_safe() {
    let first = run_nextjs_example_scenario();
    let second = run_nextjs_example_scenario();
    assert_eq!(first, second);
    assert_eq!(first.phase, NextjsBootstrapPhase::RuntimeReady);
    assert!(first.runtime_init_attempts >= 4);
    assert_eq!(first.runtime_init_attempts, first.runtime_init_successes);
    assert!(first.cancellation_count >= 2);
    assert_eq!(first.hard_navigation_count, 1);
    assert_eq!(first.cache_revalidation_count, 1);
}

#[test]
fn canonical_nextjs_invalid_runtime_init_before_hydration_is_actionable() {
    let mut state = NextjsBootstrapState::new();
    let err = state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect_err("runtime init before hydration must fail");
    assert!(matches!(
        err,
        NextjsBootstrapError::RuntimeUnavailable {
            phase: NextjsBootstrapPhase::ServerRendered,
            ..
        }
    ));
}

#[test]
fn canonical_examples_doc_lists_scenarios_and_repro_commands() {
    let path = Path::new("docs/wasm_canonical_examples.md");
    assert!(path.exists(), "canonical examples doc must exist");
    let doc = std::fs::read_to_string(path).expect("failed to load canonical examples doc");

    for expected in [
        "asupersync-umelq.16.3",
        "asupersync-3qv04.9.3.1",
        "vanilla.behavior_loser_drain_replay",
        "L6-BUNDLER-VITE",
        "TS-TYPE-VANILLA",
        "react_ref.task_group_cancel",
        "next_ref.template_deploy",
        "tests/fixtures/vite-vanilla-consumer",
        "scripts/validate_vite_vanilla_consumer.sh",
        "target/e2e-results/vite_vanilla_consumer/",
        "PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh",
        "python3 scripts/run_browser_onboarding_checks.py --scenario vanilla",
        "python3 scripts/run_browser_onboarding_checks.py --scenario react",
        "python3 scripts/run_browser_onboarding_checks.py --scenario next",
        "cargo test --test react_wasm_strictmode_harness -- --nocapture",
        "cargo test --test nextjs_bootstrap_harness -- --nocapture",
    ] {
        assert!(
            doc.contains(expected),
            "canonical examples doc missing required token: {expected}"
        );
    }

    for related_doc in [
        "docs/wasm_quickstart_migration.md",
        "docs/wasm_react_reference_patterns.md",
        "docs/wasm_nextjs_template_cookbook.md",
        "docs/wasm_typescript_type_model_contract.md",
    ] {
        assert!(
            Path::new(related_doc).exists(),
            "canonical examples dependency doc missing: {related_doc}"
        );
    }
}

#[test]
fn canonical_vanilla_cancel_events_move_active_to_cancelling() {
    let mut dispatcher = WasmExportDispatcher::new();
    let (runtime, scope) = dispatcher
        .create_scoped_runtime(Some("canonical-vanilla-cancel-state"), None)
        .expect("runtime/scope creation should succeed");
    let task = dispatcher
        .spawn(WasmTaskSpawnBuilder::new(scope).label("state-check"), None)
        .expect("task spawn should succeed");

    dispatcher
        .task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "state-check".to_string(),
                message: Some("state-check-cancel".to_string()),
            },
            None,
        )
        .expect("cancel should succeed");
    dispatcher
        .task_join(
            &task,
            cancelled_outcome("state-check", "state-check-cancel"),
            None,
        )
        .expect("cancelled join should succeed");
    dispatcher
        .close_scoped_runtime(&scope, &runtime, None)
        .expect("structured teardown should succeed");

    let cancel_events = dispatcher
        .event_log()
        .events()
        .iter()
        .filter(|event| event.symbol == WasmAbiSymbol::TaskCancel)
        .collect::<Vec<_>>();
    assert_eq!(cancel_events.len(), 1);
    assert_eq!(cancel_events[0].state_from, WasmBoundaryState::Active);
    assert_eq!(cancel_events[0].state_to, WasmBoundaryState::Cancelling);
}
