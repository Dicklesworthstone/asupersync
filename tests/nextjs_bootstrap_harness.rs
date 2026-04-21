#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::types::{NextjsBootstrapPhase, NextjsNavigationType, NextjsRenderEnvironment};
use asupersync::web::{
    BootstrapCommand, BootstrapLogEvent, BootstrapRecoveryAction, NextjsBootstrapError,
    NextjsBootstrapSnapshot, NextjsBootstrapState,
};
use std::{collections::BTreeMap, path::Path};

fn bootstrap_to_ready(state: &mut NextjsBootstrapState) {
    state
        .apply(BootstrapCommand::BeginHydration)
        .expect("begin hydration");
    state
        .apply(BootstrapCommand::CompleteHydration)
        .expect("complete hydration");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("initialize runtime");
}

fn run_navigation_churn_scenario() -> NextjsBootstrapSnapshot {
    let mut state = NextjsBootstrapState::new();
    bootstrap_to_ready(&mut state);

    for iteration in 0..6 {
        if iteration % 2 == 0 {
            state
                .apply(BootstrapCommand::Navigate {
                    nav: NextjsNavigationType::SoftNavigation,
                    route_segment: format!("/soft-{iteration}"),
                })
                .expect("soft nav");
            assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeReady);
            continue;
        }

        state
            .apply(BootstrapCommand::Navigate {
                nav: NextjsNavigationType::HardNavigation,
                route_segment: format!("/hard-{iteration}"),
            })
            .expect("hard nav");
        assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::ServerRendered);

        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration after hard nav");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration after hard nav");

        if iteration % 4 == 1 {
            state
                .apply(BootstrapCommand::CancelBootstrap {
                    reason: format!("interleaved-cancel-{iteration}"),
                })
                .expect("cancel bootstrap under churn");
            assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeFailed);
            state
                .apply(BootstrapCommand::Recover {
                    action: BootstrapRecoveryAction::RetryRuntimeInit,
                })
                .expect("recover after interleaved cancel");
        }

        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("initialize runtime after churn cycle");
        assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeReady);
    }

    state
        .apply(BootstrapCommand::HydrationMismatch {
            reason: "post-churn mismatch".to_string(),
        })
        .expect("inject hydration mismatch");
    state
        .apply(BootstrapCommand::Recover {
            action: BootstrapRecoveryAction::ResetToHydrating,
        })
        .expect("recover mismatch via rehydrate");
    state
        .apply(BootstrapCommand::CompleteHydration)
        .expect("complete rehydrate after mismatch");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("initialize runtime after mismatch recovery");

    state.snapshot().clone()
}

fn run_nextjs_reference_template_scenario() -> (NextjsBootstrapSnapshot, Vec<BootstrapLogEvent>) {
    let mut state = NextjsBootstrapState::new();
    let events = vec![
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration"),
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration"),
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("initialize runtime"),
        state
            .apply(BootstrapCommand::Navigate {
                nav: NextjsNavigationType::SoftNavigation,
                route_segment: "/dashboard".to_string(),
            })
            .expect("soft navigation"),
        state
            .apply(BootstrapCommand::CacheRevalidated)
            .expect("cache revalidation at runtime-ready"),
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("re-init runtime after cache invalidation"),
        state
            .apply(BootstrapCommand::HotReload)
            .expect("hot reload"),
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration after hot reload"),
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("runtime init after hot reload"),
        state
            .apply(BootstrapCommand::Navigate {
                nav: NextjsNavigationType::HardNavigation,
                route_segment: "/checkout".to_string(),
            })
            .expect("hard navigation"),
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration after hard navigation"),
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration after hard navigation"),
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("runtime init after hard navigation"),
        state
            .apply(BootstrapCommand::CancelBootstrap {
                reason: "template-cancelled-by-user-action".to_string(),
            })
            .expect("cancel bootstrap"),
        state
            .apply(BootstrapCommand::Recover {
                action: BootstrapRecoveryAction::RetryRuntimeInit,
            })
            .expect("recover via runtime retry"),
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("runtime init after retry recovery"),
    ];

    (state.snapshot().clone(), events)
}

fn template_log_fields(
    scenario_id: &str,
    deployment_target: &str,
    event: &BootstrapLogEvent,
) -> BTreeMap<String, String> {
    let mut fields = event.as_log_fields();
    fields.insert(
        "deployment_target".to_string(),
        deployment_target.to_string(),
    );
    fields.insert("scenario_id".to_string(), scenario_id.to_string());
    fields
}

#[test]
fn ssr_to_hydration_bootstrap_flow_is_deterministic() {
    let mut first = NextjsBootstrapState::new();
    bootstrap_to_ready(&mut first);
    let first_snapshot = first.snapshot().clone();

    let mut second = NextjsBootstrapState::new();
    bootstrap_to_ready(&mut second);
    let second_snapshot = second.snapshot().clone();

    assert_eq!(first_snapshot, second_snapshot);
    assert_eq!(first_snapshot.phase, NextjsBootstrapPhase::RuntimeReady);
    assert_eq!(
        first_snapshot.environment,
        NextjsRenderEnvironment::ClientHydrated
    );
    assert_eq!(first_snapshot.runtime_init_attempts, 1);
    assert_eq!(first_snapshot.runtime_init_successes, 1);
}

#[test]
fn route_transitions_keep_or_reset_runtime_as_expected() {
    let mut state = NextjsBootstrapState::new();
    bootstrap_to_ready(&mut state);

    state
        .apply(BootstrapCommand::Navigate {
            nav: NextjsNavigationType::SoftNavigation,
            route_segment: "/dashboard".to_string(),
        })
        .expect("soft nav");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeReady);
    assert_eq!(state.snapshot().soft_navigation_count, 1);

    state
        .apply(BootstrapCommand::Navigate {
            nav: NextjsNavigationType::HardNavigation,
            route_segment: "/settings".to_string(),
        })
        .expect("hard nav");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::ServerRendered);
    assert_eq!(
        state.snapshot().environment,
        NextjsRenderEnvironment::ClientSsr
    );
    assert_eq!(state.snapshot().hard_navigation_count, 1);
    assert!(!state.snapshot().runtime_initialized);
}

#[test]
fn cancelled_bootstrap_supports_retryable_recovery_path() {
    let mut state = NextjsBootstrapState::new();
    state
        .apply(BootstrapCommand::BeginHydration)
        .expect("begin hydration");
    state
        .apply(BootstrapCommand::CompleteHydration)
        .expect("complete hydration");
    state
        .apply(BootstrapCommand::CancelBootstrap {
            reason: "interrupted navigation".to_string(),
        })
        .expect("cancel");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeFailed);
    assert_eq!(state.snapshot().cancellation_count, 1);

    state
        .apply(BootstrapCommand::Recover {
            action: BootstrapRecoveryAction::RetryRuntimeInit,
        })
        .expect("recover");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("initialize runtime after recovery");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeReady);
}

#[test]
fn hydration_mismatch_recovers_via_rehydrate_path() {
    let mut state = NextjsBootstrapState::new();
    bootstrap_to_ready(&mut state);

    state
        .apply(BootstrapCommand::HydrationMismatch {
            reason: "server/client markup drift".to_string(),
        })
        .expect("mismatch");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeFailed);

    state
        .apply(BootstrapCommand::Recover {
            action: BootstrapRecoveryAction::ResetToHydrating,
        })
        .expect("reset to hydrating");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::Hydrating);

    state
        .apply(BootstrapCommand::CompleteHydration)
        .expect("complete hydration");
    state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect("re-init runtime");
    assert_eq!(state.snapshot().phase, NextjsBootstrapPhase::RuntimeReady);
    assert_eq!(state.snapshot().hydration_mismatch_count, 1);
}

#[test]
fn cache_revalidation_before_hydration_is_rejected() {
    let mut state = NextjsBootstrapState::new();
    let err = state
        .apply(BootstrapCommand::CacheRevalidated)
        .expect_err("cache revalidation must require hydrated/ready phase");
    assert!(matches!(
        err,
        NextjsBootstrapError::InvalidCommand {
            command: "cache_revalidated",
            phase: NextjsBootstrapPhase::ServerRendered
        }
    ));
}

#[test]
fn rapid_navigation_churn_with_interleaved_recovery_remains_deterministic() {
    let first = run_navigation_churn_scenario();
    let second = run_navigation_churn_scenario();

    assert_eq!(first, second, "navigation churn path must be deterministic");
    assert_eq!(first.phase, NextjsBootstrapPhase::RuntimeReady);
    assert_eq!(first.environment, NextjsRenderEnvironment::ClientHydrated);
    assert_eq!(first.soft_navigation_count, 3);
    assert_eq!(first.hard_navigation_count, 3);
    // Includes explicit CancelBootstrap events and hard-navigation scope invalidations.
    assert_eq!(first.cancellation_count, 5);
    assert_eq!(first.hydration_mismatch_count, 1);
    assert!(
        first.runtime_init_attempts >= 5,
        "expected repeated runtime init attempts during churn"
    );
    assert_eq!(
        first.runtime_init_attempts, first.runtime_init_successes,
        "churn scenario should end with successful retries"
    );
    assert!(first.runtime_initialized);
}

#[test]
fn nextjs_reference_template_deployment_flow_is_deterministic() {
    let (first_snapshot, first_events) = run_nextjs_reference_template_scenario();
    let (second_snapshot, second_events) = run_nextjs_reference_template_scenario();

    assert_eq!(first_snapshot, second_snapshot);
    assert_eq!(first_events, second_events);

    assert_eq!(first_snapshot.phase, NextjsBootstrapPhase::RuntimeReady);
    assert_eq!(
        first_snapshot.environment,
        NextjsRenderEnvironment::ClientHydrated
    );
    assert_eq!(first_snapshot.route_segment, "/checkout");
    assert_eq!(first_snapshot.soft_navigation_count, 1);
    assert_eq!(first_snapshot.hard_navigation_count, 1);
    assert_eq!(first_snapshot.cache_revalidation_count, 1);
    assert_eq!(first_snapshot.hot_reload_count, 1);
    assert_eq!(first_snapshot.cancellation_count, 4);
    assert_eq!(first_snapshot.scope_invalidation_count, 3);
    assert_eq!(first_snapshot.runtime_reinit_required_count, 3);
    assert_eq!(first_snapshot.runtime_failure_count, 1);
    assert_eq!(first_snapshot.runtime_init_attempts, 5);
    assert_eq!(first_snapshot.runtime_init_successes, 5);
    assert!(first_snapshot.runtime_initialized);
}

#[test]
fn nextjs_reference_template_structured_logs_include_replay_metadata() {
    let (_, events) = run_nextjs_reference_template_scenario();
    assert!(
        !events.is_empty(),
        "reference template scenario must emit bootstrap log events"
    );

    let fields = template_log_fields("next_ref.template_deploy", "vercel_node", &events[0]);
    let key_order: Vec<&str> = fields.keys().map(String::as_str).collect();
    assert_eq!(
        key_order,
        vec![
            "action",
            "deployment_target",
            "from_environment",
            "from_phase",
            "recovery_action",
            "route_segment",
            "scenario_id",
            "to_environment",
            "to_phase"
        ]
    );
    assert_eq!(fields["scenario_id"], "next_ref.template_deploy");
    assert_eq!(fields["deployment_target"], "vercel_node");
    assert_eq!(fields["action"], "begin_hydration");
}

#[test]
fn nextjs_runtime_init_before_hydration_is_rejected_with_actionable_error() {
    let mut state = NextjsBootstrapState::new();
    let err = state
        .apply(BootstrapCommand::InitializeRuntime)
        .expect_err("runtime init before hydration must fail");
    assert!(matches!(
        err,
        NextjsBootstrapError::RuntimeUnavailable {
            environment: NextjsRenderEnvironment::ClientSsr,
            phase: NextjsBootstrapPhase::ServerRendered
        }
    ));
}

#[test]
fn nextjs_template_cookbook_doc_lists_scenarios_and_repro_commands() {
    let path = Path::new("docs/wasm_nextjs_template_cookbook.md");
    assert!(path.exists(), "Next.js template cookbook doc must exist");
    let doc = std::fs::read_to_string(path).expect("failed to read Next.js cookbook doc");
    for expected in [
        "asupersync-umelq.11.5",
        "next_ref.template_deploy",
        "next_ref.cache_revalidation_reinit",
        "next_ref.hard_navigation_rebootstrap",
        "next_ref.cancel_retry_runtime_init",
        "cargo test --test nextjs_bootstrap_harness -- --nocapture",
    ] {
        assert!(
            doc.contains(expected),
            "Next.js cookbook doc missing required token: {expected}"
        );
    }
}
