    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn happy_path_server_render_to_runtime_ready() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("init runtime");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(
            snapshot.environment,
            NextjsRenderEnvironment::ClientHydrated
        );
        assert!(snapshot.runtime_initialized);
        assert_eq!(snapshot.runtime_init_attempts, 1);
        assert_eq!(snapshot.runtime_init_successes, 1);
    }

    #[test]
    fn runtime_init_is_idempotent_for_double_invoke_paths() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("first init");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("idempotent second init");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.runtime_init_attempts, 1);
        assert_eq!(snapshot.runtime_init_successes, 1);
    }

    #[test]
    fn cancellation_and_recovery_path_is_supported() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::CancelBootstrap {
                reason: "navigation interrupt".to_string(),
            })
            .expect("cancel");
        state
            .apply(BootstrapCommand::Recover {
                action: BootstrapRecoveryAction::RetryRuntimeInit,
            })
            .expect("recover");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("init after recovery");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(snapshot.cancellation_count, 1);
        assert_eq!(snapshot.runtime_failure_count, 1);
    }

    #[test]
    fn log_fields_include_required_bootstrap_dimensions() {
        let mut state = NextjsBootstrapState::new();
        let event = state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        let fields = event.as_log_fields();

        assert!(fields.contains_key("action"));
        assert!(fields.contains_key("from_phase"));
        assert!(fields.contains_key("to_phase"));
        assert!(fields.contains_key("from_environment"));
        assert!(fields.contains_key("to_environment"));
        assert!(fields.contains_key("route_segment"));
        assert!(fields.contains_key("recovery_action"));
    }

    #[test]
    fn cache_revalidation_invalidates_runtime_scope_and_requires_reinit() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("init runtime");
        assert_eq!(state.snapshot().active_scope_generation, 1);

        state
            .apply(BootstrapCommand::CacheRevalidated)
            .expect("cache revalidated");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::Hydrated);
        assert!(!snapshot.runtime_initialized);
        assert_eq!(snapshot.cache_revalidation_count, 1);
        assert_eq!(snapshot.scope_invalidation_count, 1);
        assert_eq!(snapshot.runtime_reinit_required_count, 1);
        assert_eq!(snapshot.cancellation_count, 1);
        assert_eq!(snapshot.last_invalidated_scope_generation, Some(1));

        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("re-init runtime");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(snapshot.active_scope_generation, 2);
        assert_eq!(snapshot.runtime_init_attempts, 2);
        assert_eq!(snapshot.runtime_init_successes, 2);
    }

    #[test]
    fn cache_revalidation_while_hydrated_without_runtime_does_not_invalidate_scope() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");

        state
            .apply(BootstrapCommand::CacheRevalidated)
            .expect("cache revalidated");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::Hydrated);
        assert!(!snapshot.runtime_initialized);
        assert_eq!(snapshot.cache_revalidation_count, 1);
        assert_eq!(snapshot.scope_invalidation_count, 0);
        assert_eq!(snapshot.runtime_reinit_required_count, 0);
        assert_eq!(snapshot.cancellation_count, 0);
        assert_eq!(snapshot.last_invalidated_scope_generation, None);
    }

    #[test]
    fn hard_navigation_invalidates_runtime_scope_before_reset() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("init runtime");
        assert_eq!(state.snapshot().active_scope_generation, 1);

        state
            .apply(BootstrapCommand::Navigate {
                nav: NextjsNavigationType::HardNavigation,
                route_segment: "/settings".to_string(),
            })
            .expect("hard navigation");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::ServerRendered);
        assert!(!snapshot.runtime_initialized);
        assert_eq!(snapshot.scope_invalidation_count, 1);
        assert_eq!(snapshot.runtime_reinit_required_count, 1);
        assert_eq!(snapshot.cancellation_count, 1);
        assert_eq!(snapshot.last_invalidated_scope_generation, Some(1));
    }

    #[test]
    fn explicit_cancel_after_runtime_ready_invalidates_runtime_scope() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("init runtime");

        state
            .apply(BootstrapCommand::CancelBootstrap {
                reason: "route boundary cancelled".to_string(),
            })
            .expect("cancel after runtime");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::RuntimeFailed);
        assert!(!snapshot.runtime_initialized);
        assert_eq!(snapshot.cancellation_count, 1);
        assert_eq!(snapshot.scope_invalidation_count, 1);
        assert_eq!(snapshot.runtime_reinit_required_count, 1);
        assert_eq!(snapshot.last_invalidated_scope_generation, Some(1));
        assert_eq!(
            snapshot.last_error.as_deref(),
            Some("route boundary cancelled")
        );
    }

    #[test]
    fn hydration_mismatch_after_runtime_ready_invalidates_runtime_scope() {
        let mut state = NextjsBootstrapState::new();
        state
            .apply(BootstrapCommand::BeginHydration)
            .expect("begin hydration");
        state
            .apply(BootstrapCommand::CompleteHydration)
            .expect("complete hydration");
        state
            .apply(BootstrapCommand::InitializeRuntime)
            .expect("init runtime");

        state
            .apply(BootstrapCommand::HydrationMismatch {
                reason: "client/server tree diverged".to_string(),
            })
            .expect("mismatch after runtime");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::RuntimeFailed);
        assert!(!snapshot.runtime_initialized);
        assert_eq!(snapshot.hydration_mismatch_count, 1);
        assert_eq!(snapshot.runtime_failure_count, 1);
        assert_eq!(snapshot.cancellation_count, 1);
        assert_eq!(snapshot.scope_invalidation_count, 1);
        assert_eq!(snapshot.runtime_reinit_required_count, 1);
        assert_eq!(snapshot.last_invalidated_scope_generation, Some(1));
        assert_eq!(
            snapshot.last_error.as_deref(),
            Some("client/server tree diverged")
        );
    }

    #[test]
    fn recovery_commands_require_failure_state() {
        let mut state = NextjsBootstrapState::new();
        let err = state
            .apply(BootstrapCommand::Recover {
                action: BootstrapRecoveryAction::RetryRuntimeInit,
            })
            .expect_err("fresh bootstrap state cannot recover");

        assert_eq!(
            err,
            NextjsBootstrapError::InvalidCommand {
                command: "recover",
                phase: NextjsBootstrapPhase::ServerRendered
            }
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.phase, NextjsBootstrapPhase::ServerRendered);
        assert_eq!(snapshot.environment, NextjsRenderEnvironment::ClientSsr);
        assert!(!snapshot.runtime_initialized);
        assert_eq!(snapshot.runtime_init_attempts, 0);
    }
