//! Hydration-safe Next.js client bootstrap state machine.
//!
//! This module models the runtime bootstrap protocol used by client boundaries
//! in a Next.js-style application:
//! 1. `ServerRendered -> Hydrating -> Hydrated`
//! 2. Runtime initialization only after hydration
//! 3. Deterministic recovery for failures (mismatch/cancel/hot-reload)

use crate::types::{
    NextjsBootstrapPhase, NextjsBootstrapTransitionError, NextjsNavigationType,
    NextjsRenderEnvironment, validate_bootstrap_transition,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Recovery action taken after a bootstrap failure signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapRecoveryAction {
    /// No recovery action was needed.
    None,
    /// Reset to hydration and re-run client bootstrap.
    ResetToHydrating,
    /// Keep hydrated state and retry runtime initialization.
    RetryRuntimeInit,
}

/// Command applied to the bootstrap state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapCommand {
    /// Begin hydration pass.
    BeginHydration,
    /// Mark hydration complete.
    CompleteHydration,
    /// Initialize runtime once hydration is complete.
    InitializeRuntime,
    /// Runtime initialization failed with a diagnostic.
    RuntimeInitFailed {
        /// Failure detail.
        reason: String,
    },
    /// Bootstrap was interrupted by cancellation.
    CancelBootstrap {
        /// Cancellation detail.
        reason: String,
    },
    /// Hydration mismatch detected.
    HydrationMismatch {
        /// Mismatch detail.
        reason: String,
    },
    /// Apply explicit recovery to continue bootstrap.
    Recover {
        /// Recovery action to apply.
        action: BootstrapRecoveryAction,
    },
    /// Apply route navigation.
    Navigate {
        /// Navigation type.
        nav: NextjsNavigationType,
        /// New route segment.
        route_segment: String,
    },
    /// Apply a hot-reload remount cycle.
    HotReload,
    /// Apply cache revalidation while hydrated/runtime-ready.
    CacheRevalidated,
}

impl BootstrapCommand {
    fn name(&self) -> &'static str {
        match self {
            Self::BeginHydration => "begin_hydration",
            Self::CompleteHydration => "complete_hydration",
            Self::InitializeRuntime => "initialize_runtime",
            Self::RuntimeInitFailed { .. } => "runtime_init_failed",
            Self::CancelBootstrap { .. } => "cancel_bootstrap",
            Self::HydrationMismatch { .. } => "hydration_mismatch",
            Self::Recover { .. } => "recover",
            Self::Navigate { .. } => "navigate",
            Self::HotReload => "hot_reload",
            Self::CacheRevalidated => "cache_revalidated",
        }
    }
}

/// Deterministic structured event emitted after one command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapLogEvent {
    /// Command name.
    pub action: String,
    /// Phase before command.
    pub from_phase: NextjsBootstrapPhase,
    /// Phase after command.
    pub to_phase: NextjsBootstrapPhase,
    /// Environment before command.
    pub from_environment: NextjsRenderEnvironment,
    /// Environment after command.
    pub to_environment: NextjsRenderEnvironment,
    /// Active route after command.
    pub route_segment: String,
    /// Recovery action taken, if any.
    pub recovery_action: BootstrapRecoveryAction,
    /// Optional diagnostic detail.
    pub detail: Option<String>,
}

impl BootstrapLogEvent {
    /// Deterministic key-sorted fields for logging pipelines.
    #[must_use]
    pub fn as_log_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("action".to_string(), self.action.clone());
        fields.insert(
            "from_environment".to_string(),
            format!("{:?}", self.from_environment),
        );
        fields.insert("from_phase".to_string(), format!("{:?}", self.from_phase));
        fields.insert(
            "recovery_action".to_string(),
            format!("{:?}", self.recovery_action),
        );
        fields.insert("route_segment".to_string(), self.route_segment.clone());
        fields.insert(
            "to_environment".to_string(),
            format!("{:?}", self.to_environment),
        );
        fields.insert("to_phase".to_string(), format!("{:?}", self.to_phase));
        if let Some(detail) = &self.detail {
            fields.insert("detail".to_string(), detail.clone());
        }
        fields
    }
}

/// Bootstrap state snapshot for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsBootstrapSnapshot {
    /// Current bootstrap phase.
    pub phase: NextjsBootstrapPhase,
    /// Current render environment.
    pub environment: NextjsRenderEnvironment,
    /// Current route segment.
    pub route_segment: String,
    /// Whether runtime init succeeded at least once in this lifecycle.
    pub runtime_initialized: bool,
    /// Number of runtime initialization attempts.
    pub runtime_init_attempts: u32,
    /// Number of successful runtime initialization calls.
    pub runtime_init_successes: u32,
    /// Number of runtime failures observed.
    pub runtime_failure_count: u32,
    /// Number of runtime cancellations observed.
    ///
    /// Includes explicit bootstrap cancellations (`CancelBootstrap`) and
    /// deterministic scope invalidations (cache revalidation, hard navigation,
    /// hot reload) that require draining active runtime work.
    pub cancellation_count: u32,
    /// Number of hydration mismatches observed.
    pub hydration_mismatch_count: u32,
    /// Number of soft navigations observed.
    pub soft_navigation_count: u32,
    /// Number of hard navigations observed.
    pub hard_navigation_count: u32,
    /// Number of popstate navigations observed.
    pub popstate_navigation_count: u32,
    /// Number of cache revalidation events observed.
    pub cache_revalidation_count: u32,
    /// Number of runtime scope invalidations triggered by route/cache events.
    pub scope_invalidation_count: u32,
    /// Number of times invalidation required runtime re-initialization.
    pub runtime_reinit_required_count: u32,
    /// Current active runtime scope generation.
    ///
    /// Increments on each successful runtime initialization.
    pub active_scope_generation: u32,
    /// Last invalidated runtime scope generation, if any.
    pub last_invalidated_scope_generation: Option<u32>,
    /// Number of hot reload events observed.
    pub hot_reload_count: u32,
    /// Last recovery action taken.
    pub last_recovery_action: BootstrapRecoveryAction,
    /// Last error detail.
    pub last_error: Option<String>,
    /// Phase history for deterministic replay.
    pub phase_history: Vec<NextjsBootstrapPhase>,
}

/// Configuration for bootstrap behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsBootstrapConfig {
    /// Initial route segment.
    pub route_segment: String,
    /// Initial render environment.
    pub initial_environment: NextjsRenderEnvironment,
    /// Whether popstate should preserve runtime when already ready.
    pub popstate_preserves_runtime: bool,
}

impl Default for NextjsBootstrapConfig {
    fn default() -> Self {
        Self {
            route_segment: "/".to_string(),
            initial_environment: NextjsRenderEnvironment::ClientSsr,
            popstate_preserves_runtime: true,
        }
    }
}

/// Error raised by bootstrap state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NextjsBootstrapError {
    /// Core phase transition was invalid.
    #[error(transparent)]
    InvalidTransition(#[from] NextjsBootstrapTransitionError),
    /// Runtime initialization was requested outside hydrated client context.
    #[error(
        "runtime initialization requires hydrated client environment; got {environment:?} in {phase:?}"
    )]
    RuntimeUnavailable {
        /// Current environment.
        environment: NextjsRenderEnvironment,
        /// Current phase.
        phase: NextjsBootstrapPhase,
    },
    /// Command cannot execute in current phase.
    #[error("command `{command}` is invalid in phase {phase:?}")]
    InvalidCommand {
        /// Command name.
        command: &'static str,
        /// Current phase.
        phase: NextjsBootstrapPhase,
    },
}

/// Deterministic bootstrap state machine for Next.js client boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextjsBootstrapState {
    config: NextjsBootstrapConfig,
    snapshot: NextjsBootstrapSnapshot,
}

impl Default for NextjsBootstrapState {
    fn default() -> Self {
        Self::new()
    }
}

impl NextjsBootstrapState {
    /// Construct state with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(NextjsBootstrapConfig::default())
    }

    /// Construct state with explicit config.
    #[must_use]
    pub fn with_config(config: NextjsBootstrapConfig) -> Self {
        let phase = NextjsBootstrapPhase::ServerRendered;
        Self {
            snapshot: NextjsBootstrapSnapshot {
                phase,
                environment: config.initial_environment,
                route_segment: config.route_segment.clone(),
                runtime_initialized: false,
                runtime_init_attempts: 0,
                runtime_init_successes: 0,
                runtime_failure_count: 0,
                cancellation_count: 0,
                hydration_mismatch_count: 0,
                soft_navigation_count: 0,
                hard_navigation_count: 0,
                popstate_navigation_count: 0,
                cache_revalidation_count: 0,
                scope_invalidation_count: 0,
                runtime_reinit_required_count: 0,
                active_scope_generation: 0,
                last_invalidated_scope_generation: None,
                hot_reload_count: 0,
                last_recovery_action: BootstrapRecoveryAction::None,
                last_error: None,
                phase_history: vec![phase],
            },
            config,
        }
    }

    /// Return current immutable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &NextjsBootstrapSnapshot {
        &self.snapshot
    }

    /// Apply one command and return a deterministic log event.
    pub fn apply(
        &mut self,
        command: BootstrapCommand,
    ) -> Result<BootstrapLogEvent, NextjsBootstrapError> {
        let action = command.name().to_string();
        let from_phase = self.snapshot.phase;
        let from_environment = self.snapshot.environment;
        self.snapshot.last_recovery_action = BootstrapRecoveryAction::None;
        self.snapshot.last_error = None;

        let detail = match &command {
            BootstrapCommand::RuntimeInitFailed { reason }
            | BootstrapCommand::CancelBootstrap { reason }
            | BootstrapCommand::HydrationMismatch { reason } => Some(reason.clone()),
            BootstrapCommand::Navigate { nav, route_segment } => {
                Some(format!("nav={nav:?}, route={route_segment}"))
            }
            BootstrapCommand::Recover { action } => Some(format!("recover={action:?}")),
            _ => None,
        };

        self.handle_command(command)?;

        Ok(BootstrapLogEvent {
            action,
            from_phase,
            to_phase: self.snapshot.phase,
            from_environment,
            to_environment: self.snapshot.environment,
            route_segment: self.snapshot.route_segment.clone(),
            recovery_action: self.snapshot.last_recovery_action,
            detail,
        })
    }

    fn handle_command(&mut self, command: BootstrapCommand) -> Result<(), NextjsBootstrapError> {
        match command {
            BootstrapCommand::BeginHydration => self.handle_begin_hydration(),
            BootstrapCommand::CompleteHydration => self.handle_complete_hydration(),
            BootstrapCommand::InitializeRuntime => self.handle_initialize_runtime(),
            BootstrapCommand::RuntimeInitFailed { reason } => {
                self.handle_runtime_init_failed(reason)
            }
            BootstrapCommand::CancelBootstrap { reason } => {
                self.handle_cancel_bootstrap(reason);
                Ok(())
            }
            BootstrapCommand::HydrationMismatch { reason } => {
                self.handle_hydration_mismatch(reason);
                Ok(())
            }
            BootstrapCommand::Recover { action } => {
                self.apply_recovery(action);
                Ok(())
            }
            BootstrapCommand::Navigate { nav, route_segment } => {
                self.handle_navigation(nav, route_segment);
                Ok(())
            }
            BootstrapCommand::HotReload => {
                self.handle_hot_reload();
                Ok(())
            }
            BootstrapCommand::CacheRevalidated => self.handle_cache_revalidated(),
        }
    }

    fn handle_begin_hydration(&mut self) -> Result<(), NextjsBootstrapError> {
        self.transition_to(NextjsBootstrapPhase::Hydrating)
    }

    fn handle_complete_hydration(&mut self) -> Result<(), NextjsBootstrapError> {
        self.transition_to(NextjsBootstrapPhase::Hydrated)?;
        self.snapshot.environment = NextjsRenderEnvironment::ClientHydrated;
        Ok(())
    }

    fn handle_initialize_runtime(&mut self) -> Result<(), NextjsBootstrapError> {
        if self.snapshot.phase == NextjsBootstrapPhase::RuntimeReady {
            return Ok(());
        }

        if !self.snapshot.environment.supports_wasm_runtime()
            || self.snapshot.phase != NextjsBootstrapPhase::Hydrated
        {
            return Err(NextjsBootstrapError::RuntimeUnavailable {
                environment: self.snapshot.environment,
                phase: self.snapshot.phase,
            });
        }

        self.snapshot.runtime_init_attempts = self.snapshot.runtime_init_attempts.saturating_add(1);
        self.transition_to(NextjsBootstrapPhase::RuntimeReady)?;
        self.snapshot.runtime_initialized = true;
        self.snapshot.runtime_init_successes =
            self.snapshot.runtime_init_successes.saturating_add(1);
        self.snapshot.active_scope_generation =
            self.snapshot.active_scope_generation.saturating_add(1);
        Ok(())
    }

    fn handle_runtime_init_failed(&mut self, reason: String) -> Result<(), NextjsBootstrapError> {
        if self.snapshot.phase != NextjsBootstrapPhase::Hydrated {
            return Err(NextjsBootstrapError::InvalidCommand {
                command: "runtime_init_failed",
                phase: self.snapshot.phase,
            });
        }
        self.transition_to(NextjsBootstrapPhase::RuntimeFailed)?;
        self.snapshot.runtime_failure_count = self.snapshot.runtime_failure_count.saturating_add(1);
        self.snapshot.last_error = Some(reason);
        Ok(())
    }

    fn handle_cancel_bootstrap(&mut self, reason: String) {
        self.snapshot.cancellation_count = self.snapshot.cancellation_count.saturating_add(1);
        self.snapshot.runtime_failure_count = self.snapshot.runtime_failure_count.saturating_add(1);
        self.force_transition(NextjsBootstrapPhase::RuntimeFailed);
        self.snapshot.last_error = Some(reason);
    }

    fn handle_hydration_mismatch(&mut self, reason: String) {
        self.snapshot.hydration_mismatch_count =
            self.snapshot.hydration_mismatch_count.saturating_add(1);
        self.snapshot.runtime_failure_count = self.snapshot.runtime_failure_count.saturating_add(1);
        self.force_transition(NextjsBootstrapPhase::RuntimeFailed);
        self.snapshot.last_error = Some(reason);
    }

    fn handle_navigation(&mut self, nav: NextjsNavigationType, route_segment: String) {
        self.snapshot.route_segment = route_segment;
        match nav {
            NextjsNavigationType::SoftNavigation => {
                self.snapshot.soft_navigation_count =
                    self.snapshot.soft_navigation_count.saturating_add(1);
            }
            NextjsNavigationType::HardNavigation => {
                self.snapshot.hard_navigation_count =
                    self.snapshot.hard_navigation_count.saturating_add(1);
                self.invalidate_runtime_scope("hard_navigation_scope_reset");
                self.snapshot.environment = NextjsRenderEnvironment::ClientSsr;
                self.force_transition(NextjsBootstrapPhase::ServerRendered);
            }
            NextjsNavigationType::PopState => {
                self.snapshot.popstate_navigation_count =
                    self.snapshot.popstate_navigation_count.saturating_add(1);
                if !(self.config.popstate_preserves_runtime
                    && self.snapshot.phase == NextjsBootstrapPhase::RuntimeReady)
                {
                    self.invalidate_runtime_scope("popstate_scope_reset");
                    self.snapshot.environment = NextjsRenderEnvironment::ClientSsr;
                    self.force_transition(NextjsBootstrapPhase::ServerRendered);
                }
            }
        }
    }

    fn handle_hot_reload(&mut self) {
        self.snapshot.hot_reload_count = self.snapshot.hot_reload_count.saturating_add(1);
        self.invalidate_runtime_scope("hot_reload_scope_reset");
        self.snapshot.environment = NextjsRenderEnvironment::ClientSsr;
        self.force_transition(NextjsBootstrapPhase::Hydrating);
    }

    fn handle_cache_revalidated(&mut self) -> Result<(), NextjsBootstrapError> {
        if !matches!(
            self.snapshot.phase,
            NextjsBootstrapPhase::Hydrated | NextjsBootstrapPhase::RuntimeReady
        ) {
            return Err(NextjsBootstrapError::InvalidCommand {
                command: "cache_revalidated",
                phase: self.snapshot.phase,
            });
        }
        self.snapshot.cache_revalidation_count =
            self.snapshot.cache_revalidation_count.saturating_add(1);
        if self.snapshot.phase == NextjsBootstrapPhase::RuntimeReady {
            self.invalidate_runtime_scope("cache_revalidation_scope_reset");
            self.snapshot.environment = NextjsRenderEnvironment::ClientHydrated;
            self.force_transition(NextjsBootstrapPhase::Hydrated);
        }
        Ok(())
    }

    fn invalidate_runtime_scope(&mut self, reason: &str) {
        if self.snapshot.runtime_initialized {
            self.snapshot.scope_invalidation_count =
                self.snapshot.scope_invalidation_count.saturating_add(1);
            self.snapshot.runtime_reinit_required_count = self
                .snapshot
                .runtime_reinit_required_count
                .saturating_add(1);
            self.snapshot.cancellation_count = self.snapshot.cancellation_count.saturating_add(1);
            self.snapshot.last_invalidated_scope_generation =
                Some(self.snapshot.active_scope_generation);
            self.snapshot.last_error = Some(reason.to_string());
        }
        self.snapshot.runtime_initialized = false;
    }

    fn transition_to(&mut self, to: NextjsBootstrapPhase) -> Result<(), NextjsBootstrapError> {
        validate_bootstrap_transition(self.snapshot.phase, to)?;
        self.force_transition(to);
        Ok(())
    }

    fn force_transition(&mut self, to: NextjsBootstrapPhase) {
        if self.snapshot.phase != to {
            self.snapshot.phase = to;
            self.snapshot.phase_history.push(to);
        }
    }

    fn apply_recovery(&mut self, action: BootstrapRecoveryAction) {
        match action {
            BootstrapRecoveryAction::None => {}
            BootstrapRecoveryAction::ResetToHydrating => {
                self.snapshot.environment = NextjsRenderEnvironment::ClientSsr;
                self.snapshot.runtime_initialized = false;
                self.force_transition(NextjsBootstrapPhase::Hydrating);
            }
            BootstrapRecoveryAction::RetryRuntimeInit => {
                self.snapshot.environment = NextjsRenderEnvironment::ClientHydrated;
                self.force_transition(NextjsBootstrapPhase::Hydrated);
            }
        }
        self.snapshot.last_recovery_action = action;
    }
}

#[cfg(test)]
mod tests {
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
}
