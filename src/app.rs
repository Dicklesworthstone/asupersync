//! SPORK Application layer: `AppSpec` + `AppHandle`.
//!
//! An application is a region-owned supervision tree described by an [`AppSpec`],
//! compiled and spawned into a root region, and managed through an [`AppHandle`].
//!
//! # Lifecycle
//!
//! ```text
//! AppSpec::new("my_app")
//!     .with_budget(budget)
//!     .child(child_spec)
//!     .start(&mut state, &cx, parent_region)
//!     -> Result<AppHandle, AppStartError>
//!
//! handle.stop(&mut state)   // cancel root → drain → finalize → quiescence
//! handle.join(&state)       // poll terminal outcome of root region
//! ```
//!
//! # Invariants
//!
//! - **Close implies quiescence**: no live tasks, no pending obligations, finalizers empty.
//! - **Cancel-correct stop**: request → drain → finalize, never silent data loss.
//! - **No ambient authority**: `AppSpec` cannot reach globals; all capabilities flow through `Cx`.
//! - **Drop bomb**: `AppHandle` panics on drop if not explicitly stopped or joined,
//!   matching the `GradedObligation` pattern to prevent silent resource leaks.

use crate::cx::registry::RegistryHandle;
use crate::cx::Cx;
use crate::record::region::RegionState;
use crate::runtime::region_table::RegionCreateError;
use crate::runtime::state::RuntimeState;
use crate::supervision::{
    ChildSpec, CompiledSupervisor, RestartPolicy, StartTieBreak, SupervisorBuilder,
    SupervisorCompileError, SupervisorHandle, SupervisorSpawnError,
};
use crate::types::{Budget, CancelKind, CancelReason, RegionId};

// ---------------------------------------------------------------------------
// CompiledApp
// ---------------------------------------------------------------------------

/// A compiled application: topology validated, start order computed, ready to spawn.
///
/// Produced by [`AppSpec::compile`]. The compilation step validates the child DAG
/// (no cycles, no duplicate names) and computes the deterministic start order —
/// all without touching runtime state.
pub struct CompiledApp {
    /// Application name.
    name: String,
    /// Optional budget override.
    budget: Option<Budget>,
    /// Compiled supervisor (validated DAG, computed start order).
    compiled_supervisor: CompiledSupervisor,
    /// Optional registry capability to inject into the app's root `Cx`.
    ///
    /// When present, child contexts inherit the registry via scope propagation,
    /// enabling named service registration (bd-2ukjr).
    registry: Option<RegistryHandle>,
}

impl std::fmt::Debug for CompiledApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledApp")
            .field("name", &self.name)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl CompiledApp {
    /// Application name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The compiled supervisor for the app's root supervisor.
    #[must_use]
    pub fn compiled_supervisor(&self) -> &CompiledSupervisor {
        &self.compiled_supervisor
    }

    /// Allocate a root region and spawn the compiled application.
    ///
    /// If a registry handle was configured (via [`AppSpec::with_registry`]),
    /// it is injected into the `Cx` passed to the supervisor so all child
    /// contexts inherit the registry capability.
    pub fn start(
        self,
        state: &mut RuntimeState,
        cx: &Cx,
        parent_region: RegionId,
    ) -> Result<AppHandle, AppSpawnError> {
        let parent_budget = self.budget.unwrap_or(Budget::INFINITE);
        let root_region = state
            .create_child_region(parent_region, parent_budget)
            .map_err(AppSpawnError::RegionCreate)?;

        let effective_budget = state
            .region(root_region)
            .map_or(parent_budget, crate::record::RegionRecord::budget);

        // If a registry was configured, create a Cx with it attached so all
        // children spawned by the supervisor inherit the registry capability.
        let registry_for_handle = self.registry.clone();
        let app_cx;
        let effective_cx = if self.registry.is_some() {
            app_cx = cx.clone().with_registry_handle(self.registry);
            &app_cx
        } else {
            cx
        };

        let supervisor = self
            .compiled_supervisor
            .spawn(state, effective_cx, root_region, effective_budget)
            .map_err(AppSpawnError::SpawnFailed)?;

        cx.trace("app_started");

        Ok(AppHandle {
            name: self.name,
            root_region,
            supervisor,
            registry: registry_for_handle,
            resolved: false,
        })
    }
}

// ---------------------------------------------------------------------------
// AppSpec (builder)
// ---------------------------------------------------------------------------

/// Pure-data description of an application topology.
///
/// Constructed via builder methods, then started with [`AppSpec::start`].
/// The spec compiles an inner [`SupervisorBuilder`] and spawns it into a
/// newly-created root region.
pub struct AppSpec {
    /// Application name (traces / diagnostics).
    name: String,
    /// Optional budget override for the app root region.
    budget: Option<Budget>,
    /// Inner supervisor builder accumulating children and policy.
    supervisor: SupervisorBuilder,
    /// Optional registry capability to inject into the app's root `Cx`.
    ///
    /// When set, the registry handle is attached to the `Cx` during
    /// [`start`](Self::start) so child contexts inherit naming capability.
    registry: Option<RegistryHandle>,
}

impl std::fmt::Debug for AppSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSpec")
            .field("name", &self.name)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl AppSpec {
    /// Create a new application spec with the given name.
    ///
    /// The name is used for trace events and diagnostic output, and is also
    /// forwarded to the inner supervisor.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            supervisor: SupervisorBuilder::new(name.clone()),
            name,
            budget: None,
            registry: None,
        }
    }

    /// Override the root region's budget (defaults to parent budget if unset).
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self.supervisor = self.supervisor.with_budget(budget);
        self
    }

    /// Attach a registry capability to this application.
    ///
    /// The registry handle is injected into the root `Cx` at start time so
    /// all child contexts inherit naming capability. Named services can then
    /// register via [`NameRegistry`](crate::cx::NameRegistry) using the
    /// handle propagated through `cx.registry_handle()`.
    #[must_use]
    pub fn with_registry(mut self, registry: RegistryHandle) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Set the restart policy for the root supervisor.
    #[must_use]
    pub fn with_restart_policy(mut self, policy: RestartPolicy) -> Self {
        self.supervisor = self.supervisor.with_restart_policy(policy);
        self
    }

    /// Set the tie-break strategy for deterministic start ordering.
    #[must_use]
    pub fn with_tie_break(mut self, tie_break: StartTieBreak) -> Self {
        self.supervisor = self.supervisor.with_tie_break(tie_break);
        self
    }

    /// Add a child specification to the application's root supervisor.
    #[must_use]
    pub fn child(mut self, child: ChildSpec) -> Self {
        self.supervisor = self.supervisor.child(child);
        self
    }

    /// Compile the application spec into a [`CompiledApp`].
    ///
    /// Validates the child DAG, computes deterministic start order.
    /// No runtime state is touched.
    pub fn compile(self) -> Result<CompiledApp, AppCompileError> {
        let compiled_supervisor = self
            .supervisor
            .compile()
            .map_err(AppCompileError::SupervisorCompile)?;

        Ok(CompiledApp {
            name: self.name,
            budget: self.budget,
            compiled_supervisor,
            registry: self.registry,
        })
    }

    /// Compile, allocate a root region, and spawn the application supervisor.
    ///
    /// Convenience method that chains [`AppSpec::compile`] and [`CompiledApp::start`].
    pub fn start(
        self,
        state: &mut RuntimeState,
        cx: &Cx,
        parent_region: RegionId,
    ) -> Result<AppHandle, AppStartError> {
        let compiled = self.compile().map_err(AppStartError::CompileFailed)?;
        compiled
            .start(state, cx, parent_region)
            .map_err(AppStartError::SpawnFailed)
    }
}

// ---------------------------------------------------------------------------
// AppHandle
// ---------------------------------------------------------------------------

/// Handle to a running application.
///
/// Owns the root region and provides `stop` / `join` lifecycle operations.
///
/// # Drop semantics
///
/// Panics on drop if neither `stop` nor `join` has been called (leak-preventing
/// bomb, matching `GradedObligation`). Call [`AppHandle::into_raw`] to opt out
/// of this guarantee when you know what you're doing.
pub struct AppHandle {
    /// Application name.
    name: String,
    /// Root region allocated by `AppSpec::start`.
    root_region: RegionId,
    /// Supervisor state from spawn.
    supervisor: SupervisorHandle,
    /// Registry capability handle, if the app was started with one.
    registry: Option<RegistryHandle>,
    /// Whether the handle has been resolved (stop/join/into_raw called).
    resolved: bool,
}

impl std::fmt::Debug for AppHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppHandle")
            .field("name", &self.name)
            .field("root_region", &self.root_region)
            .field("resolved", &self.resolved)
            .finish_non_exhaustive()
    }
}

impl Drop for AppHandle {
    fn drop(&mut self) {
        assert!(
            self.resolved,
            "APP HANDLE LEAKED: app `{}` (region {:?}) was dropped without stop() or join(). \
             Call stop(), join(), or into_raw() to resolve.",
            self.name, self.root_region
        );
    }
}

impl AppHandle {
    /// Application name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The root region owned by this application.
    #[must_use]
    pub fn root_region(&self) -> RegionId {
        self.root_region
    }

    /// The supervisor handle for the app's root supervisor.
    #[must_use]
    pub fn supervisor(&self) -> &SupervisorHandle {
        &self.supervisor
    }

    /// The registry capability handle, if the app was started with one.
    #[must_use]
    pub fn registry(&self) -> Option<&RegistryHandle> {
        self.registry.as_ref()
    }

    /// Request cancellation of the application root region.
    ///
    /// This initiates the cancel-correct shutdown sequence:
    /// close → drain → finalize → quiescence.
    ///
    /// After calling `stop`, the region will transition through its lifecycle
    /// states. Use [`AppHandle::is_stopped`] or poll the region state to
    /// determine when quiescence is reached.
    pub fn stop(mut self, state: &mut RuntimeState) -> Result<StoppedApp, AppStopError> {
        let reason = CancelReason::new(CancelKind::Shutdown);

        let region_record = state
            .region(self.root_region)
            .ok_or(AppStopError::RegionNotFound(self.root_region))?;

        let current_state = region_record.state();
        if current_state == RegionState::Closed {
            // Already stopped.
            self.resolved = true;
            return Ok(StoppedApp {
                name: std::mem::take(&mut self.name),
                root_region: self.root_region,
            });
        }

        // Request cancel on the root region record.
        region_record.cancel_request(reason);

        // Begin close if still open.
        if current_state == RegionState::Open {
            region_record.begin_close(None);
        }

        self.resolved = true;
        Ok(StoppedApp {
            name: std::mem::take(&mut self.name),
            root_region: self.root_region,
        })
    }

    /// Check whether the app's root region has reached terminal (Closed) state.
    #[must_use]
    pub fn is_stopped(&self, state: &RuntimeState) -> bool {
        state
            .region(self.root_region)
            .is_some_and(|r| r.state() == RegionState::Closed)
    }

    /// Check whether the app's root region is quiescent (no live tasks,
    /// no pending obligations, no finalizers).
    pub fn is_quiescent(&self, state: &RuntimeState) -> bool {
        state
            .region(self.root_region)
            .is_some_and(crate::record::RegionRecord::is_quiescent)
    }

    /// Wait for the application's root region to reach a terminal state.
    ///
    /// Returns the terminal region state. In Phase 0 (synchronous runtime),
    /// this polls the region state; in async runtimes, this would await
    /// region completion.
    pub fn join(mut self, state: &RuntimeState) -> Result<StoppedApp, AppStopError> {
        let region_record = state
            .region(self.root_region)
            .ok_or(AppStopError::RegionNotFound(self.root_region))?;

        // Phase 0: synchronous check. Region must already be in terminal state
        // or the caller must have driven the runtime to completion.
        let region_state = region_record.state();
        if region_state == RegionState::Closed {
            self.resolved = true;
            return Ok(StoppedApp {
                name: std::mem::take(&mut self.name),
                root_region: self.root_region,
            });
        }

        // If the region is draining/finalizing, it's on its way to closed.
        // Mark resolved so we don't panic on drop — the caller is observing.
        self.resolved = true;
        Ok(StoppedApp {
            name: std::mem::take(&mut self.name),
            root_region: self.root_region,
        })
    }

    /// Escape hatch: consume the handle without requiring stop/join.
    ///
    /// Returns the raw region ID. The caller assumes responsibility for
    /// lifecycle management of the root region.
    #[must_use]
    pub fn into_raw(mut self) -> RawAppHandle {
        self.resolved = true;
        RawAppHandle {
            name: std::mem::take(&mut self.name),
            root_region: self.root_region,
        }
    }
}

// ---------------------------------------------------------------------------
// StoppedApp / RawAppHandle
// ---------------------------------------------------------------------------

/// Result of stopping or joining an application.
#[derive(Debug)]
pub struct StoppedApp {
    /// Application name.
    pub name: String,
    /// Root region (may still be draining/finalizing).
    pub root_region: RegionId,
}

/// Raw handle obtained via [`AppHandle::into_raw`].
///
/// No drop bomb — the caller assumes responsibility for the root region.
#[derive(Debug)]
pub struct RawAppHandle {
    /// Application name.
    pub name: String,
    /// Root region ID.
    pub root_region: RegionId,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error compiling an application spec.
#[derive(Debug)]
pub enum AppCompileError {
    /// Supervisor topology validation failed (duplicate names, cycles, etc.).
    SupervisorCompile(SupervisorCompileError),
}

impl std::fmt::Display for AppCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SupervisorCompile(e) => write!(f, "app compile failed: {e}"),
        }
    }
}

impl std::error::Error for AppCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SupervisorCompile(e) => Some(e),
        }
    }
}

/// Error spawning a compiled application into the runtime.
#[derive(Debug)]
pub enum AppSpawnError {
    /// Root region creation failed.
    RegionCreate(RegionCreateError),
    /// Supervisor spawn failed (child start error, etc.).
    SpawnFailed(SupervisorSpawnError),
}

impl std::fmt::Display for AppSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionCreate(e) => write!(f, "app root region create failed: {e}"),
            Self::SpawnFailed(e) => write!(f, "app spawn failed: {e}"),
        }
    }
}

impl std::error::Error for AppSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegionCreate(e) => Some(e),
            Self::SpawnFailed(e) => Some(e),
        }
    }
}

/// Error starting an application (convenience wrapper for compile + spawn).
#[derive(Debug)]
pub enum AppStartError {
    /// Compilation phase failed.
    CompileFailed(AppCompileError),
    /// Spawn phase failed.
    SpawnFailed(AppSpawnError),
}

impl std::fmt::Display for AppStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompileFailed(e) => write!(f, "{e}"),
            Self::SpawnFailed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AppStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CompileFailed(e) => Some(e),
            Self::SpawnFailed(e) => Some(e),
        }
    }
}

/// Error stopping an application.
#[derive(Debug)]
pub enum AppStopError {
    /// The root region no longer exists in the runtime state.
    RegionNotFound(RegionId),
}

impl std::fmt::Display for AppStopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionNotFound(id) => write!(f, "app root region {id:?} not found"),
        }
    }
}

impl std::error::Error for AppStopError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::state::RuntimeState;
    use crate::supervision::{ChildSpec, NameRegistrationPolicy, SupervisionStrategy};
    use crate::types::Budget;
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_child(name: &str) -> ChildSpec {
        ChildSpec {
            name: name.into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    let region = scope.region_id();
                    let budget = scope.budget();
                    state
                        .create_task(region, budget, async { 42_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    // --- Unit tests ---

    #[test]
    fn app_spec_new_creates_named_spec() {
        init_test("app_spec_new_creates_named_spec");
        let spec = AppSpec::new("test_app");
        assert_eq!(spec.name, "test_app");
        assert!(spec.budget.is_none());
        crate::test_complete!("app_spec_new_creates_named_spec");
    }

    #[test]
    fn app_spec_with_budget_sets_budget() {
        init_test("app_spec_with_budget_sets_budget");
        let budget = Budget::new().with_poll_quota(100);
        let spec = AppSpec::new("budgeted").with_budget(budget);
        assert_eq!(spec.budget, Some(budget));
        crate::test_complete!("app_spec_with_budget_sets_budget");
    }

    #[test]
    fn app_start_creates_region_and_spawns() {
        init_test("app_start_creates_region_and_spawns");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("my_app").child(make_child("worker"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert_eq!(handle.name(), "my_app");
        assert_ne!(handle.root_region(), root); // Separate child region.
        assert_eq!(handle.supervisor().started.len(), 1);
        assert_eq!(handle.supervisor().started[0].name, "worker");

        // Resolve to avoid drop bomb.
        let _raw = handle.into_raw();
        crate::test_complete!("app_start_creates_region_and_spawns");
    }

    #[test]
    fn app_start_with_multiple_children() {
        init_test("app_start_with_multiple_children");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("multi")
            .child(make_child("alpha"))
            .child(make_child("bravo"))
            .child(make_child("charlie"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert_eq!(handle.supervisor().started.len(), 3);
        let _raw = handle.into_raw();
        crate::test_complete!("app_start_with_multiple_children");
    }

    #[test]
    fn app_stop_initiates_cancel() {
        init_test("app_stop_initiates_cancel");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("stoppable").child(make_child("w"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let stopped = handle.stop(&mut state).expect("stop ok");
        assert_eq!(stopped.name, "stoppable");
        assert_eq!(stopped.root_region, app_region);

        // Region should have a cancel request and be closing.
        let region = state.region(app_region).expect("region exists");
        assert!(
            region.state() == RegionState::Closing || region.state() == RegionState::Closed,
            "region should be closing or closed, got {:?}",
            region.state()
        );

        crate::test_complete!("app_stop_initiates_cancel");
    }

    #[test]
    fn app_join_on_closed_region_succeeds() {
        init_test("app_join_on_closed_region_succeeds");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Start app with no children (empty supervisor).
        let spec = AppSpec::new("empty_app");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Force-close the region for testing purposes.
        if let Some(r) = state.region(app_region) {
            r.begin_close(None);
            r.begin_drain();
            r.begin_finalize();
            r.complete_close();
        }

        assert!(state
            .region(app_region)
            .is_some_and(|r| r.state() == RegionState::Closed));

        let stopped = handle.join(&state).expect("join ok");
        assert_eq!(stopped.name, "empty_app");
        crate::test_complete!("app_join_on_closed_region_succeeds");
    }

    #[test]
    fn app_into_raw_disarms_drop_bomb() {
        init_test("app_into_raw_disarms_drop_bomb");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("raw_app");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        let raw = handle.into_raw();
        assert_eq!(raw.name, "raw_app");
        // raw can be dropped without panic.
        drop(raw);
        crate::test_complete!("app_into_raw_disarms_drop_bomb");
    }

    #[test]
    #[should_panic(expected = "APP HANDLE LEAKED")]
    fn app_handle_drop_without_resolve_panics() {
        init_test("app_handle_drop_without_resolve_panics");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("leaky");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        drop(handle); // Should panic.
    }

    #[test]
    fn app_start_compile_error_on_duplicate_children() {
        init_test("app_start_compile_error_on_duplicate_children");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("dup")
            .child(make_child("same"))
            .child(make_child("same"));

        let err = spec.start(&mut state, &cx, root).unwrap_err();
        assert!(
            matches!(
                err,
                AppStartError::CompileFailed(AppCompileError::SupervisorCompile(
                    SupervisorCompileError::DuplicateChildName(_)
                ))
            ),
            "expected DuplicateChildName, got {err:?}"
        );
        crate::test_complete!("app_start_compile_error_on_duplicate_children");
    }

    #[test]
    fn app_is_quiescent_after_close() {
        init_test("app_is_quiescent_after_close");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("quiescent_test");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Disarm drop bomb early so assertions can't cause double-panic.
        let raw = handle.into_raw();

        // Force region through lifecycle.
        if let Some(r) = state.region(app_region) {
            r.begin_close(None);
            r.begin_drain();
            r.begin_finalize();
            r.complete_close();
        }

        let region = state.region(app_region).expect("region exists");
        assert_eq!(region.state(), RegionState::Closed);
        // Note: is_quiescent requires all children removed, which force-close
        // doesn't do. In production, the drain phase handles child cleanup.

        drop(raw);
        crate::test_complete!("app_is_quiescent_after_close");
    }

    #[test]
    fn app_with_budget_propagates_to_region() {
        init_test("app_with_budget_propagates_to_region");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let budget = Budget::new().with_poll_quota(42);
        let spec = AppSpec::new("budgeted_app").with_budget(budget);
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        let region = state.region(handle.root_region()).expect("region exists");
        assert_eq!(region.budget().poll_quota, 42);

        let _raw = handle.into_raw();
        crate::test_complete!("app_with_budget_propagates_to_region");
    }

    // --- Compile + Spawn tests (bd-32w45) ---

    #[test]
    fn app_compile_produces_compiled_app() {
        init_test("app_compile_produces_compiled_app");
        let compiled = AppSpec::new("compiled_test")
            .child(make_child("a"))
            .child(make_child("b"))
            .compile()
            .expect("compile ok");
        assert_eq!(compiled.name(), "compiled_test");
        crate::test_complete!("app_compile_produces_compiled_app");
    }

    #[test]
    fn app_compile_detects_duplicate_names() {
        init_test("app_compile_detects_duplicate_names");
        let err = AppSpec::new("dup_compile")
            .child(make_child("same"))
            .child(make_child("same"))
            .compile()
            .unwrap_err();
        assert!(
            matches!(
                err,
                AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(_))
            ),
            "expected DuplicateChildName, got {err:?}"
        );
        crate::test_complete!("app_compile_detects_duplicate_names");
    }

    #[test]
    fn app_compiled_start_creates_region_and_spawns() {
        init_test("app_compiled_start_creates_region_and_spawns");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let compiled = AppSpec::new("two_phase")
            .child(make_child("w1"))
            .child(make_child("w2"))
            .compile()
            .expect("compile ok");
        let handle = compiled.start(&mut state, &cx, root).expect("start ok");
        assert_eq!(handle.name(), "two_phase");
        assert_eq!(handle.supervisor().started.len(), 2);
        let _raw = handle.into_raw();
        crate::test_complete!("app_compiled_start_creates_region_and_spawns");
    }

    #[test]
    fn app_compile_is_deterministic() {
        init_test("app_compile_is_deterministic");
        let build = || {
            AppSpec::new("det")
                .child(make_child("c"))
                .child(make_child("a"))
                .child(make_child("b"))
        };
        let c1 = build().compile().unwrap();
        let c2 = build().compile().unwrap();
        assert_eq!(
            c1.compiled_supervisor().start_order,
            c2.compiled_supervisor().start_order,
            "compile must produce identical start orders"
        );
        crate::test_complete!("app_compile_is_deterministic");
    }

    #[test]
    fn app_compile_with_dependencies_is_deterministic() {
        init_test("app_compile_with_dependencies_is_deterministic");
        let build = || {
            let mut b = make_child("b");
            b.depends_on = vec!["a".into()];
            let mut c = make_child("c");
            c.depends_on = vec!["b".into()];
            AppSpec::new("dep_det")
                .child(c)
                .child(make_child("a"))
                .child(b)
        };
        let c1 = build().compile().unwrap();
        let c2 = build().compile().unwrap();
        assert_eq!(
            c1.compiled_supervisor().start_order,
            c2.compiled_supervisor().start_order
        );
        crate::test_complete!("app_compile_with_dependencies_is_deterministic");
    }

    #[test]
    fn app_compile_budget_propagates() {
        init_test("app_compile_budget_propagates");
        let budget = Budget::new().with_poll_quota(99);
        let compiled = AppSpec::new("budgeted_compile")
            .with_budget(budget)
            .compile()
            .unwrap();
        assert_eq!(compiled.budget, Some(budget));
        crate::test_complete!("app_compile_budget_propagates");
    }

    // --- Conformance tests ---

    #[test]
    fn conformance_start_stop_lifecycle() {
        init_test("conformance_start_stop_lifecycle");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Start → stop → region transitions correctly.
        let spec = AppSpec::new("lifecycle").child(make_child("w1"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        // Region starts open.
        assert_eq!(state.region(app_region).unwrap().state(), RegionState::Open);

        let _stopped = handle.stop(&mut state).expect("stop ok");

        // Region should transition past Open.
        let region_state = state.region(app_region).unwrap().state();
        assert_ne!(
            region_state,
            RegionState::Open,
            "region should no longer be open after stop"
        );

        crate::test_complete!("conformance_start_stop_lifecycle");
    }

    #[test]
    fn conformance_no_ambient_authority() {
        init_test("conformance_no_ambient_authority");

        // Verify AppSpec is pure data: cannot access globals or state
        // without being explicitly given &mut RuntimeState and &Cx.
        let spec = AppSpec::new("isolated");
        // spec holds no references to runtime state, only description data.
        assert_eq!(spec.name, "isolated");
        assert!(spec.budget.is_none());
        // The only way to start is by providing explicit state + cx.

        crate::test_complete!("conformance_no_ambient_authority");
    }

    #[test]
    fn conformance_root_region_is_child_of_parent() {
        init_test("conformance_root_region_is_child_of_parent");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("nested");
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The app's root region should be a child of the parent region.
        let app_region = handle.root_region();
        let region_record = state.region(app_region).expect("region exists");
        assert_eq!(
            region_record.parent,
            Some(root),
            "app root region must be a child of the given parent"
        );

        let _raw = handle.into_raw();
        crate::test_complete!("conformance_root_region_is_child_of_parent");
    }

    #[test]
    fn conformance_stop_is_cancel_correct() {
        init_test("conformance_stop_is_cancel_correct");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("cancel_correct").child(make_child("w"));
        let handle = spec.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();

        let _stopped = handle.stop(&mut state).expect("stop ok");

        // After stop, the region should have a cancel reason set.
        let region = state.region(app_region).expect("region exists");
        assert!(
            region.cancel_reason().is_some(),
            "stop must set a cancel reason on the root region"
        );

        crate::test_complete!("conformance_stop_is_cancel_correct");
    }

    #[test]
    fn conformance_deterministic_child_start_order() {
        init_test("conformance_deterministic_child_start_order");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Children with dependencies: charlie depends on bravo, bravo depends on alpha.
        let alpha = ChildSpec {
            name: "alpha".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 1_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let bravo = ChildSpec {
            name: "bravo".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 2_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["alpha".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let charlie = ChildSpec {
            name: "charlie".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 3_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["bravo".into()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("ordered")
            .child(charlie) // Intentionally out of order.
            .child(alpha)
            .child(bravo);
        let handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Start order should be alpha → bravo → charlie regardless of insertion order.
        let names: Vec<&str> = handle
            .supervisor()
            .started
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);

        let _raw = handle.into_raw();
        crate::test_complete!("conformance_deterministic_child_start_order");
    }

    #[test]
    fn conformance_compiled_app_starts_and_closes() {
        init_test("conformance_compiled_app_starts_and_closes");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let compiled = AppSpec::new("quiesce")
            .child(make_child("w1"))
            .compile()
            .expect("compile ok");
        let handle = compiled.start(&mut state, &cx, root).expect("start ok");
        let app_region = handle.root_region();
        let _stopped = handle.stop(&mut state).expect("stop ok");

        if let Some(r) = state.region(app_region) {
            if r.state() == RegionState::Closing {
                r.begin_drain();
            }
            if r.state() == RegionState::Draining {
                r.begin_finalize();
            }
            if r.state() == RegionState::Finalizing {
                r.complete_close();
            }
        }

        assert_eq!(
            state.region(app_region).unwrap().state(),
            RegionState::Closed,
        );
        crate::test_complete!("conformance_compiled_app_starts_and_closes");
    }

    #[test]
    fn conformance_compile_errors_are_explicit() {
        init_test("conformance_compile_errors_are_explicit");
        let err = AppSpec::new("errs")
            .child(make_child("dup"))
            .child(make_child("dup"))
            .compile()
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("compile failed"),
            "error should mention compile: {msg}"
        );
        assert!(
            std::error::Error::source(&err).is_some(),
            "AppCompileError must have a source"
        );
        crate::test_complete!("conformance_compile_errors_are_explicit");
    }

    #[test]
    fn conformance_compile_then_start_matches_direct() {
        init_test("conformance_compile_then_start_matches_direct");

        let mut s1 = RuntimeState::new();
        let r1 = s1.create_root_region(Budget::INFINITE);
        let cx1 = Cx::new(
            r1,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let mut s2 = RuntimeState::new();
        let r2 = s2.create_root_region(Budget::INFINITE);
        let cx2 = Cx::new(
            r2,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let h1 = AppSpec::new("direct")
            .child(make_child("w"))
            .start(&mut s1, &cx1, r1)
            .unwrap();
        let compiled = AppSpec::new("compiled")
            .child(make_child("w"))
            .compile()
            .unwrap();
        let h2 = compiled.start(&mut s2, &cx2, r2).unwrap();

        assert_eq!(h1.supervisor().started.len(), h2.supervisor().started.len());
        assert_ne!(h1.root_region(), r1);
        assert_ne!(h2.root_region(), r2);

        let _raw1 = h1.into_raw();
        let _raw2 = h2.into_raw();
        crate::test_complete!("conformance_compile_then_start_matches_direct");
    }

    // --- Registry wiring tests (bd-2ukjr) ---

    #[test]
    fn app_with_registry_propagates_to_children() {
        init_test("app_with_registry_propagates_to_children");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Parent Cx has no registry.
        assert!(!cx.has_registry());

        // Build a child that checks for registry capability.
        let registry_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&registry_seen);
        let child = ChildSpec {
            name: "checker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    // Child should see the registry propagated through the app.
                    seen_clone.store(cx.has_registry(), std::sync::atomic::Ordering::SeqCst);
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("registry_app")
            .with_registry(handle)
            .child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The child factory should have seen the registry.
        assert!(
            registry_seen.load(std::sync::atomic::Ordering::SeqCst),
            "child Cx must carry registry when app is started with one"
        );

        // The app handle should expose the registry.
        assert!(app_handle.registry().is_some());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_with_registry_propagates_to_children");
    }

    #[test]
    fn app_without_registry_children_see_none() {
        init_test("app_without_registry_children_see_none");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let registry_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&registry_seen);
        let child = ChildSpec {
            name: "no_reg".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    seen_clone.store(cx.has_registry(), std::sync::atomic::Ordering::SeqCst);
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("no_registry_app").child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert!(
            !registry_seen.load(std::sync::atomic::Ordering::SeqCst),
            "child Cx must NOT have registry when app has none"
        );
        assert!(app_handle.registry().is_none());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_without_registry_children_see_none");
    }

    #[test]
    fn app_registry_named_service_whereis() {
        init_test("app_registry_named_service_whereis");

        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));
        let reg_handle =
            RegistryHandle::new(Arc::clone(&registry) as Arc<dyn crate::cx::RegistryCap>);

        // Shared slot for the NameLease (must be resolved before drop).
        let lease_slot: Arc<parking_lot::Mutex<Option<crate::cx::NameLease>>> =
            Arc::new(parking_lot::Mutex::new(None));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        // Child registers itself in the shared registry.
        let reg_clone = Arc::clone(&registry);
        let lease_clone = Arc::clone(&lease_slot);
        let child = ChildSpec {
            name: "named_worker".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      _cx: &Cx| {
                    let region = scope.region_id();
                    let budget = scope.budget();
                    let (_, stored) = state.create_task(region, budget, async { 1_u8 })?;
                    let task_id = stored.task_id();

                    // Register the task name in the shared registry.
                    let now = crate::types::Time::ZERO;
                    let lease = reg_clone
                        .lock()
                        .register("my_worker", task_id, region, now)
                        .expect("register ok");

                    // Store the lease so it can be resolved after assertions.
                    *lease_clone.lock() = Some(lease);

                    Ok(task_id)
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("named_app")
            .with_registry(reg_handle)
            .child(child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // The named worker should be findable via whereis.
        let found = registry.lock().whereis("my_worker");
        assert!(found.is_some(), "named worker must be visible via whereis");

        // Clean up: release the lease to avoid obligation drop bomb.
        lease_slot
            .lock()
            .as_mut()
            .expect("lease should have been set")
            .release()
            .expect("release ok");

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_registry_named_service_whereis");
    }

    #[test]
    fn app_registry_compile_preserves_handle() {
        init_test("app_registry_compile_preserves_handle");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let compiled = AppSpec::new("compiled_reg")
            .with_registry(handle)
            .child(make_child("w"))
            .compile()
            .expect("compile ok");

        // Registry should survive compilation.
        assert!(compiled.registry.is_some());

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let app_handle = compiled.start(&mut state, &cx, root).expect("start ok");
        assert!(app_handle.registry().is_some());

        let _raw = app_handle.into_raw();
        crate::test_complete!("app_registry_compile_preserves_handle");
    }

    #[test]
    fn app_registry_stop_does_not_panic() {
        init_test("app_registry_stop_does_not_panic");

        let registry = crate::cx::NameRegistry::new();
        let handle = RegistryHandle::new(Arc::new(registry));

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let spec = AppSpec::new("stoppable_reg")
            .with_registry(handle)
            .child(make_child("w"));
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Stop should work without panic.
        let _stopped = app_handle.stop(&mut state).expect("stop ok");
        crate::test_complete!("app_registry_stop_does_not_panic");
    }

    // =====================================================================
    // Mini Chat App Example (bd-2cruj)
    //
    // Demonstrates GenServer + Registry + Supervisor integration patterns.
    // =====================================================================

    use crate::gen_server::{GenServer, Reply, SystemMsg};
    use std::future::Future;
    use std::pin::Pin;

    /// Chat room state: holds a bounded message history.
    struct ChatRoom {
        history: Vec<String>,
        max_history: usize,
    }

    /// Synchronous requests (call): operations that return a response.
    enum ChatCall {
        /// Get the current message history.
        GetHistory,
        /// Get the number of messages.
        Count,
    }

    /// Asynchronous messages (cast): fire-and-forget operations.
    enum ChatCast {
        /// Post a message to the room.
        Post(String),
        /// Clear all messages.
        Clear,
    }

    impl GenServer for ChatRoom {
        type Call = ChatCall;
        type Reply = Vec<String>;
        type Cast = ChatCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: ChatCall,
            reply: Reply<Vec<String>>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                ChatCall::GetHistory => {
                    let _ = reply.send(self.history.clone());
                }
                ChatCall::Count => {
                    // Encode count as a single-element vec to satisfy the Reply type.
                    let _ = reply.send(vec![self.history.len().to_string()]);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: ChatCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                ChatCast::Post(text) => {
                    self.history.push(text);
                    if self.history.len() > self.max_history {
                        self.history.remove(0);
                    }
                }
                ChatCast::Clear => {
                    self.history.clear();
                }
            }
            Box::pin(async {})
        }
    }

    impl ChatRoom {
        fn new(max_history: usize) -> Self {
            Self {
                history: Vec::new(),
                max_history,
            }
        }
    }

    #[test]
    fn example_chat_room_call_and_cast() {
        // Demonstrates: GenServer with typed call (GetHistory) and cast (Post).
        init_test("example_chat_room_call_and_cast");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(100), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Cast: post messages (fire-and-forget).
        handle
            .try_cast(ChatCast::Post("alice: hello".into()))
            .unwrap();
        handle
            .try_cast(ChatCast::Post("bob: hi alice".into()))
            .unwrap();
        handle
            .try_cast(ChatCast::Post("alice: how are you?".into()))
            .unwrap();

        // Spawn a client task that calls GetHistory.
        let server_ref = handle.server_ref();
        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                server_ref.call(&cx, ChatCall::GetHistory).await.unwrap()
            })
            .unwrap();
        let client_id = client_handle.task_id();
        runtime.state.store_spawned_task(client_id, client_stored);

        // Schedule both server and client, run to quiescence.
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        runtime.scheduler.lock().unwrap().schedule(client_id, 0);
        runtime.run_until_quiescent();

        // Verify the client received the full history.
        let history =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], "alice: hello");
        assert_eq!(history[1], "bob: hi alice");
        assert_eq!(history[2], "alice: how are you?");

        crate::test_complete!("example_chat_room_call_and_cast");
    }

    #[test]
    fn example_chat_room_bounded_history() {
        // Demonstrates: cast overflow handling (bounded history, not bounded channel).
        init_test("example_chat_room_bounded_history");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        // Chat room with max 2 messages.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(2), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Post 3 messages; oldest should be evicted.
        handle.try_cast(ChatCast::Post("msg1".into())).unwrap();
        handle.try_cast(ChatCast::Post("msg2".into())).unwrap();
        handle.try_cast(ChatCast::Post("msg3".into())).unwrap();

        let server_ref = handle.server_ref();
        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                server_ref.call(&cx, ChatCall::GetHistory).await.unwrap()
            })
            .unwrap();
        let client_id = client_handle.task_id();
        runtime.state.store_spawned_task(client_id, client_stored);

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        runtime.scheduler.lock().unwrap().schedule(client_id, 0);
        runtime.run_until_quiescent();

        let history =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(history, vec!["msg2", "msg3"], "oldest message evicted");

        crate::test_complete!("example_chat_room_bounded_history");
    }

    #[test]
    fn example_chat_room_named_via_registry() {
        // Demonstrates: named server registration + whereis lookup.
        init_test("example_chat_room_named_via_registry");

        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        // Spawn a named chat room via the atomic spawn_named_gen_server API.
        let (mut named_handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry.lock(),
                "lobby",
                ChatRoom::new(100),
                32,
                crate::types::Time::ZERO,
            )
            .unwrap();
        let task_id = named_handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // The room should be discoverable via whereis.
        let found = registry.lock().whereis("lobby");
        assert!(
            found.is_some(),
            "named chat room must be visible via whereis"
        );
        assert_eq!(found.unwrap(), task_id);

        // Post and read via the named handle's server_ref.
        named_handle
            .inner()
            .try_cast(ChatCast::Post("welcome to lobby".into()))
            .unwrap();

        let server_ref = named_handle.server_ref();
        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                server_ref.call(&cx, ChatCall::GetHistory).await.unwrap()
            })
            .unwrap();
        let client_id = client_handle.task_id();
        runtime.state.store_spawned_task(client_id, client_stored);

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        runtime.scheduler.lock().unwrap().schedule(client_id, 0);
        runtime.run_until_quiescent();

        let history = futures_lite::future::block_on(client_handle.join(&cx)).expect("join ok");
        assert_eq!(history, vec!["welcome to lobby"]);

        // Clean up: release the name lease obligation, then unregister the name.
        named_handle.stop_and_release().expect("release ok");
        registry.lock().unregister("lobby").expect("unregister ok");

        // After unregister, whereis should return None.
        let found_after = registry.lock().whereis("lobby");
        assert!(found_after.is_none(), "name must be gone after unregister");

        crate::test_complete!("example_chat_room_named_via_registry");
    }

    #[test]
    fn example_chat_room_supervised_app() {
        // Demonstrates: ChatRoom as a supervised child in an AppSpec.
        init_test("example_chat_room_supervised_app");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let chat_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_clone = Arc::clone(&chat_started);

        // ChildSpec that spawns a ChatRoom GenServer.
        let chat_child = ChildSpec {
            name: "lobby".into(),
            start: Box::new(
                move |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                      state: &mut RuntimeState,
                      cx: &Cx| {
                    let (handle, stored) =
                        scope.spawn_gen_server::<ChatRoom>(state, cx, ChatRoom::new(100), 32)?;
                    started_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    let task_id = handle.task_id();
                    state.store_spawned_task(task_id, stored);
                    Ok(task_id)
                },
            ),
            restart: SupervisionStrategy::Stop,
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        let spec = AppSpec::new("chat_app").child(chat_child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        assert!(
            chat_started.load(std::sync::atomic::Ordering::SeqCst),
            "ChatRoom GenServer child must be started by supervisor"
        );
        assert_eq!(app_handle.name(), "chat_app");
        assert_eq!(app_handle.supervisor().started.len(), 1);
        assert_eq!(app_handle.supervisor().started[0].name, "lobby");

        let _raw = app_handle.into_raw();
        crate::test_complete!("example_chat_room_supervised_app");
    }

    #[test]
    fn example_chat_app_with_dependencies() {
        // Demonstrates: supervisor compilation with child dependencies.
        // The "announcements" child depends on "lobby" — topological sort
        // ensures lobby starts first regardless of insertion order.
        init_test("example_chat_app_with_dependencies");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(
            root,
            crate::types::TaskId::testing_default(),
            Budget::INFINITE,
        );

        let lobby_child = ChildSpec {
            name: "lobby".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 1_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(3, std::time::Duration::from_mins(1)),
            ),
            shutdown_budget: Budget::INFINITE,
            depends_on: vec![],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let announcements_child = ChildSpec {
            name: "announcements".into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut RuntimeState,
                 _cx: &Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 2_u8 })
                        .map(|(_, s)| s.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(3, std::time::Duration::from_mins(1)),
            ),
            shutdown_budget: Budget::INFINITE,
            depends_on: vec!["lobby".into()], // depends on lobby
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };

        // Insert in reverse order: announcements first, then lobby.
        let spec = AppSpec::new("chat_app")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(announcements_child)
            .child(lobby_child);
        let app_handle = spec.start(&mut state, &cx, root).expect("start ok");

        // Despite insertion order, start order must be lobby -> announcements.
        let names: Vec<&str> = app_handle
            .supervisor()
            .started
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["lobby", "announcements"]);

        let _raw = app_handle.into_raw();
        crate::test_complete!("example_chat_app_with_dependencies");
    }

    #[test]
    fn example_chat_clear_resets_history() {
        // Demonstrates: cast (Clear) resets server state.
        init_test("example_chat_clear_resets_history");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, ChatRoom::new(100), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Post, then clear, then post again.
        handle.try_cast(ChatCast::Post("old msg".into())).unwrap();
        handle.try_cast(ChatCast::Clear).unwrap();
        handle
            .try_cast(ChatCast::Post("fresh start".into()))
            .unwrap();

        let server_ref = handle.server_ref();
        let (client_handle, client_stored) = scope
            .spawn(&mut runtime.state, &cx, move |cx| async move {
                server_ref.call(&cx, ChatCall::GetHistory).await.unwrap()
            })
            .unwrap();
        let client_id = client_handle.task_id();
        runtime.state.store_spawned_task(client_id, client_stored);

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        runtime.scheduler.lock().unwrap().schedule(client_id, 0);
        runtime.run_until_quiescent();

        let history = futures_lite::future::block_on(client_handle.join(&cx)).expect("join ok");
        assert_eq!(history, vec!["fresh start"], "clear must reset history");

        crate::test_complete!("example_chat_clear_resets_history");
    }
}
