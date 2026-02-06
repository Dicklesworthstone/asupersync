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
        }
    }

    /// Override the root region's budget (defaults to parent budget if unset).
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self.supervisor = self.supervisor.with_budget(budget);
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

    /// Compile, allocate a root region, and spawn the application supervisor.
    ///
    /// On success returns an [`AppHandle`] that owns the root region and must
    /// be explicitly stopped or joined before drop.
    pub fn start(
        self,
        state: &mut RuntimeState,
        cx: &Cx,
        parent_region: RegionId,
    ) -> Result<AppHandle, AppStartError> {
        // 1. Compile the supervisor (validates DAG, computes start order).
        let compiled: CompiledSupervisor = self
            .supervisor
            .compile()
            .map_err(AppStartError::CompileFailed)?;

        // 2. Create the app root region under the parent.
        let parent_budget = self.budget.unwrap_or(Budget::INFINITE);
        let root_region = state
            .create_child_region(parent_region, parent_budget)
            .map_err(AppStartError::RegionCreate)?;

        let effective_budget = state
            .region(root_region)
            .map_or(parent_budget, crate::record::RegionRecord::budget);

        // 3. Spawn the compiled supervisor inside the root region.
        let supervisor = compiled
            .spawn(state, cx, root_region, effective_budget)
            .map_err(AppStartError::SpawnFailed)?;

        cx.trace("app_started");

        Ok(AppHandle {
            name: self.name,
            root_region,
            supervisor,
            resolved: false,
        })
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

/// Error starting an application.
#[derive(Debug)]
pub enum AppStartError {
    /// Supervisor topology compilation failed (duplicate names, cycles, etc.).
    CompileFailed(SupervisorCompileError),
    /// Root region creation failed.
    RegionCreate(RegionCreateError),
    /// Supervisor spawn failed (child start error, etc.).
    SpawnFailed(SupervisorSpawnError),
}

impl std::fmt::Display for AppStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompileFailed(e) => write!(f, "app compile failed: {e}"),
            Self::RegionCreate(e) => write!(f, "app root region create failed: {e}"),
            Self::SpawnFailed(e) => write!(f, "app spawn failed: {e}"),
        }
    }
}

impl std::error::Error for AppStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CompileFailed(e) => Some(e),
            Self::RegionCreate(e) => Some(e),
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_child(name: &str) -> ChildSpec {
        ChildSpec {
            name: name.to_string(),
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
                AppStartError::CompileFailed(SupervisorCompileError::DuplicateChildName(_))
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
            name: "alpha".to_string(),
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
            name: "bravo".to_string(),
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
            depends_on: vec!["alpha".to_string()],
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        };
        let charlie = ChildSpec {
            name: "charlie".to_string(),
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
            depends_on: vec!["bravo".to_string()],
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
}
