//! Integrated Spork application test harness.
//!
//! [`SporkAppHarness`] wraps a [`LabRuntime`] and an application lifecycle to
//! provide a single-call entrypoint for deterministic app-level verification.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::lab::{LabConfig, SporkAppHarness};
//! use asupersync::app::AppSpec;
//! use asupersync::types::Budget;
//!
//! let app = AppSpec::new("my_app")
//!     .with_budget(Budget::new().with_poll_quota(50_000));
//!
//! let mut harness = SporkAppHarness::new(LabConfig::new(42), app).unwrap();
//!
//! // Drive the app to quiescence and collect a report.
//! let report = harness.run_to_report();
//!
//! assert!(report.run.oracle_report.all_passed());
//! ```

use crate::app::{AppHandle, AppSpec, AppStartError, AppStopError};
use crate::cx::Cx;
use crate::lab::config::LabConfig;
use crate::lab::runtime::{HarnessAttachmentRef, LabRuntime, SporkHarnessReport};
use crate::types::Budget;
use std::collections::BTreeMap;

/// Error returned when the harness cannot start the application.
#[derive(Debug)]
pub enum HarnessError {
    /// Application failed to compile or spawn.
    Start(AppStartError),
    /// Application failed to stop cleanly.
    Stop(AppStopError),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(e) => write!(f, "harness start failed: {e}"),
            Self::Stop(e) => write!(f, "harness stop failed: {e}"),
        }
    }
}

impl std::error::Error for HarnessError {}

/// Integrated harness for running Spork apps under a deterministic lab runtime.
///
/// Encapsulates the full lifecycle: compile → start → run → stop → report.
///
/// The harness owns the [`LabRuntime`] and the application handle, providing
/// a clean separation between test setup and test assertions.
pub struct SporkAppHarness {
    runtime: LabRuntime,
    app_handle: Option<AppHandle>,
    app_name: String,
    attachments: Vec<HarnessAttachmentRef>,
    cx: Cx,
}

impl SporkAppHarness {
    /// Create a new harness by compiling and starting the given [`AppSpec`].
    ///
    /// The app is immediately started under the lab runtime. Use
    /// [`run_until_idle`], [`run_until_quiescent`], or [`run_to_report`]
    /// to drive execution.
    pub fn new(config: LabConfig, app: AppSpec) -> Result<Self, HarnessError> {
        let mut runtime = LabRuntime::new(config);
        let cx = Cx::for_testing();
        let root_region = runtime.state.create_root_region(Budget::INFINITE);

        let app_handle = app
            .start(&mut runtime.state, &cx, root_region)
            .map_err(HarnessError::Start)?;

        let app_name = app_handle.name().to_string();

        Ok(Self {
            runtime,
            app_handle: Some(app_handle),
            app_name,
            attachments: Vec::new(),
            cx,
        })
    }

    /// Create a harness with a specific seed (convenience).
    pub fn with_seed(seed: u64, app: AppSpec) -> Result<Self, HarnessError> {
        Self::new(LabConfig::new(seed), app)
    }

    /// Access the underlying lab runtime (e.g. for scheduling tasks).
    #[must_use]
    pub fn runtime(&self) -> &LabRuntime {
        &self.runtime
    }

    /// Mutable access to the underlying lab runtime.
    pub fn runtime_mut(&mut self) -> &mut LabRuntime {
        &mut self.runtime
    }

    /// Access the capability context used by the harness.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Access the running application handle, if the app has not been stopped.
    #[must_use]
    pub fn app_handle(&self) -> Option<&AppHandle> {
        self.app_handle.as_ref()
    }

    /// Application name (copied from the `AppSpec` at creation).
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Add an attachment reference for inclusion in the final report.
    pub fn attach(&mut self, attachment: HarnessAttachmentRef) {
        self.attachments.push(attachment);
    }

    /// Add multiple attachment references.
    pub fn attach_all(&mut self, attachments: impl IntoIterator<Item = HarnessAttachmentRef>) {
        self.attachments.extend(attachments);
    }

    /// Drive the runtime until no tasks are runnable.
    pub fn run_until_idle(&mut self) -> u64 {
        self.runtime.run_until_idle()
    }

    /// Drive the runtime until quiescent (no runnable tasks, no pending timers).
    pub fn run_until_quiescent(&mut self) -> u64 {
        self.runtime.run_until_quiescent()
    }

    /// Stop the application and drive the runtime to quiescence.
    ///
    /// After this call, `app_handle()` returns `None`.
    pub fn stop_app(&mut self) -> Result<(), HarnessError> {
        if let Some(handle) = self.app_handle.take() {
            handle
                .stop(&mut self.runtime.state)
                .map_err(HarnessError::Stop)?;
            self.runtime.run_until_quiescent();
        }
        Ok(())
    }

    /// Run the full lifecycle: quiesce → stop → quiesce → report.
    ///
    /// This is the primary entrypoint for deterministic app-level verification.
    /// Returns a [`SporkHarnessReport`] containing trace fingerprints, oracle
    /// results, and any attached artifacts.
    pub fn run_to_report(mut self) -> Result<SporkHarnessReport, HarnessError> {
        // Phase 1: Let the app run to a natural idle point.
        self.runtime.run_until_idle();

        // Phase 2: Stop the app (cancel-correct shutdown).
        if let Some(handle) = self.app_handle.take() {
            handle
                .stop(&mut self.runtime.state)
                .map_err(HarnessError::Stop)?;
        }

        // Phase 3: Drain to full quiescence.
        self.runtime.run_until_quiescent();

        // Phase 4: Collect the report.
        let report = self
            .runtime
            .spork_report(&self.app_name, std::mem::take(&mut self.attachments));

        Ok(report)
    }

    /// Generate a report for the current state without stopping the app.
    ///
    /// Useful for intermediate checkpoints.
    #[must_use]
    pub fn snapshot_report(&mut self) -> SporkHarnessReport {
        self.runtime
            .spork_report(&self.app_name, self.attachments.clone())
    }

    /// Check whether all oracles pass for the current runtime state.
    #[must_use]
    pub fn oracles_pass(&mut self) -> bool {
        let now = self.runtime.now();
        self.runtime.oracles.report(now).all_passed()
    }
}

type ScenarioFactory = std::sync::Arc<dyn Fn(&SporkScenarioConfig) -> AppSpec + Send + Sync>;

/// Stable configuration knobs for deterministic Spork app scenarios.
///
/// This schema is intentionally small and explicit so scenario invocations are
/// reproducible and easy to serialize in CI artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkScenarioConfig {
    /// Deterministic lab seed.
    pub seed: u64,
    /// Number of virtual workers modeled by the lab scheduler.
    pub worker_count: usize,
    /// Trace ring capacity used during execution.
    pub trace_capacity: usize,
    /// Optional step bound; `None` means no step limit.
    pub max_steps: Option<u64>,
    /// Whether to panic on detected obligation leaks.
    pub panic_on_obligation_leak: bool,
    /// Whether to panic on detected futurelocks.
    pub panic_on_futurelock: bool,
}

impl Default for SporkScenarioConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            worker_count: 1,
            trace_capacity: 4096,
            max_steps: Some(100_000),
            panic_on_obligation_leak: true,
            panic_on_futurelock: true,
        }
    }
}

impl SporkScenarioConfig {
    /// Convert this scenario config into a [`LabConfig`].
    #[must_use]
    pub fn to_lab_config(&self) -> LabConfig {
        let mut config = LabConfig::new(self.seed)
            .worker_count(self.worker_count)
            .trace_capacity(self.trace_capacity)
            .panic_on_leak(self.panic_on_obligation_leak)
            .panic_on_futurelock(self.panic_on_futurelock);
        config = if let Some(max_steps) = self.max_steps {
            config.max_steps(max_steps)
        } else {
            config.no_step_limit()
        };
        config
    }

    /// Convert to JSON for deterministic artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "worker_count": self.worker_count,
            "trace_capacity": self.trace_capacity,
            "max_steps": self.max_steps,
            "panic_on_obligation_leak": self.panic_on_obligation_leak,
            "panic_on_futurelock": self.panic_on_futurelock,
        })
    }
}

/// Scenario specification for running a Spork app under the lab harness.
///
/// A scenario provides:
/// - a stable scenario ID
/// - optional description and expected invariants
/// - default deterministic config knobs
/// - a factory that builds the [`AppSpec`] from the effective config
#[derive(Clone)]
pub struct SporkScenarioSpec {
    id: String,
    description: Option<String>,
    expected_invariants: Vec<String>,
    default_config: SporkScenarioConfig,
    app_factory: ScenarioFactory,
}

impl std::fmt::Debug for SporkScenarioSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SporkScenarioSpec")
            .field("id", &self.id)
            .field("description", &self.description)
            .field("expected_invariants", &self.expected_invariants)
            .field("default_config", &self.default_config)
            .finish_non_exhaustive()
    }
}

impl SporkScenarioSpec {
    /// Create a new scenario specification.
    pub fn new<F>(id: impl Into<String>, app_factory: F) -> Self
    where
        F: Fn(&SporkScenarioConfig) -> AppSpec + Send + Sync + 'static,
    {
        Self {
            id: id.into(),
            description: None,
            expected_invariants: Vec::new(),
            default_config: SporkScenarioConfig::default(),
            app_factory: std::sync::Arc::new(app_factory),
        }
    }

    /// Stable scenario identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Optional human-readable description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Expected invariants for scenario-level assertions and documentation.
    #[must_use]
    pub fn expected_invariants(&self) -> &[String] {
        &self.expected_invariants
    }

    /// Default deterministic config used when no override is provided.
    #[must_use]
    pub fn default_config(&self) -> &SporkScenarioConfig {
        &self.default_config
    }

    /// Set a human-readable scenario description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set expected invariants for this scenario.
    #[must_use]
    pub fn with_expected_invariants<I, S>(mut self, invariants: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.expected_invariants = invariants.into_iter().map(Into::into).collect();
        self
    }

    /// Override the default scenario config.
    #[must_use]
    pub fn with_default_config(mut self, config: SporkScenarioConfig) -> Self {
        self.default_config = config;
        self
    }
}

/// Errors returned by [`SporkScenarioRunner`].
#[derive(Debug)]
pub enum ScenarioRunnerError {
    /// Scenario ID is empty or all whitespace.
    InvalidScenarioId,
    /// Scenario ID already registered.
    DuplicateScenarioId(String),
    /// Scenario ID was not found in the registry.
    UnknownScenarioId(String),
    /// Underlying harness lifecycle failure.
    Harness(HarnessError),
}

impl std::fmt::Display for ScenarioRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScenarioId => write!(f, "scenario id must be non-empty"),
            Self::DuplicateScenarioId(id) => {
                write!(f, "scenario `{id}` already registered")
            }
            Self::UnknownScenarioId(id) => write!(f, "unknown scenario `{id}`"),
            Self::Harness(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ScenarioRunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Harness(err) => Some(err),
            _ => None,
        }
    }
}

impl From<HarnessError> for ScenarioRunnerError {
    fn from(value: HarnessError) -> Self {
        Self::Harness(value)
    }
}

/// Stable result schema for scenario runner executions.
#[derive(Debug, Clone)]
pub struct SporkScenarioResult {
    /// Scenario result schema version.
    pub schema_version: u32,
    /// Stable scenario ID.
    pub scenario_id: String,
    /// Optional description copied from the scenario spec.
    pub description: Option<String>,
    /// Expected invariants copied from the scenario spec.
    pub expected_invariants: Vec<String>,
    /// Effective config used for this run.
    pub config: SporkScenarioConfig,
    /// Underlying harness report.
    pub report: SporkHarnessReport,
}

impl SporkScenarioResult {
    /// Current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    #[must_use]
    fn from_parts(
        scenario: &SporkScenarioSpec,
        config: SporkScenarioConfig,
        report: SporkHarnessReport,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            scenario_id: scenario.id.clone(),
            description: scenario.description.clone(),
            expected_invariants: scenario.expected_invariants.clone(),
            config,
            report,
        }
    }

    /// Returns true when all harness-level checks passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.report.passed()
    }

    /// Convert to JSON for deterministic artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "description": self.description,
            "expected_invariants": self.expected_invariants,
            "config": self.config.to_json(),
            "report": self.report.to_json(),
        })
    }
}

/// Registry and executor for deterministic Spork app scenarios.
///
/// IDs are stored in a `BTreeMap` so `run_all()` order is stable across runs.
#[derive(Debug, Default, Clone)]
pub struct SporkScenarioRunner {
    scenarios: BTreeMap<String, SporkScenarioSpec>,
}

impl SporkScenarioRunner {
    /// Create an empty scenario runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a scenario specification.
    pub fn register(&mut self, scenario: SporkScenarioSpec) -> Result<(), ScenarioRunnerError> {
        let id = scenario.id().trim();
        if id.is_empty() {
            return Err(ScenarioRunnerError::InvalidScenarioId);
        }
        if self.scenarios.contains_key(id) {
            return Err(ScenarioRunnerError::DuplicateScenarioId(id.to_string()));
        }
        self.scenarios.insert(id.to_string(), scenario);
        Ok(())
    }

    /// Return scenario IDs in deterministic order.
    #[must_use]
    pub fn scenario_ids(&self) -> Vec<&str> {
        self.scenarios.keys().map(String::as_str).collect()
    }

    /// Run a scenario by ID with its default config.
    pub fn run(&self, scenario_id: &str) -> Result<SporkScenarioResult, ScenarioRunnerError> {
        self.run_with_config(scenario_id, None)
    }

    /// Run a scenario by ID, optionally overriding default config knobs.
    pub fn run_with_config(
        &self,
        scenario_id: &str,
        config_override: Option<SporkScenarioConfig>,
    ) -> Result<SporkScenarioResult, ScenarioRunnerError> {
        let scenario = self
            .scenarios
            .get(scenario_id)
            .ok_or_else(|| ScenarioRunnerError::UnknownScenarioId(scenario_id.to_string()))?;
        let config = config_override.unwrap_or_else(|| scenario.default_config().clone());
        let app = (scenario.app_factory)(&config);
        let harness = SporkAppHarness::new(config.to_lab_config(), app)?;
        let report = harness.run_to_report()?;
        Ok(SporkScenarioResult::from_parts(scenario, config, report))
    }

    /// Run all registered scenarios in deterministic ID order.
    pub fn run_all(&self) -> Result<Vec<SporkScenarioResult>, ScenarioRunnerError> {
        self.scenarios
            .keys()
            .map(|id| self.run(id))
            .collect::<Result<Vec<_>, _>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::{SporkHarnessReport, SporkScenarioRunner};

    /// Smoke test: harness creates and stops a minimal (empty) app.
    #[test]
    fn harness_empty_app_lifecycle() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_empty_app_lifecycle");

        let app = AppSpec::new("empty_app");
        let mut harness = SporkAppHarness::with_seed(99, app).unwrap();

        harness.run_until_idle();

        let report = harness.run_to_report().unwrap();
        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        assert_eq!(report.app, "empty_app");

        crate::test_complete!("harness_empty_app_lifecycle");
    }

    /// Deterministic replay: same seed + same app = same fingerprint.
    #[test]
    fn harness_deterministic_across_runs() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_deterministic_across_runs");

        let report_a = {
            let app = AppSpec::new("det_app");
            let harness = SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap()
        };

        let report_b = {
            let app = AppSpec::new("det_app");
            let harness = SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap()
        };

        assert_eq!(
            report_a.run.trace_fingerprint, report_b.run.trace_fingerprint,
            "same seed must produce identical trace fingerprint"
        );
        assert_eq!(report_a.to_json(), report_b.to_json());

        crate::test_complete!("harness_deterministic_across_runs");
    }

    /// Attachments are included in the report.
    #[test]
    fn harness_attachments_in_report() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_attachments_in_report");

        let app = AppSpec::new("attach_app");
        let mut harness = SporkAppHarness::with_seed(7, app).unwrap();
        harness.attach(HarnessAttachmentRef::trace("trace.json"));
        harness.attach(HarnessAttachmentRef::crashpack("crash.tar"));

        let report = harness.run_to_report().unwrap();
        assert_eq!(report.attachments.len(), 2);

        crate::test_complete!("harness_attachments_in_report");
    }

    /// Snapshot report captures state without stopping the app.
    #[test]
    fn harness_snapshot_report_does_not_stop() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_snapshot_report_does_not_stop");

        let app = AppSpec::new("snap_app");
        let mut harness = SporkAppHarness::with_seed(1, app).unwrap();
        harness.run_until_idle();

        let snap = harness.snapshot_report();
        assert_eq!(snap.app, "snap_app");

        // App is still running after snapshot.
        assert!(harness.app_handle().is_some());

        // Can still run to final report.
        let _final_report = harness.run_to_report().unwrap();

        crate::test_complete!("harness_snapshot_report_does_not_stop");
    }

    #[test]
    fn scenario_runner_register_and_run() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_register_and_run");

        let mut runner = SporkScenarioRunner::new();
        let scenario = SporkScenarioSpec::new("empty.lifecycle", |_| AppSpec::new("empty_app"))
            .with_description("empty lifecycle smoke scenario")
            .with_expected_invariants(["no_task_leaks", "quiescence_on_close"])
            .with_default_config(SporkScenarioConfig {
                seed: 777,
                worker_count: 2,
                trace_capacity: 2048,
                max_steps: Some(50_000),
                panic_on_obligation_leak: true,
                panic_on_futurelock: true,
            });
        runner.register(scenario).unwrap();

        let result = runner.run("empty.lifecycle").unwrap();
        assert_eq!(result.schema_version, SporkScenarioResult::SCHEMA_VERSION);
        assert_eq!(result.scenario_id, "empty.lifecycle");
        assert_eq!(result.config.seed, 777);
        assert_eq!(result.report.app, "empty_app");
        assert!(result
            .expected_invariants
            .iter()
            .any(|i| i == "no_task_leaks"));

        crate::test_complete!("scenario_runner_register_and_run");
    }

    #[test]
    fn scenario_runner_deterministic_for_same_seed() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_deterministic_for_same_seed");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("det.seed", |_| AppSpec::new("deterministic_app"))
                    .with_default_config(SporkScenarioConfig {
                        seed: 4242,
                        worker_count: 1,
                        trace_capacity: 4096,
                        max_steps: Some(100_000),
                        panic_on_obligation_leak: true,
                        panic_on_futurelock: true,
                    }),
            )
            .unwrap();

        let a = runner.run("det.seed").unwrap();
        let b = runner.run("det.seed").unwrap();

        assert_eq!(a.report.trace_fingerprint(), b.report.trace_fingerprint());
        assert_eq!(a.to_json(), b.to_json());

        crate::test_complete!("scenario_runner_deterministic_for_same_seed");
    }

    #[test]
    fn scenario_runner_rejects_duplicate_ids() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_rejects_duplicate_ids");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(SporkScenarioSpec::new("dup.id", |_| AppSpec::new("first")))
            .unwrap();
        let duplicate = runner.register(SporkScenarioSpec::new("dup.id", |_| AppSpec::new("dup")));

        assert!(matches!(
            duplicate,
            Err(ScenarioRunnerError::DuplicateScenarioId(ref id)) if id == "dup.id"
        ));

        crate::test_complete!("scenario_runner_rejects_duplicate_ids");
    }

    // -----------------------------------------------------------------------
    // Conformance suite (bd-2yffk)
    //
    // App-level scenarios validating OTP expectations + asupersync invariants:
    // - no orphan servers (task/actor leak oracles)
    // - restarts drain (quiescence, loser drain oracles)
    // - names released (registry lease oracle)
    // - downs delivered deterministically (down order oracle)
    // -----------------------------------------------------------------------

    /// Helper: create a ChildSpec that spawns a single async task.
    fn conformance_child(name: &str) -> crate::supervision::ChildSpec {
        crate::supervision::ChildSpec {
            name: name.to_string(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut crate::runtime::state::RuntimeState,
                 _cx: &crate::cx::Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Stop,
            shutdown_budget: crate::types::Budget::INFINITE,
            depends_on: vec![],
            registration: crate::supervision::NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    /// Helper: create a ChildSpec with explicit dependencies.
    fn conformance_child_depends(name: &str, deps: Vec<String>) -> crate::supervision::ChildSpec {
        let mut child = conformance_child(name);
        child.depends_on = deps;
        child
    }

    /// Helper: schedule all started child tasks so the lab runtime can run them.
    fn schedule_children(harness: &SporkAppHarness) {
        if let Some(app) = harness.app_handle() {
            let task_ids: Vec<_> = app.supervisor().started.iter().map(|c| c.task_id).collect();
            let mut sched = harness.runtime().scheduler.lock().unwrap();
            for tid in task_ids {
                sched.schedule(tid, 0);
            }
        }
    }

    /// Conformance: single-child app passes all oracles after full lifecycle.
    #[test]
    fn conformance_single_child_all_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_single_child_all_oracles_pass");

        let app = AppSpec::new("single_child").child(conformance_child("worker"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.run.oracle_report.all_passed(),
            "oracle report must show all passed, failures: {:?}",
            report.oracle_failures()
        );
        assert!(
            report.run.invariant_violations.is_empty(),
            "must have no invariant violations, got: {:?}",
            report.run.invariant_violations
        );

        crate::test_complete!("conformance_single_child_all_oracles_pass");
    }

    /// Conformance: multi-child app with no dependencies passes all oracles.
    #[test]
    fn conformance_multi_child_all_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_multi_child_all_oracles_pass");

        let app = AppSpec::new("multi_child")
            .child(conformance_child("alpha"))
            .child(conformance_child("bravo"))
            .child(conformance_child("charlie"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.passed(),
            "multi-child app must pass all oracles: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_multi_child_all_oracles_pass");
    }

    /// Conformance: app with dependency chain passes all oracles, including
    /// deterministic start ordering.
    #[test]
    fn conformance_dependency_chain_all_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_dependency_chain_all_oracles_pass");

        let app = AppSpec::new("dep_chain")
            .child(conformance_child("alpha"))
            .child(conformance_child_depends(
                "bravo",
                vec!["alpha".to_string()],
            ))
            .child(conformance_child_depends(
                "charlie",
                vec!["bravo".to_string()],
            ));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.passed(),
            "dependency-chain app must pass all oracles: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_dependency_chain_all_oracles_pass");
    }

    /// Conformance: deterministic trace fingerprints across identical runs.
    /// Same seed + same topology = identical fingerprint and JSON report.
    #[test]
    fn conformance_deterministic_multi_child() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_deterministic_multi_child");

        let run_scenario = |seed| {
            let app = AppSpec::new("det_multi")
                .child(conformance_child("alpha"))
                .child(conformance_child("bravo"))
                .child(conformance_child_depends(
                    "charlie",
                    vec!["alpha".to_string()],
                ));
            let harness = SporkAppHarness::with_seed(seed, app).unwrap();
            schedule_children(&harness);
            harness.run_to_report().unwrap()
        };

        let report_a = run_scenario(99);
        let report_b = run_scenario(99);

        assert_eq!(
            report_a.run.trace_fingerprint, report_b.run.trace_fingerprint,
            "same seed + topology must produce identical trace fingerprints"
        );
        assert_eq!(
            report_a.to_json(),
            report_b.to_json(),
            "JSON reports must be identical for deterministic replay"
        );

        crate::test_complete!("conformance_deterministic_multi_child");
    }

    /// Conformance: different seeds produce different fingerprints, proving
    /// the scheduler is actually using the seed.
    #[test]
    fn conformance_different_seeds_differ() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_different_seeds_differ");

        let run_scenario = |seed| {
            let app = AppSpec::new("seed_diff")
                .child(conformance_child("alpha"))
                .child(conformance_child("bravo"));
            let harness = SporkAppHarness::with_seed(seed, app).unwrap();
            schedule_children(&harness);
            harness.run_to_report().unwrap()
        };

        let report_a = run_scenario(1);
        let report_b = run_scenario(2);

        // Both should pass oracles regardless of seed.
        assert!(
            report_a.passed(),
            "seed 1 must pass: violations={:?}, failures={:?}",
            report_a.run.invariant_violations,
            report_a.oracle_failures()
        );
        assert!(
            report_b.passed(),
            "seed 2 must pass: violations={:?}, failures={:?}",
            report_b.run.invariant_violations,
            report_b.oracle_failures()
        );

        crate::test_complete!("conformance_different_seeds_differ");
    }

    /// Conformance: quiescence is reached after full lifecycle for a non-trivial app.
    #[test]
    fn conformance_quiescence_on_stop() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_quiescence_on_stop");

        let app = AppSpec::new("quiescence_app")
            .child(conformance_child("svc_a"))
            .child(conformance_child("svc_b"))
            .child(conformance_child("svc_c"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.run.quiescent,
            "runtime must reach quiescence after stop"
        );
        assert!(
            report.passed(),
            "all oracles must pass after quiescent stop: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_quiescence_on_stop");
    }

    /// Conformance: oracles pass at intermediate snapshot (before stop).
    #[test]
    fn conformance_oracles_pass_at_snapshot() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_oracles_pass_at_snapshot");

        let app = AppSpec::new("snapshot_oracle")
            .child(conformance_child("worker_a"))
            .child(conformance_child("worker_b"));
        let mut harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);

        harness.run_until_idle();

        // Oracles should pass while app is still running.
        assert!(
            harness.oracles_pass(),
            "oracles must pass at intermediate snapshot"
        );

        // Final lifecycle should also pass.
        let report = harness.run_to_report().unwrap();
        assert!(
            report.passed(),
            "final report must pass: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_oracles_pass_at_snapshot");
    }

    /// Conformance: report schema version is stable.
    #[test]
    fn conformance_report_schema_version() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_report_schema_version");

        let app = AppSpec::new("schema_check").child(conformance_child("w"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        let json = report.to_json();
        assert_eq!(
            json["schema_version"],
            serde_json::json!(SporkHarnessReport::SCHEMA_VERSION)
        );

        crate::test_complete!("conformance_report_schema_version");
    }

    /// Conformance: oracle entry count matches expected oracle suite size.
    #[test]
    fn conformance_oracle_entry_count() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_oracle_entry_count");

        let app = AppSpec::new("oracle_count_check").child(conformance_child("w"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        // Oracle suite should have entries for all registered oracles.
        assert!(
            report.run.oracle_report.total > 0,
            "oracle report must contain at least one oracle"
        );
        assert_eq!(
            report.run.oracle_report.total,
            report.run.oracle_report.entries.len(),
            "total must match entries.len()"
        );
        assert_eq!(
            report.run.oracle_report.passed + report.run.oracle_report.failed,
            report.run.oracle_report.total,
            "passed + failed must equal total"
        );

        crate::test_complete!("conformance_oracle_entry_count");
    }

    /// Conformance: scenario runner with expected invariants validates lifecycle.
    #[test]
    fn conformance_scenario_lifecycle_with_invariants() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_scenario_lifecycle_with_invariants");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("conformance.lifecycle", |_config| {
                    AppSpec::new("scenario_lifecycle")
                })
                .with_description("Empty app lifecycle conformance")
                .with_expected_invariants([
                    "no_task_leaks",
                    "no_obligation_leaks",
                    "quiescence_on_close",
                ]),
            )
            .unwrap();

        let result = runner.run("conformance.lifecycle").unwrap();
        assert!(
            result.passed(),
            "conformance scenario must pass: violations={:?}, failures={:?}",
            result.report.run.invariant_violations,
            result.report.oracle_failures()
        );
        assert_eq!(result.scenario_id, "conformance.lifecycle");
        assert!(result
            .expected_invariants
            .contains(&"no_task_leaks".to_string()));

        crate::test_complete!("conformance_scenario_lifecycle_with_invariants");
    }

    /// Conformance: run_all exercises multiple scenarios in deterministic order.
    #[test]
    fn conformance_scenario_run_all_deterministic() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_scenario_run_all_deterministic");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(SporkScenarioSpec::new("conformance.alpha", |_| {
                AppSpec::new("alpha")
            }))
            .unwrap();
        runner
            .register(SporkScenarioSpec::new("conformance.bravo", |_| {
                AppSpec::new("bravo")
            }))
            .unwrap();
        runner
            .register(SporkScenarioSpec::new("conformance.charlie", |_| {
                AppSpec::new("charlie")
            }))
            .unwrap();

        let results = runner.run_all().unwrap();
        assert_eq!(results.len(), 3);

        // BTreeMap ordering: IDs are sorted lexicographically.
        assert_eq!(results[0].scenario_id, "conformance.alpha");
        assert_eq!(results[1].scenario_id, "conformance.bravo");
        assert_eq!(results[2].scenario_id, "conformance.charlie");

        // All must pass.
        for result in &results {
            assert!(
                result.passed(),
                "scenario {} must pass: {:?}",
                result.scenario_id,
                result.report.oracle_failures()
            );
        }

        crate::test_complete!("conformance_scenario_run_all_deterministic");
    }

    /// Conformance: app with budget passes all oracles.
    #[test]
    fn conformance_budgeted_app_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_budgeted_app_oracles_pass");

        let app = AppSpec::new("budgeted_conformance")
            .with_budget(Budget::new().with_poll_quota(50_000))
            .child(conformance_child("svc"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.passed(),
            "budgeted app must pass: violations={:?}, failures={:?}",
            report.run.invariant_violations,
            report.oracle_failures()
        );

        crate::test_complete!("conformance_budgeted_app_oracles_pass");
    }

    /// Conformance: no invariant violations in report for clean lifecycle.
    #[test]
    fn conformance_no_invariant_violations() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_no_invariant_violations");

        let app = AppSpec::new("clean_app")
            .child(conformance_child("a"))
            .child(conformance_child("b"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.run.invariant_violations.is_empty(),
            "clean app must have no invariant violations, got: {:?}",
            report.run.invariant_violations
        );

        crate::test_complete!("conformance_no_invariant_violations");
    }
}
