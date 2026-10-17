//! Integrated Spork application test harness.
//!
//! [`SporkAppHarness`] wraps a [`LabRuntime`] and an application lifecycle to
//! provide a single-call entrypoint for deterministic app-level verification.
//!
//! # Example
//!
//! ```no_run
//! use asupersync::lab::{LabConfig, SporkAppHarness};
//! use asupersync::app::AppSpec;
//! use asupersync::types::Budget;
//!
//! let app = AppSpec::new("my_app")
//!     .with_budget(Budget::new().with_poll_quota(50_000));
//!
//! let harness = SporkAppHarness::new(LabConfig::new(42), app).unwrap();
//!
//! // Drive the app to quiescence, stop it, and collect a report.
//! let report = harness.run_to_report().expect("app should stop cleanly");
//!
//! assert!(report.run.oracle_report.all_passed());
//! ```

use crate::app::{AppHandle, AppSpec, AppStartError, AppStopError};
use crate::cx::Cx;
use crate::lab::config::LabConfig;
use crate::lab::dual_run::{DualRunScenarioIdentity, ReplayMetadata, SeedLineageRecord};
use crate::lab::runtime::{HarnessAttachmentRef, LabRuntime, SporkHarnessReport};
use crate::types::{Budget, TaskId};
use std::collections::BTreeMap;

const LAB_SPORK_HARNESS_ADAPTER: &str = "lab.spork_harness";

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
    /// [`Self::run_until_idle`], [`Self::run_until_quiescent`], or
    /// [`Self::run_to_report`]
    /// to drive execution.
    pub fn new(config: LabConfig, app: AppSpec) -> Result<Self, HarnessError> {
        let mut runtime = LabRuntime::new(config);
        let root_region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(root_region, TaskId::testing_default(), Budget::INFINITE);

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
        let stop_result = if let Some(mut handle) = self.app_handle.take() {
            handle
                .stop(&mut self.runtime.state)
                .map_err(HarnessError::Stop)
                .map(|_| ())
        } else {
            Ok(())
        };

        // Drain to full quiescence even if stop() failed, to honour the
        // structured-concurrency drain invariant.
        self.runtime.run_until_quiescent();

        stop_result
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
        let stop_result = if let Some(mut handle) = self.app_handle.take() {
            handle
                .stop(&mut self.runtime.state)
                .map(|_| ())
                .map_err(HarnessError::Stop)
        } else {
            Ok(())
        };

        // Phase 3: Drain to full quiescence — even if stop() failed, we must
        // honour the structured-concurrency drain invariant.
        self.runtime.run_until_quiescent();

        stop_result?;

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
    ///
    /// The oracles are hydrated from the runtime state first, as
    /// [`Self::snapshot_report`] does. Reading the suite directly reported
    /// whatever it last saw: nothing at all before any report, so every
    /// runtime-fed oracle passed (br-asupersync-vcu2oz).
    #[must_use]
    pub fn oracles_pass(&mut self) -> bool {
        self.runtime.report().oracle_report.all_passed()
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
        if !self.panic_on_obligation_leak && !self.panic_on_futurelock {
            config = config.with_cancellation_oracle_warnings();
        }
        config = if let Some(max_steps) = self.max_steps {
            config.max_steps(max_steps)
        } else {
            config.no_step_limit()
        };
        config.with_default_replay_recording()
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
    surface_id: Option<String>,
    surface_contract_version: Option<String>,
    seed_lineage_id: Option<String>,
    app_factory: ScenarioFactory,
}

impl std::fmt::Debug for SporkScenarioSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SporkScenarioSpec")
            .field("id", &self.id)
            .field("description", &self.description)
            .field("expected_invariants", &self.expected_invariants)
            .field("default_config", &self.default_config)
            .field("surface_id", &self.surface_id)
            .field("surface_contract_version", &self.surface_contract_version)
            .field("seed_lineage_id", &self.seed_lineage_id)
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
            surface_id: None,
            surface_contract_version: None,
            seed_lineage_id: None,
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

    /// Semantic surface identifier for dual-run comparison, when set.
    #[must_use]
    pub fn surface_id(&self) -> Option<&str> {
        self.surface_id.as_deref()
    }

    /// Versioned comparator contract token for the semantic surface, when set.
    #[must_use]
    pub fn surface_contract_version(&self) -> Option<&str> {
        self.surface_contract_version.as_deref()
    }

    /// Stable seed-lineage identifier for the scenario, when set.
    #[must_use]
    pub fn seed_lineage_id(&self) -> Option<&str> {
        self.seed_lineage_id.as_deref()
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

    /// Set the semantic surface identifier for dual-run comparison.
    #[must_use]
    pub fn with_surface_id(mut self, surface_id: impl Into<String>) -> Self {
        self.surface_id = Some(surface_id.into());
        self
    }

    /// Set the surface contract version for dual-run comparison.
    #[must_use]
    pub fn with_surface_contract_version(mut self, version: impl Into<String>) -> Self {
        self.surface_contract_version = Some(version.into());
        self
    }

    /// Set the seed-lineage identifier to preserve in downstream artifacts.
    #[must_use]
    pub fn with_seed_lineage_id(mut self, seed_lineage_id: impl Into<String>) -> Self {
        self.seed_lineage_id = Some(seed_lineage_id.into());
        self
    }

    fn dual_run_identity(&self, config: &SporkScenarioConfig) -> DualRunScenarioIdentity {
        let description = self.description.clone().unwrap_or_else(|| self.id.clone());
        let mut identity = DualRunScenarioIdentity::phase1(
            &self.id,
            self.surface_id.clone().unwrap_or_else(|| self.id.clone()),
            self.surface_contract_version
                .clone()
                .unwrap_or_else(|| format!("{}.v1", self.id)),
            description,
            config.seed,
        );
        if let Some(ref seed_lineage_id) = self.seed_lineage_id {
            let mut seed_plan = identity.seed_plan.clone();
            seed_plan.seed_lineage_id.clone_from(seed_lineage_id);
            identity = identity.with_seed_plan(seed_plan);
        }
        identity
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
    /// Adapter identity that produced this result.
    pub adapter: String,
    /// Shared dual-run replay metadata for this execution.
    pub replay_metadata: ReplayMetadata,
    /// Stable seed-lineage audit record for this execution.
    pub seed_lineage: SeedLineageRecord,
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
        let identity = scenario.dual_run_identity(&config);
        let mut replay_metadata = identity
            .lab_replay_metadata()
            .with_lab_report(
                report.trace_fingerprint(),
                report.run.trace_certificate.event_hash,
                report.run.trace_certificate.event_count,
                report.run.trace_certificate.schedule_hash,
                report.run.steps_total,
            )
            .with_repro_command(format!(
                "ASUPERSYNC_SEED=0x{:X} rch exec -- cargo test {} -- --nocapture",
                config.seed, scenario.id
            ));
        if let Some(crashpack_path) = report.crashpack_path() {
            replay_metadata = replay_metadata.with_artifact_path(crashpack_path.to_string());
        }
        Self {
            schema_version: Self::SCHEMA_VERSION,
            scenario_id: scenario.id.clone(),
            description: scenario.description.clone(),
            expected_invariants: scenario.expected_invariants.clone(),
            config,
            report,
            adapter: LAB_SPORK_HARNESS_ADAPTER.to_string(),
            replay_metadata,
            seed_lineage: identity.seed_lineage(),
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
            "surface_id": self.replay_metadata.family.surface_id,
            "surface_contract_version": self.replay_metadata.family.surface_contract_version,
            "description": self.description,
            "expected_invariants": self.expected_invariants,
            "config": self.config.to_json(),
            "report": self.report.to_json(),
            "seed_lineage_id": self.seed_lineage.seed_lineage_id,
            "adapter": self.adapter,
            "execution_instance_id": self.replay_metadata.instance.key(),
            "replay_metadata": &self.replay_metadata,
            "seed_lineage": &self.seed_lineage,
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
    pub fn register(&mut self, mut scenario: SporkScenarioSpec) -> Result<(), ScenarioRunnerError> {
        let id = scenario.id().trim().to_string();
        if id.is_empty() {
            return Err(ScenarioRunnerError::InvalidScenarioId);
        }
        if self.scenarios.contains_key(&id) {
            return Err(ScenarioRunnerError::DuplicateScenarioId(id));
        }
        scenario.id.clone_from(&id);
        self.scenarios.insert(id, scenario);
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
#[path = "spork_harness_inline_tests.rs"]
mod tests;
