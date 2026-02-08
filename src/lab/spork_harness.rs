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
            handle.stop(&mut self.runtime.state).map_err(HarnessError::Stop)?;
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
            handle.stop(&mut self.runtime.state).map_err(HarnessError::Stop)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::SporkHarnessReport;

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
}
