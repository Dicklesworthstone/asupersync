#![allow(warnings)]
#![allow(clippy::all)]
//! E2E Lab Harness — reusable struct bundling LabRuntime + OracleSuite + structured logging.
//!
//! Every E2E test instantiates via `E2eLabHarness::new(name, seed)` or
//! `E2eLabHarness::with_chaos(name, seed, chaos)`.

use asupersync::lab::DualRunScenarioIdentity;
use asupersync::lab::chaos::{ChaosConfig, ChaosStats};
use asupersync::lab::oracle::OracleReport;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, RegionId, TaskId, Time};

/// Reusable E2E test harness bundling deterministic runtime + oracle verification.
pub struct E2eLabHarness {
    /// The test name (used in logging and repro commands).
    pub name: String,
    /// The deterministic lab runtime.
    pub runtime: LabRuntime,
    /// The seed used for this run.
    pub seed: u64,
    /// Whether chaos is enabled.
    pub chaos_enabled: bool,
}

impl E2eLabHarness {
    /// Create a new harness with a deterministic runtime.
    pub fn new(name: &str, seed: u64) -> Self {
        crate::common::init_test_logging();
        tracing::info!(
            test = %name,
            seed = seed,
            "========== E2E HARNESS INIT: {} (seed={:#x}) ==========",
            name, seed
        );
        let config = LabConfig::new(seed).max_steps(500_000).trace_capacity(8192);
        Self {
            name: name.to_string(),
            runtime: LabRuntime::new(config),
            seed,
            chaos_enabled: false,
        }
    }

    /// Create a harness with chaos injection enabled.
    pub fn with_chaos(name: &str, seed: u64, chaos: ChaosConfig) -> Self {
        crate::common::init_test_logging();
        tracing::info!(
            test = %name,
            seed = seed,
            "========== E2E HARNESS INIT (CHAOS): {} (seed={:#x}) ==========",
            name, seed
        );
        let config = LabConfig::new(seed)
            .max_steps(500_000)
            .trace_capacity(8192)
            .with_chaos(chaos);
        Self {
            name: name.to_string(),
            runtime: LabRuntime::new(config),
            seed,
            chaos_enabled: true,
        }
    }

    /// Create a harness with light chaos preset.
    pub fn with_light_chaos(name: &str, seed: u64) -> Self {
        Self::with_chaos(name, seed, ChaosConfig::light())
    }

    /// Create a harness with heavy chaos preset.
    pub fn with_heavy_chaos(name: &str, seed: u64) -> Self {
        Self::with_chaos(name, seed, ChaosConfig::heavy())
    }

    /// Create a harness from a shared dual-run identity.
    pub fn from_dual_run_identity(identity: &DualRunScenarioIdentity) -> Self {
        Self::new(
            &identity.scenario_id,
            identity.seed_plan.effective_lab_seed(),
        )
    }

    /// Create root region with infinite budget.
    pub fn create_root(&mut self) -> RegionId {
        self.runtime.state.create_root_region(Budget::INFINITE)
    }

    /// Create root region with a specific budget.
    pub fn create_root_with_budget(&mut self, budget: Budget) -> RegionId {
        self.runtime.state.create_root_region(budget)
    }

    /// Create a child region.
    pub fn create_child(&mut self, parent: RegionId) -> RegionId {
        self.runtime
            .state
            .create_child_region(parent, Budget::INFINITE)
            .expect("create child region")
    }

    /// Create a child region with a specific budget.
    pub fn create_child_with_budget(&mut self, parent: RegionId, budget: Budget) -> RegionId {
        self.runtime
            .state
            .create_child_region(parent, budget)
            .expect("create child region with budget")
    }

    /// Spawn a task in a region and schedule it.
    pub fn spawn<F, T>(&mut self, region: RegionId, future: F) -> TaskId
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (task_id, _handle) = self
            .runtime
            .state
            .create_task(region, Budget::INFINITE, future)
            .expect("create task");
        self.runtime.scheduler.lock().schedule(task_id, 0);
        task_id
    }

    /// Spawn a task with a specific priority.
    pub fn spawn_with_priority<F, T>(&mut self, region: RegionId, priority: u8, future: F) -> TaskId
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (task_id, _handle) = self
            .runtime
            .state
            .create_task(region, Budget::INFINITE, future)
            .expect("create task");
        self.runtime.scheduler.lock().schedule(task_id, priority);
        task_id
    }

    /// Run until quiescent and return steps taken.
    pub fn run_until_quiescent(&mut self) -> u64 {
        self.runtime.run_until_quiescent()
    }

    /// Run with automatic time advancement.
    pub fn run_with_auto_advance(&mut self) -> asupersync::lab::runtime::VirtualTimeReport {
        self.runtime.run_with_auto_advance()
    }

    /// Advance virtual time by nanoseconds.
    pub fn advance_time(&mut self, nanos: u64) {
        self.runtime.advance_time(nanos);
    }

    /// Advance virtual time by duration.
    pub fn advance_time_duration(&mut self, dur: std::time::Duration) {
        self.runtime
            .advance_time(dur.as_nanos().min(u128::from(u64::MAX)) as u64);
    }

    /// Cancel a region with a reason.
    pub fn cancel_region(&mut self, region: RegionId, reason: &'static str) -> usize {
        let cancel_reason = asupersync::types::CancelReason::user(reason);
        let tasks = self
            .runtime
            .state
            .cancel_request(region, &cancel_reason, None);
        let mut count = 0usize;
        for (task, priority) in tasks {
            self.runtime
                .scheduler
                .lock()
                .schedule_cancel(task, priority);
            count += 1;
        }
        count
    }

    /// Current virtual time.
    pub fn now(&self) -> Time {
        self.runtime.state.now
    }

    /// Check if the runtime is quiescent.
    pub fn is_quiescent(&self) -> bool {
        self.runtime.is_quiescent()
    }

    /// Hydrate and verify all oracles. Panics on any violation.
    pub fn verify_all_oracles(&mut self) {
        let now = self.runtime.state.now;
        self.runtime
            .oracles
            .hydrate_temporal_from_state(&self.runtime.state, now);
        let violations = self.runtime.oracles.check_all(now);
        if !violations.is_empty() {
            for v in &violations {
                tracing::error!(test = %self.name, violation = %v, "ORACLE VIOLATION");
            }
            panic!(
                "[{}] {} oracle violation(s) detected. First: {}",
                self.name,
                violations.len(),
                violations[0]
            );
        }
        tracing::info!(test = %self.name, "all oracles passed");
    }

    /// Check oracles and return the report without panicking.
    pub fn oracle_report(&mut self) -> OracleReport {
        let now = self.runtime.state.now;
        self.runtime
            .oracles
            .hydrate_temporal_from_state(&self.runtime.state, now);
        self.runtime.oracles.report(now)
    }

    /// Check runtime invariants (obligation leaks, futurelocks, etc).
    /// Returns the count of violations found.
    pub fn check_invariants(&mut self) -> usize {
        let violations = self.runtime.check_invariants();
        for v in &violations {
            tracing::warn!(test = %self.name, violation = ?v, "runtime invariant violation");
        }
        violations.len()
    }

    /// Get chaos stats (meaningful only when chaos is enabled).
    pub fn chaos_stats(&self) -> &ChaosStats {
        self.runtime.chaos_stats()
    }

    /// Log the reproduction command for this test.
    pub fn log_repro_command(&self) {
        tracing::info!(
            test = %self.name,
            seed = self.seed,
            "REPRO: rch exec -- cargo test -- {} --exact --test-threads=1  (seed={:#x})",
            self.name,
            self.seed
        );
    }

    /// Log a phase transition.
    pub fn phase(&self, phase_name: &str) {
        tracing::info!(
            test = %self.name,
            phase = %phase_name,
            "======== PHASE: {} ========",
            phase_name
        );
    }

    /// Log a section within a phase.
    pub fn section(&self, section_name: &str) {
        tracing::debug!(
            test = %self.name,
            section = %section_name,
            "--- {} ---",
            section_name
        );
    }

    /// Live task count.
    pub fn live_task_count(&self) -> usize {
        self.runtime.state.live_task_count()
    }

    /// Pending obligation count.
    pub fn pending_obligation_count(&self) -> usize {
        self.runtime.state.pending_obligation_count()
    }

    /// Verify quiescence + oracles and log completion.
    pub fn finish(&mut self) {
        self.verify_all_oracles();
        self.log_repro_command();
        tracing::info!(
            test = %self.name,
            seed = self.seed,
            quiescent = self.is_quiescent(),
            live_tasks = self.live_task_count(),
            "========== E2E TEST COMPLETE: {} ==========",
            self.name
        );
    }
}
