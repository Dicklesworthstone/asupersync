//! Cancellation Debt Runtime Integration
//!
//! Integrates the cancellation debt monitor with the asupersync runtime to provide
//! real-time monitoring of cancellation work accumulation and processing rates.

use crate::observability::cancellation_debt_monitor::{
    CancellationDebtConfig, CancellationDebtMonitor, DebtAlert, DebtAlertLevel, DebtSnapshot,
    PendingWork, WorkType,
};
use crate::types::{CancelKind, CancelReason, RegionId, TaskId};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

/// Integration points for debt monitoring in the runtime.
pub struct DebtRuntimeIntegration {
    monitor: Arc<CancellationDebtMonitor>,
    /// Background monitoring thread handle.
    monitoring_thread: Option<thread::JoinHandle<()>>,
    /// Shutdown signal for background thread.
    shutdown: Arc<Mutex<bool>>,
    /// Alert callback for integration with logging/alerting systems.
    alert_callback: Option<Box<dyn Fn(&DebtAlert) + Send + Sync>>,
}

impl DebtRuntimeIntegration {
    /// Creates a new debt runtime integration.
    pub fn new(config: CancellationDebtConfig) -> Self {
        let monitor = Arc::new(CancellationDebtMonitor::new(config));
        Self {
            monitor,
            monitoring_thread: None,
            shutdown: Arc::new(Mutex::new(false)),
            alert_callback: None,
        }
    }

    /// Creates integration with default configuration.
    pub fn default() -> Self {
        Self::new(CancellationDebtConfig::default())
    }

    /// Set a callback to be invoked when debt alerts are generated.
    pub fn set_alert_callback<F>(&mut self, callback: F)
    where
        F: Fn(&DebtAlert) + Send + Sync + 'static,
    {
        self.alert_callback = Some(Box::new(callback));
    }

    /// Start background monitoring thread.
    pub fn start_monitoring(&mut self, check_interval: Duration) {
        if self.monitoring_thread.is_some() {
            return; // Already started
        }

        let monitor = self.monitor.clone();
        let shutdown = self.shutdown.clone();
        let alert_callback = self.alert_callback.take();

        let handle = thread::spawn(move || {
            Self::monitoring_loop(monitor, shutdown, check_interval, alert_callback);
        });

        self.monitoring_thread = Some(handle);
    }

    /// Stop background monitoring.
    pub fn stop_monitoring(&mut self) {
        {
            let mut shutdown = self.shutdown.lock().unwrap();
            *shutdown = true;
        }

        if let Some(handle) = self.monitoring_thread.take() {
            let _ = handle.join(); // Wait for thread to finish
        }
    }

    /// Get reference to the underlying debt monitor.
    pub fn monitor(&self) -> &Arc<CancellationDebtMonitor> {
        &self.monitor
    }

    /// Called when a task begins cancellation cleanup.
    pub fn on_task_cleanup_started(
        &self,
        task_id: TaskId,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        estimated_cleanup_work: u32,
    ) -> u64 {
        self.monitor.queue_work(
            WorkType::TaskCleanup,
            format!("task-{:?}", task_id),
            self.calculate_priority(cancel_kind),
            estimated_cleanup_work,
            cancel_reason,
            cancel_kind,
            Vec::new(),
        )
    }

    /// Called when a region begins closure.
    pub fn on_region_cleanup_started(
        &self,
        region_id: RegionId,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        child_dependencies: Vec<u64>,
    ) -> u64 {
        self.monitor.queue_work(
            WorkType::RegionCleanup,
            format!("region-{:?}", region_id),
            self.calculate_priority(cancel_kind),
            100, // Baseline region cleanup cost
            cancel_reason,
            cancel_kind,
            child_dependencies,
        )
    }

    /// Called when waker cleanup is required.
    pub fn on_waker_cleanup_started(
        &self,
        waker_id: String,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
    ) -> u64 {
        self.monitor.queue_work(
            WorkType::WakerCleanup,
            waker_id,
            self.calculate_priority(cancel_kind),
            10, // Waker cleanup is typically fast
            cancel_reason,
            cancel_kind,
            Vec::new(),
        )
    }

    /// Called when channel cleanup begins.
    pub fn on_channel_cleanup_started(
        &self,
        channel_id: String,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        buffer_size: usize,
    ) -> u64 {
        let cleanup_cost = (buffer_size / 100).max(10) as u32; // Scale by buffer size
        self.monitor.queue_work(
            WorkType::ChannelCleanup,
            channel_id,
            self.calculate_priority(cancel_kind),
            cleanup_cost,
            cancel_reason,
            cancel_kind,
            Vec::new(),
        )
    }

    /// Called when obligation settlement is needed.
    pub fn on_obligation_settlement_started(
        &self,
        obligation_id: String,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        settlement_complexity: u32,
    ) -> u64 {
        self.monitor.queue_work(
            WorkType::ObligationSettlement,
            obligation_id,
            self.calculate_priority(cancel_kind) + 10, // Higher priority for obligations
            settlement_complexity,
            cancel_reason,
            cancel_kind,
            Vec::new(),
        )
    }

    /// Called when resource finalization begins.
    pub fn on_resource_finalization_started(
        &self,
        resource_id: String,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        finalization_cost: u32,
    ) -> u64 {
        self.monitor.queue_work(
            WorkType::ResourceFinalization,
            resource_id,
            self.calculate_priority(cancel_kind),
            finalization_cost,
            cancel_reason,
            cancel_kind,
            Vec::new(),
        )
    }

    /// Called when any cleanup work completes.
    pub fn on_cleanup_completed(&self, work_id: u64) {
        self.monitor.complete_work(work_id);
    }

    /// Called when multiple cleanup items complete (batch processing).
    pub fn on_batch_cleanup_completed(&self, work_ids: &[u64]) -> usize {
        self.monitor.complete_work_batch(work_ids)
    }

    /// Get current debt status for monitoring dashboards.
    pub fn get_debt_status(&self) -> DebtSnapshot {
        self.monitor.get_debt_snapshot()
    }

    /// Get pending work for a specific entity.
    pub fn get_entity_debt(&self, entity_id: &str) -> Vec<PendingWork> {
        self.monitor.get_entity_pending_work(entity_id)
    }

    /// Get highest priority pending work.
    pub fn get_priority_cleanup_work(&self, limit: usize) -> Vec<PendingWork> {
        self.monitor.get_priority_work(limit)
    }

    /// Check if emergency intervention is needed.
    pub fn check_emergency_intervention(&self) -> bool {
        let snapshot = self.get_debt_status();
        matches!(
            snapshot.alert_level,
            DebtAlertLevel::Emergency | DebtAlertLevel::Critical
        )
    }

    /// Execute emergency debt relief.
    pub fn execute_emergency_relief(&self, max_work_age: Duration) -> usize {
        self.monitor.emergency_cleanup(max_work_age)
    }

    /// Generate a debt health report.
    pub fn generate_debt_report(&self) -> DebtHealthReport {
        let snapshot = self.get_debt_status();
        let recent_alerts = self.monitor.get_recent_alerts(10);

        let recommendations = self.generate_recommendations(&snapshot);
        let health_score = self.calculate_health_score(&snapshot);

        DebtHealthReport {
            snapshot,
            recent_alerts,
            recommendations,
            health_score,
        }
    }

    /// Background monitoring loop.
    fn monitoring_loop(
        monitor: Arc<CancellationDebtMonitor>,
        shutdown: Arc<Mutex<bool>>,
        check_interval: Duration,
        alert_callback: Option<Box<dyn Fn(&DebtAlert) + Send + Sync>>,
    ) {
        let mut last_alert_check = SystemTime::now();

        loop {
            // Check shutdown signal
            {
                let should_shutdown = *shutdown.lock().unwrap();
                if should_shutdown {
                    break;
                }
            }

            // Perform monitoring checks
            let now = SystemTime::now();

            // Check for new alerts periodically
            if now
                .duration_since(last_alert_check)
                .unwrap_or(Duration::ZERO)
                >= Duration::from_secs(5)
            {
                if let Some(ref callback) = alert_callback {
                    let recent_alerts = monitor.get_recent_alerts(1);
                    for alert in recent_alerts {
                        callback(&alert);
                    }
                }
                last_alert_check = now;
            }

            // Clean up old alerts
            monitor.clear_old_alerts(Duration::from_hours(1));

            // Sleep until next check
            thread::sleep(check_interval);
        }
    }

    /// Calculate priority based on cancel kind.
    fn calculate_priority(&self, cancel_kind: CancelKind) -> u32 {
        match cancel_kind {
            CancelKind::Shutdown => 100,
            CancelKind::Timeout => 80,
            CancelKind::Deadline => 75,
            CancelKind::User => 50,
            _ => 10,
        }
    }

    /// Generate health recommendations based on current state.
    fn generate_recommendations(&self, snapshot: &DebtSnapshot) -> Vec<String> {
        let mut recommendations = Vec::new();

        match snapshot.alert_level {
            DebtAlertLevel::Emergency => {
                recommendations.push("Execute emergency cleanup immediately".to_string());
                recommendations.push("Scale up cancellation processing".to_string());
                recommendations.push("Investigate system-wide bottlenecks".to_string());
            }
            DebtAlertLevel::Critical => {
                recommendations.push("Increase cancellation worker capacity".to_string());
                recommendations.push("Implement work prioritization".to_string());
                recommendations.push("Check for deadlocked entities".to_string());
            }
            DebtAlertLevel::Warning => {
                recommendations.push("Monitor processing rates closely".to_string());
                recommendations.push("Optimize cancellation handlers".to_string());
                if snapshot.processing_rate < 10.0 {
                    recommendations
                        .push("Processing rate is very low - investigate bottlenecks".to_string());
                }
            }
            DebtAlertLevel::Watch => {
                recommendations.push("Continue monitoring debt trends".to_string());
                if snapshot.oldest_work_age > Duration::from_secs(60) {
                    recommendations
                        .push("Some work items are aging - check processing pipeline".to_string());
                }
            }
            DebtAlertLevel::Normal => {
                recommendations.push("System operating normally".to_string());
            }
        }

        // Entity-specific recommendations
        for (entity_id, &depth) in &snapshot.entity_queue_depths {
            if depth > 500 {
                recommendations.push(format!(
                    "Entity {} has high queue depth ({}) - investigate",
                    entity_id, depth
                ));
            }
        }

        recommendations
    }

    /// Calculate overall health score (0-100).
    fn calculate_health_score(&self, snapshot: &DebtSnapshot) -> f64 {
        let debt_score = (100.0 - snapshot.debt_percentage).max(0.0);
        let rate_score = if snapshot.processing_rate > 100.0 {
            100.0
        } else {
            snapshot.processing_rate.min(100.0)
        };
        let age_score = if snapshot.oldest_work_age < Duration::from_secs(10) {
            100.0
        } else if snapshot.oldest_work_age < Duration::from_secs(60) {
            75.0
        } else {
            25.0
        };

        (debt_score + rate_score + age_score) / 3.0
    }
}

impl Drop for DebtRuntimeIntegration {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}

/// Comprehensive debt health report.
#[derive(Debug, Clone)]
pub struct DebtHealthReport {
    /// Current debt snapshot.
    pub snapshot: DebtSnapshot,
    /// Recent alerts.
    pub recent_alerts: Vec<DebtAlert>,
    /// Health recommendations.
    pub recommendations: Vec<String>,
    /// Overall health score (0-100, higher is better).
    pub health_score: f64,
}

/// Example integration showing how to wire debt monitoring into runtime events.
#[cfg(feature = "test-internals")]
pub mod integration_examples {

    /// Example of how TaskRecord cancellation would be instrumented.
    ///
    /// ```rust,ignore
    /// impl TaskRecord {
    ///     pub fn request_cancel_with_budget(
    ///         &mut self,
    ///         reason: CancelReason,
    ///         cleanup_budget: Budget,
    ///         debt_integration: Option<&DebtRuntimeIntegration>,
    ///     ) -> bool {
    ///         // ... existing logic ...
    ///
    ///         match &mut self.state {
    ///             TaskState::Created | TaskState::Running => {
    ///                 // NEW: Track cleanup work debt
    ///                 if let Some(debt) = debt_integration {
    ///                     let work_id = debt.on_task_cleanup_started(
    ///                         self.id,
    ///                         &reason,
    ///                         reason.kind,
    ///                         cleanup_budget.estimate_cleanup_work(),
    ///                     );
    ///                     self.debt_work_id = Some(work_id);
    ///                 }
    ///
    ///                 // ... continue with cancellation ...
    ///             }
    ///             // ... other states ...
    ///         }
    ///     }
    ///
    ///     pub fn complete(
    ///         &mut self,
    ///         outcome: TaskOutcome,
    ///         debt_integration: Option<&DebtRuntimeIntegration>,
    ///     ) {
    ///         // ... existing logic ...
    ///
    ///         // NEW: Mark cleanup debt as resolved
    ///         if let Some(work_id) = self.debt_work_id.take() {
    ///             if let Some(debt) = debt_integration {
    ///                 debt.on_cleanup_completed(work_id);
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    pub fn example_task_integration() {
        // Documentation only
    }

    /// Example of how RegionRecord would track cleanup debt.
    ///
    /// ```rust,ignore
    /// impl RegionRecord {
    ///     pub fn begin_close(
    ///         &mut self,
    ///         reason: Option<CancelReason>,
    ///         debt_integration: Option<&DebtRuntimeIntegration>,
    ///     ) {
    ///         // ... existing logic ...
    ///
    ///         if let Some(reason) = &reason {
    ///             // NEW: Track region cleanup debt
    ///             if let Some(debt) = debt_integration {
    ///                 let child_work_ids = self.children.iter()
    ///                     .filter_map(|&child_id| self.get_child_debt_work_id(child_id))
    ///                     .collect();
    ///
    ///                 let work_id = debt.on_region_cleanup_started(
    ///                     self.id,
    ///                     reason,
    ///                     reason.kind,
    ///                     child_work_ids,
    ///                 );
    ///                 self.debt_work_id = Some(work_id);
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    pub fn example_region_integration() {
        // Documentation only
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{CancelKind, CancelReason, RegionId, TaskId};

    #[test]
    fn test_integration_creation() {
        let integration = DebtRuntimeIntegration::default();
        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 0);
        assert_eq!(snapshot.debt_percentage, 0.0);
    }

    #[test]
    fn test_task_cleanup_tracking() {
        let integration = DebtRuntimeIntegration::default();

        let task_id = TaskId::new(42);
        let cancel_reason = CancelReason::with_user_reason("test".to_string());

        let work_id =
            integration.on_task_cleanup_started(task_id, &cancel_reason, CancelKind::User, 100);

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 1);
        assert!(
            snapshot
                .pending_by_type
                .contains_key(&WorkType::TaskCleanup)
        );

        integration.on_cleanup_completed(work_id);

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_priority_calculation() {
        let integration = DebtRuntimeIntegration::default();

        // Emergency cancellation should get highest priority
        let emergency_priority = integration.calculate_priority(CancelKind::Emergency);
        let user_priority = integration.calculate_priority(CancelKind::User);

        assert!(emergency_priority > user_priority);
    }

    #[test]
    fn test_health_score_calculation() {
        let integration = DebtRuntimeIntegration::default();

        let good_snapshot = DebtSnapshot {
            snapshot_time: SystemTime::now(),
            total_pending: 0,
            pending_by_type: HashMap::new(),
            debt_percentage: 5.0,
            processing_rate: 200.0,
            entity_queue_depths: HashMap::new(),
            oldest_work_age: Duration::from_secs(1),
            memory_usage_mb: 1.0,
            alert_level: DebtAlertLevel::Normal,
        };

        let health_score = integration.calculate_health_score(&good_snapshot);
        assert!(health_score > 90.0);
    }

    #[test]
    fn test_batch_completion() {
        let integration = DebtRuntimeIntegration::default();

        let work_ids: Vec<u64> = (0..5)
            .map(|i| {
                integration.on_waker_cleanup_started(
                    format!("waker-{}", i),
                    &CancelReason::with_user_reason("batch_test".to_string()),
                    CancelKind::User,
                )
            })
            .collect();

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 5);

        let completed = integration.on_batch_cleanup_completed(&work_ids);
        assert_eq!(completed, 5);

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_emergency_intervention() {
        let mut config = CancellationDebtConfig::default();
        config.max_queue_depth = 10; // Very low threshold for testing
        let integration = DebtRuntimeIntegration::new(config);

        // Queue enough work to trigger emergency level
        for i in 0..12 {
            integration.on_task_cleanup_started(
                TaskId::new(i),
                &CancelReason::with_user_reason("emergency_test".to_string()),
                CancelKind::User,
                50,
            );
        }

        assert!(integration.check_emergency_intervention());

        let cleaned = integration.execute_emergency_relief(Duration::from_millis(1));
        assert!(cleaned > 0);
    }
}
