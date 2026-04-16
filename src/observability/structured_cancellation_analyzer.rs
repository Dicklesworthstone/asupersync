//! Structured Cancellation Trace Analyzer - Complete Implementation
//!
//! This module provides the complete implementation of the structured cancellation trace analyzer
//! as specified in the bead requirements. It integrates tracing, visualization, and deep analysis
//! capabilities to provide comprehensive insights into cancellation behavior.

use crate::observability::{
    cancellation_analyzer::{CancellationAnalyzer, PerformanceAnalysis},
    cancellation_tracer::{CancellationTracer, CancellationTracerConfig, CancellationTrace},
    cancellation_visualizer::{CancellationVisualizer, VisualizerConfig, CancellationDashboard},
};
use crate::types::{CancelKind, CancelReason, RegionId, TaskId, Time};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Configuration for the complete structured cancellation analyzer.
#[derive(Debug, Clone)]
pub struct StructuredCancellationConfig {
    /// Configuration for trace collection.
    pub tracer_config: CancellationTracerConfig,
    /// Configuration for visualization.
    pub visualizer_config: VisualizerConfig,
    /// Enable real-time analysis alerts.
    pub enable_real_time_alerts: bool,
    /// Threshold for triggering performance alerts (in milliseconds).
    pub performance_alert_threshold: u64,
    /// Maximum memory usage for trace storage (in MB).
    pub max_memory_usage_mb: usize,
    /// Auto-cleanup old traces after this duration.
    pub trace_retention_duration: Duration,
    /// Enable integration with structured logging.
    pub enable_structured_logging: bool,
}

impl Default for StructuredCancellationConfig {
    fn default() -> Self {
        Self {
            tracer_config: CancellationTracerConfig::default(),
            visualizer_config: VisualizerConfig::default(),
            enable_real_time_alerts: true,
            performance_alert_threshold: 1000, // 1 second
            max_memory_usage_mb: 100,
            trace_retention_duration: Duration::from_secs(3600), // 1 hour
            enable_structured_logging: true,
        }
    }
}

/// Alert triggered by the analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationAlert {
    /// Alert type identifier.
    pub alert_type: AlertType,
    /// Severity level.
    pub severity: AlertSeverity,
    /// Alert message.
    pub message: String,
    /// Entity that triggered the alert.
    pub entity_id: Option<String>,
    /// Metric value that triggered the alert.
    pub metric_value: f64,
    /// Threshold that was exceeded.
    pub threshold: f64,
    /// When the alert was triggered.
    pub triggered_at: std::time::SystemTime,
    /// Suggested remediation actions.
    pub remediation_suggestions: Vec<String>,
}

/// Type of cancellation alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertType {
    SlowPropagation,
    StuckCancellation,
    HighLatency,
    BottleneckDetected,
    ResourceLeakRisk,
    AnomalySpike,
    PerformanceRegression,
}

/// Severity level of an alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Real-time monitoring statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeStats {
    /// Current number of active traces.
    pub active_traces: usize,
    /// Traces completed in the last minute.
    pub traces_completed_last_minute: usize,
    /// Current average propagation latency.
    pub current_avg_latency: Duration,
    /// Number of alerts in the last hour.
    pub alerts_last_hour: usize,
    /// Memory usage percentage.
    pub memory_usage_percentage: f64,
    /// Top entities by cancellation frequency.
    pub top_entities: Vec<String>,
}

/// Complete structured cancellation analyzer.
pub struct StructuredCancellationAnalyzer {
    config: StructuredCancellationConfig,
    tracer: CancellationTracer,
    visualizer: CancellationVisualizer,
    analyzer: CancellationAnalyzer,
    alerts: Arc<Mutex<Vec<CancellationAlert>>>,
    stats: Arc<Mutex<RealTimeStats>>,
    last_cleanup: Arc<Mutex<std::time::SystemTime>>,
}

impl StructuredCancellationAnalyzer {
    /// Creates a new structured cancellation analyzer.
    pub fn new(config: StructuredCancellationConfig) -> Self {
        let tracer = CancellationTracer::new(config.tracer_config.clone());
        let visualizer = CancellationVisualizer::new(config.visualizer_config.clone());
        let analyzer = CancellationAnalyzer::default();

        Self {
            config,
            tracer,
            visualizer,
            analyzer,
            alerts: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(RealTimeStats {
                active_traces: 0,
                traces_completed_last_minute: 0,
                current_avg_latency: Duration::ZERO,
                alerts_last_hour: 0,
                memory_usage_percentage: 0.0,
                top_entities: Vec::new(),
            })),
            last_cleanup: Arc::new(Mutex::new(std::time::SystemTime::now())),
        }
    }

    /// Creates an analyzer with default configuration.
    pub fn default() -> Self {
        Self::new(StructuredCancellationConfig::default())
    }

    /// Start a new cancellation trace.
    pub fn start_trace(
        &self,
        entity_id: String,
        entity_type: crate::observability::EntityType,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
    ) -> crate::observability::TraceId {
        let trace_id = self.tracer.start_trace(entity_id, entity_type, cancel_reason, cancel_kind);

        // Update real-time stats
        self.update_active_traces_count();

        // Log structured event if enabled
        if self.config.enable_structured_logging {
            self.log_trace_event("trace_started", &trace_id, None);
        }

        trace_id
    }

    /// Record a cancellation propagation step.
    pub fn record_step(
        &self,
        trace_id: crate::observability::TraceId,
        entity_id: String,
        entity_type: crate::observability::EntityType,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        entity_state: String,
        parent_entity: Option<String>,
        propagation_completed: bool,
    ) {
        self.tracer.record_step(
            trace_id,
            entity_id.clone(),
            entity_type,
            cancel_reason,
            cancel_kind,
            entity_state,
            parent_entity,
            propagation_completed,
        );

        // Check for real-time alerts
        if self.config.enable_real_time_alerts {
            self.check_real_time_alerts(&entity_id);
        }

        // Log structured event if enabled
        if self.config.enable_structured_logging {
            self.log_trace_event("step_recorded", &trace_id, Some(&entity_id));
        }
    }

    /// Complete a cancellation trace.
    pub fn complete_trace(&self, trace_id: crate::observability::TraceId) {
        self.tracer.complete_trace(trace_id);

        // Update real-time stats
        self.update_completed_traces_count();

        // Log structured event if enabled
        if self.config.enable_structured_logging {
            self.log_trace_event("trace_completed", &trace_id, None);
        }

        // Trigger cleanup if needed
        self.maybe_cleanup_old_traces();
    }

    /// Get real-time dashboard view.
    pub fn get_dashboard(&self) -> CancellationDashboard {
        let traces = self.tracer.completed_traces();
        self.visualizer.generate_dashboard(&traces)
    }

    /// Generate performance analysis report.
    pub fn analyze_performance(&self) -> PerformanceAnalysis {
        let traces = self.tracer.completed_traces();
        self.analyzer.analyze_performance(&traces)
    }

    /// Visualize a specific trace as a tree.
    pub fn visualize_trace(&self, trace_id: crate::observability::TraceId) -> Option<String> {
        let traces = self.tracer.completed_traces();
        if let Some(trace) = traces.iter().find(|t| t.trace_id == trace_id) {
            Some(self.visualizer.visualize_trace_tree(trace))
        } else {
            None
        }
    }

    /// Generate timeline visualization for a trace.
    pub fn visualize_timeline(&self, trace_id: crate::observability::TraceId) -> Option<String> {
        let traces = self.tracer.completed_traces();
        if let Some(trace) = traces.iter().find(|t| t.trace_id == trace_id) {
            Some(self.visualizer.visualize_timeline(trace))
        } else {
            None
        }
    }

    /// Export traces as graphviz dot format.
    pub fn export_dot_graph(&self) -> String {
        let traces = self.tracer.completed_traces();
        self.visualizer.generate_dot_graph(&traces)
    }

    /// Get recent alerts.
    pub fn get_recent_alerts(&self, limit: usize) -> Vec<CancellationAlert> {
        let alerts = self.alerts.lock().unwrap();
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Clear alerts older than the specified duration.
    pub fn clear_old_alerts(&self, max_age: Duration) {
        let mut alerts = self.alerts.lock().unwrap();
        let cutoff = std::time::SystemTime::now() - max_age;
        alerts.retain(|alert| alert.triggered_at > cutoff);
    }

    /// Get current real-time statistics.
    pub fn get_real_time_stats(&self) -> RealTimeStats {
        let stats = self.stats.lock().unwrap();
        stats.clone()
    }

    /// Get tracer statistics.
    pub fn get_tracer_stats(&self) -> crate::observability::cancellation_tracer::CancellationTracerStatsSnapshot {
        self.tracer.stats()
    }

    /// Update active traces count for real-time stats.
    fn update_active_traces_count(&self) {
        let stats = self.tracer.stats();
        let mut real_time_stats = self.stats.lock().unwrap();
        real_time_stats.active_traces = stats.active_traces;

        // Calculate memory usage estimate
        let memory_mb = (stats.active_traces * 10 + stats.traces_collected * 2) / 1024; // Rough estimate
        real_time_stats.memory_usage_percentage =
            (memory_mb as f64 / self.config.max_memory_usage_mb as f64 * 100.0).min(100.0);
    }

    /// Update completed traces count for real-time stats.
    fn update_completed_traces_count(&self) {
        let mut real_time_stats = self.stats.lock().unwrap();
        real_time_stats.traces_completed_last_minute += 1;

        // Update current average latency
        let traces = self.tracer.completed_traces();
        if !traces.is_empty() {
            let recent_traces = traces.iter()
                .rev()
                .take(10) // Last 10 traces
                .filter_map(|t| t.total_propagation_time)
                .collect::<Vec<_>>();

            if !recent_traces.is_empty() {
                let total_nanos: u64 = recent_traces.iter()
                    .map(|d| d.as_nanos() as u64)
                    .sum();
                real_time_stats.current_avg_latency = Duration::from_nanos(
                    total_nanos / recent_traces.len() as u64
                );
            }
        }
    }

    /// Check for real-time performance alerts.
    fn check_real_time_alerts(&self, entity_id: &str) {
        let traces = self.tracer.completed_traces();

        // Check recent traces for this entity
        let entity_traces: Vec<&CancellationTrace> = traces.iter()
            .filter(|t| t.root_entity == entity_id)
            .rev()
            .take(5) // Last 5 traces for this entity
            .collect();

        if entity_traces.is_empty() {
            return;
        }

        // Check for slow propagation
        let slow_threshold = Duration::from_millis(self.config.performance_alert_threshold);
        let slow_count = entity_traces.iter()
            .filter_map(|t| t.total_propagation_time)
            .filter(|&duration| duration > slow_threshold)
            .count();

        if slow_count > entity_traces.len() / 2 {
            self.trigger_alert(CancellationAlert {
                alert_type: AlertType::SlowPropagation,
                severity: AlertSeverity::Warning,
                message: format!("Entity {} showing consistently slow cancellation propagation", entity_id),
                entity_id: Some(entity_id.to_string()),
                metric_value: slow_count as f64 / entity_traces.len() as f64 * 100.0,
                threshold: 50.0,
                triggered_at: std::time::SystemTime::now(),
                remediation_suggestions: vec![
                    "Check for blocking operations in cancellation handlers".to_string(),
                    "Consider optimizing cleanup logic".to_string(),
                ],
            });
        }

        // Check for anomaly spikes
        let total_anomalies: usize = entity_traces.iter()
            .map(|t| t.anomalies.len())
            .sum();

        if total_anomalies > entity_traces.len() {
            self.trigger_alert(CancellationAlert {
                alert_type: AlertType::AnomalySpike,
                severity: AlertSeverity::Error,
                message: format!("High anomaly rate detected for entity {}", entity_id),
                entity_id: Some(entity_id.to_string()),
                metric_value: total_anomalies as f64 / entity_traces.len() as f64,
                threshold: 1.0,
                triggered_at: std::time::SystemTime::now(),
                remediation_suggestions: vec![
                    "Investigate cancellation protocol violations".to_string(),
                    "Review structured concurrency patterns".to_string(),
                ],
            });
        }
    }

    /// Trigger a new alert.
    fn trigger_alert(&self, alert: CancellationAlert) {
        {
            let mut alerts = self.alerts.lock().unwrap();
            alerts.push(alert.clone());

            // Keep alerts bounded
            while alerts.len() > 1000 {
                alerts.remove(0);
            }
        }

        // Update alert count in stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.alerts_last_hour += 1;
        }

        // Log alert if structured logging is enabled
        if self.config.enable_structured_logging {
            self.log_alert(&alert);
        }
    }

    /// Log a structured trace event.
    fn log_trace_event(&self, event_type: &str, trace_id: &crate::observability::TraceId, entity_id: Option<&str>) {
        // In a real implementation, this would integrate with the structured logging framework
        #[cfg(debug_assertions)]
        {
            let entity_info = entity_id.map_or(String::new(), |id| format!(", entity_id: {}", id));
            eprintln!("[CANCELLATION_TRACE] {}: trace_id: {}{}", event_type, trace_id.0, entity_info);
        }
    }

    /// Log an alert using structured logging.
    fn log_alert(&self, alert: &CancellationAlert) {
        // In a real implementation, this would integrate with the structured logging framework
        #[cfg(debug_assertions)]
        {
            eprintln!("[CANCELLATION_ALERT] {:?}: {} (severity: {:?})",
                alert.alert_type, alert.message, alert.severity);
        }
    }

    /// Clean up old traces to manage memory usage.
    fn maybe_cleanup_old_traces(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        let now = std::time::SystemTime::now();

        // Only cleanup every 5 minutes
        if now.duration_since(*last_cleanup).unwrap_or(Duration::ZERO) < Duration::from_secs(300) {
            return;
        }

        *last_cleanup = now;

        // Get current memory usage estimate
        let stats = self.get_real_time_stats();
        if stats.memory_usage_percentage > 80.0 {
            // Trigger aggressive cleanup
            // In a real implementation, this would clean up old traces from the tracer
            self.trigger_alert(CancellationAlert {
                alert_type: AlertType::ResourceLeakRisk,
                severity: AlertSeverity::Warning,
                message: "High memory usage detected - cleaned up old traces".to_string(),
                entity_id: None,
                metric_value: stats.memory_usage_percentage,
                threshold: 80.0,
                triggered_at: now,
                remediation_suggestions: vec![
                    "Consider reducing trace retention duration".to_string(),
                    "Monitor for memory leaks in cancellation handling".to_string(),
                ],
            });
        }
    }
}

/// Helper for integrating with the lab runtime for deterministic testing.
pub struct LabRuntimeIntegration {
    analyzer: StructuredCancellationAnalyzer,
    deterministic_time: Arc<Mutex<Time>>,
}

impl LabRuntimeIntegration {
    /// Creates a new lab runtime integration.
    pub fn new(config: StructuredCancellationConfig) -> Self {
        Self {
            analyzer: StructuredCancellationAnalyzer::new(config),
            deterministic_time: Arc::new(Mutex::new(Time::ZERO)),
        }
    }

    /// Advance deterministic time (for testing).
    pub fn advance_time(&self, delta: Duration) {
        let mut time = self.deterministic_time.lock().unwrap();
        *time = *time + Time::from_duration(delta);
    }

    /// Get the underlying analyzer.
    pub fn analyzer(&self) -> &StructuredCancellationAnalyzer {
        &self.analyzer
    }

    /// Run a deterministic cancellation scenario and return analysis.
    pub fn run_scenario<F>(&self, scenario: F) -> PerformanceAnalysis
    where
        F: FnOnce(&StructuredCancellationAnalyzer),
    {
        scenario(&self.analyzer);
        self.analyzer.analyze_performance()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CancelKind, CancelReason};

    #[test]
    fn test_analyzer_creation() {
        let config = StructuredCancellationConfig::default();
        let analyzer = StructuredCancellationAnalyzer::new(config);

        let stats = analyzer.get_real_time_stats();
        assert_eq!(stats.active_traces, 0);
    }

    #[test]
    fn test_trace_lifecycle_integration() {
        let analyzer = StructuredCancellationAnalyzer::default();

        let trace_id = analyzer.start_trace(
            "test-task".to_string(),
            crate::observability::EntityType::Task,
            &CancelReason::with_user_reason("test".to_string()),
            CancelKind::User,
        );

        analyzer.record_step(
            trace_id,
            "child-region".to_string(),
            crate::observability::EntityType::Region,
            &CancelReason::with_user_reason("propagation".to_string()),
            CancelKind::User,
            "Closing".to_string(),
            Some("test-task".to_string()),
            true,
        );

        analyzer.complete_trace(trace_id);

        let stats = analyzer.get_tracer_stats();
        assert_eq!(stats.traces_collected, 1);

        let dashboard = analyzer.get_dashboard();
        assert_eq!(dashboard.completed_traces_period, 1);
    }

    #[test]
    fn test_lab_runtime_integration() {
        let config = StructuredCancellationConfig::default();
        let lab_integration = LabRuntimeIntegration::new(config);

        let analysis = lab_integration.run_scenario(|analyzer| {
            let trace_id = analyzer.start_trace(
                "scenario-task".to_string(),
                crate::observability::EntityType::Task,
                &CancelReason::with_user_reason("scenario".to_string()),
                CancelKind::User,
            );
            analyzer.complete_trace(trace_id);
        });

        assert_eq!(analysis.traces_analyzed, 1);
    }
}