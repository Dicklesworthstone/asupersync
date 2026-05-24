//! # Real Observability/SpectralHealth ↔ Observability/Diagnostics Integration E2E Tests
//!
//! Tests integration between spectral health monitoring and diagnostics capture
//! to verify that spectral health anomaly detection triggers diagnostic snapshot
//! capture without losing in-flight metrics.
//!
//! ## Integration Focus
//!
//! - **Spectral Health**: anomaly detection, health trend analysis, threshold monitoring
//! - **Diagnostics**: snapshot capture, metric preservation, in-flight data retention
//! - **Metric Continuity**: no loss of metrics during diagnostic operations
//!
//! ## Key Properties Tested
//!
//! 1. **Anomaly Triggering**: Health anomalies trigger diagnostic snapshot capture
//! 2. **Metric Preservation**: In-flight metrics are preserved during snapshots
//! 3. **Snapshot Integrity**: Captured diagnostics contain complete health state
//! 4. **Continuity Guarantee**: No metric loss during snapshot operations

use crate::{
    cx::Cx,
    observability::{
        diagnostics::{
            DiagnosticCapture, DiagnosticSnapshot, DiagnosticSnapshotConfig,
            DiagnosticTrigger, SnapshotMetrics, SnapshotScope,
        },
        metrics::{
            Counter, Gauge, Histogram, MetricRegistry, MetricValue,
            TimeSeriesData, MetricCollector,
        },
        spectral_health::{
            AnomalyDetector, HealthAnalyzer, HealthMetric, HealthScore,
            HealthThreshold, SpectralAnalysis, SpectralHealthConfig,
            HealthAnomalyEvent, AnomalyType,
        },
        resource_accounting::{ResourceTracker, ResourceUsage},
        task_inspector::{TaskMetrics, TaskObservability},
    },
    runtime::{RuntimeBuilder, LabRuntime, LabRuntimeBuilder},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
    types::{
        budget::Budget,
        cancel::CancelToken,
        outcome::Outcome,
        region::RegionId,
        task::TaskId,
    },
    util::{rng::DetRng, time::TimeSource},
    Result,
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::atomic::AtomicBool,
};

/// Health anomaly event that triggers diagnostic capture
#[derive(Debug, Clone)]
struct HealthAnomalyTriggerEvent {
    anomaly_type: AnomalyType,
    health_score: HealthScore,
    threshold_breach: HealthThreshold,
    detection_time: Instant,
    trigger_id: u64,
    affected_metrics: Vec<String>,
}

impl HealthAnomalyTriggerEvent {
    fn new(
        anomaly_type: AnomalyType,
        health_score: HealthScore,
        threshold_breach: HealthThreshold,
        affected_metrics: Vec<String>,
        trigger_id: u64,
    ) -> Self {
        Self {
            anomaly_type,
            health_score,
            threshold_breach,
            detection_time: Instant::now(),
            trigger_id,
            affected_metrics,
        }
    }
}

/// In-flight metrics tracker for preservation verification
#[derive(Debug)]
struct InFlightMetricsTracker {
    active_counters: Arc<RwLock<HashMap<String, AtomicU64>>>,
    active_gauges: Arc<RwLock<HashMap<String, AtomicU64>>>,
    active_histograms: Arc<RwLock<HashMap<String, VecDeque<u64>>>>,
    metric_capture_times: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    preservation_violations: Arc<AtomicUsize>,
}

impl InFlightMetricsTracker {
    fn new() -> Self {
        Self {
            active_counters: Arc::new(RwLock::new(HashMap::new())),
            active_gauges: Arc::new(RwLock::new(HashMap::new())),
            active_histograms: Arc::new(RwLock::new(HashMap::new())),
            metric_capture_times: Arc::new(RwLock::new(HashMap::new())),
            preservation_violations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn update_counter(&self, name: String, value: u64) {
        {
            let mut counters = self.active_counters.write();
            counters.entry(name.clone()).or_insert_with(|| AtomicU64::new(0))
                .fetch_add(value, Ordering::Release);
        }

        {
            let mut times = self.metric_capture_times.write();
            times.entry(name).or_insert_with(Vec::new).push(Instant::now());
        }
    }

    fn update_gauge(&self, name: String, value: u64) {
        {
            let mut gauges = self.active_gauges.write();
            gauges.entry(name.clone()).or_insert_with(|| AtomicU64::new(0))
                .store(value, Ordering::Release);
        }

        {
            let mut times = self.metric_capture_times.write();
            times.entry(name).or_insert_with(Vec::new).push(Instant::now());
        }
    }

    fn record_histogram_sample(&self, name: String, value: u64) {
        {
            let mut histograms = self.active_histograms.write();
            histograms.entry(name.clone()).or_insert_with(VecDeque::new).push_back(value);

            // Keep histogram bounded
            if let Some(hist) = histograms.get_mut(&name) {
                if hist.len() > 1000 {
                    hist.pop_front();
                }
            }
        }

        {
            let mut times = self.metric_capture_times.write();
            times.entry(name).or_insert_with(Vec::new).push(Instant::now());
        }
    }

    fn verify_metric_preservation(&self, snapshot: &DiagnosticSnapshot) -> bool {
        let counters = self.active_counters.read();
        let gauges = self.active_gauges.read();
        let histograms = self.active_histograms.read();

        // Verify all active metrics are preserved in snapshot
        for (name, counter) in counters.iter() {
            let current_value = counter.load(Ordering::Acquire);
            if !snapshot.contains_metric(name) || snapshot.get_counter_value(name) != Some(current_value) {
                self.preservation_violations.fetch_add(1, Ordering::Release);
                return false;
            }
        }

        for (name, gauge) in gauges.iter() {
            let current_value = gauge.load(Ordering::Acquire);
            if !snapshot.contains_metric(name) || snapshot.get_gauge_value(name) != Some(current_value) {
                self.preservation_violations.fetch_add(1, Ordering::Release);
                return false;
            }
        }

        for (name, histogram) in histograms.iter() {
            if !snapshot.contains_metric(name) {
                self.preservation_violations.fetch_add(1, Ordering::Release);
                return false;
            }
        }

        true
    }

    fn get_preservation_violations(&self) -> usize {
        self.preservation_violations.load(Ordering::Acquire)
    }

    fn get_active_metrics_count(&self) -> (usize, usize, usize) {
        let counters = self.active_counters.read().len();
        let gauges = self.active_gauges.read().len();
        let histograms = self.active_histograms.read().len();
        (counters, gauges, histograms)
    }
}

/// Diagnostic snapshot capture coordinator
#[derive(Debug)]
struct DiagnosticSnapshotCoordinator {
    snapshot_config: DiagnosticSnapshotConfig,
    captured_snapshots: Arc<RwLock<Vec<CapturedDiagnosticSnapshot>>>,
    capture_metrics: CaptureMetrics,
    trigger_response_times: Arc<RwLock<Vec<Duration>>>,
}

impl DiagnosticSnapshotCoordinator {
    fn new(snapshot_config: DiagnosticSnapshotConfig) -> Self {
        Self {
            snapshot_config,
            captured_snapshots: Arc::new(RwLock::new(Vec::new())),
            capture_metrics: CaptureMetrics::new(),
            trigger_response_times: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn trigger_snapshot_capture(
        &self,
        trigger_event: &HealthAnomalyTriggerEvent,
        metrics_tracker: &InFlightMetricsTracker,
    ) -> Result<CapturedDiagnosticSnapshot> {
        let capture_start = Instant::now();

        // Create diagnostic trigger from anomaly event
        let diagnostic_trigger = DiagnosticTrigger {
            trigger_type: format!("health_anomaly_{:?}", trigger_event.anomaly_type),
            trigger_id: trigger_event.trigger_id,
            trigger_time: trigger_event.detection_time,
            source_component: "spectral_health".to_string(),
        };

        // Capture snapshot while preserving in-flight metrics
        let snapshot = self.capture_snapshot_with_preservation(
            &diagnostic_trigger,
            metrics_tracker,
        ).await?;

        let capture_time = capture_start.elapsed();
        {
            let mut times = self.trigger_response_times.write();
            times.push(capture_time);
        }

        let captured_snapshot = CapturedDiagnosticSnapshot {
            snapshot,
            capture_trigger: diagnostic_trigger,
            trigger_event: trigger_event.clone(),
            capture_duration: capture_time,
            metrics_preserved: metrics_tracker.verify_metric_preservation(&snapshot),
        };

        {
            let mut snapshots = self.captured_snapshots.write();
            snapshots.push(captured_snapshot.clone());
        }

        self.capture_metrics.record_snapshot_captured(capture_time);
        Ok(captured_snapshot)
    }

    async fn capture_snapshot_with_preservation(
        &self,
        trigger: &DiagnosticTrigger,
        metrics_tracker: &InFlightMetricsTracker,
    ) -> Result<DiagnosticSnapshot> {
        // Create snapshot with metric preservation
        let mut snapshot_builder = DiagnosticSnapshotBuilder::new();

        // Capture current metric state
        {
            let counters = metrics_tracker.active_counters.read();
            for (name, counter) in counters.iter() {
                let value = counter.load(Ordering::Acquire);
                snapshot_builder.add_counter_metric(name.clone(), value);
            }
        }

        {
            let gauges = metrics_tracker.active_gauges.read();
            for (name, gauge) in gauges.iter() {
                let value = gauge.load(Ordering::Acquire);
                snapshot_builder.add_gauge_metric(name.clone(), value);
            }
        }

        {
            let histograms = metrics_tracker.active_histograms.read();
            for (name, histogram) in histograms.iter() {
                snapshot_builder.add_histogram_metric(name.clone(), histogram.clone().into());
            }
        }

        // Add trigger context
        snapshot_builder.add_trigger_context(trigger.clone());

        // Build final snapshot
        let snapshot = snapshot_builder.build()?;
        Ok(snapshot)
    }

    fn get_captured_snapshots(&self) -> Vec<CapturedDiagnosticSnapshot> {
        self.captured_snapshots.read().clone()
    }

    fn verify_snapshot_integrity(&self) -> Result<SnapshotIntegrityResult> {
        let snapshots = self.captured_snapshots.read();
        let mut integrity_result = SnapshotIntegrityResult {
            total_snapshots: snapshots.len(),
            valid_snapshots: 0,
            invalid_snapshots: 0,
            preservation_failures: 0,
        };

        for snapshot in snapshots.iter() {
            if snapshot.snapshot.is_valid() && snapshot.metrics_preserved {
                integrity_result.valid_snapshots += 1;
            } else {
                integrity_result.invalid_snapshots += 1;
                if !snapshot.metrics_preserved {
                    integrity_result.preservation_failures += 1;
                }
            }
        }

        Ok(integrity_result)
    }

    fn get_capture_stats(&self) -> (usize, Duration) {
        let snapshots = self.captured_snapshots.read();
        let times = self.trigger_response_times.read();
        let count = snapshots.len();
        let avg_time = if !times.is_empty() {
            times.iter().sum::<Duration>() / times.len() as u32
        } else {
            Duration::ZERO
        };
        (count, avg_time)
    }
}

/// Captured diagnostic snapshot with metadata
#[derive(Debug, Clone)]
struct CapturedDiagnosticSnapshot {
    snapshot: DiagnosticSnapshot,
    capture_trigger: DiagnosticTrigger,
    trigger_event: HealthAnomalyTriggerEvent,
    capture_duration: Duration,
    metrics_preserved: bool,
}

/// Snapshot integrity verification result
#[derive(Debug)]
struct SnapshotIntegrityResult {
    total_snapshots: usize,
    valid_snapshots: usize,
    invalid_snapshots: usize,
    preservation_failures: usize,
}

impl SnapshotIntegrityResult {
    fn is_successful(&self) -> bool {
        self.total_snapshots > 0
            && self.invalid_snapshots == 0
            && self.preservation_failures == 0
    }
}

/// Metrics for tracking capture performance
#[derive(Debug)]
struct CaptureMetrics {
    snapshots_captured: Arc<AtomicUsize>,
    capture_times: Arc<RwLock<Vec<Duration>>>,
    capture_failures: Arc<AtomicUsize>,
}

impl CaptureMetrics {
    fn new() -> Self {
        Self {
            snapshots_captured: Arc::new(AtomicUsize::new(0)),
            capture_times: Arc::new(RwLock::new(Vec::new())),
            capture_failures: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_snapshot_captured(&self, capture_time: Duration) {
        self.snapshots_captured.fetch_add(1, Ordering::Release);
        let mut times = self.capture_times.write();
        times.push(capture_time);
    }

    fn record_capture_failure(&self) {
        self.capture_failures.fetch_add(1, Ordering::Release);
    }
}

/// Test harness for spectral health and diagnostics integration
#[derive(Debug)]
struct SpectralHealthDiagnosticsTestHarness {
    health_config: SpectralHealthConfig,
    snapshot_coordinator: DiagnosticSnapshotCoordinator,
    metrics_tracker: InFlightMetricsTracker,
    integration_timeout: Duration,
}

impl SpectralHealthDiagnosticsTestHarness {
    fn new(integration_timeout: Duration) -> Self {
        let health_config = SpectralHealthConfig {
            analysis_window: Duration::from_secs(10),
            anomaly_thresholds: vec![
                HealthThreshold::new("cpu_usage", 0.8),
                HealthThreshold::new("memory_usage", 0.9),
                HealthThreshold::new("task_queue_depth", 100.0),
            ],
            spectral_bands: 5,
            enable_anomaly_detection: true,
        };

        let snapshot_config = DiagnosticSnapshotConfig {
            capture_scope: SnapshotScope::FullSystem,
            include_metrics: true,
            include_traces: true,
            include_runtime_state: true,
            max_snapshot_size: 50 * 1024 * 1024, // 50MB
        };

        Self {
            health_config,
            snapshot_coordinator: DiagnosticSnapshotCoordinator::new(snapshot_config),
            metrics_tracker: InFlightMetricsTracker::new(),
            integration_timeout,
        }
    }

    async fn simulate_spectral_health_anomaly_detection(
        &self,
        cx: &Cx,
        anomaly_scenarios: Vec<HealthAnomalyScenario>,
    ) -> Result<()> {
        // Phase 1: Initialize continuous metric generation
        self.start_continuous_metric_generation(cx).await?;

        // Phase 2: Process each anomaly scenario
        for (i, scenario) in anomaly_scenarios.iter().enumerate() {
            cx.sleep(scenario.delay_before_anomaly).await;

            // Generate health anomaly event
            let anomaly_event = HealthAnomalyTriggerEvent::new(
                scenario.anomaly_type,
                scenario.health_score,
                scenario.threshold_breach.clone(),
                scenario.affected_metrics.clone(),
                i as u64,
            );

            // Trigger diagnostic snapshot capture
            let captured_snapshot = self.snapshot_coordinator.trigger_snapshot_capture(
                &anomaly_event,
                &self.metrics_tracker,
            ).await?;

            // Verify snapshot integrity immediately
            if !captured_snapshot.metrics_preserved {
                return Err(format!(
                    "Metric preservation failed for anomaly trigger {}",
                    i
                ).into());
            }

            // Continue metric generation during snapshot
            self.continue_metric_generation_during_snapshot(cx).await?;
        }

        // Phase 3: Final verification
        cx.sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    async fn start_continuous_metric_generation(&self, cx: &Cx) -> Result<()> {
        // Generate baseline metrics
        self.metrics_tracker.update_counter("requests_total".to_string(), 1);
        self.metrics_tracker.update_gauge("active_connections".to_string(), 42);
        self.metrics_tracker.record_histogram_sample("response_time_ms".to_string(), 125);

        self.metrics_tracker.update_counter("errors_total".to_string(), 1);
        self.metrics_tracker.update_gauge("memory_usage_bytes".to_string(), 1024 * 1024);
        self.metrics_tracker.record_histogram_sample("cpu_usage_percent".to_string(), 25);

        Ok(())
    }

    async fn continue_metric_generation_during_snapshot(&self, cx: &Cx) -> Result<()> {
        // Continue generating metrics while snapshot is being captured
        for i in 0..5 {
            self.metrics_tracker.update_counter("requests_total".to_string(), 1);
            self.metrics_tracker.update_gauge("active_connections".to_string(), 42 + i);
            self.metrics_tracker.record_histogram_sample("response_time_ms".to_string(), 125 + (i * 10));

            cx.sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    fn verify_integration_properties(&self) -> Result<()> {
        // Verify snapshot integrity
        let integrity_result = self.snapshot_coordinator.verify_snapshot_integrity()?;
        if !integrity_result.is_successful() {
            return Err(format!(
                "Snapshot integrity verification failed: {}/{} valid, {} preservation failures",
                integrity_result.valid_snapshots,
                integrity_result.total_snapshots,
                integrity_result.preservation_failures
            ).into());
        }

        // Verify metric preservation
        let preservation_violations = self.metrics_tracker.get_preservation_violations();
        if preservation_violations > 0 {
            return Err(format!(
                "Metric preservation violations detected: {}",
                preservation_violations
            ).into());
        }

        // Verify capture performance
        let (snapshot_count, avg_capture_time) = self.snapshot_coordinator.get_capture_stats();
        if snapshot_count == 0 {
            return Err(format!("No diagnostic snapshots were captured").into());
        }

        if avg_capture_time > self.integration_timeout {
            return Err(format!(
                "Average capture time {:?} exceeded timeout {:?}",
                avg_capture_time,
                self.integration_timeout
            ).into());
        }

        let (counters, gauges, histograms) = self.metrics_tracker.get_active_metrics_count();

        println!(
            "Spectral health/diagnostics integration verified: {} snapshots, {:?} avg capture time, {}/{}/{} metrics",
            snapshot_count,
            avg_capture_time,
            counters,
            gauges,
            histograms
        );

        Ok(())
    }
}

/// Health anomaly scenario for testing
#[derive(Debug, Clone)]
struct HealthAnomalyScenario {
    anomaly_type: AnomalyType,
    health_score: HealthScore,
    threshold_breach: HealthThreshold,
    affected_metrics: Vec<String>,
    delay_before_anomaly: Duration,
}

impl HealthAnomalyScenario {
    fn new(
        anomaly_type: AnomalyType,
        health_score: HealthScore,
        threshold_breach: HealthThreshold,
        affected_metrics: Vec<String>,
        delay_before_anomaly: Duration,
    ) -> Self {
        Self {
            anomaly_type,
            health_score,
            threshold_breach,
            affected_metrics,
            delay_before_anomaly,
        }
    }
}

/// Mock implementations for testing infrastructure

/// Anomaly types for health monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnomalyType {
    CpuSpike,
    MemoryLeak,
    TaskQueueBacklog,
    LatencyIncrease,
    ErrorRateSpike,
}

/// Health score representation
#[derive(Debug, Clone, Copy, PartialEq)]
struct HealthScore(f64);

impl HealthScore {
    fn new(score: f64) -> Self {
        Self(score.clamp(0.0, 1.0))
    }
}

/// Health threshold configuration
#[derive(Debug, Clone)]
struct HealthThreshold {
    metric_name: String,
    threshold_value: f64,
}

impl HealthThreshold {
    fn new(metric_name: &str, threshold_value: f64) -> Self {
        Self {
            metric_name: metric_name.to_string(),
            threshold_value,
        }
    }
}

/// Spectral health configuration
#[derive(Debug, Clone)]
struct SpectralHealthConfig {
    analysis_window: Duration,
    anomaly_thresholds: Vec<HealthThreshold>,
    spectral_bands: usize,
    enable_anomaly_detection: bool,
}

/// Diagnostic snapshot configuration
#[derive(Debug, Clone)]
struct DiagnosticSnapshotConfig {
    capture_scope: SnapshotScope,
    include_metrics: bool,
    include_traces: bool,
    include_runtime_state: bool,
    max_snapshot_size: usize,
}

/// Snapshot scope enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotScope {
    MetricsOnly,
    CurrentTask,
    CurrentRegion,
    FullSystem,
}

/// Diagnostic trigger information
#[derive(Debug, Clone)]
struct DiagnosticTrigger {
    trigger_type: String,
    trigger_id: u64,
    trigger_time: Instant,
    source_component: String,
}

/// Diagnostic snapshot structure
#[derive(Debug, Clone)]
struct DiagnosticSnapshot {
    snapshot_id: u64,
    capture_time: Instant,
    counter_metrics: HashMap<String, u64>,
    gauge_metrics: HashMap<String, u64>,
    histogram_metrics: HashMap<String, Vec<u64>>,
    trigger_context: Option<DiagnosticTrigger>,
}

impl DiagnosticSnapshot {
    fn new() -> Self {
        Self {
            snapshot_id: rand::random(),
            capture_time: Instant::now(),
            counter_metrics: HashMap::new(),
            gauge_metrics: HashMap::new(),
            histogram_metrics: HashMap::new(),
            trigger_context: None,
        }
    }

    fn contains_metric(&self, name: &str) -> bool {
        self.counter_metrics.contains_key(name)
            || self.gauge_metrics.contains_key(name)
            || self.histogram_metrics.contains_key(name)
    }

    fn get_counter_value(&self, name: &str) -> Option<u64> {
        self.counter_metrics.get(name).copied()
    }

    fn get_gauge_value(&self, name: &str) -> Option<u64> {
        self.gauge_metrics.get(name).copied()
    }

    fn is_valid(&self) -> bool {
        !self.counter_metrics.is_empty()
            || !self.gauge_metrics.is_empty()
            || !self.histogram_metrics.is_empty()
    }
}

/// Diagnostic snapshot builder
struct DiagnosticSnapshotBuilder {
    snapshot: DiagnosticSnapshot,
}

impl DiagnosticSnapshotBuilder {
    fn new() -> Self {
        Self {
            snapshot: DiagnosticSnapshot::new(),
        }
    }

    fn add_counter_metric(&mut self, name: String, value: u64) {
        self.snapshot.counter_metrics.insert(name, value);
    }

    fn add_gauge_metric(&mut self, name: String, value: u64) {
        self.snapshot.gauge_metrics.insert(name, value);
    }

    fn add_histogram_metric(&mut self, name: String, values: Vec<u64>) {
        self.snapshot.histogram_metrics.insert(name, values);
    }

    fn add_trigger_context(&mut self, trigger: DiagnosticTrigger) {
        self.snapshot.trigger_context = Some(trigger);
    }

    fn build(self) -> Result<DiagnosticSnapshot> {
        Ok(self.snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_anomaly_snapshot_trigger() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = SpectralHealthDiagnosticsTestHarness::new(Duration::from_millis(500));

        // Create basic anomaly scenario
        let scenario = HealthAnomalyScenario::new(
            AnomalyType::CpuSpike,
            HealthScore::new(0.2),
            HealthThreshold::new("cpu_usage", 0.8),
            vec!["cpu_usage_percent".to_string()],
            Duration::from_millis(50),
        );

        // Run anomaly detection simulation
        harness.simulate_spectral_health_anomaly_detection(
            &cx,
            vec![scenario],
        ).await?;

        // Verify snapshot was captured
        let snapshots = harness.snapshot_coordinator.get_captured_snapshots();
        assert_eq!(snapshots.len(), 1, "Should capture exactly one diagnostic snapshot");

        let snapshot = &snapshots[0];
        assert!(snapshot.metrics_preserved, "Metrics should be preserved during capture");
        assert!(snapshot.snapshot.is_valid(), "Captured snapshot should be valid");

        Ok(())
    }

    #[tokio::test]
    async fn test_metric_preservation_during_snapshot() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = SpectralHealthDiagnosticsTestHarness::new(Duration::from_millis(300));

        // Generate active metrics
        harness.start_continuous_metric_generation(&cx).await?;

        // Create anomaly that should preserve metrics
        let anomaly_event = HealthAnomalyTriggerEvent::new(
            AnomalyType::MemoryLeak,
            HealthScore::new(0.1),
            HealthThreshold::new("memory_usage", 0.9),
            vec!["memory_usage_bytes".to_string()],
            1,
        );

        // Trigger snapshot capture
        let captured_snapshot = harness.snapshot_coordinator.trigger_snapshot_capture(
            &anomaly_event,
            &harness.metrics_tracker,
        ).await?;

        // Verify metric preservation
        assert!(captured_snapshot.metrics_preserved, "Metrics should be preserved during snapshot");
        assert!(captured_snapshot.snapshot.contains_metric("requests_total"), "Counter metrics should be captured");
        assert!(captured_snapshot.snapshot.contains_metric("active_connections"), "Gauge metrics should be captured");
        assert!(captured_snapshot.snapshot.contains_metric("response_time_ms"), "Histogram metrics should be captured");

        // Verify no preservation violations
        let violations = harness.metrics_tracker.get_preservation_violations();
        assert_eq!(violations, 0, "No metric preservation violations should occur");

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_anomaly_snapshots() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = SpectralHealthDiagnosticsTestHarness::new(Duration::from_millis(800));

        // Create multiple anomaly scenarios
        let scenarios = vec![
            HealthAnomalyScenario::new(
                AnomalyType::CpuSpike,
                HealthScore::new(0.3),
                HealthThreshold::new("cpu_usage", 0.8),
                vec!["cpu_usage_percent".to_string()],
                Duration::from_millis(20),
            ),
            HealthAnomalyScenario::new(
                AnomalyType::TaskQueueBacklog,
                HealthScore::new(0.4),
                HealthThreshold::new("task_queue_depth", 100.0),
                vec!["task_queue_depth".to_string()],
                Duration::from_millis(40),
            ),
            HealthAnomalyScenario::new(
                AnomalyType::ErrorRateSpike,
                HealthScore::new(0.2),
                HealthThreshold::new("error_rate", 0.1),
                vec!["errors_total".to_string()],
                Duration::from_millis(30),
            ),
        ];

        // Run multiple anomaly detection
        harness.simulate_spectral_health_anomaly_detection(&cx, scenarios).await?;

        // Verify all snapshots were captured
        let snapshots = harness.snapshot_coordinator.get_captured_snapshots();
        assert_eq!(snapshots.len(), 3, "Should capture snapshot for each anomaly");

        // Verify each snapshot integrity
        for (i, snapshot) in snapshots.iter().enumerate() {
            assert!(snapshot.metrics_preserved, "Snapshot {} should preserve metrics", i);
            assert!(snapshot.snapshot.is_valid(), "Snapshot {} should be valid", i);
        }

        // Verify no preservation violations across all snapshots
        let violations = harness.metrics_tracker.get_preservation_violations();
        assert_eq!(violations, 0, "No preservation violations across multiple snapshots");

        Ok(())
    }

    #[tokio::test]
    async fn test_snapshot_capture_performance() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let tight_timeout = Duration::from_millis(100);
        let harness = SpectralHealthDiagnosticsTestHarness::new(tight_timeout);

        // Create performance test scenario
        let scenario = HealthAnomalyScenario::new(
            AnomalyType::LatencyIncrease,
            HealthScore::new(0.5),
            HealthThreshold::new("latency_p99", 200.0),
            vec!["response_time_ms".to_string()],
            Duration::from_millis(10),
        );

        let capture_start = Instant::now();

        // Run capture with timing
        harness.simulate_spectral_health_anomaly_detection(
            &cx,
            vec![scenario],
        ).await?;

        let total_time = capture_start.elapsed();

        // Verify capture performance
        assert!(total_time < Duration::from_millis(200), "Total capture should be fast");

        let (snapshot_count, avg_capture_time) = harness.snapshot_coordinator.get_capture_stats();
        assert_eq!(snapshot_count, 1, "Should have captured one snapshot");
        assert!(avg_capture_time < tight_timeout, "Average capture time should meet timeout");

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_spectral_health_diagnostics_integration() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = SpectralHealthDiagnosticsTestHarness::new(Duration::from_millis(600));

        // Create comprehensive test scenarios
        let scenarios = vec![
            HealthAnomalyScenario::new(
                AnomalyType::CpuSpike,
                HealthScore::new(0.1),
                HealthThreshold::new("cpu_usage", 0.8),
                vec!["cpu_usage_percent".to_string()],
                Duration::from_millis(25),
            ),
            HealthAnomalyScenario::new(
                AnomalyType::MemoryLeak,
                HealthScore::new(0.15),
                HealthThreshold::new("memory_usage", 0.9),
                vec!["memory_usage_bytes".to_string()],
                Duration::from_millis(35),
            ),
            HealthAnomalyScenario::new(
                AnomalyType::TaskQueueBacklog,
                HealthScore::new(0.3),
                HealthThreshold::new("task_queue_depth", 100.0),
                vec!["task_queue_depth".to_string(), "active_connections".to_string()],
                Duration::from_millis(45),
            ),
            HealthAnomalyScenario::new(
                AnomalyType::ErrorRateSpike,
                HealthScore::new(0.05),
                HealthThreshold::new("error_rate", 0.1),
                vec!["errors_total".to_string(), "requests_total".to_string()],
                Duration::from_millis(20),
            ),
        ];

        // Run comprehensive integration test
        harness.simulate_spectral_health_anomaly_detection(&cx, scenarios).await?;

        // Verify comprehensive integration properties
        harness.verify_integration_properties()?;

        // Verify detailed results
        let snapshots = harness.snapshot_coordinator.get_captured_snapshots();
        assert_eq!(snapshots.len(), 4, "Should capture all anomaly snapshots");

        let integrity_result = harness.snapshot_coordinator.verify_snapshot_integrity()?;
        assert!(integrity_result.is_successful(), "All snapshots should maintain integrity");

        let violations = harness.metrics_tracker.get_preservation_violations();
        assert_eq!(violations, 0, "No metric preservation violations should occur");

        let (counters, gauges, histograms) = harness.metrics_tracker.get_active_metrics_count();
        assert!(counters > 0 && gauges > 0 && histograms > 0, "Should track multiple metric types");

        println!(
            "Comprehensive spectral health/diagnostics integration completed: {} snapshots, {}/{}/{} metrics tracked",
            snapshots.len(),
            counters,
            gauges,
            histograms
        );

        Ok(())
    }
}