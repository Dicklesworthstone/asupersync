//! Structured Cancellation Trace Analyzer
//!
//! Deep analysis and visualization of cancellation propagation paths through the structured
//! concurrency tree. Detects anomalies like slow propagation, stuck cancellations, or
//! incorrect propagation patterns.
//!
//! This module provides real-time cancellation monitoring with minimal overhead, building
//! on the existing observability infrastructure to provide comprehensive insights into
//! cancellation behavior across complex structured concurrency applications.

use crate::types::{CancelKind, CancelReason};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Configuration for cancellation trace collection.
#[derive(Debug, Clone)]
pub struct CancellationTracerConfig {
    /// Enable real-time cancellation tracing.
    pub enable_tracing: bool,
    /// Maximum trace depth to collect (prevents memory explosion).
    pub max_trace_depth: usize,
    /// Maximum number of traces to keep in memory.
    pub max_traces: usize,
    /// Threshold for detecting slow cancellation propagation.
    pub slow_propagation_threshold_ms: u64,
    /// Threshold for detecting stuck cancellations.
    pub stuck_cancellation_timeout_ms: u64,
    /// Enable detailed timing measurements (higher overhead).
    pub enable_timing_analysis: bool,
    /// Sample rate for trace collection (0.0-1.0).
    pub sample_rate: f64,
}

impl Default for CancellationTracerConfig {
    fn default() -> Self {
        Self {
            enable_tracing: true,
            max_trace_depth: 64,
            max_traces: 10_000,
            slow_propagation_threshold_ms: 100,
            stuck_cancellation_timeout_ms: 5_000,
            enable_timing_analysis: cfg!(debug_assertions),
            sample_rate: 1.0,
        }
    }
}

/// Unique identifier for a cancellation trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraceId(u64);

impl TraceId {
    /// Creates a new trace ID.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns the inner trace ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

/// A single step in a cancellation propagation trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationTraceStep {
    /// Sequence number within the trace.
    pub step_id: u32,
    /// Entity that received cancellation.
    pub entity_id: String,
    /// Type of entity (Task, Region).
    pub entity_type: EntityType,
    /// Cancellation reason.
    pub cancel_reason: String,
    /// Kind of cancellation.
    pub cancel_kind: String,
    /// Timestamp when cancellation was received.
    pub timestamp: SystemTime,
    /// Time elapsed since trace started.
    pub elapsed_since_start: Duration,
    /// Time elapsed since previous step.
    pub elapsed_since_prev: Duration,
    /// Depth in the propagation tree.
    pub depth: u32,
    /// Parent entity that propagated cancellation to this entity.
    pub parent_entity: Option<String>,
    /// Current state of the entity.
    pub entity_state: String,
    /// Whether this step completed propagation successfully.
    pub propagation_completed: bool,
}

/// Type of entity in the cancellation trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    /// A task entity.
    Task,
    /// A region entity.
    Region,
}

/// A complete cancellation propagation trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationTrace {
    /// Unique identifier for this trace.
    pub trace_id: TraceId,
    /// Root cancellation that started the trace.
    pub root_cancel_reason: String,
    /// Initial cancellation kind.
    pub root_cancel_kind: String,
    /// Entity that initiated the cancellation.
    pub root_entity: String,
    /// Type of root entity.
    pub root_entity_type: EntityType,
    /// Timestamp when trace started.
    pub start_time: SystemTime,
    /// All propagation steps in order.
    pub steps: Vec<CancellationTraceStep>,
    /// Whether the trace is complete (all propagation finished).
    pub is_complete: bool,
    /// Total propagation time (if complete).
    pub total_propagation_time: Option<Duration>,
    /// Maximum depth reached in propagation tree.
    pub max_depth: u32,
    /// Number of entities that were cancelled.
    pub entities_cancelled: u32,
    /// Detected anomalies in this trace.
    pub anomalies: Vec<PropagationAnomaly>,
}

/// Types of anomalies detected during cancellation propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropagationAnomaly {
    /// Propagation took longer than expected threshold.
    SlowPropagation {
        step_id: u32,
        entity_id: String,
        elapsed: Duration,
        threshold: Duration,
    },
    /// Cancellation appears to be stuck.
    StuckCancellation {
        entity_id: String,
        stuck_duration: Duration,
    },
    /// Child was cancelled before parent.
    IncorrectPropagationOrder {
        parent_entity: String,
        child_entity: String,
        parent_step: u32,
        child_step: u32,
    },
    /// Unexpected propagation pattern.
    UnexpectedPropagation {
        description: String,
        affected_entities: Vec<String>,
    },
    /// Propagation depth exceeded normal bounds.
    ExcessiveDepth { depth: u32, entity_id: String },
}

/// Statistics about cancellation tracing.
#[derive(Debug, Default)]
pub struct CancellationTracerStats {
    /// Total number of traces collected.
    pub traces_collected: AtomicU64,
    /// Total number of propagation steps recorded.
    pub steps_recorded: AtomicU64,
    /// Number of anomalies detected.
    pub anomalies_detected: AtomicU64,
    /// Number of slow propagations detected.
    pub slow_propagations: AtomicU64,
    /// Number of stuck cancellations detected.
    pub stuck_cancellations: AtomicU64,
    /// Number of incorrect propagation orders detected.
    pub incorrect_orders: AtomicU64,
    /// Average trace depth.
    pub avg_trace_depth: AtomicU64,
    /// Average propagation time in microseconds.
    pub avg_propagation_time_us: AtomicU64,
}

impl CancellationTracerStats {
    /// Gets a snapshot of current statistics.
    pub fn snapshot(&self) -> CancellationTracerStatsSnapshot {
        CancellationTracerStatsSnapshot {
            traces_collected: self.traces_collected.load(Ordering::Relaxed),
            steps_recorded: self.steps_recorded.load(Ordering::Relaxed),
            anomalies_detected: self.anomalies_detected.load(Ordering::Relaxed),
            slow_propagations: self.slow_propagations.load(Ordering::Relaxed),
            stuck_cancellations: self.stuck_cancellations.load(Ordering::Relaxed),
            incorrect_orders: self.incorrect_orders.load(Ordering::Relaxed),
            avg_trace_depth: self.avg_trace_depth.load(Ordering::Relaxed),
            avg_propagation_time_us: self.avg_propagation_time_us.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of cancellation tracer statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationTracerStatsSnapshot {
    pub traces_collected: u64,
    pub steps_recorded: u64,
    pub anomalies_detected: u64,
    pub slow_propagations: u64,
    pub stuck_cancellations: u64,
    pub incorrect_orders: u64,
    pub avg_trace_depth: u64,
    pub avg_propagation_time_us: u64,
}

/// In-progress cancellation trace being built.
#[derive(Debug)]
struct InProgressTrace {
    trace: CancellationTrace,
    last_step_time: SystemTime,
    entity_to_step: HashMap<String, u32>,
    depth_by_entity: HashMap<String, u32>,
}

/// Structured cancellation trace analyzer.
#[derive(Debug)]
pub struct CancellationTracer {
    config: CancellationTracerConfig,
    stats: CancellationTracerStats,
    /// In-progress traces being built.
    in_progress: Arc<Mutex<HashMap<TraceId, InProgressTrace>>>,
    /// Completed traces.
    completed_traces: Arc<Mutex<VecDeque<CancellationTrace>>>,
    /// Mapping from entity to active trace IDs.
    entity_traces: Arc<Mutex<HashMap<String, Vec<TraceId>>>>,
}

impl CancellationTracer {
    /// Creates a new cancellation tracer.
    pub fn new(config: CancellationTracerConfig) -> Self {
        Self {
            config,
            stats: CancellationTracerStats::default(),
            in_progress: Arc::new(Mutex::new(HashMap::new())),
            completed_traces: Arc::new(Mutex::new(VecDeque::new())),
            entity_traces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Starts a new cancellation trace from a root cancellation.
    pub fn start_trace(
        &self,
        root_entity: String,
        entity_type: EntityType,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
    ) -> TraceId {
        if !self.config.enable_tracing {
            return TraceId::new(); // Return dummy ID
        }

        // Sample based on configured rate
        if self.config.sample_rate < 1.0 {
            let hash = self.hash_entity(&root_entity);
            if self.sample_unit_interval(hash) > self.config.sample_rate {
                return TraceId::new(); // Skip this trace
            }
        }

        let trace_id = TraceId::new();
        let now = SystemTime::now();

        let trace = CancellationTrace {
            trace_id,
            root_cancel_reason: format!("{cancel_reason:?}"),
            root_cancel_kind: format!("{cancel_kind:?}"),
            root_entity: root_entity.clone(),
            root_entity_type: entity_type,
            start_time: now,
            steps: Vec::new(),
            is_complete: false,
            total_propagation_time: None,
            max_depth: 0,
            entities_cancelled: 0,
            anomalies: Vec::new(),
        };

        let in_progress_trace = InProgressTrace {
            trace,
            last_step_time: now,
            entity_to_step: HashMap::new(),
            depth_by_entity: HashMap::new(),
        };

        // Store the in-progress trace
        if let Ok(mut in_progress) = self.in_progress.lock() {
            in_progress.insert(trace_id, in_progress_trace);
        }

        // Track entity -> trace mapping
        if let Ok(mut entity_traces) = self.entity_traces.lock() {
            entity_traces.entry(root_entity).or_default().push(trace_id);
        }

        self.stats.traces_collected.fetch_add(1, Ordering::Relaxed);
        trace_id
    }

    /// Records a cancellation propagation step.
    pub fn record_step(
        &self,
        trace_id: TraceId,
        entity_id: String,
        entity_type: EntityType,
        cancel_reason: &CancelReason,
        cancel_kind: CancelKind,
        entity_state: String,
        parent_entity: Option<String>,
        propagation_completed: bool,
    ) {
        if !self.config.enable_tracing {
            return;
        }

        let now = SystemTime::now();

        if let Ok(mut in_progress) = self.in_progress.lock() {
            if let Some(in_progress_trace) = in_progress.get_mut(&trace_id) {
                let elapsed_since_start = now
                    .duration_since(in_progress_trace.trace.start_time)
                    .unwrap_or(Duration::ZERO);
                let elapsed_since_prev = now
                    .duration_since(in_progress_trace.last_step_time)
                    .unwrap_or(Duration::ZERO);

                // Determine depth
                let depth = if let Some(parent) = &parent_entity {
                    in_progress_trace
                        .depth_by_entity
                        .get(parent)
                        .copied()
                        .unwrap_or(0)
                        + 1
                } else {
                    0
                };

                let step_id = in_progress_trace.trace.steps.len() as u32;
                let step = CancellationTraceStep {
                    step_id,
                    entity_id: entity_id.clone(),
                    entity_type,
                    cancel_reason: format!("{cancel_reason:?}"),
                    cancel_kind: format!("{cancel_kind:?}"),
                    timestamp: now,
                    elapsed_since_start,
                    elapsed_since_prev,
                    depth,
                    parent_entity,
                    entity_state,
                    propagation_completed,
                };

                // Check for anomalies
                self.check_for_anomalies(&step, in_progress_trace);

                // Update trace state
                in_progress_trace.trace.steps.push(step);
                in_progress_trace.last_step_time = now;
                in_progress_trace
                    .entity_to_step
                    .insert(entity_id.clone(), step_id);
                in_progress_trace
                    .depth_by_entity
                    .insert(entity_id.clone(), depth);
                in_progress_trace.trace.max_depth = in_progress_trace.trace.max_depth.max(depth);
                in_progress_trace.trace.entities_cancelled += 1;

                self.stats.steps_recorded.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Completes a cancellation trace.
    pub fn complete_trace(&self, trace_id: TraceId) {
        if !self.config.enable_tracing {
            return;
        }

        if let Ok(mut in_progress) = self.in_progress.lock() {
            if let Some(mut in_progress_trace) = in_progress.remove(&trace_id) {
                let completion_time = SystemTime::now();
                let total_time = completion_time
                    .duration_since(in_progress_trace.trace.start_time)
                    .unwrap_or(Duration::ZERO);

                in_progress_trace.trace.is_complete = true;
                in_progress_trace.trace.total_propagation_time = Some(total_time);

                // Update statistics
                self.update_completion_stats(&in_progress_trace.trace);

                // Store completed trace
                if let Ok(mut completed) = self.completed_traces.lock() {
                    completed.push_back(in_progress_trace.trace);

                    // Maintain size limit
                    while completed.len() > self.config.max_traces {
                        completed.pop_front();
                    }
                }

                // Clean up entity mappings
                if let Ok(mut entity_traces) = self.entity_traces.lock() {
                    for traces in entity_traces.values_mut() {
                        traces.retain(|&id| id != trace_id);
                    }
                }
            }
        }
    }

    /// Gets statistics about cancellation tracing.
    pub fn stats(&self) -> CancellationTracerStatsSnapshot {
        self.stats.snapshot()
    }

    /// Gets all completed traces (for analysis).
    pub fn completed_traces(&self) -> Vec<CancellationTrace> {
        self.completed_traces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Gets traces that are currently in progress.
    pub fn in_progress_traces(&self) -> Vec<TraceId> {
        self.in_progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Gets traces related to a specific entity.
    pub fn traces_for_entity(&self, entity_id: &str) -> Vec<TraceId> {
        self.entity_traces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(entity_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Detects anomalies in cancellation propagation.
    fn check_for_anomalies(&self, step: &CancellationTraceStep, trace: &mut InProgressTrace) {
        // Check for slow propagation
        if step.elapsed_since_prev.as_millis() > self.config.slow_propagation_threshold_ms as u128 {
            let anomaly = PropagationAnomaly::SlowPropagation {
                step_id: step.step_id,
                entity_id: step.entity_id.clone(),
                elapsed: step.elapsed_since_prev,
                threshold: Duration::from_millis(self.config.slow_propagation_threshold_ms),
            };
            trace.trace.anomalies.push(anomaly);
            self.stats.slow_propagations.fetch_add(1, Ordering::Relaxed);
        }

        // Check for excessive depth
        if step.depth > self.config.max_trace_depth as u32 {
            let anomaly = PropagationAnomaly::ExcessiveDepth {
                depth: step.depth,
                entity_id: step.entity_id.clone(),
            };
            trace.trace.anomalies.push(anomaly);
        }

        // Check for incorrect propagation order (simplified check)
        if let Some(parent) = &step.parent_entity {
            if let Some(&parent_step_id) = trace.entity_to_step.get(parent) {
                if step.step_id < parent_step_id {
                    let anomaly = PropagationAnomaly::IncorrectPropagationOrder {
                        parent_entity: parent.clone(),
                        child_entity: step.entity_id.clone(),
                        parent_step: parent_step_id,
                        child_step: step.step_id,
                    };
                    trace.trace.anomalies.push(anomaly);
                    self.stats.incorrect_orders.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        if !trace.trace.anomalies.is_empty() {
            self.stats
                .anomalies_detected
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Updates statistics when a trace completes.
    fn update_completion_stats(&self, trace: &CancellationTrace) {
        if let Some(total_time) = trace.total_propagation_time {
            self.stats
                .avg_propagation_time_us
                .store(total_time.as_micros() as u64, Ordering::Relaxed);
        }

        self.stats
            .avg_trace_depth
            .store(trace.max_depth as u64, Ordering::Relaxed);
    }

    /// Hash function for sampling decisions.
    fn hash_entity(&self, entity: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        entity.hash(&mut hasher);
        hasher.finish()
    }

    /// Convert hash to unit interval for sampling.
    fn sample_unit_interval(&self, hash: u64) -> f64 {
        const TWO_POW_53_F64: f64 = 9_007_199_254_740_992.0;
        let bits = hash >> 11;
        bits as f64 / TWO_POW_53_F64
    }
}

/// Analysis result for cancellation patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationAnalysis {
    /// Time period analyzed.
    pub analysis_period: Duration,
    /// Total number of traces analyzed.
    pub traces_analyzed: usize,
    /// Total propagation steps.
    pub total_steps: usize,
    /// Average propagation depth.
    pub avg_depth: f64,
    /// Average propagation time.
    pub avg_propagation_time: Duration,
    /// Most common cancellation kinds.
    pub common_cancel_kinds: Vec<(String, usize)>,
    /// Entities with highest cancellation frequency.
    pub high_cancellation_entities: Vec<(String, usize)>,
    /// Summary of detected anomalies.
    pub anomaly_summary: BTreeMap<String, usize>,
    /// Performance bottlenecks identified.
    pub bottlenecks: Vec<String>,
    /// Recommendations for optimization.
    pub recommendations: Vec<String>,
}

/// Analyzes cancellation traces to extract insights.
pub fn analyze_cancellation_patterns(traces: &[CancellationTrace]) -> CancellationAnalysis {
    if traces.is_empty() {
        return CancellationAnalysis {
            analysis_period: Duration::ZERO,
            traces_analyzed: 0,
            total_steps: 0,
            avg_depth: 0.0,
            avg_propagation_time: Duration::ZERO,
            common_cancel_kinds: Vec::new(),
            high_cancellation_entities: Vec::new(),
            anomaly_summary: BTreeMap::new(),
            bottlenecks: Vec::new(),
            recommendations: Vec::new(),
        };
    }

    let total_steps: usize = traces.iter().map(|t| t.steps.len()).sum();
    let avg_depth: f64 =
        traces.iter().map(|t| t.max_depth as f64).sum::<f64>() / traces.len() as f64;

    let avg_propagation_time = traces
        .iter()
        .filter_map(|t| t.total_propagation_time)
        .map(|d| d.as_nanos() as f64)
        .sum::<f64>()
        / traces.len() as f64;

    // Analyze common cancellation kinds
    let mut cancel_kind_counts: HashMap<String, usize> = HashMap::new();
    for trace in traces {
        *cancel_kind_counts
            .entry(trace.root_cancel_kind.clone())
            .or_default() += 1;
    }
    let mut common_cancel_kinds: Vec<_> = cancel_kind_counts.into_iter().collect();
    common_cancel_kinds.sort_by(|a, b| b.1.cmp(&a.1));

    // Analyze high-cancellation entities
    let mut entity_counts: HashMap<String, usize> = HashMap::new();
    for trace in traces {
        for step in &trace.steps {
            *entity_counts.entry(step.entity_id.clone()).or_default() += 1;
        }
    }
    let mut high_cancellation_entities: Vec<_> = entity_counts.into_iter().collect();
    high_cancellation_entities.sort_by(|a, b| b.1.cmp(&a.1));
    high_cancellation_entities.truncate(10); // Top 10

    // Analyze anomalies
    let mut anomaly_summary: BTreeMap<String, usize> = BTreeMap::new();
    for trace in traces {
        for anomaly in &trace.anomalies {
            let anomaly_type = match anomaly {
                PropagationAnomaly::SlowPropagation { .. } => "SlowPropagation",
                PropagationAnomaly::StuckCancellation { .. } => "StuckCancellation",
                PropagationAnomaly::IncorrectPropagationOrder { .. } => "IncorrectOrder",
                PropagationAnomaly::UnexpectedPropagation { .. } => "UnexpectedPropagation",
                PropagationAnomaly::ExcessiveDepth { .. } => "ExcessiveDepth",
            };
            *anomaly_summary.entry(anomaly_type.to_string()).or_default() += 1;
        }
    }

    // Detect performance bottlenecks
    let mut bottlenecks = Vec::new();

    // Bottleneck 1: Entities with disproportionately high cancellation frequency
    let total_entity_cancellations: usize = high_cancellation_entities
        .iter()
        .map(|(_, count)| *count)
        .sum();
    if total_entity_cancellations > 0 {
        for (entity_id, count) in &high_cancellation_entities {
            let frequency_ratio = *count as f64 / total_entity_cancellations as f64;
            if frequency_ratio > 0.3 {
                // Entity accounts for >30% of all cancellations
                bottlenecks.push(format!(
                    "High-frequency cancellation source: {} ({:.1}% of all cancellations)",
                    entity_id,
                    frequency_ratio * 100.0
                ));
            }
        }
    }

    // Bottleneck 2: Entities frequently involved in slow propagations
    let mut slow_propagation_entities: HashMap<String, usize> = HashMap::new();
    for trace in traces {
        for anomaly in &trace.anomalies {
            if let PropagationAnomaly::SlowPropagation { entity_id, .. } = anomaly {
                *slow_propagation_entities
                    .entry(entity_id.clone())
                    .or_default() += 1;
            }
        }
    }
    for (entity_id, slow_count) in slow_propagation_entities {
        if slow_count > traces.len() / 20 {
            // Appears in >5% of traces with slow propagation
            bottlenecks.push(format!(
                "Slow propagation bottleneck: {} (involved in {} slow propagations)",
                entity_id, slow_count
            ));
        }
    }

    // Bottleneck 3: Entities causing stuck cancellations
    let mut stuck_entities: HashMap<String, usize> = HashMap::new();
    for trace in traces {
        for anomaly in &trace.anomalies {
            if let PropagationAnomaly::StuckCancellation { entity_id, .. } = anomaly {
                *stuck_entities.entry(entity_id.clone()).or_default() += 1;
            }
        }
    }
    for (entity_id, stuck_count) in stuck_entities {
        if stuck_count > 0 {
            // Any stuck cancellation is a bottleneck
            bottlenecks.push(format!(
                "Stuck cancellation bottleneck: {} ({} instances)",
                entity_id, stuck_count
            ));
        }
    }

    // Bottleneck 4: Deep cancellation tree origins
    let mut depth_bottlenecks: HashMap<String, f64> = HashMap::new();
    for trace in traces {
        if trace.steps.len() as f64 > avg_depth * 1.5 {
            // Traces significantly deeper than average
            if let Some(first_step) = trace.steps.first() {
                let current_avg = depth_bottlenecks
                    .entry(first_step.entity_id.clone())
                    .or_insert(0.0);
                *current_avg = (*current_avg + trace.steps.len() as f64) / 2.0; // Running average
            }
        }
    }
    for (entity_id, avg_depth_caused) in depth_bottlenecks {
        if avg_depth_caused > avg_depth * 1.5 {
            bottlenecks.push(format!(
                "Deep cancellation tree origin: {} (avg depth: {:.1})",
                entity_id, avg_depth_caused
            ));
        }
    }

    // Generate recommendations
    let mut recommendations = Vec::new();
    if avg_propagation_time > 10_000_000.0 {
        // 10ms
        recommendations.push(
            "Consider optimizing cancellation propagation - average time is high".to_string(),
        );
    }
    if avg_depth > 10.0 {
        recommendations.push(
            "Deep cancellation trees detected - consider flatter structured concurrency"
                .to_string(),
        );
    }
    if anomaly_summary.get("SlowPropagation").copied().unwrap_or(0) > traces.len() / 10 {
        recommendations.push(
            "Frequent slow propagations - investigate blocking operations in cancellation handlers"
                .to_string(),
        );
    }
    if !bottlenecks.is_empty() {
        recommendations.push(format!(
            "Address {} identified performance bottlenecks to improve cancellation efficiency",
            bottlenecks.len()
        ));
    }

    CancellationAnalysis {
        analysis_period: Duration::from_nanos(avg_propagation_time as u64),
        traces_analyzed: traces.len(),
        total_steps,
        avg_depth,
        avg_propagation_time: Duration::from_nanos(avg_propagation_time as u64),
        common_cancel_kinds,
        high_cancellation_entities,
        anomaly_summary,
        bottlenecks,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_creation() {
        let config = CancellationTracerConfig::default();
        let tracer = CancellationTracer::new(config);
        let stats = tracer.stats();
        assert_eq!(stats.traces_collected, 0);
        assert_eq!(stats.steps_recorded, 0);
    }

    #[test]
    fn test_trace_lifecycle() {
        let config = CancellationTracerConfig::default();
        let tracer = CancellationTracer::new(config);

        // Start a trace
        let trace_id = tracer.start_trace(
            "task-1".to_string(),
            EntityType::Task,
            &CancelReason::with_user_reason("test".to_string()),
            CancelKind::User,
        );

        // Record a step
        tracer.record_step(
            trace_id,
            "region-1".to_string(),
            EntityType::Region,
            &CancelReason::with_user_reason("propagation".to_string()),
            CancelKind::User,
            "Closing".to_string(),
            Some("task-1".to_string()),
            true,
        );

        // Complete the trace
        tracer.complete_trace(trace_id);

        let stats = tracer.stats();
        assert_eq!(stats.traces_collected, 1);
        assert_eq!(stats.steps_recorded, 1);

        let completed = tracer.completed_traces();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].is_complete);
    }

    #[test]
    fn test_anomaly_detection() {
        let mut config = CancellationTracerConfig::default();
        config.slow_propagation_threshold_ms = 1; // Very low threshold for testing
        let tracer = CancellationTracer::new(config);

        let trace_id = tracer.start_trace(
            "task-1".to_string(),
            EntityType::Task,
            &CancelReason::with_user_reason("test".to_string()),
            CancelKind::User,
        );

        // Simulate slow propagation by adding delay
        std::thread::sleep(Duration::from_millis(5));

        tracer.record_step(
            trace_id,
            "region-1".to_string(),
            EntityType::Region,
            &CancelReason::with_user_reason("slow".to_string()),
            CancelKind::User,
            "Closing".to_string(),
            Some("task-1".to_string()),
            true,
        );

        tracer.complete_trace(trace_id);

        let completed = tracer.completed_traces();
        assert!(!completed.is_empty());

        // Should detect slow propagation anomaly
        assert!(!completed[0].anomalies.is_empty());
        assert!(matches!(
            completed[0].anomalies[0],
            PropagationAnomaly::SlowPropagation { .. }
        ));
    }

    #[test]
    fn test_analysis_patterns() {
        let traces = vec![
            CancellationTrace {
                trace_id: TraceId::new(),
                root_cancel_reason: "test1".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "task-1".to_string(),
                root_entity_type: EntityType::Task,
                start_time: SystemTime::now(),
                steps: vec![],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(10)),
                max_depth: 3,
                entities_cancelled: 5,
                anomalies: vec![],
            },
            CancellationTrace {
                trace_id: TraceId::new(),
                root_cancel_reason: "test2".to_string(),
                root_cancel_kind: "Timeout".to_string(),
                root_entity: "task-2".to_string(),
                root_entity_type: EntityType::Task,
                start_time: SystemTime::now(),
                steps: vec![],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(5)),
                max_depth: 2,
                entities_cancelled: 3,
                anomalies: vec![],
            },
        ];

        let analysis = analyze_cancellation_patterns(&traces);
        assert_eq!(analysis.traces_analyzed, 2);
        assert_eq!(analysis.avg_depth, 2.5);
        assert!(!analysis.common_cancel_kinds.is_empty());
    }

    #[test]
    fn test_bottleneck_detection() {
        // Create traces with various bottleneck patterns
        let traces = vec![
            CancellationTrace {
                trace_id: "trace1".to_string(),
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "bottleneck-entity".to_string(),
                root_entity_type: EntityType::Task,
                start_time: SystemTime::now(),
                steps: vec![CancellationStep {
                    entity_id: "bottleneck-entity".to_string(),
                    entity_type: EntityType::Task,
                    cancel_reason: CancelReason::with_user_reason("high frequency".to_string()),
                    cancel_kind: CancelKind::User,
                    result: "Cancelled".to_string(),
                    parent_entity: None,
                    timestamp: SystemTime::now(),
                    is_root: true,
                }],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(1)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![
                    PropagationAnomaly::SlowPropagation {
                        entity_id: "slow-entity".to_string(),
                        expected_time: Duration::from_millis(1),
                        actual_time: Duration::from_millis(100),
                    },
                    PropagationAnomaly::StuckCancellation {
                        entity_id: "stuck-entity".to_string(),
                        timeout: Duration::from_millis(500),
                    },
                ],
            },
            // Create multiple traces to make "bottleneck-entity" high frequency
            CancellationTrace {
                trace_id: "trace2".to_string(),
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "bottleneck-entity".to_string(),
                root_entity_type: EntityType::Task,
                start_time: SystemTime::now(),
                steps: vec![CancellationStep {
                    entity_id: "bottleneck-entity".to_string(),
                    entity_type: EntityType::Task,
                    cancel_reason: CancelReason::with_user_reason("high frequency".to_string()),
                    cancel_kind: CancelKind::User,
                    result: "Cancelled".to_string(),
                    parent_entity: None,
                    timestamp: SystemTime::now(),
                    is_root: true,
                }],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(1)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![],
            },
            CancellationTrace {
                trace_id: "trace3".to_string(),
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "other-entity".to_string(),
                root_entity_type: EntityType::Task,
                start_time: SystemTime::now(),
                steps: vec![CancellationStep {
                    entity_id: "other-entity".to_string(),
                    entity_type: EntityType::Task,
                    cancel_reason: CancelReason::with_user_reason("normal".to_string()),
                    cancel_kind: CancelKind::User,
                    result: "Cancelled".to_string(),
                    parent_entity: None,
                    timestamp: SystemTime::now(),
                    is_root: true,
                }],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(1)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![],
            },
        ];

        let analysis = analyze_cancellation_patterns(&traces);

        // Should detect bottlenecks
        assert!(
            !analysis.bottlenecks.is_empty(),
            "Should detect bottlenecks"
        );

        // Check for high-frequency bottleneck (bottleneck-entity appears in 2/3 traces)
        let has_high_freq_bottleneck = analysis.bottlenecks.iter().any(|b| {
            b.contains("High-frequency cancellation source") && b.contains("bottleneck-entity")
        });
        assert!(
            has_high_freq_bottleneck,
            "Should detect high-frequency cancellation source"
        );

        // Check for slow propagation bottleneck
        let has_slow_bottleneck = analysis
            .bottlenecks
            .iter()
            .any(|b| b.contains("Slow propagation bottleneck") && b.contains("slow-entity"));
        assert!(
            has_slow_bottleneck,
            "Should detect slow propagation bottleneck"
        );

        // Check for stuck cancellation bottleneck
        let has_stuck_bottleneck = analysis
            .bottlenecks
            .iter()
            .any(|b| b.contains("Stuck cancellation bottleneck") && b.contains("stuck-entity"));
        assert!(
            has_stuck_bottleneck,
            "Should detect stuck cancellation bottleneck"
        );

        // Should include recommendation about addressing bottlenecks
        let has_bottleneck_recommendation = analysis
            .recommendations
            .iter()
            .any(|r| r.contains("Address") && r.contains("bottlenecks"));
        assert!(
            has_bottleneck_recommendation,
            "Should recommend addressing bottlenecks"
        );
    }
}
