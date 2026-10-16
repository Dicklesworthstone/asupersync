//! Cancellation Trace Visualizer
//!
//! Real-time visualization tools for cancellation propagation trees and analysis.
//! Provides multiple output formats for different debugging scenarios.
//!
//! It is opt-in: it renders the traces the caller collected with a
//! [`CancellationTracer`](crate::observability::cancellation_tracer::CancellationTracer), and the
//! runtime records nothing into either (asupersync-7yq1pv).

use crate::observability::cancellation_tracer::{
    CancellationTrace, CancellationTraceId, CancellationTraceStep, EntityType, PropagationAnomaly,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

/// br-asupersync-indxfz — Cardinality cap on the entity_throughput
/// HashMap so attacker-controllable entity_id strings cannot drive
/// unbounded HashMap growth (DoS / OOM amplifier). Sized for
/// "high but finite" tenancy.
const MAX_THROUGHPUT_ENTITIES: usize = 4096;

/// br-asupersync-indxfz — Sentinel key used when the throughput
/// cardinality cap is hit. Operators see the bucket explicitly so
/// the cap activation is auditable rather than silent.
const THROUGHPUT_OVERFLOW_BUCKET: &str = "__overflow__";

/// Configuration for visualization output.
#[derive(Debug, Clone)]
pub struct VisualizerConfig {
    /// Include timing information in visualizations.
    pub show_timing: bool,
    /// Maximum depth to visualize (prevents overwhelming output).
    pub max_depth: u32,
    /// Highlight anomalies in visual output.
    pub highlight_anomalies: bool,
    /// Include detailed step information.
    pub show_step_details: bool,
    /// Format for timing display.
    pub timing_format: TimingFormat,
}

impl Default for VisualizerConfig {
    fn default() -> Self {
        Self {
            show_timing: true,
            max_depth: 20,
            highlight_anomalies: true,
            show_step_details: false,
            timing_format: TimingFormat::Milliseconds,
        }
    }
}

/// Format for displaying timing information.
#[derive(Debug, Clone, Copy)]
pub enum TimingFormat {
    /// Display timing in nanoseconds.
    Nanoseconds,
    /// Display timing in microseconds.
    Microseconds,
    /// Display timing in milliseconds.
    Milliseconds,
    /// Display timing in seconds.
    Seconds,
    /// Automatically choose the most appropriate unit.
    Auto,
}

/// A tree node in the cancellation propagation visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationTreeNode {
    /// Unique identifier for the entity (task, region, etc.).
    pub entity_id: String,
    /// Type of the entity represented by this node.
    pub entity_type: EntityType,
    /// Depth level in the cancellation tree.
    pub depth: u32,
    /// Total time for cancellation to complete for this entity.
    pub timing: Option<Duration>,
    /// Delay between parent cancellation and this entity's cancellation start.
    pub propagation_delay: Option<Duration>,
    /// List of detected anomalies or issues during cancellation.
    pub anomalies: Vec<String>,
    /// Child nodes in the cancellation tree.
    pub children: Vec<Self>,
    /// Whether cancellation has completed for this entity.
    pub completed: bool,
}

/// Real-time cancellation statistics for monitoring dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationDashboard {
    /// Current time of snapshot.
    pub snapshot_time: std::time::SystemTime,
    /// Active traces being tracked.
    pub active_traces: usize,
    /// Completed traces in the last period.
    pub completed_traces_period: usize,
    /// Average propagation latency.
    pub avg_propagation_latency: Duration,
    /// 95th percentile propagation latency.
    pub p95_propagation_latency: Duration,
    /// Current bottlenecks detected.
    pub current_bottlenecks: Vec<BottleneckInfo>,
    /// Anomalies detected in the last period.
    pub recent_anomalies: Vec<AnomalyInfo>,
    /// Entity throughput statistics.
    pub entity_throughput: HashMap<String, ThroughputStats>,
}

/// Information about a detected bottleneck.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BottleneckInfo {
    /// ID of the entity causing the bottleneck.
    pub entity_id: String,
    /// Type of the entity causing the bottleneck.
    pub entity_type: EntityType,
    /// Average delay caused by this bottleneck.
    pub avg_delay: Duration,
    /// Current queue depth at this bottleneck.
    pub queue_depth: usize,
    /// Impact score indicating severity (0.0 to 1.0).
    pub impact_score: f64,
}

/// Information about a detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyInfo {
    /// Trace ID associated with the anomaly.
    pub trace_id: CancellationTraceId,
    /// Type or category of the anomaly.
    pub anomaly_type: String,
    /// Severity level of the anomaly.
    pub severity: AnomalySeverity,
    /// Human-readable description of the anomaly.
    pub description: String,
    /// When the anomaly was detected.
    pub detected_at: std::time::SystemTime,
}

/// Severity level of an anomaly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Low severity anomaly, informational.
    Low,
    /// Medium severity anomaly, monitor.
    Medium,
    /// High severity anomaly, investigate.
    High,
    /// Critical severity anomaly, immediate attention required.
    Critical,
}

/// Throughput statistics for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputStats {
    /// Number of cancellations processed per second.
    pub cancellations_per_second: f64,
    /// Average time to process a cancellation.
    pub avg_processing_time: Duration,
    /// Current depth of the processing queue.
    pub queue_depth: usize,
    /// Success rate for cancellation processing (0.0 to 1.0).
    pub success_rate: f64,
}

/// Cancellation trace visualizer.
pub struct CancellationVisualizer {
    config: VisualizerConfig,
}

impl CancellationVisualizer {
    /// Creates a new visualizer with the given configuration.
    #[must_use]
    pub fn new(config: VisualizerConfig) -> Self {
        Self { config }
    }

    /// Creates a visualizer with default configuration.
    #[must_use]
    pub fn default() -> Self {
        Self::new(VisualizerConfig::default())
    }

    /// Generate a tree visualization of a cancellation trace.
    #[must_use]
    pub fn visualize_trace_tree(&self, trace: &CancellationTrace) -> String {
        let tree = self.build_tree(trace);
        self.format_tree(&tree, 0)
    }

    /// Generate a timeline visualization showing propagation order.
    #[must_use]
    pub fn visualize_timeline(&self, trace: &CancellationTrace) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "=== Cancellation Timeline (Trace {}) ===\n",
            trace.trace_id.as_u64()
        ));
        output.push_str(&format!(
            "Root: {} ({})\n",
            trace.root_entity, trace.root_cancel_reason
        ));
        output.push_str(&format!("Start: {:?}\n", trace.start_time));

        if trace.steps.is_empty() {
            output.push_str("No propagation steps recorded.\n");
            return output;
        }

        output.push_str("\nPropagation Timeline:\n");

        for (i, step) in trace.steps.iter().enumerate() {
            let timing = if self.config.show_timing {
                format!(" [+{}]", self.format_duration(step.elapsed_since_start))
            } else {
                String::new()
            };

            let parent_info = match &step.parent_entity {
                Some(parent) => format!(" ← {parent}"),
                None => String::new(),
            };

            let anomaly_marker = if self.config.highlight_anomalies
                && trace
                    .anomalies
                    .iter()
                    .any(|a| self.step_has_anomaly(step, a))
            {
                " ⚠️"
            } else {
                ""
            };

            output.push_str(&format!(
                "  {}: {}{}{}{}\n",
                i + 1,
                step.entity_id,
                parent_info,
                timing,
                anomaly_marker
            ));

            if self.config.show_step_details {
                output.push_str(&format!(
                    "     State: {} | Depth: {} | Kind: {}\n",
                    step.entity_state, step.depth, step.cancel_kind
                ));
            }
        }

        if let Some(total_time) = &trace.total_propagation_time {
            output.push_str(&format!(
                "\nTotal propagation time: {}\n",
                self.format_duration(*total_time)
            ));
        }

        output.push_str(&format!(
            "Entities cancelled: {}\n",
            trace.entities_cancelled
        ));
        output.push_str(&format!("Max depth: {}\n", trace.max_depth));

        if !trace.anomalies.is_empty() {
            output.push_str(&format!(
                "\n⚠️  {} anomalies detected:\n",
                trace.anomalies.len()
            ));
            for anomaly in &trace.anomalies {
                output.push_str(&format!("  - {}\n", self.format_anomaly(anomaly)));
            }
        }

        output
    }

    /// Generate a dot graph for use with graphviz.
    #[must_use]
    pub fn generate_dot_graph(&self, traces: &[CancellationTrace]) -> String {
        let mut output = String::new();
        output.push_str("digraph cancellation_traces {\n");
        output.push_str("  rankdir=TB;\n");
        output.push_str("  node [shape=box];\n\n");

        for trace in traces {
            output.push_str(&format!("  // Trace {}\n", trace.trace_id.as_u64()));

            // Root node
            output.push_str(&format!(
                "  \"{}\" [label=\"{}\\n{}\" style=filled fillcolor=lightblue];\n",
                Self::dot_node_id(trace.trace_id, &trace.root_entity),
                Self::escape_dot_text(&trace.root_entity),
                Self::escape_dot_text(&trace.root_cancel_reason)
            ));

            for step in &trace.steps {
                output.push_str(&format!(
                    "  \"{}\" [label=\"{}\\n{:?}\"];\n",
                    Self::dot_node_id(trace.trace_id, &step.entity_id),
                    Self::escape_dot_text(&step.entity_id),
                    step.entity_type
                ));
            }

            // Steps as edges
            for step in &trace.steps {
                let color = if trace
                    .anomalies
                    .iter()
                    .any(|a| self.step_has_anomaly(step, a))
                {
                    "red"
                } else {
                    "black"
                };

                let parent = step.parent_entity.as_ref().unwrap_or(&trace.root_entity);
                if parent != &step.entity_id {
                    output.push_str(&format!(
                        "  \"{}\" -> \"{}\" [label=\"{:.1}ms\" color={}];\n",
                        Self::dot_node_id(trace.trace_id, parent),
                        Self::dot_node_id(trace.trace_id, &step.entity_id),
                        step.elapsed_since_prev.as_secs_f64() * 1000.0,
                        color
                    ));
                }
            }

            output.push('\n');
        }

        output.push_str("}\n");
        output
    }

    /// Generate a real-time dashboard view.
    #[must_use]
    pub fn generate_dashboard(&self, traces: &[CancellationTrace]) -> CancellationDashboard {
        let now = super::replayable_system_time();
        let active_traces = traces.iter().filter(|t| !t.is_complete).count();
        let completed_traces = traces.iter().filter(|t| t.is_complete).count();

        let propagation_times: Vec<Duration> = traces
            .iter()
            .filter_map(|t| t.total_propagation_time)
            .collect();

        let avg_propagation_latency = if propagation_times.is_empty() {
            Duration::ZERO
        } else {
            let total: u128 = propagation_times.iter().map(Duration::as_nanos).sum();
            Self::duration_from_avg_nanos(total, propagation_times.len())
        };

        let mut sorted_times = propagation_times;
        sorted_times.sort();
        let p95_propagation_latency = if sorted_times.is_empty() {
            Duration::ZERO
        } else {
            let index = (sorted_times.len() as f64 * 0.95) as usize;
            sorted_times[index.min(sorted_times.len() - 1)]
        };

        // Detect bottlenecks
        let bottlenecks = self.identify_bottlenecks(traces);

        // Collect recent anomalies
        let recent_anomalies: Vec<AnomalyInfo> = traces
            .iter()
            .flat_map(|trace| {
                trace.anomalies.iter().map(|anomaly| AnomalyInfo {
                    trace_id: trace.trace_id,
                    anomaly_type: match anomaly {
                        PropagationAnomaly::SlowPropagation { .. } => "SlowPropagation".to_string(),
                        PropagationAnomaly::StuckCancellation { .. } => {
                            "StuckCancellation".to_string()
                        }
                        PropagationAnomaly::IncorrectPropagationOrder { .. } => {
                            "IncorrectPropagationOrder".to_string()
                        }
                        PropagationAnomaly::UnexpectedPropagation { .. } => {
                            "UnexpectedPropagation".to_string()
                        }
                        PropagationAnomaly::ExcessiveDepth { .. } => "ExcessiveDepth".to_string(),
                    },
                    severity: self.anomaly_severity(anomaly),
                    description: self.format_anomaly(anomaly),
                    detected_at: now,
                })
            })
            .collect();

        // Calculate entity throughput
        let entity_throughput = self.calculate_entity_throughput(traces);

        CancellationDashboard {
            snapshot_time: now,
            active_traces,
            completed_traces_period: completed_traces,
            avg_propagation_latency,
            p95_propagation_latency,
            current_bottlenecks: bottlenecks,
            recent_anomalies,
            entity_throughput,
        }
    }

    /// Identify performance bottlenecks in the traces.
    fn identify_bottlenecks(&self, traces: &[CancellationTrace]) -> Vec<BottleneckInfo> {
        // br-asupersync-ovp553: BTreeMap so the returned
        // Vec<BottleneckInfo> is in canonical (sorted) order. The previous
        // HashMap iteration at line 411 produced a non-deterministic
        // ordering that broke deterministic-replay tooling consuming
        // analyzer output.
        let mut entity_delays: BTreeMap<String, Vec<Duration>> = BTreeMap::new();

        for trace in traces {
            for step in &trace.steps {
                entity_delays
                    .entry(step.entity_id.clone())
                    .or_default()
                    .push(step.elapsed_since_prev);
            }
        }

        let mut bottlenecks = Vec::new();

        for (entity_id, delays) in entity_delays {
            if delays.len() < 2 {
                continue;
            }

            let total_delay_nanos: u128 = delays.iter().map(Duration::as_nanos).sum();
            let avg_delay = Self::duration_from_avg_nanos(total_delay_nanos, delays.len());

            // Consider it a bottleneck if average delay is above threshold
            let threshold = Duration::from_millis(10);
            if avg_delay > threshold {
                let trace_count = traces.len().max(1) as f64;
                let severity_ratio = avg_delay.as_secs_f64() / threshold.as_secs_f64();
                let frequency_ratio = delays.len() as f64 / trace_count;
                let impact_score = (severity_ratio * frequency_ratio).min(1.0);

                bottlenecks.push(BottleneckInfo {
                    entity_id: entity_id.clone(),
                    entity_type: EntityType::Task, // Would need type tracking to be accurate
                    avg_delay,
                    queue_depth: delays.len(),
                    impact_score,
                });
            }
        }

        // Sort by impact score
        bottlenecks.sort_by(|a, b| {
            b.impact_score
                .partial_cmp(&a.impact_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        bottlenecks
    }

    /// Calculate throughput statistics for entities.
    ///
    /// br-asupersync-indxfz — entity_id strings flow through here
    /// from upstream user-controllable sources. The accumulator
    /// HashMap is bounded at [`MAX_THROUGHPUT_ENTITIES`]; once
    /// full, additional distinct entity_ids fold into the
    /// [`THROUGHPUT_OVERFLOW_BUCKET`] sentinel so a malicious
    /// producer can't drive unbounded HashMap growth (DoS / OOM
    /// vector). The overflow bucket aggregates the metric for
    /// auditability rather than dropping the data silently.
    fn calculate_entity_throughput(
        &self,
        traces: &[CancellationTrace],
    ) -> HashMap<String, ThroughputStats> {
        struct ThroughputAccumulator {
            samples: usize,
            total_processing_nanos: u128,
            completed: usize,
        }

        let mut accumulators: HashMap<String, ThroughputAccumulator> = HashMap::new();

        for trace in traces {
            for step in &trace.steps {
                let key = if accumulators.contains_key(&step.entity_id)
                    || accumulators.len() < MAX_THROUGHPUT_ENTITIES
                {
                    step.entity_id.clone()
                } else {
                    THROUGHPUT_OVERFLOW_BUCKET.to_string()
                };
                let accumulator = accumulators.entry(key).or_insert(ThroughputAccumulator {
                    samples: 0,
                    total_processing_nanos: 0,
                    completed: 0,
                });
                accumulator.samples += 1;
                accumulator.total_processing_nanos += step.elapsed_since_prev.as_nanos();
                if step.propagation_completed {
                    accumulator.completed += 1;
                }
            }
        }

        accumulators
            .into_iter()
            .map(|(entity_id, accumulator)| {
                let avg_processing_time = Self::duration_from_avg_nanos(
                    accumulator.total_processing_nanos,
                    accumulator.samples,
                );
                let total_secs = accumulator.total_processing_nanos as f64 / 1_000_000_000.0;
                let cancellations_per_second = if total_secs > 0.0 {
                    accumulator.samples as f64 / total_secs
                } else {
                    accumulator.samples as f64
                };
                let success_rate = accumulator.completed as f64 / accumulator.samples as f64;

                (
                    entity_id,
                    ThroughputStats {
                        cancellations_per_second,
                        avg_processing_time,
                        queue_depth: 0,
                        success_rate,
                    },
                )
            })
            .collect()
    }

    /// Build a tree structure from a trace for visualization.
    fn build_tree(&self, trace: &CancellationTrace) -> CancellationTreeNode {
        let mut root = CancellationTreeNode {
            entity_id: trace.root_entity.clone(),
            entity_type: trace.root_entity_type,
            depth: 0,
            timing: trace.total_propagation_time,
            propagation_delay: None,
            anomalies: Vec::new(),
            children: Vec::new(),
            completed: trace.is_complete,
        };

        let mut children_by_parent: HashMap<&str, Vec<&CancellationTraceStep>> = HashMap::new();
        for step in &trace.steps {
            if step.entity_id == trace.root_entity {
                root.entity_type = step.entity_type;
                root.depth = step.depth;
                root.timing = Some(step.elapsed_since_start);
                root.propagation_delay = Some(step.elapsed_since_prev);
                root.completed = step.propagation_completed;
                root.anomalies = self.anomalies_for_entity(trace, &step.entity_id);
                continue;
            }

            let parent = step.parent_entity.as_deref().unwrap_or(&trace.root_entity);
            children_by_parent.entry(parent).or_default().push(step);
        }

        if root.anomalies.is_empty() {
            root.anomalies = self.anomalies_for_entity(trace, &trace.root_entity);
        }

        let mut visited = HashSet::new();
        visited.insert(trace.root_entity.clone());
        self.add_child_nodes(&mut root, &children_by_parent, trace, &mut visited);

        // Preserve steps whose parent was not recorded in the trace by attaching
        // them to the root instead of silently dropping diagnostic data.
        for step in &trace.steps {
            if step.entity_id != trace.root_entity && visited.insert(step.entity_id.clone()) {
                let mut child = self.node_from_step(trace, step);
                self.add_child_nodes(&mut child, &children_by_parent, trace, &mut visited);
                root.children.push(child);
            }
        }

        root
    }

    /// Format a tree node for display.
    fn format_tree(&self, node: &CancellationTreeNode, indent: usize) -> String {
        let mut output = String::new();
        let prefix = "  ".repeat(indent);

        let timing = if let Some(timing) = node.timing {
            format!(" [{}]", self.format_duration(timing))
        } else {
            String::new()
        };

        let anomaly_marker = if !node.anomalies.is_empty() && self.config.highlight_anomalies {
            " ⚠️"
        } else {
            ""
        };

        output.push_str(&format!(
            "{}├─ {}{}{}\n",
            prefix, node.entity_id, timing, anomaly_marker
        ));

        for child in &node.children {
            output.push_str(&self.format_tree(child, indent + 1));
        }

        output
    }

    /// Format a duration according to the configured format.
    fn format_duration(&self, duration: Duration) -> String {
        match self.config.timing_format {
            TimingFormat::Nanoseconds => format!("{}ns", duration.as_nanos()),
            TimingFormat::Microseconds => format!("{:.1}μs", duration.as_secs_f64() * 1_000_000.0),
            TimingFormat::Milliseconds => format!("{:.1}ms", duration.as_secs_f64() * 1000.0),
            TimingFormat::Seconds => format!("{:.3}s", duration.as_secs_f64()),
            TimingFormat::Auto => {
                let nanos = duration.as_nanos();
                if nanos < 1_000 {
                    format!("{nanos}ns")
                } else if nanos < 1_000_000 {
                    format!("{:.1}μs", nanos as f64 / 1_000.0)
                } else if nanos < 1_000_000_000 {
                    format!("{:.1}ms", nanos as f64 / 1_000_000.0)
                } else {
                    format!("{:.3}s", nanos as f64 / 1_000_000_000.0)
                }
            }
        }
    }

    /// Format an anomaly for display.
    fn format_anomaly(&self, anomaly: &PropagationAnomaly) -> String {
        match anomaly {
            PropagationAnomaly::SlowPropagation {
                elapsed, threshold, ..
            } => {
                format!(
                    "Slow propagation: {} (threshold: {})",
                    self.format_duration(*elapsed),
                    self.format_duration(*threshold)
                )
            }
            PropagationAnomaly::StuckCancellation { stuck_duration, .. } => {
                format!(
                    "Stuck cancellation: timeout after {}",
                    self.format_duration(*stuck_duration)
                )
            }
            PropagationAnomaly::IncorrectPropagationOrder {
                parent_entity,
                child_entity,
                ..
            } => {
                format!("Incorrect ordering: parent {parent_entity} before child {child_entity}")
            }
            PropagationAnomaly::UnexpectedPropagation { description, .. } => {
                format!("Unexpected propagation: {description}")
            }
            PropagationAnomaly::ExcessiveDepth { depth, entity_id } => {
                format!("Excessive depth: {depth} levels for entity {entity_id}")
            }
        }
    }

    /// Determine the severity of an anomaly.
    fn anomaly_severity(&self, anomaly: &PropagationAnomaly) -> AnomalySeverity {
        match anomaly {
            PropagationAnomaly::SlowPropagation { elapsed, .. } => {
                if elapsed.as_millis() > 1000 {
                    AnomalySeverity::High
                } else if elapsed.as_millis() > 100 {
                    AnomalySeverity::Medium
                } else {
                    AnomalySeverity::Low
                }
            }
            PropagationAnomaly::StuckCancellation { .. } => AnomalySeverity::Critical,
            PropagationAnomaly::IncorrectPropagationOrder { .. } => AnomalySeverity::High,
            PropagationAnomaly::UnexpectedPropagation { .. } => AnomalySeverity::Medium,
            PropagationAnomaly::ExcessiveDepth { .. } => AnomalySeverity::Medium,
        }
    }

    /// Check if a step is associated with a specific anomaly.
    fn step_has_anomaly(&self, step: &CancellationTraceStep, anomaly: &PropagationAnomaly) -> bool {
        match anomaly {
            PropagationAnomaly::SlowPropagation {
                step_id, entity_id, ..
            } => step.step_id == *step_id && step.entity_id == *entity_id,
            PropagationAnomaly::StuckCancellation { entity_id, .. }
            | PropagationAnomaly::ExcessiveDepth { entity_id, .. } => step.entity_id == *entity_id,
            PropagationAnomaly::IncorrectPropagationOrder {
                parent_entity,
                child_entity,
                ..
            } => step.entity_id == *parent_entity || step.entity_id == *child_entity,
            PropagationAnomaly::UnexpectedPropagation {
                affected_entities, ..
            } => affected_entities
                .iter()
                .any(|entity| entity == &step.entity_id),
        }
    }

    fn add_child_nodes<'a>(
        &self,
        node: &mut CancellationTreeNode,
        children_by_parent: &HashMap<&'a str, Vec<&'a CancellationTraceStep>>,
        trace: &CancellationTrace,
        visited: &mut HashSet<String>,
    ) {
        if node.depth >= self.config.max_depth {
            return;
        }

        if let Some(children) = children_by_parent.get(node.entity_id.as_str()) {
            for step in children {
                if !visited.insert(step.entity_id.clone()) {
                    continue;
                }

                let mut child = self.node_from_step(trace, step);
                self.add_child_nodes(&mut child, children_by_parent, trace, visited);
                node.children.push(child);
            }
        }
    }

    fn node_from_step(
        &self,
        trace: &CancellationTrace,
        step: &CancellationTraceStep,
    ) -> CancellationTreeNode {
        CancellationTreeNode {
            entity_id: step.entity_id.clone(),
            entity_type: step.entity_type,
            depth: step.depth,
            timing: Some(step.elapsed_since_start),
            propagation_delay: Some(step.elapsed_since_prev),
            anomalies: self.anomalies_for_entity(trace, &step.entity_id),
            children: Vec::new(),
            completed: step.propagation_completed,
        }
    }

    fn anomalies_for_entity(&self, trace: &CancellationTrace, entity_id: &str) -> Vec<String> {
        trace
            .anomalies
            .iter()
            .filter(|anomaly| Self::anomaly_mentions_entity(anomaly, entity_id))
            .map(|anomaly| self.format_anomaly(anomaly))
            .collect()
    }

    fn anomaly_mentions_entity(anomaly: &PropagationAnomaly, entity_id: &str) -> bool {
        match anomaly {
            PropagationAnomaly::SlowPropagation {
                entity_id: anomaly_entity,
                ..
            }
            | PropagationAnomaly::StuckCancellation {
                entity_id: anomaly_entity,
                ..
            }
            | PropagationAnomaly::ExcessiveDepth {
                entity_id: anomaly_entity,
                ..
            } => anomaly_entity == entity_id,
            PropagationAnomaly::IncorrectPropagationOrder {
                parent_entity,
                child_entity,
                ..
            } => parent_entity == entity_id || child_entity == entity_id,
            PropagationAnomaly::UnexpectedPropagation {
                affected_entities, ..
            } => affected_entities.iter().any(|entity| entity == entity_id),
        }
    }

    fn duration_from_avg_nanos(total_nanos: u128, count: usize) -> Duration {
        if count == 0 {
            return Duration::ZERO;
        }

        let avg_nanos = total_nanos / count as u128;
        Duration::from_nanos(u64::try_from(avg_nanos).unwrap_or(u64::MAX))
    }

    fn dot_node_id(trace_id: CancellationTraceId, entity_id: &str) -> String {
        Self::escape_dot_text(&format!("trace:{}:{entity_id}", trace_id.as_u64()))
    }

    fn escape_dot_text(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }
}

#[cfg(test)]
#[path = "cancellation_visualizer_inline_tests.rs"]
mod tests;
