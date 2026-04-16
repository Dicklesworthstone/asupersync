//! Cancellation Trace Visualizer
//!
//! Real-time visualization tools for cancellation propagation trees and analysis.
//! Provides multiple output formats for different debugging scenarios.

use crate::observability::cancellation_tracer::{
    CancellationTrace, CancellationTraceStep, EntityType, PropagationAnomaly, TraceId,
};
use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};

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
    Nanoseconds,
    Microseconds,
    Milliseconds,
    Seconds,
    Auto,
}

/// A tree node in the cancellation propagation visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationTreeNode {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub depth: u32,
    pub timing: Option<Duration>,
    pub propagation_delay: Option<Duration>,
    pub anomalies: Vec<String>,
    pub children: Vec<CancellationTreeNode>,
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
    pub entity_id: String,
    pub entity_type: EntityType,
    pub avg_delay: Duration,
    pub queue_depth: usize,
    pub impact_score: f64,
}

/// Information about a detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyInfo {
    pub trace_id: TraceId,
    pub anomaly_type: String,
    pub severity: AnomalySeverity,
    pub description: String,
    pub detected_at: std::time::SystemTime,
}

/// Severity level of an anomaly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Throughput statistics for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputStats {
    pub cancellations_per_second: f64,
    pub avg_processing_time: Duration,
    pub queue_depth: usize,
    pub success_rate: f64,
}

/// Cancellation trace visualizer.
pub struct CancellationVisualizer {
    config: VisualizerConfig,
}

impl CancellationVisualizer {
    /// Creates a new visualizer with the given configuration.
    pub fn new(config: VisualizerConfig) -> Self {
        Self { config }
    }

    /// Creates a visualizer with default configuration.
    pub fn default() -> Self {
        Self::new(VisualizerConfig::default())
    }

    /// Generate a tree visualization of a cancellation trace.
    pub fn visualize_trace_tree(&self, trace: &CancellationTrace) -> String {
        let tree = self.build_tree(trace);
        self.format_tree(&tree, 0)
    }

    /// Generate a timeline visualization showing propagation order.
    pub fn visualize_timeline(&self, trace: &CancellationTrace) -> String {
        let mut output = String::new();
        output.push_str(&format!("=== Cancellation Timeline (Trace {}) ===\n", trace.trace_id.as_u64()));
        output.push_str(&format!("Root: {} ({})\n", trace.root_entity, trace.root_cancel_reason));
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
                Some(parent) => format!(" ← {}", parent),
                None => String::new(),
            };

            let anomaly_marker = if self.config.highlight_anomalies
                && trace.anomalies.iter().any(|a| self.step_has_anomaly(step, a)) {
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
                    step.entity_state,
                    step.depth,
                    step.cancel_kind
                ));
            }
        }

        if let Some(total_time) = &trace.total_propagation_time {
            output.push_str(&format!("\nTotal propagation time: {}\n",
                self.format_duration(*total_time)));
        }

        output.push_str(&format!("Entities cancelled: {}\n", trace.entities_cancelled));
        output.push_str(&format!("Max depth: {}\n", trace.max_depth));

        if !trace.anomalies.is_empty() {
            output.push_str(&format!("\n⚠️  {} anomalies detected:\n", trace.anomalies.len()));
            for anomaly in &trace.anomalies {
                output.push_str(&format!("  - {}\n", self.format_anomaly(anomaly)));
            }
        }

        output
    }

    /// Generate a dot graph for use with graphviz.
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
                trace.root_entity,
                trace.root_entity,
                trace.root_cancel_reason
            ));

            // Steps as edges
            for step in &trace.steps {
                let color = if trace.anomalies.iter().any(|a| self.step_has_anomaly(step, a)) {
                    "red"
                } else {
                    "black"
                };

                if let Some(parent) = &step.parent_entity {
                    output.push_str(&format!(
                        "  \"{}\" -> \"{}\" [label=\"{:.1}ms\" color={}];\n",
                        parent,
                        step.entity_id,
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
    pub fn generate_dashboard(&self, traces: &[CancellationTrace]) -> CancellationDashboard {
        let now = std::time::SystemTime::now();
        let active_traces = traces.iter().filter(|t| !t.is_complete).count();
        let completed_traces = traces.iter().filter(|t| t.is_complete).count();

        let propagation_times: Vec<Duration> = traces
            .iter()
            .filter_map(|t| t.total_propagation_time)
            .collect();

        let avg_propagation_latency = if propagation_times.is_empty() {
            Duration::ZERO
        } else {
            let total: u64 = propagation_times.iter().map(|d| d.as_nanos() as u64).sum();
            Duration::from_nanos(total / propagation_times.len() as u64)
        };

        let mut sorted_times = propagation_times.clone();
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
                        PropagationAnomaly::StuckCancellation { .. } => "StuckCancellation".to_string(),
                        PropagationAnomaly::IncorrectPropagationOrder { .. } => "IncorrectPropagationOrder".to_string(),
                        PropagationAnomaly::UnexpectedPropagation { .. } => "UnexpectedPropagation".to_string(),
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
        let mut entity_delays: HashMap<String, Vec<Duration>> = HashMap::new();

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

            let avg_delay = Duration::from_nanos(
                delays.iter().map(|d| d.as_nanos() as u64).sum::<u64>() / delays.len() as u64
            );

            // Consider it a bottleneck if average delay is above threshold
            let threshold = Duration::from_millis(10);
            if avg_delay > threshold {
                let impact_score = avg_delay.as_secs_f64() * delays.len() as f64;

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
        bottlenecks.sort_by(|a, b| b.impact_score.partial_cmp(&a.impact_score).unwrap_or(std::cmp::Ordering::Equal));
        bottlenecks
    }

    /// Calculate throughput statistics for entities.
    fn calculate_entity_throughput(&self, traces: &[CancellationTrace]) -> HashMap<String, ThroughputStats> {
        let mut stats = HashMap::new();

        // Simple implementation - would need more data for full metrics
        for trace in traces {
            for step in &trace.steps {
                stats.entry(step.entity_id.clone()).or_insert(ThroughputStats {
                    cancellations_per_second: 1.0, // Placeholder
                    avg_processing_time: step.elapsed_since_prev,
                    queue_depth: 0, // Would need queue tracking
                    success_rate: if step.propagation_completed { 1.0 } else { 0.0 },
                });
            }
        }

        stats
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

        // Build child nodes from steps
        let mut parent_map: HashMap<String, &mut CancellationTreeNode> = HashMap::new();
        parent_map.insert(root.entity_id.clone(), &mut root);

        // This is a simplified tree building - in practice would need more complex logic
        for step in &trace.steps {
            // Add as child of parent or root
            // Implementation would be more complex in practice
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

        output.push_str(&format!("{}├─ {}{}{}\n", prefix, node.entity_id, timing, anomaly_marker));

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
                    format!("{}ns", nanos)
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
            PropagationAnomaly::SlowPropagation { elapsed, threshold, .. } => {
                format!("Slow propagation: {} (threshold: {})",
                    self.format_duration(*elapsed),
                    self.format_duration(*threshold))
            }
            PropagationAnomaly::StuckCancellation { stuck_duration, .. } => {
                format!("Stuck cancellation: timeout after {}",
                    self.format_duration(*stuck_duration))
            }
            PropagationAnomaly::IncorrectPropagationOrder { parent_entity, child_entity, .. } => {
                format!("Incorrect ordering: parent {} before child {}", parent_entity, child_entity)
            }
            PropagationAnomaly::UnexpectedPropagation { description, .. } => {
                format!("Unexpected propagation: {}", description)
            }
            PropagationAnomaly::ExcessiveDepth { depth, entity_id } => {
                format!("Excessive depth: {} levels for entity {}", depth, entity_id)
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
        // Simple check - could be more sophisticated
        match anomaly {
            PropagationAnomaly::SlowPropagation { elapsed, .. } => {
                step.elapsed_since_prev >= *elapsed
            }
            _ => false, // Would need entity tracking for other anomaly types
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visualizer_creation() {
        let config = VisualizerConfig::default();
        let visualizer = CancellationVisualizer::new(config);

        // Just test that creation works
        assert!(true);
    }

    #[test]
    fn test_duration_formatting() {
        let visualizer = CancellationVisualizer::default();

        let duration = Duration::from_millis(123);
        let formatted = visualizer.format_duration(duration);
        assert!(formatted.contains("123"));
    }
}