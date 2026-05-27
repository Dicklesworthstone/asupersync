//! Network diagnostics integration for ATP network truth instrumentation.
//!
//! Provides CLI-friendly and structured output for network metrics, path quality,
//! and pressure model data.

use crate::observability::metrics::HistogramSnapshot;
use crate::observability::network_truth::{NetworkTruthCollector, PathQuality, PressureModel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Comprehensive network diagnostic report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiagnosticReport {
    /// Summary of current network state
    pub summary: NetworkSummary,
    /// Detailed path quality assessments
    pub paths: BTreeMap<String, PathQuality>,
    /// Current pressure model
    pub pressure: PressureModel,
    /// Metric snapshots
    pub metrics: NetworkMetricSnapshots,
    /// Diagnostic timestamp
    pub timestamp: std::time::SystemTime,
}

/// High-level network summary for quick assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Overall network health score (0.0-1.0, higher is better)
    pub health_score: f64,
    /// Primary limiting factor
    pub limiting_factor: LimitingFactor,
    /// Number of active paths
    pub active_paths: usize,
    /// Average RTT across all paths
    pub avg_rtt_ms: f64,
    /// Total loss events in last period
    pub recent_loss_events: u64,
    /// Overall pressure level
    pub pressure_level: PressureLevel,
}

/// Primary factor limiting network performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LimitingFactor {
    /// Network congestion or loss
    Network,
    /// Disk I/O latency
    Disk,
    /// CPU encoding/decoding
    Cpu,
    /// Memory pressure
    Memory,
    /// Path migration instability
    Instability,
    /// No significant limiting factor detected
    None,
}

impl fmt::Display for LimitingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitingFactor::Network => write!(f, "Network congestion"),
            LimitingFactor::Disk => write!(f, "Disk I/O latency"),
            LimitingFactor::Cpu => write!(f, "CPU processing"),
            LimitingFactor::Memory => write!(f, "Memory pressure"),
            LimitingFactor::Instability => write!(f, "Path instability"),
            LimitingFactor::None => write!(f, "No bottleneck"),
        }
    }
}

/// Overall pressure level classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PressureLevel {
    /// Low pressure, optimal performance
    Low,
    /// Moderate pressure, some impact
    Moderate,
    /// High pressure, significant impact
    High,
    /// Critical pressure, severe performance impact
    Critical,
}

impl fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PressureLevel::Low => write!(f, "Low"),
            PressureLevel::Moderate => write!(f, "Moderate"),
            PressureLevel::High => write!(f, "High"),
            PressureLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Snapshot of key network metrics for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetricSnapshots {
    /// RTT statistics
    pub rtt_stats: MetricSnapshot,
    /// ACK delay statistics
    pub ack_delay_stats: MetricSnapshot,
    /// Loss event count
    pub loss_events: u64,
    /// PTO event count
    pub pto_events: u64,
    /// Current congestion window (bytes)
    pub congestion_window: i64,
    /// Current bytes in flight
    pub bytes_in_flight: i64,
    /// Send buffer pressure percentage
    pub send_buffer_pressure: i64,
    /// Receive buffer pressure percentage
    pub recv_buffer_pressure: i64,
}

/// Metric snapshot with key statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    /// Total observation count
    pub count: u64,
    /// Sum of all observations
    pub sum: f64,
    /// Average value
    pub mean: f64,
    /// 50th percentile (median)
    pub p50: Option<f64>,
    /// 95th percentile
    pub p95: Option<f64>,
    /// 99th percentile
    pub p99: Option<f64>,
}

/// Network diagnostic reporter.
pub struct NetworkDiagnosticReporter {
    collector: NetworkTruthCollector,
}

impl NetworkDiagnosticReporter {
    /// Creates a new diagnostic reporter wrapping the given collector.
    pub fn new(collector: NetworkTruthCollector) -> Self {
        Self { collector }
    }

    /// Generates a comprehensive network diagnostic report.
    pub fn generate_report(&self) -> NetworkDiagnosticReport {
        let metrics = self.collector.metrics();
        let pressure = self.collector.get_pressure_model().unwrap_or_default();
        let paths = self.collector.path_qualities();

        // Generate metric snapshots
        let rtt_snapshot = MetricSnapshot::from_histogram(metrics.rtt.snapshot());
        let ack_delay_snapshot = MetricSnapshot::from_histogram(metrics.ack_delay.snapshot());

        let metric_snapshots = NetworkMetricSnapshots {
            rtt_stats: rtt_snapshot,
            ack_delay_stats: ack_delay_snapshot,
            loss_events: metrics.loss_events.get(),
            pto_events: metrics.pto_events.get(),
            congestion_window: metrics.congestion_window.get(),
            bytes_in_flight: metrics.bytes_in_flight.get(),
            send_buffer_pressure: metrics.send_buffer_pressure.get(),
            recv_buffer_pressure: metrics.recv_buffer_pressure.get(),
        };

        // Determine limiting factor
        let limiting_factor = self.determine_limiting_factor(&pressure);

        // Calculate health score
        let health_score = self.calculate_health_score(&pressure, &metric_snapshots);

        // Get pressure level
        let pressure_level = self.classify_pressure_level(&pressure);

        let summary = NetworkSummary {
            health_score,
            limiting_factor,
            active_paths: paths.len(),
            avg_rtt_ms: average_path_rtt_ms(&paths)
                .unwrap_or(metric_snapshots.rtt_stats.mean * 1000.0),
            recent_loss_events: metric_snapshots.loss_events,
            pressure_level,
        };

        NetworkDiagnosticReport {
            summary,
            paths,
            pressure,
            metrics: metric_snapshots,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Generates a concise human-readable summary.
    pub fn generate_summary(&self) -> String {
        let report = self.generate_report();

        format!(
            "Network Status: {} pressure, {} health score\n\
             Limiting factor: {}\n\
             RTT: {:.1}ms avg, Loss: {} events, Paths: {}",
            report.summary.pressure_level,
            (report.summary.health_score * 100.0) as u8,
            report.summary.limiting_factor,
            report.summary.avg_rtt_ms,
            report.summary.recent_loss_events,
            report.summary.active_paths
        )
    }

    /// Generates detailed JSON report for expert analysis.
    pub fn generate_json_report(&self) -> Result<String, serde_json::Error> {
        let report = self.generate_report();
        serde_json::to_string_pretty(&report)
    }

    fn determine_limiting_factor(&self, pressure: &PressureModel) -> LimitingFactor {
        let factors = vec![
            (pressure.network, LimitingFactor::Network),
            (pressure.disk, LimitingFactor::Disk),
            (pressure.cpu, LimitingFactor::Cpu),
            (pressure.memory, LimitingFactor::Memory),
        ];

        factors
            .into_iter()
            .max_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(LimitingFactor::None, |(pressure_level, factor)| {
                if pressure_level > 0.3 {
                    factor
                } else {
                    LimitingFactor::None
                }
            })
    }

    fn calculate_health_score(
        &self,
        pressure: &PressureModel,
        _metrics: &NetworkMetricSnapshots,
    ) -> f64 {
        // Simple health score based on pressure levels
        // Higher pressure = lower health score
        let pressure_impact = 1.0 - pressure.overall;

        // Clamp to 0.0-1.0 range
        pressure_impact.clamp(0.0, 1.0)
    }

    fn classify_pressure_level(&self, pressure: &PressureModel) -> PressureLevel {
        match pressure.overall {
            p if p < 0.25 => PressureLevel::Low,
            p if p < 0.5 => PressureLevel::Moderate,
            p if p < 0.75 => PressureLevel::High,
            _ => PressureLevel::Critical,
        }
    }
}

/// CLI-friendly network diagnostic commands.
pub struct NetworkDiagnosticCli {
    reporter: NetworkDiagnosticReporter,
}

impl NetworkDiagnosticCli {
    /// Creates a new CLI interface.
    pub fn new(collector: NetworkTruthCollector) -> Self {
        Self {
            reporter: NetworkDiagnosticReporter::new(collector),
        }
    }

    /// Handles the `atp network status` command.
    pub fn handle_status_command(&self, json: bool) -> Result<String, Box<dyn std::error::Error>> {
        if json {
            Ok(self.reporter.generate_json_report()?)
        } else {
            Ok(self.reporter.generate_summary())
        }
    }

    /// Handles the `atp network explain` command with detailed explanations.
    pub fn handle_explain_command(&self) -> String {
        let report = self.reporter.generate_report();

        let mut explanation = String::new();
        explanation.push_str("=== ATP Network Diagnostics ===\n\n");

        explanation.push_str(&format!(
            "Overall Health: {}/100\n",
            (report.summary.health_score * 100.0) as u8
        ));
        explanation.push_str(&format!(
            "Pressure Level: {}\n",
            report.summary.pressure_level
        ));
        explanation.push_str(&format!(
            "Primary Bottleneck: {}\n\n",
            report.summary.limiting_factor
        ));

        explanation.push_str("Network Metrics:\n");
        explanation.push_str(&format!(
            "  RTT: {:.1}ms average",
            report.summary.avg_rtt_ms
        ));
        if let Some(p95) = report.metrics.rtt_stats.p95 {
            explanation.push_str(&format!(", {:.1}ms p95", p95 * 1000.0));
        }
        explanation.push('\n');

        explanation.push_str(&format!(
            "  Loss: {} events\n",
            report.summary.recent_loss_events
        ));
        explanation.push_str(&format!(
            "  Congestion window: {} bytes\n",
            report.metrics.congestion_window
        ));
        explanation.push_str(&format!(
            "  Bytes in flight: {}\n\n",
            report.metrics.bytes_in_flight
        ));

        explanation.push_str("Pressure Breakdown:\n");
        explanation.push_str(&format!(
            "  Network: {:.1}%\n",
            report.pressure.network * 100.0
        ));
        explanation.push_str(&format!("  Disk: {:.1}%\n", report.pressure.disk * 100.0));
        explanation.push_str(&format!("  CPU: {:.1}%\n", report.pressure.cpu * 100.0));
        explanation.push_str(&format!(
            "  Memory: {:.1}%\n",
            report.pressure.memory * 100.0
        ));

        // Add recommendations based on limiting factor
        explanation.push_str("\nRecommendations:\n");
        match report.summary.limiting_factor {
            LimitingFactor::Network => {
                explanation
                    .push_str("  • Consider relay paths if direct connection is congested\n");
                explanation.push_str("  • Check for competing network traffic\n");
                explanation.push_str("  • Monitor path migration events\n");
            }
            LimitingFactor::Disk => {
                explanation.push_str("  • Consider faster storage for ATP cache\n");
                explanation.push_str("  • Check for competing disk I/O\n");
                explanation.push_str("  • Monitor disk space availability\n");
            }
            LimitingFactor::Cpu => {
                explanation.push_str("  • Consider hardware acceleration for encoding/decoding\n");
                explanation.push_str("  • Check for competing CPU-intensive processes\n");
                explanation.push_str("  • Monitor thermal throttling\n");
            }
            LimitingFactor::Memory => {
                explanation.push_str("  • Consider increasing system memory\n");
                explanation.push_str("  • Check for memory leaks in other processes\n");
                explanation.push_str("  • Monitor swap usage\n");
            }
            LimitingFactor::Instability => {
                explanation.push_str("  • Check network stability and path selection\n");
                explanation.push_str("  • Consider different relay servers\n");
                explanation.push_str("  • Monitor connection quality\n");
            }
            LimitingFactor::None => {
                explanation.push_str("  • System operating within normal parameters\n");
                explanation.push_str("  • Monitor trends for early detection\n");
            }
        }

        explanation
    }
}

impl MetricSnapshot {
    fn from_histogram(snapshot: HistogramSnapshot) -> Self {
        let mean = if snapshot.count > 0 {
            snapshot.sum / snapshot.count as f64
        } else {
            0.0
        };

        Self {
            count: snapshot.count,
            sum: snapshot.sum,
            mean,
            p50: histogram_quantile(&snapshot, 0.50),
            p95: histogram_quantile(&snapshot, 0.95),
            p99: histogram_quantile(&snapshot, 0.99),
        }
    }
}

fn histogram_quantile(snapshot: &HistogramSnapshot, quantile: f64) -> Option<f64> {
    if !(0.0..=1.0).contains(&quantile) || snapshot.count == 0 {
        return None;
    }

    let rank = ((snapshot.count as f64) * quantile).ceil().max(1.0) as u64;
    let mut cumulative = 0_u64;

    for (index, bucket_count) in snapshot.bucket_counts.iter().enumerate() {
        cumulative = cumulative.saturating_add(*bucket_count);
        if cumulative >= rank {
            return snapshot.bucket_boundaries.get(index).copied();
        }
    }

    None
}

fn average_path_rtt_ms(paths: &BTreeMap<String, PathQuality>) -> Option<f64> {
    if paths.is_empty() {
        return None;
    }

    let sum_seconds = paths
        .values()
        .map(|quality| quality.rtt_estimate.value.max(0.0))
        .sum::<f64>();
    Some((sum_seconds / paths.len() as f64) * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::network_truth::NetworkTruthCollector;

    #[test]
    fn test_diagnostic_report_generation() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let report = reporter.generate_report();

        // Should generate a valid report even with no data
        assert!(report.summary.health_score >= 0.0);
        assert!(report.summary.health_score <= 1.0);
        assert_eq!(report.summary.active_paths, 0);
    }

    #[test]
    fn test_summary_generation() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let summary = reporter.generate_summary();

        // Should contain key information
        assert!(summary.contains("Network Status"));
        assert!(summary.contains("health score"));
        assert!(summary.contains("Limiting factor"));
    }

    #[test]
    fn test_json_serialization() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let json = reporter.generate_json_report().unwrap();

        // Should be valid JSON
        let _: NetworkDiagnosticReport = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_pressure_level_classification() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let mut pressure = PressureModel::new();

        // Test low pressure
        pressure.overall = 0.1;
        assert!(matches!(
            reporter.classify_pressure_level(&pressure),
            PressureLevel::Low
        ));

        // Test high pressure
        pressure.overall = 0.8;
        assert!(matches!(
            reporter.classify_pressure_level(&pressure),
            PressureLevel::Critical
        ));
    }

    #[test]
    fn test_limiting_factor_detection() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let mut pressure = PressureModel::new();

        // Test network limiting
        pressure.network = 0.8;
        pressure.disk = 0.2;
        pressure.cpu = 0.1;
        pressure.memory = 0.1;

        assert!(matches!(
            reporter.determine_limiting_factor(&pressure),
            LimitingFactor::Network
        ));

        // Test no bottleneck
        pressure.network = 0.1;
        pressure.disk = 0.1;
        pressure.cpu = 0.1;
        pressure.memory = 0.1;

        assert!(matches!(
            reporter.determine_limiting_factor(&pressure),
            LimitingFactor::None
        ));
    }
}
