//! Deep Cancellation Performance Analyzer
//!
//! Advanced analysis capabilities for cancellation behavior including bottleneck identification,
//! resource cleanup timing analysis, and performance optimization recommendations.

use crate::observability::cancellation_tracer::{
    CancellationTrace, EntityType, PropagationAnomaly,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Configuration for deep analysis.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Minimum sample size for statistical analysis.
    pub min_sample_size: usize,
    /// Confidence level for statistical tests (0.0-1.0).
    pub confidence_level: f64,
    /// Minimum impact threshold for reporting bottlenecks.
    pub bottleneck_threshold: f64,
    /// Enable advanced statistical analysis (higher CPU cost).
    pub enable_statistical_analysis: bool,
    /// Window size for trend analysis.
    pub trend_window_size: usize,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            min_sample_size: 10,
            confidence_level: 0.95,
            bottleneck_threshold: 0.1, // 10% of total time
            enable_statistical_analysis: true,
            trend_window_size: 100,
        }
    }
}

/// Deep performance analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnalysis {
    /// Analysis period.
    pub analysis_window: Duration,
    /// Total traces analyzed.
    pub traces_analyzed: usize,
    /// Statistical distribution of propagation times.
    pub propagation_time_distribution: DistributionStats,
    /// Depth distribution statistics.
    pub depth_distribution: DistributionStats,
    /// Identified performance bottlenecks.
    pub bottlenecks: Vec<BottleneckAnalysis>,
    /// Resource cleanup timing analysis.
    pub cleanup_analysis: CleanupTimingAnalysis,
    /// Entity performance rankings.
    pub entity_rankings: Vec<EntityPerformance>,
    /// Trend analysis over time.
    pub trends: TrendAnalysis,
    /// Performance regression detection.
    pub regressions: Vec<PerformanceRegression>,
    /// Optimization recommendations.
    pub recommendations: Vec<OptimizationRecommendation>,
}

/// Statistical distribution information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionStats {
    /// Total number of samples.
    pub count: usize,
    /// Arithmetic mean of the samples.
    pub mean: f64,
    /// Median value of the samples.
    pub median: f64,
    /// Standard deviation of the samples.
    pub std_dev: f64,
    /// 95th percentile value.
    pub percentile_95: f64,
    /// 99th percentile value.
    pub percentile_99: f64,
    /// Minimum observed value.
    pub min: f64,
    /// Maximum observed value.
    pub max: f64,
    /// Number of outlier samples detected.
    pub outlier_count: usize,
}

/// Detailed bottleneck analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BottleneckAnalysis {
    /// Entity causing the bottleneck.
    pub entity_id: String,
    /// Type of the entity causing the bottleneck.
    pub entity_type: EntityType,
    /// Contribution to total cancellation latency.
    pub impact_percentage: f64,
    /// Average processing time.
    pub avg_processing_time: Duration,
    /// Number of occurrences.
    pub occurrence_count: usize,
    /// Statistical confidence in this being a bottleneck.
    pub confidence: f64,
    /// Suggested mitigation strategies.
    pub mitigation_suggestions: Vec<String>,
}

/// Resource cleanup timing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupTimingAnalysis {
    /// Average time from cancellation signal to cleanup completion.
    pub avg_cleanup_latency: Duration,
    /// Distribution of cleanup times.
    pub cleanup_distribution: DistributionStats,
    /// Entities with slow cleanup.
    pub slow_cleanup_entities: Vec<String>,
    /// Resource leak risk assessment.
    pub leak_risk_score: f64,
    /// Cleanup efficiency metrics.
    pub cleanup_efficiency: CleanupEfficiency,
}

/// Cleanup efficiency metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupEfficiency {
    /// Percentage of cancellations that complete cleanup successfully.
    pub success_rate: f64,
    /// Average resource release time.
    pub avg_release_time: Duration,
    /// Cleanup parallelization effectiveness.
    pub parallelization_score: f64,
}

/// Performance metrics for individual entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityPerformance {
    /// Unique identifier for the entity.
    pub entity_id: String,
    /// Type of the entity being measured.
    pub entity_type: EntityType,
    /// Overall performance score (higher is better).
    pub performance_score: f64,
    /// Processing time statistics.
    pub processing_stats: DistributionStats,
    /// Throughput metrics.
    pub throughput: ThroughputMetrics,
    /// Error and anomaly rates.
    pub error_rate: f64,
    /// Rate of anomalies detected (0.0 to 1.0).
    pub anomaly_rate: f64,
}

/// Throughput measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputMetrics {
    /// Cancellations handled per second.
    pub cancellations_per_second: f64,
    /// Peak throughput observed.
    pub peak_throughput: f64,
    /// Throughput stability score.
    pub stability_score: f64,
}

/// Trend analysis over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    /// Trend in average propagation time.
    pub latency_trend: TrendDirection,
    /// Trend in throughput.
    pub throughput_trend: TrendDirection,
    /// Trend in anomaly frequency.
    pub anomaly_trend: TrendDirection,
    /// Performance stability trend.
    pub stability_trend: TrendDirection,
}

/// Direction of a trend.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TrendDirection {
    /// Trend is improving over time.
    Improving,
    /// Trend is stable with no significant change.
    Stable,
    /// Trend is degrading or worsening over time.
    Degrading,
    /// Insufficient data to determine trend direction.
    Insufficient,
}

/// Detected performance regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRegression {
    /// Entity or system component affected.
    pub affected_component: String,
    /// Metric that regressed.
    pub metric_name: String,
    /// Magnitude of regression.
    pub regression_magnitude: f64,
    /// Confidence in regression detection.
    pub confidence: f64,
    /// When regression was first detected.
    pub detected_at: SystemTime,
}

/// Optimization recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendation {
    /// Priority of this recommendation.
    pub priority: RecommendationPriority,
    /// Target component.
    pub target: String,
    /// Description of the optimization.
    pub description: String,
    /// Estimated impact of implementing this optimization.
    pub estimated_impact: f64,
    /// Implementation complexity estimate.
    pub complexity: ImplementationComplexity,
}

/// Priority level for recommendations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RecommendationPriority {
    /// Critical priority - immediate action required.
    Critical,
    /// High priority - action needed soon.
    High,
    /// Medium priority - address when convenient.
    Medium,
    /// Low priority - nice to have improvement.
    Low,
}

/// Implementation complexity estimate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ImplementationComplexity {
    /// Very simple change requiring minimal effort.
    Trivial,
    /// Simple change with low implementation cost.
    Simple,
    /// Moderate complexity requiring some design work.
    Moderate,
    /// Complex change requiring significant development effort.
    Complex,
    /// Major architectural change affecting multiple components.
    Architectural,
}

/// Deep performance analyzer.
pub struct CancellationAnalyzer {
    config: AnalyzerConfig,
}

impl CancellationAnalyzer {
    /// Creates a new analyzer with the given configuration.
    #[must_use]
    pub fn new(config: AnalyzerConfig) -> Self {
        Self { config }
    }

    /// Creates an analyzer with default configuration.
    #[must_use]
    pub fn default() -> Self {
        Self::new(AnalyzerConfig::default())
    }

    /// Perform deep performance analysis on a set of traces.
    #[must_use]
    pub fn analyze_performance(&self, traces: &[CancellationTrace]) -> PerformanceAnalysis {
        if traces.is_empty() || traces.len() < self.config.min_sample_size {
            return self.create_insufficient_data_analysis(traces.len());
        }

        let analysis_start = super::replayable_system_time();

        // Calculate distributions
        let propagation_times: Vec<f64> = traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0)) // Convert to ms
            .collect();

        let depths: Vec<f64> = traces.iter().map(|t| f64::from(t.max_depth)).collect();

        let propagation_time_distribution = self.calculate_distribution_stats(&propagation_times);
        let depth_distribution = self.calculate_distribution_stats(&depths);

        // Identify bottlenecks
        let bottlenecks = self.identify_bottlenecks(traces);

        // Analyze cleanup timing
        let cleanup_analysis = self.analyze_cleanup_timing(traces);

        // Rank entity performance
        let entity_rankings = self.rank_entity_performance(traces);

        // Analyze trends (would need historical data in practice)
        let trends = self.analyze_trends(traces);

        // Detect regressions (would need baseline comparison)
        let regressions = self.detect_regressions(traces);

        // Generate recommendations
        let recommendations =
            self.generate_recommendations(traces, &bottlenecks, &cleanup_analysis);

        let analysis_window = analysis_start.elapsed().unwrap_or(Duration::ZERO);

        PerformanceAnalysis {
            analysis_window,
            traces_analyzed: traces.len(),
            propagation_time_distribution,
            depth_distribution,
            bottlenecks,
            cleanup_analysis,
            entity_rankings,
            trends,
            regressions,
            recommendations,
        }
    }

    /// Calculate statistical distribution for a set of values.
    fn calculate_distribution_stats(&self, values: &[f64]) -> DistributionStats {
        if values.is_empty() {
            return DistributionStats {
                count: 0,
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
                percentile_95: 0.0,
                percentile_99: 0.0,
                min: 0.0,
                max: 0.0,
                outlier_count: 0,
            };
        }

        let mut sorted_values = values.to_vec();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let count = values.len();
        let mean = values.iter().sum::<f64>() / count as f64;
        let median = self.percentile(&sorted_values, 50.0);
        let percentile_95 = self.percentile(&sorted_values, 95.0);
        let percentile_99 = self.percentile(&sorted_values, 99.0);
        let min = sorted_values[0];
        let max = sorted_values[count - 1];

        // Calculate standard deviation
        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();

        // Count outliers (values more than 2 standard deviations from mean)
        let outlier_count = values
            .iter()
            .filter(|&&x| (x - mean).abs() > 2.0 * std_dev)
            .count();

        DistributionStats {
            count,
            mean,
            median,
            std_dev,
            percentile_95,
            percentile_99,
            min,
            max,
            outlier_count,
        }
    }

    /// Calculate percentile value from sorted data.
    fn percentile(&self, sorted_values: &[f64], percentile: f64) -> f64 {
        if sorted_values.is_empty() {
            return 0.0;
        }

        let index = (percentile / 100.0 * (sorted_values.len() - 1) as f64).round() as usize;
        sorted_values[index.min(sorted_values.len() - 1)]
    }

    /// Identify performance bottlenecks using statistical analysis.
    fn identify_bottlenecks(&self, traces: &[CancellationTrace]) -> Vec<BottleneckAnalysis> {
        let mut entity_timings: HashMap<String, Vec<Duration>> = HashMap::new();
        let mut total_trace_time_ms = 0.0;

        // Collect timing data per entity
        for trace in traces {
            if let Some(t) = trace.total_propagation_time {
                total_trace_time_ms += t.as_secs_f64() * 1000.0;
            }
            for step in &trace.steps {
                entity_timings
                    .entry(step.entity_id.clone())
                    .or_default()
                    .push(step.elapsed_since_prev);
            }
        }

        // Prevent division by zero
        if total_trace_time_ms == 0.0 {
            total_trace_time_ms = 1.0;
        }

        let mut bottlenecks = Vec::new();

        for (entity_id, timings) in entity_timings {
            if timings.len() < self.config.min_sample_size {
                continue;
            }

            let timing_ms: Vec<f64> = timings.iter().map(|d| d.as_secs_f64() * 1000.0).collect();

            let stats = self.calculate_distribution_stats(&timing_ms);
            let avg_processing_time = Duration::from_secs_f64(stats.mean / 1000.0);

            // Calculate impact as percentage of total cancellation time
            let total_time_contribution = stats.mean * timings.len() as f64;
            let impact_fraction = total_time_contribution / total_trace_time_ms;
            let impact_percentage = impact_fraction * 100.0;

            if impact_fraction > self.config.bottleneck_threshold {
                let confidence = if stats.count >= 50 && stats.std_dev < stats.mean {
                    0.9 // High confidence
                } else if stats.count >= 20 {
                    0.7 // Medium confidence
                } else {
                    0.5 // Low confidence
                };

                let mitigation_suggestions = self.generate_mitigation_suggestions(&stats);

                bottlenecks.push(BottleneckAnalysis {
                    entity_id,
                    entity_type: EntityType::Task, // Would need type tracking
                    impact_percentage,
                    avg_processing_time,
                    occurrence_count: stats.count,
                    confidence,
                    mitigation_suggestions,
                });
            }
        }

        // Sort by impact
        bottlenecks.sort_by(|a, b| {
            b.impact_percentage
                .partial_cmp(&a.impact_percentage)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        bottlenecks
    }

    /// Generate mitigation suggestions for bottlenecks.
    fn generate_mitigation_suggestions(&self, stats: &DistributionStats) -> Vec<String> {
        let mut suggestions = Vec::new();

        if stats.max > stats.mean * 3.0 {
            suggestions.push("High variability detected - investigate outlier cases".to_string());
        }

        if stats.mean > 100.0 {
            // 100ms threshold
            suggestions.push("Consider optimizing cancellation handler performance".to_string());
        }

        if stats.std_dev > stats.mean {
            suggestions
                .push("Inconsistent performance - check for resource contention".to_string());
        }

        if suggestions.is_empty() {
            suggestions.push("Monitor for performance degradation".to_string());
        }

        suggestions
    }

    /// Analyze resource cleanup timing patterns.
    fn analyze_cleanup_timing(&self, traces: &[CancellationTrace]) -> CleanupTimingAnalysis {
        let cleanup_times: Vec<f64> = traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        let cleanup_distribution = self.calculate_distribution_stats(&cleanup_times);
        let avg_cleanup_latency = Duration::from_secs_f64(cleanup_distribution.mean / 1000.0);

        // Identify entities with consistently slow cleanup
        let slow_cleanup_entities = self.identify_slow_cleanup_entities(traces);

        // Calculate leak risk score based on cleanup success rate
        let successful_cleanups = traces.iter().filter(|t| t.is_complete).count() as f64;
        let success_rate = successful_cleanups / traces.len() as f64;
        let leak_risk_score = (1.0 - success_rate) * 100.0;

        let cleanup_efficiency = CleanupEfficiency {
            success_rate,
            avg_release_time: avg_cleanup_latency,
            parallelization_score: self.calculate_parallelization_score(traces),
        };

        CleanupTimingAnalysis {
            avg_cleanup_latency,
            cleanup_distribution,
            slow_cleanup_entities,
            leak_risk_score,
            cleanup_efficiency,
        }
    }

    /// Identify entities with consistently slow cleanup.
    fn identify_slow_cleanup_entities(&self, traces: &[CancellationTrace]) -> Vec<String> {
        let mut entity_cleanup_times: HashMap<String, Vec<Duration>> = HashMap::new();

        for trace in traces {
            if let Some(_total_time) = trace.total_propagation_time {
                for step in &trace.steps {
                    // Rough approximation - in practice would need better tracking
                    entity_cleanup_times
                        .entry(step.entity_id.clone())
                        .or_default()
                        .push(step.elapsed_since_prev);
                }
            }
        }

        let mut slow_entities = Vec::new();
        let threshold = Duration::from_millis(50); // 50ms threshold

        for (entity_id, times) in entity_cleanup_times {
            if times.len() < 3 {
                continue; // Need minimum samples
            }

            let avg_time = Duration::from_nanos(
                times.iter().map(|d| d.as_nanos() as u64).sum::<u64>() / times.len() as u64,
            );

            if avg_time > threshold {
                slow_entities.push(entity_id);
            }
        }

        slow_entities
    }

    /// Calculate parallelization effectiveness score.
    fn calculate_parallelization_score(&self, traces: &[CancellationTrace]) -> f64 {
        // Simplified score based on depth vs entities ratio
        let total_entities: usize = traces.iter().map(|t| t.entities_cancelled as usize).sum();
        let total_depth: u32 = traces.iter().map(|t| t.max_depth).sum();

        if total_depth == 0 {
            return 1.0;
        }

        // Higher ratio means better parallelization
        let ratio = total_entities as f64 / f64::from(total_depth);
        (ratio / 10.0).min(1.0) // Normalize to 0-1
    }

    /// Rank entities by overall performance.
    fn rank_entity_performance(&self, traces: &[CancellationTrace]) -> Vec<EntityPerformance> {
        let mut entity_data: HashMap<String, Vec<Duration>> = HashMap::new();
        let mut entity_anomalies: HashMap<String, usize> = HashMap::new();

        // Collect performance data
        for trace in traces {
            for step in &trace.steps {
                entity_data
                    .entry(step.entity_id.clone())
                    .or_default()
                    .push(step.elapsed_since_prev);
            }

            // Count anomalies per entity
            for anomaly in &trace.anomalies {
                match anomaly {
                    PropagationAnomaly::SlowPropagation { entity_id, .. }
                    | PropagationAnomaly::StuckCancellation { entity_id, .. }
                    | PropagationAnomaly::ExcessiveDepth { entity_id, .. } => {
                        *entity_anomalies.entry(entity_id.clone()).or_default() += 1;
                    }
                    PropagationAnomaly::IncorrectPropagationOrder { parent_entity, .. } => {
                        *entity_anomalies.entry(parent_entity.clone()).or_default() += 1;
                    }
                    PropagationAnomaly::UnexpectedPropagation {
                        affected_entities, ..
                    } => {
                        for entity_id in affected_entities {
                            *entity_anomalies.entry(entity_id.clone()).or_default() += 1;
                        }
                    }
                }
            }
        }

        let mut rankings = Vec::new();

        for (entity_id, times) in entity_data {
            if times.is_empty() {
                continue;
            }
            let timing_ms: Vec<f64> = times.iter().map(|d| d.as_secs_f64() * 1000.0).collect();

            let processing_stats = self.calculate_distribution_stats(&timing_ms);
            let anomaly_count = entity_anomalies.get(&entity_id).copied().unwrap_or(0);
            let anomaly_rate = anomaly_count as f64 / times.len() as f64;

            // Calculate throughput
            let total_time_seconds = times
                .iter()
                .map(std::time::Duration::as_secs_f64)
                .sum::<f64>();
            let throughput = if total_time_seconds > 0.0 {
                times.len() as f64 / total_time_seconds
            } else {
                0.0
            };

            let throughput_metrics = ThroughputMetrics {
                cancellations_per_second: throughput,
                peak_throughput: throughput, // Would need sliding window analysis
                stability_score: 1.0 - (processing_stats.std_dev / processing_stats.mean.max(1.0)),
            };

            // Calculate overall performance score
            let latency_score = 100.0 / (1.0 + processing_stats.mean);
            let reliability_score = (1.0 - anomaly_rate) * 100.0;
            let throughput_score = throughput.min(100.0);
            let performance_score = (latency_score + reliability_score + throughput_score) / 3.0;

            rankings.push(EntityPerformance {
                entity_id,
                entity_type: EntityType::Task, // Would need type tracking
                performance_score,
                processing_stats,
                throughput: throughput_metrics,
                error_rate: 0.0, // Would need error tracking
                anomaly_rate,
            });
        }

        // Sort by performance score
        rankings.sort_by(|a, b| {
            b.performance_score
                .partial_cmp(&a.performance_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        rankings
    }

    /// Analyze performance trends based on trace data ordered by timestamp.
    fn analyze_trends(&self, traces: &[CancellationTrace]) -> TrendAnalysis {
        if traces.len() < self.config.trend_window_size {
            return TrendAnalysis {
                latency_trend: TrendDirection::Insufficient,
                throughput_trend: TrendDirection::Insufficient,
                anomaly_trend: TrendDirection::Insufficient,
                stability_trend: TrendDirection::Insufficient,
            };
        }

        // Sort traces by start time to establish temporal order
        let mut ordered_traces = traces.to_vec();
        ordered_traces.sort_by_key(|t| t.start_time);

        // Split into early and recent halves for trend comparison
        let split_point = ordered_traces.len() / 2;
        let early_traces = &ordered_traces[..split_point];
        let recent_traces = &ordered_traces[split_point..];

        // Calculate trend directions
        let latency_trend = self.calculate_latency_trend(early_traces, recent_traces);
        let throughput_trend = self.calculate_throughput_trend(early_traces, recent_traces);
        let anomaly_trend = self.calculate_anomaly_trend(early_traces, recent_traces);
        let stability_trend = self.calculate_stability_trend(early_traces, recent_traces);

        TrendAnalysis {
            latency_trend,
            throughput_trend,
            anomaly_trend,
            stability_trend,
        }
    }

    /// Detect performance regressions by comparing recent performance to historical baseline.
    fn detect_regressions(&self, traces: &[CancellationTrace]) -> Vec<PerformanceRegression> {
        if traces.len() < self.config.min_sample_size * 2 {
            return Vec::new(); // Need sufficient data for comparison
        }

        let mut regressions = Vec::new();
        let now = super::replayable_system_time();

        // Sort traces by start time for temporal analysis
        let mut ordered_traces = traces.to_vec();
        ordered_traces.sort_by_key(|t| t.start_time);

        // Split into baseline (first 60%) and recent (last 40%) for comparison
        let baseline_end = (ordered_traces.len() as f64 * 0.6) as usize;
        let baseline_traces = &ordered_traces[..baseline_end];
        let recent_traces = &ordered_traces[baseline_end..];

        // Detect latency regressions
        if let Some(regression) =
            self.detect_latency_regression(baseline_traces, recent_traces, now)
        {
            regressions.push(regression);
        }

        // Detect throughput regressions
        if let Some(regression) =
            self.detect_throughput_regression(baseline_traces, recent_traces, now)
        {
            regressions.push(regression);
        }

        // Detect anomaly increase regressions
        if let Some(regression) =
            self.detect_anomaly_regression(baseline_traces, recent_traces, now)
        {
            regressions.push(regression);
        }

        regressions
    }

    /// Generate optimization recommendations.
    fn generate_recommendations(
        &self,
        traces: &[CancellationTrace],
        bottlenecks: &[BottleneckAnalysis],
        cleanup_analysis: &CleanupTimingAnalysis,
    ) -> Vec<OptimizationRecommendation> {
        let mut recommendations = Vec::new();

        // Bottleneck-based recommendations
        for bottleneck in bottlenecks {
            if bottleneck.impact_percentage > 50.0 {
                recommendations.push(OptimizationRecommendation {
                    priority: RecommendationPriority::Critical,
                    target: bottleneck.entity_id.clone(),
                    description: format!(
                        "Optimize {} - causing {}% of cancellation latency",
                        bottleneck.entity_id, bottleneck.impact_percentage
                    ),
                    estimated_impact: bottleneck.impact_percentage,
                    complexity: ImplementationComplexity::Moderate,
                });
            }
        }

        // Cleanup-based recommendations
        if cleanup_analysis.leak_risk_score > 10.0 {
            recommendations.push(OptimizationRecommendation {
                priority: RecommendationPriority::High,
                target: "cleanup".to_string(),
                description: format!(
                    "Improve cleanup reliability - {}% leak risk",
                    cleanup_analysis.leak_risk_score
                ),
                estimated_impact: cleanup_analysis.leak_risk_score,
                complexity: ImplementationComplexity::Complex,
            });
        }

        // General recommendations based on patterns
        let total_entities: usize = traces.iter().map(|t| t.entities_cancelled as usize).sum();
        if total_entities > traces.len() * 50 {
            recommendations.push(OptimizationRecommendation {
                priority: RecommendationPriority::Medium,
                target: "architecture".to_string(),
                description: "Consider reducing structured concurrency depth".to_string(),
                estimated_impact: 20.0,
                complexity: ImplementationComplexity::Architectural,
            });
        }

        recommendations
    }

    /// Calculate relative change while handling zero-valued baselines deterministically.
    fn relative_change(&self, baseline: f64, recent: f64) -> f64 {
        if baseline.abs() <= f64::EPSILON {
            if recent.abs() <= f64::EPSILON {
                0.0
            } else {
                1.0
            }
        } else {
            (recent - baseline) / baseline
        }
    }

    /// Calculate a regression drop ratio against a positive baseline.
    fn regression_drop(&self, baseline: f64, recent: f64) -> f64 {
        if baseline.abs() <= f64::EPSILON {
            0.0
        } else {
            (baseline - recent) / baseline
        }
    }

    /// Calculate latency trend by comparing early vs recent traces.
    fn calculate_latency_trend(
        &self,
        early_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
    ) -> TrendDirection {
        let early_latencies: Vec<f64> = early_traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        let recent_latencies: Vec<f64> = recent_traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        if early_latencies.is_empty() || recent_latencies.is_empty() {
            return TrendDirection::Insufficient;
        }

        let early_avg = early_latencies.iter().sum::<f64>() / early_latencies.len() as f64;
        let recent_avg = recent_latencies.iter().sum::<f64>() / recent_latencies.len() as f64;

        // 5% threshold for significance
        let change_ratio = self.relative_change(early_avg, recent_avg);
        if change_ratio > 0.05 {
            TrendDirection::Degrading // Latency increased
        } else if change_ratio < -0.05 {
            TrendDirection::Improving // Latency decreased
        } else {
            TrendDirection::Stable
        }
    }

    /// Calculate throughput trend by comparing trace processing rates.
    fn calculate_throughput_trend(
        &self,
        early_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
    ) -> TrendDirection {
        if early_traces.is_empty() || recent_traces.is_empty() {
            return TrendDirection::Insufficient;
        }

        // Approximate throughput as entities cancelled per unit time
        let early_throughput = early_traces
            .iter()
            .filter_map(|t| {
                t.total_propagation_time.map(|duration| {
                    if duration.as_secs_f64() > 0.0 {
                        t.entities_cancelled as f64 / duration.as_secs_f64()
                    } else {
                        0.0
                    }
                })
            })
            .collect::<Vec<f64>>();

        let recent_throughput = recent_traces
            .iter()
            .filter_map(|t| {
                t.total_propagation_time.map(|duration| {
                    if duration.as_secs_f64() > 0.0 {
                        t.entities_cancelled as f64 / duration.as_secs_f64()
                    } else {
                        0.0
                    }
                })
            })
            .collect::<Vec<f64>>();

        if early_throughput.is_empty() || recent_throughput.is_empty() {
            return TrendDirection::Insufficient;
        }

        let early_avg = early_throughput.iter().sum::<f64>() / early_throughput.len() as f64;
        let recent_avg = recent_throughput.iter().sum::<f64>() / recent_throughput.len() as f64;

        let change_ratio = self.relative_change(early_avg, recent_avg);
        if change_ratio > 0.05 {
            TrendDirection::Improving // Throughput increased
        } else if change_ratio < -0.05 {
            TrendDirection::Degrading // Throughput decreased
        } else {
            TrendDirection::Stable
        }
    }

    /// Calculate anomaly trend by comparing anomaly rates.
    fn calculate_anomaly_trend(
        &self,
        early_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
    ) -> TrendDirection {
        let early_anomaly_rate = if early_traces.is_empty() {
            0.0
        } else {
            early_traces
                .iter()
                .map(|t| t.anomalies.len())
                .sum::<usize>() as f64
                / early_traces.len() as f64
        };

        let recent_anomaly_rate = if recent_traces.is_empty() {
            0.0
        } else {
            recent_traces
                .iter()
                .map(|t| t.anomalies.len())
                .sum::<usize>() as f64
                / recent_traces.len() as f64
        };

        if early_anomaly_rate == 0.0 && recent_anomaly_rate == 0.0 {
            return TrendDirection::Stable;
        }

        // For anomalies, we use absolute change since rates are typically small
        let change = recent_anomaly_rate - early_anomaly_rate;
        if change > 0.1 {
            TrendDirection::Degrading // More anomalies
        } else if change < -0.1 {
            TrendDirection::Improving // Fewer anomalies
        } else {
            TrendDirection::Stable
        }
    }

    /// Calculate stability trend by comparing latency variance.
    fn calculate_stability_trend(
        &self,
        early_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
    ) -> TrendDirection {
        let early_latencies: Vec<f64> = early_traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        let recent_latencies: Vec<f64> = recent_traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        if early_latencies.len() < 2 || recent_latencies.len() < 2 {
            return TrendDirection::Insufficient;
        }

        let early_stats = self.calculate_distribution_stats(&early_latencies);
        let recent_stats = self.calculate_distribution_stats(&recent_latencies);

        // Coefficient of variation as stability metric (lower is more stable)
        let early_cv = if early_stats.mean > 0.0 {
            early_stats.std_dev / early_stats.mean
        } else if early_stats.std_dev <= f64::EPSILON {
            0.0
        } else {
            f64::INFINITY
        };
        let recent_cv = if recent_stats.mean > 0.0 {
            recent_stats.std_dev / recent_stats.mean
        } else if recent_stats.std_dev <= f64::EPSILON {
            0.0
        } else {
            f64::INFINITY
        };

        if early_cv.is_infinite() || recent_cv.is_infinite() {
            return TrendDirection::Insufficient;
        }

        // 10% threshold for coefficient of variation change
        let change_ratio = self.relative_change(early_cv, recent_cv);
        if change_ratio > 0.1 {
            TrendDirection::Degrading // Less stable
        } else if change_ratio < -0.1 {
            TrendDirection::Improving // More stable
        } else {
            TrendDirection::Stable
        }
    }

    /// Detect latency regression by comparing baseline to recent performance.
    fn detect_latency_regression(
        &self,
        baseline_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
        detected_at: SystemTime,
    ) -> Option<PerformanceRegression> {
        let baseline_latencies: Vec<f64> = baseline_traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        let recent_latencies: Vec<f64> = recent_traces
            .iter()
            .filter_map(|t| t.total_propagation_time.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        if baseline_latencies.is_empty() || recent_latencies.is_empty() {
            return None;
        }

        let baseline_avg = baseline_latencies.iter().sum::<f64>() / baseline_latencies.len() as f64;
        let recent_avg = recent_latencies.iter().sum::<f64>() / recent_latencies.len() as f64;

        // Detect regression if recent latency is significantly higher
        let regression_magnitude = self.relative_change(baseline_avg, recent_avg);
        if regression_magnitude > 0.2 {
            // 20% increase threshold
            let confidence = if regression_magnitude > 0.5 {
                0.9
            } else if regression_magnitude > 0.3 {
                0.7
            } else {
                0.5
            };

            Some(PerformanceRegression {
                affected_component: "cancellation_latency".to_string(),
                metric_name: "average_propagation_time".to_string(),
                regression_magnitude,
                confidence,
                detected_at,
            })
        } else {
            None
        }
    }

    /// Detect throughput regression by comparing processing rates.
    fn detect_throughput_regression(
        &self,
        baseline_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
        detected_at: SystemTime,
    ) -> Option<PerformanceRegression> {
        let baseline_throughput = baseline_traces
            .iter()
            .filter_map(|t| {
                t.total_propagation_time.map(|duration| {
                    if duration.as_secs_f64() > 0.0 {
                        t.entities_cancelled as f64 / duration.as_secs_f64()
                    } else {
                        0.0
                    }
                })
            })
            .filter(|&x| x > 0.0)
            .collect::<Vec<f64>>();

        let recent_throughput = recent_traces
            .iter()
            .filter_map(|t| {
                t.total_propagation_time.map(|duration| {
                    if duration.as_secs_f64() > 0.0 {
                        t.entities_cancelled as f64 / duration.as_secs_f64()
                    } else {
                        0.0
                    }
                })
            })
            .filter(|&x| x > 0.0)
            .collect::<Vec<f64>>();

        if baseline_throughput.is_empty() || recent_throughput.is_empty() {
            return None;
        }

        let baseline_avg =
            baseline_throughput.iter().sum::<f64>() / baseline_throughput.len() as f64;
        let recent_avg = recent_throughput.iter().sum::<f64>() / recent_throughput.len() as f64;

        // Detect regression if recent throughput is significantly lower
        let throughput_drop = self.regression_drop(baseline_avg, recent_avg);
        if throughput_drop > 0.15 {
            // 15% decrease threshold
            let confidence = if throughput_drop > 0.4 {
                0.9
            } else if throughput_drop > 0.25 {
                0.7
            } else {
                0.5
            };

            Some(PerformanceRegression {
                affected_component: "cancellation_throughput".to_string(),
                metric_name: "entities_per_second".to_string(),
                regression_magnitude: throughput_drop,
                confidence,
                detected_at,
            })
        } else {
            None
        }
    }

    /// Detect anomaly rate regression (increase in anomalies).
    fn detect_anomaly_regression(
        &self,
        baseline_traces: &[CancellationTrace],
        recent_traces: &[CancellationTrace],
        detected_at: SystemTime,
    ) -> Option<PerformanceRegression> {
        let baseline_anomaly_rate = if baseline_traces.is_empty() {
            0.0
        } else {
            baseline_traces
                .iter()
                .map(|t| t.anomalies.len())
                .sum::<usize>() as f64
                / baseline_traces.len() as f64
        };

        let recent_anomaly_rate = if recent_traces.is_empty() {
            0.0
        } else {
            recent_traces
                .iter()
                .map(|t| t.anomalies.len())
                .sum::<usize>() as f64
                / recent_traces.len() as f64
        };

        // Detect regression if anomaly rate increased significantly
        let anomaly_increase = recent_anomaly_rate - baseline_anomaly_rate;
        if anomaly_increase > 0.5 {
            // 0.5 anomalies per trace threshold
            let regression_magnitude = if baseline_anomaly_rate > 0.0 {
                anomaly_increase / baseline_anomaly_rate
            } else {
                anomaly_increase // Use absolute increase if baseline was 0
            };

            let confidence = if anomaly_increase > 2.0 {
                0.9
            } else if anomaly_increase > 1.0 {
                0.7
            } else {
                0.5
            };

            Some(PerformanceRegression {
                affected_component: "cancellation_anomalies".to_string(),
                metric_name: "anomaly_rate".to_string(),
                regression_magnitude,
                confidence,
                detected_at,
            })
        } else {
            None
        }
    }

    /// Create analysis for insufficient data scenarios.
    fn create_insufficient_data_analysis(&self, trace_count: usize) -> PerformanceAnalysis {
        PerformanceAnalysis {
            analysis_window: Duration::ZERO,
            traces_analyzed: trace_count,
            propagation_time_distribution: DistributionStats {
                count: 0,
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
                percentile_95: 0.0,
                percentile_99: 0.0,
                min: 0.0,
                max: 0.0,
                outlier_count: 0,
            },
            depth_distribution: DistributionStats {
                count: 0,
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
                percentile_95: 0.0,
                percentile_99: 0.0,
                min: 0.0,
                max: 0.0,
                outlier_count: 0,
            },
            bottlenecks: Vec::new(),
            cleanup_analysis: CleanupTimingAnalysis {
                avg_cleanup_latency: Duration::ZERO,
                cleanup_distribution: DistributionStats {
                    count: 0,
                    mean: 0.0,
                    median: 0.0,
                    std_dev: 0.0,
                    percentile_95: 0.0,
                    percentile_99: 0.0,
                    min: 0.0,
                    max: 0.0,
                    outlier_count: 0,
                },
                slow_cleanup_entities: Vec::new(),
                leak_risk_score: 0.0,
                cleanup_efficiency: CleanupEfficiency {
                    success_rate: 0.0,
                    avg_release_time: Duration::ZERO,
                    parallelization_score: 0.0,
                },
            },
            entity_rankings: Vec::new(),
            trends: TrendAnalysis {
                latency_trend: TrendDirection::Insufficient,
                throughput_trend: TrendDirection::Insufficient,
                anomaly_trend: TrendDirection::Insufficient,
                stability_trend: TrendDirection::Insufficient,
            },
            regressions: Vec::new(),
            recommendations: vec![OptimizationRecommendation {
                priority: RecommendationPriority::Low,
                target: "monitoring".to_string(),
                description: format!("Collect more data - only {trace_count} traces available"),
                estimated_impact: 0.0,
                complexity: ImplementationComplexity::Trivial,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::observability::cancellation_tracer::{CancellationTraceId, CancellationTraceStep};

    fn test_step(entity_id: String, elapsed_since_prev: Duration) -> CancellationTraceStep {
        CancellationTraceStep {
            step_id: 0,
            entity_id,
            entity_type: EntityType::Task,
            cancel_reason: "test".to_string(),
            cancel_kind: "User".to_string(),
            timestamp: SystemTime::UNIX_EPOCH,
            elapsed_since_start: elapsed_since_prev,
            elapsed_since_prev,
            depth: 0,
            parent_entity: None,
            entity_state: "Cancelled".to_string(),
            propagation_completed: true,
        }
    }

    fn test_trace(
        trace_index: usize,
        start_time: SystemTime,
        total_propagation_time: Duration,
        entities_cancelled: u32,
        steps: Vec<CancellationTraceStep>,
        anomalies: Vec<PropagationAnomaly>,
    ) -> CancellationTrace {
        CancellationTrace {
            trace_id: CancellationTraceId::new(),
            root_cancel_reason: format!("test-{trace_index}"),
            root_cancel_kind: "User".to_string(),
            root_entity: "root".to_string(),
            root_entity_type: EntityType::Task,
            start_time,
            steps,
            is_complete: true,
            total_propagation_time: Some(total_propagation_time),
            max_depth: 3,
            entities_cancelled,
            anomalies,
        }
    }

    #[test]
    fn test_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let _analyzer = CancellationAnalyzer::new(config);
        assert!(true); // Just test creation
    }

    #[test]
    fn test_distribution_stats() {
        let analyzer = CancellationAnalyzer::default();
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = analyzer.calculate_distribution_stats(&values);

        assert_eq!(stats.count, 5);
        assert_eq!(stats.mean, 3.0);
        assert_eq!(stats.median, 3.0);
    }

    #[test]
    fn test_insufficient_data_handling() {
        let analyzer = CancellationAnalyzer::default();
        let traces = Vec::new(); // Empty traces
        let analysis = analyzer.analyze_performance(&traces);

        assert_eq!(analysis.traces_analyzed, 0);
        assert!(!analysis.recommendations.is_empty()); // Should have "collect more data" recommendation
    }

    #[test]
    fn test_empty_input_is_insufficient_even_with_zero_min_sample_size() {
        let analyzer = CancellationAnalyzer::new(AnalyzerConfig {
            min_sample_size: 0,
            ..AnalyzerConfig::default()
        });
        let analysis = analyzer.analyze_performance(&[]);

        assert_eq!(analysis.traces_analyzed, 0);
        assert!(
            analysis
                .cleanup_analysis
                .cleanup_efficiency
                .success_rate
                .is_finite()
        );
        assert_eq!(
            analysis.cleanup_analysis.cleanup_efficiency.success_rate,
            0.0
        );
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_bottleneck_threshold_is_fraction_not_percentage_points() {
        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;
        let traces = (0..10)
            .map(|i| {
                test_trace(
                    i,
                    base_time + Duration::from_secs(i as u64),
                    Duration::from_millis(100),
                    2,
                    vec![
                        test_step("minor".to_string(), Duration::from_millis(1)),
                        test_step("major".to_string(), Duration::from_millis(20)),
                    ],
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();

        let bottlenecks = analyzer.identify_bottlenecks(&traces);

        assert_eq!(bottlenecks.len(), 1);
        assert_eq!(bottlenecks[0].entity_id, "major");
        assert!((bottlenecks[0].impact_percentage - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_trend_analysis_non_placeholder() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        // Create traces with improving latency trend (early high, recent low)
        let mut traces = Vec::new();

        // Early traces (higher latency)
        for i in 0..50 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(100 + i * 2),
                5,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(20),
                )],
                Vec::new(),
            ));
        }

        // Recent traces (lower latency)
        for i in 50..100 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(50 + (i - 50) / 2),
                8,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(15),
                )],
                Vec::new(),
            ));
        }

        let trends = analyzer.analyze_trends(&traces);

        // Should detect improving latency and throughput trends
        assert!(
            matches!(trends.latency_trend, TrendDirection::Improving),
            "Expected improving latency trend, got {:?}",
            trends.latency_trend
        );
        assert!(
            matches!(trends.throughput_trend, TrendDirection::Improving),
            "Expected improving throughput trend, got {:?}",
            trends.throughput_trend
        );
        assert!(
            !matches!(trends.latency_trend, TrendDirection::Insufficient),
            "Should not return placeholder Insufficient result"
        );
    }

    #[test]
    fn test_regression_detection_non_placeholder() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        let mut traces = Vec::new();

        // Baseline traces (good performance)
        for i in 0..30 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(50),
                10,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(15),
                )],
                Vec::new(),
            ));
        }

        // Recent traces with regression (much higher latency + anomalies)
        for i in 30..50 {
            let mut anomalies = Vec::new();
            if i % 3 == 0 {
                anomalies.push(PropagationAnomaly::SlowPropagation {
                    step_id: 0,
                    entity_id: format!("entity-slow-{}", i),
                    elapsed: Duration::from_millis(150),
                    threshold: Duration::from_millis(50),
                });
            }

            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(200),
                8,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(60),
                )],
                anomalies,
            ));
        }

        let regressions = analyzer.detect_regressions(&traces);

        // Should detect latency and potentially throughput/anomaly regressions
        assert!(!regressions.is_empty(), "Should detect regressions");

        let latency_regression = regressions
            .iter()
            .find(|r| r.metric_name == "average_propagation_time");
        assert!(
            latency_regression.is_some(),
            "Should detect latency regression"
        );

        if let Some(reg) = latency_regression {
            assert!(
                reg.regression_magnitude > 0.2,
                "Should detect significant regression"
            );
            assert!(reg.confidence > 0.0, "Should have confidence measure");
        }
    }

    #[test]
    fn test_trend_analysis_stable_case() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        // Create traces with stable performance (no significant change)
        let mut traces = Vec::new();
        for i in 0..100 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(100),
                5,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(20),
                )],
                Vec::new(),
            ));
        }

        let trends = analyzer.analyze_trends(&traces);

        // Should detect stable trends, not placeholder insufficient
        assert!(
            matches!(trends.latency_trend, TrendDirection::Stable),
            "Expected stable latency trend, got {:?}",
            trends.latency_trend
        );
        assert!(
            !matches!(trends.latency_trend, TrendDirection::Insufficient),
            "Should not return placeholder result for sufficient data"
        );
    }

    #[test]
    fn test_no_regression_with_good_performance() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        // Create traces with consistently good performance
        let mut traces = Vec::new();
        for i in 0..50 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(50),
                10,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(15),
                )],
                Vec::new(),
            ));
        }

        let regressions = analyzer.detect_regressions(&traces);

        // Should not detect any regressions with consistent good performance
        assert!(
            regressions.is_empty(),
            "Should not detect regressions with stable good performance"
        );
    }

    #[test]
    fn test_zero_baseline_trends_do_not_divide_by_zero() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;
        let early_traces = vec![
            test_trace(
                0,
                base_time,
                Duration::ZERO,
                0,
                vec![test_step("entity-a".to_string(), Duration::ZERO)],
                Vec::new(),
            ),
            test_trace(
                1,
                base_time + Duration::from_secs(1),
                Duration::ZERO,
                0,
                vec![test_step("entity-b".to_string(), Duration::ZERO)],
                Vec::new(),
            ),
        ];
        let recent_traces = vec![
            test_trace(
                2,
                base_time + Duration::from_secs(2),
                Duration::from_millis(10),
                2,
                vec![test_step("entity-c".to_string(), Duration::from_millis(10))],
                Vec::new(),
            ),
            test_trace(
                3,
                base_time + Duration::from_secs(3),
                Duration::from_millis(20),
                4,
                vec![test_step("entity-d".to_string(), Duration::from_millis(20))],
                Vec::new(),
            ),
        ];

        assert!(matches!(
            analyzer.calculate_latency_trend(&early_traces, &recent_traces),
            TrendDirection::Degrading
        ));
        assert!(matches!(
            analyzer.calculate_throughput_trend(&early_traces, &recent_traces),
            TrendDirection::Improving
        ));
        assert!(matches!(
            analyzer.calculate_stability_trend(&early_traces, &recent_traces),
            TrendDirection::Degrading
        ));
    }

    #[test]
    fn test_zero_baseline_regressions_do_not_divide_by_zero() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let detected_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let baseline_traces = vec![test_trace(
            0,
            SystemTime::UNIX_EPOCH,
            Duration::ZERO,
            0,
            vec![test_step("entity-a".to_string(), Duration::ZERO)],
            Vec::new(),
        )];
        let recent_traces = vec![test_trace(
            1,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            Duration::from_millis(25),
            5,
            vec![test_step("entity-b".to_string(), Duration::from_millis(25))],
            Vec::new(),
        )];

        let latency_regression =
            analyzer.detect_latency_regression(&baseline_traces, &recent_traces, detected_at);
        assert!(
            latency_regression.is_some(),
            "positive latency after a zero baseline should register as a regression"
        );
        assert_eq!(
            latency_regression.unwrap().regression_magnitude,
            1.0,
            "zero-baseline regression magnitude should be clamped to a finite sentinel"
        );

        let throughput_regression =
            analyzer.detect_throughput_regression(&baseline_traces, &recent_traces, detected_at);
        assert!(
            throughput_regression.is_none(),
            "zero throughput baseline should not report a throughput drop regression"
        );
    }
}
