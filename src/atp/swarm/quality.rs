//! ATP Swarm Quality Metrics - Quality assessment and monitoring for swarm performance.
//!
//! Provides comprehensive quality metrics collection, analysis, and monitoring
//! for swarm transfers and peer performance.

use super::{MailboxTransferId, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Comprehensive quality metrics collector for swarm operations.
#[derive(Debug)]
pub struct QualityMetrics {
    /// Transfer-level metrics
    transfer_metrics: HashMap<MailboxTransferId, TransferQualityMetrics>,

    /// Peer-level metrics
    peer_metrics: HashMap<PeerId, PeerQualityMetrics>,

    /// Global swarm health metrics
    global_metrics: GlobalSwarmMetrics,

    /// Metric collection configuration
    config: QualityConfig,
}

/// Configuration for quality metrics collection.
#[derive(Debug, Clone)]
pub struct QualityConfig {
    /// Maximum history length for time series data
    pub max_history_length: usize,

    /// Sampling interval for metrics
    pub sampling_interval: Duration,

    /// Window size for moving averages
    pub moving_average_window: Duration,

    /// Quality threshold for alerts
    pub quality_alert_threshold: f64,
}

impl Default for QualityConfig {
    fn default() -> Self {
        Self {
            max_history_length: 1000,
            sampling_interval: Duration::from_secs(5),
            moving_average_window: Duration::from_secs(60),
            quality_alert_threshold: 0.3,
        }
    }
}

/// Quality metrics for a specific transfer.
#[derive(Debug, Clone)]
pub struct TransferQualityMetrics {
    /// Transfer identifier
    pub transfer_id: MailboxTransferId,

    /// Transfer start time
    pub started_at: Instant,

    /// Transfer completion time (if completed)
    pub completed_at: Option<Instant>,

    /// Download rate history (bytes/sec)
    pub download_rate_history: VecDeque<TimestampedMetric<f64>>,

    /// Upload rate history (bytes/sec)
    pub upload_rate_history: VecDeque<TimestampedMetric<f64>>,

    /// Peer response times
    pub peer_response_times: HashMap<PeerId, VecDeque<TimestampedMetric<Duration>>>,

    /// Verification failure rate over time
    pub verification_failures: VecDeque<TimestampedMetric<f64>>,

    /// Total verification attempts observed for this transfer
    pub verification_attempt_count: u64,

    /// Total verification failures observed for this transfer
    pub verification_failure_count: u64,

    /// Swarm health score over time
    pub health_scores: VecDeque<TimestampedMetric<f64>>,

    /// Current transfer status
    pub current_status: TransferQualityStatus,
}

/// Quality metrics for a specific peer.
#[derive(Debug, Clone)]
pub struct PeerQualityMetrics {
    /// Peer identifier
    pub peer_id: PeerId,

    /// First seen timestamp
    pub first_seen: Instant,

    /// Last activity timestamp
    pub last_activity: Instant,

    /// Download speeds over time (bytes/sec)
    pub download_speeds: VecDeque<TimestampedMetric<f64>>,

    /// Upload speeds over time (bytes/sec)
    pub upload_speeds: VecDeque<TimestampedMetric<f64>>,

    /// Response times over time
    pub response_times: VecDeque<TimestampedMetric<Duration>>,

    /// Reliability measurements over time
    pub reliability_scores: VecDeque<TimestampedMetric<f64>>,

    /// Uptime percentage
    pub uptime_percentage: f64,

    /// Total bytes transferred
    pub total_bytes_transferred: u64,

    /// Connection quality metrics
    pub connection_quality: ConnectionQualityMetrics,
}

/// Global metrics for the entire swarm.
#[derive(Debug, Clone, Default)]
pub struct GlobalSwarmMetrics {
    /// Total active transfers
    pub active_transfers: u32,

    /// Total active peers
    pub active_peers: u32,

    /// Global throughput (bytes/sec)
    pub global_throughput: f64,

    /// Average peer quality
    pub avg_peer_quality: f64,

    /// Overall swarm health score
    pub swarm_health_score: f64,

    /// Resource utilization metrics
    pub resource_utilization: ResourceUtilization,

    /// Network efficiency metrics
    pub network_efficiency: NetworkEfficiency,
}

/// Resource utilization tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUtilization {
    /// Bandwidth utilization percentage
    pub bandwidth_utilization: f64,

    /// Connection pool utilization
    pub connection_utilization: f64,

    /// Memory usage for swarm operations
    pub memory_usage_mb: f64,

    /// CPU usage percentage for swarm processing
    pub cpu_usage: f64,
}

/// Network efficiency metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkEfficiency {
    /// Effective bandwidth usage (useful data / total bandwidth)
    pub effective_bandwidth_ratio: f64,

    /// Redundancy efficiency (1.0 = optimal redundancy)
    pub redundancy_efficiency: f64,

    /// Peer discovery efficiency
    pub peer_discovery_success_rate: f64,

    /// Request-response efficiency
    pub request_response_efficiency: f64,
}

/// Connection quality metrics for peer-to-peer links.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionQualityMetrics {
    /// Round-trip time statistics
    pub rtt_stats: LatencyStats,

    /// Packet loss rate
    pub packet_loss_rate: f64,

    /// Bandwidth stability (variance measure)
    pub bandwidth_stability: f64,

    /// Connection uptime percentage
    pub uptime_percentage: f64,

    /// Number of reconnection attempts
    pub reconnection_count: u32,
}

/// Statistical measurements for latency/timing data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Mean latency
    pub mean: Duration,

    /// Median latency
    pub median: Duration,

    /// 95th percentile latency
    pub p95: Duration,

    /// 99th percentile latency
    pub p99: Duration,

    /// Standard deviation
    pub std_dev: Duration,

    /// Minimum observed latency
    pub min: Duration,

    /// Maximum observed latency
    pub max: Duration,
}

/// Current quality status of a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferQualityStatus {
    /// Transfer is performing well
    Healthy {
        /// Overall health score
        health_score: f64,
    },

    /// Transfer has degraded performance
    Degraded {
        /// Current health score
        health_score: f64,
        /// List of performance issues
        issues: Vec<String>,
    },

    /// Transfer is experiencing critical issues
    Critical {
        /// Current health score
        health_score: f64,
        /// Critical issues requiring attention
        critical_issues: Vec<String>,
    },
}

/// Timestamped metric data point.
#[derive(Debug, Clone)]
pub struct TimestampedMetric<T> {
    /// Timestamp when metric was recorded
    pub timestamp: Instant,

    /// Metric value
    pub value: T,

    /// Optional metadata
    pub metadata: Option<String>,
}

impl<T> TimestampedMetric<T> {
    pub fn new(value: T) -> Self {
        Self {
            timestamp: Instant::now(),
            value,
            metadata: None,
        }
    }

    pub fn with_metadata(value: T, metadata: String) -> Self {
        Self {
            timestamp: Instant::now(),
            value,
            metadata: Some(metadata),
        }
    }
}

impl QualityMetrics {
    /// Create a new quality metrics collector.
    pub fn new() -> Self {
        Self {
            transfer_metrics: HashMap::new(),
            peer_metrics: HashMap::new(),
            global_metrics: GlobalSwarmMetrics::default(),
            config: QualityConfig::default(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: QualityConfig) -> Self {
        Self {
            transfer_metrics: HashMap::new(),
            peer_metrics: HashMap::new(),
            global_metrics: GlobalSwarmMetrics::default(),
            config,
        }
    }

    /// Start tracking a new transfer.
    pub fn start_transfer_tracking(&mut self, transfer_id: MailboxTransferId) {
        let metrics = TransferQualityMetrics {
            transfer_id,
            started_at: Instant::now(),
            completed_at: None,
            download_rate_history: VecDeque::new(),
            upload_rate_history: VecDeque::new(),
            peer_response_times: HashMap::new(),
            verification_failures: VecDeque::new(),
            verification_attempt_count: 0,
            verification_failure_count: 0,
            health_scores: VecDeque::new(),
            current_status: TransferQualityStatus::Healthy { health_score: 1.0 },
        };

        self.transfer_metrics.insert(transfer_id, metrics);
        self.global_metrics.active_transfers += 1;
    }

    /// Complete transfer tracking.
    pub fn complete_transfer_tracking(&mut self, transfer_id: &MailboxTransferId) {
        if let Some(metrics) = self.transfer_metrics.get_mut(transfer_id) {
            metrics.completed_at = Some(Instant::now());
            if self.global_metrics.active_transfers > 0 {
                self.global_metrics.active_transfers -= 1;
            }
        }
    }

    /// Start tracking a new peer.
    pub fn start_peer_tracking(&mut self, peer_id: PeerId) {
        let metrics = PeerQualityMetrics {
            peer_id: peer_id.clone(),
            first_seen: Instant::now(),
            last_activity: Instant::now(),
            download_speeds: VecDeque::new(),
            upload_speeds: VecDeque::new(),
            response_times: VecDeque::new(),
            reliability_scores: VecDeque::new(),
            uptime_percentage: 100.0,
            total_bytes_transferred: 0,
            connection_quality: ConnectionQualityMetrics::default(),
        };

        self.peer_metrics.insert(peer_id, metrics);
        self.global_metrics.active_peers += 1;
    }

    /// Remove peer tracking.
    pub fn remove_peer_tracking(&mut self, peer_id: &PeerId) {
        self.peer_metrics.remove(peer_id);
        if self.global_metrics.active_peers > 0 {
            self.global_metrics.active_peers -= 1;
        }
    }

    /// Record download rate for a transfer.
    pub fn record_download_rate(&mut self, transfer_id: &MailboxTransferId, rate: f64) {
        let max_history_length = self.config.max_history_length;
        if let Some(metrics) = self.transfer_metrics.get_mut(transfer_id) {
            metrics
                .download_rate_history
                .push_back(TimestampedMetric::new(rate));
            Self::trim_history(&mut metrics.download_rate_history, max_history_length);
        }
    }

    /// Record upload rate for a transfer.
    pub fn record_upload_rate(&mut self, transfer_id: &MailboxTransferId, rate: f64) {
        let max_history_length = self.config.max_history_length;
        if let Some(metrics) = self.transfer_metrics.get_mut(transfer_id) {
            metrics
                .upload_rate_history
                .push_back(TimestampedMetric::new(rate));
            Self::trim_history(&mut metrics.upload_rate_history, max_history_length);
        }
    }

    /// Record peer response time.
    pub fn record_peer_response_time(
        &mut self,
        transfer_id: &MailboxTransferId,
        peer_id: &PeerId,
        response_time: Duration,
    ) {
        let max_history_length = self.config.max_history_length;
        if let Some(metrics) = self.transfer_metrics.get_mut(transfer_id) {
            let peer_times = metrics
                .peer_response_times
                .entry(peer_id.clone())
                .or_insert_with(VecDeque::new);

            peer_times.push_back(TimestampedMetric::new(response_time));
            Self::trim_history(peer_times, max_history_length);
        }

        // Also record in peer metrics
        if let Some(peer_metrics) = self.peer_metrics.get_mut(peer_id) {
            peer_metrics
                .response_times
                .push_back(TimestampedMetric::new(response_time));
            peer_metrics.last_activity = Instant::now();
            Self::trim_history(&mut peer_metrics.response_times, max_history_length);
        }
    }

    /// Record peer download speed.
    pub fn record_peer_download_speed(&mut self, peer_id: &PeerId, speed: f64) {
        let max_history_length = self.config.max_history_length;
        if let Some(metrics) = self.peer_metrics.get_mut(peer_id) {
            metrics
                .download_speeds
                .push_back(TimestampedMetric::new(speed));
            metrics.last_activity = Instant::now();
            Self::trim_history(&mut metrics.download_speeds, max_history_length);
        }
    }

    /// Record a successful verification attempt.
    pub fn record_verification_success(&mut self, transfer_id: &MailboxTransferId) {
        if let Some(metrics) = self.transfer_metrics.get_mut(transfer_id) {
            metrics.verification_attempt_count =
                metrics.verification_attempt_count.saturating_add(1);
            Self::record_current_verification_rate(metrics, self.config.max_history_length);
        }
    }

    /// Record verification failure.
    pub fn record_verification_failure(&mut self, transfer_id: &MailboxTransferId) {
        if let Some(metrics) = self.transfer_metrics.get_mut(transfer_id) {
            metrics.verification_attempt_count =
                metrics.verification_attempt_count.saturating_add(1);
            metrics.verification_failure_count =
                metrics.verification_failure_count.saturating_add(1);
            Self::record_current_verification_rate(metrics, self.config.max_history_length);
        }
    }

    /// Calculate and update swarm health score.
    pub fn update_swarm_health(&mut self) {
        let mut health_factors = Vec::new();

        // Factor 1: Average peer quality
        let avg_peer_quality = self.calculate_average_peer_quality();
        health_factors.push(avg_peer_quality);

        // Factor 2: Transfer success rate
        let transfer_success_rate = self.calculate_transfer_success_rate();
        health_factors.push(transfer_success_rate);

        // Factor 3: Network efficiency
        let network_efficiency = self.calculate_network_efficiency();
        health_factors.push(network_efficiency);

        // Factor 4: Resource utilization (inverse - lower is better)
        let resource_efficiency = 1.0
            - (self
                .global_metrics
                .resource_utilization
                .bandwidth_utilization
                / 100.0);
        health_factors.push(resource_efficiency.clamp(0.0, 1.0));

        // Calculate weighted average
        let weights = [0.3, 0.3, 0.2, 0.2]; // Adjust weights as needed
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (factor, weight) in health_factors.iter().zip(weights.iter()) {
            weighted_sum += factor * weight;
            total_weight += weight;
        }

        self.global_metrics.swarm_health_score = if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.5 // Default neutral score
        };
    }

    /// Get transfer quality status.
    pub fn get_transfer_status(
        &self,
        transfer_id: &MailboxTransferId,
    ) -> Option<&TransferQualityStatus> {
        self.transfer_metrics
            .get(transfer_id)
            .map(|m| &m.current_status)
    }

    /// Get peer quality summary.
    pub fn get_peer_quality_summary(&self, peer_id: &PeerId) -> Option<PeerQualitySummary> {
        self.peer_metrics.get(peer_id).map(|metrics| {
            let avg_download_speed = self.calculate_average_download_speed(metrics);
            let avg_response_time = self.calculate_average_response_time(metrics);
            let reliability_score = self.calculate_peer_reliability(metrics);

            PeerQualitySummary {
                peer_id: peer_id.clone(),
                avg_download_speed,
                avg_response_time,
                reliability_score,
                uptime_percentage: metrics.uptime_percentage,
                total_bytes_transferred: metrics.total_bytes_transferred,
            }
        })
    }

    /// Get global metrics snapshot.
    pub fn get_global_metrics(&self) -> &GlobalSwarmMetrics {
        &self.global_metrics
    }

    /// Trim history to maintain configured maximum length.
    fn trim_history<T>(history: &mut VecDeque<TimestampedMetric<T>>, max_history_length: usize) {
        while history.len() > max_history_length {
            history.pop_front();
        }
    }

    fn record_current_verification_rate(
        metrics: &mut TransferQualityMetrics,
        max_history_length: usize,
    ) {
        let failure_rate = if metrics.verification_attempt_count == 0 {
            0.0
        } else {
            metrics.verification_failure_count as f64 / metrics.verification_attempt_count as f64
        };

        metrics
            .verification_failures
            .push_back(TimestampedMetric::new(failure_rate.clamp(0.0, 1.0)));
        Self::trim_history(&mut metrics.verification_failures, max_history_length);
    }

    /// Calculate average peer quality across all peers.
    fn calculate_average_peer_quality(&self) -> f64 {
        if self.peer_metrics.is_empty() {
            return 0.5; // Neutral score
        }

        let total_quality: f64 = self
            .peer_metrics
            .values()
            .map(|metrics| self.calculate_peer_reliability(metrics))
            .sum();

        total_quality / self.peer_metrics.len() as f64
    }

    /// Calculate transfer success rate.
    fn calculate_transfer_success_rate(&self) -> f64 {
        let total_transfers = self.transfer_metrics.len();
        if total_transfers == 0 {
            return 0.5;
        }

        let aggregate_quality: f64 = self
            .transfer_metrics
            .values()
            .map(|metrics| {
                let status_score = match &metrics.current_status {
                    TransferQualityStatus::Healthy { health_score } => health_score.to_owned(),
                    TransferQualityStatus::Degraded { health_score, .. } => {
                        health_score.to_owned() * 0.75
                    }
                    TransferQualityStatus::Critical { health_score, .. } => {
                        health_score.to_owned() * 0.25
                    }
                };
                let completion_weight = if metrics.completed_at.is_some() {
                    1.0
                } else {
                    0.85
                };
                (status_score * completion_weight).clamp(0.0, 1.0)
            })
            .sum();

        aggregate_quality / total_transfers as f64
    }

    /// Calculate network efficiency.
    fn calculate_network_efficiency(&self) -> f64 {
        let efficiency = &self.global_metrics.network_efficiency;
        let observed = [
            efficiency.effective_bandwidth_ratio,
            efficiency.redundancy_efficiency,
            efficiency.peer_discovery_success_rate,
            efficiency.request_response_efficiency,
        ];

        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        let weights = [0.35, 0.25, 0.15, 0.25];

        for (value, weight) in observed.into_iter().zip(weights) {
            if value > 0.0 {
                weighted_sum += value.clamp(0.0, 1.0) * weight;
                total_weight += weight;
            }
        }

        if total_weight == 0.0 {
            0.5
        } else {
            (weighted_sum / total_weight).clamp(0.0, 1.0)
        }
    }

    /// Calculate average download speed for a peer.
    fn calculate_average_download_speed(&self, metrics: &PeerQualityMetrics) -> f64 {
        if metrics.download_speeds.is_empty() {
            return 0.0;
        }

        let total: f64 = metrics.download_speeds.iter().map(|m| m.value).sum();
        total / metrics.download_speeds.len() as f64
    }

    /// Calculate average response time for a peer.
    fn calculate_average_response_time(&self, metrics: &PeerQualityMetrics) -> Duration {
        if metrics.response_times.is_empty() {
            return Duration::from_secs(0);
        }

        let total_nanos: u128 = metrics
            .response_times
            .iter()
            .map(|m| m.value.as_nanos())
            .sum();

        Duration::from_nanos((total_nanos / metrics.response_times.len() as u128) as u64)
    }

    /// Calculate reliability score for a peer.
    fn calculate_peer_reliability(&self, metrics: &PeerQualityMetrics) -> f64 {
        if metrics.reliability_scores.is_empty() {
            let uptime_score = (metrics.uptime_percentage / 100.0).clamp(0.0, 1.0);
            let connection_uptime =
                (metrics.connection_quality.uptime_percentage / 100.0).clamp(0.0, 1.0);
            let loss_score = (1.0 - metrics.connection_quality.packet_loss_rate).clamp(0.0, 1.0);
            let reconnection_score = (1.0
                / (1.0 + f64::from(metrics.connection_quality.reconnection_count) * 0.25))
                .clamp(0.0, 1.0);
            let response_score = {
                let avg = self.calculate_average_response_time(metrics);
                if avg.is_zero() {
                    0.5
                } else {
                    (1.0 / (1.0 + avg.as_secs_f64())).clamp(0.0, 1.0)
                }
            };

            return (uptime_score * 0.25
                + connection_uptime * 0.20
                + loss_score * 0.25
                + reconnection_score * 0.15
                + response_score * 0.15)
                .clamp(0.0, 1.0);
        }

        let total: f64 = metrics.reliability_scores.iter().map(|m| m.value).sum();
        total / metrics.reliability_scores.len() as f64
    }
}

/// Summary of peer quality metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerQualitySummary {
    /// Peer identifier
    pub peer_id: PeerId,

    /// Average download speed
    pub avg_download_speed: f64,

    /// Average response time
    pub avg_response_time: Duration,

    /// Overall reliability score
    pub reliability_score: f64,

    /// Uptime percentage
    pub uptime_percentage: f64,

    /// Total bytes transferred
    pub total_bytes_transferred: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_metrics_creation() {
        let metrics = QualityMetrics::new();
        assert_eq!(metrics.transfer_metrics.len(), 0);
        assert_eq!(metrics.peer_metrics.len(), 0);
    }

    #[test]
    fn test_start_transfer_tracking() {
        let mut metrics = QualityMetrics::new();
        let transfer_id = MailboxTransferId::new();

        metrics.start_transfer_tracking(transfer_id);

        assert!(metrics.transfer_metrics.contains_key(&transfer_id));
        assert_eq!(metrics.global_metrics.active_transfers, 1);
    }

    #[test]
    fn test_start_peer_tracking() {
        let mut metrics = QualityMetrics::new();
        let peer_id = PeerId::new("test-peer");

        metrics.start_peer_tracking(peer_id.clone());

        assert!(metrics.peer_metrics.contains_key(&peer_id));
        assert_eq!(metrics.global_metrics.active_peers, 1);
    }

    #[test]
    fn test_record_metrics() {
        let mut metrics = QualityMetrics::new();
        let transfer_id = MailboxTransferId::new();
        let peer_id = PeerId::new("test-peer");

        metrics.start_transfer_tracking(transfer_id);
        metrics.start_peer_tracking(peer_id.clone());

        metrics.record_download_rate(&transfer_id, 1_000_000.0);
        metrics.record_peer_response_time(&transfer_id, &peer_id, Duration::from_millis(100));

        let transfer_metrics = metrics.transfer_metrics.get(&transfer_id).unwrap();
        assert_eq!(transfer_metrics.download_rate_history.len(), 1);
        assert_eq!(
            transfer_metrics
                .peer_response_times
                .get(&peer_id)
                .unwrap()
                .len(),
            1
        );

        let peer_metrics = metrics.peer_metrics.get(&peer_id).unwrap();
        assert_eq!(peer_metrics.response_times.len(), 1);
    }

    #[test]
    fn test_timestamped_metric() {
        let metric = TimestampedMetric::new(42.0);
        assert_eq!(metric.value, 42.0);
        assert!(metric.metadata.is_none());

        let metric_with_meta = TimestampedMetric::with_metadata(42.0, "test".to_string());
        assert_eq!(metric_with_meta.value, 42.0);
        assert_eq!(metric_with_meta.metadata, Some("test".to_string()));
    }
}
