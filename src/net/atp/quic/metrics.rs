//! ATP Transport Metrics Integration
//!
//! Exposes QUIC transport metrics to the ATP Transfer Brain for path selection,
//! congestion adaptation, and performance monitoring.

use crate::net::QuicTransportMachine;
use crate::observability::metrics::{Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// ATP transport metrics snapshot for Transfer Brain decision-making.
#[derive(Debug, Clone)]
pub struct AtpTransportMetrics {
    /// Connection identifier for correlation.
    pub connection_id: String,
    /// Path identifier for multi-path scenarios.
    pub path_id: String,
    /// Current smoothed RTT in microseconds.
    pub smoothed_rtt_micros: Option<u64>,
    /// Latest RTT sample in microseconds.
    pub latest_rtt_micros: Option<u64>,
    /// RTT variance in microseconds.
    pub rttvar_micros: Option<u64>,
    /// Current bytes in flight.
    pub bytes_in_flight: u64,
    /// Current congestion window in bytes.
    pub congestion_window_bytes: u64,
    /// Slow-start threshold in bytes.
    pub ssthresh_bytes: u64,
    /// Current PTO count (backoff level).
    pub pto_count: u32,
    /// Whether congestion window is currently limited.
    pub congestion_limited: bool,
    /// Anti-amplification state.
    pub anti_amplification_limited: bool,
    /// Total packets sent on this path.
    pub packets_sent: u64,
    /// Total packets lost on this path.
    pub packets_lost: u64,
    /// Total packets acknowledged on this path.
    pub packets_acked: u64,
    /// Current loss rate (0.0 - 1.0).
    pub loss_rate: f64,
    /// Path stability score (0.0 - 1.0, higher = more stable).
    pub path_stability: f64,
    /// Timestamp of last metric update.
    pub last_updated: Instant,
    /// Optional path doctor assessment.
    pub path_doctor_assessment: Option<PathDoctorAssessment>,
}

/// Path doctor assessment for transport troubleshooting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathDoctorAssessment {
    /// Overall path health score (0.0 - 1.0).
    pub health_score: f64,
    /// Detected issues with this path.
    pub detected_issues: Vec<PathIssue>,
    /// Recommended actions for path optimization.
    pub recommendations: Vec<PathRecommendation>,
    /// Performance classification.
    pub performance_class: PathPerformanceClass,
}

/// Detected path issues for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathIssue {
    /// High RTT variance indicating unstable path.
    HighRttVariance { variance_micros: u64 },
    /// High packet loss rate.
    HighPacketLoss { loss_rate: f64 },
    /// Persistent congestion detected.
    PersistentCongestion { duration_ms: u64 },
    /// Frequent PTO events indicating poor connectivity.
    FrequentTimeouts { pto_rate: f64 },
    /// Anti-amplification limiting throughput.
    AntiAmplificationLimited,
    /// Suspected middlebox interference.
    MiddleboxInterference,
    /// NAT rebinding detected.
    NatRebinding,
    /// Path MTU issues.
    MtuProblems { detected_mtu: u16 },
}

/// Path optimization recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathRecommendation {
    /// Switch to different path.
    SwitchPath { suggested_path_id: String },
    /// Reduce sending rate.
    ReduceSendingRate { factor: f64 },
    /// Enable path validation.
    EnablePathValidation,
    /// Perform MTU discovery.
    PerformMtuDiscovery,
    /// Consider relay usage.
    ConsiderRelay,
    /// Enable FEC/repair.
    EnableRepair { fec_rate: f64 },
}

/// Path performance classification for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathPerformanceClass {
    /// Excellent performance, preferred for large transfers.
    Excellent,
    /// Good performance, suitable for most transfers.
    Good,
    /// Fair performance, usable but not optimal.
    Fair,
    /// Poor performance, should be avoided.
    Poor,
    /// Unusable path, should be failed immediately.
    Unusable,
}

impl PathPerformanceClass {
    /// Get numeric score for path ranking (higher = better).
    #[must_use]
    pub const fn score(self) -> u8 {
        match self {
            Self::Excellent => 5,
            Self::Good => 4,
            Self::Fair => 3,
            Self::Poor => 2,
            Self::Unusable => 1,
        }
    }

    /// Determine performance class from metrics.
    #[must_use]
    pub fn from_metrics(metrics: &AtpTransportMetrics) -> Self {
        let rtt_score = metrics.smoothed_rtt_micros.map_or(0.0, |rtt| {
            match rtt {
                0..=50_000 => 1.0,        // <= 50ms: excellent
                50_001..=150_000 => 0.8,  // 50-150ms: good
                150_001..=300_000 => 0.6, // 150-300ms: fair
                300_001..=500_000 => 0.4, // 300-500ms: poor
                _ => 0.2,                 // >500ms: unusable
            }
        });

        let loss_score = 1.0 - metrics.loss_rate.min(1.0);

        let congestion_score = if metrics.congestion_limited { 0.6 } else { 1.0 };

        let stability_score = metrics.path_stability;

        let timeout_score = match metrics.pto_count {
            0 => 1.0,
            1 => 0.75,
            2 => 0.5,
            3 => 0.25,
            _ => 0.0,
        };

        let overall_score =
            (rtt_score + loss_score + congestion_score + stability_score + timeout_score) / 5.0;

        let mut class = match overall_score {
            s if s >= 0.9 => Self::Excellent,
            s if s >= 0.7 => Self::Good,
            s if s >= 0.5 => Self::Fair,
            s if s >= 0.3 => Self::Poor,
            _ => Self::Unusable,
        };

        if metrics.pto_count >= 4
            || metrics.loss_rate >= 0.5
            || matches!(metrics.smoothed_rtt_micros, Some(rtt) if rtt > 500_000)
        {
            return Self::Unusable;
        }

        if metrics.pto_count >= 3
            || metrics.loss_rate >= 0.2
            || matches!(metrics.smoothed_rtt_micros, Some(300_001..=500_000))
        {
            if class.score() > Self::Poor.score() {
                class = Self::Poor;
            }
        }

        if metrics.loss_rate >= 0.1 && class.score() > Self::Good.score() {
            class = Self::Good;
        }

        class
    }
}

/// ATP Transport Metrics Collector
///
/// Collects and exposes QUIC transport metrics for ATP Transfer Brain consumption.
pub struct AtpTransportMetricsCollector {
    /// Connection identifier.
    connection_id: String,
    /// Path identifier.
    path_id: String,
    /// Metrics counters.
    packets_sent: Counter,
    packets_lost: Counter,
    packets_acked: Counter,
    pto_events: Counter,
    /// Metrics gauges.
    bytes_in_flight: Gauge,
    congestion_window: Gauge,
    rtt_gauge: Gauge,
    /// Path stability tracker.
    stability_tracker: PathStabilityTracker,
    /// Anti-amplification limiter.
    anti_amplification: AntiAmplificationLimiter,
}

impl AtpTransportMetricsCollector {
    /// Create a new metrics collector.
    #[must_use]
    pub fn new(connection_id: String, path_id: String) -> Self {
        Self {
            packets_sent: Counter::new(format!("atp_quic_packets_sent_{}", connection_id)),
            packets_lost: Counter::new(format!("atp_quic_packets_lost_{}", connection_id)),
            packets_acked: Counter::new(format!("atp_quic_packets_acked_{}", connection_id)),
            pto_events: Counter::new(format!("atp_quic_pto_events_{}", connection_id)),
            bytes_in_flight: Gauge::new(format!("atp_quic_bytes_in_flight_{}", connection_id)),
            congestion_window: Gauge::new(format!("atp_quic_congestion_window_{}", connection_id)),
            rtt_gauge: Gauge::new(format!("atp_quic_rtt_micros_{}", connection_id)),
            connection_id,
            path_id,
            stability_tracker: PathStabilityTracker::new(),
            anti_amplification: AntiAmplificationLimiter::new(),
        }
    }

    /// Update metrics from transport machine state.
    pub fn update_from_transport(&mut self, transport: &QuicTransportMachine) {
        // Update basic metrics
        let rtt = transport.rtt();
        self.bytes_in_flight
            .set(transport.bytes_in_flight().cast_signed());
        self.congestion_window
            .set(transport.congestion_window_bytes().cast_signed());

        if let Some(smoothed_rtt) = rtt.smoothed_rtt_micros() {
            self.rtt_gauge.set(smoothed_rtt.cast_signed());
            self.stability_tracker.update_rtt(smoothed_rtt);
        }

        // Update stability based on recent metrics
        self.stability_tracker.update();
    }

    /// Record packet send event.
    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.packets_sent.increment();
        self.anti_amplification.on_packet_sent(bytes);
    }

    /// Record inbound peer bytes that credit the anti-amplification budget.
    pub fn on_datagram_received(&mut self, bytes: u64) {
        self.anti_amplification.on_datagram_received(bytes);
    }

    /// Record packet acknowledgment.
    pub fn on_packet_acked(&mut self, bytes: u64) {
        self.packets_acked.increment();
        self.anti_amplification.on_ack_received(bytes);
    }

    /// Record packet loss.
    pub fn on_packet_lost(&mut self, _bytes: u64) {
        self.packets_lost.increment();
        self.stability_tracker.on_packet_lost();
    }

    /// Record PTO event.
    pub fn on_pto_expired(&mut self) {
        self.pto_events.increment();
        self.stability_tracker.on_pto_event();
    }

    /// Check if anti-amplification is limiting sends.
    #[must_use]
    pub fn is_anti_amplification_limited(&self) -> bool {
        self.anti_amplification.is_limited()
    }

    /// Get current transport metrics snapshot.
    #[must_use]
    pub fn current_metrics(&self, transport: &QuicTransportMachine) -> AtpTransportMetrics {
        let rtt = transport.rtt();
        let packets_sent = self.packets_sent.get();
        let packets_lost = self.packets_lost.get();
        let packets_acked = self.packets_acked.get();

        let loss_rate = if packets_sent > 0 {
            packets_lost as f64 / packets_sent as f64
        } else {
            0.0
        };

        let mut metrics = AtpTransportMetrics {
            connection_id: self.connection_id.clone(),
            path_id: self.path_id.clone(),
            smoothed_rtt_micros: rtt.smoothed_rtt_micros(),
            latest_rtt_micros: rtt.latest_rtt_micros(),
            rttvar_micros: rtt.rttvar_micros(),
            bytes_in_flight: transport.bytes_in_flight(),
            congestion_window_bytes: transport.congestion_window_bytes(),
            ssthresh_bytes: transport.ssthresh_bytes(),
            pto_count: transport.pto_count(),
            congestion_limited: !transport.can_send(1200), // Typical packet size
            anti_amplification_limited: self.is_anti_amplification_limited(),
            packets_sent,
            packets_lost,
            packets_acked,
            loss_rate,
            path_stability: self.stability_tracker.stability_score(),
            last_updated: Instant::now(),
            path_doctor_assessment: None,
        };
        metrics.path_doctor_assessment = Some(self.assess_path_health(&metrics));

        metrics
    }

    /// Assess path health and generate doctor report.
    fn assess_path_health(&self, metrics: &AtpTransportMetrics) -> PathDoctorAssessment {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();
        let mut recommended_rate_reduction = false;

        // Check RTT variance
        if let (Some(rtt), Some(rttvar)) = (metrics.smoothed_rtt_micros, metrics.rttvar_micros) {
            let variance_ratio = rttvar as f64 / rtt as f64;
            if variance_ratio > 0.5 {
                issues.push(PathIssue::HighRttVariance {
                    variance_micros: rttvar,
                });
                recommendations.push(PathRecommendation::EnablePathValidation);
            }
        }

        // Check loss rate
        if metrics.loss_rate > 0.05 {
            issues.push(PathIssue::HighPacketLoss {
                loss_rate: metrics.loss_rate,
            });
            if metrics.loss_rate > 0.1 {
                recommendations.push(PathRecommendation::EnableRepair { fec_rate: 0.2 });
            }
        }

        // Check PTO backoff. A rising transport PTO count is actionable even
        // when the collector has not yet accumulated enough RTT samples.
        let pto_pressure = self.pto_pressure(metrics.pto_count);
        if metrics.pto_count >= 2 || pto_pressure >= 0.25 {
            issues.push(PathIssue::FrequentTimeouts {
                pto_rate: pto_pressure,
            });
            let factor = if metrics.pto_count >= 4 || pto_pressure >= 0.75 {
                0.5
            } else {
                0.7
            };
            recommendations.push(PathRecommendation::ReduceSendingRate { factor });
            recommended_rate_reduction = true;
            recommendations.push(PathRecommendation::EnablePathValidation);
            if metrics.pto_count >= 3 || pto_pressure >= 0.75 {
                recommendations.push(PathRecommendation::ConsiderRelay);
            }
        }

        // Check congestion
        if metrics.congestion_limited && !recommended_rate_reduction {
            recommendations.push(PathRecommendation::ReduceSendingRate { factor: 0.8 });
        }

        // Check anti-amplification
        if metrics.anti_amplification_limited {
            issues.push(PathIssue::AntiAmplificationLimited);
            recommendations.push(PathRecommendation::EnablePathValidation);
        }

        let performance_class = PathPerformanceClass::from_metrics(metrics);
        let health_score = match performance_class {
            PathPerformanceClass::Excellent => 0.95,
            PathPerformanceClass::Good => 0.80,
            PathPerformanceClass::Fair => 0.60,
            PathPerformanceClass::Poor => 0.40,
            PathPerformanceClass::Unusable => 0.20,
        };

        PathDoctorAssessment {
            health_score,
            detected_issues: issues,
            recommendations,
            performance_class,
        }
    }

    fn pto_pressure(&self, pto_count: u32) -> f64 {
        let event_pressure = self.stability_tracker.pto_rate();
        let backoff_pressure = match pto_count {
            0 => 0.0,
            1 => 0.25,
            2 => 0.5,
            3 => 0.75,
            _ => 1.0,
        };
        event_pressure.max(backoff_pressure)
    }
}

/// Tracks path stability over time.
#[derive(Debug)]
struct PathStabilityTracker {
    rtt_samples: Vec<u64>,
    loss_events: u32,
    pto_events: u32,
    sample_count: u32,
    last_update: Instant,
}

impl PathStabilityTracker {
    fn new() -> Self {
        Self {
            rtt_samples: Vec::with_capacity(100),
            loss_events: 0,
            pto_events: 0,
            sample_count: 0,
            last_update: Instant::now(),
        }
    }

    fn update_rtt(&mut self, rtt_micros: u64) {
        self.rtt_samples.push(rtt_micros);
        if self.rtt_samples.len() > 100 {
            self.rtt_samples.remove(0);
        }
        self.sample_count += 1;
    }

    fn on_packet_lost(&mut self) {
        self.loss_events += 1;
    }

    fn on_pto_event(&mut self) {
        self.pto_events += 1;
    }

    fn update(&mut self) {
        self.last_update = Instant::now();
    }

    fn pto_rate(&self) -> f64 {
        let denominator = self.sample_count.max(self.pto_events).max(1);
        (self.pto_events as f64 / denominator as f64).min(1.0)
    }

    fn stability_score(&self) -> f64 {
        if self.sample_count == 0 {
            return 0.5; // Neutral score with no data
        }

        // Calculate RTT stability (lower variance = higher stability)
        let rtt_stability = if self.rtt_samples.len() >= 2 {
            let mean = self.rtt_samples.iter().sum::<u64>() as f64 / self.rtt_samples.len() as f64;
            let variance = self
                .rtt_samples
                .iter()
                .map(|&x| {
                    let diff = x as f64 - mean;
                    diff * diff
                })
                .sum::<f64>()
                / self.rtt_samples.len() as f64;
            let coefficient_of_variation = variance.sqrt() / mean;
            (1.0 - coefficient_of_variation.min(1.0)).max(0.0)
        } else {
            1.0
        };

        // Calculate loss stability (fewer losses = higher stability)
        let loss_stability = if self.sample_count > 0 {
            let loss_rate = self.loss_events as f64 / self.sample_count as f64;
            (1.0 - loss_rate.min(1.0)).max(0.0)
        } else {
            1.0
        };

        // Calculate timeout stability (fewer PTOs = higher stability)
        let pto_stability = (1.0 - self.pto_rate()).max(0.0);

        // Weighted average
        (rtt_stability * 0.5 + loss_stability * 0.3 + pto_stability * 0.2).clamp(0.0, 1.0)
    }
}

/// Anti-amplification limiter per RFC 9000.
#[derive(Debug)]
struct AntiAmplificationLimiter {
    bytes_sent: u64,
    bytes_received: u64,
    address_validated: bool,
    last_reset: Instant,
}

impl AntiAmplificationLimiter {
    fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            address_validated: false,
            last_reset: Instant::now(),
        }
    }

    fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.maybe_reset();
    }

    fn on_datagram_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.maybe_reset();
    }

    fn on_ack_received(&mut self, _bytes: u64) {
        // Receiving an ACK validates the peer address and lifts the
        // anti-amplification limiter for this path.
        self.address_validated = true;
        self.maybe_reset();
    }

    fn is_limited(&self) -> bool {
        if self.address_validated {
            return false;
        }

        // RFC 9000: server MUST NOT send more than 3x received bytes
        self.bytes_sent > self.bytes_received.saturating_mul(3)
    }

    fn maybe_reset(&mut self) {
        // Reset counters periodically to avoid overflow
        if self.last_reset.elapsed() > Duration::from_secs(60) {
            self.bytes_sent = 0;
            self.bytes_received = 0;
            self.last_reset = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::quic_native::QuicTransportMachine;

    #[test]
    fn path_performance_classification() {
        let mut metrics = AtpTransportMetrics {
            connection_id: "test".to_string(),
            path_id: "path1".to_string(),
            smoothed_rtt_micros: Some(30_000), // 30ms
            latest_rtt_micros: Some(32_000),
            rttvar_micros: Some(5_000),
            bytes_in_flight: 1200,
            congestion_window_bytes: 12_000,
            ssthresh_bytes: 24_000,
            pto_count: 0,
            congestion_limited: false,
            anti_amplification_limited: false,
            packets_sent: 100,
            packets_lost: 1,
            packets_acked: 99,
            loss_rate: 0.01,
            path_stability: 0.95,
            last_updated: Instant::now(),
            path_doctor_assessment: None,
        };

        // Should be excellent with low RTT, low loss, no congestion, high stability
        assert_eq!(
            PathPerformanceClass::from_metrics(&metrics),
            PathPerformanceClass::Excellent
        );

        // Higher loss should degrade performance
        metrics.loss_rate = 0.1;
        assert_eq!(
            PathPerformanceClass::from_metrics(&metrics),
            PathPerformanceClass::Good
        );

        // High RTT should further degrade
        metrics.smoothed_rtt_micros = Some(400_000); // 400ms
        assert_eq!(
            PathPerformanceClass::from_metrics(&metrics),
            PathPerformanceClass::Poor
        );
    }

    #[test]
    fn anti_amplification_limits() {
        let mut limiter = AntiAmplificationLimiter::new();

        // No peer bytes received yet, so sending any bytes exceeds the budget.
        limiter.on_packet_sent(1000);
        assert!(limiter.is_limited());

        // Receive 400 bytes from the peer: the server may send up to 1200 bytes.
        limiter.on_datagram_received(400);
        assert!(!limiter.is_limited());

        // Sending beyond the 3x received budget is limited.
        limiter.on_packet_sent(201);
        assert!(limiter.is_limited());

        // Receiving an ACK validates the address and lifts the limiter.
        limiter.on_ack_received(0);
        assert!(!limiter.is_limited());
    }

    #[test]
    fn path_stability_tracking() {
        let mut tracker = PathStabilityTracker::new();

        // Add consistent RTT samples
        for _ in 0..10 {
            tracker.update_rtt(50_000); // Consistent 50ms
        }

        let stable_score = tracker.stability_score();
        assert!(
            stable_score > 0.9,
            "Consistent RTT should give high stability"
        );

        // Add variable RTT samples
        for rtt in [25_000, 75_000, 40_000, 90_000, 30_000] {
            tracker.update_rtt(rtt);
        }

        let variable_score = tracker.stability_score();
        assert!(
            variable_score < stable_score,
            "Variable RTT should reduce stability"
        );

        // Add loss events
        tracker.on_packet_lost();
        tracker.on_packet_lost();

        let loss_score = tracker.stability_score();
        assert!(
            loss_score < variable_score,
            "Packet loss should further reduce stability"
        );
    }

    #[test]
    fn metrics_collector_integration() {
        let mut collector =
            AtpTransportMetricsCollector::new("conn123".to_string(), "path456".to_string());

        let mut transport = QuicTransportMachine::new();

        // Send some packets
        collector.on_packet_sent(1200);
        collector.on_packet_sent(1200);

        // Ack one packet
        collector.on_packet_acked(1200);

        // Lose one packet
        collector.on_packet_lost(1200);

        // Record PTO backoff in both the transport machine and collector.
        transport.on_pto_expired();
        transport.on_pto_expired();
        collector.on_pto_expired();
        collector.on_pto_expired();

        let metrics = collector.current_metrics(&transport);

        assert_eq!(metrics.packets_sent, 2);
        assert_eq!(metrics.packets_acked, 1);
        assert_eq!(metrics.packets_lost, 1);
        assert_eq!(metrics.pto_count, 2);
        assert_eq!(metrics.loss_rate, 0.5);
        assert_eq!(metrics.connection_id, "conn123");
        assert_eq!(metrics.path_id, "path456");
    }
}
