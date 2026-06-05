//! Persistent Congestion Detection
//!
//! Implements RFC 9002 persistent congestion detection with ATP enhancements.

use crate::net::quic_native::{RttEstimator, SentPacketMeta};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Persistent congestion detector per RFC 9002.
pub struct PersistentCongestionDetector {
    /// Configuration parameters.
    config: PersistentCongestionConfig,
    /// Recent congestion events.
    congestion_events: VecDeque<CongestionEvent>,
    /// Current congestion epoch.
    current_epoch: Option<CongestionEpoch>,
    /// Detection metrics.
    metrics: PersistentCongestionMetrics,
}

/// Configuration for persistent congestion detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentCongestionConfig {
    /// Persistent congestion threshold multiplier (default: 3.0).
    pub threshold_multiplier: f64,
    /// Minimum persistent congestion duration (microseconds).
    pub min_duration_micros: u64,
    /// Maximum tracking window (microseconds).
    pub tracking_window_micros: u64,
    /// Enable adaptive threshold based on network conditions.
    pub adaptive_threshold: bool,
    /// Congestion event correlation window.
    pub correlation_window_micros: u64,
}

impl Default for PersistentCongestionConfig {
    fn default() -> Self {
        Self {
            threshold_multiplier: 3.0,
            min_duration_micros: 100_000,       // 100ms
            tracking_window_micros: 10_000_000, // 10s
            adaptive_threshold: true,
            correlation_window_micros: 1_000_000, // 1s
        }
    }
}

/// A congestion event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionEvent {
    /// Event timestamp.
    #[serde(skip, default = "Instant::now")]
    timestamp: Instant,
    /// Event type.
    event_type: CongestionEventType,
    /// Network conditions at event time.
    conditions: NetworkConditions,
    /// Duration of the event.
    duration_micros: u64,
}

/// Types of congestion events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum CongestionEventType {
    /// Multiple consecutive packet losses.
    PacketLossBurst,
    /// RTT spike indicating queueing.
    RttSpike,
    /// PTO events in quick succession.
    PtoCluster,
    /// Congestion window reduction.
    CwndReduction,
}

/// Network conditions snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConditions {
    /// RTT at event time.
    rtt_micros: Option<u64>,
    /// RTT variance.
    rttvar_micros: Option<u64>,
    /// Loss rate.
    loss_rate: f64,
    /// Bytes in flight.
    bytes_in_flight: u64,
    /// Congestion window size.
    congestion_window: u64,
}

/// A congestion epoch (period of sustained congestion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionEpoch {
    /// Epoch start time.
    #[serde(skip, default = "Instant::now")]
    start_time: Instant,
    /// Associated events.
    events: Vec<CongestionEvent>,
    /// Peak congestion severity (0.0 - 1.0).
    peak_severity: f64,
    /// Whether epoch is still active.
    is_active: bool,
}

/// Persistent congestion detection metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentCongestionMetrics {
    /// Total persistent congestion episodes.
    pub total_episodes: u64,
    /// Total duration of persistent congestion (microseconds).
    pub total_duration_micros: u64,
    /// Average episode duration (microseconds).
    pub avg_episode_duration_micros: f64,
    /// Peak congestion severity observed.
    pub peak_severity: f64,
    /// False positive rate (episodes that resolved quickly).
    pub false_positive_rate: f64,
    /// Current congestion level (0.0 - 1.0).
    pub current_congestion_level: f64,
}

impl Default for PersistentCongestionMetrics {
    fn default() -> Self {
        Self {
            total_episodes: 0,
            total_duration_micros: 0,
            avg_episode_duration_micros: 0.0,
            peak_severity: 0.0,
            false_positive_rate: 0.0,
            current_congestion_level: 0.0,
        }
    }
}

/// Result of persistent congestion detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentCongestionResult {
    /// Whether persistent congestion is detected.
    pub is_persistent_congestion: bool,
    /// Congestion severity (0.0 - 1.0).
    pub severity: f64,
    /// Duration of current congestion (microseconds).
    pub duration_micros: u64,
    /// Recommended actions.
    pub recommendations: Vec<CongestionRecommendation>,
    /// Confidence in detection (0.0 - 1.0).
    pub confidence: f64,
}

/// Recommendations for handling persistent congestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CongestionRecommendation {
    /// Reset congestion window to minimum.
    ResetCongestionWindow,
    /// Reduce sending rate aggressively.
    ReduceSendingRate { factor: f64 },
    /// Enable pacing to smooth traffic.
    EnablePacing { rate: u64 },
    /// Switch to different congestion control algorithm.
    SwitchAlgorithm { algorithm: String },
    /// Increase probe frequency.
    IncreaseProbing,
    /// Consider path switching.
    ConsiderPathSwitch,
    /// Enable Forward Error Correction.
    EnableFec { rate: f64 },
}

impl PersistentCongestionDetector {
    /// Create a new persistent congestion detector.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PersistentCongestionConfig::default())
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: PersistentCongestionConfig) -> Self {
        Self {
            config,
            congestion_events: VecDeque::new(),
            current_epoch: None,
            metrics: PersistentCongestionMetrics::default(),
        }
    }

    /// Check for persistent congestion after loss detection.
    pub fn check_persistent_congestion(
        &mut self,
        lost_packets: &[SentPacketMeta],
        rtt: &RttEstimator,
        bytes_in_flight: u64,
        congestion_window: u64,
        now: Instant,
    ) -> PersistentCongestionResult {
        if lost_packets.is_empty() {
            return self.no_congestion_result();
        }

        // Calculate persistent congestion threshold per RFC 9002
        let threshold_duration = self.calculate_threshold_duration(rtt);

        // Check if the lost packets span the persistent congestion period
        let earliest_lost = lost_packets
            .iter()
            .min_by_key(|p| p.time_sent_micros)
            .unwrap();
        let latest_lost = lost_packets
            .iter()
            .max_by_key(|p| p.time_sent_micros)
            .unwrap();

        let loss_span_micros = latest_lost
            .time_sent_micros
            .saturating_sub(earliest_lost.time_sent_micros);

        // Record congestion event
        let loss_rate = self.estimate_loss_rate(lost_packets, bytes_in_flight);
        let conditions = NetworkConditions {
            rtt_micros: rtt.smoothed_rtt_micros(),
            rttvar_micros: rtt.rttvar_micros(),
            loss_rate,
            bytes_in_flight,
            congestion_window,
        };

        self.record_congestion_event(
            CongestionEventType::PacketLossBurst,
            conditions.clone(),
            now,
        );

        // Check for persistent congestion
        let is_persistent = loss_span_micros >= threshold_duration;
        let severity =
            self.calculate_congestion_severity(&conditions, loss_span_micros, threshold_duration);

        if is_persistent {
            self.start_or_extend_epoch(severity, now);
        } else {
            self.end_current_epoch(now);
        }

        // Generate recommendations
        let recommendations = self.generate_recommendations(severity, is_persistent, &conditions);

        // Calculate confidence
        let confidence =
            self.calculate_detection_confidence(severity, loss_span_micros, threshold_duration);

        PersistentCongestionResult {
            is_persistent_congestion: is_persistent,
            severity,
            duration_micros: loss_span_micros,
            recommendations,
            confidence,
        }
    }

    /// Record RTT spike event.
    pub fn on_rtt_spike(&mut self, old_rtt: u64, new_rtt: u64, conditions: NetworkConditions) {
        if old_rtt == 0 || new_rtt <= old_rtt {
            return;
        }

        let spike_ratio = new_rtt as f64 / old_rtt as f64;
        if spike_ratio > 2.0 {
            // Significant RTT increase
            self.record_congestion_event(CongestionEventType::RttSpike, conditions, Instant::now());
        }
    }

    /// Record PTO event.
    pub fn on_pto_event(&mut self, conditions: NetworkConditions) {
        self.record_congestion_event(CongestionEventType::PtoCluster, conditions, Instant::now());
    }

    /// Record congestion window reduction.
    pub fn on_cwnd_reduction(
        &mut self,
        old_cwnd: u64,
        new_cwnd: u64,
        conditions: NetworkConditions,
    ) {
        if old_cwnd == 0 || new_cwnd >= old_cwnd {
            return;
        }

        let reduction_ratio = (old_cwnd - new_cwnd) as f64 / old_cwnd as f64;
        if reduction_ratio > 0.1 {
            // Significant reduction
            self.record_congestion_event(
                CongestionEventType::CwndReduction,
                conditions,
                Instant::now(),
            );
        }
    }

    /// Get current metrics.
    #[must_use]
    pub fn metrics(&self) -> &PersistentCongestionMetrics {
        &self.metrics
    }

    /// Export congestion analysis.
    #[must_use]
    pub fn export_analysis(&self) -> CongestionAnalysisExport {
        CongestionAnalysisExport {
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            recent_events: self.congestion_events.iter().cloned().collect(),
            current_epoch: self.current_epoch.clone(),
        }
    }

    // Private helper methods

    fn calculate_threshold_duration(&self, rtt: &RttEstimator) -> u64 {
        let base_rtt = rtt
            .smoothed_rtt_micros()
            .filter(|&rtt_micros| rtt_micros > 0)
            .unwrap_or(333_000); // 333ms default

        let threshold = if self.config.adaptive_threshold {
            // Adaptive threshold based on RTT variance
            let rttvar = rtt.rttvar_micros().unwrap_or(base_rtt / 4);
            let adaptive_multiplier =
                self.config.threshold_multiplier + (rttvar as f64 / base_rtt as f64);
            (base_rtt as f64 * adaptive_multiplier) as u64
        } else {
            (base_rtt as f64 * self.config.threshold_multiplier) as u64
        };

        threshold.max(self.config.min_duration_micros)
    }

    fn estimate_loss_rate(&self, lost_packets: &[SentPacketMeta], bytes_in_flight: u64) -> f64 {
        if bytes_in_flight == 0 {
            return 0.0;
        }

        let lost_bytes = lost_packets
            .iter()
            .fold(0_u64, |total, packet| total.saturating_add(packet.bytes));
        (lost_bytes as f64 / bytes_in_flight as f64).min(1.0)
    }

    fn calculate_congestion_severity(
        &self,
        conditions: &NetworkConditions,
        duration_micros: u64,
        threshold_micros: u64,
    ) -> f64 {
        let duration_factor = (duration_micros as f64 / threshold_micros as f64).min(2.0) / 2.0;
        let loss_factor = conditions.loss_rate.min(1.0);

        let rtt_factor = if let Some(rtt) = conditions.rtt_micros {
            // Higher RTT indicates more congestion
            (rtt as f64 / 500_000.0).min(1.0) // Normalize against 500ms
        } else {
            0.5
        };

        let utilization_factor = if conditions.congestion_window > 0 {
            (conditions.bytes_in_flight as f64 / conditions.congestion_window as f64).min(1.0)
        } else {
            0.0
        };

        // Weighted combination
        (duration_factor * 0.3 + loss_factor * 0.4 + rtt_factor * 0.2 + utilization_factor * 0.1)
            .clamp(0.0, 1.0)
    }

    fn record_congestion_event(
        &mut self,
        event_type: CongestionEventType,
        conditions: NetworkConditions,
        now: Instant,
    ) {
        let event = CongestionEvent {
            timestamp: now,
            event_type,
            conditions,
            duration_micros: 0, // Will be calculated later
        };

        self.congestion_events.push_back(event);

        // Limit memory usage
        while self.congestion_events.len() > 1000 {
            self.congestion_events.pop_front();
        }

        // Clean up old events outside tracking window
        if let Some(cutoff) =
            now.checked_sub(Duration::from_micros(self.config.tracking_window_micros))
        {
            self.congestion_events.retain(|e| e.timestamp >= cutoff);
        }
    }

    fn start_or_extend_epoch(&mut self, severity: f64, now: Instant) {
        match &mut self.current_epoch {
            Some(epoch) => {
                // Extend current epoch
                epoch.peak_severity = epoch.peak_severity.max(severity);
            }
            None => {
                // Start new epoch
                self.current_epoch = Some(CongestionEpoch {
                    start_time: now,
                    events: Vec::new(),
                    peak_severity: severity,
                    is_active: true,
                });
                self.metrics.total_episodes += 1;
            }
        }
    }

    fn end_current_epoch(&mut self, now: Instant) {
        if let Some(mut epoch) = self.current_epoch.take() {
            epoch.is_active = false;
            let duration_micros = now
                .checked_duration_since(epoch.start_time)
                .map_or(0, duration_as_micros_saturating);

            self.metrics.total_duration_micros = self
                .metrics
                .total_duration_micros
                .saturating_add(duration_micros);
            self.metrics.avg_episode_duration_micros =
                self.metrics.total_duration_micros as f64 / self.metrics.total_episodes as f64;
            self.metrics.peak_severity = self.metrics.peak_severity.max(epoch.peak_severity);

            // Check for false positives (very short episodes)
            if duration_micros < self.config.min_duration_micros / 2 {
                self.metrics.false_positive_rate = (self.metrics.false_positive_rate
                    * (self.metrics.total_episodes - 1) as f64
                    + 1.0)
                    / self.metrics.total_episodes as f64;
            }
        }
    }

    fn generate_recommendations(
        &self,
        severity: f64,
        is_persistent: bool,
        conditions: &NetworkConditions,
    ) -> Vec<CongestionRecommendation> {
        let mut recommendations = Vec::new();

        if is_persistent {
            // Persistent congestion detected
            if severity > 0.8 {
                recommendations.push(CongestionRecommendation::ResetCongestionWindow);
                recommendations.push(CongestionRecommendation::ReduceSendingRate { factor: 0.25 });
            } else if severity > 0.5 {
                recommendations.push(CongestionRecommendation::ReduceSendingRate { factor: 0.5 });
                recommendations.push(CongestionRecommendation::EnablePacing { rate: 100_000 });
            } else {
                recommendations.push(CongestionRecommendation::ReduceSendingRate { factor: 0.75 });
            }

            // Algorithm-specific recommendations
            if conditions.loss_rate > 0.1 {
                recommendations.push(CongestionRecommendation::SwitchAlgorithm {
                    algorithm: "bbr".to_string(),
                });
                recommendations.push(CongestionRecommendation::EnableFec { rate: 0.1 });
            }

            // Network-specific recommendations
            if let Some(rtt) = conditions.rtt_micros {
                if rtt > 500_000 {
                    // High latency network
                    recommendations.push(CongestionRecommendation::ConsiderPathSwitch);
                }
            }
        } else {
            // Mild congestion
            if severity > 0.3 {
                recommendations.push(CongestionRecommendation::EnablePacing {
                    rate: conditions.congestion_window / 10,
                });
            }
        }

        recommendations
    }

    fn calculate_detection_confidence(&self, severity: f64, duration: u64, threshold: u64) -> f64 {
        let doubled_threshold = threshold.saturating_mul(2);
        let duration_confidence = if duration >= doubled_threshold {
            1.0
        } else if duration >= threshold {
            0.8
        } else {
            0.5
        };

        let severity_confidence = severity;

        let history_confidence = if self.metrics.total_episodes > 0 {
            1.0 - self.metrics.false_positive_rate
        } else {
            0.5
        };

        (duration_confidence + severity_confidence + history_confidence) / 3.0
    }

    fn no_congestion_result(&mut self) -> PersistentCongestionResult {
        self.end_current_epoch(Instant::now());
        self.metrics.current_congestion_level = 0.0;

        PersistentCongestionResult {
            is_persistent_congestion: false,
            severity: 0.0,
            duration_micros: 0,
            recommendations: Vec::new(),
            confidence: 1.0,
        }
    }
}

impl Default for PersistentCongestionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Export data for congestion analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionAnalysisExport {
    /// Current configuration.
    pub config: PersistentCongestionConfig,
    /// Detection metrics.
    pub metrics: PersistentCongestionMetrics,
    /// Recent congestion events.
    pub recent_events: Vec<CongestionEvent>,
    /// Current congestion epoch.
    pub current_epoch: Option<CongestionEpoch>,
}

fn duration_as_micros_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::quic_native::{PacketNumberSpace, RttEstimator, SentPacketMeta};

    fn create_test_packet(pn: u64, time_micros: u64) -> SentPacketMeta {
        SentPacketMeta {
            space: PacketNumberSpace::ApplicationData,
            packet_number: pn,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: time_micros,
        }
    }

    fn test_conditions() -> NetworkConditions {
        NetworkConditions {
            rtt_micros: Some(100_000),
            rttvar_micros: Some(25_000),
            loss_rate: 0.0,
            bytes_in_flight: 6000,
            congestion_window: 12_000,
        }
    }

    #[test]
    fn persistent_congestion_detection_basic() {
        let mut detector = PersistentCongestionDetector::new();
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms RTT

        // Create lost packets spanning enough time for persistent congestion
        let lost_packets = vec![
            create_test_packet(0, 0),
            create_test_packet(1, 50_000),
            create_test_packet(2, 400_000), // 400ms span > 3 * 100ms threshold
        ];

        let result = detector.check_persistent_congestion(
            &lost_packets,
            &rtt,
            3600,  // bytes in flight
            12000, // congestion window
            Instant::now(),
        );

        assert!(result.is_persistent_congestion);
        assert!(result.severity > 0.0);
        assert!(!result.recommendations.is_empty());
    }

    #[test]
    fn persistent_congestion_not_detected() {
        let mut detector = PersistentCongestionDetector::new();
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms RTT

        // Create lost packets with short span
        let lost_packets = vec![
            create_test_packet(0, 0),
            create_test_packet(1, 50_000), // Only 50ms span < 3 * 100ms threshold
        ];

        let result = detector.check_persistent_congestion(
            &lost_packets,
            &rtt,
            2400,  // bytes in flight
            12000, // congestion window
            Instant::now(),
        );

        assert!(!result.is_persistent_congestion);
        assert!(result.severity < 0.5);
    }

    #[test]
    fn congestion_severity_calculation() {
        let detector = PersistentCongestionDetector::new();

        let conditions = NetworkConditions {
            rtt_micros: Some(200_000), // 200ms
            rttvar_micros: Some(50_000),
            loss_rate: 0.1,
            bytes_in_flight: 6000,
            congestion_window: 12000,
        };

        let severity = detector.calculate_congestion_severity(
            &conditions,
            600_000, // 600ms duration
            300_000, // 300ms threshold
        );

        assert!(
            severity > 0.3,
            "Severity should be significant: {}",
            severity
        );
        assert!(severity < 1.0, "Severity should be bounded: {}", severity);
    }

    #[test]
    fn epoch_management() {
        let mut detector = PersistentCongestionDetector::new();
        let now = Instant::now();

        // Start epoch
        detector.start_or_extend_epoch(0.6, now);
        assert!(detector.current_epoch.is_some());
        assert_eq!(detector.metrics.total_episodes, 1);

        // Extend epoch
        detector.start_or_extend_epoch(0.8, now);
        assert!(detector.current_epoch.is_some());
        assert_eq!(detector.metrics.total_episodes, 1); // Should not increment

        // End epoch
        detector.end_current_epoch(now + Duration::from_millis(100));
        assert!(detector.current_epoch.is_none());
        assert!(detector.metrics.total_duration_micros > 0);
    }

    #[test]
    fn adaptive_threshold_calculation() {
        let detector = PersistentCongestionDetector::with_config(PersistentCongestionConfig {
            adaptive_threshold: true,
            ..Default::default()
        });

        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms base RTT
        rtt.update(150_000, 0); // Variable RTT to create variance

        let threshold = detector.calculate_threshold_duration(&rtt);
        let base_threshold = 100_000.0 * 3.0; // Base threshold

        // Adaptive threshold should be different from base
        assert_ne!(threshold as f64, base_threshold);
        assert!(threshold >= detector.config.min_duration_micros);
    }

    #[test]
    fn rtt_spike_requires_positive_increasing_baseline() {
        let mut detector = PersistentCongestionDetector::new();

        detector.on_rtt_spike(0, 100_000, test_conditions());
        detector.on_rtt_spike(100_000, 100_000, test_conditions());
        detector.on_rtt_spike(100_000, 90_000, test_conditions());

        assert!(detector.congestion_events.is_empty());

        detector.on_rtt_spike(100_000, 250_000, test_conditions());
        assert_eq!(detector.congestion_events.len(), 1);
    }

    #[test]
    fn cwnd_reduction_requires_positive_decrease() {
        let mut detector = PersistentCongestionDetector::new();

        detector.on_cwnd_reduction(0, 0, test_conditions());
        detector.on_cwnd_reduction(10_000, 10_000, test_conditions());
        detector.on_cwnd_reduction(10_000, 12_000, test_conditions());
        detector.on_cwnd_reduction(10_000, 9_500, test_conditions());

        assert!(detector.congestion_events.is_empty());

        detector.on_cwnd_reduction(10_000, 8_000, test_conditions());
        assert_eq!(detector.congestion_events.len(), 1);
    }

    #[test]
    fn tracking_window_that_precedes_instant_epoch_keeps_current_events() {
        let mut detector = PersistentCongestionDetector::with_config(PersistentCongestionConfig {
            tracking_window_micros: u64::MAX,
            ..Default::default()
        });

        detector.on_pto_event(test_conditions());

        assert_eq!(detector.congestion_events.len(), 1);
    }

    #[test]
    fn ending_epoch_before_start_saturates_to_zero_duration() {
        let mut detector = PersistentCongestionDetector::new();
        let now = Instant::now();

        detector.start_or_extend_epoch(0.6, now);
        let earlier = now.checked_sub(Duration::from_millis(1)).unwrap_or(now);
        detector.end_current_epoch(earlier);

        assert_eq!(detector.metrics.total_duration_micros, 0);
        assert!(detector.metrics.avg_episode_duration_micros.abs() < f64::EPSILON);
        assert!(detector.current_epoch.is_none());
    }

    #[test]
    fn loss_rate_uses_saturating_sum_and_is_capped() {
        let detector = PersistentCongestionDetector::new();
        let lost_packets = [
            SentPacketMeta {
                bytes: u64::MAX,
                ..create_test_packet(0, 0)
            },
            SentPacketMeta {
                bytes: u64::MAX,
                ..create_test_packet(1, 10)
            },
        ];

        let loss_rate = detector.estimate_loss_rate(&lost_packets, 1200);

        assert!((loss_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_threshold_doubling_is_saturating() {
        let detector = PersistentCongestionDetector::new();

        let confidence = detector.calculate_detection_confidence(0.5, u64::MAX, u64::MAX);

        assert!(confidence.is_finite());
        assert!(confidence > 0.0);
    }
}
