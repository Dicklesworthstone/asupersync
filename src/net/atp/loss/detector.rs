//! ATP Loss Detection Algorithms
//!
//! Advanced loss detection for ATP with improved accuracy and
//! integration with transfer decision-making.

#![allow(dead_code)]

use crate::net::atp::protocol::outcome::AtpOutcome;
use crate::net::quic_native::{
    AckRange, PacketNumberSpace, QuicTransportMachine, RttEstimator, SentPacketMeta,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Helper macro to extract success value from AtpOutcome or early return with error.
macro_rules! try_outcome {
    ($expr:expr) => {
        match $expr {
            AtpOutcome::Ok(v) => v,
            AtpOutcome::Err(e) => return AtpOutcome::Err(e),
            AtpOutcome::Cancelled(r) => return AtpOutcome::Cancelled(r),
            AtpOutcome::Panicked(p) => return AtpOutcome::Panicked(p),
        }
    };
}

/// ATP-enhanced loss detector with adaptive algorithms.
pub struct AtpLossDetector {
    /// Per-space loss detection state.
    spaces: [SpaceLossState; 3],
    /// Global loss detection configuration.
    config: LossDetectionConfig,
    /// Loss pattern analyzer.
    pattern_analyzer: LossPatternAnalyzer,
    /// Reordering tolerance tracker.
    reordering_tracker: ReorderingTracker,
    /// Lost packet numbers already counted as spurious, keyed by packet number space.
    spurious_loss_packets: HashSet<(usize, u64)>,
    /// Detection metrics for analysis.
    metrics: LossDetectionMetrics,
}

/// Loss detection state for a single packet number space.
#[derive(Debug, Clone)]
struct SpaceLossState {
    /// Sent packets awaiting acknowledgment.
    sent_packets: VecDeque<SentPacketMeta>,
    /// Largest acknowledged packet number.
    largest_acked: Option<u64>,
    /// Time of largest acked packet.
    largest_acked_time: Option<u64>,
    /// Loss detection timer deadline.
    loss_timer_deadline: Option<u64>,
    /// Early retransmit timer deadline.
    early_retransmit_deadline: Option<u64>,
}

/// Loss detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossDetectionConfig {
    /// Packet threshold for declaring loss (default: 3).
    pub packet_threshold: u32,
    /// Time threshold multiplier (default: 9/8).
    pub time_threshold_multiplier: f64,
    /// Minimum time threshold in microseconds.
    pub min_time_threshold_micros: u64,
    /// Maximum reordering threshold.
    pub max_reordering_threshold: u32,
    /// Enable adaptive packet threshold.
    pub adaptive_packet_threshold: bool,
    /// Enable early retransmit.
    pub enable_early_retransmit: bool,
    /// Early retransmit threshold.
    pub early_retransmit_threshold: u32,
}

impl Default for LossDetectionConfig {
    fn default() -> Self {
        Self {
            packet_threshold: 3,
            time_threshold_multiplier: 9.0 / 8.0,
            min_time_threshold_micros: 1_000, // 1ms
            max_reordering_threshold: 10,
            adaptive_packet_threshold: true,
            enable_early_retransmit: true,
            early_retransmit_threshold: 1,
        }
    }
}

/// Loss pattern analysis for adaptive behavior.
#[derive(Debug, Clone)]
struct LossPatternAnalyzer {
    /// Recent loss events.
    loss_events: VecDeque<LossEvent>,
    /// Detected loss patterns.
    patterns: Vec<LossPattern>,
    /// Pattern confidence scores.
    pattern_confidence: HashMap<LossPattern, f64>,
}

/// Loss event for pattern analysis.
#[derive(Debug, Clone)]
struct LossEvent {
    /// Timestamp of loss detection.
    timestamp: Instant,
    /// Lost packet numbers.
    lost_packets: Vec<u64>,
    /// Detection method used.
    detection_method: LossDetectionMethod,
    /// Network conditions at time of loss.
    conditions: NetworkConditions,
}

/// Network conditions snapshot.
#[derive(Debug, Clone)]
struct NetworkConditions {
    /// RTT at time of loss.
    rtt_micros: Option<u64>,
    /// RTT variance.
    rttvar_micros: Option<u64>,
    /// Bytes in flight.
    bytes_in_flight: u64,
    /// Congestion window.
    congestion_window: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CanonicalAckRange {
    smallest: u64,
    largest: u64,
}

/// Transport recovery state used by ATP loss analysis.
///
/// The detector keeps its own sent-packet view for ATP decisions, but RTT and
/// congestion context must come from the live transport recovery state so loss
/// classification sees the same network conditions as QUIC recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossTransportState {
    /// Latest RTT sample.
    pub latest_rtt_micros: Option<u64>,
    /// Smoothed RTT estimate.
    pub smoothed_rtt_micros: Option<u64>,
    /// RTT variance estimate.
    pub rttvar_micros: Option<u64>,
    /// Bytes currently in flight according to transport recovery.
    pub bytes_in_flight: u64,
    /// Current congestion window in bytes.
    pub congestion_window: u64,
}

impl LossTransportState {
    /// Build a snapshot from the native QUIC transport machine.
    #[must_use]
    pub fn from_transport(transport: &QuicTransportMachine) -> Self {
        Self::from_rtt_and_recovery(
            transport.rtt(),
            transport.bytes_in_flight(),
            transport.congestion_window_bytes(),
        )
    }

    /// Build a snapshot from explicit recovery counters and RTT estimator.
    #[must_use]
    pub fn from_rtt_and_recovery(
        rtt: &RttEstimator,
        bytes_in_flight: u64,
        congestion_window: u64,
    ) -> Self {
        Self {
            latest_rtt_micros: rtt.latest_rtt_micros(),
            smoothed_rtt_micros: rtt.smoothed_rtt_micros(),
            rttvar_micros: rtt.rttvar_micros(),
            bytes_in_flight,
            congestion_window,
        }
    }

    fn base_rtt_micros(self) -> u64 {
        self.latest_rtt_micros
            .or(self.smoothed_rtt_micros)
            .unwrap_or(333_000)
    }
}

/// Detected loss patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LossPattern {
    /// Random sporadic losses.
    Sporadic,
    /// Burst losses (multiple consecutive packets).
    Burst,
    /// Periodic losses (pattern of losses).
    Periodic,
    /// Reordering-induced false losses.
    Reordering,
    /// Congestion-induced losses.
    Congestion,
    /// Tail losses (end of flight).
    Tail,
}

/// Loss detection methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LossDetectionMethod {
    /// Packet threshold exceeded.
    PacketThreshold,
    /// Time threshold exceeded.
    TimeThreshold,
    /// Early retransmit.
    EarlyRetransmit,
    /// Both packet and time thresholds.
    Combined,
}

/// Reordering tolerance tracking.
#[derive(Debug, Clone)]
struct ReorderingTracker {
    /// Recent reordering measurements.
    reordering_measurements: VecDeque<u32>,
    /// Current reordering threshold.
    current_threshold: u32,
    /// Maximum observed reordering.
    max_reordering: u32,
    /// Reordering adaptation factor.
    adaptation_factor: f64,
}

/// Loss detection metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossDetectionMetrics {
    /// Total packets declared lost.
    pub total_lost_packets: u64,
    /// Packets lost by packet threshold.
    pub packet_threshold_losses: u64,
    /// Packets lost by time threshold.
    pub time_threshold_losses: u64,
    /// False loss declarations (spurious retransmits).
    pub false_losses: u64,
    /// Average packet threshold used.
    pub avg_packet_threshold: f64,
    /// Average time threshold used.
    pub avg_time_threshold_micros: f64,
    /// Reordering events detected.
    pub reordering_events: u64,
    /// Pattern detection accuracy.
    pub pattern_accuracy: f64,
}

/// Loss detection result.
#[derive(Debug, Clone)]
pub struct LossDetectionResult {
    /// Newly detected lost packets.
    pub lost_packets: Vec<LostPacketInfo>,
    /// Total number of packets/datagrams represented by this result.
    ///
    /// `lost_packets` may be sample-capped for bounded memory when the input is
    /// aggregate datagram loss evidence; this count preserves the actual loss
    /// pressure for transfer-brain decisions.
    pub lost_packet_count: u64,
    /// Total lost bytes.
    pub lost_bytes: u64,
    /// Detection method used.
    pub detection_method: LossDetectionMethod,
    /// Confidence in the detection (0.0 - 1.0).
    pub confidence: f64,
    /// Recommended actions.
    pub recommendations: Vec<LossRecommendation>,
}

/// Information about a lost packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LostPacketInfo {
    /// Packet number.
    pub packet_number: u64,
    /// Packet size in bytes.
    pub bytes: u64,
    /// Time when packet was sent.
    pub sent_time_micros: u64,
    /// Time when loss was detected.
    pub detected_time_micros: u64,
    /// Reason for declaring loss.
    pub reason: LossReason,
}

/// Reason for packet loss declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LossReason {
    /// Packet threshold exceeded (N packets acked beyond this one).
    PacketThreshold { threshold: u32 },
    /// Time threshold exceeded (too much time elapsed).
    TimeThreshold { threshold_micros: u64 },
    /// Both thresholds exceeded.
    BothThresholds {
        packet_threshold: u32,
        time_threshold_micros: u64,
    },
    /// Early retransmit triggered.
    EarlyRetransmit,
}

/// Loss-based recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LossRecommendation {
    /// Reduce congestion window.
    ReduceCongestionWindow { factor: f64 },
    /// Increase reordering threshold.
    IncreaseReorderingThreshold { new_threshold: u32 },
    /// Enable pacing.
    EnablePacing { rate: u64 },
    /// Switch to different congestion control.
    SwitchCongestionControl { algorithm: String },
    /// Enable forward error correction.
    EnableFec { rate: f64 },
}

/// Compact loss pressure signal consumed by transfer scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TransferLossSignal {
    /// Estimated loss pressure in the interval, clamped to `[0.0, 1.0]`.
    pub loss_pressure: f64,
    /// Optional FEC/repair rate hint derived from detector recommendations.
    pub repair_rate_hint: Option<f64>,
    /// Optional congestion-window reduction factor.
    pub cwnd_reduction_factor: Option<f64>,
    /// Optional pacing rate hint in bytes per second.
    pub pacing_rate_hint: Option<u64>,
    /// Whether the detector recommended moving to BBR-like control.
    pub prefer_bbr: bool,
    /// Detector confidence for this signal, clamped to `[0.0, 1.0]`.
    pub confidence: f64,
}

impl AtpLossDetector {
    /// Create a new ATP loss detector.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(LossDetectionConfig::default())
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: LossDetectionConfig) -> Self {
        Self {
            spaces: [
                SpaceLossState::new(),
                SpaceLossState::new(),
                SpaceLossState::new(),
            ],
            config,
            pattern_analyzer: LossPatternAnalyzer::new(),
            reordering_tracker: ReorderingTracker::new(),
            spurious_loss_packets: HashSet::new(),
            metrics: LossDetectionMetrics::default(),
        }
    }

    /// Track sent packet.
    pub fn on_packet_sent(&mut self, packet: SentPacketMeta) {
        let space_idx = packet.space as usize;
        self.spaces[space_idx].sent_packets.push_back(packet);

        // Limit memory usage
        if self.spaces[space_idx].sent_packets.len() > 10_000 {
            self.spaces[space_idx].sent_packets.pop_front();
        }
    }

    /// Process acknowledgment and detect losses.
    pub fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        ack_ranges: &[AckRange],
        _ack_delay_micros: u64,
        now_micros: u64,
        transport_state: &LossTransportState,
    ) -> AtpOutcome<LossDetectionResult> {
        let space_idx = space as usize;
        let state = &mut self.spaces[space_idx];

        // Find newly acknowledged packets
        let mut newly_acked = Vec::new();
        let acked_packet_numbers = acked_sent_packet_index(&state.sent_packets, ack_ranges);
        let largest_newly_acked = acked_packet_numbers.iter().copied().max();

        // Process acknowledgments
        let mut remaining_packets = VecDeque::new();
        while let Some(packet) = state.sent_packets.pop_front() {
            if acked_packet_numbers.contains(&packet.packet_number) {
                newly_acked.push(packet);
            } else {
                remaining_packets.push_back(packet);
            }
        }
        state.sent_packets = remaining_packets;

        // Update largest acked
        if let Some(largest) = largest_newly_acked {
            if state.largest_acked.is_none_or(|prev| largest > prev) {
                state.largest_acked = Some(largest);
                state.largest_acked_time = Some(now_micros);
            }
        }

        // Detect losses
        let loss_result = try_outcome!(self.detect_losses(space, now_micros, transport_state));

        // Update pattern analysis
        if !loss_result.lost_packets.is_empty() {
            self.update_pattern_analysis(&loss_result, transport_state);
        }

        // Update reordering tracking. Newly acked packets still in the sent
        // queue catch ordinary reordering; ACK ranges catch packets already
        // removed after a previous loss declaration.
        self.update_reordering_tracking(space_idx, &newly_acked, ack_ranges, &loss_result);

        AtpOutcome::ok(loss_result)
    }

    /// Feed aggregate datagram-round loss evidence into the ATP loss analyzer.
    ///
    /// RaptorQ-style transports receive per-round `NeedMore` pressure instead of
    /// QUIC ACK ranges. This bridge lets them reuse the same pattern analyzer and
    /// recommendation logic without synthesizing full packet histories or changing
    /// their wire protocol.
    #[allow(clippy::cast_precision_loss)]
    pub fn observe_datagram_loss_sample(
        &mut self,
        sent_datagrams: u64,
        lost_datagrams: u64,
        rtt: Option<Duration>,
        bytes_in_flight: u64,
        congestion_window: u64,
    ) -> LossDetectionResult {
        if sent_datagrams == 0 {
            return LossDetectionResult::empty();
        }

        let lost_datagrams = lost_datagrams.min(sent_datagrams);
        if lost_datagrams == 0 {
            if let Some(rtt) = rtt {
                self.metrics.avg_time_threshold_micros = rtt.as_micros() as f64;
            }
            return LossDetectionResult::empty();
        }

        let sample_cap = lost_datagrams.min(128);
        let rtt_micros = rtt.and_then(|duration| u64::try_from(duration.as_micros()).ok());
        let detected_time_micros = rtt_micros.unwrap_or(1);
        let lost_packets: Vec<LostPacketInfo> = (0..sample_cap)
            .map(|packet_number| LostPacketInfo {
                packet_number,
                bytes: bytes_in_flight
                    .checked_div(sent_datagrams)
                    .unwrap_or(0)
                    .max(1),
                sent_time_micros: 0,
                detected_time_micros,
                reason: LossReason::PacketThreshold {
                    threshold: self.config.packet_threshold,
                },
            })
            .collect();

        self.metrics.total_lost_packets = self
            .metrics
            .total_lost_packets
            .saturating_add(lost_datagrams);
        self.metrics.packet_threshold_losses = self
            .metrics
            .packet_threshold_losses
            .saturating_add(lost_datagrams);
        if let Some(rtt) = rtt {
            self.metrics.avg_time_threshold_micros = rtt.as_micros() as f64;
        }

        let detection_method = LossDetectionMethod::PacketThreshold;
        let confidence = self.calculate_detection_confidence(&lost_packets, detection_method);
        let recommendations = self.generate_recommendations(&lost_packets, detection_method);
        let result = LossDetectionResult {
            lost_packets,
            lost_packet_count: lost_datagrams,
            lost_bytes: bytes_in_flight.min(
                bytes_in_flight
                    .checked_mul(lost_datagrams)
                    .and_then(|bytes| bytes.checked_div(sent_datagrams))
                    .unwrap_or(bytes_in_flight),
            ),
            detection_method,
            confidence,
            recommendations,
        };
        self.update_pattern_analysis(
            &result,
            &LossTransportState {
                latest_rtt_micros: rtt_micros,
                smoothed_rtt_micros: rtt_micros,
                rttvar_micros: None,
                bytes_in_flight,
                congestion_window,
            },
        );
        result
    }

    /// Detect losses in a packet number space.
    fn detect_losses(
        &mut self,
        space: PacketNumberSpace,
        now_micros: u64,
        transport_state: &LossTransportState,
    ) -> AtpOutcome<LossDetectionResult> {
        let space_idx = space as usize;
        let Some(largest_acked) = self.spaces[space_idx].largest_acked else {
            return AtpOutcome::ok(LossDetectionResult::empty());
        };

        let mut lost_packets = Vec::new();
        let mut lost_bytes: u64 = 0;
        let mut detection_methods = Vec::new();

        // Calculate thresholds
        let packet_threshold = self.get_adaptive_packet_threshold(space);
        let time_threshold = self.calculate_time_threshold(*transport_state);

        // Check for time threshold losses only after enough time has elapsed.
        // A saturating subtraction would floor the boundary to zero and mark a
        // packet sent at t=0 as time-lost before the threshold is reachable.
        let time_threshold_boundary = now_micros.checked_sub(time_threshold);

        let mut remaining_packets = VecDeque::new();
        let enable_early_retransmit = self.config.enable_early_retransmit;
        let early_retransmit_threshold = self.config.early_retransmit_threshold;
        let state = &mut self.spaces[space_idx];
        while let Some(packet) = state.sent_packets.pop_front() {
            let mut is_lost = false;
            let mut loss_reason = None;

            // Packet threshold loss
            if packet
                .packet_number
                .checked_add(u64::from(packet_threshold))
                .is_some_and(|threshold_packet| threshold_packet <= largest_acked)
            {
                is_lost = true;
                loss_reason = Some(LossReason::PacketThreshold {
                    threshold: packet_threshold,
                });
                detection_methods.push(LossDetectionMethod::PacketThreshold);
                self.metrics.packet_threshold_losses += 1;
            }

            // Time threshold loss
            if time_threshold_boundary.is_some_and(|boundary| packet.time_sent_micros <= boundary)
                && packet.packet_number <= largest_acked
            {
                if is_lost {
                    // Both thresholds
                    loss_reason = Some(LossReason::BothThresholds {
                        packet_threshold,
                        time_threshold_micros: time_threshold,
                    });
                    detection_methods.clear();
                    detection_methods.push(LossDetectionMethod::Combined);
                } else {
                    is_lost = true;
                    loss_reason = Some(LossReason::TimeThreshold {
                        threshold_micros: time_threshold,
                    });
                    detection_methods.push(LossDetectionMethod::TimeThreshold);
                    self.metrics.time_threshold_losses += 1;
                }
            }

            // Early retransmit
            if !is_lost && enable_early_retransmit {
                if packet
                    .packet_number
                    .checked_add(u64::from(early_retransmit_threshold))
                    == Some(largest_acked)
                {
                    is_lost = true;
                    loss_reason = Some(LossReason::EarlyRetransmit);
                    detection_methods.push(LossDetectionMethod::EarlyRetransmit);
                }
            }

            if is_lost {
                lost_bytes = lost_bytes.saturating_add(packet.bytes);
                if let Some(reason) = loss_reason {
                    lost_packets.push(LostPacketInfo {
                        packet_number: packet.packet_number,
                        bytes: packet.bytes,
                        sent_time_micros: packet.time_sent_micros,
                        detected_time_micros: now_micros,
                        reason,
                    });
                } else {
                    // Edge case: packet marked as lost but no specific reason set
                    // Fall back to time threshold as a safe default
                    lost_packets.push(LostPacketInfo {
                        packet_number: packet.packet_number,
                        bytes: packet.bytes,
                        sent_time_micros: packet.time_sent_micros,
                        detected_time_micros: now_micros,
                        reason: LossReason::TimeThreshold {
                            threshold_micros: time_threshold,
                        },
                    });
                }
            } else {
                remaining_packets.push_back(packet);
            }
        }

        state.sent_packets = remaining_packets;
        self.metrics.total_lost_packets = self
            .metrics
            .total_lost_packets
            .saturating_add(lost_packets.len() as u64);

        // Determine primary detection method
        let detection_method = if detection_methods.contains(&LossDetectionMethod::Combined) {
            LossDetectionMethod::Combined
        } else if detection_methods.contains(&LossDetectionMethod::PacketThreshold) {
            LossDetectionMethod::PacketThreshold
        } else if detection_methods.contains(&LossDetectionMethod::TimeThreshold) {
            LossDetectionMethod::TimeThreshold
        } else if detection_methods.contains(&LossDetectionMethod::EarlyRetransmit) {
            LossDetectionMethod::EarlyRetransmit
        } else {
            LossDetectionMethod::PacketThreshold
        };

        // Calculate confidence
        let confidence = self.calculate_detection_confidence(&lost_packets, detection_method);

        // Generate recommendations
        let recommendations = self.generate_recommendations(&lost_packets, detection_method);

        AtpOutcome::ok(LossDetectionResult {
            lost_packet_count: lost_packets.len() as u64,
            lost_packets,
            lost_bytes,
            detection_method,
            confidence,
            recommendations,
        })
    }

    fn get_adaptive_packet_threshold(&mut self, _space: PacketNumberSpace) -> u32 {
        if !self.config.adaptive_packet_threshold {
            return self.config.packet_threshold;
        }

        // Use reordering tracker to adapt threshold
        let current_threshold = self.reordering_tracker.current_threshold;
        current_threshold.max(self.config.packet_threshold)
    }

    fn calculate_time_threshold(&self, transport_state: LossTransportState) -> u64 {
        let threshold = (transport_state.base_rtt_micros() as f64
            * self.config.time_threshold_multiplier) as u64;
        threshold.max(self.config.min_time_threshold_micros)
    }

    fn should_early_retransmit(&self, packet: &SentPacketMeta, largest_acked: u64) -> bool {
        // Early retransmit if only one packet ahead is acked
        packet
            .packet_number
            .checked_add(u64::from(self.config.early_retransmit_threshold))
            == Some(largest_acked)
    }

    fn calculate_detection_confidence(
        &self,
        lost_packets: &[LostPacketInfo],
        method: LossDetectionMethod,
    ) -> f64 {
        if lost_packets.is_empty() {
            return 1.0;
        }

        // Base confidence by method
        let base_confidence = match method {
            LossDetectionMethod::Combined => 0.95,
            LossDetectionMethod::PacketThreshold => 0.85,
            LossDetectionMethod::TimeThreshold => 0.75,
            LossDetectionMethod::EarlyRetransmit => 0.60,
        };

        // Adjust based on pattern analysis
        let pattern_bonus = self
            .pattern_analyzer
            .patterns
            .iter()
            .map(|pattern| {
                self.pattern_analyzer
                    .pattern_confidence
                    .get(pattern)
                    .unwrap_or(&0.0)
            })
            .fold(0.0_f64, |acc, &conf| acc.max(conf))
            * 0.1;

        (base_confidence + pattern_bonus).min(1.0_f64)
    }

    fn generate_recommendations(
        &self,
        lost_packets: &[LostPacketInfo],
        method: LossDetectionMethod,
    ) -> Vec<LossRecommendation> {
        let mut recommendations = Vec::new();

        if lost_packets.len() > 5 {
            // Many losses suggest congestion
            recommendations.push(LossRecommendation::ReduceCongestionWindow { factor: 0.5 });
        }

        if method == LossDetectionMethod::EarlyRetransmit {
            // Early retransmit might indicate reordering
            recommendations.push(LossRecommendation::IncreaseReorderingThreshold {
                new_threshold: self.reordering_tracker.current_threshold.saturating_add(1),
            });
        }

        // Check loss patterns
        for pattern in &self.pattern_analyzer.patterns {
            match pattern {
                LossPattern::Burst => {
                    recommendations.push(LossRecommendation::EnablePacing { rate: 100_000 });
                }
                LossPattern::Periodic => {
                    recommendations.push(LossRecommendation::EnableFec { rate: 0.1 });
                }
                LossPattern::Congestion => {
                    recommendations.push(LossRecommendation::SwitchCongestionControl {
                        algorithm: "bbr".to_string(),
                    });
                }
                _ => {}
            }
        }

        recommendations
    }

    fn update_pattern_analysis(
        &mut self,
        result: &LossDetectionResult,
        transport_state: &LossTransportState,
    ) {
        let loss_event = LossEvent {
            timestamp: Instant::now(),
            lost_packets: result
                .lost_packets
                .iter()
                .map(|p| p.packet_number)
                .collect(),
            detection_method: result.detection_method,
            conditions: NetworkConditions {
                rtt_micros: transport_state
                    .latest_rtt_micros
                    .or(transport_state.smoothed_rtt_micros),
                rttvar_micros: transport_state.rttvar_micros,
                bytes_in_flight: transport_state.bytes_in_flight,
                congestion_window: transport_state.congestion_window,
            },
        };

        self.pattern_analyzer.loss_events.push_back(loss_event);
        if self.pattern_analyzer.loss_events.len() > 1000 {
            self.pattern_analyzer.loss_events.pop_front();
        }

        self.analyze_loss_patterns();
    }

    fn analyze_loss_patterns(&mut self) {
        self.pattern_analyzer.patterns.clear();
        self.pattern_analyzer.pattern_confidence.clear();

        if self.pattern_analyzer.loss_events.len() < 3 {
            return;
        }

        let recent_events: Vec<_> = self
            .pattern_analyzer
            .loss_events
            .iter()
            .rev()
            .take(10)
            .collect();

        let sample_count = recent_events.len() as f64;
        let burst_events = recent_events
            .iter()
            .filter(|event| event.lost_packets.len() > 3)
            .count();
        if burst_events > 0 {
            self.pattern_analyzer.patterns.push(LossPattern::Burst);
            self.pattern_analyzer
                .pattern_confidence
                .insert(LossPattern::Burst, burst_events as f64 / sample_count);
        }

        let intervals: Vec<_> = recent_events
            .windows(2)
            .map(|w| w[0].timestamp.duration_since(w[1].timestamp))
            .collect();

        if intervals.len() >= 3 {
            let interval_micros: Vec<f64> = intervals
                .iter()
                .map(|interval| interval.as_micros() as f64)
                .collect();
            let avg_interval = interval_micros.iter().sum::<f64>() / interval_micros.len() as f64;
            if avg_interval > 0.0 {
                let variance = interval_micros
                    .iter()
                    .map(|interval| {
                        let diff = *interval - avg_interval;
                        diff * diff
                    })
                    .sum::<f64>()
                    / interval_micros.len() as f64;
                let coefficient_of_variation = variance.sqrt() / avg_interval;
                if coefficient_of_variation <= 0.15 {
                    self.pattern_analyzer.patterns.push(LossPattern::Periodic);
                    self.pattern_analyzer.pattern_confidence.insert(
                        LossPattern::Periodic,
                        (1.0 - coefficient_of_variation / 0.15).clamp(0.0, 1.0),
                    );
                }
            }
        }

        let congestion_events = recent_events
            .iter()
            .filter(|event| {
                event
                    .conditions
                    .rttvar_micros
                    .zip(event.conditions.rtt_micros)
                    .is_some_and(|(rttvar, rtt)| rtt > 0 && rttvar.saturating_mul(4) > rtt)
                    || (event.conditions.congestion_window > 0
                        && event.conditions.bytes_in_flight
                            >= event.conditions.congestion_window.saturating_mul(9) / 10)
            })
            .count();
        if congestion_events > 0 {
            self.pattern_analyzer.patterns.push(LossPattern::Congestion);
            self.pattern_analyzer.pattern_confidence.insert(
                LossPattern::Congestion,
                congestion_events as f64 / sample_count,
            );
        }

        let tail_events = recent_events
            .iter()
            .filter(|event| matches!(event.detection_method, LossDetectionMethod::EarlyRetransmit))
            .count();
        if tail_events > 0 {
            self.pattern_analyzer.patterns.push(LossPattern::Tail);
            self.pattern_analyzer
                .pattern_confidence
                .insert(LossPattern::Tail, tail_events as f64 / sample_count);
        }

        if self.pattern_analyzer.patterns.is_empty() {
            self.pattern_analyzer.patterns.push(LossPattern::Sporadic);
            self.pattern_analyzer
                .pattern_confidence
                .insert(LossPattern::Sporadic, 1.0);
        }
    }

    fn update_reordering_tracking(
        &mut self,
        space_idx: usize,
        acked_packets: &[SentPacketMeta],
        ack_ranges: &[AckRange],
        _loss_result: &LossDetectionResult,
    ) {
        let Some(last_loss) = self.pattern_analyzer.loss_events.back() else {
            return;
        };

        let canonical_ranges = canonical_ack_ranges(ack_ranges);
        let mut reordered_packets: HashSet<u64> = HashSet::new();

        for acked in acked_packets {
            if last_loss.lost_packets.contains(&acked.packet_number) {
                reordered_packets.insert(acked.packet_number);
            }
        }

        for lost_packet in &last_loss.lost_packets {
            if canonical_ranges_contain_packet(&canonical_ranges, *lost_packet) {
                reordered_packets.insert(*lost_packet);
            }
        }

        let mut newly_recorded_reordering = false;
        for packet_number in reordered_packets {
            if !self
                .spurious_loss_packets
                .insert((space_idx, packet_number))
            {
                continue;
            }

            newly_recorded_reordering = true;
            self.metrics.false_losses = self.metrics.false_losses.saturating_add(1);
            let reordering_depth = last_loss
                .lost_packets
                .iter()
                .copied()
                .filter(|lost| *lost > packet_number)
                .count()
                .saturating_add(1);
            self.reordering_tracker
                .record_reordering(u32::try_from(reordering_depth).unwrap_or(u32::MAX));
        }

        if !self
            .pattern_analyzer
            .patterns
            .contains(&LossPattern::Reordering)
            && newly_recorded_reordering
        {
            self.pattern_analyzer.patterns.push(LossPattern::Reordering);
        }
        if newly_recorded_reordering {
            self.pattern_analyzer.pattern_confidence.insert(
                LossPattern::Reordering,
                self.reordering_tracker.confidence(),
            );
        }
    }

    /// Get current metrics.
    #[must_use]
    pub fn metrics(&self) -> &LossDetectionMetrics {
        &self.metrics
    }

    /// Export detection log for analysis.
    #[must_use]
    pub fn export_analysis(&self) -> LossAnalysisExport {
        LossAnalysisExport {
            metrics: self.metrics.clone(),
            patterns: self.pattern_analyzer.patterns.clone(),
            pattern_confidence: self.pattern_analyzer.pattern_confidence.clone(),
            config: self.config.clone(),
        }
    }
}

impl Default for AtpLossDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SpaceLossState {
    fn new() -> Self {
        Self {
            sent_packets: VecDeque::new(),
            largest_acked: None,
            largest_acked_time: None,
            loss_timer_deadline: None,
            early_retransmit_deadline: None,
        }
    }
}

impl LossPatternAnalyzer {
    fn new() -> Self {
        Self {
            loss_events: VecDeque::new(),
            patterns: Vec::new(),
            pattern_confidence: HashMap::new(),
        }
    }
}

impl ReorderingTracker {
    fn new() -> Self {
        Self {
            reordering_measurements: VecDeque::new(),
            current_threshold: 3, // Start with default
            max_reordering: 0,
            adaptation_factor: 0.1,
        }
    }

    fn adapt_threshold(&mut self) {
        self.record_reordering(self.current_threshold);
    }

    fn record_reordering(&mut self, depth: u32) {
        let measured_depth = depth.max(1);
        self.max_reordering = self.max_reordering.max(measured_depth);
        let target_threshold = self.current_threshold.max(measured_depth.saturating_add(1));
        let blended = self.current_threshold as f64
            + (target_threshold as f64 - self.current_threshold as f64) * self.adaptation_factor;
        self.current_threshold = blended.ceil() as u32;
        self.current_threshold = self.current_threshold.min(10);
        self.reordering_measurements.push_back(measured_depth);
        if self.reordering_measurements.len() > 100 {
            self.reordering_measurements.pop_front();
        }
    }

    fn confidence(&self) -> f64 {
        if self.reordering_measurements.is_empty() {
            return 0.0;
        }

        let recent = self.reordering_measurements.len().min(20);
        let recent_sum = self
            .reordering_measurements
            .iter()
            .rev()
            .take(recent)
            .copied()
            .map(f64::from)
            .sum::<f64>();
        let recent_avg = recent_sum / recent as f64;
        (recent_avg / f64::from(self.current_threshold.max(1))).clamp(0.0, 1.0)
    }
}

impl Default for LossDetectionMetrics {
    fn default() -> Self {
        Self {
            total_lost_packets: 0,
            packet_threshold_losses: 0,
            time_threshold_losses: 0,
            false_losses: 0,
            avg_packet_threshold: 3.0,
            avg_time_threshold_micros: 333_000.0,
            reordering_events: 0,
            pattern_accuracy: 0.0,
        }
    }
}

impl LossDetectionResult {
    fn empty() -> Self {
        Self {
            lost_packets: Vec::new(),
            lost_packet_count: 0,
            lost_bytes: 0,
            detection_method: LossDetectionMethod::PacketThreshold,
            confidence: 1.0,
            recommendations: Vec::new(),
        }
    }

    /// Convert this result into transfer-brain loss pressure.
    ///
    /// `sent_units` is the packet/datagram denominator for the detector window.
    /// A zero denominator deliberately yields zero pressure while still carrying
    /// recommendation hints, so fail-closed callers can avoid divide-by-zero
    /// amplification.
    #[must_use]
    pub fn transfer_signal(&self, sent_units: u64) -> TransferLossSignal {
        let observed_pressure = if sent_units == 0 {
            0.0
        } else {
            self.lost_packet_count.min(sent_units) as f64 / sent_units as f64
        };

        let mut loss_pressure = observed_pressure;
        let mut repair_rate_hint = None;
        let mut cwnd_reduction_factor = None;
        let mut pacing_rate_hint = None;
        let mut prefer_bbr = false;

        for recommendation in &self.recommendations {
            match recommendation {
                LossRecommendation::ReduceCongestionWindow { factor } => {
                    let factor = finite_unit(*factor);
                    cwnd_reduction_factor = Some(
                        cwnd_reduction_factor.map_or(factor, |current: f64| current.min(factor)),
                    );
                }
                LossRecommendation::IncreaseReorderingThreshold { .. } => {}
                LossRecommendation::EnablePacing { rate } => {
                    pacing_rate_hint =
                        Some(pacing_rate_hint.map_or(*rate, |current: u64| current.min(*rate)));
                }
                LossRecommendation::SwitchCongestionControl { algorithm } => {
                    prefer_bbr |= algorithm.eq_ignore_ascii_case("bbr");
                }
                LossRecommendation::EnableFec { rate } => {
                    if let Some(rate) = bounded_repair_rate(*rate) {
                        repair_rate_hint =
                            Some(repair_rate_hint.map_or(rate, |current: f64| current.max(rate)));
                        loss_pressure = loss_pressure.max(rate);
                    }
                }
            }
        }

        let confidence = finite_unit(self.confidence);
        let repair_rate_hint = repair_rate_hint.or_else(|| {
            (observed_pressure > 0.0)
                .then(|| bounded_repair_rate(observed_pressure * 1.5))
                .flatten()
        });

        TransferLossSignal {
            loss_pressure: finite_unit(loss_pressure),
            repair_rate_hint,
            cwnd_reduction_factor,
            pacing_rate_hint,
            prefer_bbr,
            confidence,
        }
    }
}

fn finite_unit(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn bounded_repair_rate(rate: f64) -> Option<f64> {
    if rate.is_finite() && rate > 0.0 {
        Some(rate.clamp(0.05, 0.30))
    } else {
        None
    }
}

/// Loss analysis export for external tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossAnalysisExport {
    /// Current metrics.
    pub metrics: LossDetectionMetrics,
    /// Detected patterns.
    pub patterns: Vec<LossPattern>,
    /// Pattern confidence scores.
    pub pattern_confidence: HashMap<LossPattern, f64>,
    /// Current configuration.
    pub config: LossDetectionConfig,
}

fn canonical_ack_ranges(ack_ranges: &[AckRange]) -> Vec<CanonicalAckRange> {
    let mut ranges: Vec<_> = ack_ranges
        .iter()
        .map(|range| CanonicalAckRange {
            smallest: range.smallest,
            largest: range.largest,
        })
        .collect();
    ranges.sort_unstable_by_key(|range| (range.smallest, range.largest));

    let mut merged: Vec<CanonicalAckRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if range.smallest <= last.largest.saturating_add(1) {
                last.largest = last.largest.max(range.largest);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

fn acked_sent_packet_index(
    sent_packets: &VecDeque<SentPacketMeta>,
    ack_ranges: &[AckRange],
) -> HashSet<u64> {
    let ranges = canonical_ack_ranges(ack_ranges);
    let mut acked_packet_numbers = HashSet::with_capacity(sent_packets.len());

    if sent_packets_are_packet_number_ordered(sent_packets) {
        let mut range_idx = 0;
        for packet in sent_packets {
            while let Some(range) = ranges.get(range_idx) {
                if packet.packet_number <= range.largest {
                    break;
                }
                range_idx += 1;
            }

            let Some(range) = ranges.get(range_idx) else {
                break;
            };

            if packet.packet_number >= range.smallest {
                acked_packet_numbers.insert(packet.packet_number);
            }
        }
    } else {
        for packet in sent_packets {
            if canonical_ranges_contain_packet(&ranges, packet.packet_number) {
                acked_packet_numbers.insert(packet.packet_number);
            }
        }
    }

    acked_packet_numbers
}

fn sent_packets_are_packet_number_ordered(sent_packets: &VecDeque<SentPacketMeta>) -> bool {
    let mut previous_packet_number = None;
    for packet in sent_packets {
        if previous_packet_number.is_some_and(|previous| packet.packet_number < previous) {
            return false;
        }
        previous_packet_number = Some(packet.packet_number);
    }
    true
}

fn canonical_ranges_contain_packet(ranges: &[CanonicalAckRange], packet_number: u64) -> bool {
    let range_idx = ranges.partition_point(|range| range.largest < packet_number);
    ranges
        .get(range_idx)
        .is_some_and(|range| packet_number >= range.smallest)
}

#[cfg(test)]
#[path = "detector_inline_tests.rs"]
mod tests;
