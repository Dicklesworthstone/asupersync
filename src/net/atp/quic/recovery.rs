//! ATP QUIC Recovery Integration
//!
//! Integrates QUIC loss detection and recovery with ATP-specific requirements:
//! - Structured logging for replay and diagnostics
//! - Cancellation-aware recovery timers
//! - ATP-specific congestion control adaptations

use crate::cx::Cx;
use crate::net::atp::protocol::outcome::{AtpError, AtpOutcome, TransportError};
use crate::net::quic_native::{
    AckEvent, PacketNumberSpace, QuicTransportMachine, RttEstimator, SentPacketMeta,
};
use crate::types::cancel::CancelReason;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// ATP Recovery Manager
///
/// Wraps the native QUIC transport machine with ATP-specific recovery logic,
/// structured logging, and cancellation-aware timer management.
pub struct AtpRecoveryManager {
    /// Underlying QUIC transport machine.
    transport: QuicTransportMachine,
    /// Recovery event logger.
    logger: RecoveryLogger,
    /// Active recovery timers.
    timers: HashMap<String, RecoveryTimer>,
    /// Congestion control strategy.
    congestion_strategy: CongestionStrategy,
    /// Anti-amplification state.
    anti_amplification: AntiAmplificationTracker,
    /// Connection identifier for logging.
    connection_id: String,
    /// Last update timestamp.
    last_update: Instant,
}

/// Structured recovery event logging.
#[derive(Debug, Clone)]
pub struct RecoveryLogger {
    /// Connection identifier.
    connection_id: String,
    /// Recent events for replay.
    events: Vec<RecoveryEvent>,
    /// Event sequence number.
    sequence: u64,
}

/// Recovery event for structured logging and replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEvent {
    /// Event sequence number.
    pub sequence: u64,
    /// Event timestamp (microseconds since connection start).
    pub timestamp_micros: u64,
    /// Event type and details.
    pub event_type: RecoveryEventType,
    /// Connection identifier.
    pub connection_id: String,
    /// Packet number space if applicable.
    pub space: Option<PacketNumberSpace>,
    /// Current transport state snapshot.
    pub transport_state: TransportStateSnapshot,
}

/// Types of recovery events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryEventType {
    /// Packet was sent.
    PacketSent {
        packet_number: u64,
        bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
    },
    /// ACK was received.
    AckReceived {
        acked_packets: Vec<u64>,
        ack_delay_micros: u64,
        newly_acked_bytes: u64,
        newly_lost_bytes: u64,
        largest_acked: u64,
    },
    /// Packet loss detected.
    LossDetected {
        lost_packets: Vec<u64>,
        detection_method: LossDetectionMethod,
        loss_delay_micros: u64,
    },
    /// PTO timer expired.
    PtoExpired { pto_count: u32, backoff_level: u32 },
    /// Congestion window updated.
    CongestionWindowUpdated {
        old_cwnd: u64,
        new_cwnd: u64,
        ssthresh: u64,
        reason: CongestionUpdateReason,
    },
    /// RTT sample recorded.
    RttSample {
        sample_micros: u64,
        ack_delay_micros: u64,
        smoothed_rtt_micros: u64,
        rttvar_micros: u64,
    },
    /// Recovery state changed.
    RecoveryStateChanged {
        old_state: String,
        new_state: String,
        trigger: String,
    },
    /// Anti-amplification limit triggered.
    AntiAmplificationLimited {
        bytes_sent: u64,
        bytes_received: u64,
        limit_ratio: f64,
    },
}

/// Loss detection methods for diagnostics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LossDetectionMethod {
    /// Packet threshold (3+ packets acknowledged above this one).
    PacketThreshold,
    /// Time threshold (too much time elapsed).
    TimeThreshold,
    /// Both thresholds triggered.
    BothThresholds,
}

/// Congestion window update reasons.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CongestionUpdateReason {
    /// ACK received (growth).
    AckReceived,
    /// Loss detected (reduction).
    LossDetected,
    /// PTO expired (probe).
    PtoExpired,
    /// Connection reset.
    Reset,
    /// Anti-amplification limit.
    AntiAmplificationLimit,
}

/// Transport state snapshot for logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStateSnapshot {
    /// Connection state.
    pub connection_state: String,
    /// Bytes in flight.
    pub bytes_in_flight: u64,
    /// Congestion window.
    pub congestion_window: u64,
    /// Slow-start threshold.
    pub ssthresh: u64,
    /// PTO count.
    pub pto_count: u32,
    /// RTT estimates.
    pub rtt_estimates: RttSnapshot,
}

/// RTT snapshot for logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttSnapshot {
    /// Smoothed RTT in microseconds.
    pub smoothed_rtt_micros: Option<u64>,
    /// Latest RTT in microseconds.
    pub latest_rtt_micros: Option<u64>,
    /// RTT variance in microseconds.
    pub rttvar_micros: Option<u64>,
}

/// Recovery timer for cancellation-aware PTO handling.
#[derive(Debug)]
struct RecoveryTimer {
    /// Timer identifier.
    id: String,
    /// Timer deadline.
    deadline: Instant,
    /// Associated packet number space.
    space: PacketNumberSpace,
    /// Cancellation reason (TODO: Integrate with Cx cancellation).
    _cancel_reason: Option<CancelReason>,
    /// Whether timer is active.
    is_active: bool,
}

/// Congestion control strategy.
#[derive(Debug, Clone, Copy)]
pub enum CongestionStrategy {
    /// Conservative (NewReno-like).
    Conservative,
    /// Standard (Cubic-like).
    Standard,
    /// Aggressive (BBR-like).
    Aggressive,
    /// ATP adaptive algorithm.
    AtpAdaptive,
}

/// Anti-amplification tracking per RFC 9000.
#[derive(Debug)]
struct AntiAmplificationTracker {
    /// Bytes sent to unvalidated addresses.
    bytes_sent: u64,
    /// Bytes received from peer (validates address).
    bytes_received: u64,
    /// Whether address is validated.
    address_validated: bool,
    /// Last reset timestamp.
    last_reset: Instant,
}

impl AtpRecoveryManager {
    /// Create a new ATP recovery manager.
    #[must_use]
    pub fn new(connection_id: String) -> Self {
        Self {
            transport: QuicTransportMachine::new(),
            logger: RecoveryLogger::new(connection_id.clone()),
            timers: HashMap::new(),
            congestion_strategy: CongestionStrategy::AtpAdaptive,
            anti_amplification: AntiAmplificationTracker::new(),
            connection_id,
            last_update: Instant::now(),
        }
    }

    /// Begin handshake with recovery tracking.
    pub fn begin_handshake(&mut self, _cx: &Cx) -> AtpOutcome<()> {
        match self.transport.begin_handshake() {
            Ok(()) => {
                self.log_event(RecoveryEventType::RecoveryStateChanged {
                    old_state: "idle".to_string(),
                    new_state: "handshaking".to_string(),
                    trigger: "begin_handshake".to_string(),
                });
                AtpOutcome::ok(())
            }
            Err(_e) => AtpOutcome::transport_error(TransportError::QuicHandshakeFailed),
        }
    }

    /// Mark connection as established.
    pub fn on_established(&mut self) -> AtpOutcome<()> {
        match self.transport.on_established() {
            Ok(()) => {
                self.log_event(RecoveryEventType::RecoveryStateChanged {
                    old_state: "handshaking".to_string(),
                    new_state: "established".to_string(),
                    trigger: "handshake_complete".to_string(),
                });
                AtpOutcome::ok(())
            }
            Err(_e) => AtpOutcome::transport_error(TransportError::QuicHandshakeFailed),
        }
    }

    /// Send packet with recovery tracking.
    pub fn on_packet_sent(&mut self, packet: SentPacketMeta) -> AtpOutcome<()> {
        // Check anti-amplification limits
        if !self.anti_amplification.address_validated
            && !self.anti_amplification.can_send(packet.bytes)
        {
            self.log_event(RecoveryEventType::AntiAmplificationLimited {
                bytes_sent: self.anti_amplification.bytes_sent,
                bytes_received: self.anti_amplification.bytes_received,
                limit_ratio: 3.0,
            });
            return AtpOutcome::transport_error(TransportError::NetworkUnreachable);
        }

        self.transport.on_packet_sent(packet.clone());
        self.anti_amplification.on_packet_sent(packet.bytes);

        self.log_event(RecoveryEventType::PacketSent {
            packet_number: packet.packet_number,
            bytes: packet.bytes,
            ack_eliciting: packet.ack_eliciting,
            in_flight: packet.in_flight,
        });

        // Schedule PTO timer if needed
        self.update_pto_timer(packet.space);

        AtpOutcome::ok(())
    }

    /// Process ACK with recovery tracking.
    pub fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        acked_packets: &[u64],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> AtpOutcome<AckEvent> {
        let old_cwnd = self.transport.congestion_window_bytes();
        let event =
            self.transport
                .on_ack_received(space, acked_packets, ack_delay_micros, now_micros);

        self.anti_amplification.on_ack_received();

        // Log ACK processing
        self.log_event(RecoveryEventType::AckReceived {
            acked_packets: acked_packets.to_vec(),
            ack_delay_micros,
            newly_acked_bytes: event.acked_bytes,
            newly_lost_bytes: event.lost_bytes,
            largest_acked: acked_packets.iter().copied().max().unwrap_or(0),
        });

        // Log loss detection if any
        if event.lost_packets > 0 {
            self.log_event(RecoveryEventType::LossDetected {
                lost_packets: Vec::new(), // TODO: Track specific lost packets
                detection_method: LossDetectionMethod::PacketThreshold, // TODO: Determine actual method
                loss_delay_micros: 0, // TODO: Calculate loss delay
            });
        }

        // Log congestion window changes
        let new_cwnd = self.transport.congestion_window_bytes();
        if new_cwnd != old_cwnd {
            let reason = if event.lost_packets > 0 {
                CongestionUpdateReason::LossDetected
            } else {
                CongestionUpdateReason::AckReceived
            };

            self.log_event(RecoveryEventType::CongestionWindowUpdated {
                old_cwnd,
                new_cwnd,
                ssthresh: self.transport.ssthresh_bytes(),
                reason,
            });
        }

        // Log RTT sample if available
        let rtt = self.transport.rtt();
        if let (Some(smoothed), Some(latest), Some(rttvar)) = (
            rtt.smoothed_rtt_micros(),
            rtt.latest_rtt_micros(),
            rtt.rttvar_micros(),
        ) {
            self.log_event(RecoveryEventType::RttSample {
                sample_micros: latest,
                ack_delay_micros,
                smoothed_rtt_micros: smoothed,
                rttvar_micros: rttvar,
            });
        }

        // Cancel PTO timer if needed
        if event.acked_packets > 0 {
            self.cancel_pto_timer(space);
        }

        AtpOutcome::ok(event)
    }

    /// Handle PTO timer expiration.
    pub fn on_pto_expired(&mut self, space: PacketNumberSpace) -> AtpOutcome<()> {
        let old_pto_count = 0; // TODO: Get from transport
        self.transport.on_pto_expired();

        self.log_event(RecoveryEventType::PtoExpired {
            pto_count: old_pto_count + 1,
            backoff_level: std::cmp::min(old_pto_count, 10), // Capped at 10
        });

        // Schedule next PTO timer
        self.update_pto_timer(space);

        AtpOutcome::ok(())
    }

    /// Poll recovery timers and handle cancellation.
    pub fn poll(&mut self, cx: &Cx, now: Instant) -> AtpOutcome<Vec<RecoveryAction>> {
        let mut actions = Vec::new();

        // Check for cancelled operations
        if cx.is_cancelled() {
            return self.handle_cancellation(cx.cancel_reason());
        }

        // Poll transport machine
        let now_micros = now.duration_since(self.last_update).as_micros() as u64;
        self.transport.poll(now_micros);

        // Check PTO timers
        let expired_timers: Vec<_> = self
            .timers
            .iter()
            .filter(|(_, timer)| timer.deadline <= now && timer.is_active)
            .map(|(id, timer)| (id.clone(), timer.space))
            .collect();

        for (timer_id, space) in expired_timers {
            self.on_pto_expired(space).ok();
            actions.push(RecoveryAction::SendProbePackets { space, count: 2 });
            self.timers.remove(&timer_id);
        }

        self.last_update = now;
        AtpOutcome::ok(actions)
    }

    /// Get current transport state.
    #[must_use]
    pub fn transport(&self) -> &QuicTransportMachine {
        &self.transport
    }

    /// Get recovery event log for replay.
    #[must_use]
    pub fn recovery_log(&self) -> &[RecoveryEvent] {
        &self.logger.events
    }

    /// Export recovery log for external analysis.
    #[must_use]
    pub fn export_recovery_log(&self) -> Vec<RecoveryEvent> {
        self.logger.events.clone()
    }

    /// Set congestion control strategy.
    pub fn set_congestion_strategy(&mut self, strategy: CongestionStrategy) {
        self.congestion_strategy = strategy;
    }

    /// Check if anti-amplification is limiting sends.
    #[must_use]
    pub fn is_anti_amplification_limited(&self) -> bool {
        !self.anti_amplification.address_validated && !self.anti_amplification.can_send(1200) // Typical packet size
    }

    // Private helper methods

    fn log_event(&mut self, event_type: RecoveryEventType) {
        let event = RecoveryEvent {
            sequence: self.logger.sequence,
            timestamp_micros: self.last_update.elapsed().as_micros() as u64,
            event_type,
            connection_id: self.connection_id.clone(),
            space: None, // TODO: Extract from event type
            transport_state: self.create_transport_snapshot(),
        };

        self.logger.events.push(event);
        self.logger.sequence += 1;

        // Limit log size
        if self.logger.events.len() > 10_000 {
            self.logger.events.remove(0);
        }
    }

    fn create_transport_snapshot(&self) -> TransportStateSnapshot {
        let rtt = self.transport.rtt();
        TransportStateSnapshot {
            connection_state: format!("{:?}", self.transport.state()),
            bytes_in_flight: self.transport.bytes_in_flight(),
            congestion_window: self.transport.congestion_window_bytes(),
            ssthresh: self.transport.ssthresh_bytes(),
            pto_count: 0, // TODO: Get from transport
            rtt_estimates: RttSnapshot {
                smoothed_rtt_micros: rtt.smoothed_rtt_micros(),
                latest_rtt_micros: rtt.latest_rtt_micros(),
                rttvar_micros: rtt.rttvar_micros(),
            },
        }
    }

    fn update_pto_timer(&mut self, space: PacketNumberSpace) {
        let timer_id = format!("pto_{}_{:?}", self.connection_id, space);

        if let Some(deadline_micros) = self.transport.pto_deadline_micros(0) {
            let deadline = Instant::now() + Duration::from_micros(deadline_micros);

            let timer = RecoveryTimer {
                id: timer_id.clone(),
                deadline,
                space,
                _cancel_reason: None, // TODO: Integrate with Cx cancellation
                is_active: true,
            };

            self.timers.insert(timer_id, timer);
        }
    }

    fn cancel_pto_timer(&mut self, space: PacketNumberSpace) {
        let timer_id = format!("pto_{}_{:?}", self.connection_id, space);
        if let Some(timer) = self.timers.get_mut(&timer_id) {
            timer.is_active = false;
            // Timer cancellation handled by setting is_active = false
        }
    }

    fn handle_cancellation(&mut self, reason: CancelReason) -> AtpOutcome<Vec<RecoveryAction>> {
        // Cancel all active timers
        for timer in self.timers.values_mut() {
            timer.is_active = false;
            // Timer cancellation handled by setting is_active = false
        }

        self.log_event(RecoveryEventType::RecoveryStateChanged {
            old_state: format!("{:?}", self.transport.state()),
            new_state: "cancelled".to_string(),
            trigger: format!("cancellation: {}", reason.message().unwrap_or("unknown")),
        });

        AtpOutcome::cancelled(reason)
    }
}

impl RecoveryLogger {
    fn new(connection_id: String) -> Self {
        Self {
            connection_id,
            events: Vec::new(),
            sequence: 0,
        }
    }
}

impl AntiAmplificationTracker {
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

    fn on_ack_received(&mut self) {
        // Receiving an ACK validates the address
        self.address_validated = true;
    }

    fn can_send(&self, bytes: u64) -> bool {
        if self.address_validated {
            return true;
        }

        // RFC 9000: server MUST NOT send more than 3x received bytes
        self.bytes_sent.saturating_add(bytes) <= self.bytes_received.saturating_mul(3)
    }

    fn maybe_reset(&mut self) {
        if self.last_reset.elapsed() > Duration::from_secs(60) {
            self.bytes_sent = 0;
            self.bytes_received = 0;
            self.last_reset = Instant::now();
        }
    }
}

/// Actions that the recovery manager wants to take.
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// Send probe packets for PTO.
    SendProbePackets {
        space: PacketNumberSpace,
        count: u32,
    },
    /// Update congestion window.
    UpdateCongestionWindow { new_cwnd: u64, reason: String },
    /// Cancel active transfers due to persistent failure.
    CancelTransfers { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;

    #[test]
    fn recovery_manager_lifecycle() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        let cx = Cx::root();

        // Begin handshake
        let result = manager.begin_handshake(&cx);
        assert!(result.is_ok());

        // Should log recovery state change
        let events = manager.recovery_log();
        assert_eq!(events.len(), 1);
        if let RecoveryEventType::RecoveryStateChanged { new_state, .. } = &events[0].event_type {
            assert_eq!(new_state, "handshaking");
        } else {
            panic!("Expected RecoveryStateChanged event");
        }
    }

    #[test]
    fn anti_amplification_limits() {
        let mut tracker = AntiAmplificationTracker::new();

        // Should allow sending initially (no bytes received yet, but under limits)
        assert!(!tracker.can_send(1000)); // No bytes received, can't send anything

        // Simulate receiving some data (validates address)
        tracker.on_ack_received();
        assert!(tracker.can_send(1000)); // Address validated, can send freely
    }

    #[test]
    fn recovery_event_logging() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());

        // Send a packet
        let packet = SentPacketMeta {
            space: PacketNumberSpace::Initial,
            packet_number: 1,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: 1000,
        };

        let result = manager.on_packet_sent(packet);
        assert!(result.is_err()); // Should fail due to anti-amplification

        // Should log the limit event
        let events = manager.recovery_log();
        assert!(!events.is_empty());
    }

    #[test]
    fn pto_timer_management() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());

        // Initially no timers
        assert!(manager.timers.is_empty());

        // Send packet should create PTO timer
        // First validate address
        manager.anti_amplification.address_validated = true;

        let packet = SentPacketMeta {
            space: PacketNumberSpace::Initial,
            packet_number: 1,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: 1000,
        };

        let result = manager.on_packet_sent(packet);
        assert!(result.is_ok());

        // Should have created a PTO timer
        assert!(!manager.timers.is_empty());
    }
}
