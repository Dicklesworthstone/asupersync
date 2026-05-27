//! ATP QUIC Recovery Integration
//!
//! Integrates QUIC loss detection and recovery with ATP-specific requirements:
//! - Structured logging for replay and diagnostics
//! - Cancellation-aware recovery timers
//! - ATP-specific congestion control adaptations

use crate::cx::Cx;
use crate::net::atp::protocol::outcome::{AtpOutcome, TransportError};
use crate::net::quic_native::{AckEvent, PacketNumberSpace, QuicTransportMachine, SentPacketMeta};
use crate::types::cancel::CancelReason;
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
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
    /// ATP-owned recovery telemetry mirror for proof logs.
    telemetry: RecoveryTelemetry,
    /// PTO count mirrored for diagnostics and snapshots.
    pto_count: u32,
    /// Connection identifier for logging.
    connection_id: String,
    /// Last update timestamp.
    last_update: Instant,
}

/// Structured recovery event logging.
#[derive(Debug, Clone)]
pub struct RecoveryLogger {
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "packet_number_space_serde::serialize_option",
        deserialize_with = "packet_number_space_serde::deserialize_option"
    )]
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
    /// Timer deadline.
    deadline: Instant,
    /// Associated packet number space.
    space: PacketNumberSpace,
    /// Cancellation reason if timer was cancelled.
    cancel_reason: Option<CancelReason>,
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
            telemetry: RecoveryTelemetry::new(),
            pto_count: 0,
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
        self.telemetry.on_packet_sent(packet.clone());
        self.anti_amplification.on_packet_sent(packet.bytes);

        self.log_event_for_space(
            Some(packet.space),
            RecoveryEventType::PacketSent {
                packet_number: packet.packet_number,
                bytes: packet.bytes,
                ack_eliciting: packet.ack_eliciting,
                in_flight: packet.in_flight,
            },
        );

        // Schedule PTO timer if needed
        self.update_pto_timer(packet.space);

        AtpOutcome::ok(())
    }

    /// Process received datagram (updates anti-amplification limits).
    pub fn on_datagram_received(&mut self, bytes: u64) {
        self.anti_amplification.on_datagram_received(bytes);
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
        if event.acked_packets > 0 {
            self.pto_count = 0;
        }
        let loss_delay_micros = self.loss_delay_micros();
        let loss_telemetry =
            self.telemetry
                .on_ack_received(space, acked_packets, now_micros, loss_delay_micros);
        let telemetry_lost_bytes = loss_telemetry.as_ref().map_or(0, |loss| loss.lost_bytes);

        self.anti_amplification.on_ack_received();

        // Log ACK processing
        self.log_event_for_space(
            Some(space),
            RecoveryEventType::AckReceived {
                acked_packets: acked_packets.to_vec(),
                ack_delay_micros,
                newly_acked_bytes: event.acked_bytes,
                newly_lost_bytes: event.lost_bytes.max(telemetry_lost_bytes),
                largest_acked: acked_packets.iter().copied().max().unwrap_or(0),
            },
        );

        // Log loss detection if any
        if let Some(loss) = loss_telemetry {
            self.log_event_for_space(
                Some(space),
                RecoveryEventType::LossDetected {
                    lost_packets: loss.lost_packets,
                    detection_method: loss.detection_method,
                    loss_delay_micros: loss.loss_delay_micros,
                },
            );
        }

        // Log congestion window changes
        let new_cwnd = self.transport.congestion_window_bytes();
        if new_cwnd != old_cwnd {
            let reason = if event.lost_packets > 0 {
                CongestionUpdateReason::LossDetected
            } else {
                CongestionUpdateReason::AckReceived
            };

            self.log_event_for_space(
                Some(space),
                RecoveryEventType::CongestionWindowUpdated {
                    old_cwnd,
                    new_cwnd,
                    ssthresh: self.transport.ssthresh_bytes(),
                    reason,
                },
            );
        }

        // Log RTT sample if available
        let rtt = self.transport.rtt();
        if let (Some(smoothed), Some(latest), Some(rttvar)) = (
            rtt.smoothed_rtt_micros(),
            rtt.latest_rtt_micros(),
            rtt.rttvar_micros(),
        ) {
            self.log_event_for_space(
                Some(space),
                RecoveryEventType::RttSample {
                    sample_micros: latest,
                    ack_delay_micros,
                    smoothed_rtt_micros: smoothed,
                    rttvar_micros: rttvar,
                },
            );
        }

        // Cancel PTO timer if needed
        if event.acked_packets > 0 {
            self.cancel_pto_timer(space);
        }

        AtpOutcome::ok(event)
    }

    /// Handle PTO timer expiration.
    pub fn on_pto_expired(&mut self, space: PacketNumberSpace) -> AtpOutcome<()> {
        self.transport.on_pto_expired();
        self.pto_count = self.pto_count.saturating_add(1);

        self.log_event_for_space(
            Some(space),
            RecoveryEventType::PtoExpired {
                pto_count: self.pto_count,
                backoff_level: self.pto_count.min(10),
            },
        );

        // Schedule next PTO timer
        self.update_pto_timer(space);

        AtpOutcome::ok(())
    }

    /// Poll recovery timers and handle cancellation.
    pub fn poll(&mut self, cx: &Cx, now: Instant) -> AtpOutcome<Vec<RecoveryAction>> {
        let mut actions = Vec::new();

        // Check for cancelled operations
        if let Some(reason) = cx.cancel_reason() {
            return self.handle_cancellation(reason);
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
            match self.on_pto_expired(space) {
                Outcome::Ok(()) => {}
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
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
        self.log_event_for_space(None, event_type);
    }

    fn log_event_for_space(
        &mut self,
        space: Option<PacketNumberSpace>,
        event_type: RecoveryEventType,
    ) {
        let event = RecoveryEvent {
            sequence: self.logger.sequence,
            timestamp_micros: self.last_update.elapsed().as_micros() as u64,
            event_type,
            connection_id: self.connection_id.clone(),
            space,
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
            pto_count: self.pto_count,
            rtt_estimates: RttSnapshot {
                smoothed_rtt_micros: rtt.smoothed_rtt_micros(),
                latest_rtt_micros: rtt.latest_rtt_micros(),
                rttvar_micros: rtt.rttvar_micros(),
            },
        }
    }

    fn loss_delay_micros(&self) -> u64 {
        let rtt = self.transport.rtt();
        let latest = rtt.latest_rtt_micros().unwrap_or(333_000);
        let smoothed = rtt.smoothed_rtt_micros().unwrap_or(333_000);
        (9u64.saturating_mul(latest.max(smoothed)) / 8).max(1_000)
    }

    fn update_pto_timer(&mut self, space: PacketNumberSpace) {
        let timer_id = format!("pto_{}_{:?}", self.connection_id, space);

        if let Some(deadline_micros) = self.transport.pto_deadline_micros(0) {
            let deadline = Instant::now() + Duration::from_micros(deadline_micros);

            let timer = RecoveryTimer {
                deadline,
                space,
                cancel_reason: None,
                is_active: true,
            };

            self.timers.insert(timer_id, timer);
        }
    }

    fn cancel_pto_timer(&mut self, space: PacketNumberSpace) {
        self.cancel_pto_timer_with_reason(space, None);
    }

    fn cancel_pto_timer_with_reason(
        &mut self,
        space: PacketNumberSpace,
        reason: Option<CancelReason>,
    ) {
        let timer_id = format!("pto_{}_{:?}", self.connection_id, space);
        if let Some(timer) = self.timers.get_mut(&timer_id) {
            timer.is_active = false;
            timer.cancel_reason = reason;
        }
    }

    fn handle_cancellation(&mut self, reason: CancelReason) -> AtpOutcome<Vec<RecoveryAction>> {
        // Cancel all active timers and record cancellation reason
        for timer in self.timers.values_mut() {
            if timer.is_active {
                timer.is_active = false;
                timer.cancel_reason = Some(reason.clone());
            }
        }

        self.log_event(RecoveryEventType::RecoveryStateChanged {
            old_state: format!("{:?}", self.transport.state()),
            new_state: "cancelled".to_string(),
            trigger: format!("cancellation: {}", reason.message().unwrap_or("unknown")),
        });

        AtpOutcome::cancelled(reason)
    }

    /// Cancel recovery operations with structured cancellation.
    ///
    /// This method integrates recovery timer cancellation with ATP's structured
    /// cancellation protocol, ensuring all timers are properly cancelled with
    /// the provided reason.
    pub async fn cancel_recovery(&mut self, cx: &Cx, reason: CancelReason) -> AtpOutcome<()> {
        cx.trace(&format!("atp_recovery_cancel {:?}", reason));

        // Check if we're already cancelled via Cx
        if let Some(cx_reason) = cx.cancel_reason() {
            // Use the Cx cancellation reason if available
            match self.handle_cancellation(cx_reason.clone()) {
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                _ => return AtpOutcome::cancelled(cx_reason),
            }
        }

        // Otherwise use the provided reason
        match self.handle_cancellation(reason.clone()) {
            Outcome::Cancelled(r) => AtpOutcome::cancelled(r),
            _ => AtpOutcome::cancelled(reason),
        }
    }

    /// Check if any recovery timers have been cancelled.
    ///
    /// Returns the cancellation reason for the first cancelled timer found,
    /// or None if no timers have been cancelled.
    pub fn cancellation_reason(&self) -> Option<&CancelReason> {
        self.timers
            .values()
            .find_map(|timer| timer.cancel_reason.as_ref())
    }

    /// Get the number of active timers.
    pub fn active_timer_count(&self) -> usize {
        self.timers.values().filter(|timer| timer.is_active).count()
    }

    /// Get the number of cancelled timers.
    pub fn cancelled_timer_count(&self) -> usize {
        self.timers
            .values()
            .filter(|timer| !timer.is_active && timer.cancel_reason.is_some())
            .count()
    }
}

impl RecoveryLogger {
    fn new(_connection_id: String) -> Self {
        Self {
            events: Vec::new(),
            sequence: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct RecoveryTelemetry {
    spaces: [RecoverySpaceTelemetry; 3],
}

#[derive(Debug, Clone)]
struct RecoverySpaceTelemetry {
    sent_packets: VecDeque<SentPacketMeta>,
    largest_acked: Option<u64>,
}

#[derive(Debug, Clone)]
struct RecoveryLossTelemetry {
    lost_packets: Vec<u64>,
    lost_bytes: u64,
    detection_method: LossDetectionMethod,
    loss_delay_micros: u64,
}

impl RecoveryTelemetry {
    fn new() -> Self {
        Self {
            spaces: std::array::from_fn(|_| RecoverySpaceTelemetry::new()),
        }
    }

    fn on_packet_sent(&mut self, packet: SentPacketMeta) {
        let space = &mut self.spaces[packet.space as usize];
        space.sent_packets.push_back(packet);
        if space.sent_packets.len() > 10_000 {
            space.sent_packets.pop_front();
        }
    }

    fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        acked_packets: &[u64],
        now_micros: u64,
        loss_delay_micros: u64,
    ) -> Option<RecoveryLossTelemetry> {
        if acked_packets.is_empty() {
            return None;
        }

        let space = &mut self.spaces[space as usize];
        let mut acked = acked_packets.to_vec();
        acked.sort_unstable();
        acked.dedup();

        let mut largest_newly_acked = None;
        let mut unacked = VecDeque::with_capacity(space.sent_packets.len());
        while let Some(packet) = space.sent_packets.pop_front() {
            if acked.binary_search(&packet.packet_number).is_ok() {
                largest_newly_acked = Some(
                    largest_newly_acked.map_or(packet.packet_number, |largest: u64| {
                        largest.max(packet.packet_number)
                    }),
                );
            } else {
                unacked.push_back(packet);
            }
        }
        space.sent_packets = unacked;

        if let Some(largest) = largest_newly_acked {
            space.largest_acked = Some(
                space
                    .largest_acked
                    .map_or(largest, |seen| seen.max(largest)),
            );
        }

        let largest_acked = space.largest_acked?;
        let time_threshold_micros = now_micros.saturating_sub(loss_delay_micros);
        let mut lost_packets = Vec::new();
        let mut lost_bytes = 0u64;
        let mut packet_threshold_lost = false;
        let mut time_threshold_lost = false;
        let mut survivors = VecDeque::with_capacity(space.sent_packets.len());

        while let Some(packet) = space.sent_packets.pop_front() {
            let lost_by_packet_threshold = packet.packet_number.saturating_add(3) <= largest_acked;
            let lost_by_time_threshold = packet.packet_number <= largest_acked
                && packet.time_sent_micros <= time_threshold_micros;

            if lost_by_packet_threshold || lost_by_time_threshold {
                packet_threshold_lost |= lost_by_packet_threshold;
                time_threshold_lost |= lost_by_time_threshold;
                lost_bytes = lost_bytes.saturating_add(packet.bytes);
                lost_packets.push(packet.packet_number);
            } else {
                survivors.push_back(packet);
            }
        }
        space.sent_packets = survivors;

        if lost_packets.is_empty() {
            return None;
        }

        let detection_method = match (packet_threshold_lost, time_threshold_lost) {
            (true, true) => LossDetectionMethod::BothThresholds,
            (true, false) => LossDetectionMethod::PacketThreshold,
            (false, true) => LossDetectionMethod::TimeThreshold,
            (false, false) => unreachable!("lost packet must have a threshold"),
        };

        Some(RecoveryLossTelemetry {
            lost_packets,
            lost_bytes,
            detection_method,
            loss_delay_micros,
        })
    }
}

impl RecoverySpaceTelemetry {
    fn new() -> Self {
        Self {
            sent_packets: VecDeque::new(),
            largest_acked: None,
        }
    }
}

mod packet_number_space_serde {
    use super::PacketNumberSpace;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    #[allow(clippy::ref_option)]
    pub(super) fn serialize_option<S>(
        value: &Option<PacketNumberSpace>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.map(packet_number_space_name).serialize(serializer)
    }

    pub(super) fn deserialize_option<'de, D>(
        deserializer: D,
    ) -> Result<Option<PacketNumberSpace>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Some(value) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };

        match value.as_str() {
            "initial" => Ok(Some(PacketNumberSpace::Initial)),
            "handshake" => Ok(Some(PacketNumberSpace::Handshake)),
            "application_data" => Ok(Some(PacketNumberSpace::ApplicationData)),
            other => Err(de::Error::unknown_variant(
                other,
                &["initial", "handshake", "application_data"],
            )),
        }
    }

    const fn packet_number_space_name(space: PacketNumberSpace) -> &'static str {
        match space {
            PacketNumberSpace::Initial => "initial",
            PacketNumberSpace::Handshake => "handshake",
            PacketNumberSpace::ApplicationData => "application_data",
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

    fn on_datagram_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
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

    fn sent_packet(
        space: PacketNumberSpace,
        packet_number: u64,
        time_sent_micros: u64,
    ) -> SentPacketMeta {
        SentPacketMeta {
            space,
            packet_number,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros,
        }
    }

    #[test]
    fn recovery_manager_lifecycle() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        let cx = Cx::for_testing();

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

        // No bytes received, can't send anything
        assert!(!tracker.can_send(1000));

        // Receive 400 bytes, can send up to 1200 bytes
        tracker.on_datagram_received(400);
        assert!(tracker.can_send(1000));
        assert!(tracker.can_send(1200));
        assert!(!tracker.can_send(1201));

        // Send 1000 bytes
        tracker.on_packet_sent(1000);

        // Only 200 bytes left
        assert!(tracker.can_send(200));
        assert!(!tracker.can_send(201));

        // Receiving an ACK validates the address.
        tracker.on_ack_received();
        assert!(tracker.can_send(5000)); // Address validated, can send freely
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

    #[test]
    fn ack_loss_logs_concrete_packets_method_delay_and_space() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        manager.anti_amplification.address_validated = true;

        for packet_number in 0..6 {
            let packet = sent_packet(
                PacketNumberSpace::ApplicationData,
                packet_number,
                10_000 + packet_number,
            );
            assert!(manager.on_packet_sent(packet).is_ok());
        }

        let ack = manager.on_ack_received(PacketNumberSpace::ApplicationData, &[5], 0, 20_000);
        assert!(ack.is_ok());

        let loss_event = manager
            .recovery_log()
            .iter()
            .find_map(|event| match &event.event_type {
                RecoveryEventType::LossDetected {
                    lost_packets,
                    detection_method,
                    loss_delay_micros,
                } => Some((
                    event.space,
                    lost_packets,
                    detection_method,
                    loss_delay_micros,
                )),
                _ => None,
            });
        assert!(loss_event.is_some(), "expected loss event in recovery log");
        let Some(loss_event) = loss_event else {
            return;
        };

        assert_eq!(loss_event.0, Some(PacketNumberSpace::ApplicationData));
        assert_eq!(loss_event.1, &vec![0, 1, 2]);
        assert!(matches!(loss_event.2, LossDetectionMethod::PacketThreshold));
        assert!(*loss_event.3 > 0);
    }

    #[test]
    fn pto_expiry_logs_incrementing_count_backoff_and_snapshot() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());

        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );
        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );

        let pto_events: Vec<_> = manager
            .recovery_log()
            .iter()
            .filter_map(|event| match event.event_type {
                RecoveryEventType::PtoExpired {
                    pto_count,
                    backoff_level,
                } => Some((
                    event.space,
                    pto_count,
                    backoff_level,
                    event.transport_state.pto_count,
                )),
                _ => None,
            })
            .collect();

        assert_eq!(
            pto_events,
            vec![
                (Some(PacketNumberSpace::ApplicationData), 1, 1, 1),
                (Some(PacketNumberSpace::ApplicationData), 2, 2, 2),
            ]
        );
    }

    #[test]
    fn ack_resets_pto_count_before_snapshot_logging() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        manager.anti_amplification.address_validated = true;
        assert!(
            manager
                .on_packet_sent(sent_packet(PacketNumberSpace::ApplicationData, 7, 10_000))
                .is_ok()
        );
        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );
        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );

        let ack = manager.on_ack_received(PacketNumberSpace::ApplicationData, &[7], 0, 20_000);
        assert!(ack.is_ok());

        let ack_event = manager
            .recovery_log()
            .iter()
            .find(|event| matches!(event.event_type, RecoveryEventType::AckReceived { .. }));
        assert!(ack_event.is_some(), "expected ack event in recovery log");
        let Some(ack_event) = ack_event else {
            return;
        };

        assert_eq!(ack_event.space, Some(PacketNumberSpace::ApplicationData));
        assert_eq!(ack_event.transport_state.pto_count, 0);
    }
}
