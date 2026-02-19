//! Native QUIC transport + loss-recovery state machine.
//!
//! This module keeps deterministic, runtime-agnostic transport logic:
//! packet accounting, RTT estimation, loss detection, and PTO scheduling.

use std::collections::VecDeque;
use std::fmt;

/// QUIC packet number space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketNumberSpace {
    /// Initial packets.
    Initial = 0,
    /// Handshake packets.
    Handshake = 1,
    /// Application-data (1-RTT) packets.
    ApplicationData = 2,
}

impl PacketNumberSpace {
    fn idx(self) -> usize {
        self as usize
    }
}

/// Sent packet metadata tracked for loss recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentPacketMeta {
    /// Number space.
    pub space: PacketNumberSpace,
    /// Packet number.
    pub packet_number: u64,
    /// Bytes in packet.
    pub bytes: u64,
    /// Whether the packet is ack-eliciting.
    pub ack_eliciting: bool,
    /// Whether bytes count towards bytes-in-flight.
    pub in_flight: bool,
    /// Monotonic send timestamp in microseconds.
    pub time_sent_micros: u64,
}

/// ACK processing summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckEvent {
    /// Number of acked packets found in sent history.
    pub acked_packets: usize,
    /// Number of packets newly marked lost.
    pub lost_packets: usize,
    /// Acked bytes counted in this event.
    pub acked_bytes: u64,
    /// Lost bytes counted in this event.
    pub lost_bytes: u64,
}

impl AckEvent {
    fn empty() -> Self {
        Self {
            acked_packets: 0,
            lost_packets: 0,
            acked_bytes: 0,
            lost_bytes: 0,
        }
    }
}

/// Inclusive ACK range (`smallest..=largest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    /// Largest acknowledged packet number.
    pub largest: u64,
    /// Smallest acknowledged packet number.
    pub smallest: u64,
}

impl AckRange {
    /// Construct a validated range.
    #[must_use]
    pub fn new(largest: u64, smallest: u64) -> Option<Self> {
        if smallest > largest {
            return None;
        }
        Some(Self { largest, smallest })
    }

    fn contains(self, packet_number: u64) -> bool {
        packet_number >= self.smallest && packet_number <= self.largest
    }
}

/// RTT estimator state.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RttEstimator {
    min_rtt_micros: Option<u64>,
    latest_rtt_micros: Option<u64>,
    smoothed_rtt_micros: Option<u64>,
    rttvar_micros: Option<u64>,
}

impl RttEstimator {
    /// Record one RTT sample (microseconds), applying ACK delay where valid.
    pub fn update(&mut self, sample_micros: u64, ack_delay_micros: u64) {
        if sample_micros == 0 {
            return;
        }
        self.min_rtt_micros = Some(
            self.min_rtt_micros
                .map_or(sample_micros, |min| min.min(sample_micros)),
        );
        let min_rtt = self.min_rtt_micros.unwrap_or(sample_micros);
        let adjusted = sample_micros.saturating_sub(ack_delay_micros.min(sample_micros - min_rtt));
        self.latest_rtt_micros = Some(adjusted);

        match (self.smoothed_rtt_micros, self.rttvar_micros) {
            (None, None) => {
                self.smoothed_rtt_micros = Some(adjusted);
                self.rttvar_micros = Some(adjusted / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                let abs_err = srtt.abs_diff(adjusted);
                let new_rttvar = ((3 * rttvar) + abs_err) / 4;
                let new_srtt = ((7 * srtt) + adjusted) / 8;
                self.rttvar_micros = Some(new_rttvar);
                self.smoothed_rtt_micros = Some(new_srtt);
            }
            _ => unreachable!("smoothed/rttvar tracked together"),
        }
    }

    /// Current smoothed RTT.
    #[must_use]
    pub fn smoothed_rtt_micros(&self) -> Option<u64> {
        self.smoothed_rtt_micros
    }

    /// Latest RTT sample.
    #[must_use]
    pub fn latest_rtt_micros(&self) -> Option<u64> {
        self.latest_rtt_micros
    }

    /// Current RTT variance.
    #[must_use]
    pub fn rttvar_micros(&self) -> Option<u64> {
        self.rttvar_micros
    }
}

/// Transport state machine errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Transition was invalid for the current state.
    InvalidStateTransition {
        /// Current state.
        from: QuicConnectionState,
        /// Requested state.
        to: QuicConnectionState,
    },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStateTransition { from, to } => {
                write!(f, "invalid transport state transition: {from:?} -> {to:?}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectionState {
    /// No packets sent.
    Idle,
    /// Handshake in progress.
    Handshaking,
    /// 1-RTT established.
    Established,
    /// Connection close initiated; draining in progress.
    Draining,
    /// Terminal closed state.
    Closed,
}

#[derive(Debug, Clone)]
struct LossRecovery {
    sent_packets: VecDeque<SentPacketMeta>,
    largest_acked: [Option<u64>; 3],
    bytes_in_flight: u64,
    pto_count: u32,
    max_ack_delay_micros: u64,
    rtt: RttEstimator,
    congestion_window_bytes: u64,
    ssthresh_bytes: u64,
    max_datagram_size: u64,
}

impl Default for LossRecovery {
    fn default() -> Self {
        Self {
            sent_packets: VecDeque::new(),
            largest_acked: [None, None, None],
            bytes_in_flight: 0,
            pto_count: 0,
            max_ack_delay_micros: 25_000,
            rtt: RttEstimator::default(),
            congestion_window_bytes: 12_000,
            ssthresh_bytes: u64::MAX,
            max_datagram_size: 1_200,
        }
    }
}

impl LossRecovery {
    fn on_packet_sent(&mut self, packet: SentPacketMeta) {
        if packet.in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(packet.bytes);
        }
        self.sent_packets.push_back(packet);
    }

    fn on_ack_from_packet_numbers(
        &mut self,
        space: PacketNumberSpace,
        acked_packet_numbers: &[u64],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> AckEvent {
        let ranges = ack_ranges_from_packet_numbers(acked_packet_numbers);
        self.on_ack_ranges(space, &ranges, ack_delay_micros, now_micros)
    }

    fn on_ack_ranges(
        &mut self,
        space: PacketNumberSpace,
        ack_ranges: &[AckRange],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> AckEvent {
        if ack_ranges.is_empty() {
            return AckEvent::empty();
        }
        let largest_acked = ack_ranges
            .iter()
            .map(|range| range.largest)
            .max()
            .unwrap_or(0);
        self.largest_acked[space.idx()] =
            Some(self.largest_acked[space.idx()].map_or(largest_acked, |v| v.max(largest_acked)));

        let loss_delay = self.loss_delay_micros();
        let time_threshold = now_micros.saturating_sub(loss_delay);
        let mut event = AckEvent::empty();

        let mut retained = VecDeque::with_capacity(self.sent_packets.len());
        while let Some(pkt) = self.sent_packets.pop_front() {
            let acked = pkt.space == space
                && ack_ranges
                    .iter()
                    .copied()
                    .any(|range| range.contains(pkt.packet_number));
            if acked {
                event.acked_packets += 1;
                if pkt.in_flight {
                    event.acked_bytes = event.acked_bytes.saturating_add(pkt.bytes);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes);
                }
                let sample = now_micros.saturating_sub(pkt.time_sent_micros);
                if pkt.ack_eliciting {
                    self.rtt.update(sample, ack_delay_micros);
                }
            } else {
                retained.push_back(pkt);
            }
        }
        self.sent_packets = retained;

        // Packet-threshold loss detection (kPacketThreshold = 3)
        let mut survivors = VecDeque::with_capacity(self.sent_packets.len());
        while let Some(pkt) = self.sent_packets.pop_front() {
            let packet_threshold_lost =
                pkt.space == space && pkt.packet_number.saturating_add(3) <= largest_acked;
            let time_threshold_lost = pkt.space == space
                && pkt.packet_number <= largest_acked
                && pkt.time_sent_micros <= time_threshold;
            let lost = packet_threshold_lost || time_threshold_lost;
            if lost {
                event.lost_packets += 1;
                if pkt.in_flight {
                    event.lost_bytes = event.lost_bytes.saturating_add(pkt.bytes);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes);
                }
            } else {
                survivors.push_back(pkt);
            }
        }
        self.sent_packets = survivors;

        if event.acked_packets > 0 {
            self.pto_count = 0;
            self.on_ack_congestion(event.acked_bytes);
        }
        if event.lost_packets > 0 {
            self.on_loss_congestion();
        }
        event
    }

    fn loss_delay_micros(&self) -> u64 {
        let base_rtt = self
            .rtt
            .latest_rtt_micros()
            .unwrap_or_else(|| self.rtt.smoothed_rtt_micros().unwrap_or(333_000));
        ((9 * base_rtt) / 8).max(1_000)
    }

    fn on_ack_congestion(&mut self, acked_bytes: u64) {
        if self.congestion_window_bytes < self.ssthresh_bytes {
            self.congestion_window_bytes = self.congestion_window_bytes.saturating_add(acked_bytes);
        } else {
            let increment = (self.max_datagram_size.saturating_mul(acked_bytes))
                .saturating_div(self.congestion_window_bytes.max(1));
            self.congestion_window_bytes = self
                .congestion_window_bytes
                .saturating_add(increment.max(1));
        }
    }

    fn on_loss_congestion(&mut self) {
        let min_cwnd = self.max_datagram_size.saturating_mul(2);
        let reduced = (self.congestion_window_bytes / 2).max(min_cwnd);
        self.ssthresh_bytes = reduced;
        self.congestion_window_bytes = reduced;
    }

    fn pto_deadline_micros(&self, now_micros: u64) -> Option<u64> {
        if self.bytes_in_flight == 0 {
            return None;
        }
        let srtt = self.rtt.smoothed_rtt_micros().unwrap_or(333_000);
        let rttvar = self.rtt.rttvar_micros().unwrap_or(srtt / 2);
        let granularity = 1_000;
        let mut timeout = srtt + (4 * rttvar).max(granularity);
        timeout = timeout.saturating_add(self.max_ack_delay_micros);
        let backoff = 1u64 << self.pto_count.min(10);
        Some(now_micros.saturating_add(timeout.saturating_mul(backoff)))
    }
}

fn ack_ranges_from_packet_numbers(acked_packet_numbers: &[u64]) -> Vec<AckRange> {
    if acked_packet_numbers.is_empty() {
        return Vec::new();
    }
    let mut sorted = acked_packet_numbers.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut ranges = Vec::new();
    let mut smallest = sorted[0];
    let mut largest = sorted[0];
    for pn in sorted.iter().copied().skip(1) {
        if pn == largest.saturating_add(1) {
            largest = pn;
            continue;
        }
        ranges.push(AckRange { largest, smallest });
        smallest = pn;
        largest = pn;
    }
    ranges.push(AckRange { largest, smallest });
    ranges
}

/// Native transport connection machine.
#[derive(Debug, Clone)]
pub struct QuicTransportMachine {
    state: QuicConnectionState,
    recovery: LossRecovery,
    drain_deadline_micros: Option<u64>,
    close_code: Option<u64>,
}

impl Default for QuicTransportMachine {
    fn default() -> Self {
        Self {
            state: QuicConnectionState::Idle,
            recovery: LossRecovery::default(),
            drain_deadline_micros: None,
            close_code: None,
        }
    }
}

impl QuicTransportMachine {
    /// Create a new transport machine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current connection state.
    #[must_use]
    pub fn state(&self) -> QuicConnectionState {
        self.state
    }

    /// Current bytes in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.recovery.bytes_in_flight
    }

    /// Current congestion window (bytes).
    #[must_use]
    pub fn congestion_window_bytes(&self) -> u64 {
        self.recovery.congestion_window_bytes
    }

    /// Current slow-start threshold (bytes).
    #[must_use]
    pub fn ssthresh_bytes(&self) -> u64 {
        self.recovery.ssthresh_bytes
    }

    /// Whether another in-flight packet can be sent under congestion limits.
    #[must_use]
    pub fn can_send(&self, in_flight_bytes: u64) -> bool {
        self.recovery
            .bytes_in_flight
            .saturating_add(in_flight_bytes)
            <= self.recovery.congestion_window_bytes
    }

    /// Begin handshake progression.
    pub fn begin_handshake(&mut self) -> Result<(), TransportError> {
        self.transition(QuicConnectionState::Handshaking)
    }

    /// Mark connection established.
    pub fn on_established(&mut self) -> Result<(), TransportError> {
        self.transition(QuicConnectionState::Established)
    }

    /// Start draining with a timeout window.
    pub fn start_draining(
        &mut self,
        now_micros: u64,
        drain_timeout_micros: u64,
    ) -> Result<(), TransportError> {
        self.transition(QuicConnectionState::Draining)?;
        self.drain_deadline_micros = Some(now_micros.saturating_add(drain_timeout_micros));
        Ok(())
    }

    /// Start draining and record application close code.
    pub fn start_draining_with_code(
        &mut self,
        now_micros: u64,
        drain_timeout_micros: u64,
        code: u64,
    ) -> Result<(), TransportError> {
        self.start_draining(now_micros, drain_timeout_micros)?;
        self.close_code = Some(code);
        Ok(())
    }

    /// Close the connection immediately with an application error code.
    pub fn close_immediately(&mut self, code: u64) {
        self.state = QuicConnectionState::Closed;
        self.drain_deadline_micros = None;
        self.close_code = Some(code);
    }

    /// Poll draining timer; transitions to `Closed` when deadline is reached.
    pub fn poll(&mut self, now_micros: u64) {
        if self.state == QuicConnectionState::Draining
            && self
                .drain_deadline_micros
                .is_some_and(|deadline| now_micros >= deadline)
        {
            self.state = QuicConnectionState::Closed;
        }
    }

    /// Track packet transmission.
    pub fn on_packet_sent(&mut self, packet: SentPacketMeta) {
        self.recovery.on_packet_sent(packet);
    }

    /// Process ACK reception.
    pub fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        acked_packet_numbers: &[u64],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> AckEvent {
        self.recovery.on_ack_from_packet_numbers(
            space,
            acked_packet_numbers,
            ack_delay_micros,
            now_micros,
        )
    }

    /// Process ACK reception via explicit ranges.
    pub fn on_ack_ranges(
        &mut self,
        space: PacketNumberSpace,
        ack_ranges: &[AckRange],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> AckEvent {
        self.recovery
            .on_ack_ranges(space, ack_ranges, ack_delay_micros, now_micros)
    }

    /// Compute PTO deadline from current recovery state.
    #[must_use]
    pub fn pto_deadline_micros(&self, now_micros: u64) -> Option<u64> {
        self.recovery.pto_deadline_micros(now_micros)
    }

    /// Record a PTO timer expiration (backoff signal).
    pub fn on_pto_expired(&mut self) {
        self.recovery.pto_count = self.recovery.pto_count.saturating_add(1);
    }

    /// Current RTT estimator snapshot.
    #[must_use]
    pub fn rtt(&self) -> &RttEstimator {
        &self.recovery.rtt
    }

    /// Close code, if connection is closed with application error.
    #[must_use]
    pub fn close_code(&self) -> Option<u64> {
        self.close_code
    }

    fn transition(&mut self, to: QuicConnectionState) -> Result<(), TransportError> {
        use QuicConnectionState::{Closed, Draining, Established, Handshaking, Idle};
        let ok = matches!(
            (self.state, to),
            (Idle, Handshaking)
                | (Handshaking, Established | Draining)
                | (Established, Draining)
                | (Draining, Closed)
        );
        if ok {
            self.state = to;
            Ok(())
        } else if self.state == to {
            Ok(())
        } else {
            Err(TransportError::InvalidStateTransition {
                from: self.state,
                to,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(space: PacketNumberSpace, pn: u64, t: u64) -> SentPacketMeta {
        SentPacketMeta {
            space,
            packet_number: pn,
            bytes: 100,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: t,
        }
    }

    #[test]
    fn transport_state_transitions() {
        let mut t = QuicTransportMachine::new();
        assert_eq!(t.state(), QuicConnectionState::Idle);
        t.begin_handshake().expect("handshake");
        assert_eq!(t.state(), QuicConnectionState::Handshaking);
        t.on_established().expect("established");
        assert_eq!(t.state(), QuicConnectionState::Established);
        t.start_draining(1_000, 500).expect("drain");
        assert_eq!(t.state(), QuicConnectionState::Draining);
        t.poll(1_499);
        assert_eq!(t.state(), QuicConnectionState::Draining);
        t.poll(1_500);
        assert_eq!(t.state(), QuicConnectionState::Closed);
    }

    #[test]
    fn loss_recovery_ack_and_loss_detection() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().expect("hs");
        t.on_established().expect("est");

        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 10_000));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 2, 10_100));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 3, 10_200));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 4, 10_300));
        assert_eq!(t.bytes_in_flight(), 400);

        // Ack packet 4 only; packet threshold should mark packet 1 lost.
        let event = t.on_ack_received(PacketNumberSpace::ApplicationData, &[4], 0, 20_000);
        assert_eq!(event.acked_packets, 1);
        assert_eq!(event.lost_packets, 1);
        assert_eq!(t.bytes_in_flight(), 200);
    }

    #[test]
    fn packet_threshold_loss_does_not_overflow_near_u64_max() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            u64::MAX - 2,
            10_000,
        ));
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            u64::MAX - 1,
            10_100,
        ));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, u64::MAX, 10_200));

        let event = t.on_ack_received(PacketNumberSpace::ApplicationData, &[u64::MAX], 0, 20_000);
        assert_eq!(event.acked_packets, 1);
        assert_eq!(event.lost_packets, 2);
    }

    #[test]
    fn ack_ranges_allow_sparse_ack_processing() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 1_000));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 2, 1_100));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 3, 1_200));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 9, 1_300));
        let ranges = [
            AckRange::new(3, 2).expect("range"),
            AckRange::new(9, 9).expect("range"),
        ];
        let event = t.on_ack_ranges(PacketNumberSpace::ApplicationData, &ranges, 0, 10_000);
        assert_eq!(event.acked_packets, 3);
        assert_eq!(event.acked_bytes, 300);
    }

    #[test]
    fn ack_range_builder_deduplicates_and_compacts() {
        let ranges = ack_ranges_from_packet_numbers(&[5, 3, 4, 4, 10, 12, 11]);
        assert_eq!(
            ranges,
            vec![
                AckRange::new(5, 3).expect("range"),
                AckRange::new(12, 10).expect("range"),
            ]
        );
    }

    #[test]
    fn pto_deadline_is_computable() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 0, 1_000));
        // No RTT sample yet: fallback timeout is used.
        let deadline = t.pto_deadline_micros(1_500).expect("deadline");
        assert!(deadline > 1_500);
    }

    #[test]
    fn pto_deadline_none_when_nothing_in_flight() {
        let t = QuicTransportMachine::new();
        assert!(t.pto_deadline_micros(10_000).is_none());
    }

    #[test]
    fn pto_backoff_increases_after_timeout() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 1, 1_000));
        let first = t.pto_deadline_micros(2_000).expect("first deadline");
        t.on_pto_expired();
        let second = t.pto_deadline_micros(2_000).expect("second deadline");
        assert!(second > first);
    }

    #[test]
    fn immediate_close_sets_terminal_state_and_code() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().expect("handshake");
        t.close_immediately(0x1337);
        assert_eq!(t.state(), QuicConnectionState::Closed);
        assert_eq!(t.close_code(), Some(0x1337));
    }

    #[test]
    fn start_draining_with_code_sets_close_code() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().expect("handshake");
        t.start_draining_with_code(1_000, 500, 0x42)
            .expect("draining");
        assert_eq!(t.state(), QuicConnectionState::Draining);
        assert_eq!(t.close_code(), Some(0x42));
    }

    #[test]
    fn rtt_updates_on_ack() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 9, 50_000));
        let event = t.on_ack_received(PacketNumberSpace::ApplicationData, &[9], 2_000, 70_000);
        assert_eq!(event.acked_packets, 1);
        assert!(t.rtt().smoothed_rtt_micros().is_some());
    }

    #[test]
    fn congestion_window_grows_on_acks_and_shrinks_on_loss() {
        let mut t = QuicTransportMachine::new();
        let initial_cwnd = t.congestion_window_bytes();
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 10_000));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 2, 10_050));
        let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[1], 0, 20_000);
        assert!(t.congestion_window_bytes() > initial_cwnd);

        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 3, 10_100));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 4, 10_150));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 5, 10_200));
        let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[5], 0, 20_050);
        assert!(t.congestion_window_bytes() <= t.ssthresh_bytes());
    }

    #[test]
    fn can_send_obeys_congestion_window() {
        let mut t = QuicTransportMachine::new();
        assert!(t.can_send(1_200));
        for pn in 0..20 {
            if !t.can_send(1_200) {
                break;
            }
            t.on_packet_sent(sent(PacketNumberSpace::Initial, pn, 1_000 + pn));
        }
        assert!(!t.can_send(t.congestion_window_bytes()));
    }

    // ---- RttEstimator ----

    #[test]
    fn rtt_estimator_default_is_none() {
        let rtt = RttEstimator::default();
        assert_eq!(rtt.smoothed_rtt_micros(), None);
        assert_eq!(rtt.rttvar_micros(), None);
    }

    #[test]
    fn rtt_estimator_ignores_zero_sample() {
        let mut rtt = RttEstimator::default();
        rtt.update(0, 0);
        assert_eq!(rtt.smoothed_rtt_micros(), None);
    }

    #[test]
    fn rtt_estimator_first_sample_sets_values() {
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0);
        assert_eq!(rtt.smoothed_rtt_micros(), Some(100_000));
        assert_eq!(rtt.rttvar_micros(), Some(50_000)); // initial/2
    }

    #[test]
    fn rtt_estimator_second_sample_ewma() {
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0);
        rtt.update(80_000, 0);
        // EWMA: srtt = (7*100_000 + 80_000)/8 = 97_500
        assert_eq!(rtt.smoothed_rtt_micros(), Some(97_500));
        // rttvar = (3*50_000 + |100_000-80_000|)/4 = (150_000 + 20_000)/4 = 42_500
        assert_eq!(rtt.rttvar_micros(), Some(42_500));
    }

    // ---- TransportError ----

    #[test]
    fn transport_error_display() {
        let err = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Established,
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid transport state transition"), "{msg}");
        assert!(msg.contains("Idle"), "{msg}");
        assert!(msg.contains("Established"), "{msg}");
    }

    #[test]
    fn transport_error_source_is_none() {
        use std::error::Error;
        let err = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Closed,
        };
        assert!(err.source().is_none());
    }

    // ---- State transitions ----

    #[test]
    fn invalid_state_transition_idle_to_established() {
        let mut t = QuicTransportMachine::new();
        let err = t.on_established().unwrap_err();
        assert!(matches!(err, TransportError::InvalidStateTransition { .. }));
    }

    #[test]
    fn invalid_state_transition_established_to_handshaking() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().unwrap();
        t.on_established().unwrap();
        let err = t.begin_handshake().unwrap_err();
        assert!(matches!(err, TransportError::InvalidStateTransition { .. }));
    }

    #[test]
    fn same_state_transition_is_idempotent() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().unwrap();
        // Same state should be a no-op success
        t.begin_handshake().expect("idempotent");
        assert_eq!(t.state(), QuicConnectionState::Handshaking);
    }

    #[test]
    fn handshaking_can_drain_directly() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().unwrap();
        t.start_draining(1000, 500)
            .expect("handshaking -> draining");
        assert_eq!(t.state(), QuicConnectionState::Draining);
    }

    // ---- QuicConnectionState ----

    #[test]
    fn connection_state_debug() {
        assert_eq!(format!("{:?}", QuicConnectionState::Idle), "Idle");
        assert_eq!(
            format!("{:?}", QuicConnectionState::Handshaking),
            "Handshaking"
        );
        assert_eq!(
            format!("{:?}", QuicConnectionState::Established),
            "Established"
        );
        assert_eq!(format!("{:?}", QuicConnectionState::Draining), "Draining");
        assert_eq!(format!("{:?}", QuicConnectionState::Closed), "Closed");
    }

    // ---- PacketNumberSpace ----

    #[test]
    fn packet_number_space_idx_values() {
        assert_eq!(PacketNumberSpace::Initial.idx(), 0);
        assert_eq!(PacketNumberSpace::Handshake.idx(), 1);
        assert_eq!(PacketNumberSpace::ApplicationData.idx(), 2);
    }

    // ---- AckEvent ----

    #[test]
    fn ack_event_empty() {
        let e = AckEvent::empty();
        assert_eq!(e.acked_packets, 0);
        assert_eq!(e.lost_packets, 0);
        assert_eq!(e.acked_bytes, 0);
        assert_eq!(e.lost_bytes, 0);
    }

    #[test]
    fn ack_empty_packet_numbers_returns_empty_event() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 0, 1000));
        let event = t.on_ack_received(PacketNumberSpace::Initial, &[], 0, 2000);
        assert_eq!(event.acked_packets, 0);
    }

    // ---- close_immediately ----

    #[test]
    fn close_immediately_clears_drain_deadline() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().unwrap();
        t.on_established().unwrap();
        t.start_draining(1000, 5000).unwrap();
        assert_eq!(t.state(), QuicConnectionState::Draining);
        t.close_immediately(0);
        assert_eq!(t.state(), QuicConnectionState::Closed);
        assert_eq!(t.close_code(), Some(0));
    }

    #[test]
    fn close_code_none_before_close() {
        let t = QuicTransportMachine::new();
        assert_eq!(t.close_code(), None);
    }

    // ---- Non-ack-eliciting packet ----

    #[test]
    fn non_ack_eliciting_packet_no_rtt_update() {
        let mut t = QuicTransportMachine::new();
        let pkt = SentPacketMeta {
            space: PacketNumberSpace::ApplicationData,
            packet_number: 1,
            bytes: 50,
            ack_eliciting: false,
            in_flight: true,
            time_sent_micros: 10_000,
        };
        t.on_packet_sent(pkt);
        t.on_ack_received(PacketNumberSpace::ApplicationData, &[1], 0, 20_000);
        // Non-ack-eliciting: RTT should not be updated
        assert_eq!(t.rtt().smoothed_rtt_micros(), None);
    }

    #[test]
    fn non_in_flight_packet_not_counted_in_bytes() {
        let mut t = QuicTransportMachine::new();
        let pkt = SentPacketMeta {
            space: PacketNumberSpace::Initial,
            packet_number: 0,
            bytes: 200,
            ack_eliciting: true,
            in_flight: false,
            time_sent_micros: 1000,
        };
        t.on_packet_sent(pkt);
        assert_eq!(t.bytes_in_flight(), 0);
        let ack = t.on_ack_received(PacketNumberSpace::Initial, &[0], 0, 2_000);
        assert_eq!(ack.acked_packets, 1);
        assert_eq!(ack.acked_bytes, 0);
    }

    // ---- Gap 1: Draining -> Established via on_established() is invalid ----

    #[test]
    fn draining_to_established_is_invalid() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().unwrap();
        t.on_established().unwrap();
        t.start_draining(1_000, 5_000).unwrap();
        assert_eq!(t.state(), QuicConnectionState::Draining);
        let err = t.on_established().unwrap_err();
        assert_eq!(
            err,
            TransportError::InvalidStateTransition {
                from: QuicConnectionState::Draining,
                to: QuicConnectionState::Established,
            }
        );
        // State unchanged after rejection
        assert_eq!(t.state(), QuicConnectionState::Draining);
    }

    // ---- Gap 2: Closed -> * transitions all produce InvalidStateTransition ----

    #[test]
    fn closed_to_any_transition_is_invalid() {
        // Closed -> Handshaking
        let mut t = QuicTransportMachine::new();
        t.close_immediately(0);
        assert_eq!(t.state(), QuicConnectionState::Closed);
        let err = t.begin_handshake().unwrap_err();
        assert_eq!(
            err,
            TransportError::InvalidStateTransition {
                from: QuicConnectionState::Closed,
                to: QuicConnectionState::Handshaking,
            }
        );

        // Closed -> Established
        let mut t2 = QuicTransportMachine::new();
        t2.close_immediately(0);
        let err = t2.on_established().unwrap_err();
        assert_eq!(
            err,
            TransportError::InvalidStateTransition {
                from: QuicConnectionState::Closed,
                to: QuicConnectionState::Established,
            }
        );

        // Closed -> Draining
        let mut t3 = QuicTransportMachine::new();
        t3.close_immediately(0);
        let err = t3.start_draining(1_000, 5_000).unwrap_err();
        assert_eq!(
            err,
            TransportError::InvalidStateTransition {
                from: QuicConnectionState::Closed,
                to: QuicConnectionState::Draining,
            }
        );
    }

    #[test]
    fn closed_to_closed_is_idempotent() {
        // Closed -> Closed is same-state, should be Ok (idempotent)
        let mut t = QuicTransportMachine::new();
        t.close_immediately(0);
        assert_eq!(t.state(), QuicConnectionState::Closed);
        // close_immediately bypasses transition(), so use poll to stay closed
        t.poll(999_999);
        assert_eq!(t.state(), QuicConnectionState::Closed);
    }

    // ---- Gap 3: AckRange::new with smallest > largest returns None ----

    #[test]
    fn ack_range_new_invalid_returns_none() {
        assert!(AckRange::new(5, 10).is_none());
        assert!(AckRange::new(0, 1).is_none());
        assert!(AckRange::new(100, u64::MAX).is_none());
    }

    #[test]
    fn ack_range_new_equal_returns_some() {
        let range = AckRange::new(7, 7).expect("equal range should be valid");
        assert_eq!(range.largest, 7);
        assert_eq!(range.smallest, 7);
        assert!(range.contains(7));
        assert!(!range.contains(6));
        assert!(!range.contains(8));
    }

    // ---- Gap 4: Time-threshold loss detection ----

    #[test]
    fn time_threshold_loss_detection() {
        let mut t = QuicTransportMachine::new();
        // First, establish an RTT sample so loss_delay_micros is deterministic.
        // Send pkt 0 at t=10_000, ack at t=20_000 => RTT=10_000 us
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 0, 10_000));
        let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[0], 0, 20_000);
        // smoothed_rtt = 10_000, loss_delay = max(9*10_000/8, 1_000) = 11_250

        // Send pkt 1 at t=30_000, pkt 2 at t=30_100
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 30_000));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 2, 30_100));

        // Ack pkt 2 at time that is NOT enough past pkt 1 send for time-threshold.
        // Packet threshold: pkt 1 + 3 = 4, largest_acked = 2, so 4 > 2, NOT packet-threshold lost.
        // Time threshold: pkt 1 sent at 30_000, now=40_000, threshold=40_000-11_250=28_750.
        // pkt 1 sent at 30_000 > 28_750, so NOT time-threshold lost either.
        let event1 = t.on_ack_received(PacketNumberSpace::ApplicationData, &[2], 0, 40_000);
        assert_eq!(event1.acked_packets, 1);
        assert_eq!(event1.lost_packets, 0, "pkt 1 should NOT be lost yet");

        // Now send pkt 3 and ack it at t=50_000 (further in the future).
        // pkt 1 sent at 30_000, time_threshold = 50_000 - 11_250 = 38_750
        // pkt 1 sent at 30_000 <= 38_750, and pkt 1 <= largest_acked=3, so time-threshold lost!
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 3, 40_100));
        let event2 = t.on_ack_received(PacketNumberSpace::ApplicationData, &[3], 0, 50_000);
        assert_eq!(event2.acked_packets, 1);
        assert_eq!(
            event2.lost_packets, 1,
            "pkt 1 should be lost via time threshold"
        );
        assert_eq!(event2.lost_bytes, 100);
    }

    // ---- Gap 5: Congestion avoidance branch (AIMD after loss) ----

    #[test]
    fn congestion_avoidance_aimd_increment() {
        let mut t = QuicTransportMachine::new();
        let initial_cwnd = t.congestion_window_bytes(); // 12_000
        assert_eq!(t.ssthresh_bytes(), u64::MAX); // slow start initially

        // Trigger loss to set ssthresh via on_loss_congestion.
        // Send packets 0..5, ack only pkt 5 => pkt 0,1,2 lost (packet threshold).
        for pn in 0..6 {
            t.on_packet_sent(sent(
                PacketNumberSpace::ApplicationData,
                pn,
                10_000 + pn * 100,
            ));
        }
        let event = t.on_ack_received(PacketNumberSpace::ApplicationData, &[5], 0, 50_000);
        assert!(event.lost_packets > 0, "should have loss");
        let ssthresh_after_loss = t.ssthresh_bytes();
        assert!(
            ssthresh_after_loss < initial_cwnd,
            "ssthresh should be reduced: {} < {}",
            ssthresh_after_loss,
            initial_cwnd
        );
        assert_eq!(t.congestion_window_bytes(), ssthresh_after_loss);

        // Now ack the remaining unacked packets (3 and 4) to clear them out
        // so they don't trigger spurious loss on the next ack.
        let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[3, 4], 0, 51_000);

        // Now cwnd >= ssthresh, so we are in congestion avoidance.
        let cwnd_before = t.congestion_window_bytes();
        assert!(
            cwnd_before >= t.ssthresh_bytes(),
            "should be in congestion avoidance"
        );

        // Send a single packet and ack it; no loss this time.
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 10, 60_000));
        let ack_event = t.on_ack_received(PacketNumberSpace::ApplicationData, &[10], 0, 70_000);
        assert_eq!(ack_event.lost_packets, 0, "no further loss expected");
        let cwnd_after = t.congestion_window_bytes();

        // AIMD increment: (max_datagram_size * acked_bytes) / cwnd
        // = (1200 * 100) / cwnd_before, at least 1
        assert!(
            cwnd_after > cwnd_before,
            "cwnd should grow in congestion avoidance: {} > {}",
            cwnd_after,
            cwnd_before
        );
        let growth = cwnd_after - cwnd_before;
        // Growth should be much less than acked_bytes (100), because AIMD is additive.
        assert!(
            growth < 100,
            "congestion avoidance growth should be less than acked_bytes: {} < 100",
            growth
        );
    }

    // ---- Gap 6: Multiple PTO backoff levels, capped at pto_count=10 ----

    #[test]
    fn pto_backoff_caps_at_count_10() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 1, 1_000));

        // Fire PTO 12 times to go past the cap
        for _ in 0..12 {
            t.on_pto_expired();
        }
        // pto_count is now 12, but backoff uses min(pto_count, 10)
        let deadline_at_12 = t.pto_deadline_micros(100_000).expect("deadline at 12");

        // Reset and fire exactly 10 times
        let mut t2 = QuicTransportMachine::new();
        t2.on_packet_sent(sent(PacketNumberSpace::Initial, 1, 1_000));
        for _ in 0..10 {
            t2.on_pto_expired();
        }
        let deadline_at_10 = t2.pto_deadline_micros(100_000).expect("deadline at 10");

        // Both should produce the same deadline because backoff is capped at 2^10
        assert_eq!(
            deadline_at_12, deadline_at_10,
            "PTO backoff should be capped at pto_count=10: {} == {}",
            deadline_at_12, deadline_at_10
        );

        // Verify the backoff is indeed 2^10 = 1024 times the base timeout
        let mut t3 = QuicTransportMachine::new();
        t3.on_packet_sent(sent(PacketNumberSpace::Initial, 1, 1_000));
        let base_deadline = t3.pto_deadline_micros(100_000).expect("base deadline");
        let base_timeout = base_deadline - 100_000;
        let capped_timeout = deadline_at_10 - 100_000;
        assert_eq!(
            capped_timeout,
            base_timeout * 1024,
            "backoff at 10 should be 1024x base"
        );
    }

    // ---- Gap 7: on_ack_ranges with empty ranges slice ----

    #[test]
    fn on_ack_ranges_empty_slice_returns_empty_event() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 10_000));
        t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 2, 10_100));
        assert_eq!(t.bytes_in_flight(), 200);

        let event = t.on_ack_ranges(PacketNumberSpace::ApplicationData, &[], 0, 20_000);
        assert_eq!(event, AckEvent::empty());
        // Nothing changed
        assert_eq!(t.bytes_in_flight(), 200);
    }

    // ---- Gap 8: RttEstimator with large ack_delay edge cases ----

    #[test]
    fn rtt_estimator_large_ack_delay_clamped() {
        let mut rtt = RttEstimator::default();
        // First sample: 50_000us with zero ack_delay to establish min_rtt
        rtt.update(50_000, 0);
        assert_eq!(rtt.smoothed_rtt_micros(), Some(50_000));

        // Second sample: 80_000us with ack_delay larger than (sample - min_rtt)
        // ack_delay is clamped to min(ack_delay, sample - min_rtt) = min(1_000_000, 80_000 - 50_000) = 30_000
        // adjusted = 80_000 - 30_000 = 50_000
        rtt.update(80_000, 1_000_000);
        // srtt = (7*50_000 + 50_000)/8 = 50_000 (no change since adjusted == smoothed)
        assert_eq!(rtt.smoothed_rtt_micros(), Some(50_000));
    }

    #[test]
    fn rtt_estimator_ack_delay_equal_to_sample() {
        let mut rtt = RttEstimator::default();
        // First sample: 100_000us; ack_delay = 100_000 (equal to sample)
        // min_rtt = 100_000
        // ack_delay.min(sample - min_rtt) = 100_000.min(0) = 0
        // adjusted = 100_000 - 0 = 100_000
        rtt.update(100_000, 100_000);
        assert_eq!(rtt.smoothed_rtt_micros(), Some(100_000));
        assert_eq!(rtt.latest_rtt_micros(), Some(100_000));
    }

    #[test]
    fn rtt_estimator_very_large_sample_saturating() {
        let mut rtt = RttEstimator::default();
        // Very large sample near u64 limits
        rtt.update(u64::MAX / 2, 0);
        assert_eq!(rtt.smoothed_rtt_micros(), Some(u64::MAX / 2));
        assert_eq!(rtt.rttvar_micros(), Some((u64::MAX / 2) / 2));
    }

    // ---- Gap 9: Bytes-in-flight across Initial/Handshake spaces ----

    #[test]
    fn bytes_in_flight_across_initial_and_handshake_spaces() {
        let mut t = QuicTransportMachine::new();

        // Send packets in Initial space
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 0, 1_000));
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 1, 1_100));
        assert_eq!(t.bytes_in_flight(), 200);

        // Send packets in Handshake space
        t.on_packet_sent(sent(PacketNumberSpace::Handshake, 0, 2_000));
        t.on_packet_sent(sent(PacketNumberSpace::Handshake, 1, 2_100));
        assert_eq!(t.bytes_in_flight(), 400);

        // Ack one Initial packet
        let event_init = t.on_ack_received(PacketNumberSpace::Initial, &[0], 0, 3_000);
        assert_eq!(event_init.acked_packets, 1);
        assert_eq!(event_init.acked_bytes, 100);
        assert_eq!(t.bytes_in_flight(), 300);

        // Ack one Handshake packet
        let event_hs = t.on_ack_received(PacketNumberSpace::Handshake, &[1], 0, 3_100);
        assert_eq!(event_hs.acked_packets, 1);
        assert_eq!(event_hs.acked_bytes, 100);
        assert_eq!(t.bytes_in_flight(), 200);

        // Cross-space ack should NOT ack packets from wrong space
        let event_cross = t.on_ack_received(PacketNumberSpace::Initial, &[0, 1], 0, 4_000);
        // pn 0 already acked, pn 1 is still there; should ack pn 1
        assert_eq!(event_cross.acked_packets, 1);
        assert_eq!(t.bytes_in_flight(), 100);

        // Remaining: Handshake pn 0
        let event_final = t.on_ack_received(PacketNumberSpace::Handshake, &[0], 0, 5_000);
        assert_eq!(event_final.acked_packets, 1);
        assert_eq!(t.bytes_in_flight(), 0);
    }

    #[test]
    fn ack_wrong_space_does_not_ack_packets() {
        let mut t = QuicTransportMachine::new();
        t.on_packet_sent(sent(PacketNumberSpace::Initial, 5, 1_000));
        // Try to ack with Handshake space -- should not match
        let event = t.on_ack_received(PacketNumberSpace::Handshake, &[5], 0, 2_000);
        assert_eq!(event.acked_packets, 0);
        assert_eq!(t.bytes_in_flight(), 100);
    }

    #[test]
    fn packet_number_space_debug_clone_copy_eq() {
        let sp = PacketNumberSpace::ApplicationData;
        let dbg = format!("{sp:?}");
        assert!(dbg.contains("ApplicationData"), "{dbg}");
        let copied: PacketNumberSpace = sp;
        let cloned = sp.clone();
        assert_eq!(copied, cloned);
        assert_ne!(sp, PacketNumberSpace::Initial);
    }

    #[test]
    fn sent_packet_meta_debug_clone_eq() {
        let m = SentPacketMeta {
            space: PacketNumberSpace::Handshake,
            packet_number: 7,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: 500,
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Handshake"), "{dbg}");
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn ack_range_debug_clone_copy_eq() {
        let r = AckRange::new(10, 5).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("10"), "{dbg}");
        let copied: AckRange = r;
        let cloned = r.clone();
        assert_eq!(copied, cloned);
        assert_eq!(r, AckRange::new(10, 5).unwrap());
    }

    #[test]
    fn ack_event_debug_clone_eq() {
        let e = AckEvent {
            acked_packets: 3,
            lost_packets: 1,
            acked_bytes: 3600,
            lost_bytes: 1200,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("3600"), "{dbg}");
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn rtt_estimator_debug_clone_default_eq() {
        let r = RttEstimator::default();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RttEstimator"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    // ---- Gap 10: start_draining without code -> close_code() stays None ----

    #[test]
    fn start_draining_without_code_keeps_close_code_none() {
        let mut t = QuicTransportMachine::new();
        t.begin_handshake().unwrap();
        t.on_established().unwrap();
        assert_eq!(t.close_code(), None);

        // Drain without code
        t.start_draining(1_000, 5_000).unwrap();
        assert_eq!(t.state(), QuicConnectionState::Draining);
        assert_eq!(
            t.close_code(),
            None,
            "close_code should remain None after start_draining without code"
        );

        // Poll to closed
        t.poll(6_000);
        assert_eq!(t.state(), QuicConnectionState::Closed);
        assert_eq!(
            t.close_code(),
            None,
            "close_code should remain None after poll to Closed"
        );
    }
}
