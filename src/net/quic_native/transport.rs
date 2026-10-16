//! Native QUIC transport + loss-recovery state machine.
//!
//! This module keeps deterministic, runtime-agnostic transport logic:
//! packet accounting, RTT estimation, loss detection, and PTO scheduling.

use std::borrow::Cow;
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

/// ACK ranges in disjoint descending order, so a packet-number lookup is a
/// binary search. A peer can put hundreds of ranges in one ACK frame; testing
/// every packet in flight against every range made each such ACK cost their
/// product (br-asupersync-5f1fcj). Ranges decoded from an ACK frame are
/// already disjoint and descending and are used in place; anything else is
/// sorted and merged once.
#[derive(Debug, Clone)]
pub(crate) struct AckRangeSet<'a> {
    ranges: Cow<'a, [AckRange]>,
}

impl<'a> AckRangeSet<'a> {
    pub(crate) fn new(ranges: &'a [AckRange]) -> Self {
        if ranges
            .windows(2)
            .all(|pair| pair[1].largest < pair[0].smallest)
        {
            return Self {
                ranges: Cow::Borrowed(ranges),
            };
        }
        let mut sorted = ranges.to_vec();
        sorted.sort_unstable_by_key(|range| range.smallest);
        let mut merged: Vec<AckRange> = Vec::with_capacity(sorted.len());
        for range in sorted {
            match merged.last_mut() {
                Some(last) if range.smallest <= last.largest.saturating_add(1) => {
                    last.largest = last.largest.max(range.largest);
                }
                _ => merged.push(range),
            }
        }
        merged.reverse();
        Self {
            ranges: Cow::Owned(merged),
        }
    }

    pub(crate) fn contains(&self, packet_number: u64) -> bool {
        // The first range starting at or below the packet is the only one
        // that can hold it.
        let candidate = self
            .ranges
            .partition_point(|range| range.smallest > packet_number);
        self.ranges
            .get(candidate)
            .is_some_and(|range| range.contains(packet_number))
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
        let adjusted = if min_rtt.saturating_add(ack_delay_micros) < sample_micros {
            sample_micros.saturating_sub(ack_delay_micros)
        } else {
            sample_micros
        };
        self.latest_rtt_micros = Some(adjusted);

        match (self.smoothed_rtt_micros, self.rttvar_micros) {
            (None, None) => {
                self.smoothed_rtt_micros = Some(adjusted);
                self.rttvar_micros = Some(adjusted / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                let abs_err = srtt.abs_diff(adjusted);
                let new_rttvar = (3u64.saturating_mul(rttvar).saturating_add(abs_err)) / 4;
                let new_srtt = (7u64.saturating_mul(srtt).saturating_add(adjusted)) / 8;
                self.rttvar_micros = Some(new_rttvar);
                self.smoothed_rtt_micros = Some(new_srtt);
            }
            _ => unreachable!("smoothed/rttvar tracked together"),
        }
    }

    /// Minimum RTT observed over the connection's lifetime (RTprop).
    #[must_use]
    pub fn min_rtt_micros(&self) -> Option<u64> {
        self.min_rtt_micros
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

/// ACK-only packets kept per space even when no in-flight packet needs them,
/// so a late acknowledgment of one still resets the PTO backoff.
const RETAINED_ACK_ONLY_PACKETS: usize = 64;
/// History length at which ACK-only pruning first runs.
const ACK_ONLY_PRUNE_FLOOR: usize = 1024;

#[derive(Debug, Clone)]
struct LossRecovery {
    sent_packets: VecDeque<SentPacketMeta>,
    /// History length that triggers the next ACK-only prune. It doubles from
    /// the length left after each prune, so pruning is amortized O(1).
    ack_only_prune_at: usize,
    newly_lost_packet_numbers: [Vec<u64>; 3],
    largest_acked: [Option<u64>; 3],
    bytes_in_flight: u64,
    packets_acked_total: u64,
    packets_lost_total: u64,
    pto_count: u32,
    latest_ack_eliciting_sent_micros: [Option<u64>; 3],
    pto_rearmed_at_micros: Option<u64>,
    max_ack_delay_micros: u64,
    rtt: RttEstimator,
    congestion_window_bytes: u64,
    ssthresh_bytes: u64,
    max_datagram_size: u64,
    /// RFC 9002 Appendix B.6: Tracks start of the current congestion recovery
    /// epoch so that cwnd is reduced at most once per round-trip.
    congestion_recovery_start_time: Option<u64>,
    /// RFC 9002 Appendix B.8 / §7.6: wall-clock time (micros) at which the
    /// first RTT sample was obtained. Persistent-congestion detection only
    /// considers packets sent strictly after this instant, so losses of
    /// packets sent before any RTT estimate existed (e.g. early handshake
    /// flights) can never collapse the window. `None` until the first sample.
    first_rtt_sample_micros: Option<u64>,
}

impl Default for LossRecovery {
    fn default() -> Self {
        Self {
            sent_packets: VecDeque::new(),
            ack_only_prune_at: ACK_ONLY_PRUNE_FLOOR,
            newly_lost_packet_numbers: std::array::from_fn(|_| Vec::new()),
            largest_acked: [None, None, None],
            bytes_in_flight: 0,
            packets_acked_total: 0,
            packets_lost_total: 0,
            pto_count: 0,
            latest_ack_eliciting_sent_micros: [None; 3],
            pto_rearmed_at_micros: None,
            max_ack_delay_micros: 25_000,
            rtt: RttEstimator::default(),
            congestion_window_bytes: 12_000,
            ssthresh_bytes: u64::MAX,
            max_datagram_size: 1_200,
            congestion_recovery_start_time: None,
            first_rtt_sample_micros: None,
        }
    }
}

impl LossRecovery {
    fn clear(&mut self) {
        self.sent_packets.clear();
        self.ack_only_prune_at = ACK_ONLY_PRUNE_FLOOR;
        for lost in &mut self.newly_lost_packet_numbers {
            lost.clear();
        }
        self.largest_acked = [None, None, None];
        self.bytes_in_flight = 0;
        self.packets_acked_total = 0;
        self.packets_lost_total = 0;
        self.pto_count = 0;
        self.latest_ack_eliciting_sent_micros = [None; 3];
        self.pto_rearmed_at_micros = None;
        self.congestion_recovery_start_time = None;
        self.first_rtt_sample_micros = None;
    }

    pub fn discard_space(&mut self, space: PacketNumberSpace) {
        self.newly_lost_packet_numbers[space.idx()].clear();
        self.latest_ack_eliciting_sent_micros[space.idx()] = None;
        let mut retained = VecDeque::with_capacity(self.sent_packets.len());
        while let Some(pkt) = self.sent_packets.pop_front() {
            if pkt.space == space {
                if pkt.in_flight {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes);
                }
            } else {
                retained.push_back(pkt);
            }
        }
        self.sent_packets = retained;
    }

    fn on_packet_sent(&mut self, packet: SentPacketMeta) {
        if packet.ack_eliciting && packet.in_flight {
            let latest = &mut self.latest_ack_eliciting_sent_micros[packet.space.idx()];
            *latest = Some(latest.map_or(packet.time_sent_micros, |seen| {
                seen.max(packet.time_sent_micros)
            }));
        }
        if packet.in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(packet.bytes);
        }
        let ack_only = !packet.in_flight;
        self.sent_packets.push_back(packet);
        // A pure receiver's peer never acknowledges its ACK-only packets, so
        // largest_acked never passes them and loss detection never forgets them.
        if ack_only && self.sent_packets.len() >= self.ack_only_prune_at {
            self.prune_ack_only_packets();
            self.ack_only_prune_at = self
                .sent_packets
                .len()
                .saturating_mul(2)
                .max(ACK_ONLY_PRUNE_FLOOR);
        }
    }

    /// Forget ACK-only packets no recovery decision can still use.
    ///
    /// RFC 9002 section 7.6.2 asks whether any packet sent between two lost
    /// in-flight packets was acknowledged. An ACK-only packet sent before every
    /// in-flight packet of its space cannot lie between two of them, so only
    /// the newest few such packets are kept, for PTO-backoff resets.
    fn prune_ack_only_packets(&mut self) {
        let mut oldest_in_flight: [Option<u64>; 3] = [None; 3];
        for pkt in self.sent_packets.iter().filter(|pkt| pkt.in_flight) {
            let oldest = &mut oldest_in_flight[pkt.space.idx()];
            *oldest =
                Some(oldest.map_or(pkt.time_sent_micros, |seen| seen.min(pkt.time_sent_micros)));
        }
        let mut kept = [0usize; 3];
        let mut retained = VecDeque::with_capacity(self.sent_packets.len());
        while let Some(pkt) = self.sent_packets.pop_back() {
            if !pkt.in_flight {
                let idx = pkt.space.idx();
                let needed =
                    oldest_in_flight[idx].is_some_and(|oldest| pkt.time_sent_micros >= oldest);
                if !needed && kept[idx] >= RETAINED_ACK_ONLY_PACKETS {
                    continue;
                }
                kept[idx] += 1;
            }
            retained.push_front(pkt);
        }
        self.sent_packets = retained;
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
        self.newly_lost_packet_numbers[space.idx()].clear();
        if ack_ranges.is_empty() {
            return AckEvent::empty();
        }
        let mut event = AckEvent::empty();
        let mut newest_lost_packet_sent_micros: Option<u64> = None;
        // RFC 9002 B.5: Only grow cwnd for packets sent AFTER the recovery
        // epoch started. Packets sent during recovery (sent_time <=
        // congestion_recovery_start_time) must not contribute to cwnd growth.
        let mut acked_bytes_for_growth: u64 = 0;

        let largest_acked_pn = ack_ranges.iter().map(|range| range.largest).max();
        let mut largest_newly_acked_pn: Option<u64> = None;
        let mut largest_acked_time: Option<u64> = None;
        let mut newly_acked_ack_eliciting = false;
        // RFC 9002 §7.6.2: any packet acknowledged in the interval between two
        // lost ack-eliciting packets breaks a persistent-congestion run, so
        // record every newly-acknowledged send time in this space.
        let mut acked_sent_times: Vec<u64> = Vec::new();

        let acked_set = AckRangeSet::new(ack_ranges);
        let mut retained = VecDeque::with_capacity(self.sent_packets.len());
        while let Some(pkt) = self.sent_packets.pop_front() {
            let acked = pkt.space == space && acked_set.contains(pkt.packet_number);
            if acked {
                event.acked_packets += 1;
                acked_sent_times.push(pkt.time_sent_micros);
                if pkt.in_flight {
                    event.acked_bytes = event.acked_bytes.saturating_add(pkt.bytes);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes);
                    let in_recovery = self
                        .congestion_recovery_start_time
                        .is_some_and(|t| pkt.time_sent_micros <= t);
                    if !in_recovery {
                        acked_bytes_for_growth = acked_bytes_for_growth.saturating_add(pkt.bytes);
                    }
                }

                if largest_newly_acked_pn.is_none_or(|pn| pkt.packet_number > pn) {
                    largest_newly_acked_pn = Some(pkt.packet_number);
                }
                if Some(pkt.packet_number) == largest_acked_pn {
                    largest_acked_time = Some(pkt.time_sent_micros);
                }
                newly_acked_ack_eliciting |= pkt.ack_eliciting;
            } else {
                retained.push_back(pkt);
            }
        }
        self.sent_packets = retained;

        let Some(largest_newly_acked_pn) = largest_newly_acked_pn else {
            return AckEvent::empty();
        };
        let global_largest_acked = self.largest_acked[space.idx()]
            .map_or(largest_newly_acked_pn, |seen| {
                seen.max(largest_newly_acked_pn)
            });
        self.largest_acked[space.idx()] = Some(global_largest_acked);

        // RFC 9002 section 5.1: the frame's largest packet must itself be
        // newly acknowledged, and at least one newly acknowledged packet
        // must be ack-eliciting. They need not be the same packet. A frame
        // repeating its largest packet cannot sample an older new ACK.
        if newly_acked_ack_eliciting && let Some(time_sent) = largest_acked_time {
            let sample = now_micros.saturating_sub(time_sent);
            let effective_ack_delay = if space == PacketNumberSpace::ApplicationData {
                ack_delay_micros
            } else {
                0
            };
            self.rtt.update(sample, effective_ack_delay);
            // RFC 9002 Appendix B.8: remember when the first genuine RTT sample
            // landed. `update` ignores a zero sample (leaving smoothed_rtt
            // `None`), so a non-`None` smoothed RTT here means a real sample was
            // just recorded; the first one fixes the persistent-congestion
            // exclusion boundary.
            if self.first_rtt_sample_micros.is_none() && self.rtt.smoothed_rtt_micros().is_some() {
                self.first_rtt_sample_micros = Some(now_micros);
            }
        }

        // RFC 9002 Appendix A.7 updates RTT before detecting losses from the
        // same ACK. Using the previous estimate can falsely lose packets when
        // path latency grows, or retain expired packets when it shrinks.
        let loss_delay = self.loss_delay_micros();
        // RFC 9002 section 6.1.2: use checked subtraction so an early clock
        // does not floor the boundary to zero and falsely lose packets sent
        // at t=0 before a complete loss-delay interval has elapsed.
        let time_threshold = now_micros.checked_sub(loss_delay);

        // Packet-threshold loss detection (kPacketThreshold = 3)
        // RFC 9002 §7.6.2: persistent congestion is bounded by two *ack-eliciting*
        // lost packets, so collect their send times as they are declared lost.
        let mut lost_ae_sent_times: Vec<u64> = Vec::new();
        let mut survivors = VecDeque::with_capacity(self.sent_packets.len());
        while let Some(pkt) = self.sent_packets.pop_front() {
            let packet_threshold_lost =
                pkt.space == space && pkt.packet_number.saturating_add(3) <= global_largest_acked;
            let time_threshold_lost = pkt.space == space
                && pkt.packet_number <= global_largest_acked
                && time_threshold.is_some_and(|boundary| pkt.time_sent_micros <= boundary);
            if !(packet_threshold_lost || time_threshold_lost) {
                survivors.push_back(pkt);
                continue;
            }
            if !pkt.in_flight {
                // RFC 9002 §6.1 / Appendix A.10: only in-flight packets can be
                // declared lost. A packet that is not in flight (ACK-only)
                // and sits behind the largest acknowledged packet is simply
                // forgotten: RFC 9000 §13.2.3 lets a receiver leave
                // non-ack-eliciting packets out of its ACK ranges, it carries
                // no retransmittable frame, and it never counted toward
                // bytes_in_flight. Counting it as lost is what collapsed cwnd
                // to two packets on clean ~30 ms paths (GH#71): every ACK-only
                // packet a cwnd-limited sender emitted was "lost" three
                // packets later and halved the window once per round trip.
                continue;
            }
            event.lost_packets += 1;
            self.newly_lost_packet_numbers[space.idx()].push(pkt.packet_number);
            if pkt.ack_eliciting {
                lost_ae_sent_times.push(pkt.time_sent_micros);
            }
            newest_lost_packet_sent_micros = Some(
                newest_lost_packet_sent_micros
                    .map_or(pkt.time_sent_micros, |seen| seen.max(pkt.time_sent_micros)),
            );
            event.lost_bytes = event.lost_bytes.saturating_add(pkt.bytes);
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes);
        }
        self.sent_packets = survivors;

        // RFC 9002 Appendix A.7 order: process loss BEFORE ack-driven growth.
        // A newly detected loss moves the recovery epoch to `now`, and every
        // packet acknowledged by this same ACK was sent before `now`, so per
        // `InCongestionRecovery` none of them may grow cwnd. Growing first and
        // halving second (the previous order) let a large ACK carrying a single
        // loss inflate cwnd before the halving, weakening or even nullifying the
        // multiplicative decrease (asupersync-f3x3e3).
        let mut loss_reduced_cwnd =
            if let Some(lost_packet_sent_time) = newest_lost_packet_sent_micros {
                self.on_loss_congestion(lost_packet_sent_time, now_micros)
            } else {
                false
            };
        // RFC 9002 §7.6 / Appendix B.8: after the ordinary congestion event,
        // check whether this loss run establishes persistent congestion — a
        // full-outage window in which every ack-eliciting packet spanning more
        // than the persistent-congestion duration was lost. If so, collapse
        // cwnd to the minimum window (kMinimumWindow = 2 * max_datagram_size)
        // and clear the recovery epoch so the next loss opens a fresh one. This
        // overrides any same-ACK growth for the acknowledged packets.
        if let Some(first_rtt_sample) = self.first_rtt_sample_micros {
            let duration = self.persistent_congestion_duration_micros();
            if Self::is_persistent_congestion(
                &lost_ae_sent_times,
                &acked_sent_times,
                first_rtt_sample,
                duration,
            ) {
                self.congestion_window_bytes = self.max_datagram_size.saturating_mul(2);
                self.congestion_recovery_start_time = None;
                loss_reduced_cwnd = true;
            }
        }
        if event.acked_packets > 0 {
            self.pto_count = 0;
            self.pto_rearmed_at_micros = None;
            // Suppress growth for this ACK when the loss just moved the recovery
            // epoch to `now` — all acknowledged packets are then in recovery.
            // When no new reduction occurred (no loss, or a loss belonging to an
            // already-active epoch), `acked_bytes_for_growth` was already gated
            // against the active epoch in the accounting loop above.
            if acked_bytes_for_growth > 0 && !loss_reduced_cwnd {
                self.on_ack_congestion(acked_bytes_for_growth);
            }
        }
        let acked_packets = u64::try_from(event.acked_packets).unwrap_or(u64::MAX);
        let lost_packets = u64::try_from(event.lost_packets).unwrap_or(u64::MAX);
        self.packets_acked_total = self.packets_acked_total.saturating_add(acked_packets);
        self.packets_lost_total = self.packets_lost_total.saturating_add(lost_packets);
        event
    }

    fn loss_delay_micros(&self) -> u64 {
        // RFC 9002 Section 6.1.2: loss_delay = max(latest_rtt, smoothed_rtt)
        let latest = self.rtt.latest_rtt_micros().unwrap_or(333_000);
        let smoothed = self.rtt.smoothed_rtt_micros().unwrap_or(333_000);
        let base_rtt = latest.max(smoothed);
        (9u64.saturating_mul(base_rtt) / 8).max(1_000)
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

    /// Reduce cwnd for a congestion event. Returns `true` if this call actually
    /// moved the recovery epoch to `now_micros` and halved cwnd, `false` if it
    /// was a no-op because the lost packet belongs to an already-active epoch
    /// (RFC 9002 Appendix B.6, one reduction per epoch). The return lets
    /// `on_ack_ranges` honor the RFC 9002 A.7 ordering: when a loss moves the
    /// epoch to `now`, the packets acknowledged by the same ACK must not grow
    /// cwnd (asupersync-f3x3e3).
    fn on_loss_congestion(&mut self, newest_lost_packet_sent_micros: u64, now_micros: u64) -> bool {
        // RFC 9002 Appendix B.6: Only reduce cwnd once per recovery epoch.
        if let Some(recovery_start) = self.congestion_recovery_start_time {
            if newest_lost_packet_sent_micros <= recovery_start {
                return false;
            }
        }
        self.congestion_recovery_start_time = Some(now_micros);
        let min_cwnd = self.max_datagram_size.saturating_mul(2);
        let reduced = (self.congestion_window_bytes / 2).max(min_cwnd);
        self.ssthresh_bytes = reduced;
        self.congestion_window_bytes = reduced;
        true
    }

    fn base_pto_micros(&self) -> u64 {
        let srtt = self.rtt.smoothed_rtt_micros().unwrap_or(333_000);
        let rttvar = self.rtt.rttvar_micros().unwrap_or(srtt / 2);
        srtt.saturating_add(4u64.saturating_mul(rttvar).max(1_000))
    }

    /// RFC 9002 §7.6.1: persistent-congestion duration.
    ///
    /// `(smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay) *
    /// kPersistentCongestionThreshold`, with `kGranularity = 1 ms` and
    /// `kPersistentCongestionThreshold = 3`. Unlike the PTO in Section 6.2,
    /// this duration always includes `max_ack_delay` regardless of the packet
    /// number space the losses were established in.
    fn persistent_congestion_duration_micros(&self) -> u64 {
        let srtt = self.rtt.smoothed_rtt_micros().unwrap_or(333_000);
        let rttvar = self.rtt.rttvar_micros().unwrap_or(srtt / 2);
        let pto = srtt
            .saturating_add(4u64.saturating_mul(rttvar).max(1_000))
            .saturating_add(self.max_ack_delay_micros);
        pto.saturating_mul(3)
    }

    /// RFC 9002 §7.6.2 `AreAllPacketsLost`: decide whether the newly-lost
    /// ack-eliciting packets establish persistent congestion.
    ///
    /// Persistent congestion requires two ack-eliciting packets, both sent
    /// strictly after the first RTT sample, whose send times are separated by
    /// more than `duration`, with no packet acknowledged anywhere in that
    /// interval (an acknowledgement proves the path was not fully out). A
    /// single acknowledgement inside the span breaks the run; a later unbroken
    /// sub-run can still qualify.
    ///
    /// `lost_ae_sent` are the send times of newly-lost ack-eliciting packets;
    /// `acked_sent` are the send times of every packet acknowledged by the same
    /// ACK. Both are confined to the acknowledged packet number space, matching
    /// the per-space conservative approach RFC 9002 §7.6.2 permits.
    fn is_persistent_congestion(
        lost_ae_sent: &[u64],
        acked_sent: &[u64],
        first_rtt_sample: u64,
        duration: u64,
    ) -> bool {
        // Only packets sent after the first RTT sample count (RFC 9002 B.8).
        let mut lost: Vec<u64> = lost_ae_sent
            .iter()
            .copied()
            .filter(|&t| t > first_rtt_sample)
            .collect();
        if lost.len() < 2 {
            return false;
        }
        lost.sort_unstable();
        let mut acked = acked_sent.to_vec();
        acked.sort_unstable();
        // Walk lost packets oldest-to-newest. A run is broken when a packet was
        // acknowledged strictly between two consecutive lost send times; then a
        // fresh run starts at the later packet. The earliest acknowledged send
        // time after `prev` decides that, found by binary search.
        let mut run_start = lost[0];
        let mut prev = lost[0];
        for &t in &lost[1..] {
            let first_after_prev = acked.partition_point(|&a| a <= prev);
            let broken = acked.get(first_after_prev).is_some_and(|&a| a < t);
            if broken {
                run_start = t;
            } else if t.saturating_sub(run_start) > duration {
                return true;
            }
            prev = t;
        }
        false
    }

    fn pto_deadline_micros(&self, _now_micros: u64) -> Option<u64> {
        if self.bytes_in_flight == 0 {
            return None;
        }
        let backoff = 1u64 << self.pto_count.min(10);
        let base_timeout = self.base_pto_micros();

        let mut ack_eliciting_in_flight = [false; 3];
        for pkt in &self.sent_packets {
            if !pkt.in_flight || !pkt.ack_eliciting {
                continue;
            }
            ack_eliciting_in_flight[pkt.space.idx()] = true;
        }

        let mut deadline: Option<u64> = None;
        for (idx, in_flight) in ack_eliciting_in_flight.iter().copied().enumerate() {
            if !in_flight {
                continue;
            }
            // Sending another ack-eliciting packet restarts this space's PTO,
            // even if that newer packet is subsequently acknowledged while an
            // older packet remains in flight (RFC 9002 sections 6.2.1/6.2.4).
            let Some(latest_sent) = self.latest_ack_eliciting_sent_micros[idx] else {
                continue;
            };
            let mut timeout = base_timeout;
            if idx == PacketNumberSpace::ApplicationData.idx() {
                timeout = timeout.saturating_add(self.max_ack_delay_micros);
            }
            // A delayed or capped timeout must still wait a complete backed-off
            // PTO after firing, including when anti-amplification blocks its
            // probe. Merely reusing a past send timestamp would busy-loop.
            let anchor = latest_sent.max(self.pto_rearmed_at_micros.unwrap_or(latest_sent));
            let Some(candidate) = anchor.checked_add(timeout.saturating_mul(backoff)) else {
                // No representable future deadline; never arm an expired one.
                continue;
            };
            deadline = Some(match deadline {
                Some(seen) => seen.min(candidate),
                None => candidate,
            });
        }

        deadline
    }

    fn on_loss_timeout_expired(&mut self, space: PacketNumberSpace, now_micros: u64) -> AckEvent {
        self.newly_lost_packet_numbers[space.idx()].clear();
        let mut event = AckEvent::empty();
        let mut newest_lost_packet_sent_micros: Option<u64> = None;
        let mut retained = VecDeque::with_capacity(self.sent_packets.len());

        while let Some(pkt) = self.sent_packets.pop_front() {
            let lost = pkt.space == space && pkt.in_flight && pkt.ack_eliciting;
            if lost {
                event.lost_packets += 1;
                self.newly_lost_packet_numbers[space.idx()].push(pkt.packet_number);
                event.lost_bytes = event.lost_bytes.saturating_add(pkt.bytes);
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.bytes);
                newest_lost_packet_sent_micros = Some(
                    newest_lost_packet_sent_micros
                        .map_or(pkt.time_sent_micros, |seen| seen.max(pkt.time_sent_micros)),
                );
            } else {
                retained.push_back(pkt);
            }
        }

        self.sent_packets = retained;

        if event.lost_packets > 0 {
            self.pto_count = self.pto_count.saturating_add(1);
            self.packets_lost_total = self
                .packets_lost_total
                .saturating_add(u64::try_from(event.lost_packets).unwrap_or(u64::MAX));
            if let Some(lost_packet_sent_time) = newest_lost_packet_sent_micros {
                self.on_loss_congestion(lost_packet_sent_time, now_micros);
            }
        }

        event
    }

    fn take_newly_lost_packet_numbers(&mut self, space: PacketNumberSpace) -> Vec<u64> {
        std::mem::take(&mut self.newly_lost_packet_numbers[space.idx()])
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

    /// Adopt the peer's advertised `max_ack_delay` (RFC 9000 §18.2). It bounds
    /// both the RTT-sample `ack_delay` adjustment (RFC 9002 §5.3) and the PTO
    /// computation. Callers pass **microseconds** (the transport parameter is
    /// carried in milliseconds) (asupersync-mc7m2r).
    pub fn set_peer_max_ack_delay_micros(&mut self, max_ack_delay_micros: u64) {
        self.recovery.max_ack_delay_micros = max_ack_delay_micros;
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

    /// Current PTO backoff count.
    #[must_use]
    pub fn pto_count(&self) -> u32 {
        self.recovery.pto_count
    }

    /// Cumulative packets acknowledged since the current recovery state began.
    #[must_use]
    pub fn packets_acked_total(&self) -> u64 {
        self.recovery.packets_acked_total
    }

    /// Cumulative packets declared lost since the current recovery state began.
    #[must_use]
    pub fn packets_lost_total(&self) -> u64 {
        self.recovery.packets_lost_total
    }

    /// Cumulative packet loss rate over packets that reached a terminal
    /// recovery outcome (`acked` or `lost`).
    #[must_use]
    pub fn packet_loss_rate(&self) -> f64 {
        let total = self
            .recovery
            .packets_acked_total
            .saturating_add(self.recovery.packets_lost_total);
        if total == 0 {
            0.0
        } else {
            self.recovery.packets_lost_total as f64 / total as f64
        }
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
    ///
    /// Idempotent: if already draining, preserves the original deadline.
    pub fn start_draining(
        &mut self,
        now_micros: u64,
        drain_timeout_micros: u64,
    ) -> Result<(), TransportError> {
        if self.state == QuicConnectionState::Draining {
            return Ok(());
        }
        self.transition(QuicConnectionState::Draining)?;
        self.drain_deadline_micros = Some(now_micros.saturating_add(drain_timeout_micros));
        Ok(())
    }

    /// Start draining and record application close code.
    ///
    /// Idempotent: if already draining, preserves the original deadline
    /// and close code.
    pub fn start_draining_with_code(
        &mut self,
        now_micros: u64,
        drain_timeout_micros: u64,
        code: u64,
    ) -> Result<(), TransportError> {
        if self.state == QuicConnectionState::Draining {
            return Ok(());
        }
        self.start_draining(now_micros, drain_timeout_micros)?;
        self.close_code = Some(code);
        Ok(())
    }

    /// Close the connection immediately with an application error code.
    pub fn close_immediately(&mut self, code: u64) {
        self.state = QuicConnectionState::Closed;
        self.drain_deadline_micros = None;
        self.close_code = Some(code);
        self.recovery.clear();
    }

    /// Poll draining timer; transitions to `Closed` when deadline is reached.
    pub fn poll(&mut self, now_micros: u64) {
        if self.state == QuicConnectionState::Draining
            && self
                .drain_deadline_micros
                .is_some_and(|deadline| now_micros >= deadline)
        {
            self.state = QuicConnectionState::Closed;
            self.drain_deadline_micros = None;
            self.recovery.clear();
        }
    }

    /// Discard all packets and in-flight tracking for a given space.
    pub fn discard_space(&mut self, space: PacketNumberSpace) {
        self.recovery.discard_space(space);
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

    /// Highest ACK that matched a packet in this transport's sent history.
    /// Unsent packet numbers and ACKs from other spaces cannot confirm a
    /// locally initiated 1-RTT key update.
    pub(crate) fn largest_acked_packet_number(&self, space: PacketNumberSpace) -> Option<u64> {
        self.recovery.largest_acked[space.idx()]
    }

    /// Compute PTO deadline from current recovery state.
    #[must_use]
    pub fn pto_deadline_micros(&self, now_micros: u64) -> Option<u64> {
        self.recovery.pto_deadline_micros(now_micros)
    }

    /// RFC 9000 section 10.1 permits at least three probe intervals before
    /// idle expiry. Recovery backoff must not indefinitely move idle expiry.
    pub(crate) fn idle_timeout_floor_micros(&self) -> u64 {
        self.recovery
            .base_pto_micros()
            .saturating_add(self.recovery.max_ack_delay_micros)
            .saturating_mul(3)
    }

    pub(crate) fn drain_deadline_micros(&self) -> Option<u64> {
        self.drain_deadline_micros
    }

    /// Record a PTO timer expiration (backoff signal).
    pub fn on_pto_expired(&mut self) {
        self.recovery.pto_count = self.recovery.pto_count.saturating_add(1);
    }

    /// Rearm a fired managed PTO from the supplied clock using the newly
    /// backed-off duration. Returns `None` when no ack-eliciting flight remains
    /// or the next deadline cannot be represented.
    pub(crate) fn on_pto_expired_at(&mut self, now_micros: u64) -> Option<u64> {
        self.on_pto_expired();
        self.recovery.pto_rearmed_at_micros = Some(now_micros);
        self.pto_deadline_micros(now_micros)
    }

    /// Declare ack-eliciting in-flight packets in `space` lost after a
    /// PTO-style application timeout.
    ///
    /// Generic QUIC PTO sends probes instead of immediately marking packets
    /// lost. ATP's native DATAGRAM data plane does not retransmit individual
    /// DATAGRAM packets; fountain repair owns recovery, so stale DATAGRAM
    /// in-flight accounting must be released or a small cwnd can remain full
    /// forever behind lost packets.
    pub fn on_loss_timeout_expired(
        &mut self,
        space: PacketNumberSpace,
        now_micros: u64,
    ) -> AckEvent {
        self.recovery.on_loss_timeout_expired(space, now_micros)
    }

    /// Take the exact packet numbers removed by the most recent loss event in
    /// `space`. This keeps higher-layer reliable-frame ledgers aligned with the
    /// recovery machine without widening the stable [`AckEvent`] summary.
    pub(crate) fn take_newly_lost_packet_numbers(&mut self, space: PacketNumberSpace) -> Vec<u64> {
        self.recovery.take_newly_lost_packet_numbers(space)
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
#[path = "transport_inline_tests.rs"]
mod tests;
