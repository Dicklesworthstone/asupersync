//! QUIC DATAGRAM Congestion Control
//!
//! Implements congestion-aware handling of DATAGRAM frames to prevent overwhelming
//! the network while prioritizing critical frames. Uses priority queuing, rate limiting,
//! and adaptive backoff to maintain fairness with reliable streams.

use crate::net::atp::datagram::frame::{
    DatagramError, DatagramFrame, DatagramMetadata, DatagramPriority,
};
use crate::types::outcome::Outcome;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Congestion control algorithm for DATAGRAM frames
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// Simple rate limiting based on configured rates
    RateLimited,
    /// AIMD (Additive Increase Multiplicative Decrease)
    Aimd,
    /// Token bucket with burst allowance
    #[default]
    TokenBucket,
    /// Adaptive based on RTT and loss detection
    Adaptive,
}

/// Congestion control configuration
#[derive(Debug, Clone)]
pub struct CongestionConfig {
    /// Congestion algorithm to use
    pub algorithm: CongestionAlgorithm,
    /// Maximum datagrams per second
    pub max_rate_per_sec: u32,
    /// Maximum burst size
    pub max_burst_size: u32,
    /// Target queue depth before dropping
    pub max_queue_depth: usize,
    /// Minimum interval between sends
    pub min_send_interval: Duration,
    /// AIMD increase factor (packets per RTT)
    pub aimd_increase: f64,
    /// AIMD decrease factor (multiplicative)
    pub aimd_decrease: f64,
    /// RTT threshold for congestion detection
    pub rtt_threshold: Duration,
    /// Loss ratio threshold for congestion
    pub loss_threshold: f64,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            algorithm: CongestionAlgorithm::default(),
            max_rate_per_sec: 100,
            max_burst_size: 10,
            max_queue_depth: 50,
            min_send_interval: Duration::from_millis(10),
            aimd_increase: 1.0,
            aimd_decrease: 0.5,
            rtt_threshold: Duration::from_millis(100),
            loss_threshold: 0.05, // 5% loss
        }
    }
}

/// Deterministic BBR-style rate controller configuration for ATP datagram
/// transports.
///
/// RQ UDP and QUIC DATAGRAM senders feed the same sent/delivered byte samples,
/// RTT, and receiver credit into this controller, then consume one pacing/cwnd
/// decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DatagramRateConfig {
    /// Initial pacing rate in payload bytes per second.
    pub initial_pacing_bytes_per_s: u64,
    /// Lower bound for pacing rate in payload bytes per second.
    pub min_pacing_bytes_per_s: u64,
    /// Upper bound for pacing rate in payload bytes per second.
    pub max_pacing_bytes_per_s: u64,
    /// Initial congestion window in payload bytes.
    pub initial_cwnd_bytes: u64,
    /// Minimum congestion window in payload bytes.
    pub min_cwnd_bytes: u64,
    /// Maximum congestion window in payload bytes.
    pub max_cwnd_bytes: u64,
    /// Multiplier applied to the current delivery-rate estimate when pacing.
    pub pacing_gain: f64,
    /// Multiplier applied to the bandwidth-delay product for cwnd.
    pub cwnd_gain: f64,
    /// Sender-side loss fraction that triggers loss backoff.
    pub loss_backoff_threshold: f64,
    /// Multiplicative backoff applied when sender-side loss is above threshold.
    pub loss_backoff_factor: f64,
    /// Extra headroom over measured delivery rate after a loss backoff.
    pub loss_delivery_headroom: f64,
    /// Window after which the minimum RTT estimate may be refreshed upward.
    pub min_rtt_window_micros: u64,
}

impl Default for DatagramRateConfig {
    fn default() -> Self {
        Self {
            initial_pacing_bytes_per_s: 1024 * 1024,
            min_pacing_bytes_per_s: 64 * 1024,
            max_pacing_bytes_per_s: 256 * 1024 * 1024,
            initial_cwnd_bytes: 256 * 1024,
            min_cwnd_bytes: 16 * 1024,
            max_cwnd_bytes: 16 * 1024 * 1024,
            pacing_gain: 1.0,
            cwnd_gain: 2.0,
            loss_backoff_threshold: 0.02,
            loss_backoff_factor: 0.50,
            loss_delivery_headroom: 1.25,
            min_rtt_window_micros: 10_000_000,
        }
    }
}

/// One ack-clocked feedback sample for the deterministic datagram rate
/// controller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramRateSample {
    /// Monotonic sample timestamp in microseconds.
    pub now_micros: u64,
    /// Payload bytes sent in the sampled interval.
    pub sent_bytes: u64,
    /// Payload bytes acknowledged or otherwise confirmed delivered.
    pub acked_bytes: u64,
    /// Payload bytes explicitly declared lost by packet/loss detection.
    pub lost_bytes: u64,
    /// Latest RTT sample in microseconds.
    pub rtt_micros: Option<u64>,
    /// Receiver-advertised remaining flow-control credit in payload bytes.
    pub receiver_credit_bytes: Option<u64>,
}

/// Deterministic pacing and inflight decision for one datagram send epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramRateDecision {
    /// Payload pacing rate in bytes per second.
    pub pacing_bytes_per_s: u64,
    /// Payload pacing rate in bits per second for token-bucket adapters.
    pub pacing_rate_bps: u64,
    /// Congestion window in payload bytes before receiver-credit clipping.
    pub cwnd_bytes: u64,
    /// Current bottleneck delivery-rate estimate in payload bytes per second.
    pub bottleneck_bytes_per_s: u64,
    /// Effective inflight limit after receiver-credit clipping.
    pub inflight_limit_bytes: u64,
    /// Bytes available to send immediately under cwnd and receiver credit.
    pub send_budget_bytes: u64,
    /// Receiver-advertised remaining flow-control credit in payload bytes.
    pub receiver_credit_bytes: Option<u64>,
    /// Current windowed minimum RTT estimate in microseconds.
    pub min_rtt_micros: Option<u64>,
    /// Sender-side loss fraction from sent-vs-delivered evidence.
    pub sender_loss_fraction_ppm: u32,
    /// Ack-clocked delivery-rate estimate in payload bytes per second.
    pub delivery_rate_bytes_per_s: u64,
}

/// Shared deterministic datagram congestion authority.
#[derive(Debug, Clone)]
pub struct DatagramRateController {
    config: DatagramRateConfig,
    pacing_bytes_per_s: u64,
    bottleneck_bytes_per_s: u64,
    cwnd_bytes: u64,
    min_rtt_micros: Option<u64>,
    min_rtt_stamp_micros: u64,
    last_ack_micros: Option<u64>,
    next_send_micros: Option<u64>,
}

impl DatagramRateController {
    /// Create a deterministic datagram rate controller.
    #[must_use]
    pub fn new(config: DatagramRateConfig) -> Self {
        let pacing_bytes_per_s = config.initial_pacing_bytes_per_s.clamp(
            config.min_pacing_bytes_per_s.max(1),
            config.max_pacing_bytes_per_s.max(1),
        );
        let cwnd_bytes = config
            .initial_cwnd_bytes
            .clamp(config.min_cwnd_bytes.max(1), config.max_cwnd_bytes.max(1));
        Self {
            config,
            pacing_bytes_per_s,
            bottleneck_bytes_per_s: pacing_bytes_per_s,
            cwnd_bytes,
            min_rtt_micros: None,
            min_rtt_stamp_micros: 0,
            last_ack_micros: None,
            next_send_micros: None,
        }
    }

    /// Observe one delivery/loss sample and return the new pacing decision.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    #[must_use]
    pub fn observe(&mut self, sample: DatagramRateSample) -> DatagramRateDecision {
        self.observe_min_rtt(sample);
        let delivery_rate = self.delivery_rate_bytes_per_s(sample);
        let sender_loss = sender_loss_fraction(sample);

        if delivery_rate > 0 {
            if sender_loss > self.config.loss_backoff_threshold {
                self.bottleneck_bytes_per_s = self.bottleneck_bytes_per_s.min(delivery_rate);
            } else {
                self.bottleneck_bytes_per_s = self.bottleneck_bytes_per_s.max(delivery_rate);
            }
            let target = (self.bottleneck_bytes_per_s as f64
                * finite_positive_or(self.config.pacing_gain, 1.0))
            .ceil() as u64;
            self.pacing_bytes_per_s = self.clamp_pacing(target);
        }

        if sender_loss > self.config.loss_backoff_threshold {
            let multiplicative = (self.pacing_bytes_per_s as f64
                * finite_positive_or(self.config.loss_backoff_factor, 0.5))
            .ceil() as u64;
            let delivery_backoff = if delivery_rate == 0 {
                self.config.min_pacing_bytes_per_s
            } else {
                (delivery_rate as f64 * finite_positive_or(self.config.loss_delivery_headroom, 1.0))
                    .ceil() as u64
            };
            self.pacing_bytes_per_s = self.clamp_pacing(multiplicative.min(delivery_backoff));
        }

        self.update_cwnd();
        self.decision(sample, delivery_rate, sender_loss)
    }

    /// Return whether `bytes` may be sent with the given bytes already in flight.
    #[must_use]
    pub fn can_send(&self, bytes_in_flight: u64, bytes: u64, receiver_credit: Option<u64>) -> bool {
        let inflight_limit = receiver_credit
            .map_or(self.cwnd_bytes, |credit| self.cwnd_bytes.min(credit))
            .max(1);
        bytes_in_flight.saturating_add(bytes) <= inflight_limit
    }

    /// Consume one ack-clocked pacing slot if both pacing and cwnd allow it.
    pub fn try_send(
        &mut self,
        now_micros: u64,
        bytes_in_flight: u64,
        bytes: u64,
        receiver_credit: Option<u64>,
    ) -> bool {
        if !self.can_send(bytes_in_flight, bytes, receiver_credit) {
            return false;
        }
        if self
            .next_send_micros
            .is_some_and(|deadline| now_micros < deadline)
        {
            return false;
        }
        self.next_send_micros = now_micros.checked_add(duration_micros_for_bytes(
            bytes.max(1),
            self.pacing_bytes_per_s,
        ));
        true
    }

    /// Deterministic pacing delay in microseconds until a send slot is available.
    #[must_use]
    pub fn time_until_send_micros(&self, now_micros: u64) -> u64 {
        self.next_send_micros
            .map_or(0, |deadline| deadline.saturating_sub(now_micros))
    }

    fn observe_min_rtt(&mut self, sample: DatagramRateSample) {
        let Some(rtt) = sample.rtt_micros.filter(|rtt| *rtt > 0) else {
            return;
        };
        let expired = sample.now_micros.saturating_sub(self.min_rtt_stamp_micros)
            >= self.config.min_rtt_window_micros.max(1);
        if self
            .min_rtt_micros
            .is_none_or(|min_rtt| rtt < min_rtt || expired)
        {
            self.min_rtt_micros = Some(rtt);
            self.min_rtt_stamp_micros = sample.now_micros;
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn delivery_rate_bytes_per_s(&mut self, sample: DatagramRateSample) -> u64 {
        if sample.acked_bytes == 0 {
            return 0;
        }
        let elapsed_micros = self
            .last_ack_micros
            .map(|last| sample.now_micros.saturating_sub(last))
            .filter(|elapsed| *elapsed > 0)
            .or(self.min_rtt_micros)
            .unwrap_or(1)
            .max(1);
        self.last_ack_micros = Some(sample.now_micros);
        ((sample.acked_bytes as f64 * 1_000_000.0) / elapsed_micros as f64)
            .ceil()
            .clamp(1.0, u64::MAX as f64) as u64
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn update_cwnd(&mut self) {
        let Some(min_rtt) = self.min_rtt_micros else {
            self.cwnd_bytes = self.cwnd_bytes.clamp(
                self.config.min_cwnd_bytes.max(1),
                self.config.max_cwnd_bytes.max(1),
            );
            return;
        };
        let bdp = self.pacing_bytes_per_s as f64 * (min_rtt as f64 / 1_000_000.0);
        let target = (bdp * finite_positive_or(self.config.cwnd_gain, 2.0)).ceil() as u64;
        self.cwnd_bytes = target.clamp(
            self.config.min_cwnd_bytes.max(1),
            self.config.max_cwnd_bytes.max(1),
        );
    }

    fn decision(
        &self,
        sample: DatagramRateSample,
        delivery_rate: u64,
        sender_loss: f64,
    ) -> DatagramRateDecision {
        let receiver_limit = sample.receiver_credit_bytes.unwrap_or(u64::MAX);
        let inflight_limit = self.cwnd_bytes.min(receiver_limit).max(1);
        DatagramRateDecision {
            pacing_bytes_per_s: self.pacing_bytes_per_s,
            pacing_rate_bps: self.pacing_bytes_per_s.saturating_mul(8),
            cwnd_bytes: self.cwnd_bytes,
            bottleneck_bytes_per_s: self.bottleneck_bytes_per_s,
            inflight_limit_bytes: inflight_limit,
            send_budget_bytes: inflight_limit,
            receiver_credit_bytes: sample.receiver_credit_bytes,
            min_rtt_micros: self.min_rtt_micros,
            sender_loss_fraction_ppm: fraction_to_ppm(sender_loss),
            delivery_rate_bytes_per_s: delivery_rate,
        }
    }

    fn clamp_pacing(&self, value: u64) -> u64 {
        value.clamp(
            self.config.min_pacing_bytes_per_s.max(1),
            self.config.max_pacing_bytes_per_s.max(1),
        )
    }
}

fn finite_positive_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        fallback
    }
}

#[allow(clippy::cast_precision_loss)]
fn sender_loss_fraction(sample: DatagramRateSample) -> f64 {
    let sent_loss = if sample.sent_bytes == 0 {
        0.0
    } else {
        sample
            .sent_bytes
            .saturating_sub(sample.acked_bytes.min(sample.sent_bytes)) as f64
            / sample.sent_bytes as f64
    };
    let explicit_loss = if sample.lost_bytes == 0 {
        0.0
    } else {
        let denominator = sample.acked_bytes.saturating_add(sample.lost_bytes).max(1);
        sample.lost_bytes as f64 / denominator as f64
    };
    sent_loss.max(explicit_loss).clamp(0.0, 1.0)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn fraction_to_ppm(value: f64) -> u32 {
    (value.clamp(0.0, 1.0) * 1_000_000.0).round() as u32
}

fn duration_micros_for_bytes(bytes: u64, bytes_per_s: u64) -> u64 {
    if bytes == 0 || bytes_per_s == 0 {
        return 0;
    }
    let micros = u128::from(bytes)
        .saturating_mul(1_000_000)
        .div_ceil(u128::from(bytes_per_s));
    u64::try_from(micros).unwrap_or(u64::MAX)
}

/// Congestion state for rate limiting
#[derive(Debug, Clone)]
struct CongestionState {
    /// Current congestion window (packets)
    congestion_window: f64,
    /// Tokens available for sending
    tokens: f64,
    /// Last token refill time
    last_refill: Instant,
    /// Last send time
    last_send: Instant,
    /// Recent RTT measurements
    rtt_samples: VecDeque<Duration>,
    /// Recent loss events
    loss_events: VecDeque<Instant>,
    /// Current state
    in_congestion: bool,
}

impl CongestionState {
    fn new() -> Self {
        Self {
            congestion_window: 10.0,
            tokens: 10.0,
            last_refill: Instant::now(),
            last_send: Instant::now(),
            rtt_samples: VecDeque::with_capacity(10),
            loss_events: VecDeque::with_capacity(20),
            in_congestion: false,
        }
    }

    /// Update state with RTT measurement
    fn add_rtt_sample(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > 10 {
            self.rtt_samples.pop_front();
        }
    }

    /// Record loss event
    fn record_loss(&mut self) {
        self.loss_events.push_back(Instant::now());
    }

    /// Get average RTT from recent samples
    fn avg_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.is_empty() {
            return None;
        }

        let total_micros: u64 = self
            .rtt_samples
            .iter()
            .map(|rtt| rtt.as_micros() as u64)
            .sum();
        Some(Duration::from_micros(
            total_micros / self.rtt_samples.len() as u64,
        ))
    }

    /// Calculate recent loss ratio
    fn loss_ratio(&self, window: Duration) -> f64 {
        let cutoff = Instant::now().checked_sub(window).unwrap();
        let recent_losses = self.loss_events.iter().filter(|&&t| t > cutoff).count();

        // Estimate based on recent activity
        if recent_losses > 0 {
            0.1 // Conservative estimate
        } else {
            0.0
        }
    }

    /// Clean old samples and events
    fn cleanup_old_data(&mut self, window: Duration) {
        let cutoff = Instant::now().checked_sub(window).unwrap();
        self.loss_events.retain(|&t| t > cutoff);
    }
}

/// Prioritized datagram queue entry
#[derive(Debug)]
#[allow(dead_code)]
struct QueuedDatagram {
    frame: DatagramFrame,
    metadata: DatagramMetadata,
    enqueued_at: Instant,
}

/// Congestion-aware datagram sender
#[derive(Debug)]
pub struct CongestionController {
    /// Configuration
    config: CongestionConfig,
    /// Per-priority queues
    priority_queues: HashMap<DatagramPriority, VecDeque<QueuedDatagram>>,
    /// Congestion state
    state: CongestionState,
    /// Statistics
    stats: CongestionStats,
}

impl CongestionController {
    /// Create new congestion controller
    pub fn new(config: CongestionConfig) -> Self {
        let mut priority_queues = HashMap::new();
        priority_queues.insert(DatagramPriority::High, VecDeque::new());
        priority_queues.insert(DatagramPriority::Normal, VecDeque::new());
        priority_queues.insert(DatagramPriority::Low, VecDeque::new());
        priority_queues.insert(DatagramPriority::Background, VecDeque::new());

        let mut state = CongestionState::new();
        if let Some(initial_last_send) = state.last_send.checked_sub(config.min_send_interval) {
            state.last_send = initial_last_send;
        }

        Self {
            config,
            priority_queues,
            state,
            stats: CongestionStats::default(),
        }
    }

    /// Enqueue datagram for transmission
    pub fn enqueue_datagram(
        &mut self,
        frame: DatagramFrame,
        metadata: DatagramMetadata,
    ) -> Outcome<(), DatagramError> {
        // Check queue depth limit
        let total_queued = self.total_queued_count();
        if total_queued >= self.config.max_queue_depth {
            // Drop lower priority items first
            if !self.try_drop_lower_priority(metadata.priority) {
                self.stats.dropped_count += 1;
                return Outcome::err(DatagramError::CongestionDrop);
            }
        }

        // Add to appropriate priority queue
        let queue = self
            .priority_queues
            .get_mut(&metadata.priority)
            .expect("priority queue should exist");

        queue.push_back(QueuedDatagram {
            frame,
            metadata,
            enqueued_at: Instant::now(),
        });

        self.stats.enqueued_count += 1;
        Outcome::ok(())
    }

    /// Try to send next datagram if congestion allows
    pub fn try_send_next(
        &mut self,
    ) -> Outcome<Option<(DatagramFrame, DatagramMetadata)>, DatagramError> {
        let now = Instant::now();

        // Update tokens and congestion state
        self.update_congestion_state(now);

        // Check if we can send based on congestion control
        if !self.can_send_now(now) {
            return Outcome::ok(None);
        }

        // Find next datagram to send (highest priority first)
        let priorities = [
            DatagramPriority::High,
            DatagramPriority::Normal,
            DatagramPriority::Low,
            DatagramPriority::Background,
        ];

        for priority in &priorities {
            let queue = self
                .priority_queues
                .get_mut(priority)
                .expect("priority queue should exist");

            // Remove expired datagrams
            while let Some(front) = queue.front() {
                if front.metadata.is_expired() {
                    queue.pop_front();
                    self.stats.expired_count += 1;
                } else {
                    break;
                }
            }

            // Send first non-expired datagram
            if let Some(queued) = queue.pop_front() {
                self.consume_send_budget();
                self.stats.sent_count += 1;
                self.state.last_send = now;

                return Outcome::ok(Some((queued.frame, queued.metadata)));
            }
        }

        Outcome::ok(None)
    }

    /// Update congestion state based on feedback
    pub fn update_congestion_feedback(&mut self, rtt: Option<Duration>, loss_detected: bool) {
        if let Some(rtt) = rtt {
            self.state.add_rtt_sample(rtt);
        }

        if loss_detected {
            self.state.record_loss();
            self.handle_congestion_event();
        }

        self.state.cleanup_old_data(Duration::from_secs(10));
    }

    /// Reconfigure the controller as a token bucket for raw datagram senders.
    ///
    /// ATP transports that already own their wire framing (for example RQ UDP
    /// symbols) can use the same pacing engine without enqueueing synthetic
    /// [`DatagramFrame`] values. Existing queue users are unaffected.
    pub fn configure_token_bucket(
        &mut self,
        max_rate_per_sec: u32,
        max_burst_size: u32,
        min_send_interval: Duration,
    ) {
        self.config.algorithm = CongestionAlgorithm::TokenBucket;
        self.config.max_rate_per_sec = max_rate_per_sec.max(1);
        self.config.max_burst_size = max_burst_size.max(1);
        self.config.min_send_interval = min_send_interval;
        self.state.tokens = self.state.tokens.min(f64::from(self.config.max_burst_size));
    }

    /// Configure token-bucket pacing from a measured *path rate* in bits/second.
    ///
    /// Convenience for the raw-datagram spray path: translate a path-bandwidth
    /// estimate (e.g. the adaptive controller's `bw_*_bps` / a netem `rate` cap)
    /// into a per-datagram token bucket so the sender paces to the link instead
    /// of bursting. The datagram rate is `path_bps / (8 * symbol_size_bytes)`,
    /// clamped to `[1, u32::MAX]` so a zero/garbage estimate can never wedge the
    /// pacer at a zero rate.
    ///
    /// `max_burst_datagrams` is the load-bearing knob: it bounds how many
    /// datagrams a single spray round may release back-to-back. Sized to the
    /// receiver / shaped-qdisc absorb depth (a few dozen datagrams), it prevents
    /// the failure an *unpaced* spray hits on a fast, low-latency link — the
    /// kernel netem/tbf buffer fills, tail-drops the overflow, and the fountain
    /// never source-completes. Pair with [`Self::try_consume_send_budget`] /
    /// [`Self::time_until_send_budget`] in the per-datagram send loop.
    pub fn configure_for_path_rate(
        &mut self,
        path_bps: u64,
        symbol_size_bytes: u32,
        max_burst_datagrams: u32,
    ) {
        let bits_per_datagram = u64::from(symbol_size_bytes.max(1)).saturating_mul(8).max(1);
        let datagrams_per_sec = (path_bps / bits_per_datagram).clamp(1, u64::from(u32::MAX));
        let rate = u32::try_from(datagrams_per_sec).unwrap_or(u32::MAX);
        self.configure_token_bucket(rate, max_burst_datagrams.max(1), Duration::ZERO);
    }

    /// Configure this token bucket from the shared ATP datagram rate decision.
    ///
    /// RQ, native QUIC DATAGRAM, and any future bonded donor should consume this
    /// decision instead of carrying an independent rate model.
    pub fn configure_from_rate_decision(
        &mut self,
        decision: DatagramRateDecision,
        symbol_size_bytes: u32,
        max_burst_datagrams: u32,
    ) {
        let symbol_bytes = u64::from(symbol_size_bytes.max(1));
        if decision.send_budget_bytes < symbol_bytes {
            self.configure_for_path_rate(decision.pacing_rate_bps.max(1), symbol_size_bytes, 1);
            self.state.tokens = 0.0;
            return;
        }

        let flow_limited_burst = (decision.send_budget_bytes / symbol_bytes)
            .clamp(1, u64::from(max_burst_datagrams.max(1)));
        let burst = u32::try_from(flow_limited_burst).unwrap_or(max_burst_datagrams.max(1));
        self.configure_for_path_rate(decision.pacing_rate_bps.max(1), symbol_size_bytes, burst);
    }

    /// Try to consume one raw-datagram send budget unit.
    ///
    /// Returns `true` when the caller may emit one datagram immediately. Returns
    /// `false` when the configured congestion algorithm is currently pacing the
    /// sender. This method shares the same budget accounting as
    /// [`Self::try_send_next`] but does not touch the priority queues.
    pub fn try_consume_send_budget(&mut self, now: Instant) -> bool {
        self.update_congestion_state(now);
        if !self.can_send_now(now) {
            return false;
        }
        self.consume_send_budget();
        self.stats.sent_count = self.stats.sent_count.saturating_add(1);
        self.state.last_send = now;
        true
    }

    /// Return the deterministic wait until one raw datagram budget unit is likely
    /// to be available.
    ///
    /// The caller still rechecks [`Self::try_consume_send_budget`] after sleeping;
    /// this is a pacing hint, not a reservation.
    pub fn time_until_send_budget(&mut self, now: Instant) -> Duration {
        self.update_congestion_state(now);
        if self.can_send_now(now) {
            return Duration::ZERO;
        }

        match self.config.algorithm {
            CongestionAlgorithm::TokenBucket => {
                let deficit = (1.0 - self.state.tokens).max(0.0);
                if deficit <= f64::EPSILON {
                    Duration::ZERO
                } else {
                    let seconds = deficit / f64::from(self.config.max_rate_per_sec.max(1));
                    Duration::from_secs_f64(seconds.max(0.000_001))
                }
            }
            CongestionAlgorithm::RateLimited
            | CongestionAlgorithm::Aimd
            | CongestionAlgorithm::Adaptive => self
                .config
                .min_send_interval
                .saturating_sub(now.duration_since(self.state.last_send)),
        }
    }

    /// Handle congestion event (loss, timeout, etc.)
    fn handle_congestion_event(&mut self) {
        match self.config.algorithm {
            CongestionAlgorithm::RateLimited => {
                // No adjustment for simple rate limiting
            }
            CongestionAlgorithm::Aimd => {
                self.state.congestion_window *= self.config.aimd_decrease;
                self.state.congestion_window = self.state.congestion_window.max(1.0);
                self.state.in_congestion = true;
            }
            CongestionAlgorithm::TokenBucket => {
                // Reduce token generation rate temporarily
                self.state.tokens = self.state.tokens.min(1.0);
                self.state.congestion_window *= self.config.aimd_decrease;
                self.state.congestion_window = self.state.congestion_window.max(1.0);
            }
            CongestionAlgorithm::Adaptive => {
                // Adaptive response based on current conditions
                if let Some(avg_rtt) = self.state.avg_rtt() {
                    if avg_rtt > self.config.rtt_threshold {
                        self.state.congestion_window *= 0.7; // Aggressive reduction
                    } else {
                        self.state.congestion_window *= 0.85; // Mild reduction
                    }
                }
                self.state.congestion_window = self.state.congestion_window.max(1.0);
            }
        }

        self.stats.congestion_events += 1;
    }

    /// Update congestion control state
    fn update_congestion_state(&mut self, now: Instant) {
        match self.config.algorithm {
            CongestionAlgorithm::RateLimited => {
                // Simple rate limiting - no state update needed
            }
            CongestionAlgorithm::Aimd => {
                // Increase window if not in congestion
                if !self.state.in_congestion {
                    let since_last = now.duration_since(self.state.last_send);
                    if let Some(avg_rtt) = self.state.avg_rtt() {
                        if since_last >= avg_rtt {
                            self.state.congestion_window += self.config.aimd_increase;
                        }
                    }
                }

                // Exit congestion state after delay
                if self.state.in_congestion {
                    let loss_ratio = self.state.loss_ratio(Duration::from_secs(5));
                    if loss_ratio < self.config.loss_threshold {
                        self.state.in_congestion = false;
                    }
                }
            }
            CongestionAlgorithm::TokenBucket => {
                self.refill_tokens(now);
            }
            CongestionAlgorithm::Adaptive => {
                self.adaptive_update(now);
            }
        }
    }

    /// Refill token bucket
    fn refill_tokens(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.state.last_refill);
        let tokens_to_add = (elapsed.as_secs_f64() * self.config.max_rate_per_sec as f64)
            .min(self.config.max_burst_size as f64);

        self.state.tokens =
            (self.state.tokens + tokens_to_add).min(self.config.max_burst_size as f64);
        self.state.last_refill = now;
    }

    /// Adaptive congestion control update
    fn adaptive_update(&mut self, _now: Instant) {
        let loss_ratio = self.state.loss_ratio(Duration::from_secs(5));
        let avg_rtt = self.state.avg_rtt();

        // Adjust based on current network conditions
        if loss_ratio > self.config.loss_threshold {
            // High loss - reduce window
            self.state.congestion_window *= 0.8;
        } else if let Some(rtt) = avg_rtt {
            if rtt > self.config.rtt_threshold {
                // High RTT - moderate reduction
                self.state.congestion_window *= 0.9;
            } else {
                // Good conditions - gradual increase
                self.state.congestion_window += 0.5;
            }
        } else {
            // No RTT data - conservative increase
            self.state.congestion_window += 0.1;
        }

        self.state.congestion_window = self.state.congestion_window.clamp(1.0, 100.0);
    }

    /// Check if we can send now based on congestion control
    fn can_send_now(&self, now: Instant) -> bool {
        match self.config.algorithm {
            CongestionAlgorithm::RateLimited => {
                now.duration_since(self.state.last_send) >= self.config.min_send_interval
            }
            CongestionAlgorithm::Aimd => {
                self.state.congestion_window >= 1.0
                    && now.duration_since(self.state.last_send) >= self.config.min_send_interval
            }
            CongestionAlgorithm::TokenBucket => self.state.tokens >= 1.0,
            CongestionAlgorithm::Adaptive => {
                self.state.congestion_window >= 1.0
                    && now.duration_since(self.state.last_send) >= self.config.min_send_interval
            }
        }
    }

    /// Consume send budget (tokens, window, etc.)
    fn consume_send_budget(&mut self) {
        match self.config.algorithm {
            CongestionAlgorithm::RateLimited => {
                // No budget consumption
            }
            CongestionAlgorithm::Aimd | CongestionAlgorithm::Adaptive => {
                self.state.congestion_window -= 1.0;
            }
            CongestionAlgorithm::TokenBucket => {
                self.state.tokens -= 1.0;
            }
        }
    }

    /// Try to drop lower priority items to make space
    fn try_drop_lower_priority(&mut self, new_priority: DatagramPriority) -> bool {
        // Try to drop from lower priority queues
        let priorities = [
            DatagramPriority::Background,
            DatagramPriority::Low,
            DatagramPriority::Normal,
            DatagramPriority::High,
        ];

        for priority in &priorities {
            if *priority >= new_priority {
                break;
            }

            let queue = self
                .priority_queues
                .get_mut(priority)
                .expect("priority queue should exist");

            if !queue.is_empty() {
                queue.pop_front();
                self.stats.dropped_count += 1;
                return true;
            }
        }

        false
    }

    /// Get total number of queued datagrams
    fn total_queued_count(&self) -> usize {
        self.priority_queues.values().map(|queue| queue.len()).sum()
    }

    /// Get congestion statistics
    pub fn get_stats(&self) -> &CongestionStats {
        &self.stats
    }

    /// Get queue depth by priority
    pub fn queue_depth(&self, priority: DatagramPriority) -> usize {
        self.priority_queues
            .get(&priority)
            .map_or(0, |queue| queue.len())
    }

    /// Get total queue depth
    pub fn total_queue_depth(&self) -> usize {
        self.total_queued_count()
    }

    /// Check if congestion control is limiting sends
    pub fn is_congestion_limited(&self) -> bool {
        !self.can_send_now(Instant::now()) || self.state.in_congestion
    }

    /// Get current congestion window size
    pub fn congestion_window(&self) -> f64 {
        self.state.congestion_window
    }

    /// Get available tokens (for token bucket algorithm)
    pub fn available_tokens(&self) -> f64 {
        self.state.tokens
    }
}

/// Congestion control statistics
#[derive(Debug, Default, Clone)]
pub struct CongestionStats {
    /// Total datagrams enqueued
    pub enqueued_count: u64,
    /// Total datagrams sent
    pub sent_count: u64,
    /// Total datagrams dropped due to congestion
    pub dropped_count: u64,
    /// Total datagrams expired before sending
    pub expired_count: u64,
    /// Number of congestion events
    pub congestion_events: u64,
}

impl CongestionStats {
    /// Calculate drop ratio
    pub fn drop_ratio(&self) -> f64 {
        if self.enqueued_count > 0 {
            self.dropped_count as f64 / self.enqueued_count as f64
        } else {
            0.0
        }
    }

    /// Calculate send ratio
    pub fn send_ratio(&self) -> f64 {
        if self.enqueued_count > 0 {
            self.sent_count as f64 / self.enqueued_count as f64
        } else {
            0.0
        }
    }

    /// Check if congestion control is performing well
    pub fn is_performing_well(&self) -> bool {
        self.drop_ratio() < 0.1 && // Less than 10% drops
        self.send_ratio() > 0.8 // More than 80% sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::net::atp::datagram::frame::DatagramFrame;

    fn create_test_datagram(priority: DatagramPriority) -> (DatagramFrame, DatagramMetadata) {
        let frame = DatagramFrame::with_length(Bytes::from_static(b"test"));
        let metadata = DatagramMetadata::new("test").with_priority(priority);
        (frame, metadata)
    }

    fn matrix162_rate_config() -> DatagramRateConfig {
        DatagramRateConfig {
            initial_pacing_bytes_per_s: 1_000_000,
            min_pacing_bytes_per_s: 64_000,
            max_pacing_bytes_per_s: 100_000_000,
            initial_cwnd_bytes: 128_000,
            min_cwnd_bytes: 16_000,
            max_cwnd_bytes: 8_000_000,
            pacing_gain: 1.0,
            cwnd_gain: 2.0,
            loss_backoff_threshold: 0.02,
            loss_backoff_factor: 0.50,
            loss_delivery_headroom: 1.25,
            min_rtt_window_micros: 1_000_000,
        }
    }

    fn matrix162_rate_sample(
        at_micros: u64,
        sent_bytes: u64,
        delivered_bytes: u64,
        rtt_micros: u64,
        receiver_credit_bytes: u64,
    ) -> DatagramRateSample {
        DatagramRateSample {
            now_micros: at_micros,
            sent_bytes,
            acked_bytes: delivered_bytes,
            lost_bytes: 0,
            rtt_micros: Some(rtt_micros),
            receiver_credit_bytes: (receiver_credit_bytes > 0).then_some(receiver_credit_bytes),
        }
    }

    fn observe_rate(
        controller: &mut DatagramRateController,
        sample: DatagramRateSample,
    ) -> DatagramRateDecision {
        controller.observe(sample)
    }

    #[test]
    fn matrix162_rate_controller_tracks_ack_clocked_bottleneck_bandwidth() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());

        let clean = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
        );
        assert_eq!(clean.bottleneck_bytes_per_s, 1_000_000);
        assert_eq!(clean.pacing_bytes_per_s, 1_000_000);
        assert_eq!(clean.pacing_rate_bps, 8_000_000);
        assert_eq!(clean.min_rtt_micros, Some(100_000));
        assert_eq!(clean.sender_loss_fraction_ppm, 0);

        let faster = observe_rate(
            &mut controller,
            matrix162_rate_sample(200_000, 200_000, 200_000, 120_000, 0),
        );
        assert_eq!(faster.bottleneck_bytes_per_s, 2_000_000);
        assert_eq!(faster.pacing_bytes_per_s, 2_000_000);
        assert_eq!(faster.pacing_rate_bps, 16_000_000);
        assert_eq!(
            faster.min_rtt_micros,
            Some(100_000),
            "higher RTT inside the min-RTT window must not replace the floor"
        );
        assert!(
            faster.cwnd_bytes > clean.cwnd_bytes,
            "cwnd should grow with the bottleneck-bandwidth estimate"
        );
    }

    #[test]
    fn matrix162_rate_controller_backs_off_on_sender_side_delivery_loss() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let clean = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
        );

        let lossy = observe_rate(
            &mut controller,
            matrix162_rate_sample(200_000, 1_000_000, 100_000, 110_000, 0),
        );
        assert!(
            lossy.sender_loss_fraction_ppm >= 900_000,
            "sender-side sent-vs-delivered loss must see queue overflow"
        );
        assert!(
            lossy.pacing_bytes_per_s < clean.pacing_bytes_per_s,
            "loss must back off the shared pacing authority"
        );
    }

    #[test]
    fn matrix162_rate_controller_tracks_windowed_min_rtt() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());

        let floor = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
        );
        assert_eq!(floor.min_rtt_micros, Some(100_000));

        let in_window = observe_rate(
            &mut controller,
            matrix162_rate_sample(600_000, 100_000, 100_000, 130_000, 0),
        );
        assert_eq!(
            in_window.min_rtt_micros,
            Some(100_000),
            "higher RTT inside the window must not raise the floor"
        );

        let expired = observe_rate(
            &mut controller,
            matrix162_rate_sample(1_300_000, 100_000, 100_000, 140_000, 0),
        );
        assert_eq!(
            expired.min_rtt_micros,
            Some(140_000),
            "expired min-RTT windows may refresh upward"
        );
    }

    #[test]
    fn matrix162_rate_controller_caps_inflight_to_receiver_credit() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let decision = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 1_000_000, 1_000_000, 100_000, 64_000),
        );

        assert_eq!(decision.receiver_credit_bytes, Some(64_000));
        assert!(
            decision.cwnd_bytes > 64_000,
            "test sample should build a larger congestion window than receiver credit"
        );
        assert_eq!(
            decision.inflight_limit_bytes, 64_000,
            "receiver credit must cap the effective send window"
        );
    }

    #[test]
    fn matrix162_rate_controller_replays_deterministically() {
        let samples = [
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
            matrix162_rate_sample(200_000, 1_000_000, 100_000, 120_000, 0),
            matrix162_rate_sample(1_400_000, 1_500_000, 1_500_000, 90_000, 0),
        ];

        let mut left = DatagramRateController::new(matrix162_rate_config());
        let mut right = DatagramRateController::new(matrix162_rate_config());
        let left_decisions: Vec<_> = samples
            .iter()
            .copied()
            .map(|sample| observe_rate(&mut left, sample))
            .collect();
        let right_decisions: Vec<_> = samples
            .iter()
            .copied()
            .map(|sample| observe_rate(&mut right, sample))
            .collect();

        assert_eq!(
            left_decisions, right_decisions,
            "explicit samples must replay to identical controller decisions"
        );
    }

    #[test]
    fn matrix162_rate_controller_enforces_send_slot_and_receiver_credit() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let decision = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 64_000),
        );

        assert!(controller.can_send(0, 1200, decision.receiver_credit_bytes));
        assert!(!controller.can_send(64_000, 1200, decision.receiver_credit_bytes));
        assert!(controller.try_send(100_000, 0, 1200, decision.receiver_credit_bytes));
        assert!(
            !controller.try_send(100_000, 1200, 1200, decision.receiver_credit_bytes),
            "second send at the same timestamp must wait for the pacing slot"
        );
        let wait = controller.time_until_send_micros(100_000);
        assert!(wait > 0);
        assert!(controller.try_send(100_000 + wait, 1200, 1200, decision.receiver_credit_bytes));
    }

    #[test]
    fn matrix162_rate_controller_configures_shared_receiver_limited_budget() {
        let mut rate = DatagramRateController::new(DatagramRateConfig {
            initial_pacing_bytes_per_s: 48_000,
            min_pacing_bytes_per_s: 48_000,
            max_pacing_bytes_per_s: 48_000,
            initial_cwnd_bytes: 16_000,
            min_cwnd_bytes: 16_000,
            max_cwnd_bytes: 16_000,
            ..DatagramRateConfig::default()
        });
        let decision = rate.observe(DatagramRateSample {
            now_micros: 100_000,
            sent_bytes: 4 * 1200,
            acked_bytes: 4 * 1200,
            lost_bytes: 0,
            rtt_micros: Some(100_000),
            receiver_credit_bytes: Some(4 * 1200),
        });

        let mut controller = CongestionController::new(CongestionConfig::default());
        controller.configure_from_rate_decision(decision, 1200, 32);
        let now = Instant::now();

        let mut burst = 0;
        while controller.try_consume_send_budget(now) {
            burst += 1;
            assert!(
                burst <= 4,
                "receiver-limited shared decision allowed burst {burst}"
            );
        }
        assert_eq!(
            burst, 4,
            "shared receiver credit should limit the legacy token budget"
        );
        assert!(controller.time_until_send_budget(now) > Duration::ZERO);
    }

    #[test]
    fn test_congestion_controller_creation() {
        let config = CongestionConfig::default();
        let controller = CongestionController::new(config);

        assert_eq!(controller.total_queue_depth(), 0);
        assert!(!controller.is_congestion_limited());
        assert!(controller.congestion_window() > 0.0);
    }

    #[test]
    fn test_datagram_enqueuing() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        controller.enqueue_datagram(frame, metadata).unwrap();

        assert_eq!(controller.total_queue_depth(), 1);
        assert_eq!(controller.queue_depth(DatagramPriority::Normal), 1);
    }

    #[test]
    fn test_priority_ordering() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        // Enqueue low priority first, then high priority
        let (frame1, metadata1) = create_test_datagram(DatagramPriority::Low);
        let (frame2, metadata2) = create_test_datagram(DatagramPriority::High);

        controller.enqueue_datagram(frame1, metadata1).unwrap();
        controller.enqueue_datagram(frame2, metadata2).unwrap();

        // High priority should come out first
        let (_frame, metadata) = controller.try_send_next().unwrap().unwrap();
        assert_eq!(metadata.priority, DatagramPriority::High);
    }

    #[test]
    fn test_congestion_feedback() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        let initial_window = controller.congestion_window();

        // Report loss - should reduce congestion window
        controller.update_congestion_feedback(Some(Duration::from_millis(50)), true);

        assert!(controller.congestion_window() < initial_window);
        assert!(controller.get_stats().congestion_events > 0);
    }

    #[test]
    fn test_token_bucket_algorithm() {
        let mut config = CongestionConfig::default();
        config.algorithm = CongestionAlgorithm::TokenBucket;
        config.max_rate_per_sec = 10;
        config.max_burst_size = 5;

        let mut controller = CongestionController::new(config);

        // Should have initial tokens
        assert!(controller.available_tokens() > 0.0);

        // Send until tokens are exhausted
        for _ in 0..10 {
            let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
            controller.enqueue_datagram(frame, metadata).unwrap();
        }

        // Send a few datagrams
        let mut sent_count = 0;
        while controller.try_send_next().unwrap().is_some() {
            sent_count += 1;
            if sent_count > 10 {
                break; // Prevent infinite loop
            }
        }

        // Should eventually run out of tokens
        assert!(controller.available_tokens() < 1.0);
    }

    #[test]
    fn token_bucket_raw_budget_consumes_without_queue_frames() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        controller.configure_token_bucket(10, 2, Duration::ZERO);
        let now = Instant::now();

        assert!(controller.try_consume_send_budget(now));
        assert!(controller.try_consume_send_budget(now));
        assert!(!controller.try_consume_send_budget(now));
        assert!(controller.time_until_send_budget(now) > Duration::ZERO);
        assert_eq!(controller.total_queue_depth(), 0);
        assert_eq!(controller.get_stats().sent_count, 2);
    }

    #[test]
    fn configure_for_path_rate_bounds_burst_and_paces_to_datagram_rate() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        // 96 kbit/s over 1200-byte datagrams = 9600 bit/datagram => 10 datagrams/sec.
        controller.configure_for_path_rate(96_000, 1200, 4);
        let now = Instant::now();

        // A single spray burst is bounded by max_burst_datagrams (the qdisc guard).
        let mut burst = 0u32;
        while controller.try_consume_send_budget(now) {
            burst += 1;
            assert!(burst <= 4, "burst {burst} exceeded the configured bound");
        }
        assert_eq!(
            burst, 4,
            "burst should drain exactly the bounded token count"
        );

        // Drained: the pacer now gates, and the hint is ~1/rate (100 ms at 10 dps).
        assert!(!controller.try_consume_send_budget(now));
        let wait = controller.time_until_send_budget(now);
        assert!(wait > Duration::ZERO);
        assert!(
            wait <= Duration::from_millis(150),
            "wait {wait:?} too long for 10 dps"
        );
    }

    #[test]
    fn configure_for_path_rate_faster_link_refills_sooner() {
        let now = Instant::now();
        let mut slow = CongestionController::new(CongestionConfig::default());
        slow.configure_for_path_rate(96_000, 1200, 1); // 10 datagrams/sec
        let mut fast = CongestionController::new(CongestionConfig::default());
        fast.configure_for_path_rate(9_600_000, 1200, 1); // 1000 datagrams/sec

        // Drain the single-token burst on each, then compare refill latency.
        assert!(slow.try_consume_send_budget(now));
        assert!(fast.try_consume_send_budget(now));
        assert!(fast.time_until_send_budget(now) < slow.time_until_send_budget(now));
    }

    #[test]
    fn configure_for_path_rate_clamps_degenerate_rate_to_one_dps() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        // A zero / garbage path estimate must not wedge the pacer at a zero rate.
        controller.configure_for_path_rate(0, 1200, 8);
        let now = Instant::now();

        for _ in 0..8 {
            controller.try_consume_send_budget(now);
        }
        assert!(!controller.try_consume_send_budget(now));
        let wait = controller.time_until_send_budget(now);
        assert!(wait > Duration::ZERO);
        assert!(
            wait <= Duration::from_millis(1100),
            "rate clamp should yield ~1 dps, got {wait:?}"
        );
    }

    #[test]
    fn test_queue_depth_limiting() {
        let mut config = CongestionConfig::default();
        config.max_queue_depth = 3;

        let mut controller = CongestionController::new(config);

        // Fill queue to limit
        for _ in 0..3 {
            let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
            controller.enqueue_datagram(frame, metadata).unwrap();
        }

        // Next enqueue should fail or drop something
        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        let result = controller.enqueue_datagram(frame, metadata);

        // Either the enqueue fails or queue depth remains at limit
        if result.is_ok() {
            assert_eq!(controller.total_queue_depth(), 3);
        } else {
            assert!(matches!(
                result,
                Outcome::Err(DatagramError::CongestionDrop)
            ));
        }
    }

    #[test]
    fn test_expired_datagram_cleanup() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        // Create expired datagram
        let frame = DatagramFrame::with_length(Bytes::from_static(b"test"));
        let metadata = DatagramMetadata::new("test")
            .with_priority(DatagramPriority::Normal)
            .with_expiration(
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .expect("test instant should support one-second subtraction"),
            ); // Already expired

        controller.enqueue_datagram(frame, metadata).unwrap();
        assert_eq!(controller.total_queue_depth(), 1);

        // Try to send - should clean up expired datagram
        let result = controller.try_send_next().unwrap();
        assert!(result.is_none());
        assert_eq!(controller.total_queue_depth(), 0);
        assert!(controller.get_stats().expired_count > 0);
    }

    #[test]
    fn test_congestion_stats() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        controller.enqueue_datagram(frame, metadata).unwrap();
        controller.try_send_next().unwrap();

        let stats = controller.get_stats();
        assert_eq!(stats.enqueued_count, 1);
        assert_eq!(stats.sent_count, 1);
        assert!(stats.is_performing_well());
    }

    #[test]
    fn test_algorithm_types() {
        for algorithm in [
            CongestionAlgorithm::RateLimited,
            CongestionAlgorithm::Aimd,
            CongestionAlgorithm::TokenBucket,
            CongestionAlgorithm::Adaptive,
        ] {
            let mut config = CongestionConfig::default();
            config.algorithm = algorithm;

            let controller = CongestionController::new(config);
            assert!(controller.congestion_window() > 0.0);
        }
    }
}
