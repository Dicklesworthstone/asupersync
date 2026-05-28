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
