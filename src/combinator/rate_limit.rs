//! Rate limiting combinator for throughput control.
//!
//! The rate_limit combinator enforces throughput limits on operations using a
//! token bucket algorithm. This prevents overwhelming downstream services and
//! helps stay within API quotas.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::combinator::rate_limit::*;
//! use std::time::Duration;
//!
//! let policy = RateLimitPolicy {
//!     name: "api".into(),
//!     rate: 100,  // 100 operations per second
//!     period: Duration::from_secs(1),
//!     burst: 10,
//!     ..Default::default()
//! };
//!
//! let limiter = RateLimiter::new(policy);
//! let now = Time::from_millis(0);
//!
//! // Try to acquire a token
//! if limiter.try_acquire(1, now) {
//!     // Execute rate-limited operation
//!     do_work();
//! } else {
//!     // Rate exceeded, check retry_after
//!     let wait = limiter.retry_after(1, now);
//! }
//! ```

use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::types::Time;

// =========================================================================
// Policy Configuration
// =========================================================================

/// Rate limiter configuration.
#[derive(Clone)]
pub struct RateLimitPolicy {
    /// Name for logging/metrics.
    pub name: String,

    /// Operations allowed per period.
    pub rate: u32,

    /// Time period for rate calculation.
    pub period: Duration,

    /// Maximum burst capacity (tokens can accumulate up to this).
    pub burst: u32,

    /// How to handle rate exceeded.
    pub wait_strategy: WaitStrategy,

    /// Cost per operation (default 1, allows weighted operations).
    pub default_cost: u32,

    /// Algorithm variant.
    pub algorithm: RateLimitAlgorithm,
}

/// Strategy when rate limit is exceeded.
#[derive(Clone, Debug, Default)]
pub enum WaitStrategy {
    /// Wait until tokens available (requires polling).
    #[default]
    Block,

    /// Fail immediately if rate exceeded.
    Reject,

    /// Wait up to specified duration, then fail.
    BlockWithTimeout(Duration),
}

/// Rate limiting algorithm.
#[derive(Clone, Debug, Default)]
pub enum RateLimitAlgorithm {
    /// Classic token bucket.
    #[default]
    TokenBucket,

    /// Sliding window log (more memory, smoother).
    SlidingWindowLog {
        /// Window size for the sliding window.
        window_size: Duration,
    },

    /// Fixed window (simpler, allows bursts at boundaries).
    FixedWindow,
}

impl fmt::Debug for RateLimitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimitPolicy")
            .field("name", &self.name)
            .field("rate", &self.rate)
            .field("period", &self.period)
            .field("burst", &self.burst)
            .field("wait_strategy", &self.wait_strategy)
            .field("default_cost", &self.default_cost)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            name: "default".into(),
            rate: 100,
            period: Duration::from_secs(1),
            burst: 10,
            wait_strategy: WaitStrategy::default(),
            default_cost: 1,
            algorithm: RateLimitAlgorithm::default(),
        }
    }
}

impl RateLimitPolicy {
    /// Sets the rate (operations per period).
    #[must_use]
    pub const fn rate(mut self, rate: u32) -> Self {
        self.rate = rate;
        self
    }

    /// Sets the burst capacity.
    #[must_use]
    pub const fn burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }
}

// =========================================================================
// Metrics & Observability
// =========================================================================

/// Metrics exposed by rate limiter.
#[derive(Clone, Debug, Default)]
pub struct RateLimitMetrics {
    /// Current available tokens.
    pub available_tokens: f64,

    /// Total operations allowed.
    pub total_allowed: u64,

    /// Total operations rejected (immediate).
    pub total_rejected: u64,

    /// Total operations that waited.
    pub total_waited: u64,

    /// Total time spent waiting (all operations).
    pub total_wait_time: Duration,

    /// Average wait time per operation that waited.
    pub avg_wait_time: Duration,

    /// Maximum wait time observed.
    pub max_wait_time: Duration,

    /// Operations per second (recent).
    pub current_rate: f64,

    /// Time until next token available.
    pub next_token_available: Option<Duration>,
}

// =========================================================================
// Wait Queue Entry
// =========================================================================

/// Reason an entry was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectionReason {
    Timeout,
    Cancelled,
}

/// Result of a queue entry: None = waiting, Some(Ok(())) = granted, Some(Err(reason)) = rejected.
type QueueEntryResult = Option<Result<(), RejectionReason>>;

/// Entry in the waiting queue.
#[derive(Debug)]
struct QueueEntry {
    id: u64,
    cost: u32,
    enqueued_at_millis: u64,
    deadline_millis: u64,
    /// State of this entry.
    result: QueueEntryResult,
}

// =========================================================================
// Token Bucket Implementation
// =========================================================================

/// Fixed-point scale for token storage (allows fractional tokens).
const FIXED_POINT_SCALE: u64 = 1000;

#[inline]
fn duration_to_millis_saturating(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

/// Internal state of the token bucket.
struct BucketState {
    /// Token bucket state (stored as fixed-point).
    /// tokens * FIXED_POINT_SCALE to allow fractional tokens.
    tokens_fixed: u64,

    /// Last refill time (as millis since epoch).
    last_refill: u64,
}

/// Thread-safe rate limiter using token bucket algorithm.
pub struct RateLimiter {
    policy: RateLimitPolicy,

    /// Pre-computed tokens per millisecond in fixed-point scale.
    /// Avoids FP division on every `refill_inner` call.
    tokens_per_ms_fixed: f64,

    /// Protected bucket state.
    state: Mutex<BucketState>,

    /// Waiting queue for FIFO ordering.
    wait_queue: RwLock<VecDeque<QueueEntry>>,

    /// Next entry ID.
    next_id: AtomicU64,

    // Atomic counters for hot path
    total_allowed: AtomicU64,
    total_rejected: AtomicU64,
    total_waited: AtomicU64,
    total_wait_time_ms: AtomicU64,
    max_wait_time_ms: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given policy.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(policy: RateLimitPolicy) -> Self {
        let initial_tokens = u64::from(policy.burst) * FIXED_POINT_SCALE;
        let period_ms = duration_to_millis_saturating(policy.period) as f64;
        let tokens_per_ms_fixed = if period_ms > 0.0 {
            (f64::from(policy.rate) / period_ms) * FIXED_POINT_SCALE as f64
        } else {
            0.0
        };

        Self {
            policy,
            tokens_per_ms_fixed,
            state: Mutex::new(BucketState {
                tokens_fixed: initial_tokens,
                last_refill: 0,
            }),
            wait_queue: RwLock::new(VecDeque::new()),
            next_id: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            total_waited: AtomicU64::new(0),
            total_wait_time_ms: AtomicU64::new(0),
            max_wait_time_ms: AtomicU64::new(0),
        }
    }

    /// Get policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.policy.name
    }

    /// Get the policy.
    #[must_use]
    pub fn policy(&self) -> &RateLimitPolicy {
        &self.policy
    }

    /// Get current metrics.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn metrics(&self) -> RateLimitMetrics {
        // Avoid lock-order inversion with process_queue() by not holding
        // metrics and state locks at the same time.
        let available_tokens = {
            let state = self.state.lock();
            state.tokens_fixed as f64 / FIXED_POINT_SCALE as f64
        };

        let total_waited = self.total_waited.load(Ordering::Relaxed);
        let total_wait_time_ms = self.total_wait_time_ms.load(Ordering::Relaxed);
        let max_wait_time_ms = self.max_wait_time_ms.load(Ordering::Relaxed);
        let avg_wait_time = if total_waited > 0 {
            Duration::from_millis(total_wait_time_ms / total_waited)
        } else {
            Duration::ZERO
        };

        RateLimitMetrics {
            available_tokens,
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_rejected: self.total_rejected.load(Ordering::Relaxed),
            total_waited,
            total_wait_time: Duration::from_millis(total_wait_time_ms),
            avg_wait_time,
            max_wait_time: Duration::from_millis(max_wait_time_ms),
            current_rate: 0.0,
            next_token_available: None,
        }
    }

    /// Refill tokens based on elapsed time.
    ///
    /// Requires lock on state.
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    fn refill_inner(&self, state: &mut BucketState, now_millis: u64) {
        if now_millis <= state.last_refill {
            return;
        }

        let elapsed_ms = now_millis - state.last_refill;

        if self.tokens_per_ms_fixed > 0.0 {
            let tokens_to_add = (elapsed_ms as f64 * self.tokens_per_ms_fixed) as u64;
            let max_tokens = u64::from(self.policy.burst) * FIXED_POINT_SCALE;

            state.tokens_fixed = (state.tokens_fixed + tokens_to_add).min(max_tokens);
        }

        state.last_refill = now_millis;
    }

    /// Refill tokens based on elapsed time from the provided deterministic clock.
    pub fn refill(&self, now: Time) {
        let mut state = self.state.lock();
        self.refill_inner(&mut state, now.as_millis());
    }

    /// Try to acquire tokens without waiting.
    ///
    /// Returns `true` if tokens were acquired, `false` if insufficient tokens.
    #[must_use]
    pub fn try_acquire(&self, cost: u32, now: Time) -> bool {
        let mut state = self.state.lock();
        let now_millis = now.as_millis();

        self.refill_inner(&mut state, now_millis);

        let cost_fixed = u64::from(cost) * FIXED_POINT_SCALE;

        if state.tokens_fixed >= cost_fixed {
            state.tokens_fixed -= cost_fixed;
            drop(state); // Release bucket lock immediately

            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Try to acquire with default cost.
    #[must_use]
    pub fn try_acquire_default(&self, now: Time) -> bool {
        self.try_acquire(self.policy.default_cost, now)
    }

    /// Execute an operation if tokens are available (no waiting).
    ///
    /// This mirrors bulkhead's synchronous call pattern: fail fast when
    /// the rate limit is exceeded.
    pub fn call<T, E, F>(&self, now: Time, op: F) -> Result<T, RateLimitError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        self.call_weighted(now, self.policy.default_cost, op)
    }

    /// Execute a weighted operation if tokens are available (no waiting).
    pub fn call_weighted<T, E, F>(
        &self,
        now: Time,
        cost: u32,
        op: F,
    ) -> Result<T, RateLimitError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        if !self.try_acquire(cost, now) {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RateLimitError::RateLimitExceeded);
        }

        match op() {
            Ok(v) => Ok(v),
            Err(e) => Err(RateLimitError::Inner(e)),
        }
    }

    /// Calculate time until tokens available.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn time_until_available(&self, cost: u32, now: Time) -> Duration {
        let current_fixed = {
            let mut state = self.state.lock();
            self.refill_inner(&mut state, now.as_millis());
            state.tokens_fixed
        };
        let cost_fixed = u64::from(cost) * FIXED_POINT_SCALE;

        if current_fixed >= cost_fixed {
            return Duration::ZERO;
        }

        let tokens_needed = cost_fixed - current_fixed;
        let period_ms = self.policy.period.as_millis() as f64;
        let tokens_per_ms = (f64::from(self.policy.rate) / period_ms) * FIXED_POINT_SCALE as f64;

        if tokens_per_ms <= 0.0 {
            return Duration::MAX; // No refill rate
        }

        let ms_needed = (tokens_needed as f64 / tokens_per_ms).ceil() as u64;
        Duration::from_millis(ms_needed)
    }

    /// Get retry-after duration (for HTTP 429 responses).
    ///
    /// Uses the provided time for determinism (pass `cx.now()` or similar).
    #[must_use]
    pub fn retry_after(&self, cost: u32, now: Time) -> Duration {
        self.time_until_available(cost, now)
    }

    /// Get retry-after duration for default cost.
    #[must_use]
    pub fn retry_after_default(&self, now: Time) -> Duration {
        self.retry_after(self.policy.default_cost, now)
    }

    /// Get available tokens (for metrics/debugging).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn available_tokens(&self) -> f64 {
        let state = self.state.lock();
        state.tokens_fixed as f64 / FIXED_POINT_SCALE as f64
    }

    // =========================================================================
    // Queue-based waiting (similar to bulkhead)
    // =========================================================================

    /// Enqueue a waiting operation.
    ///
    /// Returns `Ok(entry_id)` if enqueued, `Err(RateLimitExceeded)` if rate exceeded
    /// and policy is Reject.
    #[allow(clippy::cast_precision_loss, clippy::significant_drop_tightening)]
    pub fn enqueue(&self, cost: u32, now: Time) -> Result<u64, RateLimitError<()>> {
        // Fast path: try immediate acquisition
        if self.try_acquire(cost, now) {
            return Ok(u64::MAX); // Special sentinel meaning "already acquired"
        }

        // Check wait strategy
        match &self.policy.wait_strategy {
            WaitStrategy::Reject => {
                self.total_rejected.fetch_add(1, Ordering::Relaxed);
                return Err(RateLimitError::RateLimitExceeded);
            }
            WaitStrategy::Block | WaitStrategy::BlockWithTimeout(_) => {
                // Will enqueue below
            }
        }

        // Calculate deadline
        let now_millis = now.as_millis();
        let deadline_millis = match &self.policy.wait_strategy {
            WaitStrategy::BlockWithTimeout(timeout) => {
                let timeout_millis = duration_to_millis_saturating(*timeout);
                now_millis.saturating_add(timeout_millis)
            }
            _ => u64::MAX,
        };

        let mut queue = self.wait_queue.write();
        let entry_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        queue.push_back(QueueEntry {
            id: entry_id,
            cost,
            enqueued_at_millis: now_millis,
            deadline_millis,
            result: None,
        });

        self.total_waited.fetch_add(1, Ordering::Relaxed);

        Ok(entry_id)
    }

    /// Process the queue, granting entries that can now proceed.
    ///
    /// Call this periodically or when time advances.
    /// Returns the ID of any entry that was granted, or None.
    #[allow(clippy::cast_precision_loss, clippy::significant_drop_tightening)]
    pub fn process_queue(&self, now: Time) -> Option<u64> {
        let now_millis = now.as_millis();

        let mut queue = self.wait_queue.write();

        // First, timeout expired entries
        for entry in queue.iter_mut() {
            if entry.result.is_none() && now_millis >= entry.deadline_millis {
                entry.result = Some(Err(RejectionReason::Timeout));
            }
        }

        // Try to grant awaiting entries
        let mut first_granted = None;
        let mut state = self.state.lock();
        self.refill_inner(&mut state, now_millis);

        // Accumulate metrics on the stack, then flush once outside the loop.
        let mut granted_count = 0u64;
        let mut acc_wait_time = Duration::ZERO;
        let mut max_wait_time = Duration::ZERO;

        for entry in queue.iter_mut() {
            // Skip already processed (granted/timeout/cancelled)
            if entry.result.is_some() {
                continue;
            }

            let cost_fixed = u64::from(entry.cost) * FIXED_POINT_SCALE;

            if state.tokens_fixed >= cost_fixed {
                state.tokens_fixed -= cost_fixed;
                entry.result = Some(Ok(()));

                if first_granted.is_none() {
                    first_granted = Some(entry.id);
                }

                let wait_ms = now_millis.saturating_sub(entry.enqueued_at_millis);
                let wait_duration = Duration::from_millis(wait_ms);
                acc_wait_time += wait_duration;
                if wait_duration > max_wait_time {
                    max_wait_time = wait_duration;
                }
                granted_count += 1;
            } else {
                // Stop at first ungrantable entry to preserve FIFO order.
                break;
            }
        }

        // Flush accumulated metrics via atomics (no write lock needed).
        if granted_count > 0 {
            self.total_allowed
                .fetch_add(granted_count, Ordering::Relaxed);

            let wait_ms = duration_to_millis_saturating(acc_wait_time);
            self.total_wait_time_ms.fetch_add(wait_ms, Ordering::Relaxed);

            // CAS loop for max_wait_time_ms
            let new_max_ms = duration_to_millis_saturating(max_wait_time);
            let mut cur = self.max_wait_time_ms.load(Ordering::Relaxed);
            while new_max_ms > cur {
                match self.max_wait_time_ms.compare_exchange_weak(
                    cur,
                    new_max_ms,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }

        first_granted
    }

    /// Check the status of a queued entry.
    ///
    /// Returns:
    /// - `Ok(true)` if granted
    /// - `Ok(false)` if still waiting
    /// - `Err(Timeout)` if timed out
    /// - `Err(Cancelled)` if cancelled
    #[allow(clippy::option_if_let_else, clippy::significant_drop_tightening)]
    pub fn check_entry(&self, entry_id: u64, now: Time) -> Result<bool, RateLimitError<()>> {
        // Special sentinel for already acquired
        if entry_id == u64::MAX {
            return Ok(true);
        }

        // Process queue to handle timeouts and grants
        let _ = self.process_queue(now);

        let mut queue = self.wait_queue.write();
        let entry_idx = queue.iter().position(|e| e.id == entry_id);

        if let Some(idx) = entry_idx {
            let entry = &queue[idx];
            match entry.result {
                Some(Ok(())) => {
                    // Remove the granted entry
                    queue.remove(idx);
                    Ok(true)
                }
                Some(Err(RejectionReason::Timeout)) => {
                    let wait_ms = now.as_millis().saturating_sub(entry.enqueued_at_millis);
                    queue.remove(idx);
                    Err(RateLimitError::Timeout {
                        waited: Duration::from_millis(wait_ms),
                    })
                }
                Some(Err(RejectionReason::Cancelled)) => {
                    queue.remove(idx);
                    Err(RateLimitError::Cancelled)
                }
                None => Ok(false),
            }
        } else {
            // Entry not found - likely already processed
            Err(RateLimitError::Cancelled)
        }
    }

    /// Cancel a queued entry.
    pub fn cancel_entry(&self, entry_id: u64) {
        if entry_id == u64::MAX {
            return; // Special sentinel, nothing to cancel
        }

        let mut queue = self.wait_queue.write();
        if let Some(entry) = queue.iter_mut().find(|e| e.id == entry_id) {
            if entry.result.is_none() {
                entry.result = Some(Err(RejectionReason::Cancelled));
            }
        }
    }

    /// Reset the rate limiter to full capacity.
    pub fn reset(&self) {
        let initial_tokens = u64::from(self.policy.burst) * FIXED_POINT_SCALE;

        {
            let mut state = self.state.lock();
            state.tokens_fixed = initial_tokens;
            state.last_refill = 0;
        }

        let mut queue = self.wait_queue.write();
        for entry in queue.iter_mut() {
            if entry.result.is_none() {
                entry.result = Some(Err(RejectionReason::Cancelled));
            }
        }
        queue.clear();
    }
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("name", &self.policy.name)
            .field("available_tokens", &self.available_tokens())
            .field("rate", &self.policy.rate)
            .field("burst", &self.policy.burst)
            .finish_non_exhaustive()
    }
}

// =========================================================================
// Sliding Window Implementation
// =========================================================================

/// Sliding window rate limiter for smoother rate enforcement.
pub struct SlidingWindowRateLimiter {
    policy: RateLimitPolicy,

    /// Timestamps of recent operations: (timestamp_millis, cost).
    window: RwLock<VecDeque<(u64, u32)>>,

    /// Running total of costs in the window. Maintained incrementally to
    /// avoid O(n) summation on every `try_acquire`.
    window_cost: AtomicU32,

    // Atomic counters
    total_allowed: AtomicU64,
    total_rejected: AtomicU64,
}

impl SlidingWindowRateLimiter {
    /// Create a new sliding window rate limiter.
    #[must_use]
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            window: RwLock::new(VecDeque::new()),
            window_cost: AtomicU32::new(0),
            total_allowed: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }

    /// Get policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.policy.name
    }

    /// Calculate current usage within the window.
    #[allow(clippy::cast_possible_truncation)]
    fn current_usage(&self, _now: Time) -> u32 {
        // O(1): read the running total maintained by try_acquire and cleanup_old.
        self.window_cost.load(Ordering::Relaxed)
    }

    /// Clean up old entries outside the window.
    #[allow(clippy::significant_drop_tightening, clippy::cast_possible_truncation)]
    fn cleanup_old(&self, now: Time) {
        let now_millis = now.as_millis();
        let period_millis = duration_to_millis_saturating(self.policy.period);
        let mut window = self.window.write();

        while let Some((t, c)) = window.front() {
            // Remove entries where (now - t) >= period, i.e., entry is outside the window
            if now_millis.saturating_sub(*t) >= period_millis {
                let evicted_cost = *c;
                window.pop_front();
                self.window_cost.fetch_sub(evicted_cost, Ordering::Relaxed);
            } else {
                break;
            }
        }
    }

    /// Try to acquire without waiting.
    #[must_use]
    #[allow(clippy::significant_drop_tightening, clippy::cast_possible_truncation)]
    pub fn try_acquire(&self, cost: u32, now: Time) -> bool {
        let now_millis = now.as_millis();
        let period_millis = duration_to_millis_saturating(self.policy.period);

        // Single lock acquisition: cleanup expired + check usage + add entry
        let mut window = self.window.write();

        // Cleanup expired entries inline, decrementing the running cost total.
        while let Some((t, c)) = window.front() {
            if now_millis.saturating_sub(*t) >= period_millis {
                let evicted_cost = *c;
                window.pop_front();
                self.window_cost.fetch_sub(evicted_cost, Ordering::Relaxed);
            } else {
                break;
            }
        }

        // O(1) usage from the running total (replaces O(n) summation).
        let usage = self.window_cost.load(Ordering::Relaxed);

        if usage + cost <= self.policy.rate {
            window.push_back((now_millis, cost));
            self.window_cost.fetch_add(cost, Ordering::Relaxed);
            drop(window);
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            drop(window);
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Try to acquire with default cost.
    #[must_use]
    pub fn try_acquire_default(&self, now: Time) -> bool {
        self.try_acquire(self.policy.default_cost, now)
    }

    /// Get time until capacity available.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::significant_drop_tightening)]
    pub fn time_until_available(&self, cost: u32, now: Time) -> Duration {
        self.cleanup_old(now);

        let usage = self.current_usage(now);
        if usage + cost <= self.policy.rate {
            return Duration::ZERO;
        }

        // Find when enough capacity frees up
        let needed = (usage + cost) - self.policy.rate;
        let window = self.window.read();
        let period_millis = duration_to_millis_saturating(self.policy.period);
        let now_millis = now.as_millis();

        let mut freed = 0u32;
        for (t, c) in window.iter() {
            freed += c;
            if freed >= needed {
                // This entry will expire at t + period
                let expire_at = t + period_millis;
                return Duration::from_millis(expire_at.saturating_sub(now_millis));
            }
        }

        // Should not happen if rate > 0
        Duration::MAX
    }

    /// Get retry-after duration.
    #[must_use]
    pub fn retry_after(&self, cost: u32, now: Time) -> Duration {
        self.time_until_available(cost, now)
    }

    /// Get metrics.
    #[must_use]
    pub fn metrics(&self) -> RateLimitMetrics {
        RateLimitMetrics {
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_rejected: self.total_rejected.load(Ordering::Relaxed),
            ..RateLimitMetrics::default()
        }
    }

    /// Reset the sliding window.
    pub fn reset(&self) {
        let mut window = self.window.write();
        window.clear();
        drop(window);
        self.window_cost.store(0, Ordering::Relaxed);
    }
}

impl fmt::Debug for SlidingWindowRateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlidingWindowRateLimiter")
            .field("name", &self.policy.name)
            .field("rate", &self.policy.rate)
            .field("period", &self.policy.period)
            .finish_non_exhaustive()
    }
}

// =========================================================================
// Error Types
// =========================================================================

/// Errors from rate limiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError<E> {
    /// Rate limit exceeded (reject strategy).
    RateLimitExceeded,

    /// Timed out waiting for rate limit.
    Timeout {
        /// How long we waited.
        waited: Duration,
    },

    /// Cancelled while waiting.
    Cancelled,

    /// Underlying operation error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for RateLimitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::Timeout { waited } => write!(f, "rate limit timeout after {waited:?}"),
            Self::Cancelled => write!(f, "cancelled while waiting for rate limit"),
            Self::Inner(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RateLimitError<E> {}

// =========================================================================
// Builder Pattern
// =========================================================================

/// Builder for `RateLimitPolicy`.
#[derive(Default)]
pub struct RateLimitPolicyBuilder {
    policy: RateLimitPolicy,
}

impl RateLimitPolicyBuilder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the rate limiter name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.policy.name = name.into();
        self
    }

    /// Set the rate (operations per period).
    #[must_use]
    pub const fn rate(mut self, rate: u32) -> Self {
        self.policy.rate = rate;
        self
    }

    /// Set the time period.
    #[must_use]
    pub const fn period(mut self, period: Duration) -> Self {
        self.policy.period = period;
        self
    }

    /// Set the burst capacity.
    #[must_use]
    pub const fn burst(mut self, burst: u32) -> Self {
        self.policy.burst = burst;
        self
    }

    /// Set the wait strategy.
    #[must_use]
    pub fn wait_strategy(mut self, strategy: WaitStrategy) -> Self {
        self.policy.wait_strategy = strategy;
        self
    }

    /// Set the default cost per operation.
    #[must_use]
    pub const fn default_cost(mut self, cost: u32) -> Self {
        self.policy.default_cost = cost;
        self
    }

    /// Set the algorithm.
    #[must_use]
    pub fn algorithm(mut self, algorithm: RateLimitAlgorithm) -> Self {
        self.policy.algorithm = algorithm;
        self
    }

    /// Build the policy.
    #[must_use]
    pub fn build(self) -> RateLimitPolicy {
        self.policy
    }
}

// =========================================================================
// Registry for Named Rate Limiters
// =========================================================================

/// Registry for managing multiple named rate limiters.
pub struct RateLimiterRegistry {
    limiters: RwLock<HashMap<String, Arc<RateLimiter>>>,
    default_policy: RateLimitPolicy,
}

impl RateLimiterRegistry {
    /// Create a new registry with a default policy.
    #[must_use]
    pub fn new(default_policy: RateLimitPolicy) -> Self {
        Self {
            limiters: RwLock::new(HashMap::new()),
            default_policy,
        }
    }

    /// Get or create a named rate limiter.
    pub fn get_or_create(&self, name: &str) -> Arc<RateLimiter> {
        // Fast path: read lock
        {
            let limiters = self.limiters.read();
            if let Some(l) = limiters.get(name) {
                return l.clone();
            }
        }

        // Slow path: write lock
        let mut limiters = self.limiters.write();
        limiters
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(RateLimiter::new(RateLimitPolicy {
                    name: name.to_string(),
                    ..self.default_policy.clone()
                }))
            })
            .clone()
    }

    /// Get or create with custom policy.
    pub fn get_or_create_with(&self, name: &str, policy: RateLimitPolicy) -> Arc<RateLimiter> {
        let mut limiters = self.limiters.write();
        limiters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::new(policy)))
            .clone()
    }

    /// Get metrics for all limiters.
    #[must_use]
    pub fn all_metrics(&self) -> HashMap<String, RateLimitMetrics> {
        let limiters = self.limiters.read();
        limiters
            .iter()
            .map(|(name, l)| (name.clone(), l.metrics()))
            .collect()
    }

    /// Remove a named limiter.
    pub fn remove(&self, name: &str) -> Option<Arc<RateLimiter>> {
        let mut limiters = self.limiters.write();
        limiters.remove(name)
    }
}

impl fmt::Debug for RateLimiterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let limiters = self.limiters.read();
        f.debug_struct("RateLimiterRegistry")
            .field("count", &limiters.len())
            .finish_non_exhaustive()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Token Bucket Basic Tests
    // =========================================================================

    #[test]
    fn new_limiter_has_burst_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 5,
            ..Default::default()
        });

        let tokens = rl.available_tokens();
        assert!((tokens - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn acquire_reduces_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(3, now));

        let tokens = rl.available_tokens();
        assert!((tokens - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn acquire_fails_when_insufficient_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Use all tokens
        assert!(rl.try_acquire(5, now));

        // Should fail
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn tokens_refill_over_time() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10, // 10 per second
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(10, now));
        assert!(!rl.try_acquire(1, now));

        // After 100ms, should have ~1 token
        let later = Time::from_millis(100);
        rl.refill(later);

        let tokens = rl.available_tokens();
        assert!(
            (0.9..=1.1).contains(&tokens),
            "Expected ~1 token, got {tokens}"
        );
    }

    #[test]
    fn tokens_cap_at_burst() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        rl.refill(now);

        // Wait long time
        let later = Time::from_millis(10_000);
        rl.refill(later);

        // Should still only have burst tokens
        assert!((rl.available_tokens() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_cost_always_succeeds() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 0, // No burst capacity
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Zero cost should always succeed
        assert!(rl.try_acquire(0, now));
    }

    // =========================================================================
    // Wait Strategy Tests
    // =========================================================================

    #[test]
    fn reject_strategy_fails_immediately() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            wait_strategy: WaitStrategy::Reject,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Use the token
        assert!(rl.try_acquire(1, now));

        // Next should fail
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn enqueue_with_reject_strategy_returns_error() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            wait_strategy: WaitStrategy::Reject,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Use the token
        assert!(rl.try_acquire(1, now));

        // Enqueue should return error
        let result = rl.enqueue(1, now);
        assert!(matches!(result, Err(RateLimitError::RateLimitExceeded)));
    }

    // =========================================================================
    // Weighted Operations Tests
    // =========================================================================

    #[test]
    fn weighted_operations_consume_multiple_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Heavy operation costs 5 tokens
        assert!(rl.try_acquire(5, now));
        assert!((rl.available_tokens() - 5.0).abs() < f64::EPSILON);

        // Another heavy operation
        assert!(rl.try_acquire(5, now));
        assert!(rl.available_tokens() < 0.1);

        // Cannot do even light operation
        assert!(!rl.try_acquire(1, now));
    }

    // =========================================================================
    // Time Until Available Tests
    // =========================================================================

    #[test]
    fn time_until_available_when_empty() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10, // 10 per second
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(10, now));

        // Need 1 token = 100ms
        let wait = rl.time_until_available(1, now);
        assert!(
            wait.as_millis() >= 90 && wait.as_millis() <= 110,
            "Expected ~100ms, got {wait:?}"
        );
    }

    #[test]
    fn time_until_available_zero_when_sufficient() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        let wait = rl.time_until_available(5, now);
        assert_eq!(wait, Duration::ZERO);
    }

    #[test]
    fn retry_after_uses_provided_time() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(10, now));

        // Using the provided time (not system time)
        let retry = rl.retry_after(1, now);
        assert!(retry.as_millis() >= 90 && retry.as_millis() <= 110);

        // With later time, should be less
        let later = Time::from_millis(50);
        let retry_later = rl.retry_after(1, later);
        assert!(retry_later < retry);
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn metrics_initial_values() {
        let rl = RateLimiter::new(RateLimitPolicy {
            name: "test".into(),
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let m = rl.metrics();
        assert_eq!(m.total_allowed, 0);
        assert_eq!(m.total_rejected, 0);
        assert_eq!(m.total_waited, 0);
        assert_eq!(m.total_wait_time, Duration::ZERO);
        assert_eq!(m.max_wait_time, Duration::ZERO);
    }

    #[test]
    fn metrics_track_allowed() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        assert!(rl.try_acquire(1, now));
        assert!(rl.try_acquire(1, now));
        assert!(rl.try_acquire(1, now));

        assert_eq!(rl.metrics().total_allowed, 3);
    }

    // =========================================================================
    // Queue Tests
    // =========================================================================

    #[test]
    fn enqueue_immediate_acquisition_returns_sentinel() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Should succeed immediately and return sentinel
        let result = rl.enqueue(1, now);
        assert_eq!(result, Ok(u64::MAX));
    }

    #[test]
    fn enqueue_adds_to_queue_when_exhausted() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(1, now));

        // Enqueue should succeed and return a real ID
        let result = rl.enqueue(1, now);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), u64::MAX);
    }

    #[test]
    fn process_queue_grants_when_tokens_available() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10, // 10 per second
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(1, now));

        // Enqueue
        let entry_id = rl.enqueue(1, now).unwrap();

        // Process at same time - should not grant
        assert!(rl.process_queue(now).is_none());

        // Process after 100ms - should grant (tokens refilled)
        let later = Time::from_millis(100);
        let granted = rl.process_queue(later);
        assert_eq!(granted, Some(entry_id));
    }

    #[test]
    fn check_entry_returns_granted() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Still waiting at t=0
        let result = rl.check_entry(entry_id, now);
        assert!(matches!(result, Ok(false)));

        // Granted at t=100
        let later = Time::from_millis(100);
        let result = rl.check_entry(entry_id, later);
        assert!(matches!(result, Ok(true)));
    }

    #[test]
    fn check_entry_timeout() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_mins(1), // Very slow refill
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(100)),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Check after timeout
        let later = Time::from_millis(200);
        let result = rl.check_entry(entry_id, later);
        assert!(matches!(result, Err(RateLimitError::Timeout { .. })));
    }

    #[test]
    fn cancel_entry_triggers_cancelled_error() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_mins(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Cancel
        rl.cancel_entry(entry_id);

        // Check - should return Cancelled
        let result = rl.check_entry(entry_id, now);
        assert!(matches!(result, Err(RateLimitError::Cancelled)));
    }

    // =========================================================================
    // Sliding Window Tests
    // =========================================================================

    #[test]
    fn sliding_window_enforces_rate() {
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 5,
            period: Duration::from_secs(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 5 operations should succeed
        for _ in 0..5 {
            assert!(rl.try_acquire(1, now));
        }

        // 6th should fail
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn sliding_window_clears_old_entries() {
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 5,
            period: Duration::from_secs(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Fill window
        for _ in 0..5 {
            assert!(rl.try_acquire(1, now));
        }

        // After period, should allow more
        let later = Time::from_millis(1100);
        assert!(rl.try_acquire(1, later));
    }

    #[test]
    fn sliding_window_time_until_available() {
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            name: "test".into(),
            rate: 5,
            period: Duration::from_secs(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Fill window
        for _ in 0..5 {
            assert!(rl.try_acquire(1, now));
        }

        // Should need to wait for first entry to expire
        let wait = rl.time_until_available(1, now);
        assert!(
            wait >= Duration::from_millis(900) && wait <= Duration::from_millis(1100),
            "Expected ~1000ms, got {wait:?}"
        );
    }

    #[test]
    fn sliding_window_period_overflow_does_not_wrap() {
        let overflowing_millis = Duration::new(18_446_744_073_709_551, 616_000_000);
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: overflowing_millis,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));
        // With saturating conversion this second acquire must be rejected:
        // the first entry remains inside the (effectively max) window.
        assert!(!rl.try_acquire(1, Time::from_millis(1)));
    }

    // =========================================================================
    // Registry Tests
    // =========================================================================

    #[test]
    fn registry_creates_named_limiters() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l1 = registry.get_or_create("api-a");
        let l2 = registry.get_or_create("api-b");
        let l3 = registry.get_or_create("api-a");

        assert!(Arc::ptr_eq(&l1, &l3));
        assert!(!Arc::ptr_eq(&l1, &l2));
    }

    #[test]
    fn registry_uses_provided_name() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l = registry.get_or_create("my-api");
        assert_eq!(l.name(), "my-api");
    }

    #[test]
    fn registry_custom_policy() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l = registry.get_or_create_with(
            "custom",
            RateLimitPolicy {
                rate: 1000,
                burst: 500,
                ..Default::default()
            },
        );

        assert!((l.available_tokens() - 500.0).abs() < f64::EPSILON);
    }

    #[test]
    fn registry_remove() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l1 = registry.get_or_create("temp");
        let removed = registry.remove("temp");

        assert!(removed.is_some());
        assert!(Arc::ptr_eq(&l1, &removed.unwrap()));
        assert!(registry.remove("temp").is_none());
    }

    #[test]
    fn registry_all_metrics() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l1 = registry.get_or_create("api-1");
        let l2 = registry.get_or_create("api-2");

        let now = Time::from_millis(0);
        assert!(l1.try_acquire(1, now));
        assert!(l2.try_acquire(2, now));

        let all = registry.all_metrics();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("api-1").unwrap().total_allowed, 1);
        assert_eq!(all.get("api-2").unwrap().total_allowed, 1);
    }

    // =========================================================================
    // Concurrent Access Tests
    // =========================================================================

    #[test]
    fn concurrent_acquire_safe() {
        use std::sync::atomic::AtomicU32;
        use std::thread;

        let rl = Arc::new(RateLimiter::new(RateLimitPolicy {
            rate: 1000,
            burst: 1000,
            ..Default::default()
        }));

        let now = Time::from_millis(0);
        let acquired = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let rl = rl.clone();
                let acq = acquired.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        if rl.try_acquire(1, now) {
                            acq.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Should have acquired exactly burst amount
        assert_eq!(acquired.load(Ordering::SeqCst), 1000);
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn builder_creates_policy() {
        let policy = RateLimitPolicyBuilder::new()
            .name("test")
            .rate(50)
            .period(Duration::from_millis(500))
            .burst(20)
            .default_cost(2)
            .wait_strategy(WaitStrategy::Reject)
            .build();

        assert_eq!(policy.name, "test");
        assert_eq!(policy.rate, 50);
        assert_eq!(policy.period, Duration::from_millis(500));
        assert_eq!(policy.burst, 20);
        assert_eq!(policy.default_cost, 2);
        assert!(matches!(policy.wait_strategy, WaitStrategy::Reject));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let exceeded: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        assert!(exceeded.to_string().contains("exceeded"));

        let timeout: RateLimitError<&str> = RateLimitError::Timeout {
            waited: Duration::from_millis(100),
        };
        assert!(timeout.to_string().contains("timeout"));

        let cancelled: RateLimitError<&str> = RateLimitError::Cancelled;
        assert!(cancelled.to_string().contains("cancelled"));

        let inner: RateLimitError<&str> = RateLimitError::Inner("inner error");
        assert_eq!(inner.to_string(), "inner error");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_restores_capacity() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust
        assert!(rl.try_acquire(10, now));
        assert!(rl.available_tokens() < 0.1);

        // Reset
        rl.reset();
        assert!((rl.available_tokens() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reset_cancels_queued_entries() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_mins(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Reset
        rl.reset();

        // Entry should be cancelled
        let result = rl.check_entry(entry_id, now);
        assert!(matches!(result, Err(RateLimitError::Cancelled)));
    }

    #[test]
    fn enqueue_deadline_saturates_for_huge_timeouts() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_mins(1),
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::MAX),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).expect("enqueue should succeed");
        let deadline_millis = rl
            .wait_queue
            .read()
            .iter()
            .find(|entry| entry.id == entry_id)
            .map(|entry| entry.deadline_millis)
            .expect("queued entry should exist");

        assert_eq!(deadline_millis, u64::MAX);
    }

    #[test]
    fn duration_to_millis_saturates_for_large_durations() {
        assert_eq!(duration_to_millis_saturating(Duration::MAX), u64::MAX);
    }

    #[test]
    fn metrics_completes_after_state_lock_released() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let rl = Arc::new(RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 10,
            ..Default::default()
        }));

        let state_guard = rl.state.lock();
        let rendezvous = Arc::new(Barrier::new(2));
        let rl_clone = Arc::clone(&rl);
        let rendezvous_clone = Arc::clone(&rendezvous);

        let handle = thread::spawn(move || {
            rendezvous_clone.wait();
            let _ = rl_clone.metrics();
        });

        rendezvous.wait();
        // Let spawned thread attempt metrics() while state lock is held.
        thread::sleep(Duration::from_millis(10));

        // metrics() is now lock-free except for state.lock() (for available_tokens).
        // Release state lock so the spawned thread can complete.
        drop(state_guard);
        handle.join().expect("metrics thread should complete");
    }
}
