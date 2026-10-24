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
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
    ///
    /// The limiters keep time in whole milliseconds and round the period up,
    /// so a period of 100 us counts as 1 ms and 1.9 ms as 2 ms.
    pub period: Duration,

    /// Maximum burst capacity (tokens can accumulate up to this).
    pub burst: u32,

    /// How to handle rate exceeded.
    pub wait_strategy: WaitStrategy,

    /// Cost per operation (default 1, allows weighted operations).
    pub default_cost: u32,

    /// Algorithm variant. [`RateLimiter`] runs a token bucket whichever
    /// variant is set; see [`RateLimitAlgorithm`].
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
///
/// [`RateLimiter`] implements only [`TokenBucket`](Self::TokenBucket) and
/// runs a token bucket for the other variants too. For a sliding window use
/// [`SlidingWindowRateLimiter`], whose window is the policy's `period`.
#[derive(Clone, Debug, Default)]
pub enum RateLimitAlgorithm {
    /// Classic token bucket.
    #[default]
    TokenBucket,

    /// Sliding window log (more memory, smoother). Not implemented by
    /// [`RateLimiter`]; see the type docs.
    SlidingWindowLog {
        /// Window size for the sliding window. Not read.
        window_size: Duration,
    },

    /// Fixed window (simpler, allows bursts at boundaries). Not implemented
    /// by [`RateLimiter`]; see the type docs.
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
    pub available_tokens: u32,

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
    pub current_rate: u32,

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
}

/// Result of a queue entry: None = waiting, Some(Ok(())) = granted, Some(Err(reason)) = rejected.
type QueueEntryResult = Option<Result<(), RejectionReason>>;

/// Out-of-band ID returned by `enqueue` when the caller acquired tokens
/// immediately and therefore has no queue entry to track.
const IMMEDIATE_ACQUIRE_SENTINEL: u64 = u64::MAX;

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

#[inline]
fn duration_to_millis_saturating(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

/// The policy period in whole milliseconds, the unit these limiters keep time
/// in, rounded up. Truncated, a sub-millisecond period became 0: the token
/// bucket never refilled (retry_after said `Duration::MAX`) and the sliding
/// window never expired an entry, so the limiter stayed shut. A fractional
/// period such as 1.9 ms became 1 ms and admitted 1.9 times the rate. Rounded
/// up, a limiter never admits more than `rate` per period. Zero stays zero
/// (br-asupersync-e9gn8y).
#[inline]
fn period_to_millis_ceil(period: Duration) -> u64 {
    let whole = period.as_millis();
    let rounded = if period.subsec_nanos() % 1_000_000 == 0 {
        whole
    } else {
        whole + 1
    };
    u64::try_from(rounded).unwrap_or(u64::MAX)
}

/// Internal state of the token bucket.
struct BucketState {
    /// Token bucket state.
    tokens: u32,

    /// Fractional tokens accumulated (0 to period_ms - 1).
    fractional: u64,

    /// Last refill time (as millis since epoch).
    last_refill: u64,
}

/// Thread-safe rate limiter using token bucket algorithm.
pub struct RateLimiter {
    policy: RateLimitPolicy,

    /// Protected bucket state.
    state: Mutex<BucketState>,

    /// Waiting queue for FIFO ordering.
    wait_queue: RwLock<VecDeque<QueueEntry>>,

    /// Number of pending (result == None) entries. Maintained atomically
    /// so `try_acquire` can check if anyone is actually waiting without
    /// being blocked by zombie entries (granted/timed-out but not claimed).
    pending_queue_count: AtomicU32,

    /// Next entry ID.
    next_id: AtomicU64,

    // Atomic counters for hot path
    total_allowed: AtomicU64,
    total_rejected: AtomicU64,
    total_waited: AtomicU64,
    total_wait_time_ms: AtomicU64,
    max_wait_time_ms: AtomicU64,
}

/// RAII permit returned by [`RateLimiter::acquire_permit`].
///
/// The permit refunds its token cost if dropped before [`Self::commit`]. This
/// is useful for async or panic-prone call paths where the protected work is
/// split from synchronous token acquisition.
pub struct RateLimitPermit<'a> {
    limiter: &'a RateLimiter,
    cost: u32,
    refund: bool,
}

impl RateLimitPermit<'_> {
    /// Mark the protected work as successfully completed.
    pub fn commit(mut self) {
        self.refund = false;
    }
}

impl Drop for RateLimitPermit<'_> {
    fn drop(&mut self) {
        if self.refund {
            self.limiter.refund_tokens(self.cost);
        }
    }
}

/// Owns a rate-limit acquisition until its permit is claimed.
///
/// This guard removes its queue entry when dropped. If tokens have already
/// been granted, including an immediate acquisition, it refunds them instead
/// of leaving an abandoned reservation behind. Keep the guard alive across
/// waits so cancellation of the enclosing future releases the acquisition.
///
/// This is a caller-driven queue handle, not a future: it does not register a
/// waker or arrange another poll. Call [`Self::poll_claim`] after the caller's
/// timer or other progress source fires.
#[derive(Debug)]
#[must_use = "dropping the guard cancels the acquisition and refunds any granted tokens"]
pub struct QueuedRateLimitAcquire<'a> {
    limiter: &'a RateLimiter,
    entry_id: Option<u64>,
    cost: u32,
    last_observed_now: Time,
}

impl<'a> QueuedRateLimitAcquire<'a> {
    /// Claim the refundable permit once the acquisition is granted.
    ///
    /// Returns `Ok(None)` while waiting, `Ok(Some(permit))` on a grant, or the
    /// existing timeout/cancellation error after removing a terminal entry.
    /// After a permit or error is returned, this guard is spent: further calls
    /// return [`RateLimitError::Cancelled`] and dropping it has no effect.
    ///
    /// The returned [`RateLimitPermit`] owns the token reservation and refunds
    /// it on drop until committed. Queue capacity is released when the permit
    /// is claimed, even if the permit is kept alive.
    pub fn poll_claim(
        &mut self,
        now: Time,
    ) -> Result<Option<RateLimitPermit<'a>>, RateLimitError<()>> {
        let Some(entry_id) = self.entry_id else {
            return Err(RateLimitError::Cancelled);
        };
        self.last_observed_now = now;

        match self.limiter.check_entry(entry_id, now) {
            Ok(true) => {
                self.entry_id = None;
                Ok(Some(RateLimitPermit {
                    limiter: self.limiter,
                    cost: self.cost,
                    refund: true,
                }))
            }
            Ok(false) => Ok(None),
            Err(error) => {
                self.entry_id = None;
                Err(error)
            }
        }
    }
}

impl Drop for QueuedRateLimitAcquire<'_> {
    fn drop(&mut self) {
        let Some(entry_id) = self.entry_id.take() else {
            return;
        };

        if entry_id == IMMEDIATE_ACQUIRE_SENTINEL {
            // The raw sentinel does not retain its cost, so cancel_entry()
            // cannot refund an immediate grant. This owner retains that cost.
            self.limiter.refund_tokens(self.cost);
        } else {
            // Cancellation removes pending and terminal records alike and
            // refunds a granted-but-unclaimed entry exactly once. The latest
            // caller-provided time supplies drop-time wait accounting.
            self.limiter.cancel_entry(entry_id, self.last_observed_now);
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter with the given policy.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(policy: RateLimitPolicy) -> Self {
        let burst = policy.burst;
        Self {
            policy,
            state: Mutex::new(BucketState {
                tokens: burst,
                fractional: 0,
                last_refill: 0,
            }),
            wait_queue: RwLock::new(VecDeque::with_capacity(16)),
            pending_queue_count: AtomicU32::new(0),
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
            state.tokens
        };

        let total_waited = self.total_waited.load(Ordering::Relaxed);
        let total_wait_time_ms = self.total_wait_time_ms.load(Ordering::Relaxed);
        let max_wait_time_ms = self.max_wait_time_ms.load(Ordering::Relaxed);
        let avg_wait_time = total_wait_time_ms
            .checked_div(total_waited)
            .map_or(Duration::ZERO, Duration::from_millis);

        RateLimitMetrics {
            available_tokens,
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_rejected: self.total_rejected.load(Ordering::Relaxed),
            total_waited,
            total_wait_time: Duration::from_millis(total_wait_time_ms),
            avg_wait_time,
            max_wait_time: Duration::from_millis(max_wait_time_ms),
            current_rate: 0,
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
        let period_ms = period_to_millis_ceil(self.policy.period);

        if period_ms > 0 && self.policy.rate > 0 {
            let added_fractional = u128::from(elapsed_ms) * u128::from(self.policy.rate);
            let total_fractional = u128::from(state.fractional) + added_fractional;

            let new_tokens =
                (total_fractional / u128::from(period_ms)).min(u128::from(u64::MAX)) as u64;
            let new_fractional = (total_fractional % u128::from(period_ms)) as u64;

            state.tokens =
                (u64::from(state.tokens) + new_tokens).min(u64::from(self.policy.burst)) as u32;
            state.fractional = new_fractional;

            if state.tokens == self.policy.burst {
                state.fractional = 0;
            }
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
    #[allow(clippy::cast_precision_loss)]
    pub fn try_acquire(&self, cost: u32, now: Time) -> bool {
        if self.pending_queue_count.load(Ordering::Relaxed) > 0 {
            // Preserve FIFO fairness for queued waiters, but do not let stale
            // timed-out or already-grantable queue state strand the fast path.
            let _ = self.process_queue(now);
            if self.pending_queue_count.load(Ordering::Relaxed) > 0 {
                return false;
            }
        }

        // Serialize against enqueue so a waiter that was just pushed to the wait
        // queue — but whose `pending_queue_count` bump is not yet visible to the
        // counter checks above — cannot have its FIFO turn barged by this fast
        // path. Hold wait_queue.read() across the token consume (mirrors
        // bulkhead::try_acquire), acquiring it BEFORE `state` to match the
        // enqueue/process_queue lock order (wait_queue -> state) and avoid an
        // AB-BA deadlock (d8ji01).
        let wait_queue = self.wait_queue.read();
        if wait_queue.iter().any(|entry| entry.result.is_none()) {
            return false;
        }

        let mut state = self.state.lock();
        let now_millis = now.as_millis();

        self.refill_inner(&mut state, now_millis);

        let acquired = if state.tokens >= cost {
            state.tokens -= cost;
            true
        } else {
            false
        };
        drop(state);
        drop(wait_queue);

        if acquired {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
        }
        acquired
    }

    /// Allocate a queue entry ID while reserving `IMMEDIATE_ACQUIRE_SENTINEL`
    /// for the fast-path return from `enqueue`.
    ///
    /// Queue entry IDs are externally visible handles used by `check_entry()`
    /// and `cancel_entry()`. Reusing an ID after wrap would let a stale caller
    /// alias a later waiter and observe or cancel the wrong entry, so the
    /// allocator fails closed when the ID space is exhausted.
    fn allocate_entry_id(&self, queue: &VecDeque<QueueEntry>) -> Result<u64, RateLimitError<()>> {
        let mut current = self.next_id.load(Ordering::Relaxed);

        loop {
            let mut candidate = current;
            while candidate != IMMEDIATE_ACQUIRE_SENTINEL
                && queue.iter().any(|entry| entry.id == candidate)
            {
                candidate = candidate.saturating_add(1);
            }

            if candidate == IMMEDIATE_ACQUIRE_SENTINEL {
                return Err(RateLimitError::QueueIdExhausted);
            }

            let next = candidate.saturating_add(1);

            match self.next_id.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(candidate),
                Err(observed) => current = observed,
            }
        }
    }

    fn refund_tokens(&self, cost: u32) {
        if cost == 0 {
            return;
        }

        let mut state = self.state.lock();
        state.tokens = state.tokens.saturating_add(cost).min(self.policy.burst);
    }

    /// Acquire a refundable permit for `cost` tokens.
    ///
    /// The returned permit refunds tokens on drop until committed. Failed
    /// acquisitions update rejection metrics just like [`Self::call_weighted`].
    pub fn acquire_permit(
        &self,
        cost: u32,
        now: Time,
    ) -> Result<RateLimitPermit<'_>, RateLimitError<()>> {
        if !self.try_acquire(cost, now) {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RateLimitError::RateLimitExceeded);
        }

        Ok(RateLimitPermit {
            limiter: self,
            cost,
            refund: true,
        })
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
        let permit = self.acquire_permit(cost, now).map_err(|err| match err {
            RateLimitError::RateLimitExceeded => RateLimitError::RateLimitExceeded,
            RateLimitError::Timeout { waited } => RateLimitError::Timeout { waited },
            RateLimitError::Cancelled => RateLimitError::Cancelled,
            RateLimitError::QueueIdExhausted => RateLimitError::QueueIdExhausted,
            RateLimitError::Inner(()) => unreachable!("permit acquisition has no inner op"),
        })?;

        match catch_unwind(AssertUnwindSafe(op)) {
            Ok(Ok(v)) => {
                permit.commit();
                Ok(v)
            }
            Ok(Err(e)) => {
                permit.commit();
                Err(RateLimitError::Inner(e))
            }
            Err(panic) => resume_unwind(panic),
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
        if cost > self.policy.burst {
            return Duration::MAX;
        }

        let (current_tokens, current_fractional) = {
            let mut state = self.state.lock();
            self.refill_inner(&mut state, now.as_millis());
            (state.tokens, state.fractional)
        };

        // Queued waiters are served first, so a new request also waits for
        // their tokens: free tokens the head waiter cannot use yet do not make
        // a try_acquire succeed now (br-asupersync-r0x5ho).
        let queued_cost: u64 = if self.pending_queue_count.load(Ordering::Relaxed) > 0 {
            self.wait_queue
                .read()
                .iter()
                .filter(|entry| entry.result.is_none())
                .map(|entry| u64::from(entry.cost))
                .sum()
        } else {
            0
        };
        let demand = queued_cost.saturating_add(u64::from(cost));
        if u64::from(current_tokens) >= demand {
            return Duration::ZERO;
        }

        if self.policy.rate == 0 || self.policy.period.is_zero() {
            return Duration::MAX; // No refill rate
        }

        let period_ms = period_to_millis_ceil(self.policy.period);

        let tokens_needed = demand - u64::from(current_tokens);
        let fractional_needed = u128::from(tokens_needed) * u128::from(period_ms);
        let additional_fractional =
            fractional_needed.saturating_sub(u128::from(current_fractional));

        let rate = u128::from(self.policy.rate);
        let ms_needed = additional_fractional
            .div_ceil(rate)
            .min(u128::from(u64::MAX)) as u64;

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
    pub fn available_tokens(&self) -> u32 {
        let state = self.state.lock();
        state.tokens
    }

    // =========================================================================
    // Queue-based waiting (similar to bulkhead)
    // =========================================================================

    /// Acquire a queue-owned token reservation.
    ///
    /// Prefer this to [`Self::enqueue`] when the caller can be cancelled or
    /// dropped before claiming its grant. Dropping the returned guard removes
    /// the entry and refunds any granted tokens. Claim the reservation with
    /// [`QueuedRateLimitAcquire::poll_claim`], then commit its permit when the
    /// protected operation should consume the tokens.
    ///
    /// Waiting is caller-driven; this method does not register a waker.
    pub fn acquire_queued(
        &self,
        cost: u32,
        now: Time,
    ) -> Result<QueuedRateLimitAcquire<'_>, RateLimitError<()>> {
        let entry_id = self.enqueue(cost, now)?;
        Ok(QueuedRateLimitAcquire {
            limiter: self,
            entry_id: Some(entry_id),
            cost,
            last_observed_now: now,
        })
    }

    /// Acquire a queue-owned reservation with a bound on retained queue entries.
    ///
    /// Immediate acquisitions do not need a queue slot. If the request must
    /// wait, admission fails with [`RateLimitError::RateLimitExceeded`] when
    /// `max_queued` entries are already retained. The check and insertion are
    /// atomic with respect to other queue admissions.
    ///
    /// All retained entries count, including grants and timeouts not yet
    /// claimed or dropped. A zero bound permits only immediate acquisitions.
    /// Use the same bound for all admissions to enforce a limiter-wide cap;
    /// [`Self::enqueue`] and [`Self::acquire_queued`] remain unbounded, and a
    /// different bound on another call does not evict existing entries.
    pub fn acquire_queued_bounded(
        &self,
        cost: u32,
        now: Time,
        max_queued: usize,
    ) -> Result<QueuedRateLimitAcquire<'_>, RateLimitError<()>> {
        let entry_id = self.enqueue_with_limit(cost, now, Some(max_queued))?;
        Ok(QueuedRateLimitAcquire {
            limiter: self,
            entry_id: Some(entry_id),
            cost,
            last_observed_now: now,
        })
    }

    /// Enqueue a waiting operation.
    ///
    /// Returns `Ok(entry_id)` if enqueued, `Err(RateLimitExceeded)` if rate exceeded
    /// and policy is Reject, or `Err(QueueIdExhausted)` if the queue-handle
    /// ID space has been exhausted and the limiter must fail closed.
    pub fn enqueue(&self, cost: u32, now: Time) -> Result<u64, RateLimitError<()>> {
        self.enqueue_with_limit(cost, now, None)
    }

    #[allow(clippy::cast_precision_loss, clippy::significant_drop_tightening)]
    fn enqueue_with_limit(
        &self,
        cost: u32,
        now: Time,
        max_queued: Option<usize>,
    ) -> Result<u64, RateLimitError<()>> {
        // Fast path: try immediate acquisition
        if self.try_acquire(cost, now) {
            return Ok(IMMEDIATE_ACQUIRE_SENTINEL); // Already acquired
        }

        if cost > self.policy.burst {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RateLimitError::RateLimitExceeded);
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
        if max_queued.is_some_and(|limit| queue.len() >= limit) {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RateLimitError::RateLimitExceeded);
        }
        let entry_id = self.allocate_entry_id(&queue)?;

        queue.push_back(QueueEntry {
            id: entry_id,
            cost,
            enqueued_at_millis: now_millis,
            deadline_millis,
            result: None,
        });

        self.pending_queue_count.fetch_add(1, Ordering::Relaxed);
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

        let mut state = self.state.lock();
        self.refill_inner(&mut state, now_millis);

        // Apply grants/timeouts in a single pass so an entry that becomes
        // runnable exactly at its deadline is granted instead of timing out.
        // Later entries may still time out behind a FIFO-blocking live waiter,
        // but they may not be granted out of order.
        let mut timeout_count = 0u64;
        let mut timeout_wait_ms = 0u64;
        let mut max_timeout_wait_ms = 0u64;
        let mut fifo_blocked = false;

        let mut first_granted = None;
        let mut granted_count = 0u64;
        let mut acc_wait_time = Duration::ZERO;
        let mut max_wait_time = Duration::ZERO;

        for entry in queue.iter_mut() {
            // Skip already processed (granted/timeout/cancelled)
            if entry.result.is_some() {
                continue;
            }

            match now_millis.cmp(&entry.deadline_millis) {
                std::cmp::Ordering::Greater => {
                    entry.result = Some(Err(RejectionReason::Timeout));
                    timeout_count += 1;
                    let wait = now_millis.saturating_sub(entry.enqueued_at_millis);
                    timeout_wait_ms = timeout_wait_ms.saturating_add(wait);
                    if wait > max_timeout_wait_ms {
                        max_timeout_wait_ms = wait;
                    }
                }
                std::cmp::Ordering::Equal => {
                    if !fifo_blocked && state.tokens >= entry.cost {
                        state.tokens -= entry.cost;
                        entry.result = Some(Ok(()));
                        self.pending_queue_count.fetch_sub(1, Ordering::Relaxed);

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
                        entry.result = Some(Err(RejectionReason::Timeout));
                        timeout_count += 1;
                        let wait = now_millis.saturating_sub(entry.enqueued_at_millis);
                        timeout_wait_ms = timeout_wait_ms.saturating_add(wait);
                        if wait > max_timeout_wait_ms {
                            max_timeout_wait_ms = wait;
                        }
                    }
                }
                std::cmp::Ordering::Less => {
                    if !fifo_blocked && state.tokens >= entry.cost {
                        state.tokens -= entry.cost;
                        entry.result = Some(Ok(()));
                        self.pending_queue_count.fetch_sub(1, Ordering::Relaxed);

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
                        fifo_blocked = true;
                    }
                }
            }
        }

        if timeout_count > 0 {
            #[allow(clippy::cast_possible_truncation)]
            self.pending_queue_count
                .fetch_sub(timeout_count as u32, Ordering::Relaxed);
            self.total_wait_time_ms
                .fetch_add(timeout_wait_ms, Ordering::Relaxed);
            self.max_wait_time_ms
                .fetch_max(max_timeout_wait_ms, Ordering::Relaxed);
        }

        // Flush accumulated metrics via atomics (no write lock needed).
        if granted_count > 0 {
            self.total_allowed
                .fetch_add(granted_count, Ordering::Relaxed);

            let wait_ms = duration_to_millis_saturating(acc_wait_time);
            self.total_wait_time_ms
                .fetch_add(wait_ms, Ordering::Relaxed);

            let new_max_ms = duration_to_millis_saturating(max_wait_time);
            self.max_wait_time_ms
                .fetch_max(new_max_ms, Ordering::Relaxed);
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
        if entry_id == IMMEDIATE_ACQUIRE_SENTINEL {
            return Ok(true);
        }

        // Process queue to handle timeouts and grants
        let _ = self.process_queue(now);

        let mut queue = self.wait_queue.write();
        let entry_idx = queue.iter().position(|e| e.id == entry_id);

        if let Some(idx) = entry_idx {
            match queue[idx].result {
                Some(Ok(())) => {
                    queue.remove(idx);
                    Ok(true)
                }
                Some(Err(RejectionReason::Timeout)) => {
                    let entry = queue.remove(idx).expect("must exist");
                    let wait_ms = now.as_millis().saturating_sub(entry.enqueued_at_millis);
                    Err(RateLimitError::Timeout {
                        waited: Duration::from_millis(wait_ms),
                    })
                }
                None => Ok(false),
            }
        } else {
            // Entry not found - likely already processed and garbage collected
            Err(RateLimitError::Cancelled)
        }
    }

    /// Cancel a queued entry.
    pub fn cancel_entry(&self, entry_id: u64, now: Time) {
        if entry_id == IMMEDIATE_ACQUIRE_SENTINEL {
            return; // Special sentinel, nothing to cancel
        }

        let mut queue = self.wait_queue.write();
        if let Some(idx) = queue.iter().position(|e| e.id == entry_id) {
            let entry = queue.remove(idx).expect("must exist");
            let previous_result = entry.result;
            let cost = entry.cost;
            let enqueued_at_millis = entry.enqueued_at_millis;
            // Every change to the count happens under the queue lock: a
            // concurrent reset() zeroing it between the removal and this
            // decrement wrapped it to u32::MAX, closing the fast path for good.
            if previous_result.is_none() {
                self.pending_queue_count.fetch_sub(1, Ordering::Relaxed);
            }
            drop(queue);

            if previous_result == Some(Ok(())) {
                // Refund tokens if already granted but not consumed by the caller
                let mut state = self.state.lock();
                state.tokens = state.tokens.saturating_add(cost).min(self.policy.burst);
                // We could decrement total_allowed here, but the operation was technically
                // allowed from the rate limiter's perspective, just not consumed.
                drop(state);
                let _ = self.process_queue(now);
            } else if previous_result.is_none() {
                let wait_ms = now.as_millis().saturating_sub(enqueued_at_millis);
                self.total_wait_time_ms
                    .fetch_add(wait_ms, Ordering::Relaxed);
                self.max_wait_time_ms.fetch_max(wait_ms, Ordering::Relaxed);
            }
        }
    }

    /// Reset the rate limiter to full capacity.
    pub fn reset(&self) {
        let initial_tokens = self.policy.burst;

        // Refill, clear and zero under the queue lock (taken before `state`,
        // the order process_queue uses), so no enqueue, grant or cancel lands
        // between them. A grant between a refill and the clear took tokens for
        // an entry the clear then dropped, leaving the bucket short.
        let mut queue = self.wait_queue.write();
        {
            let mut state = self.state.lock();
            state.tokens = initial_tokens;
            state.fractional = 0;
            state.last_refill = 0;
        }
        queue.clear();
        self.pending_queue_count.store(0, Ordering::Relaxed);
        drop(queue);
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

    /// Recent operations and their summed cost, under one lock.
    window: RwLock<SlidingWindow>,

    // Atomic counters
    total_allowed: AtomicU64,
    total_rejected: AtomicU64,
}

/// The operations a sliding window still counts, with their total cost.
#[derive(Default)]
struct SlidingWindow {
    /// Timestamps of recent operations: (timestamp_millis, cost).
    entries: VecDeque<(u64, u32)>,
    /// Sum of the entries' costs. It changes only with `entries`, under the
    /// same lock: an atomic shadow counter beside the lock used to race, and
    /// re-summing the entries cost O(rate) on every call.
    cost: u64,
}

impl SlidingWindow {
    /// Drop the entries a window of `period_millis` no longer covers at
    /// `now_millis`. A zero period never expires anything.
    fn expire(&mut self, now_millis: u64, period_millis: u64) {
        while let Some(&(t, c)) = self.entries.front() {
            if period_millis > 0 && now_millis.saturating_sub(t) >= period_millis {
                self.entries.pop_front();
                self.cost -= u64::from(c);
            } else {
                break;
            }
        }
    }
}

impl SlidingWindowRateLimiter {
    /// Create a new sliding window rate limiter.
    #[must_use]
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            // Policy limits describe admitted work, not an allocation request.
            // Grow with actual accepted operations so extreme but valid limits
            // cannot force a multi-gigabyte constructor allocation.
            window: RwLock::new(SlidingWindow::default()),
            total_allowed: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }

    /// Get policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.policy.name
    }

    /// Try to acquire without waiting.
    #[must_use]
    #[allow(clippy::significant_drop_tightening, clippy::cast_possible_truncation)]
    pub fn try_acquire(&self, cost: u32, now: Time) -> bool {
        let now_millis = now.as_millis();
        let period_millis = period_to_millis_ceil(self.policy.period);

        // Single lock acquisition: cleanup expired + check usage + add entry
        let mut window = self.window.write();
        window.expire(now_millis, period_millis);
        let usage = window.cost;

        if usage.saturating_add(u64::from(cost)) <= u64::from(self.policy.rate) {
            if cost > 0 {
                window.entries.push_back((now_millis, cost));
                window.cost += u64::from(cost);
            }
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
        let now_millis = now.as_millis();
        let period_millis = period_to_millis_ceil(self.policy.period);

        let mut window = self.window.write();
        window.expire(now_millis, period_millis);

        let usage = window.cost;
        let requested = usage.saturating_add(u64::from(cost));
        if requested <= u64::from(self.policy.rate) {
            return Duration::ZERO;
        }

        if period_millis == 0 {
            return Duration::MAX;
        }

        // Find when enough capacity frees up
        let needed = requested.saturating_sub(u64::from(self.policy.rate));
        let mut freed = 0u64;
        for (t, c) in &window.entries {
            freed = freed.saturating_add(u64::from(*c));
            if freed >= needed {
                // This entry will expire at t + period
                let expire_at = t.saturating_add(period_millis);
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
        window.entries.clear();
        window.cost = 0;
        drop(window);
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

    /// Waiting entry ID space exhausted.
    ///
    /// This is fail-closed: queue IDs are not reused because stale handles
    /// would otherwise be able to alias later waiters after wraparound.
    QueueIdExhausted,

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
            Self::QueueIdExhausted => write!(f, "rate limit queue ID space exhausted"),
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

    /// Set the algorithm. [`RateLimiter`] runs a token bucket for every
    /// variant; see [`RateLimitAlgorithm`].
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
            limiters: RwLock::new(HashMap::with_capacity(8)),
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

    /// Get metrics for all limiters, keyed by limiter name in a
    /// deterministic (lexicographic) iteration order.
    ///
    /// br-asupersync-sap5a9: returns [`std::collections::BTreeMap`]
    /// instead of `HashMap` so callers that fold this into a content
    /// hash (crashpack manifests, trace certificates, debug
    /// snapshots) get a stable result across replays. The internal
    /// `limiters` map remains a `HashMap` for O(1) named lookup; the
    /// public iteration view is sorted to close the determinism gap.
    /// Mirrors the closed asupersync-q6vujm /
    /// asupersync-ks0t6j fix-shape (deterministic iteration for any
    /// view a hash consumer might fold over).
    #[must_use]
    pub fn all_metrics(&self) -> std::collections::BTreeMap<String, RateLimitMetrics> {
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
#[path = "rate_limit_inline_tests.rs"]
mod tests;
