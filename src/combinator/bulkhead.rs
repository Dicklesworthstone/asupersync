//! Bulkhead combinator for resource isolation and concurrency limiting.
//!
//! The bulkhead pattern isolates concurrent operations into partitions,
//! preventing failures or resource exhaustion in one partition from affecting
//! others. Named after ship compartments that contain flooding.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::combinator::bulkhead::*;
//! use std::time::Duration;
//!
//! let policy = BulkheadPolicy {
//!     name: "database".into(),
//!     max_concurrent: 10,
//!     max_queue: 100,
//!     ..Default::default()
//! };
//!
//! let bulkhead = Bulkhead::new(policy);
//!
//! // Try to acquire a permit (pass the current clock reading so stale queued
//! // entries are drained before the fast path).
//! if let Some(permit) = bulkhead.try_acquire(1, now) {
//!     // Execute protected operation
//!     do_work();
//!     // Permit automatically released on drop
//! } else {
//!     // Bulkhead full, handle rejection
//! }
//! ```

use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use std::task::Poll;

use crate::cx::Cx;
use crate::sync::Notify;
use crate::types::{CancelReason, Time};

// =========================================================================
// Policy Configuration
// =========================================================================

/// Bulkhead configuration.
#[derive(Clone)]
pub struct BulkheadPolicy {
    /// Name for logging/metrics.
    pub name: String,

    /// Maximum concurrent operations.
    pub max_concurrent: u32,

    /// Maximum queue size (waiting operations).
    pub max_queue: u32,

    /// Maximum time to wait in queue.
    pub queue_timeout: Duration,

    /// Enable weighted permits (operations can require multiple permits).
    /// Not read: `call_weighted` takes any weight whether or not this is set.
    pub weighted: bool,

    /// Callback when permits exhausted.
    pub on_full: Option<FullCallback>,
}

impl BulkheadPolicy {
    /// Sets the maximum concurrent operations.
    #[must_use]
    pub fn concurrency(mut self, max: u32) -> Self {
        self.max_concurrent = max;
        self
    }
}

/// Callback type when bulkhead is full.
pub type FullCallback = Arc<dyn Fn(&BulkheadMetrics) + Send + Sync>;

impl fmt::Debug for BulkheadPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkheadPolicy")
            .field("name", &self.name)
            .field("max_concurrent", &self.max_concurrent)
            .field("max_queue", &self.max_queue)
            .field("queue_timeout", &self.queue_timeout)
            .field("weighted", &self.weighted)
            .field("on_full", &self.on_full.is_some())
            .finish()
    }
}

impl Default for BulkheadPolicy {
    fn default() -> Self {
        Self {
            name: "default".into(),
            max_concurrent: 10,
            max_queue: 100,
            queue_timeout: Duration::from_secs(5),
            weighted: false,
            on_full: None,
        }
    }
}

// =========================================================================
// Metrics & Observability
// =========================================================================

/// Metrics exposed by bulkhead.
#[derive(Clone, Debug, Default)]
pub struct BulkheadMetrics {
    /// Currently active permits.
    pub active_permits: u32,

    /// Current queue depth.
    pub queue_depth: u32,

    /// Total operations executed.
    pub total_executed: u64,

    /// Total operations queued.
    pub total_queued: u64,

    /// Total operations rejected (queue full or immediate rejection).
    pub total_rejected: u64,

    /// Total operations timed out in queue.
    pub total_timeout: u64,

    /// Total operations cancelled while queued.
    pub total_cancelled: u64,

    /// Average queue wait time (ms).
    pub avg_queue_wait_ms: f64,

    /// Max queue wait time (ms).
    pub max_queue_wait_ms: u64,

    /// Current utilization (active / max).
    pub utilization: f64,
}

// =========================================================================
// Queue Entry
// =========================================================================

/// Reason an entry was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectionReason {
    Timeout,
}

/// Result of a queue entry: None = waiting, Some(Ok(())) = granted, Some(Err(reason)) = rejected.
type QueueEntryResult = Option<Result<(), RejectionReason>>;

/// Entry in the waiting queue.
#[derive(Debug)]
struct QueueEntry {
    id: u64,
    weight: u32,
    enqueued_at_millis: u64,
    deadline_millis: u64,
    /// State of this entry.
    result: QueueEntryResult,
}

// =========================================================================
// Core Implementation
// =========================================================================

/// Thread-safe bulkhead for resource isolation.
pub struct Bulkhead {
    policy: BulkheadPolicy,

    /// Available permits.
    available_permits: AtomicU32,

    /// Queue of waiting operations.
    queue: RwLock<VecDeque<QueueEntry>>,

    /// Number of pending (result == None) entries. Maintained atomically
    /// so `metrics()` can read queue depth without locking the queue.
    pending_queue_count: AtomicU32,

    /// Queue/capacity mutations wake async admission after releasing state locks.
    changed: Notify,

    /// Next queue entry ID.
    next_id: AtomicU64,

    /// Wait time accumulator for average calculation.
    total_wait_time_ms: AtomicU64,

    /// Total operations executed.
    total_executed_atomic: AtomicU64,

    /// Total operations queued.
    total_queued_atomic: AtomicU64,

    /// Total operations rejected.
    total_rejected_atomic: AtomicU64,

    /// Total operations timed out in queue.
    total_timeout_atomic: AtomicU64,

    /// Total operations cancelled while queued.
    total_cancelled_atomic: AtomicU64,

    /// Max queue wait time (ms).
    max_queue_wait_ms_atomic: AtomicU64,
}

impl Bulkhead {
    /// Create a new bulkhead with the given policy.
    #[must_use]
    pub fn new(policy: BulkheadPolicy) -> Self {
        let available = policy.max_concurrent;
        let max_queue = policy.max_queue as usize;
        Self {
            policy,
            available_permits: AtomicU32::new(available),
            queue: RwLock::new(VecDeque::with_capacity(max_queue)),
            pending_queue_count: AtomicU32::new(0),
            changed: Notify::new(),
            next_id: AtomicU64::new(0),
            total_wait_time_ms: AtomicU64::new(0),
            total_executed_atomic: AtomicU64::new(0),
            total_queued_atomic: AtomicU64::new(0),
            total_rejected_atomic: AtomicU64::new(0),
            total_timeout_atomic: AtomicU64::new(0),
            total_cancelled_atomic: AtomicU64::new(0),
            max_queue_wait_ms_atomic: AtomicU64::new(0),
        }
    }

    /// Get policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.policy.name
    }

    /// Get maximum concurrent permits.
    #[must_use]
    pub fn max_concurrent(&self) -> u32 {
        self.policy.max_concurrent
    }

    /// Get available permits.
    #[must_use]
    pub fn available(&self) -> u32 {
        self.available_permits.load(Ordering::Acquire)
    }

    /// Get current metrics.
    #[must_use]
    #[allow(clippy::significant_drop_tightening, clippy::cast_precision_loss)]
    pub fn metrics(&self) -> BulkheadMetrics {
        let active = self.pending_queue_count.load(Ordering::Relaxed);
        let used_permits =
            self.policy.max_concurrent - self.available_permits.load(Ordering::Acquire);

        let total_executed = self.total_executed_atomic.load(Ordering::Relaxed);
        let total_queued = self.total_queued_atomic.load(Ordering::Relaxed);
        let completed_queued = total_queued.saturating_sub(u64::from(active));
        let avg_queue_wait_ms = if completed_queued > 0 {
            self.total_wait_time_ms.load(Ordering::Relaxed) as f64 / completed_queued as f64
        } else {
            0.0
        };

        BulkheadMetrics {
            active_permits: used_permits,
            queue_depth: active,
            total_executed,
            total_queued: self.total_queued_atomic.load(Ordering::Relaxed),
            total_rejected: self.total_rejected_atomic.load(Ordering::Relaxed),
            total_timeout: self.total_timeout_atomic.load(Ordering::Relaxed),
            total_cancelled: self.total_cancelled_atomic.load(Ordering::Relaxed),
            avg_queue_wait_ms,
            max_queue_wait_ms: self.max_queue_wait_ms_atomic.load(Ordering::Relaxed),
            utilization: if self.policy.max_concurrent > 0 {
                f64::from(used_permits) / f64::from(self.policy.max_concurrent)
            } else {
                0.0
            },
        }
    }

    /// Try to acquire permit without waiting.
    ///
    /// Returns `Some(permit)` if acquired immediately, `None` if bulkhead is full.
    /// Queued operations hold priority once they enter the FIFO wait queue.
    ///
    /// `now` is the deterministic clock reading used to drain stale timed-out
    /// queue entries before the fast path (mirrors [`RateLimiter::try_acquire`]).
    ///
    /// [`RateLimiter::try_acquire`]: crate::combinator::rate_limit::RateLimiter::try_acquire
    #[must_use]
    pub fn try_acquire(&self, weight: u32, now: Time) -> Option<BulkheadPermit<'_>> {
        // Fast-path rejection when a published waiter already exists — but first
        // time out any stale queue entries. An abandoned bare `enqueue` (never
        // resolved via check_entry/cancel_entry) would otherwise keep
        // `pending_queue_count > 0` past its deadline forever and starve every
        // try_acquire/call/call_weighted with all permits free
        // (br-asupersync-bulkhead-tryacquire-starve-kodql2). We only *time out*
        // expired entries here — we deliberately do NOT grant live queued
        // entries (that is `process_queue`'s job on permit release): granting a
        // waiter inside the fast path would consume a permit into a
        // granted-but-unclaimed slot and, for an abandoned entry, that permit
        // would never be reclaimed, re-starving the fast path.
        if self.pending_queue_count.load(Ordering::Acquire) > 0 {
            self.drain_expired_entries(now);
            if self.pending_queue_count.load(Ordering::Acquire) > 0 {
                return None;
            }
        }

        self.try_acquire_ready(weight)
    }

    /// Claim currently available capacity without advancing queue deadlines.
    fn try_acquire_ready(&self, weight: u32) -> Option<BulkheadPermit<'_>> {
        // Serialize against queue mutation so a waiter cannot slip into the
        // queue after our counter check but before we consume permits. This
        // closes the barging window where enqueue has pushed the waiter but has
        // not published `pending_queue_count` yet.
        let queue = self.queue.read();
        if queue.iter().any(|entry| entry.result.is_none()) {
            return None;
        }

        let mut available = self.available_permits.load(Ordering::Acquire);
        loop {
            if available < weight {
                return None;
            }

            match self.available_permits.compare_exchange_weak(
                available,
                available - weight,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.total_executed_atomic.fetch_add(1, Ordering::Relaxed);
                    return Some(BulkheadPermit {
                        bulkhead: self,
                        weight,
                    });
                }
                Err(actual) => available = actual,
            }
        }
    }

    /// Check if a queued entry can be granted.
    ///
    /// Call this periodically or when permits become available.
    /// Returns the ID of any entry that was granted, or None.
    #[allow(clippy::cast_precision_loss)]
    pub fn process_queue(&self, now: Time) -> Option<u64> {
        let mut queue = self.queue.write();
        let pending_before = self.pending_queue_count.load(Ordering::Acquire);
        let result = self.process_queue_inner(&mut queue, now);
        let changed = self.pending_queue_count.load(Ordering::Acquire) != pending_before;
        drop(queue);
        if changed {
            self.notify_admission_change();
        }
        result
    }

    /// Time out (but never grant) any queue entries whose deadline has passed.
    ///
    /// Used by [`try_acquire`](Self::try_acquire) so an abandoned bare `enqueue`
    /// — one never resolved via `check_entry`/`cancel_entry` — cannot keep
    /// `pending_queue_count > 0` past its deadline and starve the fast path
    /// forever. Unlike [`process_queue`](Self::process_queue) this deliberately
    /// does NOT grant a live waiter: granting inside the fast path would consume
    /// a permit into a granted-but-unclaimed slot that, for an abandoned entry,
    /// is never reclaimed (br-asupersync-bulkhead-tryacquire-starve-kodql2).
    #[allow(clippy::significant_drop_tightening)]
    fn drain_expired_entries(&self, now: Time) {
        let now_millis = now.as_millis();
        let mut queue = self.queue.write();
        let mut timeout_count = 0u64;
        let mut timeout_wait_ms = 0u64;
        let mut max_individual_wait_ms = 0u64;
        for entry in queue.iter_mut() {
            if entry.result.is_none() && now_millis >= entry.deadline_millis {
                entry.result = Some(Err(RejectionReason::Timeout));
                timeout_count += 1;
                let wait = now_millis.saturating_sub(entry.enqueued_at_millis);
                timeout_wait_ms += wait;
                max_individual_wait_ms = max_individual_wait_ms.max(wait);
            }
        }
        if timeout_count > 0 {
            #[allow(clippy::cast_possible_truncation)]
            self.pending_queue_count
                .fetch_sub(timeout_count as u32, Ordering::Release);
            self.total_timeout_atomic
                .fetch_add(timeout_count, Ordering::Relaxed);
            self.total_wait_time_ms
                .fetch_add(timeout_wait_ms, Ordering::Relaxed);
            self.max_queue_wait_ms_atomic
                .fetch_max(max_individual_wait_ms, Ordering::Relaxed);
        }
        drop(queue);
        if timeout_count > 0 {
            self.notify_admission_change();
        }
    }

    /// Inner queue processing logic that operates on an already-locked queue.
    fn process_queue_inner(&self, queue: &mut VecDeque<QueueEntry>, now: Time) -> Option<u64> {
        let now_millis = now.as_millis();

        // First, timeout expired entries — count timeouts locally and batch-update
        // the metrics lock once, instead of acquiring it per timed-out entry.
        let mut timeout_count = 0u64;
        let mut timeout_wait_ms = 0u64;
        let mut max_individual_wait_ms = 0u64;
        for entry in queue.iter_mut() {
            if entry.result.is_none() && now_millis >= entry.deadline_millis {
                entry.result = Some(Err(RejectionReason::Timeout));
                timeout_count += 1;
                let wait = now_millis.saturating_sub(entry.enqueued_at_millis);
                timeout_wait_ms += wait;
                max_individual_wait_ms = max_individual_wait_ms.max(wait);
            }
        }
        if timeout_count > 0 {
            #[allow(clippy::cast_possible_truncation)]
            self.pending_queue_count
                .fetch_sub(timeout_count as u32, Ordering::Release);
            self.total_timeout_atomic
                .fetch_add(timeout_count, Ordering::Relaxed);
            self.total_wait_time_ms
                .fetch_add(timeout_wait_ms, Ordering::Relaxed);
            self.max_queue_wait_ms_atomic
                .fetch_max(max_individual_wait_ms, Ordering::Relaxed);
        }

        // Find all waiting entries that can be granted
        let mut first_granted = None;
        for entry in queue.iter_mut() {
            if entry.result.is_none() {
                // CAS loop to safely consume permits (prevents TOCTOU race with try_acquire)
                let granted = {
                    let mut current = self.available_permits.load(Ordering::Acquire);
                    loop {
                        if current < entry.weight {
                            break false;
                        }
                        match self.available_permits.compare_exchange_weak(
                            current,
                            current - entry.weight,
                            Ordering::Acquire,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break true,
                            Err(actual) => current = actual,
                        }
                    }
                };
                if !granted {
                    // Stop at first ungrantable entry to preserve FIFO order
                    break;
                }
                entry.result = Some(Ok(()));
                self.pending_queue_count.fetch_sub(1, Ordering::Release);

                // Record wait time
                let wait_ms = now_millis.saturating_sub(entry.enqueued_at_millis);
                self.total_wait_time_ms
                    .fetch_add(wait_ms, Ordering::Relaxed);

                self.total_executed_atomic.fetch_add(1, Ordering::Relaxed);
                self.max_queue_wait_ms_atomic
                    .fetch_max(wait_ms, Ordering::Relaxed);

                if first_granted.is_none() {
                    first_granted = Some(entry.id);
                }
            }
        }

        first_granted
    }

    /// Enqueue a waiting operation.
    ///
    /// Returns `Ok(entry_id)` if enqueued, `Err(QueueFull)` if queue is full.
    #[allow(clippy::significant_drop_tightening, clippy::cast_precision_loss)]
    pub fn enqueue(&self, weight: u32, now: Time) -> Result<u64, BulkheadError<()>> {
        if weight > self.policy.max_concurrent {
            self.total_rejected_atomic.fetch_add(1, Ordering::Relaxed);
            return Err(BulkheadError::Full);
        }

        let now_millis = now.as_millis();
        let timeout_millis = self
            .policy
            .queue_timeout
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let deadline_millis = now_millis.saturating_add(timeout_millis);

        let mut queue = self.queue.write();

        // Check queue capacity
        // We check total length (including completed-but-unclaimed entries) to
        // prevent unbounded memory growth if the user abandons request IDs.
        if queue.len() >= self.policy.max_queue as usize {
            self.total_rejected_atomic.fetch_add(1, Ordering::Relaxed);

            if let Some(ref callback) = self.policy.on_full {
                drop(queue);
                callback(&self.metrics());
            }

            return Err(BulkheadError::QueueFull);
        }

        let entry_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        queue.push_back(QueueEntry {
            id: entry_id,
            weight,
            enqueued_at_millis: now_millis,
            deadline_millis,
            result: None,
        });

        // Release ordering ensures the queue push above is visible to any
        // thread that observes this counter increment via Acquire load.
        self.pending_queue_count.fetch_add(1, Ordering::Release);
        self.total_queued_atomic.fetch_add(1, Ordering::Relaxed);
        drop(queue);
        self.notify_admission_change();

        Ok(entry_id)
    }

    /// Check the status of a queued entry.
    ///
    /// Returns:
    /// - `Ok(Some(permit))` if granted
    /// - `Ok(None)` if still waiting
    /// - `Err(QueueTimeout)` if timed out
    /// - `Err(Cancelled)` if cancelled
    #[allow(clippy::option_if_let_else, clippy::significant_drop_tightening)]
    pub fn check_entry(
        &self,
        entry_id: u64,
        now: Time,
    ) -> Result<Option<BulkheadPermit<'_>>, BulkheadError<()>> {
        // Single write lock: process queue + check entry in one acquisition.
        let mut queue = self.queue.write();
        let pending_before = self.pending_queue_count.load(Ordering::Acquire);
        let _ = self.process_queue_inner(&mut queue, now);
        let changed = self.pending_queue_count.load(Ordering::Acquire) != pending_before;

        let entry_idx = queue.iter().position(|e| e.id == entry_id);

        let result = if let Some(idx) = entry_idx {
            match queue[idx].result {
                Some(Ok(())) => {
                    let entry = queue.remove(idx).expect("entry must exist");
                    Ok(Some(BulkheadPermit {
                        bulkhead: self,
                        weight: entry.weight,
                    }))
                }
                Some(Err(RejectionReason::Timeout)) => {
                    let entry = queue.remove(idx).expect("entry must exist");
                    let wait_ms = now.as_millis().saturating_sub(entry.enqueued_at_millis);
                    Err(BulkheadError::QueueTimeout {
                        waited: Duration::from_millis(wait_ms),
                    })
                }
                None => Ok(None),
            }
        } else {
            // Entry not found - likely already processed
            Err(BulkheadError::Cancelled)
        };
        drop(queue);
        if changed {
            self.notify_admission_change();
        }
        result
    }

    /// Cancel a queued entry.
    pub fn cancel_entry(&self, entry_id: u64, now: Time) {
        let mut queue = self.queue.write();
        if let Some(idx) = queue.iter().position(|e| e.id == entry_id) {
            let entry = queue.remove(idx).expect("entry must exist");
            let previous_result = entry.result;
            // Every change to the count happens under the queue lock: a
            // concurrent reset() zeroing it between the removal and this
            // decrement wrapped it to u32::MAX, closing the fast path for good.
            if previous_result.is_none() {
                self.pending_queue_count.fetch_sub(1, Ordering::Release);
            }
            drop(queue);

            if matches!(previous_result, Some(Ok(()))) {
                // Permit was granted but not claimed. Release it.
                self.release_permit(entry.weight);
                self.total_cancelled_atomic.fetch_add(1, Ordering::Relaxed);
                let _ = self.process_queue(now);
            } else if previous_result.is_none() {
                // Still waiting. Mark as cancelled.
                let wait_ms = now.as_millis().saturating_sub(entry.enqueued_at_millis);
                self.total_wait_time_ms
                    .fetch_add(wait_ms, Ordering::Relaxed);
                self.max_queue_wait_ms_atomic
                    .fetch_max(wait_ms, Ordering::Relaxed);

                self.total_cancelled_atomic.fetch_add(1, Ordering::Relaxed);
                let _ = self.process_queue(now);
            }
            // If entry.result was Some(Err(_)), it was already counted (e.g. as Timeout)
            // and pending_queue_count was decremented. Removing it keeps queue capacity honest.
            self.notify_admission_change();
        }
    }

    /// Release permit (internal use - prefer RAII via permit).
    ///
    /// Uses a CAS loop to cap `available_permits` at `max_concurrent`,
    /// preventing overflow if permits are released after a `reset()`.
    fn release_permit(&self, weight: u32) {
        let max = self.policy.max_concurrent;
        let mut current = self.available_permits.load(Ordering::Acquire);
        let changed = loop {
            let new = current.saturating_add(weight).min(max);
            if new == current {
                break false;
            }
            match self.available_permits.compare_exchange_weak(
                current,
                new,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break true,
                Err(actual) => current = actual,
            }
        };
        if changed {
            self.notify_admission_change();
        }
    }

    /// Execute an operation with bulkhead protection (synchronous, immediate).
    ///
    /// This is a convenience method for synchronous operations that don't need
    /// queuing. `now` is the deterministic clock reading forwarded to
    /// [`try_acquire`](Self::try_acquire) for stale-entry draining.
    pub fn call<T, E, F>(&self, now: Time, op: F) -> Result<T, BulkheadError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: fmt::Display,
    {
        self.call_weighted(1, now, op)
    }

    /// Execute an operation with weighted bulkhead protection.
    ///
    /// The permit is always released, even if the operation panics. `now` is the
    /// deterministic clock reading forwarded to
    /// [`try_acquire`](Self::try_acquire) for stale-entry draining.
    pub fn call_weighted<T, E, F>(
        &self,
        weight: u32,
        now: Time,
        op: F,
    ) -> Result<T, BulkheadError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: fmt::Display,
    {
        let _permit = self.try_acquire(weight, now).ok_or(BulkheadError::Full)?;
        op().map_err(BulkheadError::Inner)
    }

    /// Manually reset the bulkhead to full capacity.
    pub fn reset(&self) {
        // Restore the permits under the queue lock: restored first, a grant
        // could take permits for an entry this then clears, and that entry's
        // weight never came back.
        let mut queue = self.queue.write();
        queue.clear();
        self.pending_queue_count.store(0, Ordering::Release);
        self.available_permits
            .store(self.policy.max_concurrent, Ordering::Release);
        drop(queue);
        self.notify_admission_change();
    }
}

impl fmt::Debug for Bulkhead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bulkhead")
            .field("name", &self.policy.name)
            .field("available", &self.available_permits.load(Ordering::Relaxed))
            .field("max_concurrent", &self.policy.max_concurrent)
            .finish_non_exhaustive()
    }
}

// =========================================================================
// Permit Guard (RAII)
// =========================================================================

/// RAII permit guard.
///
/// Automatically releases the permit to the bulkhead when dropped.
/// Use `release()` to explicitly release it early.
#[derive(Debug)]
pub struct BulkheadPermit<'a> {
    bulkhead: &'a Bulkhead,
    weight: u32,
}

impl BulkheadPermit<'_> {
    /// Get the weight of this permit.
    #[must_use]
    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// Explicitly release the permit back to the bulkhead.
    ///
    /// This consumes the guard, preventing it from running `Drop`.
    pub fn release(self) {
        // Drop implementation handles the release.
        // By consuming self, we ensure it's dropped now.
        drop(self);
    }
}

impl Drop for BulkheadPermit<'_> {
    fn drop(&mut self) {
        self.bulkhead.release_permit(self.weight);
    }
}

// =========================================================================
// Queued acquisition guard (RAII)
// =========================================================================

/// RAII guard for a *queued* bulkhead acquisition.
///
/// `enqueue` returns a bare entry id whose granted-but-unclaimed permit (or
/// waiting slot) leaks unless the caller remembers to call `cancel_entry`. This
/// guard makes that automatic: poll it with [`poll_claim`](Self::poll_claim) to
/// obtain the [`BulkheadPermit`] once granted, and if it is dropped before the
/// permit is claimed — e.g. the acquiring future is cancelled — it cancels the
/// queue entry, releasing any granted-but-unclaimed permit so the slot is not
/// leaked (5vzqse). Caller-driven guards preserve their enqueue timestamp on
/// drop. Async admission captures its authorized timer driver so cancellation
/// processes follower deadlines using the current time.
#[derive(Debug)]
pub struct QueuedAcquire<'a> {
    bulkhead: &'a Bulkhead,
    entry_id: u64,
    enqueued_now: Time,
    timer_driver: Option<crate::time::TimerDriverHandle>,
    claimed: bool,
}

impl<'a> QueuedAcquire<'a> {
    /// The id of the underlying queue entry.
    #[must_use]
    pub fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// Poll the queued entry. Returns `Ok(Some(permit))` once granted (after
    /// which this guard no longer cancels the entry on drop, since ownership has
    /// passed to the returned [`BulkheadPermit`]), `Ok(None)` while still
    /// waiting (keep polling), or `Err(..)` if the entry timed out or was
    /// cancelled (already removed; the guard becomes a no-op on drop).
    pub fn poll_claim(
        &mut self,
        now: Time,
    ) -> Result<Option<BulkheadPermit<'a>>, BulkheadError<()>> {
        let result = self.bulkhead.check_entry(self.entry_id, now);
        match &result {
            // Granted (permit handed out) or terminal error (entry removed):
            // the entry is gone from the queue, so the drop-time cancel must not
            // run (it would otherwise double-release or no-op spuriously).
            Ok(Some(_)) | Err(_) => self.claimed = true,
            Ok(None) => {}
        }
        result
    }
}

impl Drop for QueuedAcquire<'_> {
    fn drop(&mut self) {
        if !self.claimed {
            // The acquisition was abandoned before the permit was claimed.
            // cancel_entry releases a granted-but-unclaimed permit (or dequeues a
            // still-waiting entry), so no permit slot is leaked (5vzqse).
            let now = self
                .timer_driver
                .as_ref()
                .map_or(self.enqueued_now, |driver| driver.now());
            self.bulkhead.cancel_entry(self.entry_id, now);
        }
    }
}

impl Bulkhead {
    /// Enqueue an acquisition and return an RAII [`QueuedAcquire`] guard that
    /// cannot leak a permit if the acquiring future is cancelled (5vzqse).
    ///
    /// Prefer this over the bare [`enqueue`](Self::enqueue) + manual
    /// [`cancel_entry`](Self::cancel_entry) when the acquisition may be dropped
    /// before its permit is claimed.
    pub fn acquire_queued(
        &self,
        weight: u32,
        now: Time,
    ) -> Result<QueuedAcquire<'_>, BulkheadError<()>> {
        let entry_id = self.enqueue(weight, now)?;
        Ok(QueuedAcquire {
            bulkhead: self,
            entry_id,
            enqueued_now: now,
            timer_driver: None,
            claimed: false,
        })
    }
}

// =========================================================================
// Error Types
// =========================================================================

/// Failures from cancellation-aware async bulkhead admission.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BulkheadAcquireError {
    /// The bulkhead refused or expired the queued acquisition.
    Admission(BulkheadError<()>),
    /// The supplied context cancelled before ownership was handed to the caller.
    Cancelled(CancelReason),
    /// A contended acquisition needs the supplied context's time capability
    /// and timer driver to enforce queue deadlines without polling.
    TimerUnavailable,
}

impl fmt::Display for BulkheadAcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => write!(f, "bulkhead admission failed: {error:?}"),
            Self::Cancelled(reason) => write!(f, "bulkhead admission cancelled: {reason:?}"),
            Self::TimerUnavailable => f.write_str(
                "waiting for bulkhead admission requires time capability and a timer driver",
            ),
        }
    }
}

impl std::error::Error for BulkheadAcquireError {}

impl From<BulkheadError<()>> for BulkheadAcquireError {
    fn from(error: BulkheadError<()>) -> Self {
        Self::Admission(error)
    }
}

impl BulkheadAcquireError {
    fn cancelled<Caps>(cx: &Cx<Caps>) -> Self {
        Self::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("bulkhead admission cancelled")),
        )
    }
}

impl Bulkhead {
    /// Acquire a weighted permit, parking until capacity or a terminal event.
    ///
    /// Immediate admission needs no timer. A queued acquisition requires the
    /// supplied context's time capability and timer driver. Without a driver,
    /// only currently free capacity with no pending FIFO predecessor is used.
    /// Authorized waiting uses the same
    /// FIFO order, queue bound and queue timeout as the existing queue APIs.
    /// Release, queue progress and reset wake parked callers; no background
    /// task, self-wake loop or periodic polling is used.
    ///
    /// The pending queue entry remains owned across every wait. Cancellation
    /// or dropping this future removes it and refunds an unclaimed grant.
    /// A permit returned successfully has the normal RAII release behavior.
    /// Cancellation takes precedence when observed before the handoff.
    ///
    /// # Errors
    ///
    /// Returns a typed cancellation, timer-authority failure, or the original
    /// bulkhead queue refusal/timeout. Reset invalidates a pending entry and
    /// returns `Admission(BulkheadError::Cancelled)`.
    pub async fn acquire_async<Caps>(
        &self,
        cx: &Cx<Caps>,
        weight: u32,
    ) -> Result<BulkheadPermit<'_>, BulkheadAcquireError>
    where
        Caps: crate::cx::cap::HasTime,
    {
        cx.checkpoint()
            .map_err(|_| BulkheadAcquireError::cancelled(cx))?;
        let driver = cx.timer_driver();
        let now = driver.as_ref().map_or(Time::ZERO, |driver| driver.now());
        let immediate = if driver.is_some() {
            self.try_acquire(weight, now)
        } else {
            self.try_acquire_ready(weight)
        };
        if let Some(permit) = immediate {
            cx.checkpoint()
                .map_err(|_| BulkheadAcquireError::cancelled(cx))?;
            return Ok(permit);
        }
        if weight > self.policy.max_concurrent {
            self.total_rejected_atomic.fetch_add(1, Ordering::Relaxed);
            return Err(BulkheadError::Full.into());
        }
        let driver = driver.ok_or(BulkheadAcquireError::TimerUnavailable)?;
        let mut queued = self.acquire_queued(weight, now)?;
        queued.timer_driver = Some(driver.clone());
        let mut cancelled = std::pin::pin!(cx.cancelled());

        loop {
            let mut changed = std::pin::pin!(self.changed.notified());
            // Arm the creation-time generation before checking state. Merely
            // constructing Notified would capture it on first poll and could
            // lose a release between poll_claim and waiter registration.
            changed.as_mut().enable();
            let now = driver.now();
            // Enforce deadlines after the time snapshot used below: an elapsed
            // owner deadline may be omitted from the timer only if masked.
            cx.checkpoint()
                .map_err(|_| BulkheadAcquireError::cancelled(cx))?;
            if let Some(permit) = queued.poll_claim(now)? {
                cx.checkpoint()
                    .map_err(|_| BulkheadAcquireError::cancelled(cx))?;
                return Ok(permit);
            }

            // A raw FIFO predecessor might never be polled again. Its expiry
            // must wake this owner so it can retire the predecessor and proceed.
            let queue_deadline = self
                .queue
                .read()
                .iter()
                .filter(|entry| entry.result.is_none())
                .map(|entry| Time::from_millis(entry.deadline_millis))
                .min()
                .unwrap_or(Time::MAX);
            let wake_at = cx
                .budget()
                .deadline
                // An expired but masked cancellation must not create a
                // permanently-ready timer loop. Cancellation stays deferred.
                .filter(|deadline| *deadline > now)
                .map_or(queue_deadline, |deadline| queue_deadline.min(deadline));
            let mut timer =
                std::pin::pin!(crate::time::Sleep::with_timer_driver(wake_at, driver.clone()));
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                    return Poll::Ready(());
                }
                if changed.as_mut().poll(task).is_ready()
                    || (wake_at > now && timer.as_mut().poll_deadline(task).is_ready())
                {
                    return Poll::Ready(());
                }
                Poll::Pending
            })
            .await;
        }
    }

    /// Queue/capacity publication cannot unwind through the owner because an
    /// external wake callback panics. Notify still completes its entire fanout.
    fn notify_admission_change(&self) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.changed.notify_waiters();
        })) {
            // A panic payload can itself have a panicking destructor. Contain
            // that too; leaking only the secondary payload keeps an already
            // published transition from unwinding before its RAII owner exists.
            if let Err(secondary) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
            {
                std::mem::forget(secondary);
            }
        }
    }
}

/// Errors from bulkhead.
#[derive(Debug, Clone)]
pub enum BulkheadError<E> {
    /// Bulkhead is full (no permits available, immediate rejection).
    Full,

    /// Queue is full, cannot enqueue.
    QueueFull,

    /// Timed out waiting in queue.
    QueueTimeout {
        /// How long we waited.
        waited: Duration,
    },

    /// Cancelled while waiting in queue.
    Cancelled,

    /// Underlying operation error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for BulkheadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "bulkhead full"),
            Self::QueueFull => write!(f, "bulkhead queue full"),
            Self::QueueTimeout { waited } => {
                write!(f, "bulkhead queue timeout after {waited:?}")
            }
            Self::Cancelled => write!(f, "cancelled while waiting for bulkhead"),
            Self::Inner(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for BulkheadError<E> {}

// =========================================================================
// Builder Pattern
// =========================================================================

/// Builder for `BulkheadPolicy`.
#[derive(Default)]
pub struct BulkheadPolicyBuilder {
    policy: BulkheadPolicy,
}

impl BulkheadPolicyBuilder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bulkhead name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.policy.name = name.into();
        self
    }

    /// Set the maximum concurrent permits.
    #[must_use]
    pub const fn max_concurrent(mut self, max: u32) -> Self {
        self.policy.max_concurrent = max;
        self
    }

    /// Set the maximum queue size.
    #[must_use]
    pub const fn max_queue(mut self, max: u32) -> Self {
        self.policy.max_queue = max;
        self
    }

    /// Set the queue timeout.
    #[must_use]
    pub const fn queue_timeout(mut self, timeout: Duration) -> Self {
        self.policy.queue_timeout = timeout;
        self
    }

    /// Enable weighted permits.
    #[must_use]
    pub const fn weighted(mut self, enabled: bool) -> Self {
        self.policy.weighted = enabled;
        self
    }

    /// Set a callback for when bulkhead is full.
    #[must_use]
    pub fn on_full(mut self, callback: FullCallback) -> Self {
        self.policy.on_full = Some(callback);
        self
    }

    /// Build the policy.
    #[must_use]
    pub fn build(self) -> BulkheadPolicy {
        self.policy
    }
}

// =========================================================================
// Registry for Named Bulkheads
// =========================================================================

/// Registry for managing multiple named bulkheads.
pub struct BulkheadRegistry {
    bulkheads: RwLock<HashMap<String, Arc<Bulkhead>>>,
    default_policy: BulkheadPolicy,
}

const DEFAULT_BULKHEAD_REGISTRY_CAPACITY: usize = 16;

impl BulkheadRegistry {
    /// Create a new registry with a default policy.
    #[must_use]
    pub fn new(default_policy: BulkheadPolicy) -> Self {
        Self {
            bulkheads: RwLock::new(HashMap::with_capacity(DEFAULT_BULKHEAD_REGISTRY_CAPACITY)),
            default_policy,
        }
    }

    /// Get or create a named bulkhead.
    pub fn get_or_create(&self, name: &str) -> Arc<Bulkhead> {
        // Fast path: read lock
        {
            let bulkheads = self.bulkheads.read();
            if let Some(b) = bulkheads.get(name) {
                return b.clone();
            }
        }

        // Slow path: write lock
        let mut bulkheads = self.bulkheads.write();
        bulkheads
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(Bulkhead::new(BulkheadPolicy {
                    name: name.to_string(),
                    ..self.default_policy.clone()
                }))
            })
            .clone()
    }

    /// Get or create with custom policy.
    pub fn get_or_create_with(&self, name: &str, policy: BulkheadPolicy) -> Arc<Bulkhead> {
        let mut bulkheads = self.bulkheads.write();
        bulkheads
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Bulkhead::new(policy)))
            .clone()
    }

    /// Get metrics for all bulkheads.
    #[must_use]
    pub fn all_metrics(&self) -> HashMap<String, BulkheadMetrics> {
        let bulkheads = self.bulkheads.read();
        let mut metrics = HashMap::with_capacity(bulkheads.len());
        for (name, bulkhead) in bulkheads.iter() {
            metrics.insert(name.clone(), bulkhead.metrics());
        }
        drop(bulkheads);
        metrics
    }

    /// Remove a named bulkhead.
    pub fn remove(&self, name: &str) -> Option<Arc<Bulkhead>> {
        let mut bulkheads = self.bulkheads.write();
        bulkheads.remove(name)
    }
}

impl fmt::Debug for BulkheadRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bulkheads = self.bulkheads.read();
        f.debug_struct("BulkheadRegistry")
            .field("count", &bulkheads.len())
            .finish_non_exhaustive()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[path = "bulkhead_inline_tests.rs"]
mod tests;
