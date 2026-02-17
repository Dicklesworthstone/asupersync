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
//! // Try to acquire a permit
//! if let Some(permit) = bulkhead.try_acquire(1) {
//!     // Execute protected operation
//!     do_work();
//!     // Permit automatically released on drop
//! } else {
//!     // Bulkhead full, handle rejection
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::types::Time;

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
    Cancelled,
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
    queue: RwLock<Vec<QueueEntry>>,

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
            queue: RwLock::new(Vec::with_capacity(max_queue)),
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
        let queue = self.queue.read().expect("lock poisoned");
        let active = queue.iter().filter(|e| e.result.is_none()).count() as u32;
        let used_permits =
            self.policy.max_concurrent - self.available_permits.load(Ordering::Acquire);

        let total_executed = self.total_executed_atomic.load(Ordering::Relaxed);
        let avg_queue_wait_ms = if total_executed > 0 {
            self.total_wait_time_ms.load(Ordering::Relaxed) as f64 / total_executed as f64
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
    #[must_use]
    pub fn try_acquire(&self, weight: u32) -> Option<BulkheadPermit<'_>> {
        loop {
            let available = self.available_permits.load(Ordering::Acquire);
            if available >= weight {
                if self
                    .available_permits
                    .compare_exchange(
                        available,
                        available - weight,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Some(BulkheadPermit {
                        bulkhead: self,
                        weight,
                    });
                }
                // CAS failed, retry
            } else {
                return None;
            }
        }
    }

    /// Check if a queued entry can be granted.
    ///
    /// Call this periodically or when permits become available.
    /// Returns the ID of any entry that was granted, or None.
    #[allow(clippy::cast_precision_loss)]
    pub fn process_queue(&self, now: Time) -> Option<u64> {
        let now_millis = now.as_millis();

        let mut queue = self.queue.write().expect("lock poisoned");

        // First, timeout expired entries — count timeouts locally and batch-update
        // the metrics lock once, instead of acquiring it per timed-out entry.
        let mut timeout_count = 0u64;
        for entry in queue.iter_mut() {
            if entry.result.is_none() && now_millis >= entry.deadline_millis {
                entry.result = Some(Err(RejectionReason::Timeout));
                timeout_count += 1;
            }
        }
        if timeout_count > 0 {
            self.total_timeout_atomic.fetch_add(timeout_count, Ordering::Relaxed);
        }

        // Find first waiting entry that can be granted
        for entry in queue.iter_mut() {
            if entry.result.is_none() {
                // CAS loop to safely consume permits (prevents TOCTOU race with try_acquire)
                let granted = loop {
                    let current = self.available_permits.load(Ordering::Acquire);
                    if current < entry.weight {
                        break false;
                    }
                    if self
                        .available_permits
                        .compare_exchange(
                            current,
                            current - entry.weight,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break true;
                    }
                };
                if !granted {
                    continue;
                }
                entry.result = Some(Ok(()));

                // Record wait time
                let wait_ms = now_millis.saturating_sub(entry.enqueued_at_millis);
                self.total_wait_time_ms
                    .fetch_add(wait_ms, Ordering::Relaxed);

                self.total_executed_atomic.fetch_add(1, Ordering::Relaxed);
                self.max_queue_wait_ms_atomic.fetch_max(wait_ms, Ordering::Relaxed);

                return Some(entry.id);
            }
        }

        // Clean up old completed entries (only those that have been processed)
        // Keep rejected entries so check_entry can return the proper error
        // queue.retain(|e| !matches!(e.result, Some(Ok(()))));

        drop(queue);
        None
    }

    /// Enqueue a waiting operation.
    ///
    /// Returns `Ok(entry_id)` if enqueued, `Err(QueueFull)` if queue is full.
    #[allow(clippy::significant_drop_tightening, clippy::cast_precision_loss)]
    pub fn enqueue(&self, weight: u32, now: Time) -> Result<u64, BulkheadError<()>> {
        let now_millis = now.as_millis();
        let deadline_millis = now_millis + self.policy.queue_timeout.as_millis() as u64;

        let mut queue = self.queue.write().expect("lock poisoned");

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

        queue.push(QueueEntry {
            id: entry_id,
            weight,
            enqueued_at_millis: now_millis,
            deadline_millis,
            result: None,
        });

        self.total_queued_atomic.fetch_add(1, Ordering::Relaxed);

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
        // First process the queue to handle timeouts and grants
        let _ = self.process_queue(now);

        let mut queue = self.queue.write().expect("lock poisoned");
        let entry_idx = queue.iter().position(|e| e.id == entry_id);

        if let Some(idx) = entry_idx {
            let entry = &queue[idx];
            match entry.result {
                Some(Ok(())) => {
                    let weight = entry.weight;
                    // Remove the granted entry
                    queue.remove(idx);
                    Ok(Some(BulkheadPermit {
                        bulkhead: self,
                        weight,
                    }))
                }
                Some(Err(RejectionReason::Timeout)) => {
                    let wait_ms = now.as_millis().saturating_sub(entry.enqueued_at_millis);
                    // Remove the timed-out entry
                    queue.remove(idx);
                    Err(BulkheadError::QueueTimeout {
                        waited: Duration::from_millis(wait_ms),
                    })
                }
                Some(Err(RejectionReason::Cancelled)) => {
                    // Remove the cancelled entry
                    queue.remove(idx);
                    Err(BulkheadError::Cancelled)
                }
                None => Ok(None),
            }
        } else {
            // Entry not found - likely already processed
            Err(BulkheadError::Cancelled)
        }
    }

    /// Cancel a queued entry.
    pub fn cancel_entry(&self, entry_id: u64) {
        let mut queue = self.queue.write().expect("lock poisoned");
        if let Some(idx) = queue.iter().position(|e| e.id == entry_id) {
            let entry = &mut queue[idx];

            if matches!(entry.result, Some(Ok(()))) {
                // Permit was granted but not claimed. Release it.
                let weight = entry.weight;
                queue.remove(idx);
                drop(queue);
                self.release_permit(weight);
                self.total_cancelled_atomic.fetch_add(1, Ordering::Relaxed);
            } else if entry.result.is_none() {
                // Still waiting. Mark as cancelled.
                entry.result = Some(Err(RejectionReason::Cancelled));
                drop(queue);
                self.total_cancelled_atomic.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Release permit (internal use - prefer RAII via permit).
    ///
    /// Uses a CAS loop to cap `available_permits` at `max_concurrent`,
    /// preventing overflow if permits are released after a `reset()`.
    fn release_permit(&self, weight: u32) {
        let max = self.policy.max_concurrent;
        loop {
            let current = self.available_permits.load(Ordering::Acquire);
            let new = current.saturating_add(weight).min(max);
            if new == current {
                break;
            }
            if self
                .available_permits
                .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Execute an operation with bulkhead protection (synchronous, immediate).
    ///
    /// This is a convenience method for synchronous operations that don't need queuing.
    pub fn call<T, E, F>(&self, op: F) -> Result<T, BulkheadError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: fmt::Display,
    {
        self.call_weighted(1, op)
    }

    /// Execute an operation with weighted bulkhead protection.
    ///
    /// The permit is always released, even if the operation panics.
    pub fn call_weighted<T, E, F>(&self, weight: u32, op: F) -> Result<T, BulkheadError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: fmt::Display,
    {
        let permit = self.try_acquire(weight).ok_or(BulkheadError::Full)?;

        // Use catch_unwind to ensure permit is released even if op panics.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(op));

        // Permit is automatically released when dropped here or on unwind.
        // We explicitly drop it here to be clear that the protected section ends.
        drop(permit);

        match result {
            Ok(Ok(value)) => {
                self.total_executed_atomic.fetch_add(1, Ordering::Relaxed);
                Ok(value)
            }
            Ok(Err(e)) => Err(BulkheadError::Inner(e)),
            Err(panic_payload) => std::panic::resume_unwind(panic_payload),
        }
    }

    /// Manually reset the bulkhead to full capacity.
    pub fn reset(&self) {
        self.available_permits
            .store(self.policy.max_concurrent, Ordering::Release);

        let mut queue = self.queue.write().expect("lock poisoned");
        for entry in queue.iter_mut() {
            if entry.result.is_none() {
                entry.result = Some(Err(RejectionReason::Cancelled));
            }
        }
        queue.clear();
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
// Error Types
// =========================================================================

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
            let bulkheads = self.bulkheads.read().expect("lock poisoned");
            if let Some(b) = bulkheads.get(name) {
                return b.clone();
            }
        }

        // Slow path: write lock
        let mut bulkheads = self.bulkheads.write().expect("lock poisoned");
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
        let mut bulkheads = self.bulkheads.write().expect("lock poisoned");
        bulkheads
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Bulkhead::new(policy)))
            .clone()
    }

    /// Get metrics for all bulkheads.
    #[must_use]
    pub fn all_metrics(&self) -> HashMap<String, BulkheadMetrics> {
        let bulkheads = self.bulkheads.read().expect("lock poisoned");
        let mut metrics = HashMap::with_capacity(bulkheads.len());
        for (name, bulkhead) in bulkheads.iter() {
            metrics.insert(name.clone(), bulkhead.metrics());
        }
        drop(bulkheads);
        metrics
    }

    /// Remove a named bulkhead.
    pub fn remove(&self, name: &str) -> Option<Arc<Bulkhead>> {
        let mut bulkheads = self.bulkheads.write().expect("lock poisoned");
        bulkheads.remove(name)
    }
}

impl fmt::Debug for BulkheadRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bulkheads = self.bulkheads.read().expect("lock poisoned");
        f.debug_struct("BulkheadRegistry")
            .field("count", &bulkheads.len())
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
    // Basic Permit Acquisition
    // =========================================================================

    #[test]
    fn new_bulkhead_has_full_capacity() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
        assert_eq!(bh.metrics().active_permits, 0);
        assert!((bh.metrics().utilization - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn try_acquire_reduces_available() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        let permit = bh.try_acquire(1).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 9);
        assert_eq!(bh.metrics().active_permits, 1);

        permit.release();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
        assert_eq!(bh.metrics().active_permits, 0);
    }

    #[test]
    fn try_acquire_fails_when_exhausted() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 2,
            ..Default::default()
        });

        let p1 = bh.try_acquire(1).unwrap();
        let p2 = bh.try_acquire(1).unwrap();
        let p3 = bh.try_acquire(1);

        assert!(p3.is_none());
        assert_eq!(bh.metrics().active_permits, 2);

        p1.release();
        p2.release();
    }

    // =========================================================================
    // Weighted Permits
    // =========================================================================

    #[test]
    fn weighted_permit_consumes_multiple() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        let permit = bh.try_acquire(5).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 5);
        assert_eq!(permit.weight(), 5);

        // Cannot acquire 6 more
        assert!(bh.try_acquire(6).is_none());

        // Can acquire 5
        let p2 = bh.try_acquire(5).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 0);

        permit.release();
        p2.release();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn weighted_permit_zero_weight_allowed() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        // Zero weight permits can be useful for "observer" patterns
        let permit = bh.try_acquire(0).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
        permit.release();
    }

    // =========================================================================
    // Queue Tests
    // =========================================================================

    #[test]
    fn enqueue_adds_to_queue() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1).unwrap();

        // Enqueue should succeed
        let entry_id = bh.enqueue(1, now).unwrap();
        assert!(entry_id < 1000); // Sanity check

        assert_eq!(bh.metrics().total_queued, 1);
    }

    #[test]
    fn enqueue_rejects_when_queue_full() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 2,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1).unwrap();

        // Fill queue
        bh.enqueue(1, now).unwrap();
        bh.enqueue(1, now).unwrap();

        // Third should fail
        let result = bh.enqueue(1, now);
        assert!(matches!(result, Err(BulkheadError::QueueFull)));
        assert_eq!(bh.metrics().total_rejected, 1);
    }

    #[test]
    fn process_queue_grants_when_permits_available() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_mins(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let p = bh.try_acquire(1).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Release permit
        p.release();

        // Process queue - should grant
        let granted = bh.process_queue(now);
        assert_eq!(granted, Some(entry_id));
    }

    #[test]
    fn check_entry_returns_permit_when_granted() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 2,
            max_queue: 10,
            queue_timeout: Duration::from_mins(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let p1 = bh.try_acquire(1).unwrap();
        let _p2 = bh.try_acquire(1).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Still waiting
        let result = bh.check_entry(entry_id, now);
        assert!(matches!(result, Ok(None)));

        // Release one permit
        p1.release();

        // Now should be granted
        let result = bh.check_entry(entry_id, now);
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn queue_timeout_triggers_error() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_millis(100),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Check after timeout
        let later = Time::from_millis(200);
        let result = bh.check_entry(entry_id, later);

        assert!(matches!(result, Err(BulkheadError::QueueTimeout { .. })));
        assert_eq!(bh.metrics().total_timeout, 1);
    }

    #[test]
    fn cancel_entry_triggers_cancellation() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_mins(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Cancel
        bh.cancel_entry(entry_id);

        assert_eq!(bh.metrics().total_cancelled, 1);
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn metrics_track_active_permits() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        assert_eq!(bh.metrics().active_permits, 0);

        let p1 = bh.try_acquire(1).unwrap();
        assert_eq!(bh.metrics().active_permits, 1);

        let p2 = bh.try_acquire(3).unwrap();
        assert_eq!(bh.metrics().active_permits, 4);

        p1.release();
        assert_eq!(bh.metrics().active_permits, 3);

        p2.release();
        assert_eq!(bh.metrics().active_permits, 0);
    }

    #[test]
    fn metrics_calculate_utilization() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        assert!((bh.metrics().utilization - 0.0).abs() < f64::EPSILON);

        let p1 = bh.try_acquire(5).unwrap();
        assert!((bh.metrics().utilization - 0.5).abs() < f64::EPSILON);

        let p2 = bh.try_acquire(5).unwrap();
        assert!((bh.metrics().utilization - 1.0).abs() < f64::EPSILON);

        p1.release();
        p2.release();
    }

    #[test]
    fn metrics_initial_values() {
        let bh = Bulkhead::new(BulkheadPolicy {
            name: "test".into(),
            max_concurrent: 5,
            ..Default::default()
        });

        let m = bh.metrics();
        assert_eq!(m.active_permits, 0);
        assert_eq!(m.queue_depth, 0);
        assert_eq!(m.total_executed, 0);
        assert_eq!(m.total_queued, 0);
        assert_eq!(m.total_rejected, 0);
        assert_eq!(m.total_timeout, 0);
        assert_eq!(m.total_cancelled, 0);
        assert!((m.avg_queue_wait_ms - 0.0).abs() < f64::EPSILON);
        assert_eq!(m.max_queue_wait_ms, 0);
    }

    // =========================================================================
    // Registry Tests
    // =========================================================================

    #[test]
    fn registry_creates_named_bulkheads() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh1 = registry.get_or_create("service-a");
        let bh2 = registry.get_or_create("service-b");
        let bh3 = registry.get_or_create("service-a");

        // Same name returns same instance
        assert!(Arc::ptr_eq(&bh1, &bh3));

        // Different names return different instances
        assert!(!Arc::ptr_eq(&bh1, &bh2));
    }

    #[test]
    fn registry_uses_provided_name() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh = registry.get_or_create("my-service");
        assert_eq!(bh.name(), "my-service");
    }

    #[test]
    fn registry_custom_policy() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh = registry.get_or_create_with(
            "custom",
            BulkheadPolicy {
                max_concurrent: 100,
                max_queue: 500,
                ..Default::default()
            },
        );

        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn registry_all_metrics() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh1 = registry.get_or_create("db");
        let bh2 = registry.get_or_create("api");

        let _p1 = bh1.try_acquire(1);
        let _p2 = bh2.try_acquire(3);

        let all = registry.all_metrics();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("db").unwrap().active_permits, 1);
        assert_eq!(all.get("api").unwrap().active_permits, 3);
    }

    #[test]
    fn registry_remove() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh1 = registry.get_or_create("temp");
        assert_eq!(registry.all_metrics().len(), 1);

        let removed = registry.remove("temp");
        assert!(removed.is_some());
        assert!(Arc::ptr_eq(&bh1, &removed.unwrap()));
        assert_eq!(registry.all_metrics().len(), 0);

        // Remove non-existent returns None
        assert!(registry.remove("nonexistent").is_none());
    }

    // =========================================================================
    // Concurrent Access Tests
    // =========================================================================

    #[test]
    fn concurrent_acquire_release_safe() {
        use std::thread;

        let bh = Arc::new(Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        }));

        let handles: Vec<_> = (0..100)
            .map(|_| {
                let bh = bh.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        if let Some(permit) = bh.try_acquire(1) {
                            // Simulate work
                            std::thread::yield_now();
                            permit.release();
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All permits should be returned
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn concurrent_never_exceeds_max() {
        use std::sync::atomic::AtomicU32;
        use std::thread;

        let bh = Arc::new(Bulkhead::new(BulkheadPolicy {
            max_concurrent: 5,
            ..Default::default()
        }));

        let current = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..50)
            .map(|_| {
                let bh = bh.clone();
                let current = current.clone();
                let peak = peak.clone();

                thread::spawn(move || {
                    for _ in 0..20 {
                        if let Some(permit) = bh.try_acquire(1) {
                            let c = current.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(c, Ordering::SeqCst);

                            std::thread::yield_now();

                            current.fetch_sub(1, Ordering::SeqCst);
                            permit.release();
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert!(peak.load(Ordering::SeqCst) <= 5);
    }

    // =========================================================================
    // Call Helper Tests
    // =========================================================================

    #[test]
    fn call_executes_and_records() {
        let bh = Bulkhead::new(BulkheadPolicy::default());

        let result = bh.call(|| Ok::<_, &str>(42));

        assert_eq!(result.unwrap(), 42);
        assert_eq!(bh.metrics().total_executed, 1);
    }

    #[test]
    fn call_handles_inner_error() {
        let bh = Bulkhead::new(BulkheadPolicy::default());

        let result: Result<i32, BulkheadError<&str>> = bh.call(|| Err("error"));

        assert!(matches!(result, Err(BulkheadError::Inner("error"))));
    }

    #[test]
    fn call_rejects_when_full() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        });

        let _p = bh.try_acquire(1).unwrap();

        let result: Result<i32, BulkheadError<&str>> = bh.call(|| Ok(42));

        assert!(matches!(result, Err(BulkheadError::Full)));
    }

    #[test]
    fn call_releases_permit_on_panic() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        });

        // Verify starting capacity
        assert_eq!(bh.available(), 1);

        // Call that panics
        let result = catch_unwind(AssertUnwindSafe(|| {
            bh.call(|| -> Result<(), &str> { panic!("intentional test panic") })
        }));

        // Should have panicked
        assert!(result.is_err());

        // Permit should be released despite panic
        assert_eq!(bh.available(), 1, "permit should be released after panic");

        // Should be able to acquire again
        let permit = bh.try_acquire(1);
        assert!(permit.is_some(), "should be able to acquire after panic");
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn builder_creates_policy() {
        let policy = BulkheadPolicyBuilder::new()
            .name("test")
            .max_concurrent(20)
            .max_queue(50)
            .queue_timeout(Duration::from_secs(30))
            .weighted(true)
            .build();

        assert_eq!(policy.name, "test");
        assert_eq!(policy.max_concurrent, 20);
        assert_eq!(policy.max_queue, 50);
        assert_eq!(policy.queue_timeout, Duration::from_secs(30));
        assert!(policy.weighted);
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let full: BulkheadError<&str> = BulkheadError::Full;
        assert!(full.to_string().contains("full"));

        let queue_full: BulkheadError<&str> = BulkheadError::QueueFull;
        assert!(queue_full.to_string().contains("queue full"));

        let timeout: BulkheadError<&str> = BulkheadError::QueueTimeout {
            waited: Duration::from_millis(500),
        };
        assert!(timeout.to_string().contains("timeout"));

        let cancelled: BulkheadError<&str> = BulkheadError::Cancelled;
        assert!(cancelled.to_string().contains("cancelled"));

        let inner: BulkheadError<&str> = BulkheadError::Inner("inner error");
        assert_eq!(inner.to_string(), "inner error");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_restores_capacity() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        let _p1 = bh.try_acquire(5).unwrap();
        let _p2 = bh.try_acquire(3).unwrap();

        assert_eq!(bh.available(), 2);

        bh.reset();

        assert_eq!(bh.available(), 10);
    }

    #[test]
    fn release_after_reset_does_not_exceed_max_concurrent() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        // Acquire permits
        let p1 = bh.try_acquire(5).unwrap();
        let p2 = bh.try_acquire(3).unwrap();
        assert_eq!(bh.available(), 2);

        // Reset while permits outstanding
        bh.reset();
        assert_eq!(bh.available(), 10);

        // Release pre-reset permits — must NOT exceed max_concurrent
        p1.release();
        assert_eq!(
            bh.available(),
            10,
            "available_permits must be capped at max_concurrent after reset + release"
        );

        p2.release();
        assert_eq!(
            bh.available(),
            10,
            "available_permits must still be capped after second release"
        );

        // Core invariant: must not grant more than max_concurrent permits
        let mut permits: Vec<BulkheadPermit> = Vec::new();
        for _ in 0..10 {
            permits.push(bh.try_acquire(1).unwrap());
        }
        assert!(
            bh.try_acquire(1).is_none(),
            "must reject 11th permit even after reset + release"
        );

        for p in permits {
            p.release();
        }
    }

    #[test]
    fn cancel_entry_releases_permit_if_already_granted() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 1. Exhaust permits
        let p1 = bh.try_acquire(1).unwrap();

        // 2. Enqueue waiter
        let entry_id = bh.enqueue(1, now).unwrap();

        // 3. Release permit (making it available for the waiter)
        p1.release();

        // 4. Process queue (grants the permit to the waiter)
        let granted_id = bh.process_queue(now);
        assert_eq!(granted_id, Some(entry_id));

        // At this point, the waiter has the permit reserved (available = 0)
        // but hasn't claimed it via check_entry.
        assert_eq!(bh.available(), 0);

        // 5. Cancel the entry (simulate user dropping the future)
        bh.cancel_entry(entry_id);

        // 6. Verify permit is returned
        // BUG: Without the fix, this assertion fails because the permit is leaked.
        assert_eq!(
            bh.available(),
            1,
            "permit should be released upon cancellation of granted entry"
        );
    }

    #[test]
    fn zombies_fill_queue() {
        // Regression test for unbounded queue growth due to abandoned entries.
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 2,
            queue_timeout: Duration::from_mins(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 1. Exhaust permits
        let p1 = bh.try_acquire(1).unwrap();

        // 2. Fill queue
        let id1 = bh.enqueue(1, now).unwrap();
        let _id2 = bh.enqueue(1, now).unwrap();

        // 3. Release permit - grants id1
        p1.release();
        let granted = bh.process_queue(now);
        assert_eq!(granted, Some(id1));

        // 4. Don't claim id1. It sits in queue as "Granted".
        // Queue len is still 2.

        // 5. Try to enqueue - should be rejected because queue is full of zombies/waiting
        let result = bh.enqueue(1, now);
        assert!(
            matches!(result, Err(BulkheadError::QueueFull)),
            "Zombies should count towards queue limit"
        );

        // 6. Claim id1 (removes it)
        let permit = bh.check_entry(id1, now).unwrap().unwrap();
        permit.release();

        // 7. Queue len now 1. Can enqueue.
        assert!(bh.enqueue(1, now).is_ok());
    }
}
