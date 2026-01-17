//! Two-phase semaphore with permit obligations.
//!
//! A semaphore controls access to a finite number of resources through permits.
//! Each acquired permit is tracked as an obligation that must be released.
//!
//! # Cancel Safety
//!
//! The acquire operation is split into two phases:
//! - **Phase 1**: Wait for permit availability (cancel-safe)
//! - **Phase 2**: Acquire permit and create obligation (cannot fail)
//!
//! If cancelled during the wait phase, no permits are acquired and no cleanup
//! is needed. Once a permit is acquired, it will always be released on drop.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::sync::Semaphore;
//!
//! // Create semaphore with 10 permits
//! let sem = Semaphore::new(10);
//!
//! // Acquire a permit (blocks until available)
//! let permit = sem.acquire(&cx, 1)?;
//!
//! // Do work while holding permit...
//!
//! // Permit is automatically released when dropped
//! drop(permit);
//! ```
//!
//! # Bounded Concurrency Pattern
//!
//! ```ignore
//! let sem = Semaphore::new(10);  // Max 10 concurrent
//!
//! // Worker acquires permit before doing work
//! async fn worker(cx: &mut Cx, sem: &Semaphore) -> Result<(), Error> {
//!     let _permit = sem.acquire(cx, 1)?;
//!     // ... do bounded work ...
//!     // permit released on drop
//!     Ok(())
//! }
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::cx::Cx;

/// Error returned when semaphore acquisition fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// The semaphore was closed.
    Closed,
    /// Cancelled while waiting.
    Cancelled,
}

impl std::fmt::Display for AcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "semaphore closed"),
            Self::Cancelled => write!(f, "semaphore acquire cancelled"),
        }
    }
}

impl std::error::Error for AcquireError {}

/// Error returned when trying to acquire more permits than available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryAcquireError;

impl std::fmt::Display for TryAcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no semaphore permits available")
    }
}

impl std::error::Error for TryAcquireError {}

/// A counting semaphore for limiting concurrent access.
///
/// A semaphore maintains a count of available permits. Tasks can acquire
/// permits (decrementing the count) and release them (incrementing the count).
/// When no permits are available, tasks wait until one is released.
///
/// # Fairness
///
/// This semaphore is FIFO-fair: waiters are serviced in the order they arrived.
/// This prevents starvation and ensures deterministic behavior in the lab runtime.
#[derive(Debug)]
pub struct Semaphore {
    /// Number of available permits.
    permits: AtomicUsize,
    /// Maximum permits (initial count).
    max_permits: usize,
    /// Whether the semaphore is closed.
    closed: AtomicUsize, // 0 = open, 1 = closed
    /// Number of waiters (for debugging/stats).
    waiters: AtomicUsize,
    /// FIFO queue position counter for fairness.
    queue_head: Mutex<u64>,
    queue_tail: AtomicUsize,
}

impl Semaphore {
    /// Creates a new semaphore with the given number of permits.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let sem = Semaphore::new(5);
    /// assert_eq!(sem.available_permits(), 5);
    /// ```
    #[must_use]
    pub fn new(permits: usize) -> Self {
        Self {
            permits: AtomicUsize::new(permits),
            max_permits: permits,
            closed: AtomicUsize::new(0),
            waiters: AtomicUsize::new(0),
            queue_head: Mutex::new(0),
            queue_tail: AtomicUsize::new(0),
        }
    }

    /// Returns the number of currently available permits.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.permits.load(Ordering::Acquire)
    }

    /// Returns the maximum number of permits (initial count).
    #[must_use]
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Returns true if the semaphore is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != 0
    }

    /// Returns the number of tasks currently waiting for permits.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// Closes the semaphore.
    ///
    /// After closing, all pending and future acquire operations will fail
    /// with `AcquireError::Closed`.
    pub fn close(&self) {
        self.closed.store(1, Ordering::Release);
        // In full implementation: wake all waiters
    }

    /// Acquires the given number of permits, waiting if necessary.
    ///
    /// This method is cancel-safe. If cancelled while waiting:
    /// - No permits are acquired
    /// - No cleanup is needed
    /// - The wait can be retried
    ///
    /// # Errors
    ///
    /// Returns `AcquireError::Closed` if the semaphore was closed.
    /// Returns `AcquireError::Cancelled` if cancelled while waiting.
    ///
    /// # Panics
    ///
    /// Panics if `count` is 0 or greater than `max_permits`.
    pub fn acquire(&self, cx: &Cx, count: usize) -> Result<SemaphorePermit<'_>, AcquireError> {
        assert!(count > 0, "cannot acquire 0 permits");
        assert!(
            count <= self.max_permits,
            "cannot acquire more permits than semaphore capacity"
        );

        cx.trace("semaphore::acquire starting");

        // Get our position in the queue for FIFO fairness
        let our_position = {
            let mut head = self.queue_head.lock().expect("semaphore lock poisoned");
            let pos = *head;
            *head += 1;
            pos
        };

        // Mark ourselves as waiting
        self.waiters.fetch_add(1, Ordering::AcqRel);

        // Wait for our turn and available permits
        loop {
            // Check if closed
            if self.is_closed() {
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                cx.trace("semaphore::acquire closed");
                return Err(AcquireError::Closed);
            }

            // Check if it's our turn (FIFO)
            let current_tail = self.queue_tail.load(Ordering::Acquire) as u64;
            if current_tail != our_position {
                // Not our turn yet, check cancellation and yield
                if cx.checkpoint().is_err() {
                    self.waiters.fetch_sub(1, Ordering::AcqRel);
                    cx.trace("semaphore::acquire cancelled while waiting for turn");
                    return Err(AcquireError::Cancelled);
                }
                std::thread::yield_now();
                continue;
            }

            // It's our turn - try to acquire
            let available = self.permits.load(Ordering::Acquire);
            if available >= count {
                // Try to claim the permits atomically
                match self.permits.compare_exchange(
                    available,
                    available - count,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // Success! Advance the queue and return permit
                        self.queue_tail.fetch_add(1, Ordering::AcqRel);
                        self.waiters.fetch_sub(1, Ordering::AcqRel);
                        cx.trace("semaphore::acquire succeeded");

                        return Ok(SemaphorePermit {
                            semaphore: self,
                            count,
                        });
                    }
                    Err(_) => {
                        // Lost race, retry
                        continue;
                    }
                }
            }

            // Not enough permits available
            // Check cancellation before waiting
            if cx.checkpoint().is_err() {
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                // Advance queue to not block others
                self.queue_tail.fetch_add(1, Ordering::AcqRel);
                cx.trace("semaphore::acquire cancelled while waiting for permits");
                return Err(AcquireError::Cancelled);
            }

            // Phase 0: Simple spin-wait with yield
            // Future: integrate with scheduler via proper waker/condvar
            std::thread::yield_now();
        }
    }

    /// Tries to acquire the given number of permits without waiting.
    ///
    /// # Errors
    ///
    /// Returns `TryAcquireError` if permits are not available or semaphore is closed.
    ///
    /// # Panics
    ///
    /// Panics if `count` is 0 or greater than `max_permits`.
    pub fn try_acquire(&self, count: usize) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        assert!(count > 0, "cannot acquire 0 permits");
        assert!(
            count <= self.max_permits,
            "cannot acquire more permits than semaphore capacity"
        );

        if self.is_closed() {
            return Err(TryAcquireError);
        }

        loop {
            let available = self.permits.load(Ordering::Acquire);
            if available < count {
                return Err(TryAcquireError);
            }

            if self
                .permits
                .compare_exchange(
                    available,
                    available - count,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(SemaphorePermit {
                    semaphore: self,
                    count,
                });
            }
            // Lost race, retry (loop continues automatically)
        }
    }

    /// Adds permits back to the semaphore.
    ///
    /// This is called by `SemaphorePermit::drop()` to release permits.
    /// Can also be called directly to increase capacity beyond initial.
    ///
    /// # Note
    ///
    /// This can increase permits beyond `max_permits`. Use with caution.
    pub fn add_permits(&self, count: usize) {
        self.permits.fetch_add(count, Ordering::AcqRel);
        // In full implementation: wake waiters
    }
}

/// A permit from a semaphore.
///
/// When dropped, the permit is automatically returned to the semaphore.
/// This implements the two-phase commit pattern:
/// - **Acquire phase**: Wait for and obtain the permit
/// - **Commit phase**: Drop to release (always succeeds)
///
/// The permit acts as an obligation that must be resolved. Dropping the permit
/// is the commit operation that releases the resource back to the semaphore.
#[derive(Debug)]
#[must_use = "permit will be immediately released if not held"]
pub struct SemaphorePermit<'a> {
    semaphore: &'a Semaphore,
    count: usize,
}

impl SemaphorePermit<'_> {
    /// Returns the number of permits held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Forgets the permit without releasing it back to the semaphore.
    ///
    /// This permanently reduces the semaphore's capacity. Useful for
    /// implementing semaphore capacity reduction.
    ///
    /// # Warning
    ///
    /// This will reduce the total available permits. The permits will
    /// never be returned to the semaphore.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        // Return permits to the semaphore
        // This is the "commit" of the two-phase pattern
        self.semaphore.add_permits(self.count);

        // Note: In full implementation with obligation registry:
        // - Look up the obligation by our stored obligation_id
        // - Call obligation.commit() to mark it resolved
        // - This allows the runtime to verify no leaked permits
    }
}

/// An owned permit from a semaphore.
///
/// Unlike `SemaphorePermit`, this owns an `Arc<Semaphore>` and can be
/// moved between tasks. Useful when the permit needs to outlive the
/// scope where it was acquired.
#[derive(Debug)]
#[must_use = "permit will be immediately released if not held"]
pub struct OwnedSemaphorePermit {
    semaphore: std::sync::Arc<Semaphore>,
    count: usize,
}

impl OwnedSemaphorePermit {
    /// Creates an owned permit by acquiring from an Arc-wrapped semaphore.
    ///
    /// # Errors
    ///
    /// Returns an error if the semaphore is closed or acquisition is cancelled.
    pub fn acquire(
        semaphore: std::sync::Arc<Semaphore>,
        cx: &Cx,
        count: usize,
    ) -> Result<Self, AcquireError> {
        let permit = semaphore.acquire(cx, count)?;
        // The acquire succeeded and decremented permits
        // Forget the temporary permit so it doesn't release permits on drop
        // We'll release them when OwnedSemaphorePermit is dropped
        std::mem::forget(permit);
        Ok(Self { semaphore, count })
    }

    /// Tries to acquire an owned permit without waiting.
    ///
    /// # Errors
    ///
    /// Returns an error if permits are not available.
    pub fn try_acquire(
        semaphore: std::sync::Arc<Semaphore>,
        count: usize,
    ) -> Result<Self, TryAcquireError> {
        let permit = semaphore.try_acquire(count)?;
        // Forget the temporary permit so it doesn't release permits on drop
        std::mem::forget(permit);
        Ok(Self { semaphore, count })
    }

    /// Returns the number of permits held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Drop for OwnedSemaphorePermit {
    fn drop(&mut self) {
        self.semaphore.add_permits(self.count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn new_semaphore_has_correct_permits() {
        let sem = Semaphore::new(5);
        assert_eq!(sem.available_permits(), 5);
        assert_eq!(sem.max_permits(), 5);
        assert!(!sem.is_closed());
    }

    #[test]
    fn acquire_decrements_permits() {
        let cx = test_cx();
        let sem = Semaphore::new(5);

        let _permit = sem.acquire(&cx, 2).expect("acquire failed");
        assert_eq!(sem.available_permits(), 3);
    }

    #[test]
    fn drop_releases_permits() {
        let cx = test_cx();
        let sem = Semaphore::new(5);

        {
            let _permit = sem.acquire(&cx, 2).expect("acquire failed");
            assert_eq!(sem.available_permits(), 3);
        }

        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    fn multiple_acquires_exhaust_permits() {
        let cx = test_cx();
        let sem = Semaphore::new(5);

        let p1 = sem.acquire(&cx, 2).expect("acquire 1 failed");
        let p2 = sem.acquire(&cx, 2).expect("acquire 2 failed");
        let p3 = sem.acquire(&cx, 1).expect("acquire 3 failed");

        assert_eq!(sem.available_permits(), 0);

        drop(p1);
        assert_eq!(sem.available_permits(), 2);

        drop(p2);
        assert_eq!(sem.available_permits(), 4);

        drop(p3);
        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    fn try_acquire_success() {
        let sem = Semaphore::new(5);

        let permit = sem.try_acquire(3).expect("try_acquire failed");
        assert_eq!(sem.available_permits(), 2);
        assert_eq!(permit.count(), 3);
    }

    #[test]
    fn try_acquire_failure() {
        // Test trying to acquire more permits than *available* (not more than max)
        let sem = Semaphore::new(5);

        // Acquire 3 permits, leaving 2 available
        let _held = sem.try_acquire(3).expect("initial acquire failed");

        // Now try to acquire 4, but only 2 are available - should fail
        let result = sem.try_acquire(4);
        assert!(result.is_err());
        assert_eq!(sem.available_permits(), 2);
    }

    #[test]
    fn try_acquire_exact_available() {
        let sem = Semaphore::new(5);

        let permit = sem.try_acquire(5).expect("try_acquire failed");
        assert_eq!(sem.available_permits(), 0);
        drop(permit);
        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    fn close_prevents_acquire() {
        let cx = test_cx();
        let sem = Semaphore::new(5);

        sem.close();
        assert!(sem.is_closed());

        let result = sem.acquire(&cx, 1);
        assert!(matches!(result, Err(AcquireError::Closed)));
    }

    #[test]
    fn close_prevents_try_acquire() {
        let sem = Semaphore::new(5);

        sem.close();
        let result = sem.try_acquire(1);
        assert!(result.is_err());
    }

    #[test]
    fn permit_count_is_correct() {
        let cx = test_cx();
        let sem = Semaphore::new(10);

        let permit = sem.acquire(&cx, 3).expect("acquire failed");
        assert_eq!(permit.count(), 3);
    }

    #[test]
    fn forget_does_not_release() {
        let cx = test_cx();
        let sem = Semaphore::new(5);

        let permit = sem.acquire(&cx, 2).expect("acquire failed");
        permit.forget();

        // Permits should not be returned
        assert_eq!(sem.available_permits(), 3);
    }

    #[test]
    fn add_permits_increases_count() {
        let sem = Semaphore::new(5);

        sem.add_permits(3);
        assert_eq!(sem.available_permits(), 8);
    }

    #[test]
    fn waiters_count_accurate() {
        let sem = Semaphore::new(5);
        assert_eq!(sem.waiters(), 0);
    }

    #[test]
    fn cancel_during_acquire() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        // Create semaphore with capacity 1, then acquire it so 0 are available
        let sem = Semaphore::new(1);
        let _held = sem.try_acquire(1).expect("initial acquire failed");

        // Now try to acquire with cancellation requested - should detect cancel during wait
        let result = sem.acquire(&cx, 1);
        assert!(matches!(result, Err(AcquireError::Cancelled)));
    }

    #[test]
    fn owned_permit_acquire() {
        let cx = test_cx();
        let sem = std::sync::Arc::new(Semaphore::new(5));

        let permit = OwnedSemaphorePermit::acquire(sem.clone(), &cx, 2).expect("acquire failed");
        assert_eq!(sem.available_permits(), 3);
        assert_eq!(permit.count(), 2);

        drop(permit);
        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    fn owned_permit_try_acquire() {
        let sem = std::sync::Arc::new(Semaphore::new(5));

        let permit = OwnedSemaphorePermit::try_acquire(sem.clone(), 3).expect("try_acquire failed");
        assert_eq!(sem.available_permits(), 2);

        drop(permit);
        assert_eq!(sem.available_permits(), 5);
    }

    #[test]
    #[should_panic(expected = "cannot acquire 0 permits")]
    fn acquire_zero_panics() {
        let cx = test_cx();
        let sem = Semaphore::new(5);
        let _ = sem.acquire(&cx, 0);
    }

    #[test]
    #[should_panic(expected = "cannot acquire more permits than semaphore capacity")]
    fn acquire_more_than_capacity_panics() {
        let cx = test_cx();
        let sem = Semaphore::new(5);
        let _ = sem.acquire(&cx, 10);
    }

    #[test]
    fn error_display() {
        assert_eq!(AcquireError::Closed.to_string(), "semaphore closed");
        assert_eq!(
            AcquireError::Cancelled.to_string(),
            "semaphore acquire cancelled"
        );
        assert_eq!(
            TryAcquireError.to_string(),
            "no semaphore permits available"
        );
    }
}
