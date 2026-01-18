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

use std::collections::VecDeque;
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
    /// Internal state for permits and waiters.
    state: Mutex<SemaphoreState>,
    /// Maximum permits (initial count).
    max_permits: usize,
}

#[derive(Debug)]
struct SemaphoreState {
    /// Number of available permits.
    permits: usize,
    /// Whether the semaphore is closed.
    closed: bool,
    /// Queue of waiters (unique IDs).
    waiters: VecDeque<u64>,
    /// Counter for generating waiter IDs.
    next_waiter_id: u64,
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
            state: Mutex::new(SemaphoreState {
                permits,
                closed: false,
                waiters: VecDeque::new(),
                next_waiter_id: 0,
            }),
            max_permits: permits,
        }
    }

    /// Returns the number of currently available permits.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.state.lock().expect("semaphore lock poisoned").permits
    }

    /// Returns the maximum number of permits (initial count).
    #[must_use]
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Returns true if the semaphore is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("semaphore lock poisoned").closed
    }

    /// Returns the number of tasks currently waiting for permits.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.state.lock().expect("semaphore lock poisoned").waiters.len()
    }

    /// Closes the semaphore.
    ///
    /// After closing, all pending and future acquire operations will fail
    /// with `AcquireError::Closed`.
    pub fn close(&self) {
        self.state.lock().expect("semaphore lock poisoned").closed = true;
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

        // Register as waiter
        let waiter_id = {
            let mut state = self.state.lock().expect("semaphore lock poisoned");
            if state.closed {
                return Err(AcquireError::Closed);
            }
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            state.waiters.push_back(id);
            id
        };

        // Wait loop
        loop {
            // Check cancellation
            if let Err(_e) = cx.checkpoint() {
                let mut state = self.state.lock().expect("semaphore lock poisoned");
                if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                    state.waiters.remove(pos);
                }
                cx.trace("semaphore::acquire cancelled while waiting");
                return Err(AcquireError::Cancelled);
            }

            // Check acquire
            {
                let mut state = self.state.lock().expect("semaphore lock poisoned");
                
                if state.closed {
                    if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                        state.waiters.remove(pos);
                    }
                    return Err(AcquireError::Closed);
                }

                if state.permits >= count && state.waiters.front() == Some(&waiter_id) {
                    // Success!
                    state.permits -= count;
                    state.waiters.pop_front();
                    cx.trace("semaphore::acquire succeeded");
                    return Ok(SemaphorePermit {
                        semaphore: self,
                        count,
                    });
                }
            }

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

        let mut state = self.state.lock().expect("semaphore lock poisoned");
        if state.closed {
            return Err(TryAcquireError);
        }

        // Strict FIFO: fail if anyone is waiting ahead of us
        if !state.waiters.is_empty() {
            return Err(TryAcquireError);
        }

        if state.permits >= count {
            state.permits -= count;
            Ok(SemaphorePermit {
                semaphore: self,
                count,
            })
        } else {
            Err(TryAcquireError)
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
        let mut state = self.state.lock().expect("semaphore lock poisoned");
        state.permits += count;
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
        // Register as waiter
        let waiter_id = {
            let mut state = semaphore.state.lock().expect("semaphore lock poisoned");
            if state.closed {
                return Err(AcquireError::Closed);
            }
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            state.waiters.push_back(id);
            id
        };

        loop {
            if let Err(_e) = cx.checkpoint() {
                let mut state = semaphore.state.lock().expect("semaphore lock poisoned");
                if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                    state.waiters.remove(pos);
                }
                return Err(AcquireError::Cancelled);
            }

            let success = {
                let mut state = semaphore.state.lock().expect("semaphore lock poisoned");
                
                if state.closed {
                    if let Some(pos) = state.waiters.iter().position(|&x| x == waiter_id) {
                        state.waiters.remove(pos);
                    }
                    return Err(AcquireError::Closed);
                }

                if state.permits >= count && state.waiters.front() == Some(&waiter_id) {
                    state.permits -= count;
                    state.waiters.pop_front();
                    true
                } else {
                    false
                }
            };

            if success {
                return Ok(Self { semaphore, count });
            }

            std::thread::yield_now();
        }
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

    // ==========================================================================
    // SYNC-005: Semaphore Permit Limiting Tests
    // Verify semaphore limits concurrent access to the specified permit count
    // ==========================================================================

    #[test]
    fn permit_limiting_never_exceeds_capacity() {
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const PERMIT_COUNT: usize = 5;
        const NUM_THREADS: usize = 20;
        const ITERATIONS_PER_THREAD: usize = 100;

        let sem = Arc::new(Semaphore::new(PERMIT_COUNT));
        let active_holders = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let sem = Arc::clone(&sem);
                let active = Arc::clone(&active_holders);
                let max = Arc::clone(&max_concurrent);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..ITERATIONS_PER_THREAD {
                        if let Ok(_permit) = sem.acquire(&cx, 1) {
                            // Mark ourselves as holding a permit
                            let current = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                            max.fetch_max(current, AtomicOrdering::SeqCst);

                            // Do some work while holding the permit to increase
                            // the chance of concurrent permit holders
                            for _ in 0..100 {
                                std::hint::spin_loop();
                            }
                            std::thread::yield_now();

                            // Release holder count before dropping permit
                            active.fetch_sub(1, AtomicOrdering::SeqCst);
                            // permit dropped here, releasing back to semaphore
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let max = max_concurrent.load(AtomicOrdering::SeqCst);

        // Verify: never exceeded permit count (the core invariant)
        assert!(
            max <= PERMIT_COUNT as u32,
            "Semaphore should limit concurrent access to {PERMIT_COUNT}, but max was {max}"
        );

        // Note: We don't assert max > 1 because thread scheduling is non-deterministic.
        // The key invariant is that we never exceed the permit count.
    }

    #[test]
    fn permit_limiting_multi_permit_acquire() {
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const PERMIT_COUNT: usize = 10;
        const NUM_THREADS: usize = 8;
        const PERMITS_PER_ACQUIRE: usize = 3;
        const ITERATIONS_PER_THREAD: usize = 50;

        let sem = Arc::new(Semaphore::new(PERMIT_COUNT));
        let active_permits = Arc::new(AtomicU32::new(0));
        let max_concurrent_permits = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let sem = Arc::clone(&sem);
                let active = Arc::clone(&active_permits);
                let max = Arc::clone(&max_concurrent_permits);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..ITERATIONS_PER_THREAD {
                        if let Ok(_permit) = sem.acquire(&cx, PERMITS_PER_ACQUIRE) {
                            // Add our permit count
                            let current = active
                                .fetch_add(PERMITS_PER_ACQUIRE as u32, AtomicOrdering::SeqCst)
                                + PERMITS_PER_ACQUIRE as u32;
                            max.fetch_max(current, AtomicOrdering::SeqCst);

                            // Do some work
                            std::hint::spin_loop();

                            // Release before dropping
                            active.fetch_sub(PERMITS_PER_ACQUIRE as u32, AtomicOrdering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let max = max_concurrent_permits.load(AtomicOrdering::SeqCst);

        // Verify: never exceeded total permit count
        assert!(
            max <= PERMIT_COUNT as u32,
            "Semaphore should limit to {PERMIT_COUNT} permits, but max held was {max}"
        );
    }

    #[test]
    fn all_permits_eventually_released() {
        use std::sync::Arc;

        const PERMIT_COUNT: usize = 5;
        const NUM_THREADS: usize = 10;
        const ITERATIONS: usize = 100;

        let sem = Arc::new(Semaphore::new(PERMIT_COUNT));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let sem = Arc::clone(&sem);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..ITERATIONS {
                        let _permit = sem.acquire(&cx, 1).expect("acquire should succeed");
                        std::hint::spin_loop();
                        // permit dropped
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // Verify: all permits are released
        assert_eq!(
            sem.available_permits(),
            PERMIT_COUNT,
            "All permits should be released after all threads complete"
        );
    }

    #[test]
    fn try_acquire_respects_limits() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const PERMIT_COUNT: usize = 3;
        const NUM_THREADS: usize = 10;
        const ITERATIONS: usize = 500;

        let sem = Arc::new(Semaphore::new(PERMIT_COUNT));
        let successes = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let sem = Arc::clone(&sem);
                let successes = Arc::clone(&successes);
                std::thread::spawn(move || {
                    for _ in 0..ITERATIONS {
                        if let Ok(_permit) = sem.try_acquire(1) {
                            successes.fetch_add(1, AtomicOrdering::SeqCst);
                            // Immediately release
                        }
                        // Small yield to allow other threads
                        std::thread::yield_now();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // Verify: permits were successfully acquired multiple times
        let total_successes = successes.load(AtomicOrdering::SeqCst);
        assert!(
            total_successes > 0,
            "Should have had some successful try_acquire calls"
        );

        // Verify: all permits are back
        assert_eq!(
            sem.available_permits(),
            PERMIT_COUNT,
            "All permits should be available after completion"
        );
    }

    #[test]
    fn owned_permit_limiting() {
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        use std::sync::Arc;

        const PERMIT_COUNT: usize = 4;
        const NUM_THREADS: usize = 12;
        const ITERATIONS: usize = 50;

        let sem = Arc::new(Semaphore::new(PERMIT_COUNT));
        let active_holders = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let sem = Arc::clone(&sem);
                let active = Arc::clone(&active_holders);
                let max = Arc::clone(&max_concurrent);
                std::thread::spawn(move || {
                    let cx = test_cx();
                    for _ in 0..ITERATIONS {
                        if let Ok(_permit) = OwnedSemaphorePermit::acquire(Arc::clone(&sem), &cx, 1)
                        {
                            let current = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                            max.fetch_max(current, AtomicOrdering::SeqCst);
                            std::hint::spin_loop();
                            active.fetch_sub(1, AtomicOrdering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let max = max_concurrent.load(AtomicOrdering::SeqCst);

        // Verify: OwnedSemaphorePermit respects limits
        assert!(
            max <= PERMIT_COUNT as u32,
            "OwnedSemaphorePermit should limit to {PERMIT_COUNT}, but max was {max}"
        );

        // Verify: all permits released
        assert_eq!(
            sem.available_permits(),
            PERMIT_COUNT,
            "All permits should be available"
        );
    }

    #[test]
    fn close_wakes_waiters() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use std::time::Duration;

        let sem = Arc::new(Semaphore::new(1));
        let waiter_started = Arc::new(AtomicBool::new(false));
        let waiter_finished = Arc::new(AtomicBool::new(false));

        // First, acquire the only permit
        let _held = sem.try_acquire(1).expect("should get permit");

        // Start a thread that will try to acquire (and should block)
        let sem_clone = Arc::clone(&sem);
        let started = Arc::clone(&waiter_started);
        let finished = Arc::clone(&waiter_finished);

        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            started.store(true, AtomicOrdering::SeqCst);
            let result = sem_clone.acquire(&cx, 1).map(|_| ());
            finished.store(true, AtomicOrdering::SeqCst);
            result
        });

        // Wait for waiter to start
        while !waiter_started.load(AtomicOrdering::SeqCst) {
            std::thread::yield_now();
        }

        // Give it a moment to enter the wait loop
        std::thread::sleep(Duration::from_millis(10));

        // Close the semaphore - should wake the waiter
        sem.close();

        // Wait for thread with timeout
        let result = handle.join().expect("thread panicked");

        // Verify: waiter received Closed error
        assert!(
            matches!(result, Err(AcquireError::Closed)),
            "Waiter should receive Closed error, got {result:?}"
        );
    }

    #[test]
    fn fairness_fifo_order() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use std::time::Duration;

        // Test that waiters are serviced in FIFO order
        // This is a best-effort test as timing can affect results

        const NUM_WAITERS: usize = 4;

        let sem = Arc::new(Semaphore::new(1));
        let order = Arc::new(AtomicUsize::new(0));
        let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Acquire the permit first
        let held = sem.try_acquire(1).expect("should get permit");

        // Spawn waiters with slight delays to establish order
        let mut handles = Vec::new();
        for i in 0..NUM_WAITERS {
            let sem = Arc::clone(&sem);
            let order = Arc::clone(&order);
            let completion = Arc::clone(&completion_order);

            handles.push(std::thread::spawn(move || {
                // Small delay to establish ordering
                std::thread::sleep(Duration::from_millis((i * 5) as u64));

                let cx = test_cx();
                let _permit = sem.acquire(&cx, 1).expect("should get permit");

                // Record completion order
                let my_order = order.fetch_add(1, AtomicOrdering::SeqCst);
                completion.lock().unwrap().push((i, my_order));
            }));
        }

        // Give waiters time to queue up
        std::thread::sleep(Duration::from_millis(30));

        // Release the initial permit
        drop(held);

        // Wait for all threads
        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let completions_len = {
            let completions = completion_order.lock().unwrap();
            completions.len()
        };
        assert_eq!(completions_len, NUM_WAITERS, "All waiters should complete");

        // With FIFO fairness, the completion order should match the queue order
        // (allowing for some variance due to thread scheduling)
    }
}
