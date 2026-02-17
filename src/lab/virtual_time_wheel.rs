//! Virtual time wheel for deterministic Lab runtime.
//!
//! This module provides a timer wheel implementation that operates on virtual
//! time (ticks) rather than wall-clock time. It enables deterministic testing
//! by ensuring:
//!
//! - Same tick → same timers expire
//! - Expiration order is deterministic (sorted by timer ID)
//! - No wall-clock dependencies
//!
//! # Example
//!
//! ```ignore
//! use asupersync::lab::VirtualTimerWheel;
//! use std::task::Waker;
//!
//! let mut wheel = VirtualTimerWheel::new();
//!
//! // Register timers at various deadlines
//! wheel.insert(100, waker1);  // fires at tick 100
//! wheel.insert(50, waker2);   // fires at tick 50
//!
//! // Advance to next deadline (tick 50)
//! let expired = wheel.advance_to_next();
//! assert_eq!(expired.len(), 1);  // waker2 expired
//!
//! // Advance by a specific amount
//! let expired = wheel.advance_by(60);  // now at tick 110
//! assert_eq!(expired.len(), 1);  // waker1 expired
//! ```

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::task::Waker;

/// A timer entry in the virtual wheel.
#[derive(Debug)]
struct VirtualTimer {
    /// Deadline in virtual ticks.
    deadline: u64,
    /// Unique timer ID for deterministic ordering.
    timer_id: u64,
    /// Waker to call when the timer expires.
    waker: Waker,
}

impl Eq for VirtualTimer {}

impl PartialEq for VirtualTimer {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.timer_id == other.timer_id
    }
}

impl Ord for VirtualTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap ordering: earliest deadline first, then lowest timer_id
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.timer_id.cmp(&self.timer_id))
    }
}

impl PartialOrd for VirtualTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A timer handle for cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualTimerHandle {
    /// Timer ID.
    timer_id: u64,
    /// Deadline when created (for validation).
    deadline: u64,
}

impl VirtualTimerHandle {
    /// Returns the timer ID.
    #[must_use]
    pub const fn timer_id(&self) -> u64 {
        self.timer_id
    }

    /// Returns the deadline tick.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }
}

/// Expired timer info returned when advancing time.
#[derive(Debug)]
pub struct ExpiredTimer {
    /// Timer ID (for deterministic ordering).
    pub timer_id: u64,
    /// Deadline tick when the timer was set to expire.
    pub deadline: u64,
    /// Waker to wake the waiting task.
    pub waker: Waker,
}

/// Virtual time wheel for the Lab runtime.
///
/// This wheel operates on virtual ticks rather than wall-clock time,
/// enabling deterministic testing of time-dependent code.
///
/// # Determinism Guarantees
///
/// - Same tick → same timers expire (deadlines are stored as u64 ticks)
/// - Expiration order is deterministic (sorted by timer ID within same tick)
/// - No wall-clock dependencies (uses heap for simplicity and correctness)
#[derive(Debug)]
pub struct VirtualTimerWheel {
    /// Min-heap of pending timers, ordered by deadline then timer_id.
    heap: BinaryHeap<VirtualTimer>,
    /// Current virtual time in ticks.
    current_tick: u64,
    /// Next timer ID to assign.
    next_timer_id: u64,
    /// Cancelled timer IDs (for lazy cancellation).
    cancelled: std::collections::BTreeSet<u64>,
}

impl Default for VirtualTimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualTimerWheel {
    /// Creates a new virtual timer wheel starting at tick 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            current_tick: 0,
            next_timer_id: 0,
            cancelled: std::collections::BTreeSet::new(),
        }
    }

    /// Creates a virtual timer wheel starting at the given tick.
    #[must_use]
    pub fn starting_at(tick: u64) -> Self {
        Self {
            heap: BinaryHeap::new(),
            current_tick: tick,
            next_timer_id: 0,
            cancelled: std::collections::BTreeSet::new(),
        }
    }

    /// Returns the current virtual time in ticks.
    #[must_use]
    pub const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Returns the exact number of pending (non-cancelled) timers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending_count()
    }

    /// Returns true if there are no pending timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending_count() == 0
    }

    /// Returns the actual count of pending timers (excluding cancelled).
    fn pending_count(&self) -> usize {
        self.heap
            .iter()
            .filter(|t| !self.cancelled.contains(&t.timer_id))
            .count()
    }

    /// Inserts a timer to fire at the given deadline tick.
    ///
    /// Returns a handle that can be used to cancel the timer.
    pub fn insert(&mut self, deadline: u64, waker: Waker) -> VirtualTimerHandle {
        let timer_id = self.next_timer_id;
        self.next_timer_id = self
            .next_timer_id
            .checked_add(1)
            .expect("virtual timer ID space exhausted");

        self.heap.push(VirtualTimer {
            deadline,
            timer_id,
            waker,
        });

        VirtualTimerHandle { timer_id, deadline }
    }

    /// Cancels a timer by its handle.
    ///
    /// Uses lazy cancellation - the timer is marked as cancelled and will
    /// be skipped when its deadline is reached.
    pub fn cancel(&mut self, handle: VirtualTimerHandle) {
        // Guard against stale handles so live timers are never hidden from len()/is_empty().
        let still_pending = self
            .heap
            .iter()
            .any(|timer| timer.timer_id == handle.timer_id && timer.deadline == handle.deadline);
        if still_pending {
            self.cancelled.insert(handle.timer_id);
        } else {
            self.cancelled.remove(&handle.timer_id);
        }
    }

    /// Returns the deadline of the next non-cancelled timer, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        // Find the first non-cancelled timer
        self.heap
            .iter()
            .filter(|t| !self.cancelled.contains(&t.timer_id))
            .map(|t| t.deadline)
            .min()
    }

    /// Advances virtual time to the next timer deadline.
    ///
    /// Returns the list of expired timers in deterministic order (by timer_id).
    /// If there are no pending timers, returns an empty list and does not
    /// advance time.
    pub fn advance_to_next(&mut self) -> Vec<ExpiredTimer> {
        self.next_deadline()
            .map_or_else(Vec::new, |deadline| self.advance_to(deadline))
    }

    /// Advances virtual time by the given number of ticks.
    ///
    /// Returns all expired timers in deterministic order (by timer_id).
    pub fn advance_by(&mut self, ticks: u64) -> Vec<ExpiredTimer> {
        self.advance_to(self.current_tick.saturating_add(ticks))
    }

    /// Advances to the given absolute tick, processing all timers up to that point.
    ///
    /// Returns all expired timers in deterministic order (sorted by deadline,
    /// then by timer_id within each deadline).
    pub fn advance_to(&mut self, target_tick: u64) -> Vec<ExpiredTimer> {
        if target_tick < self.current_tick {
            return Vec::new();
        }

        let mut expired = Vec::new();

        // Pop all timers with deadline <= target_tick
        while let Some(timer) = self.heap.peek() {
            if timer.deadline > target_tick {
                break;
            }

            let timer = self.heap.pop().unwrap();

            // Skip cancelled timers
            if self.cancelled.remove(&timer.timer_id) {
                continue;
            }

            expired.push(ExpiredTimer {
                timer_id: timer.timer_id,
                deadline: timer.deadline,
                waker: timer.waker,
            });
        }

        self.current_tick = target_tick;

        // Clean up cancelled set (remove any IDs that aren't in the heap anymore)
        self.cleanup_cancelled();

        // Sort by deadline first, then by timer_id for determinism
        expired.sort_by(|a, b| {
            a.deadline
                .cmp(&b.deadline)
                .then_with(|| a.timer_id.cmp(&b.timer_id))
        });

        expired
    }

    /// Removes stale entries from the cancelled set.
    fn cleanup_cancelled(&mut self) {
        if self.cancelled.len() > self.heap.len() {
            // More cancelled IDs than heap entries - rebuild the set
            let heap_ids: std::collections::BTreeSet<_> =
                self.heap.iter().map(|t| t.timer_id).collect();
            self.cancelled.retain(|id| heap_ids.contains(id));
        }
    }

    /// Returns wakers for all expired timers without removing them from tracking.
    ///
    /// This is useful for waking tasks without modifying timer state.
    #[must_use]
    pub fn collect_wakers(&self, up_to_tick: u64) -> Vec<Waker> {
        self.heap
            .iter()
            .filter(|t| t.deadline <= up_to_tick && !self.cancelled.contains(&t.timer_id))
            .map(|t| t.waker.clone())
            .collect()
    }

    /// Clears all timers.
    pub fn clear(&mut self) {
        self.heap.clear();
        self.cancelled.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::Wake;

    /// A waker that counts how many times it has been woken.
    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Create a counting waker for tests.
    fn counting_waker() -> (Arc<CountingWaker>, Waker) {
        let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        (counter, waker)
    }

    #[test]
    fn new_wheel_starts_at_zero() {
        let wheel = VirtualTimerWheel::new();
        assert_eq!(wheel.current_tick(), 0);
        assert!(wheel.is_empty());
    }

    #[test]
    fn starting_at_custom_tick() {
        let wheel = VirtualTimerWheel::starting_at(1000);
        assert_eq!(wheel.current_tick(), 1000);
    }

    #[test]
    fn insert_and_advance_to() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(50, waker2);
        wheel.insert(200, waker3);

        // Advance to tick 75 - should expire the timer at 50
        let expired = wheel.advance_to(75);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 50);
        assert_eq!(wheel.current_tick(), 75);

        // Advance to tick 150 - should expire the timer at 100
        let expired = wheel.advance_to(150);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);

        // Advance to tick 250 - should expire the timer at 200
        let expired = wheel.advance_to(250);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 200);

        assert!(wheel.is_empty());
    }

    #[test]
    fn advance_to_next() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(50, waker2);

        // Should advance to 50 and expire that timer
        let expired = wheel.advance_to_next();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 50);
        assert_eq!(wheel.current_tick(), 50);

        // Should advance to 100
        let expired = wheel.advance_to_next();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(wheel.current_tick(), 100);

        // No more timers
        let expired = wheel.advance_to_next();
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick(), 100); // unchanged
    }

    #[test]
    fn advance_by() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(50, waker2);

        // Advance by 75 ticks
        let expired = wheel.advance_by(75);
        assert_eq!(expired.len(), 1);
        assert_eq!(wheel.current_tick(), 75);

        // Advance by another 50 ticks
        let expired = wheel.advance_by(50);
        assert_eq!(expired.len(), 1);
        assert_eq!(wheel.current_tick(), 125);
    }

    #[test]
    fn deterministic_ordering_by_timer_id() {
        let mut wheel = VirtualTimerWheel::new();

        // Insert multiple timers at the same deadline
        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        let h1 = wheel.insert(100, waker1);
        let h2 = wheel.insert(100, waker2);
        let h3 = wheel.insert(100, waker3);

        let expired = wheel.advance_to(100);
        assert_eq!(expired.len(), 3);

        // Should be sorted by timer_id
        assert_eq!(expired[0].timer_id, h1.timer_id());
        assert_eq!(expired[1].timer_id, h2.timer_id());
        assert_eq!(expired[2].timer_id, h3.timer_id());
    }

    #[test]
    fn cancel_timer() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let h1 = wheel.insert(100, waker1);
        let h2 = wheel.insert(100, waker2);

        // Cancel the first timer
        wheel.cancel(h1);

        let expired = wheel.advance_to(100);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_id, h2.timer_id());
    }

    #[test]
    fn stale_cancel_handle_does_not_hide_pending_timers() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, stale_waker) = counting_waker();
        let stale_handle = wheel.insert(10, stale_waker);
        let expired = wheel.advance_to(10);
        assert_eq!(expired.len(), 1);

        let (_, live_waker) = counting_waker();
        let live_handle = wheel.insert(20, live_waker);

        // Cancelling an already-expired handle should not affect live timers.
        wheel.cancel(stale_handle);
        assert_eq!(wheel.len(), 1);
        assert!(!wheel.is_empty());
        assert_eq!(wheel.next_deadline(), Some(20));

        let expired = wheel.advance_to(20);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_id, live_handle.timer_id());
    }

    #[test]
    fn next_deadline_skips_cancelled() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let h1 = wheel.insert(50, waker1);
        wheel.insert(100, waker2);

        // Cancel the earlier timer
        wheel.cancel(h1);

        // Next deadline should be 100, not 50
        assert_eq!(wheel.next_deadline(), Some(100));
    }

    #[test]
    fn determinism_across_runs() {
        fn run_test(seed: u64) -> Vec<u64> {
            let mut wheel = VirtualTimerWheel::starting_at(seed);

            // Insert timers in a "random" order based on seed
            let deadlines = [
                seed.wrapping_mul(7) % 1000,
                seed.wrapping_mul(13) % 1000,
                seed.wrapping_mul(17) % 1000,
            ];

            for deadline in deadlines {
                let (_, waker) = counting_waker();
                wheel.insert(seed + deadline, waker);
            }

            // Advance to end and collect order
            let expired = wheel.advance_to(seed + 1000);
            expired.iter().map(|e| e.timer_id).collect()
        }

        // Same seed should produce same order
        let order1 = run_test(42);
        let order2 = run_test(42);
        assert_eq!(order1, order2, "Same seed should produce same order");

        // Different seeds should work correctly too
        let order3 = run_test(123);
        assert_eq!(order3.len(), 3);
    }

    #[test]
    fn advance_to_past_is_noop() {
        let mut wheel = VirtualTimerWheel::starting_at(100);
        let expired = wheel.advance_to(50);
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick(), 100);
    }

    #[test]
    fn advance_to_current_tick_fires_due_timers() {
        let mut wheel = VirtualTimerWheel::starting_at(100);
        let (_, waker) = counting_waker();
        wheel.insert(100, waker);

        let expired = wheel.advance_to(100);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(wheel.current_tick(), 100);
    }

    #[test]
    fn large_time_jump() {
        let mut wheel = VirtualTimerWheel::new();

        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        wheel.insert(100, waker1);
        wheel.insert(1000, waker2);
        wheel.insert(1_000_000, waker3);

        // Jump far into the future
        let expired = wheel.advance_to(2_000_000);
        assert_eq!(expired.len(), 3);

        // Should be in deadline order
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(expired[1].deadline, 1000);
        assert_eq!(expired[2].deadline, 1_000_000);
    }

    #[test]
    fn mixed_deadlines_ordering() {
        let mut wheel = VirtualTimerWheel::new();

        // Insert timers with mixed deadlines
        let (_, waker1) = counting_waker();
        let (_, waker2) = counting_waker();
        let (_, waker3) = counting_waker();
        let (_, waker4) = counting_waker();
        wheel.insert(200, waker1); // id=0
        wheel.insert(100, waker2); // id=1
        wheel.insert(100, waker3); // id=2
        wheel.insert(200, waker4); // id=3

        let expired = wheel.advance_to(300);
        assert_eq!(expired.len(), 4);

        // First the 100 deadline timers (sorted by id)
        assert_eq!(expired[0].deadline, 100);
        assert_eq!(expired[0].timer_id, 1);
        assert_eq!(expired[1].deadline, 100);
        assert_eq!(expired[1].timer_id, 2);

        // Then the 200 deadline timers (sorted by id)
        assert_eq!(expired[2].deadline, 200);
        assert_eq!(expired[2].timer_id, 0);
        assert_eq!(expired[3].deadline, 200);
        assert_eq!(expired[3].timer_id, 3);
    }
}
