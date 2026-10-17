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
#[derive(Debug, Default)]
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
    /// Deadlines behind the current virtual tick are clamped to `current_tick`
    /// so already-due timers remain observable through `advance_to_next()`.
    ///
    /// Returns a handle that can be used to cancel the timer.
    pub fn insert(&mut self, deadline: u64, waker: Waker) -> VirtualTimerHandle {
        let deadline = deadline.max(self.current_tick);
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
        // Timer IDs are strictly monotonic and unique per timer.
        // A stale handle's timer_id will never match a live timer's timer_id,
        // so it's safe to blindly insert it into the cancelled set without an O(N) search.
        // Stale IDs in the cancelled set are harmless and will be cleaned up in advance_to().
        self.cancelled.insert(handle.timer_id);
    }

    /// Returns the deadline of the next non-cancelled timer, if any.
    #[must_use]
    pub fn next_deadline(&mut self) -> Option<u64> {
        while let Some(top) = self.heap.peek() {
            if self.cancelled.remove(&top.timer_id) {
                self.heap.pop();
            } else {
                return Some(top.deadline);
            }
        }
        None
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

            let Some(timer) = self.heap.pop() else {
                break;
            };

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

        // Clean up cancelled set only when it grows large relative to heap size
        // This avoids O(k) cleanup overhead on every advance_to() call
        if self.cancelled.len() > self.heap.len() / 4 || self.cancelled.len() > 1000 {
            self.cleanup_cancelled();
        }

        // Sort by deadline first, then by timer_id for determinism
        expired.sort_by(|a, b| {
            a.deadline
                .cmp(&b.deadline)
                .then_with(|| a.timer_id.cmp(&b.timer_id))
        });

        expired
    }

    /// Removes stale entries from the `cancelled` set.
    ///
    /// br-asupersync-i81jcd: prior shape was
    /// `if self.cancelled.len() > self.heap.len() { rebuild }`.
    /// That trigger only fires when cancellations have accumulated to
    /// MORE entries than the heap holds — the adversarial pattern of
    /// flooding cancel() with stale handles. In normal use, cancelled
    /// IDs that correspond to live heap entries are removed during the
    /// `advance_to` expiration loop (line ~263), so the set self-cleans
    /// IFF the timer's deadline has passed. A long-running wheel that
    /// keeps inserting AND cancelling stale handles for prior-iteration
    /// timers (whose heap entries were already popped on earlier advances)
    /// can grow `cancelled` linearly while staying just below heap.len —
    /// the threshold never trips, the set leaks unboundedly.
    ///
    /// The replacement always rebuilds when `cancelled` is non-empty
    /// (early-exit on empty avoids the O(heap.len) walk on hot paths
    /// where no cancellation has occurred). Cost is bounded by
    /// O(heap.len + cancelled.len) per `advance_to`, which is acceptable
    /// for lab/test workloads. The previous adversarial-trip semantics
    /// are preserved as a special case (when stale entries dominate, the
    /// rebuild is the same operation).
    fn cleanup_cancelled(&mut self) {
        if self.cancelled.is_empty() {
            return;
        }

        // heap.retain() does a full O(N) scan of the underlying vector and rebuilds the heap.
        // There is no benefit to doing this "incrementally", so we remove all cancelled
        // timers in one pass. By doing so, we guarantee there are no cancelled timers
        // left in the heap, which means we can safely clear the entire `cancelled` set
        // (including any stale IDs from timers that were already popped).
        self.heap
            .retain(|timer| !self.cancelled.contains(&timer.timer_id));
        self.cancelled.clear();
    }

    /// Returns wakers for all expired timers without removing them from tracking.
    ///
    /// This is useful for waking tasks without modifying timer state.
    #[must_use]
    pub fn collect_wakers(&self, up_to_tick: u64) -> Vec<Waker> {
        let mut ready: Vec<_> = self
            .heap
            .iter()
            .filter(|t| t.deadline <= up_to_tick && !self.cancelled.contains(&t.timer_id))
            .collect();
        ready.sort_by(|a, b| {
            a.deadline
                .cmp(&b.deadline)
                .then_with(|| a.timer_id.cmp(&b.timer_id))
        });
        ready.into_iter().map(|t| t.waker.clone()).collect()
    }

    /// Clears all timers.
    pub fn clear(&mut self) {
        self.heap.clear();
        self.cancelled.clear();
    }
}

#[cfg(test)]
#[path = "virtual_time_wheel_inline_tests.rs"]
mod tests;
