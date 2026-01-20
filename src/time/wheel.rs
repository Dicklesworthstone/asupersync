//! Hierarchical timing wheel for efficient timer management.
//!
//! The wheel stores timers in multiple levels of buckets with increasing
//! resolution. Timers are inserted into the coarsest level that can represent
//! their deadline relative to the current time. As time advances, buckets are
//! cascaded down to finer levels until they fire.

use crate::types::Time;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::task::Waker;

const LEVEL_COUNT: usize = 4;
const SLOTS_PER_LEVEL: usize = 256;
const LEVEL0_RESOLUTION_NS: u64 = 1_000_000; // 1ms

const LEVEL_RESOLUTIONS_NS: [u64; LEVEL_COUNT] = [
    LEVEL0_RESOLUTION_NS,
    LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64,
    LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64 * SLOTS_PER_LEVEL as u64,
    LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64 * SLOTS_PER_LEVEL as u64 * SLOTS_PER_LEVEL as u64,
];

/// Opaque handle for a scheduled timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle {
    id: u64,
    generation: u64,
}

impl TimerHandle {
    /// Returns the timer identifier.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the generation associated with this handle.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone)]
struct TimerEntry {
    deadline: Time,
    waker: Waker,
    id: u64,
    generation: u64,
}

#[derive(Debug)]
struct OverflowEntry {
    deadline: Time,
    entry: TimerEntry,
}

impl PartialEq for OverflowEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for OverflowEntry {}

impl PartialOrd for OverflowEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OverflowEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap (earliest deadline first)
        other.deadline.cmp(&self.deadline)
    }
}

#[derive(Debug)]
struct WheelLevel {
    slots: Vec<Vec<TimerEntry>>,
    resolution_ns: u64,
    cursor: usize,
}

impl WheelLevel {
    fn new(resolution_ns: u64, cursor: usize) -> Self {
        Self {
            slots: vec![Vec::new(); SLOTS_PER_LEVEL],
            resolution_ns,
            cursor,
        }
    }

    fn range_ns(&self) -> u64 {
        self.resolution_ns.saturating_mul(SLOTS_PER_LEVEL as u64)
    }
}

/// Hierarchical timing wheel for timers.
#[derive(Debug)]
pub(super) struct TimerWheel {
    current_tick: u64,
    levels: [WheelLevel; LEVEL_COUNT],
    overflow: BinaryHeap<OverflowEntry>,
    ready: Vec<TimerEntry>,
    next_id: u64,
    next_generation: u64,
    active: HashMap<u64, u64>,
}

impl TimerWheel {
    /// Creates a new timer wheel starting at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self::new_at(Time::ZERO)
    }

    /// Creates a new timer wheel starting at the given time.
    #[must_use]
    pub fn new_at(now: Time) -> Self {
        let now_nanos = now.as_nanos();
        let current_tick = now_nanos / LEVEL0_RESOLUTION_NS;
        let levels = std::array::from_fn(|idx| {
            let resolution_ns = LEVEL_RESOLUTIONS_NS[idx];
            let cursor = ((now_nanos / resolution_ns) % SLOTS_PER_LEVEL as u64) as usize;
            WheelLevel::new(resolution_ns, cursor)
        });

        Self {
            current_tick,
            levels,
            overflow: BinaryHeap::new(),
            ready: Vec::new(),
            next_id: 0,
            next_generation: 0,
            active: HashMap::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.active.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    pub fn clear(&mut self) {
        self.active.clear();
        self.ready.clear();
        self.overflow.clear();
        for level in &mut self.levels {
            for slot in &mut level.slots {
                slot.clear();
            }
        }
    }

    /// Returns the current time aligned to the wheel resolution.
    #[must_use]
    pub fn current_time(&self) -> Time {
        Time::from_nanos(self.current_tick.saturating_mul(LEVEL0_RESOLUTION_NS))
    }

    /// Registers a timer that fires at the given deadline.
    pub fn register(&mut self, deadline: Time, waker: Waker) -> TimerHandle {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);

        self.active.insert(id, generation);

        let entry = TimerEntry {
            deadline,
            waker,
            id,
            generation,
        };

        self.insert_entry(entry);

        TimerHandle { id, generation }
    }

    /// Cancels a timer by handle.
    ///
    /// Returns true if the timer was active and is now cancelled.
    pub fn cancel(&mut self, handle: &TimerHandle) -> bool {
        match self.active.get(&handle.id) {
            Some(generation) if *generation == handle.generation => {
                self.active.remove(&handle.id);
                true
            }
            _ => false,
        }
    }

    /// Returns the earliest pending deadline, if any.
    #[must_use]
    pub fn next_deadline(&mut self) -> Option<Time> {
        if self.ready.iter().any(|entry| self.is_live(entry)) {
            return Some(self.current_time());
        }

        let mut min_deadline: Option<Time> = None;

        for entry in &self.ready {
            if !self.is_live(entry) {
                continue;
            }
            min_deadline =
                Some(min_deadline.map_or(entry.deadline, |current| current.min(entry.deadline)));
        }

        for level in &self.levels {
            for slot in &level.slots {
                for entry in slot {
                    if !self.is_live(entry) {
                        continue;
                    }
                    min_deadline = Some(
                        min_deadline.map_or(entry.deadline, |current| current.min(entry.deadline)),
                    );
                }
            }
        }

        while let Some(entry) = self.overflow.peek() {
            if self.is_live(&entry.entry) {
                min_deadline = Some(
                    min_deadline.map_or(entry.deadline, |current| current.min(entry.deadline)),
                );
                break;
            }
            let _ = self.overflow.pop();
        }

        min_deadline
    }

    /// Advances time and returns expired timer wakers.
    pub fn collect_expired(&mut self, now: Time) -> Vec<Waker> {
        let now_nanos = now.as_nanos();
        let target_tick = now_nanos / LEVEL0_RESOLUTION_NS;

        if target_tick > self.current_tick {
            self.advance_to(target_tick);
        }

        self.drain_ready(now)
    }

    fn insert_entry(&mut self, entry: TimerEntry) {
        let current = self.current_time();
        if entry.deadline <= current {
            self.ready.push(entry);
            return;
        }

        let delta = entry.deadline.as_nanos().saturating_sub(current.as_nanos());
        for (idx, level) in self.levels.iter_mut().enumerate() {
            if delta < level.range_ns() {
                let tick = entry.deadline.as_nanos() / level.resolution_ns;

                // For Level 0, if the calculated tick matches the current tick (or is older),
                // it means the deadline is within the current millisecond window.
                // We treat this as ready because slot 'current % 256' has already been processed/passed.
                if idx == 0 {
                    let current_tick_l0 = current.as_nanos() / level.resolution_ns;
                    if tick <= current_tick_l0 {
                        self.ready.push(entry);
                        return;
                    }
                }

                let slot = (tick as usize) % SLOTS_PER_LEVEL;
                level.slots[slot].push(entry);
                return;
            }
        }

        self.overflow.push(OverflowEntry {
            deadline: entry.deadline,
            entry,
        });
    }

    fn advance_to(&mut self, target_tick: u64) {
        while self.current_tick < target_tick {
            // Optimization: Skip empty ticks
            let next_tick = self.next_skip_tick(target_tick);
            if next_tick > self.current_tick + 1 {
                let skip = next_tick - self.current_tick - 1;
                self.current_tick += skip;
                self.levels[0].cursor = (self.levels[0].cursor + skip as usize) % SLOTS_PER_LEVEL;
            }

            self.current_tick = self.current_tick.saturating_add(1);
            self.tick_level0();
            self.refill_overflow();
        }
    }

    fn next_skip_tick(&self, limit: u64) -> u64 {
        let l0 = &self.levels[0];
        let mut next_l0 = limit;

        // 1. Check Level 0 for next occupied slot
        for i in 1..=SLOTS_PER_LEVEL {
            let slot_idx = (l0.cursor + i) % SLOTS_PER_LEVEL;
            if slot_idx == 0 {
                // Cascade point (wrap around).
                // The tick that causes the wrap (cursor -> 0) corresponds to `current_tick + i`.
                let wrap_tick = self.current_tick + i as u64;
                if wrap_tick < next_l0 {
                    next_l0 = wrap_tick;
                }
                break;
            }
            if !l0.slots[slot_idx].is_empty() {
                // Found item
                let item_tick = self.current_tick + i as u64;
                if item_tick < next_l0 {
                    next_l0 = item_tick;
                }
                break;
            }
        }

        // 2. Check overflow
        if let Some(entry) = self.overflow.peek() {
            let max_range = self.max_range_ns();
            let entry_ns = entry.deadline.as_nanos();
            let min_enter_ns = entry_ns.saturating_sub(max_range);
            let min_enter_tick = min_enter_ns / LEVEL0_RESOLUTION_NS;

            if min_enter_tick < next_l0 {
                if min_enter_tick > self.current_tick {
                    next_l0 = min_enter_tick;
                } else {
                    return self.current_tick;
                }
            }
        }

        next_l0
    }

    fn tick_level0(&mut self) {
        let cursor = {
            let level0 = &mut self.levels[0];
            level0.cursor = (level0.cursor + 1) % SLOTS_PER_LEVEL;
            level0.cursor
        };

        let bucket = std::mem::take(&mut self.levels[0].slots[cursor]);
        self.collect_bucket(bucket);

        if cursor == 0 {
            self.cascade(1);
        }
    }

    fn cascade(&mut self, level_index: usize) {
        if level_index >= LEVEL_COUNT {
            return;
        }

        let cursor = {
            let level = &mut self.levels[level_index];
            level.cursor = (level.cursor + 1) % SLOTS_PER_LEVEL;
            level.cursor
        };

        let bucket = std::mem::take(&mut self.levels[level_index].slots[cursor]);
        for entry in bucket {
            if self.is_live(&entry) {
                self.insert_entry(entry);
            }
        }

        if cursor == 0 {
            self.cascade(level_index + 1);
        }
    }

    fn collect_bucket(&mut self, bucket: Vec<TimerEntry>) {
        let now = self.current_time();
        for entry in bucket {
            if !self.is_live(&entry) {
                continue;
            }
            if entry.deadline <= now {
                self.ready.push(entry);
            } else {
                self.insert_entry(entry);
            }
        }
    }

    fn refill_overflow(&mut self) {
        let current = self.current_time();
        let max_range = self.max_range_ns();
        while let Some(entry) = self.overflow.peek() {
            let delta = entry.deadline.as_nanos().saturating_sub(current.as_nanos());
            if delta < max_range {
                let entry = self.overflow.pop().expect("peeked entry missing");
                if self.is_live(&entry.entry) {
                    self.insert_entry(entry.entry);
                }
            } else {
                break;
            }
        }
    }

    fn drain_ready(&mut self, now: Time) -> Vec<Waker> {
        let mut wakers = Vec::new();
        let mut remaining = Vec::new();
        let ready = std::mem::take(&mut self.ready);

        for entry in ready {
            if !self.is_live(&entry) {
                continue;
            }

            if entry.deadline <= now {
                self.active.remove(&entry.id);
                wakers.push(entry.waker);
            } else {
                remaining.push(entry);
            }
        }

        self.ready = remaining;
        wakers
    }

    fn is_live(&self, entry: &TimerEntry) -> bool {
        self.active
            .get(&entry.id)
            .is_some_and(|generation| *generation == entry.generation)
    }

    fn max_range_ns(&self) -> u64 {
        self.levels.last().map_or(0, WheelLevel::range_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::Wake;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn wheel_register_and_fire() {
        init_test("wheel_register_and_fire");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));
        let waker = counter_waker(counter.clone());

        wheel.register(Time::from_millis(5), waker);

        let early = wheel.collect_expired(Time::from_millis(2));
        crate::assert_with_log!(early.is_empty(), "no early fire", true, early.len());
        let wakers = wheel.collect_expired(Time::from_millis(5));
        crate::assert_with_log!(wakers.len() == 1, "fires at deadline", 1, wakers.len());

        for waker in wakers {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter", 1, count);
        crate::assert_with_log!(wheel.is_empty(), "wheel empty", true, wheel.is_empty());
        crate::test_complete!("wheel_register_and_fire");
    }

    #[test]
    fn wheel_cancel_prevents_fire() {
        init_test("wheel_cancel_prevents_fire");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));
        let waker = counter_waker(counter.clone());

        let handle = wheel.register(Time::from_millis(5), waker);
        let cancelled = wheel.cancel(&handle);
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);

        let wakers = wheel.collect_expired(Time::from_millis(10));
        crate::assert_with_log!(wakers.is_empty(), "no fire", true, wakers.len());
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 0, "counter", 0, count);
        crate::test_complete!("wheel_cancel_prevents_fire");
    }

    #[test]
    fn wheel_overflow_promotes_when_in_range() {
        init_test("wheel_overflow_promotes_when_in_range");
        let mut wheel = TimerWheel::new();
        let waker = counter_waker(Arc::new(AtomicU64::new(0)));

        let far = Time::from_nanos(wheel.max_range_ns().saturating_add(LEVEL0_RESOLUTION_NS));
        wheel.register(far, waker);

        let wakers = wheel.collect_expired(far);
        crate::assert_with_log!(
            wakers.len() == 1,
            "fires after overflow promotion",
            1,
            wakers.len()
        );
        crate::test_complete!("wheel_overflow_promotes_when_in_range");
    }

    struct CounterWaker {
        counter: Arc<AtomicU64>,
    }

    impl Wake for CounterWaker {
        fn wake(self: Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter_waker(counter: Arc<AtomicU64>) -> Waker {
        Arc::new(CounterWaker { counter }).into()
    }

    #[test]
    fn wheel_advance_large_jump() {
        init_test("wheel_advance_large_jump");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));
        let waker = counter_waker(counter.clone());

        // Register a timer 1 hour in the future (3,600,000 ticks)
        let one_hour = Time::from_secs(3600);
        wheel.register(one_hour, waker);

        // Advance time
        let wakers = wheel.collect_expired(one_hour);

        // Should fire
        crate::assert_with_log!(wakers.len() == 1, "fires after large jump", 1, wakers.len());
        for waker in wakers {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter", 1, count);
        crate::assert_with_log!(wheel.is_empty(), "wheel empty", true, wheel.is_empty());
        crate::test_complete!("wheel_advance_large_jump");
    }
}
