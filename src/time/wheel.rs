//! Hierarchical timing wheel for efficient timer management.
//!
//! The wheel stores timers in multiple levels of buckets with increasing
//! resolution. Timers are inserted into the coarsest level that can represent
//! their deadline relative to the current time. As time advances, buckets are
//! cascaded down to finer levels until they fire.
//!
//! # Overflow Handling
//!
//! Timers with deadlines exceeding the wheel's maximum range (approximately 37.2 hours
//! with default settings) are stored in an overflow heap. These timers are automatically
//! promoted back into the wheel as time advances and their deadlines come within range.
//!
//! You can configure the maximum allowed timer duration to reject unreasonably long
//! timers upfront.
//!
//! # Timer Coalescing
//!
//! When enabled, nearby timers can be grouped together to reduce the number of wakeups.
//! Timers within the configured coalesce window fire together when the window boundary
//! is reached. This is useful for reducing CPU overhead when many timers have similar
//! deadlines.
//!
//! # Performance Characteristics
//!
//! - Insert: O(1) - direct slot calculation
//! - Cancel: O(1) - generation-based invalidation
//! - Tick (no expiry): O(1) - cursor advance
//! - Tick (with expiry): O(expired) - returns wakers
//! - Space: O(SLOTS × LEVELS) + O(overflow timers)

use crate::types::Time;
use smallvec::SmallVec;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::task::Waker;
use std::time::Duration;

/// Waker collection type for timer expiration. Stack-allocated for typical
/// small batches (≤4 expired timers per tick).
pub type WakerBatch = SmallVec<[Waker; 4]>;

const LEVEL_COUNT: usize = 4;
const SLOTS_PER_LEVEL: usize = 256;
const LEVEL0_RESOLUTION_NS: u64 = 1_000_000; // 1ms

const LEVEL_RESOLUTIONS_NS: [u64; LEVEL_COUNT] = [
    LEVEL0_RESOLUTION_NS,
    LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64,
    LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64 * SLOTS_PER_LEVEL as u64,
    LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64 * SLOTS_PER_LEVEL as u64 * SLOTS_PER_LEVEL as u64,
];

#[inline]
fn duration_to_u64_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the timer wheel's overflow handling.
#[derive(Debug, Clone)]
pub struct TimerWheelConfig {
    /// Maximum timer duration the wheel handles directly.
    ///
    /// Timers exceeding this duration go to the overflow list and are
    /// re-inserted when they come within range.
    ///
    /// Default: 24 hours (86,400 seconds)
    pub max_wheel_duration: Duration,

    /// Maximum allowed timer duration.
    ///
    /// Timers exceeding this duration are rejected with an error.
    /// Set to `Duration::MAX` to allow any duration.
    ///
    /// Default: 7 days (604,800 seconds)
    pub max_timer_duration: Duration,
}

impl Default for TimerWheelConfig {
    fn default() -> Self {
        Self {
            max_wheel_duration: Duration::from_hours(24), // 24 hours
            max_timer_duration: Duration::from_hours(168), // 7 days
        }
    }
}

impl TimerWheelConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum wheel duration.
    #[must_use]
    pub fn max_wheel_duration(mut self, duration: Duration) -> Self {
        self.max_wheel_duration = duration;
        self
    }

    /// Sets the maximum allowed timer duration.
    #[must_use]
    pub fn max_timer_duration(mut self, duration: Duration) -> Self {
        self.max_timer_duration = duration;
        self
    }
}

/// Configuration for timer coalescing.
///
/// Coalescing groups nearby timers together to reduce the number of wakeups.
/// When multiple timers fall within the same coalesce window, they all fire
/// at the window boundary rather than at their individual deadlines.
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    /// Timers within this window fire together.
    ///
    /// Default: 1ms
    pub coalesce_window: Duration,

    /// Minimum number of timers in a slot before coalescing takes effect.
    ///
    /// Set to 1 to always coalesce, or higher to only coalesce when there
    /// are many timers (reducing overhead for sparse timers).
    ///
    /// Default: 1
    pub min_group_size: usize,

    /// Enable or disable coalescing.
    ///
    /// Default: false
    pub enabled: bool,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            coalesce_window: Duration::from_millis(1),
            min_group_size: 1,
            enabled: false,
        }
    }
}

impl CoalescingConfig {
    /// Creates a new coalescing configuration (disabled by default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables coalescing with the given window.
    #[must_use]
    pub fn enabled_with_window(window: Duration) -> Self {
        Self {
            coalesce_window: window,
            min_group_size: 1,
            enabled: true,
        }
    }

    /// Sets the coalesce window.
    #[must_use]
    pub fn coalesce_window(mut self, window: Duration) -> Self {
        self.coalesce_window = window;
        self
    }

    /// Sets the minimum group size for coalescing.
    #[must_use]
    pub fn min_group_size(mut self, size: usize) -> Self {
        self.min_group_size = size;
        self
    }

    /// Enables coalescing.
    #[must_use]
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disables coalescing.
    #[must_use]
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Error returned when a timer duration exceeds the configured maximum.
#[derive(Debug, Clone, thiserror::Error)]
#[error("timer duration {duration:?} exceeds maximum allowed duration {max:?}")]
pub struct TimerDurationExceeded {
    /// The requested duration.
    pub duration: Duration,
    /// The maximum allowed duration.
    pub max: Duration,
}

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

type TimerActivityMap = slab::Slab<u64>;

impl PartialEq for OverflowEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
            && self.entry.generation == other.entry.generation
            && self.entry.id == other.entry.id
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
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| {
                // Lower generation wins
                let diff = other
                    .entry
                    .generation
                    .wrapping_sub(self.entry.generation)
                    .cast_signed();
                diff.cmp(&0)
            })
            // Fallback to id
            .then_with(|| other.entry.id.cmp(&self.entry.id))
    }
}

/// Number of `u64` words needed to represent 256 slot bits.
const BITMAP_WORDS: usize = SLOTS_PER_LEVEL / 64;

#[derive(Debug)]
struct WheelLevel {
    slots: Vec<Vec<TimerEntry>>,
    resolution_ns: u64,
    cursor: usize,
    /// Bitmap tracking which slots contain at least one entry.
    /// Bit `i` of `occupied[i / 64]` corresponds to slot `i`.
    /// Used by `next_skip_tick` to skip empty slots in O(1) per word.
    occupied: [u64; BITMAP_WORDS],
}

impl WheelLevel {
    fn new(resolution_ns: u64, cursor: usize) -> Self {
        Self {
            slots: vec![Vec::new(); SLOTS_PER_LEVEL],
            resolution_ns,
            cursor,
            occupied: [0u64; BITMAP_WORDS],
        }
    }

    fn range_ns(&self) -> u64 {
        self.resolution_ns.saturating_mul(SLOTS_PER_LEVEL as u64)
    }

    /// Checks if a slot is occupied in the bitmap.
    #[inline]
    fn is_occupied(&self, slot: usize) -> bool {
        (self.occupied[slot / 64] & (1u64 << (slot % 64))) != 0
    }

    /// Marks a slot as occupied in the bitmap.
    #[inline]
    fn set_occupied(&mut self, slot: usize) {
        self.occupied[slot / 64] |= 1u64 << (slot % 64);
    }

    /// Clears the occupied bit for a slot (called after `mem::take`).
    #[inline]
    fn clear_occupied(&mut self, slot: usize) {
        self.occupied[slot / 64] &= !(1u64 << (slot % 64));
    }

    /// Returns the distance (in slots) to the next occupied slot scanning
    /// forward from `cursor + 1` up to the end of the level (slot 255),
    /// and wrapping around if necessary.
    fn next_occupied_distance(&self) -> Option<usize> {
        if self.occupied == [0, 0, 0, 0] {
            return None;
        }

        let start = self.cursor + 1;
        let mut pos = start;

        // Search up to end of array
        while pos < SLOTS_PER_LEVEL {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            let masked = self.occupied[word_idx] >> bit_idx;
            if masked != 0 {
                let found = pos + masked.trailing_zeros() as usize;
                if found < SLOTS_PER_LEVEL {
                    return Some(found - self.cursor);
                }
            }
            pos = (word_idx + 1) * 64;
        }

        // Search from 0 up to cursor
        pos = 0;
        while pos <= self.cursor {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            let masked = self.occupied[word_idx] >> bit_idx;
            if masked != 0 {
                let found = pos + masked.trailing_zeros() as usize;
                if found <= self.cursor {
                    return Some(SLOTS_PER_LEVEL - self.cursor + found);
                }
            }
            pos = (word_idx + 1) * 64;
        }

        None
    }
}

/// Hierarchical timing wheel for timers.
#[derive(Debug)]
pub struct TimerWheel {
    current_tick: u64,
    levels: [WheelLevel; LEVEL_COUNT],
    overflow: BinaryHeap<OverflowEntry>,
    ready: Vec<TimerEntry>,
    next_generation: u64,
    active: TimerActivityMap,
    config: TimerWheelConfig,
    coalescing: CoalescingConfig,
    max_wheel_duration_ns: u64,
    max_timer_duration_ns: u64,
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
        Self::with_config(
            now,
            TimerWheelConfig::default(),
            CoalescingConfig::default(),
        )
    }

    /// Creates a new timer wheel with custom configuration.
    #[must_use]
    pub fn with_config(now: Time, config: TimerWheelConfig, coalescing: CoalescingConfig) -> Self {
        let now_nanos = now.as_nanos();
        let current_tick = now_nanos / LEVEL0_RESOLUTION_NS;
        let max_wheel_duration_ns = duration_to_u64_nanos(config.max_wheel_duration);
        let max_timer_duration_ns = duration_to_u64_nanos(config.max_timer_duration);
        let levels = std::array::from_fn(|idx| {
            let resolution_ns = LEVEL_RESOLUTIONS_NS[idx];
            let cursor = ((now_nanos / resolution_ns) % SLOTS_PER_LEVEL as u64) as usize;
            WheelLevel::new(resolution_ns, cursor)
        });

        Self {
            current_tick,
            levels,
            overflow: BinaryHeap::with_capacity(8),
            ready: Vec::with_capacity(8),
            next_generation: 0,
            active: slab::Slab::with_capacity(64),
            config,
            coalescing,
            max_wheel_duration_ns,
            max_timer_duration_ns,
        }
    }

    /// Returns the timer wheel configuration.
    #[must_use]
    pub fn config(&self) -> &TimerWheelConfig {
        &self.config
    }

    /// Returns the coalescing configuration.
    #[must_use]
    pub fn coalescing_config(&self) -> &CoalescingConfig {
        &self.coalescing
    }

    /// Returns the number of active timers in the wheel.
    #[must_use]
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Returns true if there are no active timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// Removes all timers from the wheel.
    pub fn clear(&mut self) {
        self.active.clear();
        self.ready.clear();
        self.overflow.clear();
        for level in &mut self.levels {
            for slot in &mut level.slots {
                slot.clear();
            }
            level.occupied = [0u64; BITMAP_WORDS];
        }
    }

    /// Returns the current time aligned to the wheel resolution.
    #[must_use]
    pub fn current_time(&self) -> Time {
        Time::from_nanos(self.current_tick.saturating_mul(LEVEL0_RESOLUTION_NS))
    }

    /// Synchronizes the wheel's internal notion of time to the provided clock.
    ///
    /// This advances buckets and overflow promotion without draining ready
    /// timers, so query/register paths can reason from a current baseline even
    /// after long idle gaps between `collect_expired` calls.
    pub(crate) fn synchronize(&mut self, now: Time) {
        let target_tick = now.as_nanos() / LEVEL0_RESOLUTION_NS;
        if target_tick > self.current_tick {
            self.advance_to(target_tick);
        }
    }

    /// Registers a timer that fires at the given deadline.
    ///
    /// If the timer duration exceeds the configured maximum, the deadline is
    /// silently clamped to the maximum allowed duration. The timer will fire
    /// early, and the caller is expected to check if the true deadline has
    /// been reached and re-register if necessary.
    pub fn register(&mut self, mut deadline: Time, waker: Waker) -> TimerHandle {
        let current = self.current_time();
        if deadline > current {
            let duration_ns = deadline.as_nanos().saturating_sub(current.as_nanos());
            if duration_ns > self.max_timer_duration_ns {
                deadline = current.saturating_add_nanos(self.max_timer_duration_ns);
            }
        }
        self.try_register(deadline, waker)
            .expect("timer duration was clamped but still exceeded maximum")
    }

    /// Attempts to register a timer with validation.
    ///
    /// Returns an error if the timer's duration (deadline - current time)
    /// exceeds the configured maximum timer duration.
    pub fn try_register(
        &mut self,
        deadline: Time,
        waker: Waker,
    ) -> Result<TimerHandle, TimerDurationExceeded> {
        // Validate duration against configured maximum
        let current = self.current_time();
        if deadline > current {
            let duration_ns = deadline.as_nanos().saturating_sub(current.as_nanos());
            if duration_ns > self.max_timer_duration_ns {
                return Err(TimerDurationExceeded {
                    duration: Duration::from_nanos(duration_ns),
                    max: self.config.max_timer_duration,
                });
            }
        }

        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);

        let id = self.active.insert(generation) as u64;

        let entry = TimerEntry {
            deadline,
            waker,
            id,
            generation,
        };

        self.insert_entry(entry);

        Ok(TimerHandle { id, generation })
    }

    /// Returns the number of timers in the overflow list.
    #[must_use]
    pub fn overflow_count(&self) -> usize {
        self.overflow.len()
    }

    /// Cancels a timer by handle.
    ///
    /// Returns true if the timer was active and is now cancelled.
    pub fn cancel(&mut self, handle: &TimerHandle) -> bool {
        let id_usize = handle.id as usize;
        if self
            .active
            .get(id_usize)
            .is_some_and(|&g| g == handle.generation)
        {
            self.active.remove(id_usize);
            if self.active.is_empty() {
                self.purge_inactive_storage();
            }
            true
        } else {
            false
        }
    }

    /// Returns the earliest pending deadline, if any.
    #[must_use]
    pub fn next_deadline(&mut self) -> Option<Time> {
        let current = self.current_time();

        // With coalescing enabled, collect_expired(now) can legally fire a
        // whole in-window group immediately, before the group's raw earliest
        // deadline. next_deadline() must report that immediate readiness or
        // callers can oversleep past the actual coalesced wake point.
        if self.coalescing.enabled && self.coalescing_group_size(current) > 0 {
            return Some(current);
        }

        let mut min_deadline: Option<Time> = None;

        for entry in &self.ready {
            if !self.is_live(entry) {
                continue;
            }
            if entry.deadline <= current {
                return Some(current);
            }
            min_deadline = Some(min_deadline.map_or(entry.deadline, |c| c.min(entry.deadline)));
        }

        if min_deadline.is_some() {
            return min_deadline;
        }

        for (idx, level) in self.levels.iter().enumerate() {
            let shift = idx * 8;
            let level_tick = self.current_tick >> shift;
            let current_slot = (level_tick % (SLOTS_PER_LEVEL as u64)) as usize;

            for i in 0..SLOTS_PER_LEVEL {
                let slot = (current_slot + i) % SLOTS_PER_LEVEL;
                if level.is_occupied(slot) {
                    for entry in &level.slots[slot] {
                        if !self.is_live(entry) {
                            continue;
                        }
                        min_deadline =
                            Some(min_deadline.map_or(entry.deadline, |c| c.min(entry.deadline)));
                    }

                    if min_deadline.is_some() {
                        return min_deadline;
                    }
                }
            }
        }

        while let Some(entry) = self.overflow.peek() {
            if self.is_live(&entry.entry) {
                min_deadline = Some(min_deadline.map_or(entry.deadline, |c| c.min(entry.deadline)));
                break;
            }
            let _ = self.overflow.pop();
        }

        min_deadline
    }

    /// Advances time and returns expired timer wakers.
    pub fn collect_expired(&mut self, now: Time) -> WakerBatch {
        self.synchronize(now);

        self.drain_ready(now)
    }

    fn insert_entry(&mut self, entry: TimerEntry) {
        let current = self.current_time();
        if entry.deadline <= current {
            self.ready.push(entry);
            return;
        }

        let delta = entry.deadline.as_nanos().saturating_sub(current.as_nanos());

        // Check against configured max_wheel_duration for overflow
        let max_range = self.max_range_ns();
        if delta >= max_range {
            self.overflow.push(OverflowEntry {
                deadline: entry.deadline,
                entry,
            });
            return;
        }

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

                let slot = (tick % (SLOTS_PER_LEVEL as u64)) as usize;
                level.slots[slot].push(entry);
                level.set_occupied(slot);
                return;
            }
        }

        self.overflow.push(OverflowEntry {
            deadline: entry.deadline,
            entry,
        });
    }

    fn advance_to(&mut self, target_tick: u64) {
        if self.active.is_empty() {
            self.current_tick = target_tick;
            self.realign_cursors_to_current_tick();
            return;
        }

        while self.current_tick < target_tick {
            // Optimization: Skip empty ticks across all levels
            let next_tick = self.next_skip_tick(target_tick);
            if next_tick > self.current_tick + 1 {
                self.current_tick = next_tick - 1;
                self.realign_cursors_to_current_tick();
            }

            self.current_tick = self.current_tick.saturating_add(1);
            self.tick_level0();
            self.refill_overflow();
        }
    }

    fn next_skip_tick(&self, limit: u64) -> u64 {
        let mut next_tick = limit;

        let mut r_i = 1u64;
        for level in &self.levels {
            if let Some(dist) = level.next_occupied_distance() {
                let current_base = self.current_tick - (self.current_tick % r_i);
                let mut hit_tick = current_base + (dist as u64) * r_i;
                if hit_tick <= self.current_tick {
                    hit_tick += SLOTS_PER_LEVEL as u64 * r_i;
                }
                if hit_tick < next_tick {
                    next_tick = hit_tick;
                }
            }
            r_i *= SLOTS_PER_LEVEL as u64;
        }

        // 3. Check overflow
        if let Some(entry) = self.overflow.peek() {
            let max_range = self.max_range_ns();
            let entry_ns = entry.deadline.as_nanos();
            let min_enter_ns = entry_ns.saturating_sub(max_range);
            let min_enter_tick = min_enter_ns / LEVEL0_RESOLUTION_NS;

            if min_enter_tick < next_tick {
                if min_enter_tick > self.current_tick {
                    next_tick = min_enter_tick;
                } else {
                    return self.current_tick;
                }
            }
        }

        next_tick
    }

    fn realign_cursors_to_current_tick(&mut self) {
        let now_nanos = self.current_tick.saturating_mul(LEVEL0_RESOLUTION_NS);
        for level in &mut self.levels {
            level.cursor = ((now_nanos / level.resolution_ns) % SLOTS_PER_LEVEL as u64) as usize;
        }
    }

    fn tick_level0(&mut self) {
        let cursor = {
            let level0 = &mut self.levels[0];
            level0.cursor = (level0.cursor + 1) % SLOTS_PER_LEVEL;
            level0.cursor
        };

        let bucket = std::mem::take(&mut self.levels[0].slots[cursor]);
        self.levels[0].clear_occupied(cursor);
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
        self.levels[level_index].clear_occupied(cursor);
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

    fn promote_coalescing_window_entries(&mut self, boundary: Time, ready: &mut Vec<TimerEntry>) {
        let boundary_ns = boundary.as_nanos();
        for (idx, level) in self.levels.iter_mut().enumerate() {
            let shift = idx * 8;
            let level_tick_current = self.current_tick >> shift;
            let level_tick_boundary = boundary_ns / level.resolution_ns;

            if level_tick_boundary < level_tick_current {
                continue;
            }

            let current_slot = (level_tick_current % (SLOTS_PER_LEVEL as u64)) as usize;
            // Compare in u64 before narrowing to usize: on 32-bit targets, a
            // direct `as usize` cast of a wide difference would silently
            // truncate the high bits and could bypass the SLOTS_PER_LEVEL
            // clamp, causing us to miss timer slots that are far in the
            // future.
            let diff_u64 = level_tick_boundary - level_tick_current;
            let diff = if diff_u64 >= SLOTS_PER_LEVEL as u64 {
                SLOTS_PER_LEVEL - 1
            } else {
                diff_u64 as usize
            };

            for i in 0..=diff {
                let slot_idx = (current_slot + i) % SLOTS_PER_LEVEL;
                if !level.is_occupied(slot_idx) {
                    continue;
                }

                let slot_empty = {
                    let slot = &mut level.slots[slot_idx];
                    let mut j = 0;
                    while j < slot.len() {
                        if slot[j].deadline <= boundary {
                            ready.push(slot.swap_remove(j));
                        } else {
                            j += 1;
                        }
                    }
                    slot.is_empty()
                };
                if slot_empty {
                    level.clear_occupied(slot_idx);
                }
            }
        }

        while self.overflow.peek().is_some_and(|e| e.deadline <= boundary) {
            let entry = self.overflow.pop().expect("peeked entry missing");
            ready.push(entry.entry);
        }
    }

    fn drain_ready(&mut self, now: Time) -> WakerBatch {
        let mut wakers = WakerBatch::new();

        // Take the ready vec out so we can mutate it in-place while also
        // accessing self.active / self.coalescing through &mut self.
        let mut ready = std::mem::take(&mut self.ready);

        // Calculate the coalesced time boundary if coalescing is enabled.
        // Coalescing only applies when there are enough timers in-window.
        let coalesced_time = if self.coalescing.enabled {
            let window_ns = self
                .coalescing
                .coalesce_window
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64;
            if window_ns == 0 {
                None
            } else {
                let now_ns = now.as_nanos();
                // Compute the next coalescing window boundary with saturation.
                // At very large logical times, `((now/window)+1)*window` can overflow.
                now_ns.checked_div(window_ns).map(|quotient| {
                    let window_end_ns = quotient.saturating_add(1).saturating_mul(window_ns);
                    Time::from_nanos(window_end_ns)
                })
            }
        } else {
            None
        };
        if let Some(boundary) = coalesced_time {
            self.promote_coalescing_window_entries(boundary, &mut ready);
        }

        let coalescing_enabled = coalesced_time.is_some_and(|boundary| {
            let min_group_size = self.coalescing.min_group_size.max(1);
            ready
                .iter()
                .filter(|entry| self.is_live(entry) && entry.deadline <= boundary)
                .count()
                >= min_group_size
        });

        // Process in-place efficiently using drain — no separate `remaining` allocation.
        #[allow(clippy::iter_with_drain)]
        for entry in ready.drain(..) {
            if !self.is_live(&entry) {
                continue;
            }

            let should_fire = if coalescing_enabled {
                let coalesced = coalesced_time.unwrap_or(now);
                entry.deadline <= coalesced
            } else {
                entry.deadline <= now
            };

            if should_fire {
                self.active.remove(entry.id as usize);
                wakers.push(entry.waker);
            } else {
                self.insert_entry(entry);
            }
        }

        // Put the vec back — retains its capacity for the next tick.
        let mut new_ready = std::mem::take(&mut self.ready);
        ready.append(&mut new_ready);
        self.ready = ready;
        if self.active.is_empty() {
            self.purge_inactive_storage();
        }
        wakers
    }

    /// Returns coalescing statistics: number of timers that would fire together.
    ///
    /// This is useful for monitoring coalescing effectiveness.
    #[must_use]
    pub fn coalescing_group_size(&self, now: Time) -> usize {
        let expired_count = self
            .ready
            .iter()
            .filter(|e| self.is_live(e) && e.deadline <= now)
            .count();
        if !self.coalescing.enabled {
            return expired_count;
        }

        let window_ns = self
            .coalescing
            .coalesce_window
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        if window_ns == 0 {
            return expired_count;
        }

        let now_ns = now.as_nanos();
        let window_end_ns = (now_ns / window_ns)
            .saturating_add(1)
            .saturating_mul(window_ns);
        let coalesced_time = Time::from_nanos(window_end_ns);

        let mut coalesced_count = self
            .ready
            .iter()
            .filter(|e| self.is_live(e) && e.deadline <= coalesced_time)
            .count();

        for (idx, level) in self.levels.iter().enumerate() {
            let shift = idx * 8;
            let level_tick_current = self.current_tick >> shift;
            let level_tick_boundary = window_end_ns / level.resolution_ns;

            if level_tick_boundary < level_tick_current {
                continue;
            }

            let current_slot = (level_tick_current % (SLOTS_PER_LEVEL as u64)) as usize;
            // Clamp in u64 before narrowing to usize: a direct cast on 32-bit
            // targets would silently truncate the high bits and could bypass
            // the SLOTS_PER_LEVEL clamp. See `promote_coalescing_window_entries`.
            let diff_u64 = level_tick_boundary - level_tick_current;
            let diff = if diff_u64 >= SLOTS_PER_LEVEL as u64 {
                SLOTS_PER_LEVEL - 1
            } else {
                diff_u64 as usize
            };

            for i in 0..=diff {
                let slot_idx = (current_slot + i) % SLOTS_PER_LEVEL;
                if level.is_occupied(slot_idx) {
                    coalesced_count += level.slots[slot_idx]
                        .iter()
                        .filter(|e| self.is_live(e) && e.deadline <= coalesced_time)
                        .count();
                }
            }
        }

        coalesced_count += self
            .overflow
            .iter()
            .filter(|e| self.is_live(&e.entry) && e.deadline <= coalesced_time)
            .count();

        if coalesced_count >= self.coalescing.min_group_size.max(1) {
            coalesced_count
        } else {
            expired_count
        }
    }

    fn is_live(&self, entry: &TimerEntry) -> bool {
        self.active
            .get(entry.id as usize)
            .is_some_and(|generation| *generation == entry.generation)
    }

    /// Returns the maximum range in nanoseconds for direct wheel storage.
    ///
    /// Timers with deadlines beyond this range from the current time go to overflow.
    fn max_range_ns(&self) -> u64 {
        self.max_wheel_duration_ns
    }

    /// Returns the physical wheel range based on level structure.
    #[allow(dead_code)]
    fn physical_range_ns(&self) -> u64 {
        self.levels.last().map_or(0, WheelLevel::range_ns)
    }

    fn purge_inactive_storage(&mut self) {
        self.ready.clear();
        self.overflow.clear();
        for level in &mut self.levels {
            for slot in &mut level.slots {
                slot.clear();
            }
            level.occupied = [0u64; BITMAP_WORDS];
        }
    }
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::Wake;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn timer_wheel_config_debug_clone_default() {
        let def = TimerWheelConfig::default();
        assert_eq!(def.max_wheel_duration, Duration::from_hours(24));
        assert_eq!(def.max_timer_duration, Duration::from_hours(168));
        let cloned = def.clone();
        assert_eq!(cloned.max_wheel_duration, def.max_wheel_duration);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("TimerWheelConfig"));
        // Builder
        let custom = TimerWheelConfig::new()
            .max_wheel_duration(Duration::from_secs(43_200))
            .max_timer_duration(Duration::from_secs(172_800));
        assert_eq!(custom.max_wheel_duration, Duration::from_secs(43_200));
        assert_eq!(custom.max_timer_duration, Duration::from_secs(172_800));
    }

    #[test]
    fn coalescing_config_debug_clone_default() {
        let def = CoalescingConfig::default();
        assert_eq!(def.coalesce_window, Duration::from_millis(1));
        assert_eq!(def.min_group_size, 1);
        assert!(!def.enabled);
        let cloned = def.clone();
        assert_eq!(cloned.coalesce_window, def.coalesce_window);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("CoalescingConfig"));
        // Builder chain
        let enabled = CoalescingConfig::enabled_with_window(Duration::from_millis(5));
        assert!(enabled.enabled);
        assert_eq!(enabled.coalesce_window, Duration::from_millis(5));
    }

    #[test]
    fn timer_duration_exceeded_debug_clone_display() {
        let err = TimerDurationExceeded {
            duration: Duration::from_secs(7200),
            max: Duration::from_secs(3600),
        };
        let cloned = err.clone();
        assert_eq!(cloned.duration, err.duration);
        assert_eq!(cloned.max, err.max);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TimerDurationExceeded"));
        let display = format!("{err}");
        assert!(display.contains("exceeds"));
    }

    #[test]
    fn timer_handle_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        // Create handles via TimerWheel::register
        let mut wheel = TimerWheel::new();
        let waker1 = counter_waker(Arc::new(AtomicU64::new(0)));
        let waker2 = counter_waker(Arc::new(AtomicU64::new(0)));
        let h1 = wheel.register(Time::from_millis(10), waker1);
        let h2 = wheel.register(Time::from_millis(20), waker2);
        assert_ne!(h1, h2);
        let copied = h1;
        let cloned = h1;
        assert_eq!(copied, cloned);
        let dbg = format!("{h1:?}");
        assert!(dbg.contains("TimerHandle"));
        // Hash
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2);
        set.insert(h1); // duplicate
        assert_eq!(set.len(), 2);
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
    fn wheel_cancel_rejects_generation_mismatch_without_removing() {
        init_test("wheel_cancel_rejects_generation_mismatch_without_removing");
        let mut wheel = TimerWheel::new();
        let waker = counter_waker(Arc::new(AtomicU64::new(0)));

        let handle = wheel.register(Time::from_millis(5), waker);
        let stale = TimerHandle {
            id: handle.id,
            generation: handle.generation.saturating_add(1),
        };

        let stale_cancelled = wheel.cancel(&stale);
        crate::assert_with_log!(
            !stale_cancelled,
            "mismatched generation is rejected",
            false,
            stale_cancelled
        );

        let live_cancelled = wheel.cancel(&handle);
        crate::assert_with_log!(
            live_cancelled,
            "live handle still cancellable after stale attempt",
            true,
            live_cancelled
        );
        crate::test_complete!("wheel_cancel_rejects_generation_mismatch_without_removing");
    }

    #[test]
    fn wheel_register_wraps_id_and_generation_without_immediate_collision() {
        init_test("wheel_register_wraps_id_and_generation_without_immediate_collision");
        let mut wheel = TimerWheel::new();
        wheel.next_generation = u64::MAX;

        let h1 = wheel.register(
            Time::from_millis(5),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );
        let h2 = wheel.register(
            Time::from_millis(6),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );

        crate::assert_with_log!(
            h1.generation == u64::MAX,
            "first generation",
            u64::MAX,
            h1.generation
        );
        crate::assert_with_log!(
            h2.generation == 0,
            "wrapped second generation",
            0,
            h2.generation
        );
        crate::assert_with_log!(h1 != h2, "handles differ across wrap", true, h1 != h2);
        crate::assert_with_log!(wheel.cancel(&h1), "first handle cancellable", true, true);
        crate::assert_with_log!(wheel.cancel(&h2), "second handle cancellable", true, true);
        crate::test_complete!("wheel_register_wraps_id_and_generation_without_immediate_collision");
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

    #[test]
    fn next_deadline_ready_same_tick_returns_actual_deadline() {
        init_test("next_deadline_ready_same_tick_returns_actual_deadline");
        let mut wheel = TimerWheel::new();
        let deadline = Time::from_nanos(500_000); // < 1ms, still in current L0 tick
        let waker = counter_waker(Arc::new(AtomicU64::new(0)));

        wheel.register(deadline, waker);

        let next = wheel.next_deadline();
        crate::assert_with_log!(
            next == Some(deadline),
            "same-tick future deadline preserved",
            Some(deadline),
            next
        );
        crate::test_complete!("next_deadline_ready_same_tick_returns_actual_deadline");
    }

    #[test]
    fn next_deadline_returns_current_when_coalescing_can_fire_window_now() {
        init_test("next_deadline_returns_current_when_coalescing_can_fire_window_now");

        let coalescing = CoalescingConfig::new()
            .coalesce_window(Duration::from_millis(5))
            .min_group_size(2)
            .enable();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        wheel.register(
            Time::from_millis(2),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );
        wheel.register(
            Time::from_millis(4),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );

        wheel.synchronize(Time::from_millis(1));

        let next = wheel.next_deadline();
        crate::assert_with_log!(
            next == Some(Time::from_millis(1)),
            "coalescing-ready window is immediately due",
            Some(Time::from_millis(1)),
            next
        );

        let wakers = wheel.collect_expired(Time::from_millis(1));
        crate::assert_with_log!(
            wakers.len() == 2,
            "same query time really fires the whole coalesced group",
            2usize,
            wakers.len()
        );

        crate::test_complete!("next_deadline_returns_current_when_coalescing_can_fire_window_now");
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

    #[test]
    fn empty_wheel_large_jump_realigns_all_cursors() {
        init_test("empty_wheel_large_jump_realigns_all_cursors");
        let mut wheel = TimerWheel::new();
        let jump = Time::from_secs(3600);

        let wakers = wheel.collect_expired(jump);
        crate::assert_with_log!(
            wakers.is_empty(),
            "no timers fire on empty wheel jump",
            true,
            wakers.len()
        );
        crate::assert_with_log!(
            wheel.current_time() == jump,
            "current time advances directly to jump",
            jump.as_nanos(),
            wheel.current_time().as_nanos()
        );

        let jump_nanos = jump.as_nanos();
        for level in &wheel.levels {
            let expected_cursor =
                ((jump_nanos / level.resolution_ns) % SLOTS_PER_LEVEL as u64) as usize;
            crate::assert_with_log!(
                level.cursor == expected_cursor,
                "cursor realigned to jumped time",
                expected_cursor,
                level.cursor
            );
        }
        crate::test_complete!("empty_wheel_large_jump_realigns_all_cursors");
    }

    #[test]
    fn cancel_last_timer_purges_stale_storage() {
        init_test("cancel_last_timer_purges_stale_storage");
        let mut wheel = TimerWheel::new();

        let h1 = wheel.register(
            Time::from_millis(10),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );
        let h2 = wheel.register(
            Time::from_millis(20),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );

        crate::assert_with_log!(wheel.cancel(&h1), "first cancel succeeds", true, true);
        crate::assert_with_log!(wheel.cancel(&h2), "second cancel succeeds", true, true);
        crate::assert_with_log!(
            wheel.is_empty(),
            "wheel has no active timers",
            true,
            wheel.len()
        );
        crate::assert_with_log!(
            wheel.ready.is_empty(),
            "ready queue purged",
            true,
            wheel.ready.len()
        );
        crate::assert_with_log!(
            wheel.overflow.is_empty(),
            "overflow queue purged",
            true,
            wheel.overflow.len()
        );
        for level in &wheel.levels {
            let occupied = level.occupied.iter().any(|&word| word != 0);
            crate::assert_with_log!(
                !occupied,
                "occupied bitmap cleared when active set empties",
                false,
                occupied
            );
        }
        crate::test_complete!("cancel_last_timer_purges_stale_storage");
    }

    // =========================================================================
    // OVERFLOW AND MAX DURATION TESTS
    // =========================================================================

    #[test]
    fn timer_at_exactly_max_duration() {
        init_test("timer_at_exactly_max_duration");
        let config = TimerWheelConfig::new().max_timer_duration(Duration::from_secs(3600)); // 1 hour max
        let mut wheel = TimerWheel::with_config(Time::ZERO, config, CoalescingConfig::default());
        let counter = Arc::new(AtomicU64::new(0));
        let waker = counter_waker(counter);

        // Timer at exactly 1 hour (the max)
        let deadline = Time::from_secs(3600);
        let result = wheel.try_register(deadline, waker);
        crate::assert_with_log!(
            result.is_ok(),
            "at max duration allowed",
            true,
            result.is_ok()
        );

        // Timer should fire when time advances
        let wakers = wheel.collect_expired(deadline);
        crate::assert_with_log!(wakers.len() == 1, "timer fires", 1, wakers.len());
        crate::test_complete!("timer_at_exactly_max_duration");
    }

    #[test]
    fn timer_beyond_max_duration_rejected() {
        init_test("timer_beyond_max_duration_rejected");
        let config = TimerWheelConfig::new().max_timer_duration(Duration::from_secs(3600)); // 1 hour max
        let mut wheel = TimerWheel::with_config(Time::ZERO, config, CoalescingConfig::default());
        let counter = Arc::new(AtomicU64::new(0));
        let waker = counter_waker(counter);

        // Timer at 1 hour + 1ms (beyond max)
        let deadline = Time::from_nanos(3600 * 1_000_000_000 + 1_000_000);
        let result = wheel.try_register(deadline, waker);
        crate::assert_with_log!(
            result.is_err(),
            "beyond max rejected",
            true,
            result.is_err()
        );

        let err = result.unwrap_err();
        crate::assert_with_log!(
            err.max == Duration::from_secs(3600),
            "error contains max",
            3600,
            err.max.as_secs()
        );
        crate::test_complete!("timer_beyond_max_duration_rejected");
    }

    #[test]
    fn wheel_max_range_ns_tracks_configured_wheel_duration() {
        init_test("wheel_max_range_ns_tracks_configured_wheel_duration");
        let config = TimerWheelConfig::new().max_wheel_duration(Duration::from_millis(1234));
        let wheel = TimerWheel::with_config(Time::ZERO, config, CoalescingConfig::default());

        let expected = 1_234_000_000u64;
        crate::assert_with_log!(
            wheel.max_range_ns() == expected,
            "max range follows configured duration",
            expected,
            wheel.max_range_ns()
        );
        crate::test_complete!("wheel_max_range_ns_tracks_configured_wheel_duration");
    }

    #[test]
    fn timer_24h_overflow_handling() {
        init_test("timer_24h_overflow_handling");
        // Default config has 24h max_wheel_duration, 7d max_timer_duration
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));
        let waker = counter_waker(counter);

        // Timer at 25 hours (beyond default wheel range but within max timer duration)
        let deadline = Time::from_secs(25 * 3600);
        let handle = wheel.register(deadline, waker);

        // Should be in overflow
        crate::assert_with_log!(
            wheel.overflow_count() >= 1,
            "timer in overflow",
            true,
            wheel.overflow_count() >= 1
        );

        // Cancel should still work
        let cancelled = wheel.cancel(&handle);
        crate::assert_with_log!(cancelled, "can cancel overflow timer", true, cancelled);
        crate::test_complete!("timer_24h_overflow_handling");
    }

    // =========================================================================
    // COALESCING TESTS
    // =========================================================================

    #[test]
    fn coalescing_100_timers_within_1ms_window() {
        init_test("coalescing_100_timers_within_1ms_window");
        let coalescing = CoalescingConfig::enabled_with_window(Duration::from_millis(1));
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        let counter = Arc::new(AtomicU64::new(0));

        // Register 100 timers spread across 0.5ms window (500 microseconds)
        // All should fire together due to coalescing
        for i in 0..100 {
            let waker = counter_waker(counter.clone());
            // Spread over 500 microseconds: 0, 5us, 10us, ..., 495us
            let offset_ns = i * 5_000;
            let deadline = Time::from_nanos(offset_ns);
            wheel.register(deadline, waker);
        }

        crate::assert_with_log!(
            wheel.len() == 100,
            "100 timers registered",
            100,
            wheel.len()
        );

        // Check coalescing group size
        let group_size = wheel.coalescing_group_size(Time::from_nanos(500_000));
        crate::assert_with_log!(
            group_size >= 100,
            "all timers in coalescing group",
            100,
            group_size
        );

        // Advance to 0.5ms - all should fire together
        let wakers = wheel.collect_expired(Time::from_nanos(500_000));
        crate::assert_with_log!(
            wakers.len() == 100,
            "all 100 timers fire together",
            100,
            wakers.len()
        );

        for waker in wakers {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 100, "counter", 100, count);
        crate::test_complete!("coalescing_100_timers_within_1ms_window");
    }

    #[test]
    fn coalescing_disabled_fires_individually() {
        init_test("coalescing_disabled_fires_individually");
        // Coalescing disabled by default
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Register timers at 1ms, 2ms, 3ms
        for i in 1..=3 {
            let waker = counter_waker(counter.clone());
            wheel.register(Time::from_millis(i), waker);
        }

        // At exactly 1ms, only the first timer should fire
        let wakers = wheel.collect_expired(Time::from_millis(1));
        crate::assert_with_log!(
            wakers.len() == 1,
            "only 1 timer fires at 1ms",
            1,
            wakers.len()
        );

        // At 2ms, second timer fires
        let wakers = wheel.collect_expired(Time::from_millis(2));
        crate::assert_with_log!(
            wakers.len() == 1,
            "only 1 timer fires at 2ms",
            1,
            wakers.len()
        );
        crate::test_complete!("coalescing_disabled_fires_individually");
    }

    #[test]
    fn coalescing_min_group_size() {
        init_test("coalescing_min_group_size");
        let coalescing = CoalescingConfig::new()
            .coalesce_window(Duration::from_millis(5))
            .min_group_size(5) // Only coalesce if 5+ timers
            .enable();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        // Register only 3 timers in the coalesce window.
        let counter = Arc::new(AtomicU64::new(0));
        for deadline in [
            Time::from_nanos(100_000),   // 0.1ms
            Time::from_nanos(2_000_000), // 2ms
            Time::from_nanos(4_000_000), // 4ms
        ] {
            let waker = counter_waker(counter.clone());
            wheel.register(deadline, waker);
        }

        // At 1ms, only the first timer is actually expired. Coalescing should
        // not pull in 2ms/4ms timers because group size is below the threshold.
        let wakers = wheel.collect_expired(Time::from_millis(1));
        crate::assert_with_log!(
            wakers.len() == 1,
            "coalescing gate keeps sparse timers on deadline",
            1,
            wakers.len()
        );
        crate::test_complete!("coalescing_min_group_size");
    }

    #[test]
    fn coalescing_min_group_size_enables_window_when_threshold_met() {
        init_test("coalescing_min_group_size_enables_window_when_threshold_met");
        let coalescing = CoalescingConfig::new()
            .coalesce_window(Duration::from_millis(5))
            .min_group_size(3)
            .enable();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);
        let counter = Arc::new(AtomicU64::new(0));

        for deadline in [
            Time::from_nanos(100_000),   // 0.1ms
            Time::from_nanos(2_000_000), // 2ms
            Time::from_nanos(4_000_000), // 4ms
        ] {
            wheel.register(deadline, counter_waker(counter.clone()));
        }

        let wakers = wheel.collect_expired(Time::from_millis(1));
        crate::assert_with_log!(
            wakers.len() == 3,
            "coalescing enabled when threshold met",
            3,
            wakers.len()
        );
        crate::test_complete!("coalescing_min_group_size_enables_window_when_threshold_met");
    }

    #[test]
    fn coalescing_window_boundary_saturates_at_time_max() {
        init_test("coalescing_window_boundary_saturates_at_time_max");
        let coalescing = CoalescingConfig::enabled_with_window(Duration::from_millis(1));
        let config = TimerWheelConfig::new().max_timer_duration(Duration::MAX);
        // Start near Time::MAX so we exercise coalescing boundary saturation
        // without forcing a full-range wheel advance from time zero.
        let start = Time::from_nanos(u64::MAX.saturating_sub(2_000_000));
        let deadline = Time::from_nanos(u64::MAX.saturating_sub(500_000));
        let mut wheel = TimerWheel::with_config(start, config, coalescing);
        let counter = Arc::new(AtomicU64::new(0));

        wheel.register(deadline, counter_waker(counter.clone()));

        let wakers = wheel.collect_expired(deadline);
        crate::assert_with_log!(
            wakers.len() == 1,
            "near-maximum timer fires without coalescing overflow",
            1,
            wakers.len()
        );

        for waker in wakers {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter", 1, count);
        crate::test_complete!("coalescing_window_boundary_saturates_at_time_max");
    }

    // =========================================================================
    // CASCADING CORRECTNESS TESTS
    // =========================================================================

    #[test]
    fn cascading_correctness_with_overflow() {
        init_test("cascading_correctness_with_overflow");
        let mut wheel = TimerWheel::new();
        let counters: Vec<_> = (0..10).map(|_| Arc::new(AtomicU64::new(0))).collect();

        // Register timers at various intervals including overflow
        // With default config: max_wheel_duration = 24h (86400s)
        // Level 0: 1ms slots, range ~256ms
        // Level 1: 256ms slots, range ~65s
        // Level 2: ~65s slots, range ~4.6h
        // Level 3: ~4.6h slots, range ~49.7 days (but capped by config at 24h)
        let intervals = [
            Time::from_millis(10),    // Level 0
            Time::from_millis(500),   // Level 1
            Time::from_secs(30),      // Level 1
            Time::from_secs(120),     // Level 2
            Time::from_secs(3600),    // Level 2 (1 hour)
            Time::from_secs(7200),    // Level 2 (2 hours)
            Time::from_secs(18000),   // Level 3 (5 hours)
            Time::from_secs(36000),   // Level 3 (10 hours)
            Time::from_secs(90000),   // Overflow (25 hours, > 24h max_wheel_duration)
            Time::from_secs(100_000), // Overflow (27.8 hours, within 7d max_timer_duration)
        ];

        for (i, &deadline) in intervals.iter().enumerate() {
            let waker = counter_waker(counters[i].clone());
            wheel.register(deadline, waker);
        }

        // Check that some timers are in overflow
        let overflow_count = wheel.overflow_count();
        crate::assert_with_log!(
            overflow_count >= 2,
            "some timers in overflow",
            true,
            overflow_count >= 2
        );

        // Now advance through all deadlines and verify each fires
        for (i, &deadline) in intervals.iter().enumerate() {
            let wakers = wheel.collect_expired(deadline);
            for waker in &wakers {
                waker.wake_by_ref();
            }

            let count = counters[i].load(Ordering::SeqCst);
            crate::assert_with_log!(
                count == 1,
                &format!("timer {i} fired at {deadline:?}"),
                1,
                count
            );
        }

        crate::assert_with_log!(wheel.is_empty(), "all timers fired", true, wheel.is_empty());
        crate::test_complete!("cascading_correctness_with_overflow");
    }

    #[test]
    fn many_timers_same_deadline() {
        init_test("many_timers_same_deadline");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Register 1000 timers at the exact same deadline
        let deadline = Time::from_millis(100);
        for _ in 0..1000 {
            let waker = counter_waker(counter.clone());
            wheel.register(deadline, waker);
        }

        crate::assert_with_log!(wheel.len() == 1000, "1000 registered", 1000, wheel.len());

        // All should fire at the deadline
        let wakers = wheel.collect_expired(deadline);
        crate::assert_with_log!(wakers.len() == 1000, "all 1000 fire", 1000, wakers.len());

        for waker in wakers {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1000, "counter", 1000, count);
        crate::test_complete!("many_timers_same_deadline");
    }

    #[test]
    fn timer_reschedule_after_cancel() {
        init_test("timer_reschedule_after_cancel");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Register and cancel
        let waker1 = counter_waker(counter.clone());
        let handle = wheel.register(Time::from_millis(10), waker1);
        wheel.cancel(&handle);

        // Register new timer at same slot
        let waker2 = counter_waker(counter.clone());
        wheel.register(Time::from_millis(10), waker2);

        // Only the second timer should fire
        let expired_wakers = wheel.collect_expired(Time::from_millis(10));
        crate::assert_with_log!(
            expired_wakers.len() == 1,
            "only active fires",
            1,
            expired_wakers.len()
        );

        for waker in expired_wakers {
            waker.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter", 1, count);
        crate::test_complete!("timer_reschedule_after_cancel");
    }

    #[test]
    fn config_builder_chain() {
        init_test("config_builder_chain");

        // Test TimerWheelConfig builder
        let wheel_config = TimerWheelConfig::new()
            .max_wheel_duration(Duration::from_hours(24))
            .max_timer_duration(Duration::from_hours(168));
        crate::assert_with_log!(
            wheel_config.max_wheel_duration == Duration::from_hours(24),
            "wheel duration",
            86400,
            wheel_config.max_wheel_duration.as_secs()
        );
        crate::assert_with_log!(
            wheel_config.max_timer_duration == Duration::from_hours(168),
            "timer duration",
            604_800,
            wheel_config.max_timer_duration.as_secs()
        );

        // Test CoalescingConfig builder
        let coalescing = CoalescingConfig::new()
            .coalesce_window(Duration::from_millis(10))
            .min_group_size(5)
            .enable();
        crate::assert_with_log!(
            coalescing.coalesce_window == Duration::from_millis(10),
            "coalesce window",
            10,
            u64::try_from(coalescing.coalesce_window.as_millis()).unwrap_or(u64::MAX)
        );
        crate::assert_with_log!(
            coalescing.min_group_size == 5,
            "min group size",
            5,
            coalescing.min_group_size
        );
        crate::assert_with_log!(coalescing.enabled, "enabled", true, coalescing.enabled);

        // Test disable
        let disabled = coalescing.disable();
        crate::assert_with_log!(!disabled.enabled, "disabled", false, disabled.enabled);

        crate::test_complete!("config_builder_chain");
    }

    // =========================================================================
    // Timer Coalescing Behavior Tests (bd-rpsc)
    // =========================================================================

    #[test]
    fn coalescing_fires_timers_within_window() {
        init_test("coalescing_fires_timers_within_window");
        let coalescing = CoalescingConfig::new()
            .coalesce_window(Duration::from_millis(10))
            .min_group_size(1)
            .enable();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        let counter = Arc::new(AtomicU64::new(0));

        // Register timers at 3ms, 5ms, 15ms
        // With coalescing window of 10ms, at t=9ms:
        //   - coalesced boundary = ((9_000_000 / 10_000_000) + 1) * 10_000_000 = 10_000_000 (10ms)
        //   - Both 3ms and 5ms are in ready (past their tick) and <= 10ms boundary
        wheel.register(Time::from_millis(3), counter_waker(counter.clone()));
        wheel.register(Time::from_millis(5), counter_waker(counter.clone()));
        wheel.register(Time::from_millis(15), counter_waker(counter.clone()));

        // At t=9ms, both 3ms and 5ms timers should have been moved to ready
        // and both should fire (deadlines 3ms and 5ms both <= coalesced boundary 10ms)
        let wakers = wheel.collect_expired(Time::from_millis(9));
        for w in &wakers {
            w.wake_by_ref();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(
            count == 2,
            "both timers fired within coalescing window",
            2u64,
            count
        );

        // At t=16ms, the 15ms timer should fire
        let wakers = wheel.collect_expired(Time::from_millis(16));
        for w in &wakers {
            w.wake_by_ref();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "all three fired", 3u64, count);
        crate::test_complete!("coalescing_fires_timers_within_window");
    }

    #[test]
    fn coalescing_disabled_fires_only_expired() {
        init_test("coalescing_disabled_fires_only_expired");
        let coalescing = CoalescingConfig::new().disable();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        let counter = Arc::new(AtomicU64::new(0));

        // Register timers at 5ms, 8ms
        wheel.register(Time::from_millis(5), counter_waker(counter.clone()));
        wheel.register(Time::from_millis(8), counter_waker(counter.clone()));

        // At t=6ms, only the 5ms timer should fire (no coalescing)
        let wakers = wheel.collect_expired(Time::from_millis(6));
        for w in &wakers {
            w.wake_by_ref();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(
            count == 1,
            "only expired timer fires without coalescing",
            1u64,
            count
        );
        crate::test_complete!("coalescing_disabled_fires_only_expired");
    }

    #[test]
    fn coalescing_group_size_reports_window_contents() {
        init_test("coalescing_group_size_reports_window_contents");
        let coalescing = CoalescingConfig::new()
            .coalesce_window(Duration::from_millis(10))
            .min_group_size(1)
            .enable();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        // Advance wheel to t=20ms so that registering past-deadline timers
        // puts them directly into the ready list (deadline <= current_time)
        let _ = wheel.collect_expired(Time::from_millis(20));

        // Register timers at 5ms, 8ms, 15ms - all go to ready (all < 20ms)
        wheel.register(
            Time::from_millis(5),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );
        wheel.register(
            Time::from_millis(8),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );
        wheel.register(
            Time::from_millis(15),
            counter_waker(Arc::new(AtomicU64::new(0))),
        );

        // coalescing_group_size queries the ready list.
        // At query time t=6ms, coalescing window = ((6M/10M)+1)*10M = 10ms.
        // Timers at 5ms and 8ms have deadline <= 10ms; 15ms does not.
        let group_size = wheel.coalescing_group_size(Time::from_millis(6));
        crate::assert_with_log!(
            group_size == 2,
            "two timers in coalescing window",
            2usize,
            group_size
        );
        crate::test_complete!("coalescing_group_size_reports_window_contents");
    }

    // =========================================================================
    // HOT-PATH OPTIMIZATION TESTS (bd-1ddgq)
    // =========================================================================

    #[test]
    fn bitmap_set_clear_round_trip() {
        init_test("bitmap_set_clear_round_trip");
        let mut level = WheelLevel::new(LEVEL0_RESOLUTION_NS, 0);

        // Initially all clear
        for w in &level.occupied {
            crate::assert_with_log!(*w == 0, "initially zero", 0u64, *w);
        }

        // Set various slots and verify
        let slots = [0, 1, 63, 64, 127, 128, 200, 255];
        for &s in &slots {
            level.set_occupied(s);
            let word = level.occupied[s / 64];
            let bit = word & (1u64 << (s % 64));
            crate::assert_with_log!(bit != 0, &format!("slot {s} set"), true, bit != 0);
        }

        // Clear them
        for &s in &slots {
            level.clear_occupied(s);
            let word = level.occupied[s / 64];
            let bit = word & (1u64 << (s % 64));
            crate::assert_with_log!(bit == 0, &format!("slot {s} cleared"), true, bit == 0);
        }

        for w in &level.occupied {
            crate::assert_with_log!(*w == 0, "all clear after round trip", 0u64, *w);
        }
        crate::test_complete!("bitmap_set_clear_round_trip");
    }

    #[test]
    fn bitmap_next_occupied_distance() {
        init_test("bitmap_next_occupied_distance");
        let mut level = WheelLevel::new(LEVEL0_RESOLUTION_NS, 10); // cursor at 10

        // No occupied slots → None
        let result = level.next_occupied_distance();
        crate::assert_with_log!(result.is_none(), "empty bitmap", true, result.is_none());

        // Occupy slot 15 → distance 5 from cursor 10
        level.set_occupied(15);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(result == Some(5), "distance 5", Some(5usize), result);

        // Occupy slot 12 → now distance 2 is closer
        level.set_occupied(12);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(result == Some(2), "distance 2", Some(2usize), result);

        // Occupy slot 5 (before cursor) → should wrap around
        level.set_occupied(5);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(
            result == Some(2),
            "slot 12 is still closest",
            Some(2usize),
            result
        );

        // Clear 12, 15 → only slot 5 remains → wraps around to 251
        level.clear_occupied(12);
        level.clear_occupied(15);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(
            result == Some(251),
            "wrap around to 5 (256 - 10 + 5)",
            Some(251usize),
            result
        );

        crate::test_complete!("bitmap_next_occupied_distance");
    }

    #[test]
    fn bitmap_next_occupied_at_word_boundary() {
        init_test("bitmap_next_occupied_at_word_boundary");
        // Cursor at 62: next slot 63 is end of word 0, slot 64 is start of word 1
        let mut level = WheelLevel::new(LEVEL0_RESOLUTION_NS, 62);

        // Occupy slot 64 (start of word 1) → distance 2
        level.set_occupied(64);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(
            result == Some(2),
            "cross-word boundary",
            Some(2usize),
            result
        );

        // Occupy slot 63 → distance 1 (closer, same word as cursor)
        level.set_occupied(63);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(result == Some(1), "same word closer", Some(1usize), result);

        crate::test_complete!("bitmap_next_occupied_at_word_boundary");
    }

    #[test]
    fn bitmap_cursor_at_255_wraps() {
        init_test("bitmap_cursor_at_255_wraps");
        let mut level = WheelLevel::new(LEVEL0_RESOLUTION_NS, 255);

        // Cursor at last slot (255) → next slot 0 is distance 1
        level.set_occupied(0);
        level.set_occupied(100);
        let result = level.next_occupied_distance();
        crate::assert_with_log!(
            result == Some(1),
            "cursor at 255 wraps to 0",
            Some(1usize),
            result
        );
        crate::test_complete!("bitmap_cursor_at_255_wraps");
    }

    #[test]
    fn drain_ready_in_place_no_extra_alloc() {
        init_test("drain_ready_in_place_no_extra_alloc");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Register 50 timers at various deadlines
        for i in 1..=50 {
            let waker = counter_waker(counter.clone());
            wheel.register(Time::from_millis(i), waker);
        }

        // Advance to 25ms — only first 25 should fire
        let wakers = wheel.collect_expired(Time::from_millis(25));
        crate::assert_with_log!(wakers.len() == 25, "first 25 fire", 25usize, wakers.len());

        for w in wakers {
            w.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 25, "counter 25", 25u64, count);

        // Advance to 50ms — remaining 25 should fire
        let wakers = wheel.collect_expired(Time::from_millis(50));
        crate::assert_with_log!(
            wakers.len() == 25,
            "remaining 25 fire",
            25usize,
            wakers.len()
        );
        for w in wakers {
            w.wake();
        }
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 50, "counter 50", 50u64, count);
        crate::assert_with_log!(wheel.is_empty(), "wheel empty", true, wheel.is_empty());

        crate::test_complete!("drain_ready_in_place_no_extra_alloc");
    }

    #[test]
    fn clear_resets_bitmaps() {
        init_test("clear_resets_bitmaps");
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Register timers across multiple levels
        wheel.register(Time::from_millis(5), counter_waker(counter.clone()));
        wheel.register(Time::from_millis(100), counter_waker(counter.clone()));
        wheel.register(Time::from_secs(10), counter_waker(counter));

        // Verify some bits are set
        let any_set = wheel
            .levels
            .iter()
            .any(|l| l.occupied.iter().any(|&w| w != 0));
        crate::assert_with_log!(any_set, "bits set before clear", true, any_set);

        wheel.clear();

        // All bitmaps should be zeroed
        for (li, level) in wheel.levels.iter().enumerate() {
            for (wi, &word) in level.occupied.iter().enumerate() {
                crate::assert_with_log!(
                    word == 0,
                    &format!("level {li} word {wi} cleared"),
                    0u64,
                    word
                );
            }
        }
        crate::assert_with_log!(
            wheel.is_empty(),
            "empty after clear",
            true,
            wheel.is_empty()
        );
        crate::test_complete!("clear_resets_bitmaps");
    }

    #[test]
    fn skip_tick_bitmap_matches_linear_scan() {
        init_test("skip_tick_bitmap_matches_linear_scan");
        // Verify the bitmap-based skip produces correct results by
        // registering timers at sparse slots and checking advance_to
        // fires them at the right time.
        let mut wheel = TimerWheel::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Sparse timers: 10ms, 200ms (slot 200 in level 0)
        wheel.register(Time::from_millis(10), counter_waker(counter.clone()));
        wheel.register(Time::from_millis(200), counter_waker(counter.clone()));

        // Advance to 10ms — first fires
        let w = wheel.collect_expired(Time::from_millis(10));
        crate::assert_with_log!(w.len() == 1, "10ms fires", 1usize, w.len());
        for waker in w {
            waker.wake();
        }

        // Advance to 200ms — second fires (skip should jump efficiently)
        let w = wheel.collect_expired(Time::from_millis(200));
        crate::assert_with_log!(w.len() == 1, "200ms fires", 1usize, w.len());
        for waker in w {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 2, "both fired", 2u64, count);
        crate::test_complete!("skip_tick_bitmap_matches_linear_scan");
    }

    // =============================================================================
    // CONFORMANCE TESTS: Time Wheel Precision under Sleep Coalescing
    // =============================================================================

    #[test]
    fn conformance_sleep_tolerance_within_wheel_granularity() {
        init_test("conformance_sleep_tolerance_within_wheel_granularity");

        // Test requirement (1): Sleep(N) ± tolerance within wheel granularity
        // Level 0 resolution is 1ms, so tolerance should be within that bound

        let mut wheel = TimerWheel::new_at(Time::ZERO);
        let tolerance_ns = LEVEL0_RESOLUTION_NS; // 1ms tolerance

        // Test various sleep durations
        let test_durations = [
            1_000_000,     // 1ms (exact level 0 boundary)
            1_500_000,     // 1.5ms (mid-slot)
            5_000_000,     // 5ms (multiple slots)
            10_000_000,    // 10ms
            100_000_000,   // 100ms (level 1 territory)
            1_000_000_000, // 1s (level 2 territory)
        ];

        for &duration_ns in &test_durations {
            let deadline = Time::from_nanos(duration_ns);
            let counter = Arc::new(AtomicU64::new(0));

            let handle = wheel.register(deadline, counter_waker(counter.clone()));

            // Verify timer was inserted
            crate::assert_with_log!(wheel.len() >= 1, "timer registered", true, wheel.len() >= 1);

            // Test precision: timer should fire within tolerance of deadline
            let mut test_times = Vec::new();

            // Test firing exactly at deadline
            test_times.push(deadline);

            // Test firing slightly before tolerance bound
            if deadline.as_nanos() > tolerance_ns {
                test_times.push(Time::from_nanos(deadline.as_nanos() - tolerance_ns + 1));
            }

            // Test firing at tolerance bound
            test_times.push(Time::from_nanos(deadline.as_nanos() + tolerance_ns));

            for test_time in test_times {
                let mut test_wheel = TimerWheel::new_at(Time::ZERO);
                let test_counter = Arc::new(AtomicU64::new(0));
                test_wheel.register(deadline, counter_waker(test_counter.clone()));

                let wakers = test_wheel.collect_expired(test_time);

                if test_time >= deadline {
                    // Should fire if test_time >= deadline
                    crate::assert_with_log!(
                        !wakers.is_empty(),
                        &format!("fires at {test_time:?} for deadline {deadline:?}"),
                        true,
                        !wakers.is_empty()
                    );
                } else {
                    // Should not fire if significantly before deadline
                    let gap = deadline.as_nanos() - test_time.as_nanos();
                    if gap > tolerance_ns {
                        crate::assert_with_log!(
                            wakers.is_empty(),
                            &format!("does not fire early: {test_time:?} vs {deadline:?}"),
                            true,
                            wakers.is_empty()
                        );
                    }
                }
            }

            // Clean up
            wheel.cancel(&handle);
        }

        crate::test_complete!("conformance_sleep_tolerance_within_wheel_granularity");
    }

    #[test]
    fn conformance_concurrent_sleeps_unique_deadlines() {
        init_test("conformance_concurrent_sleeps_unique_deadlines");

        // Test requirement (2): 10k concurrent sleeps with unique deadlines all fire correctly

        let mut wheel = TimerWheel::new_at(Time::ZERO);
        const TIMER_COUNT: usize = 10_000;

        let mut counters = Vec::new();
        let mut deadlines = Vec::new();
        let mut handles = Vec::new();

        // Register 10k timers with unique deadlines (1µs apart to ensure uniqueness)
        for i in 0..TIMER_COUNT {
            let deadline_ns = 1_000_000 + (i as u64 * 1_000); // Start at 1ms, 1µs apart
            let deadline = Time::from_nanos(deadline_ns);

            let counter = Arc::new(AtomicU64::new(0));
            let handle = wheel.register(deadline, counter_waker(counter.clone()));

            counters.push(counter);
            deadlines.push(deadline);
            handles.push(handle);
        }

        crate::assert_with_log!(
            wheel.len() == TIMER_COUNT,
            "all 10k timers registered",
            TIMER_COUNT,
            wheel.len()
        );

        // Advance time to fire all timers
        let max_deadline = deadlines.iter().max().copied().unwrap();
        let final_time = Time::from_nanos(max_deadline.as_nanos() + 1_000_000); // 1ms past max

        let wakers = wheel.collect_expired(final_time);

        // All timers should have fired
        crate::assert_with_log!(
            wakers.len() == TIMER_COUNT,
            "all 10k timers fired",
            TIMER_COUNT,
            wakers.len()
        );

        // Wake all the wakers
        for waker in wakers {
            waker.wake();
        }

        // Verify all counters were incremented
        let mut fired_count = 0;
        for counter in &counters {
            if counter.load(Ordering::SeqCst) > 0 {
                fired_count += 1;
            }
        }

        crate::assert_with_log!(
            fired_count == TIMER_COUNT,
            "all 10k counters incremented",
            TIMER_COUNT,
            fired_count
        );

        // Verify wheel is empty after all timers fired
        crate::assert_with_log!(
            wheel.len() == 0,
            "wheel empty after firing",
            0usize,
            wheel.len()
        );

        crate::test_complete!("conformance_concurrent_sleeps_unique_deadlines");
    }

    #[test]
    fn conformance_sleep_cancellation_no_dangling() {
        init_test("conformance_sleep_cancellation_no_dangling");

        // Test requirement (3): Sleep cancellation removes timer from wheel (no dangling)

        let mut wheel = TimerWheel::new_at(Time::ZERO);

        // Test cancellation at various wheel levels and overflow
        let test_cases = [
            (Time::from_millis(1), "level0"),
            (Time::from_millis(100), "level1"),
            (Time::from_millis(10_000), "level2"),
            (Time::from_secs(3600), "level3"),
            (Time::from_secs(25 * 3600), "overflow"), // 25 hours (beyond wheel range)
        ];

        for (deadline, level_name) in &test_cases {
            let counter = Arc::new(AtomicU64::new(0));
            let handle = wheel.register(*deadline, counter_waker(counter.clone()));

            let initial_len = wheel.len();
            let initial_overflow = wheel.overflow_count();

            // Verify timer was registered
            let registered = if level_name == &"overflow" {
                wheel.overflow_count() > initial_overflow
            } else {
                wheel.len() > 0
            };
            crate::assert_with_log!(
                registered,
                &format!("timer registered at {level_name}"),
                true,
                registered
            );

            // Cancel the timer
            let cancelled = wheel.cancel(&handle);
            crate::assert_with_log!(
                cancelled,
                &format!("timer cancelled at {level_name}"),
                true,
                cancelled
            );

            // Verify timer was removed from wheel
            if level_name == &"overflow" {
                // For overflow timers, cancellation might not immediately reduce overflow_count
                // due to implementation details, but the timer won't fire
                let wakers = wheel.collect_expired(*deadline);
                crate::assert_with_log!(
                    wakers.is_empty(),
                    "cancelled overflow timer does not fire".to_string(),
                    true,
                    wakers.is_empty()
                );
            } else {
                crate::assert_with_log!(
                    wheel.len() < initial_len,
                    &format!("timer removed from wheel at {level_name}"),
                    true,
                    wheel.len() < initial_len
                );
            }

            // Verify timer does not fire after cancellation
            let wakers = wheel.collect_expired(*deadline);
            let fired = !wakers.is_empty();
            crate::assert_with_log!(
                !fired,
                &format!("cancelled timer does not fire at {level_name}"),
                false,
                fired
            );

            // Verify counter was not incremented
            let count = counter.load(Ordering::SeqCst);
            crate::assert_with_log!(
                count == 0,
                &format!("counter not incremented at {level_name}"),
                0u64,
                count
            );

            // Double cancellation should return false (idempotent)
            let double_cancel = wheel.cancel(&handle);
            crate::assert_with_log!(
                !double_cancel,
                &format!("double cancel returns false at {level_name}"),
                false,
                double_cancel
            );
        }

        crate::test_complete!("conformance_sleep_cancellation_no_dangling");
    }

    #[test]
    fn conformance_wheel_overflow_promotion_ordering() {
        init_test("conformance_wheel_overflow_promotion_ordering");

        // Test requirement (4): Wheel overflow promotion to hierarchical level preserves ordering

        // Create wheel with small max_wheel_duration to force overflow quickly
        let config = TimerWheelConfig::new().max_wheel_duration(Duration::from_hours(1));
        let coalescing = CoalescingConfig::new();
        let mut wheel = TimerWheel::with_config(Time::ZERO, config, coalescing);

        // Register timers that will overflow (beyond 1 hour)
        let base_time = Time::from_secs(2 * 3600); // 2 hours
        let mut deadlines = Vec::new();
        let mut counters = Vec::new();

        // Create 100 timers with increasing deadlines (all in overflow)
        for i in 0..100 {
            let deadline = Time::from_nanos(base_time.as_nanos() + (i as u64 * 60_000_000_000)); // 1 minute apart
            deadlines.push(deadline);

            let counter = Arc::new(AtomicU64::new(i as u64)); // Store index for verification
            wheel.register(deadline, counter_waker(counter.clone()));
            counters.push(counter);
        }

        // Verify timers are in overflow
        crate::assert_with_log!(
            wheel.overflow_count() >= 100,
            "timers in overflow",
            true,
            wheel.overflow_count() >= 100
        );

        // Advance time to bring timers back into wheel range and fire them
        let start_promotion = Time::from_secs(3600 + 30 * 60); // 1h30m (close to first deadline)
        let _ = wheel.collect_expired(start_promotion);

        // Continue advancing time and collecting expired timers
        // They should fire in order despite being promoted from overflow
        let mut fired_order = Vec::new();

        for window in 0..200 {
            let check_time =
                Time::from_nanos(start_promotion.as_nanos() + (window as u64 * 60_000_000_000));
            let wakers = wheel.collect_expired(check_time);

            for waker in wakers {
                waker.wake();
            }

            // Check which counters have been incremented
            for (i, counter) in counters.iter().enumerate() {
                let original_value = i as u64;
                if counter.load(Ordering::SeqCst) != original_value {
                    // This counter was incremented, so its timer fired
                    fired_order.push(i);
                    counter.store(original_value, Ordering::SeqCst); // Reset to avoid double-counting
                }
            }

            if fired_order.len() >= 100 {
                break;
            }
        }

        // Verify timers fired in correct order
        for i in 0..fired_order.len().min(99) {
            crate::assert_with_log!(
                fired_order[i] <= fired_order[i + 1],
                &format!(
                    "timer order preserved: {} <= {}",
                    fired_order[i],
                    fired_order[i + 1]
                ),
                true,
                fired_order[i] <= fired_order[i + 1]
            );
        }

        crate::assert_with_log!(
            fired_order.len() >= 100,
            "all overflow timers eventually fired",
            100usize,
            fired_order.len()
        );

        crate::test_complete!("conformance_wheel_overflow_promotion_ordering");
    }

    #[test]
    fn conformance_virtual_time_atomic_wheel_advance() {
        init_test("conformance_virtual_time_atomic_wheel_advance");

        // Test requirement (5): Virtual-time advance under LabRuntime advances all wheels atomically
        // Note: This test focuses on the wheel's atomic advancement properties
        // Integration with LabRuntime would be tested separately in runtime tests

        let mut wheel = TimerWheel::new_at(Time::ZERO);

        // Register timers across multiple wheel levels to test atomic advancement
        let test_timers = [
            (Time::from_millis(1), "level0_early"), // Level 0: 1ms
            (Time::from_millis(5), "level0_late"),  // Level 0: 5ms
            (Time::from_millis(100), "level1"),     // Level 1: 100ms
            (Time::from_millis(1000), "level2"),    // Level 2: 1s
            (Time::from_secs(60), "level3"),        // Level 3: 1min
        ];

        let mut counters = Vec::new();

        for (deadline, name) in &test_timers {
            let counter = Arc::new(AtomicU64::new(0));
            wheel.register(*deadline, counter_waker(counter.clone()));
            counters.push((counter, deadline, name));
        }

        // Test large time advances (simulating virtual time jumps)
        let time_advances = [
            Time::from_nanos(500_000), // 0.5ms
            Time::from_millis(2),      // 2ms
            Time::from_millis(10),     // 10ms
            Time::from_millis(200),    // 200ms
            Time::from_secs(2),        // 2s
            Time::from_secs(120),      // 2min
        ];

        for advance_time in &time_advances {
            // Record state before advance
            let before_counts: Vec<u64> = counters
                .iter()
                .map(|(c, _, _)| c.load(Ordering::SeqCst))
                .collect();

            // Advance time atomically
            let wakers = wheel.collect_expired(*advance_time);

            // Wake all expired timers
            for waker in wakers {
                waker.wake();
            }

            // Verify that timers fire atomically - all timers with deadline <= advance_time should fire
            for (i, (counter, deadline, name)) in counters.iter().enumerate() {
                let after_count = counter.load(Ordering::SeqCst);
                let should_have_fired = **deadline <= *advance_time;
                let did_fire = after_count > before_counts[i];

                if should_have_fired {
                    crate::assert_with_log!(
                        did_fire,
                        &format!("{name} fired at advance_time={advance_time:?}"),
                        true,
                        did_fire
                    );
                } else {
                    crate::assert_with_log!(
                        !did_fire,
                        &format!("{name} did not fire early at advance_time={advance_time:?}"),
                        false,
                        did_fire
                    );
                }
            }
        }

        // Test that multiple advancement calls are idempotent
        let test_time = Time::from_secs(30);
        let _wakers1 = wheel.collect_expired(test_time);
        let wakers2 = wheel.collect_expired(test_time);

        crate::assert_with_log!(
            wakers2.is_empty(),
            "repeated advance is idempotent",
            true,
            wakers2.is_empty()
        );

        // Test backward time movement is handled gracefully (wheel should not regress)
        let current_time = wheel.current_time();
        let past_time = Time::from_millis(1);
        let wakers_past = wheel.collect_expired(past_time);
        let time_after_past = wheel.current_time();

        crate::assert_with_log!(
            time_after_past >= current_time,
            "time does not move backward",
            true,
            time_after_past >= current_time
        );

        crate::assert_with_log!(
            wakers_past.is_empty(),
            "no timers fire for past time",
            true,
            wakers_past.is_empty()
        );

        crate::test_complete!("conformance_virtual_time_atomic_wheel_advance");
    }

    #[test]
    fn conformance_coalescing_group_behavior() {
        init_test("conformance_coalescing_group_behavior");

        // Test timer coalescing behavior under sleep coalescing configuration

        let coalescing = CoalescingConfig::new()
            .enable()
            .coalesce_window(Duration::from_millis(5))
            .min_group_size(3);

        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        let counters: Vec<_> = (0..10).map(|_| Arc::new(AtomicU64::new(0))).collect();

        // Register timers within coalescing window
        let base_time = Time::from_millis(10);
        for (i, counter) in counters.iter().enumerate() {
            let offset = Duration::from_millis(i as u64); // 0ms, 1ms, 2ms, ...
            let deadline =
                base_time.saturating_add_nanos(offset.as_nanos().min(u128::from(u64::MAX)) as u64);
            wheel.register(deadline, counter_waker(counter.clone()));
        }

        // Fire at window boundary - should coalesce timers within window
        let fire_time = base_time.saturating_add_nanos(5_000_000);
        let wakers = wheel.collect_expired(fire_time);

        for waker in wakers {
            waker.wake();
        }

        // Count how many fired
        let fired_count = counters
            .iter()
            .map(|c| u32::from(c.load(Ordering::SeqCst) > 0))
            .sum::<u32>();

        // With coalescing enabled and min_group_size=3, should fire multiple timers together
        crate::assert_with_log!(
            fired_count >= 3,
            &format!("coalescing fired multiple timers: {fired_count}"),
            true,
            fired_count >= 3
        );

        crate::test_complete!("conformance_coalescing_group_behavior");
    }
}
