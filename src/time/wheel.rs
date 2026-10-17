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
//! is reached, never before their own deadlines. This is useful for reducing CPU
//! overhead when many timers have similar deadlines.
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

/// Cancelled entries tolerated beyond twice the live timers before
/// `TimerWheel::cancel` compacts stored entries.
const COMPACTION_SLACK: usize = 1024;
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

/// The end of the coalescing window that holds `time`: the first multiple of
/// `window` at or after it. Windows are `(end - window, end]`. `None` when
/// that end is past `Time::MAX`; such a timer is not coalesced.
#[inline]
fn window_end(time: Time, window: u64) -> Option<Time> {
    time.as_nanos()
        .div_ceil(window)
        .checked_mul(window)
        .map(Time::from_nanos)
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
/// at the window boundary rather than at their individual deadlines. The
/// boundary is the end of the window, so a coalesced timer never fires
/// before its deadline; it can fire up to one window later.
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    /// Timers within this window fire together.
    ///
    /// Default: 1ms
    pub coalesce_window: Duration,

    /// Minimum number of timers in a window before coalescing takes effect.
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
    range_ns: u64,
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
            range_ns: resolution_ns.saturating_mul(SLOTS_PER_LEVEL as u64),
            cursor,
            occupied: [0u64; BITMAP_WORDS],
        }
    }

    fn range_ns(&self) -> u64 {
        self.range_ns
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
        self.next_occupied_offset(1)
    }

    /// Returns the smallest offset in `from..=SLOTS_PER_LEVEL` whose slot,
    /// `(cursor + offset) % SLOTS_PER_LEVEL`, is occupied (offset
    /// `SLOTS_PER_LEVEL` is the cursor's own slot), scanning the bitmap a
    /// word at a time.
    fn next_occupied_offset(&self, from: usize) -> Option<usize> {
        if self.occupied == [0; BITMAP_WORDS] {
            return None;
        }
        let mut offset = from;
        while offset <= SLOTS_PER_LEVEL {
            let slot = (self.cursor + offset) % SLOTS_PER_LEVEL;
            // The slots from `slot` to the end of its word have consecutive
            // offsets: the wrap from slot 255 to slot 0 is a word boundary.
            let masked = self.occupied[slot / 64] >> (slot % 64);
            if masked != 0 {
                let found = offset + masked.trailing_zeros() as usize;
                // Past SLOTS_PER_LEVEL lies beyond the cursor's own slot.
                return (found <= SLOTS_PER_LEVEL).then_some(found);
            }
            offset += 64 - slot % 64;
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
    /// Cancellations since stored entries were last compacted. A cancelled
    /// entry stays in its slot until the slot is visited, which for a
    /// higher-level or overflow timer can be minutes or days; this bounds how
    /// many accumulate (br-asupersync-m85zfi).
    cancelled_since_compaction: usize,
    /// With `Some`, the wakers of the entries this wheel drops (cancelled,
    /// stale or cleared) are kept here until [`Self::take_dropped_wakers`];
    /// with `None` they drop in place. See
    /// [`Self::with_deferred_waker_drops`].
    dropped_wakers: Option<WakerBatch>,
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
            cancelled_since_compaction: 0,
            dropped_wakers: None,
        }
    }

    /// Makes the wheel keep the wakers of the entries it drops (cancelled,
    /// stale or cleared) for [`Self::take_dropped_wakers`], instead of
    /// dropping them in place.
    ///
    /// A waker can own the last reference to a task, and dropping that task
    /// drops its futures; a `Sleep` among them cancels its timer, which
    /// re-enters whatever lock guards this wheel. The timer driver guards it
    /// with a mutex, so it drops these wakers only after releasing that mutex
    /// (br-asupersync-m85zfi LOW 5).
    #[must_use]
    pub(crate) fn with_deferred_waker_drops(mut self) -> Self {
        self.dropped_wakers = Some(WakerBatch::new());
        self
    }

    /// Takes the wakers of the entries dropped since the last call, for the
    /// caller to drop once it has released its lock. Always empty unless the
    /// wheel was built with [`Self::with_deferred_waker_drops`].
    #[must_use]
    pub(crate) fn take_dropped_wakers(&mut self) -> WakerBatch {
        self.dropped_wakers
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Disposes of an entry the wheel no longer stores: its waker is kept
    /// for [`Self::take_dropped_wakers`] when drops are deferred, and drops
    /// here otherwise.
    fn discard(&mut self, entry: TimerEntry) {
        if let Some(dropped) = self.dropped_wakers.as_mut() {
            dropped.push(entry.waker);
        }
    }

    /// Discards every stored entry: ready, overflow and every slot.
    fn discard_stored_entries(&mut self) {
        let Self {
            ready,
            overflow,
            levels,
            dropped_wakers,
            ..
        } = self;
        if let Some(dropped) = dropped_wakers.as_mut() {
            dropped.extend(ready.drain(..).map(|entry| entry.waker));
            dropped.extend(overflow.drain().map(|entry| entry.entry.waker));
        } else {
            ready.clear();
            overflow.clear();
        }
        for level in levels.iter_mut() {
            for slot in &mut level.slots {
                match dropped_wakers.as_mut() {
                    Some(dropped) => dropped.extend(slot.drain(..).map(|entry| entry.waker)),
                    None => slot.clear(),
                }
            }
            level.occupied = [0u64; BITMAP_WORDS];
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
        self.discard_stored_entries();
        self.cancelled_since_compaction = 0;
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
        self.insert_validated(deadline, waker, current)
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
        Ok(self.insert_validated(deadline, waker, current))
    }

    /// Inserts a timer whose deadline has already been validated/clamped by
    /// the caller. Avoids a redundant `current_time()` read on the hot path.
    fn insert_validated(&mut self, deadline: Time, waker: Waker, current: Time) -> TimerHandle {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);

        let id = self.active.insert(generation) as u64;

        let entry = TimerEntry {
            deadline,
            waker,
            id,
            generation,
        };

        self.insert_entry_at(entry, current);

        TimerHandle { id, generation }
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
            } else {
                self.cancelled_since_compaction += 1;
                if self.cancelled_since_compaction > self.active.len() * 2 + COMPACTION_SLACK {
                    self.compact_inactive_storage();
                }
            }
            true
        } else {
            false
        }
    }

    /// Returns the earliest time at which a pending timer fires, if any.
    ///
    /// With coalescing, a timer whose window holds a group fires at the end
    /// of that window, which is at or after its own deadline, so that end is
    /// reported for it.
    #[must_use]
    pub fn next_deadline(&mut self) -> Option<Time> {
        let raw = self.raw_next_deadline()?;
        let Some(window) = self.coalescing_window_ns() else {
            return Some(raw);
        };
        let current = self.current_time();
        if raw <= current {
            // Something is due. It waits only when every due timer sits in
            // the current window and that window holds a group.
            let Some(end) = window_end(current, window) else {
                return Some(current);
            };
            let all_due_wait = end > current
                && self.window_holds_group(end, window)
                && self
                    .ready
                    .iter()
                    .filter(|entry| self.is_live(entry) && entry.deadline <= current)
                    .all(|entry| window_end(entry.deadline, window) == Some(end));
            return Some(if all_due_wait { end } else { current });
        }
        match window_end(raw, window) {
            Some(end) if end > raw && self.window_holds_group(end, window) => Some(end),
            _ => Some(raw),
        }
    }

    /// The earliest live deadline, clamped to the current time when a timer
    /// is already due; ignores coalescing.
    fn raw_next_deadline(&mut self) -> Option<Time> {
        let current = self.current_time();
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

        // Take the minimum across ALL levels. Early-returning after the first
        // level that yields a candidate is unsound: levels are not
        // deadline-ordered near cursor-wrap boundaries. A level-1 slot that
        // has not cascaded yet can hold an entry whose deadline is EARLIER
        // than a wrapped-around level-0 entry (e.g. at tick 200: level 1 slot
        // 1 holds deadline-tick 300 awaiting the tick-256 cascade, while level
        // 0 holds a wrapped entry at tick 400). Reporting the level-0 minimum
        // would make the driver oversleep and fire the level-1 timer late.
        //
        // Within one level the slots ARE ordered: an entry stored at level k
        // has its level-k tick within one revolution ahead of the level's
        // cursor (cascades keep every cursor at the current tick), so the
        // slots from `cursor + 1` around to `cursor` itself hold strictly
        // increasing ticks. The first slot there holding a live entry holds
        // the level's earliest deadline; later slots need not be scanned, and
        // slots holding only cancelled entries are skipped
        // (br-asupersync-m85zfi). The bitmap yields the occupied slots a word
        // at a time: testing every slot's bit, 4 x 256 tests per call on a
        // sparse wheel, was most of this function's cost in a parking
        // receiver (br-asupersync-dfdwyt).
        for level in &self.levels {
            let mut from = 1;
            while let Some(offset) = level.next_occupied_offset(from) {
                let slot = (level.cursor + offset) % SLOTS_PER_LEVEL;
                let earliest = level.slots[slot]
                    .iter()
                    .filter(|entry| self.is_live(entry))
                    .map(|entry| entry.deadline)
                    .min();
                if let Some(deadline) = earliest {
                    min_deadline = Some(min_deadline.map_or(deadline, |c| c.min(deadline)));
                    break;
                }
                from = offset + 1;
            }
        }

        while let Some(entry) = self.overflow.peek() {
            if self.is_live(&entry.entry) {
                min_deadline = Some(min_deadline.map_or(entry.deadline, |c| c.min(entry.deadline)));
                break;
            }
            if let Some(stale) = self.overflow.pop() {
                self.discard(stale.entry);
            }
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
        self.insert_entry_at(entry, current);
    }

    fn insert_entry_at(&mut self, entry: TimerEntry, current: Time) {
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
            if target_tick == self.current_tick.saturating_add(1)
                && self.can_fast_advance_one_no_ready_tick(target_tick)
            {
                self.current_tick = target_tick;
                self.levels[0].cursor = (self.levels[0].cursor + 1) % SLOTS_PER_LEVEL;
                continue;
            }

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

    fn can_fast_advance_one_no_ready_tick(&self, target_tick: u64) -> bool {
        let next_cursor = (self.levels[0].cursor + 1) % SLOTS_PER_LEVEL;
        if next_cursor == 0 || self.levels[0].is_occupied(next_cursor) {
            return false;
        }

        if let Some(entry) = self.overflow.peek() {
            let min_enter_ns = entry
                .deadline
                .as_nanos()
                .saturating_sub(self.max_range_ns());
            let min_enter_tick = min_enter_ns / LEVEL0_RESOLUTION_NS;
            if min_enter_tick <= target_tick {
                return false;
            }
        }

        true
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
            } else {
                self.discard(entry);
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
                self.discard(entry);
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
            // A due entry always leaves overflow, even with a zero
            // max_wheel_duration (fqdvqn): insert_entry sends it to `ready`.
            if delta < max_range || delta == 0 {
                let entry = self.overflow.pop().expect("peeked entry missing");
                if self.is_live(&entry.entry) {
                    self.insert_entry(entry.entry);
                } else {
                    self.discard(entry.entry);
                }
            } else {
                break;
            }
        }
    }

    fn drain_ready(&mut self, now: Time) -> WakerBatch {
        if self.ready.is_empty() {
            return WakerBatch::new();
        }

        // With coalescing, a due timer in the current window waits for that
        // window's end when the window holds a group: a coalesced timer fires
        // at the first window boundary at or after its deadline, never before
        // it (br-asupersync-m85zfi LOW 3).
        let held_window = self.coalescing_window_ns().and_then(|window| {
            let end = window_end(now, window)?;
            (end > now && self.window_holds_group(end, window)).then_some((end, window))
        });

        let mut wakers = WakerBatch::new();

        // Take the ready vec out so we can mutate it in-place while also
        // accessing self.active through &mut self.
        let mut ready = std::mem::take(&mut self.ready);

        // Process in-place efficiently using drain — no separate `remaining` allocation.
        #[allow(clippy::iter_with_drain)]
        for entry in ready.drain(..) {
            if !self.is_live(&entry) {
                self.discard(entry);
                continue;
            }

            if entry.deadline > now {
                self.insert_entry(entry);
            } else if held_window
                .is_some_and(|(end, window)| window_end(entry.deadline, window) == Some(end))
            {
                self.ready.push(entry);
            } else {
                self.active.remove(entry.id as usize);
                wakers.push(entry.waker);
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

    /// Returns coalescing statistics: how many timers fire together.
    ///
    /// With coalescing on, this is the group of the window that contains
    /// `now` when that window holds at least `min_group_size` timers;
    /// otherwise it is the number of timers already due at `now`. This is
    /// useful for monitoring coalescing effectiveness.
    #[must_use]
    pub fn coalescing_group_size(&self, now: Time) -> usize {
        let due = self
            .ready
            .iter()
            .filter(|e| self.is_live(e) && e.deadline <= now)
            .count();
        let Some(window) = self.coalescing_window_ns() else {
            return due;
        };
        let Some(end) = window_end(now, window) else {
            return due;
        };
        let group = self.window_group_count(end, window);
        if group >= self.coalescing.min_group_size.max(1) {
            group
        } else {
            due
        }
    }

    /// The coalescing window in nanoseconds, when coalescing is on.
    fn coalescing_window_ns(&self) -> Option<u64> {
        if !self.coalescing.enabled {
            return None;
        }
        let window = self
            .coalescing
            .coalesce_window
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        (window > 0).then_some(window)
    }

    /// Whether the window ending at `end` holds at least `min_group_size`
    /// live timers.
    fn window_holds_group(&self, end: Time, window: u64) -> bool {
        self.window_group_count(end, window) >= self.coalescing.min_group_size.max(1)
    }

    /// The live timers whose deadline falls in the window `(end - window, end]`.
    fn window_group_count(&self, end: Time, window: u64) -> usize {
        let end_ns = end.as_nanos();
        let start_ns = end_ns.saturating_sub(window);
        let in_window = |deadline: Time| {
            let ns = deadline.as_nanos();
            ns > start_ns && ns <= end_ns
        };
        let mut count = self
            .ready
            .iter()
            .filter(|e| self.is_live(e) && in_window(e.deadline))
            .count();

        // Timers not yet due sit in the slots from the current tick up to the
        // window end.
        for level in &self.levels {
            let now_nanos = self.current_tick.saturating_mul(LEVEL0_RESOLUTION_NS);
            let level_tick_current = now_nanos / level.resolution_ns;
            let level_tick_end = end_ns / level.resolution_ns;

            if level_tick_end < level_tick_current {
                continue;
            }

            let current_slot = (level_tick_current % (SLOTS_PER_LEVEL as u64)) as usize;
            // Clamp in u64 before narrowing to usize: a direct cast on 32-bit
            // targets would silently truncate the high bits and could bypass
            // the SLOTS_PER_LEVEL clamp.
            let diff_u64 = level_tick_end - level_tick_current;
            let diff = if diff_u64 >= SLOTS_PER_LEVEL as u64 {
                SLOTS_PER_LEVEL - 1
            } else {
                diff_u64 as usize
            };

            for i in 0..=diff {
                let slot_idx = (current_slot + i) % SLOTS_PER_LEVEL;
                if level.is_occupied(slot_idx) {
                    count += level.slots[slot_idx]
                        .iter()
                        .filter(|e| self.is_live(e) && in_window(e.deadline))
                        .count();
                }
            }
        }

        count
            + self
                .overflow
                .iter()
                .filter(|e| self.is_live(&e.entry) && in_window(e.deadline))
                .count()
    }

    fn is_live(&self, entry: &TimerEntry) -> bool {
        self.active
            .get(entry.id as usize)
            .is_some_and(|generation| *generation == entry.generation)
    }

    /// Returns the maximum range in nanoseconds for direct wheel storage.
    ///
    /// Timers with deadlines beyond this range from the current time go to
    /// overflow. This is clamped to the physical wheel range: a configured
    /// `max_wheel_duration` larger than the 4-level wheel can physically
    /// represent (~49.7 days at 1 ms base resolution) must NOT widen the
    /// overflow-promotion threshold past what `insert_entry` can place. If it
    /// did, `refill_overflow` would promote a timer whose delta is in
    /// `[physical_range, max_wheel_duration)`, `insert_entry` would find no
    /// level for it and push it straight back to overflow with the same
    /// deadline, and the next `peek` (with `current` unchanged within the
    /// call) would re-promote it forever — an infinite loop holding the timer
    /// driver lock (self-DoS). Clamping keeps such timers parked in overflow
    /// until time advances enough that they actually fit.
    fn max_range_ns(&self) -> u64 {
        self.max_wheel_duration_ns.min(self.physical_range_ns())
    }

    /// Returns the physical wheel range based on level structure.
    fn physical_range_ns(&self) -> u64 {
        self.levels.last().map_or(0, WheelLevel::range_ns)
    }

    fn purge_inactive_storage(&mut self) {
        self.discard_stored_entries();
        self.cancelled_since_compaction = 0;
    }

    /// Drops every stored entry whose timer was cancelled, keeping live ones
    /// where they are. Called from `cancel` once the cancellations since the
    /// last compaction exceed twice the live timers plus a constant, so the
    /// cost is amortized O(1) per cancel.
    fn compact_inactive_storage(&mut self) {
        let Self {
            active,
            ready,
            overflow,
            levels,
            dropped_wakers,
            ..
        } = self;
        let live = |entry: &TimerEntry| {
            active
                .get(entry.id as usize)
                .is_some_and(|generation| *generation == entry.generation)
        };
        let mut discard = |entry: TimerEntry| {
            if let Some(dropped) = dropped_wakers.as_mut() {
                dropped.push(entry.waker);
            }
        };
        // `extract_if` keeps the live entries in their order, as `retain` did.
        ready
            .extract_if(.., |entry| !live(entry))
            .for_each(&mut discard);
        let mut kept = Vec::with_capacity(overflow.len());
        for entry in std::mem::take(overflow).into_vec() {
            if live(&entry.entry) {
                kept.push(entry);
            } else {
                discard(entry.entry);
            }
        }
        *overflow = BinaryHeap::from(kept);
        for level in levels.iter_mut() {
            for slot in 0..SLOTS_PER_LEVEL {
                if level.is_occupied(slot) {
                    level.slots[slot]
                        .extract_if(.., |entry| !live(entry))
                        .for_each(&mut discard);
                    if level.slots[slot].is_empty() {
                        level.clear_occupied(slot);
                    }
                }
            }
        }
        self.cancelled_since_compaction = 0;
    }
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "wheel_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "wheel_metamorphic_tests.rs"]
mod metamorphic_tests;
