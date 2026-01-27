#![allow(unsafe_code)]
//! Intrusive single-level timer wheel for efficient timer management.
//!
//! This module provides a zero-allocation timer wheel using intrusive linked
//! lists. Timer nodes contain their own list links, avoiding heap allocation
//! for timer registration. This is the foundation for the hierarchical timer
//! wheel.
//!
//! # Design
//!
//! The wheel is a circular array of slots. Each slot contains a doubly-linked
//! list of timer nodes. Timers are inserted by hashing their deadline to a slot
//! index: `slot = (deadline / resolution) % SLOTS`.
//!
//! # Cancel Safety
//!
//! Cancellation is O(1) by directly removing the node from its linked list.
//! The `TimerNode` must remain pinned while registered in the wheel.
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::time::intrusive_wheel::{TimerWheel, TimerNode};
//! use std::time::Duration;
//! use std::pin::Pin;
//!
//! let mut wheel: TimerWheel<256> = TimerWheel::new(Duration::from_millis(1));
//! let mut node = Box::pin(TimerNode::new());
//!
//! // Insert with deadline
//! unsafe {
//!     wheel.insert(node.as_mut(), deadline, waker);
//! }
//!
//! // Cancel
//! unsafe {
//!     wheel.cancel(node.as_mut());
//! }
//!
//! // Process expired timers
//! let expired = wheel.tick();
//! for waker in expired {
//!     waker.wake();
//! }
//! ```

use std::cell::Cell;
use std::marker::PhantomPinned;
use std::ptr::NonNull;
use std::task::Waker;
use std::time::{Duration, Instant};

/// A timer node for intrusive linked list storage.
///
/// This struct is designed to be embedded in user types or allocated
/// separately. Once inserted into a wheel, it must remain pinned until
/// removed.
///
/// # Safety
///
/// The node must not be moved while it is linked in a wheel. Use `Pin`
/// to ensure this invariant.
pub struct TimerNode {
    /// Next node in the slot's linked list.
    next: Cell<Option<NonNull<Self>>>,
    /// Previous node in the slot's linked list.
    prev: Cell<Option<NonNull<Self>>>,
    /// Waker to call on expiration.
    waker: Cell<Option<Waker>>,
    /// Slot index this timer is in (for O(1) cancel).
    slot: Cell<usize>,
    /// Level index this timer is in (for hierarchical wheels).
    level: Cell<u8>,
    /// Absolute expiration deadline.
    deadline: Cell<Instant>,
    /// Whether this node is currently linked in a wheel.
    linked: Cell<bool>,
    /// Marker to prevent moving while pinned.
    _pinned: PhantomPinned,
}

impl std::fmt::Debug for TimerNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerNode")
            .field("next", &self.next.get().map(std::ptr::NonNull::as_ptr))
            .field("prev", &self.prev.get().map(std::ptr::NonNull::as_ptr))
            .field("waker", &"<waker>")
            .field("slot", &self.slot.get())
            .field("level", &self.level.get())
            .field("deadline", &self.deadline.get())
            .field("linked", &self.linked.get())
            .finish_non_exhaustive()
    }
}

impl TimerNode {
    /// Creates a new unlinked timer node.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: Cell::new(None),
            prev: Cell::new(None),
            waker: Cell::new(None),
            slot: Cell::new(0),
            level: Cell::new(0),
            deadline: Cell::new(Instant::now()),
            linked: Cell::new(false),
            _pinned: PhantomPinned,
        }
    }

    /// Returns true if this node is currently linked in a wheel.
    #[must_use]
    pub fn is_linked(&self) -> bool {
        self.linked.get()
    }

    /// Returns the deadline for this timer.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline.get()
    }

    /// Returns the level index for this timer.
    #[must_use]
    pub fn level(&self) -> u8 {
        self.level.get()
    }

    /// Takes the waker from this node.
    fn take_waker(&self) -> Option<Waker> {
        self.waker.take()
    }

    /// Sets the deadline and waker for this node.
    fn set(&self, deadline: Instant, waker: Waker, slot: usize, level: u8) {
        self.deadline.set(deadline);
        self.waker.set(Some(waker));
        self.slot.set(slot);
        self.level.set(level);
    }

    /// Updates slot/level metadata without touching waker/deadline.
    fn update_slot_level(&self, slot: usize, level: u8) {
        self.slot.set(slot);
        self.level.set(level);
    }
}

impl Default for TimerNode {
    fn default() -> Self {
        Self::new()
    }
}

/// A slot in the timer wheel containing a doubly-linked list of timer nodes.
#[derive(Debug)]
struct TimerSlot {
    /// Head of the linked list (sentinel-free, nullable).
    head: Cell<Option<NonNull<TimerNode>>>,
    /// Tail of the linked list for O(1) append.
    tail: Cell<Option<NonNull<TimerNode>>>,
    /// Number of nodes in this slot.
    count: Cell<usize>,
}

impl TimerSlot {
    /// Creates a new empty slot.
    const fn new() -> Self {
        Self {
            head: Cell::new(None),
            tail: Cell::new(None),
            count: Cell::new(0),
        }
    }

    /// Returns true if the slot is empty.
    fn is_empty(&self) -> bool {
        self.head.get().is_none()
    }

    /// Pushes a node to the back of the list.
    ///
    /// # Safety
    ///
    /// The caller must ensure `node` is valid and pinned.
    unsafe fn push_back(&self, node: NonNull<TimerNode>) {
        let node_ref = node.as_ref();

        node_ref.next.set(None);
        node_ref.prev.set(self.tail.get());
        node_ref.linked.set(true);

        if let Some(tail) = self.tail.get() {
            tail.as_ref().next.set(Some(node));
        } else {
            self.head.set(Some(node));
        }

        self.tail.set(Some(node));
        self.count.set(self.count.get() + 1);
    }

    /// Removes a node from the list.
    ///
    /// # Safety
    ///
    /// The caller must ensure `node` is valid and currently in this slot.
    unsafe fn remove(&self, node: NonNull<TimerNode>) {
        let node_ref = node.as_ref();

        if !node_ref.linked.get() {
            return;
        }

        let prev = node_ref.prev.get();
        let next = node_ref.next.get();

        match prev {
            Some(prev_ptr) => prev_ptr.as_ref().next.set(next),
            None => self.head.set(next),
        }

        match next {
            Some(next_ptr) => next_ptr.as_ref().prev.set(prev),
            None => self.tail.set(prev),
        }

        node_ref.prev.set(None);
        node_ref.next.set(None);
        node_ref.linked.set(false);

        self.count.set(self.count.get().saturating_sub(1));
    }

    /// Pops the head node from the list.
    ///
    /// # Safety
    ///
    /// The returned pointer is valid until the node is dropped.
    unsafe fn pop_front(&self) -> Option<NonNull<TimerNode>> {
        let head = self.head.get()?;
        self.remove(head);
        Some(head)
    }

    /// Drains all nodes from the slot, returning their wakers.
    ///
    /// # Safety
    ///
    /// All nodes in the slot must be valid.
    unsafe fn drain(&self) -> Vec<Waker> {
        let mut wakers = Vec::with_capacity(self.count.get());

        while let Some(node) = self.pop_front() {
            if let Some(waker) = node.as_ref().take_waker() {
                wakers.push(waker);
            }
        }

        wakers
    }

    /// Drains all nodes from the slot without consuming their wakers.
    ///
    /// # Safety
    ///
    /// All nodes in the slot must be valid.
    unsafe fn drain_nodes(&self) -> Vec<NonNull<TimerNode>> {
        let mut nodes = Vec::with_capacity(self.count.get());

        while let Some(node) = self.pop_front() {
            nodes.push(node);
        }

        nodes
    }

    /// Collects expired wakers without draining non-expired nodes.
    ///
    /// # Safety
    ///
    /// All nodes in the slot must be valid.
    unsafe fn collect_expired(&self, now: Instant) -> Vec<Waker> {
        let mut wakers = Vec::new();
        let mut expired = Vec::new();

        // First pass: identify expired nodes
        let mut current = self.head.get();
        while let Some(node_ptr) = current {
            let node_ref = node_ptr.as_ref();
            let next = node_ref.next.get();

            if node_ref.deadline() <= now {
                expired.push(node_ptr);
            }

            current = next;
        }

        // Second pass: remove expired and collect wakers
        for node_ptr in expired {
            self.remove(node_ptr);
            if let Some(waker) = node_ptr.as_ref().take_waker() {
                wakers.push(waker);
            }
        }

        wakers
    }
}

impl Default for TimerSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// A single-level timer wheel with configurable slot count.
///
/// The wheel uses intrusive linked lists for zero-allocation timer storage.
/// Timers are hashed to slots based on their deadline and the wheel's resolution.
///
/// # Type Parameters
///
/// * `SLOTS` - Number of slots in the wheel (should be a power of 2 for efficient modulo).
#[derive(Debug)]
pub struct TimerWheel<const SLOTS: usize> {
    /// Circular array of timer slots.
    slots: [TimerSlot; SLOTS],
    /// Current position in the wheel.
    current: usize,
    /// Resolution per tick (e.g., 1ms).
    resolution: Duration,
    /// Total number of timers in the wheel.
    count: usize,
    /// Base time for slot calculations.
    base_time: Instant,
}

impl<const SLOTS: usize> TimerWheel<SLOTS> {
    /// Creates a new timer wheel with the given resolution.
    ///
    /// # Arguments
    ///
    /// * `resolution` - Duration per slot (e.g., 1ms means each slot covers 1ms).
    #[must_use]
    pub fn new(resolution: Duration) -> Self {
        Self::new_at(resolution, Instant::now())
    }

    /// Creates a new timer wheel with a specific base time.
    #[must_use]
    pub fn new_at(resolution: Duration, base_time: Instant) -> Self {
        Self {
            // SAFETY: TimerSlot is a simple struct with const new(), safe to initialize
            slots: std::array::from_fn(|_| TimerSlot::new()),
            current: 0,
            resolution,
            count: 0,
            base_time,
        }
    }

    /// Returns the wheel's tick resolution.
    #[must_use]
    pub fn resolution(&self) -> Duration {
        self.resolution
    }

    /// Returns the total number of pending timers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if there are no pending timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the current slot index.
    #[must_use]
    pub fn current_slot(&self) -> usize {
        self.current
    }

    /// Computes the slot index for a given deadline.
    fn slot_for(&self, deadline: Instant) -> usize {
        let elapsed = deadline.saturating_duration_since(self.base_time);
        let ticks = elapsed.as_nanos() / self.resolution.as_nanos().max(1);
        (ticks as usize) % SLOTS
    }

    /// Inserts a timer node with the given deadline.
    ///
    /// # Safety
    ///
    /// * The `node` must be pinned and remain valid until removed.
    /// * The `node` must not already be linked in any wheel.
    pub unsafe fn insert(
        &mut self,
        mut node: std::pin::Pin<&mut TimerNode>,
        deadline: Instant,
        waker: Waker,
    ) {
        debug_assert!(
            !node.is_linked(),
            "attempted to insert already-linked timer node"
        );

        let slot = self.slot_for(deadline);
        node.as_mut()
            .get_unchecked_mut()
            .set(deadline, waker, slot, 0);

        let node_ptr = NonNull::from(node.as_mut().get_unchecked_mut());
        self.slots[slot].push_back(node_ptr);
        self.count += 1;
    }

    /// Cancels a timer node, removing it from the wheel.
    ///
    /// # Safety
    ///
    /// The `node` must be valid and currently linked in this wheel.
    #[allow(clippy::needless_pass_by_value)]
    pub unsafe fn cancel(&mut self, node: std::pin::Pin<&mut TimerNode>) {
        if !node.is_linked() {
            return;
        }

        let slot = node.slot.get();
        let node_ptr = NonNull::from(&*node);
        self.slots[slot].remove(node_ptr);
        self.count = self.count.saturating_sub(1);
    }

    /// Advances the wheel by one tick and returns expired wakers.
    ///
    /// Call this method periodically at the wheel's resolution interval.
    ///
    /// # Safety
    ///
    /// All timer nodes in the wheel must be valid.
    pub unsafe fn tick(&mut self) -> Vec<Waker> {
        let now = Instant::now();

        // Collect expired timers from current slot
        let wakers = self.slots[self.current].collect_expired(now);
        self.count = self.count.saturating_sub(wakers.len());

        // Advance cursor
        self.current = (self.current + 1) % SLOTS;

        wakers
    }

    /// Advances to the given time and returns all expired wakers.
    ///
    /// This method processes multiple ticks if needed to catch up to `now`.
    ///
    /// # Safety
    ///
    /// All timer nodes in the wheel must be valid.
    pub unsafe fn advance_to(&mut self, now: Instant) -> Vec<Waker> {
        let mut all_wakers = Vec::new();

        // Calculate how many ticks to advance
        let elapsed = now.saturating_duration_since(self.base_time);
        let target_slot = (elapsed.as_nanos() / self.resolution.as_nanos().max(1)) as usize % SLOTS;

        // Process slots until we reach target (handling wrap-around)
        while self.current != target_slot {
            let wakers = self.slots[self.current].collect_expired(now);
            self.count = self.count.saturating_sub(wakers.len());
            all_wakers.extend(wakers);
            self.current = (self.current + 1) % SLOTS;
        }

        // Process the target slot
        let wakers = self.slots[self.current].collect_expired(now);
        self.count = self.count.saturating_sub(wakers.len());
        all_wakers.extend(wakers);

        all_wakers
    }

    /// Returns the duration until the next timer expires, if any.
    ///
    /// Returns `None` if the wheel is empty.
    #[must_use]
    pub fn next_expiration(&self) -> Option<Duration> {
        if self.is_empty() {
            return None;
        }

        let now = Instant::now();
        let mut min_deadline: Option<Instant> = None;

        for slot in &self.slots {
            // SAFETY: We only read deadlines, not modifying the list
            let mut current = slot.head.get();
            while let Some(node_ptr) = current {
                // SAFETY: Node is valid while in the wheel
                let node_ref = unsafe { node_ptr.as_ref() };
                let deadline = node_ref.deadline();

                match min_deadline {
                    None => min_deadline = Some(deadline),
                    Some(min) if deadline < min => min_deadline = Some(deadline),
                    _ => {}
                }

                current = node_ref.next.get();
            }
        }

        min_deadline.map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Clears all timers without firing them.
    ///
    /// # Safety
    ///
    /// All timer nodes in the wheel must be valid.
    pub unsafe fn clear(&mut self) {
        for slot in &self.slots {
            // Drain and discard wakers
            let _ = slot.drain();
        }
        self.count = 0;
    }
}

/// Hierarchical timer wheel built from intrusive slots.
///
/// Level layout (default 1ms resolution):
/// - Level 0: 256 slots @ 1ms   => 256ms range
/// - Level 1: 64 slots  @ 256ms => 16.384s range
/// - Level 2: 64 slots  @ 16.384s => ~17.45min range
/// - Level 3: 128 slots @ ~17.45min => ~37.2hr range (>=24hr)
#[derive(Debug)]
pub struct HierarchicalTimerWheel {
    level0: WheelLevel<LEVEL0_SLOTS>,
    level1: WheelLevel<LEVEL1_SLOTS>,
    level2: WheelLevel<LEVEL2_SLOTS>,
    level3: WheelLevel<LEVEL3_SLOTS>,
    /// Base time for slot calculations.
    base_time: Instant,
    /// Current tick in level-0 resolution.
    current_tick: u64,
    /// Total number of timers in the wheel.
    count: usize,
}

const LEVEL0_SLOTS: usize = 256;
const LEVEL1_SLOTS: usize = 64;
const LEVEL2_SLOTS: usize = 64;
const LEVEL3_SLOTS: usize = 128;

const DEFAULT_LEVEL0_RESOLUTION: Duration = Duration::from_millis(1);

#[derive(Debug)]
struct WheelLevel<const SLOTS: usize> {
    slots: [TimerSlot; SLOTS],
    cursor: usize,
    resolution_ns: u64,
}

impl<const SLOTS: usize> WheelLevel<SLOTS> {
    fn new(resolution_ns: u64, cursor: usize) -> Self {
        Self {
            slots: std::array::from_fn(|_| TimerSlot::new()),
            cursor,
            resolution_ns,
        }
    }

    fn range_ns(&self) -> u64 {
        self.resolution_ns.saturating_mul(SLOTS as u64)
    }
}

impl HierarchicalTimerWheel {
    /// Creates a new hierarchical timer wheel with 1ms base resolution.
    #[must_use]
    pub fn new() -> Self {
        Self::new_at(DEFAULT_LEVEL0_RESOLUTION, Instant::now())
    }

    /// Creates a new hierarchical timer wheel with a specific base time.
    #[must_use]
    pub fn new_at(level0_resolution: Duration, base_time: Instant) -> Self {
        let level0_res_ns = duration_to_ns(level0_resolution);
        let level1_res_ns = level0_res_ns.saturating_mul(LEVEL0_SLOTS as u64);
        let level2_res_ns = level1_res_ns.saturating_mul(LEVEL1_SLOTS as u64);
        let level3_res_ns = level2_res_ns.saturating_mul(LEVEL2_SLOTS as u64);

        Self {
            level0: WheelLevel::new(level0_res_ns, 0),
            level1: WheelLevel::new(level1_res_ns, 0),
            level2: WheelLevel::new(level2_res_ns, 0),
            level3: WheelLevel::new(level3_res_ns, 0),
            base_time,
            current_tick: 0,
            count: 0,
        }
    }

    /// Returns the wheel's base resolution.
    #[must_use]
    pub fn resolution(&self) -> Duration {
        Duration::from_nanos(self.level0.resolution_ns.max(1))
    }

    /// Returns the total number of pending timers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if there are no pending timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the current time aligned to the wheel resolution.
    #[must_use]
    pub fn current_time(&self) -> Instant {
        self.base_time
            + Duration::from_nanos(self.current_tick.saturating_mul(self.level0.resolution_ns))
    }

    /// Inserts a timer node with the given deadline.
    ///
    /// # Safety
    ///
    /// * The `node` must be pinned and remain valid until removed.
    /// * The `node` must not already be linked in any wheel.
    pub unsafe fn insert(
        &mut self,
        mut node: std::pin::Pin<&mut TimerNode>,
        deadline: Instant,
        waker: Waker,
    ) {
        debug_assert!(
            !node.is_linked(),
            "attempted to insert already-linked timer node"
        );

        let (level, slot) = self.slot_for(deadline);
        node.as_mut()
            .get_unchecked_mut()
            .set(deadline, waker, slot, level);

        let node_ptr = NonNull::from(node.as_mut().get_unchecked_mut());
        self.push_node(level, slot, node_ptr);
        self.count += 1;
    }

    /// Cancels a timer node, removing it from the wheel.
    ///
    /// # Safety
    ///
    /// The `node` must be valid and currently linked in this wheel.
    #[allow(clippy::needless_pass_by_value)]
    pub unsafe fn cancel(&mut self, node: std::pin::Pin<&mut TimerNode>) {
        if !node.is_linked() {
            return;
        }

        let slot = node.slot.get();
        let level = node.level.get();
        let node_ptr = NonNull::from(&*node);
        self.remove_node(level, slot, node_ptr);
        self.count = self.count.saturating_sub(1);
    }

    /// Advances the wheel by one tick and returns expired wakers.
    ///
    /// # Safety
    ///
    /// All timer nodes in the wheel must be valid.
    pub unsafe fn tick(&mut self) -> Vec<Waker> {
        let now = Instant::now();
        let mut wakers = self.level0.slots[self.level0.cursor].collect_expired(now);
        self.count = self.count.saturating_sub(wakers.len());

        self.level0.cursor = (self.level0.cursor + 1) % LEVEL0_SLOTS;
        self.current_tick = self.current_tick.saturating_add(1);

        if self.level0.cursor == 0 {
            self.cascade(1, now, &mut wakers);
        }

        wakers
    }

    /// Advances to the given time and returns all expired wakers.
    ///
    /// # Safety
    ///
    /// All timer nodes in the wheel must be valid.
    pub unsafe fn advance_to(&mut self, now: Instant) -> Vec<Waker> {
        let elapsed = now.saturating_duration_since(self.base_time);
        let target_tick = duration_to_ns(elapsed) / self.level0.resolution_ns.max(1);
        let mut wakers = Vec::new();

        while self.current_tick < target_tick {
            let mut tick_wakers = self.tick();
            wakers.append(&mut tick_wakers);
        }

        // One more pass to flush any expired entries in the current slot.
        let mut current = self.level0.slots[self.level0.cursor].collect_expired(now);
        self.count = self.count.saturating_sub(current.len());
        wakers.append(&mut current);

        wakers
    }

    /// Returns the duration until the next timer expires, if any.
    ///
    /// Returns `None` if the wheel is empty.
    #[must_use]
    pub fn next_expiration(&self) -> Option<Duration> {
        if self.is_empty() {
            return None;
        }

        let now = Instant::now();
        self.min_deadline()
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Clears all timers without firing them.
    ///
    /// # Safety
    ///
    /// All timer nodes in the wheel must be valid.
    pub unsafe fn clear(&mut self) {
        let _ = self.level0.clear_slots();
        let _ = self.level1.clear_slots();
        let _ = self.level2.clear_slots();
        let _ = self.level3.clear_slots();
        self.count = 0;
    }

    fn slot_for(&self, deadline: Instant) -> (u8, usize) {
        let current = self.current_time();
        let delta_ns = duration_to_ns(deadline.saturating_duration_since(current));
        let ticks_until = delta_ns / self.level0.resolution_ns.max(1);

        if ticks_until < LEVEL0_SLOTS as u64 {
            (0, self.slot_for_level(deadline, &self.level0, LEVEL0_SLOTS))
        } else if ticks_until < (LEVEL0_SLOTS * LEVEL1_SLOTS) as u64 {
            (1, self.slot_for_level(deadline, &self.level1, LEVEL1_SLOTS))
        } else if ticks_until < (LEVEL0_SLOTS * LEVEL1_SLOTS * LEVEL2_SLOTS) as u64 {
            (2, self.slot_for_level(deadline, &self.level2, LEVEL2_SLOTS))
        } else {
            (3, self.slot_for_level(deadline, &self.level3, LEVEL3_SLOTS))
        }
    }

    fn slot_for_level<const SLOTS: usize>(
        &self,
        deadline: Instant,
        level: &WheelLevel<SLOTS>,
        slots: usize,
    ) -> usize {
        let elapsed_ns = duration_to_ns(deadline.saturating_duration_since(self.base_time));
        let tick = elapsed_ns / level.resolution_ns.max(1);
        (tick % slots as u64) as usize
    }

    fn push_node(&self, level: u8, slot: usize, node: NonNull<TimerNode>) {
        match level {
            0 => unsafe { self.level0.slots[slot].push_back(node) },
            1 => unsafe { self.level1.slots[slot].push_back(node) },
            2 => unsafe { self.level2.slots[slot].push_back(node) },
            _ => unsafe { self.level3.slots[slot].push_back(node) },
        }
    }

    fn remove_node(&self, level: u8, slot: usize, node: NonNull<TimerNode>) {
        match level {
            0 => unsafe { self.level0.slots[slot].remove(node) },
            1 => unsafe { self.level1.slots[slot].remove(node) },
            2 => unsafe { self.level2.slots[slot].remove(node) },
            _ => unsafe { self.level3.slots[slot].remove(node) },
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn cascade(&mut self, level_index: u8, now: Instant, wakers: &mut Vec<Waker>) {
        let (bucket, wrapped) = match level_index {
            1 => self.level1.advance_and_drain(),
            2 => self.level2.advance_and_drain(),
            3 => self.level3.advance_and_drain(),
            _ => return,
        };

        for node in bucket {
            let node_ref = unsafe { node.as_ref() };
            if !node_ref.is_linked() {
                let (new_level, new_slot) = self.slot_for(node_ref.deadline());
                node_ref.update_slot_level(new_slot, new_level);
                self.push_node(new_level, new_slot, node);
            }
        }

        if wrapped {
            self.cascade(level_index + 1, now, wakers);
        }
    }

    fn min_deadline(&self) -> Option<Instant> {
        let mut min_deadline: Option<Instant> = None;
        for deadline in self.iter_deadlines() {
            min_deadline = Some(min_deadline.map_or(deadline, |current| current.min(deadline)));
        }
        min_deadline
    }

    fn iter_deadlines(&self) -> impl Iterator<Item = Instant> + '_ {
        self.level0
            .iter_deadlines()
            .chain(self.level1.iter_deadlines())
            .chain(self.level2.iter_deadlines())
            .chain(self.level3.iter_deadlines())
    }
}

impl Default for HierarchicalTimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> WheelLevel<SLOTS> {
    fn iter_deadlines(&self) -> impl Iterator<Item = Instant> + '_ {
        self.slots.iter().flat_map(TimerSlot::iter_deadlines)
    }

    unsafe fn clear_slots(&mut self) -> Vec<Waker> {
        let mut wakers = Vec::new();
        for slot in &self.slots {
            wakers.extend(slot.drain());
        }
        wakers
    }

    /// Advances cursor by one and drains the slot at the old cursor position.
    ///
    /// Returns the nodes from the drained slot and whether the cursor wrapped around.
    fn advance_and_drain(&mut self) -> (Vec<NonNull<TimerNode>>, bool) {
        let old_cursor = self.cursor;
        self.cursor = (self.cursor + 1) % SLOTS;
        let wrapped = self.cursor == 0;
        let nodes = unsafe { self.slots[old_cursor].drain_nodes() };
        (nodes, wrapped)
    }
}

impl TimerSlot {
    fn iter_deadlines(&self) -> impl Iterator<Item = Instant> + '_ {
        TimerSlotIter::new(self.head.get())
    }
}

struct TimerSlotIter {
    current: Option<NonNull<TimerNode>>,
}

impl TimerSlotIter {
    fn new(current: Option<NonNull<TimerNode>>) -> Self {
        Self { current }
    }
}

impl Iterator for TimerSlotIter {
    type Item = Instant;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.current?;
        let node_ref = unsafe { node.as_ref() };
        self.current = node_ref.next.get();
        Some(node_ref.deadline())
    }
}

fn duration_to_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::Wake;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
    fn intrusive_wheel_new() {
        init_test("intrusive_wheel_new");
        let wheel: TimerWheel<256> = TimerWheel::new(Duration::from_millis(1));

        crate::assert_with_log!(
            wheel.is_empty(),
            "wheel starts empty",
            true,
            wheel.is_empty()
        );
        crate::assert_with_log!(wheel.is_empty(), "len is 0", 0, wheel.len());
        crate::assert_with_log!(
            wheel.resolution() == Duration::from_millis(1),
            "resolution",
            Duration::from_millis(1),
            wheel.resolution()
        );
        crate::test_complete!("intrusive_wheel_new");
    }

    #[test]
    fn intrusive_wheel_insert_and_tick() {
        init_test("intrusive_wheel_insert_and_tick");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(5);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        crate::assert_with_log!(wheel.len() == 1, "len is 1", 1, wheel.len());
        crate::assert_with_log!(node.is_linked(), "node is linked", true, node.is_linked());

        // Advance past deadline
        std::thread::sleep(Duration::from_millis(10));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.len() == 1, "got 1 waker", 1, wakers.len());

        for waker in wakers {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter is 1", 1, count);
        crate::assert_with_log!(wheel.is_empty(), "wheel is empty", true, wheel.is_empty());
        crate::test_complete!("intrusive_wheel_insert_and_tick");
    }

    #[test]
    fn intrusive_wheel_cancel() {
        init_test("intrusive_wheel_cancel");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(50);
        let waker = counter_waker(counter.clone());

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        crate::assert_with_log!(wheel.len() == 1, "len is 1", 1, wheel.len());

        // Cancel before it fires
        unsafe {
            wheel.cancel(node.as_mut());
        }

        crate::assert_with_log!(!node.is_linked(), "node unlinked", false, node.is_linked());
        crate::assert_with_log!(wheel.is_empty(), "wheel is empty", true, wheel.is_empty());

        // Advance time - should not fire
        std::thread::sleep(Duration::from_millis(60));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.is_empty(), "no wakers", true, wakers.is_empty());

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 0, "counter is 0", 0, count);
        crate::test_complete!("intrusive_wheel_cancel");
    }

    #[test]
    fn intrusive_wheel_multiple_timers() {
        init_test("intrusive_wheel_multiple_timers");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut nodes: Vec<Pin<Box<TimerNode>>> =
            (0..5).map(|_| Box::pin(TimerNode::new())).collect();

        // Insert timers at different deadlines
        for (i, node) in nodes.iter_mut().enumerate() {
            let deadline = base + Duration::from_millis((i as u64 + 1) * 10);
            let waker = counter_waker(counter.clone());
            unsafe {
                wheel.insert(node.as_mut(), deadline, waker);
            }
        }

        crate::assert_with_log!(wheel.len() == 5, "len is 5", 5, wheel.len());

        // Advance past all deadlines
        std::thread::sleep(Duration::from_millis(60));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.len() == 5, "got 5 wakers", 5, wakers.len());

        for waker in wakers {
            waker.wake();
        }

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 5, "counter is 5", 5, count);
        crate::test_complete!("intrusive_wheel_multiple_timers");
    }

    #[test]
    fn intrusive_wheel_wrap_around() {
        init_test("intrusive_wheel_wrap_around");
        // Small wheel to test wrap-around
        let base = Instant::now();
        let mut wheel: TimerWheel<4> = TimerWheel::new_at(Duration::from_millis(10), base);
        let counter = Arc::new(AtomicU64::new(0));

        // Insert timer that wraps around (slot 5 % 4 = 1)
        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(50);
        let waker = counter_waker(counter);

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let slot = wheel.slot_for(deadline);
        crate::assert_with_log!(slot == 1, "slot wraps to 1", 1, slot);

        // Advance and fire
        std::thread::sleep(Duration::from_millis(60));
        let wakers = unsafe { wheel.advance_to(Instant::now()) };

        crate::assert_with_log!(wakers.len() == 1, "fired", 1, wakers.len());
        crate::test_complete!("intrusive_wheel_wrap_around");
    }

    #[test]
    fn intrusive_wheel_clear() {
        init_test("intrusive_wheel_clear");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);
        let counter = Arc::new(AtomicU64::new(0));

        let mut nodes: Vec<Pin<Box<TimerNode>>> =
            (0..3).map(|_| Box::pin(TimerNode::new())).collect();

        for (i, node) in nodes.iter_mut().enumerate() {
            let deadline = base + Duration::from_millis((i as u64 + 1) * 10);
            let waker = counter_waker(counter.clone());
            unsafe {
                wheel.insert(node.as_mut(), deadline, waker);
            }
        }

        crate::assert_with_log!(wheel.len() == 3, "len is 3", 3, wheel.len());

        // Clear without firing
        unsafe {
            wheel.clear();
        }

        crate::assert_with_log!(wheel.is_empty(), "wheel empty", true, wheel.is_empty());

        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 0, "counter still 0", 0, count);
        crate::test_complete!("intrusive_wheel_clear");
    }

    #[test]
    fn timer_node_default() {
        init_test("timer_node_default");
        let node = TimerNode::default();
        crate::assert_with_log!(!node.is_linked(), "not linked", false, node.is_linked());
        crate::test_complete!("timer_node_default");
    }

    #[test]
    fn intrusive_wheel_next_expiration() {
        init_test("intrusive_wheel_next_expiration");
        let base = Instant::now();
        let mut wheel: TimerWheel<256> = TimerWheel::new_at(Duration::from_millis(1), base);

        let empty = wheel.next_expiration();
        crate::assert_with_log!(empty.is_none(), "empty wheel", true, empty.is_none());

        let mut node = Box::pin(TimerNode::new());
        let deadline = base + Duration::from_millis(100);
        let waker = Arc::new(CounterWaker {
            counter: Arc::new(AtomicU64::new(0)),
        })
        .into();

        unsafe {
            wheel.insert(node.as_mut(), deadline, waker);
        }

        let next = wheel.next_expiration();
        crate::assert_with_log!(next.is_some(), "has expiration", true, next.is_some());
        crate::test_complete!("intrusive_wheel_next_expiration");
    }
}
