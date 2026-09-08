//! Event notification primitive with cancel-aware waiting.
//!
//! [`Notify`] provides a way to signal one or more waiters that an event
//! has occurred. It supports both single-waiter notification (`notify_one`)
//! and broadcast notification (`notify_waiters`).
//!
//! # Cancel Safety
//!
//! - `notified().await`: Cancel-safe, waiter is removed on cancellation
//! - Notifications before any waiter: Stored and delivered to next waiter

use parking_lot::Mutex;
use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// Sentinel used by the intrusive active-waiter FIFO.
const NO_ACTIVE_WAITER: usize = usize::MAX;

/// A notify primitive for signaling events.
///
/// `Notify` provides a mechanism for tasks to wait for events and for
/// other tasks to signal those events. It is similar to a condition
/// variable but designed for async/await.
///
/// # Example
///
/// ```ignore
/// let notify = Notify::new();
///
/// // Spawn a task that waits for notification
/// let fut = async {
///     notify.notified().await;
///     println!("notified!");
/// };
///
/// // Later, signal the waiter
/// notify.notify_one();
/// ```
#[derive(Debug)]
pub struct Notify {
    /// Generation counter - incremented on each notify_waiters.
    generation: AtomicU64,
    /// Number of stored notifications (for notify_one before wait).
    stored_notifications: AtomicUsize,
    /// Queue of waiters (protected by mutex).
    waiters: Mutex<WaiterSlab>,
}

/// Slab-like storage for waiters that reuses freed slots to prevent
/// unbounded Vec growth when cancelled waiters leave holes in the middle.
#[derive(Debug)]
struct WaiterSlab {
    entries: SmallVec<[WaiterEntry; 4]>,
    /// Free-slot indices for reuse. SmallVec<4> avoids heap allocation for
    /// the common case of few concurrent waiters.
    free_slots: SmallVec<[FreeSlot; 4]>,
    /// Number of active waiters (those with a waker set). Maintained
    /// incrementally so `active_count()` is O(1) instead of a linear scan.
    active: usize,
    /// Head and tail of the active-waiter FIFO. Queue order is independent
    /// of reusable slab indices so filling a middle hole cannot leapfrog an
    /// older waiter.
    active_head: usize,
    active_tail: usize,
}

/// A reusable waiter slot and the epoch the next occupant must receive.
#[derive(Debug, Clone, Copy)]
struct FreeSlot {
    index: usize,
    next_epoch: u64,
}

/// Entry in the waiter queue.
#[derive(Debug)]
struct WaiterEntry {
    /// The waker to call when notified.
    waker: Option<Waker>,
    /// Intrusive links in registration order while this entry is active.
    /// Both are [`NO_ACTIVE_WAITER`] after selection or removal.
    active_prev: usize,
    active_next: usize,
    /// Whether this entry has been notified.
    notified: bool,
    /// Generation at which this waiter was registered.
    generation: u64,
    /// True when a later broadcast woke another waiter from this same
    /// pre-broadcast set while this entry was already notify_one-ready.
    broadcast_covered_peer: bool,
    /// br-asupersync-bu4r7l: per-slot epoch incremented on every reuse
    /// of this slot's index by `insert()`. A `Notified` future records
    /// the epoch at registration time and re-verifies it on `Drop` so
    /// it does not operate on a slot that was freed and reused by a
    /// different waiter in the meantime. Without this, a reused slot
    /// whose new occupant happens to be `notified=true` would be
    /// misidentified as the original waiter's notification, leading
    /// either to a duplicate baton-pass or, in the worst case, the
    /// new occupant's wakeup being silently consumed.
    slot_epoch: u64,
}

impl WaiterSlab {
    #[inline]
    fn new() -> Self {
        Self {
            entries: SmallVec::new(),
            free_slots: SmallVec::new(),
            active: 0,
            active_head: NO_ACTIVE_WAITER,
            active_tail: NO_ACTIVE_WAITER,
        }
    }

    /// Ensures the next [`WaiterSlab::insert`] cannot allocate after its
    /// caller moves a `Waker` into the new entry.
    #[inline]
    fn reserve_for_insert(&mut self) {
        // Tail shrinking deliberately leaves stale free-slot records behind.
        // Discard only records that insert() would also skip; any remaining
        // record can be reused without growing entries.
        while self
            .free_slots
            .last()
            .is_some_and(|free| free.index > self.entries.len())
        {
            self.free_slots.pop();
        }
        if self.free_slots.is_empty() {
            self.entries.reserve(1);
        }
    }

    /// Append an occupied slab slot to the active FIFO.
    #[inline]
    fn link_active_tail(&mut self, index: usize) {
        debug_assert!(index < self.entries.len());
        debug_assert!(self.entries[index].waker.is_some());
        debug_assert!(!self.entries[index].notified);
        debug_assert_eq!(self.entries[index].active_prev, NO_ACTIVE_WAITER);
        debug_assert_eq!(self.entries[index].active_next, NO_ACTIVE_WAITER);

        let previous_tail = self.active_tail;
        self.entries[index].active_prev = previous_tail;
        if previous_tail == NO_ACTIVE_WAITER {
            debug_assert_eq!(self.active_head, NO_ACTIVE_WAITER);
            self.active_head = index;
        } else {
            self.entries[previous_tail].active_next = index;
        }
        self.active_tail = index;
        self.active += 1;
    }

    /// Detach an active slab slot from the FIFO in O(1).
    #[inline]
    fn unlink_active(&mut self, index: usize) {
        debug_assert!(index < self.entries.len());
        debug_assert!(self.entries[index].waker.is_some());

        let previous = self.entries[index].active_prev;
        let next = self.entries[index].active_next;

        if previous == NO_ACTIVE_WAITER {
            debug_assert_eq!(self.active_head, index);
            self.active_head = next;
        } else {
            debug_assert_eq!(self.entries[previous].active_next, index);
            self.entries[previous].active_next = next;
        }

        if next == NO_ACTIVE_WAITER {
            debug_assert_eq!(self.active_tail, index);
            self.active_tail = previous;
        } else {
            debug_assert_eq!(self.entries[next].active_prev, index);
            self.entries[next].active_prev = previous;
        }

        self.entries[index].active_prev = NO_ACTIVE_WAITER;
        self.entries[index].active_next = NO_ACTIVE_WAITER;
        self.active -= 1;
        debug_assert_eq!(
            self.active_head == NO_ACTIVE_WAITER,
            self.active_tail == NO_ACTIVE_WAITER
        );
        debug_assert_eq!(self.active == 0, self.active_head == NO_ACTIVE_WAITER);
    }

    /// Insert a waiter entry, reusing a free slot if available.
    ///
    /// Returns `(slot_index, slot_epoch)`. The caller (a `Notified`
    /// future) MUST store both halves and verify the epoch matches
    /// before operating on the slot in its `Drop` impl
    /// (br-asupersync-bu4r7l: protects against slot reuse race).
    #[inline]
    fn insert(&mut self, mut entry: WaiterEntry) -> (usize, u64) {
        let is_active = entry.waker.is_some();
        entry.active_prev = NO_ACTIVE_WAITER;
        entry.active_next = NO_ACTIVE_WAITER;
        let (index, slot_epoch) = loop {
            if let Some(free) = self.free_slots.pop() {
                if free.index < self.entries.len() {
                    entry.slot_epoch = free.next_epoch;
                    self.entries[free.index] = entry;
                    break (free.index, free.next_epoch);
                }
                if free.index == self.entries.len() {
                    // Tail shrink removed the entry body, but the free-slot
                    // record preserves its next epoch so recreating the same
                    // index is still distinguishable from the prior occupant.
                    entry.slot_epoch = free.next_epoch;
                    self.entries.push(entry);
                    break (free.index, free.next_epoch);
                }
                // Higher stale indices were truncated away during a previous shrink.
                // Ignore it and keep popping.
            } else {
                let idx = self.entries.len();
                // Fresh slot starts at epoch 0; never reused before so
                // no prior Notified can hold a tuple for this index.
                entry.slot_epoch = 0;
                self.entries.push(entry);
                break (idx, 0);
            }
        };
        if is_active {
            self.link_active_tail(index);
        }
        (index, slot_epoch)
    }

    /// Remove a waiter entry by index, returning its slot to the free list.
    #[inline]
    fn remove(&mut self, index: usize) -> Option<Waker> {
        let mut retired_waker = None;
        if index < self.entries.len() {
            // Reserve before taking the Waker so allocation unwind leaves its
            // payload in the slab instead of destroying it under the mutex.
            self.free_slots.reserve(1);
            let next_epoch = self.entries[index].slot_epoch.wrapping_add(1);
            if self.entries[index].waker.is_some() {
                self.unlink_active(index);
            }
            retired_waker = self.entries[index].waker.take();
            self.entries[index].notified = false;
            self.entries[index].active_prev = NO_ACTIVE_WAITER;
            self.entries[index].active_next = NO_ACTIVE_WAITER;
            self.free_slots.push(FreeSlot { index, next_epoch });
        }

        // Shrink from the end: pop entries that are free and at the tail.
        while self
            .entries
            .last()
            .is_some_and(|e| e.waker.is_none() && !e.notified)
        {
            self.entries.pop();
            // We do NOT explicitly remove the popped index from `free_slots` here
            // to avoid an O(N^2) penalty when shrinking many cancelled waiters.
            // Stale `free_slots` indices (>= self.entries.len()) are harmlessly
            // ignored and discarded by `insert()` during its pop loop.
        }

        retired_waker
    }

    /// Count active waiters (those with a waker set).  O(1) via maintained counter.
    #[inline]
    fn active_count(&self) -> usize {
        self.active
    }

    #[inline]
    fn take_next_active_waker(&mut self) -> Option<Waker> {
        let index = self.active_head;
        if index == NO_ACTIVE_WAITER {
            debug_assert_eq!(self.active, 0);
            debug_assert_eq!(self.active_tail, NO_ACTIVE_WAITER);
            return None;
        }

        self.unlink_active(index);
        let entry = &mut self.entries[index];
        entry.notified = true;
        let waker = entry.waker.take();
        debug_assert!(waker.is_some());
        waker
    }
}

impl Notify {
    /// Creates a new `Notify` in the empty state.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            stored_notifications: AtomicUsize::new(0),
            waiters: Mutex::new(WaiterSlab::new()),
        }
    }

    /// Returns a future that completes when this `Notify` is notified.
    ///
    /// The returned future is cancel-safe: if dropped before completion,
    /// the waiter is cleanly removed.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::sync::Notify;
    /// use std::sync::{
    ///     Arc,
    ///     atomic::{AtomicBool, Ordering},
    /// };
    ///
    /// # futures_lite::future::block_on(async {
    /// let notify = Arc::new(Notify::new());
    /// let ready = Arc::new(AtomicBool::new(false));
    ///
    /// let signaler = {
    ///     let notify = Arc::clone(&notify);
    ///     let ready = Arc::clone(&ready);
    ///
    ///     std::thread::spawn(move || {
    ///         ready.store(true, Ordering::Release);
    ///         notify.notify_one();
    ///     })
    /// };
    ///
    /// notify.notified().await;
    /// assert!(ready.load(Ordering::Acquire));
    /// signaler.join().expect("signaler thread panicked");
    /// # });
    /// ```
    #[inline]
    pub fn notified(&self) -> Notified<'_> {
        Notified {
            notify: self,
            state: NotifiedState::Init,
            waiter_index: None,
            initial_generation: self.generation.load(Ordering::Acquire),
            generation_capture: GenerationCapture::OnFirstPoll,
        }
    }

    /// Creates a waiter armed against a generation sampled before a caller's
    /// condition check. Unlike [`Notify::notified`], this private path must
    /// preserve the supplied generation through its first poll so a broadcast
    /// between the condition check and registration cannot be lost.
    #[inline]
    fn notified_at_generation(&self, generation: u64) -> Notified<'_> {
        Notified {
            notify: self,
            state: NotifiedState::Init,
            waiter_index: None,
            initial_generation: generation,
            generation_capture: GenerationCapture::Armed(generation),
        }
    }

    /// Waits until `predicate` returns `true`, re-checking it after every wake.
    ///
    /// The predicate is evaluated before parking and again after each
    /// notification, so callers can pair a state transition with
    /// `notify_one()` / `notify_waiters()` without a separate check-then-park
    /// race window.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::sync::Notify;
    /// use std::sync::{
    ///     Arc,
    ///     atomic::{AtomicBool, Ordering},
    /// };
    ///
    /// # futures_lite::future::block_on(async {
    /// let notify = Arc::new(Notify::new());
    /// let ready = Arc::new(AtomicBool::new(false));
    ///
    /// let signaler = {
    ///     let notify = Arc::clone(&notify);
    ///     let ready = Arc::clone(&ready);
    ///
    ///     std::thread::spawn(move || {
    ///         ready.store(true, Ordering::Release);
    ///         notify.notify_one();
    ///     })
    /// };
    ///
    /// notify
    ///     .wait_until(|| ready.load(Ordering::Acquire))
    ///     .await;
    /// assert!(ready.load(Ordering::Acquire));
    /// signaler.join().expect("signaler thread panicked");
    /// # });
    /// ```
    #[inline]
    pub async fn wait_until<F>(&self, mut predicate: F)
    where
        F: FnMut() -> bool,
    {
        loop {
            let generation = self.generation.load(Ordering::Acquire);
            if predicate() {
                return;
            }
            self.notified_at_generation(generation).await;
        }
    }

    /// Notifies one waiting task.
    ///
    /// If no task is currently waiting, the notification is stored and
    /// will be delivered to the next task that calls `notified().await`.
    ///
    /// If multiple tasks are waiting, exactly one will be woken.
    ///
    /// Returns `true` when an active waiter was selected and woken, or
    /// `false` when no waiter was available and the notification was stored.
    #[inline]
    pub fn notify_one(&self) -> bool {
        let waker_to_wake = {
            let mut waiters = self.waiters.lock();

            if let Some(found_waker) = waiters.take_next_active_waker() {
                drop(waiters);
                Some(found_waker)
            } else {
                // No waiters found, store the notification.
                //
                // Important: keep the waiter lock held while incrementing
                // `stored_notifications` so a waiter can't observe
                // `stored_notifications == 0`, then register, and miss the stored
                // notification (lost wakeup).
                self.stored_notifications.fetch_add(1, Ordering::Release);
                drop(waiters);
                None
            }
        };

        // Wake outside the lock to avoid executing user waker code while holding
        // waiter state.
        if let Some(waker) = waker_to_wake {
            waker.wake();
            true
        } else {
            false
        }
    }

    /// Notifies all waiting tasks.
    ///
    /// This wakes all tasks that are currently waiting. Tasks that
    /// start waiting after this call will not be affected.
    #[inline]
    pub fn notify_waiters(&self) {
        // Increment generation to signal all waiters.
        let new_generation = self.generation.fetch_add(1, Ordering::Release) + 1;

        // Collect all wakers (SmallVec avoids heap allocation for ≤8 waiters).
        let wakers: SmallVec<[Waker; 8]> = {
            let mut waiters = self.waiters.lock();

            // Reserve before detaching any Waker so allocation failure cannot
            // retire a user payload while the waiter mutex is held.
            let mut wakers: SmallVec<[Waker; 8]> = SmallVec::with_capacity(waiters.active);

            let mut index = waiters.active_head;
            while index != NO_ACTIVE_WAITER {
                let next = waiters.entries[index].active_next;
                if waiters.entries[index].generation < new_generation {
                    waiters.unlink_active(index);
                    let entry = &mut waiters.entries[index];
                    entry.generation = new_generation;
                    entry.notified = true;
                    if let Some(waker) = entry.waker.take() {
                        wakers.push(waker);
                    }
                }
                index = next;
            }
            if !wakers.is_empty() {
                for entry in &mut waiters.entries {
                    if entry.generation < new_generation && entry.notified && entry.waker.is_none()
                    {
                        entry.broadcast_covered_peer = true;
                    }
                }
            }
            wakers
        };

        // Wake all. Isolate each detached wake so one hostile safe Waker cannot
        // strand the later waiters: they have already had their wakers taken and
        // their generation advanced under the lock, so they can only re-poll to
        // Ready if they are actually woken (br-asupersync-cnl0jn). Retain the
        // first panic, finish the fanout, then resume it once so exactly one
        // payload propagates.
        let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
        for waker in wakers {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    waker.wake();
                }))
            {
                if first_panic.is_none() {
                    first_panic = Some(payload);
                }
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }

    /// Returns the number of tasks currently waiting.
    #[inline]
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        let waiters = self.waiters.lock();
        waiters.active_count()
    }

    /// Passes a `notify_one` baton to the next active waiter, or stores it if none exist.
    /// This must be called with the waiters lock held.
    fn pass_baton(&self, mut waiters: parking_lot::MutexGuard<'_, WaiterSlab>) {
        if let Some(waker) = waiters.take_next_active_waker() {
            drop(waiters);
            waker.wake();
            return;
        }
        self.stored_notifications.fetch_add(1, Ordering::Release);
    }

    /// Passes a `notify_one` baton to a post-broadcast waiter, optionally
    /// falling back to a stored notification when none exists yet.
    ///
    /// Used when a later broadcast already covered the original waiter set
    /// but a post-broadcast waiter (existing OR about-to-register) may still
    /// need the in-flight `notify_one` baton.
    ///
    /// `store_if_absent` is true only when no other pre-broadcast waiter was
    /// covered by the broadcast. If the broadcast already woke a peer waiter,
    /// a late future waiter must not receive a ghost notify_one token.
    #[inline]
    fn pass_baton_after_broadcast(
        &self,
        mut waiters: parking_lot::MutexGuard<'_, WaiterSlab>,
        store_if_absent: bool,
    ) {
        if let Some(waker) = waiters.take_next_active_waker() {
            drop(waiters);
            waker.wake();
            return;
        }
        if store_if_absent {
            self.stored_notifications.fetch_add(1, Ordering::Release);
        }
    }
}

impl Default for Notify {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Notify {
    fn drop(&mut self) {
        // AUDIT FIX: Wake all pending waiters when Notify is dropped
        // Per asupersync cancel-aware semantics, pending waiters should be cancelled
        // with explicit error rather than hanging forever

        // Increment generation to signal drop to any waiters that check it
        // This ensures proper memory ordering for the drop event
        let _final_generation = self.generation.fetch_add(1, Ordering::Release);

        // Clear stored notifications - no more consumers can arrive
        self.stored_notifications.store(0, Ordering::Release);

        let wakers = {
            let mut waiters = self.waiters.lock();
            let mut wakers = Vec::with_capacity(waiters.active);

            // Detach all pending waiter wakers in registration order.
            while let Some(waker) = waiters.take_next_active_waker() {
                wakers.push(waker);
            }

            // Clear the waiters since the Notify is being dropped
            waiters.entries.clear();
            waiters.active = 0;
            waiters.active_head = NO_ACTIVE_WAITER;
            waiters.active_tail = NO_ACTIVE_WAITER;

            wakers
        };

        // Wake all pending waiters outside the lock. They will see the Notify
        // as dropped when they poll. Isolate each wake so one panicking safe
        // Waker cannot strand the later detached waiters (br-asupersync-b3td9n,
        // same class as notify_waiters/br-asupersync-cnl0jn). Unlike
        // notify_waiters, the payload is SUPPRESSED, never resumed: Drop can
        // run during an existing unwind, where a second panic aborts the
        // process — fail closed on teardown.
        for waker in wakers {
            drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                move || {
                    waker.wake();
                },
            )));
        }
    }
}

/// State of the `Notified` future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifiedState {
    /// Initial state, not yet polled.
    Init,
    /// Registered as a waiter.
    Waiting,
    /// Notification received.
    Done,
}

/// Controls when a `Notified` future establishes its broadcast baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerationCapture {
    /// Public `notified()` futures start waiting only when first polled.
    OnFirstPoll,
    /// `wait_until` sampled this generation before evaluating its predicate.
    Armed(u64),
}

/// Future returned by [`Notify::notified`].
///
/// This future completes when the associated `Notify` is notified.
#[derive(Debug)]
pub struct Notified<'a> {
    notify: &'a Notify,
    state: NotifiedState,
    /// br-asupersync-bu4r7l: stored as `(index, slot_epoch)` so `Drop`
    /// can verify the slot has not been freed and reused by a different
    /// waiter between registration and cleanup. `slot_epoch` matches
    /// the value `WaiterSlab::insert` returned at registration time;
    /// any divergence means the slot now belongs to someone else and
    /// must NOT be touched.
    waiter_index: Option<(usize, u64)>,
    initial_generation: u64,
    generation_capture: GenerationCapture,
}

impl Notified<'_> {
    #[inline]
    fn mark_done(&mut self) -> Poll<()> {
        self.state = NotifiedState::Done;
        Poll::Ready(())
    }

    #[inline]
    fn try_consume_stored_notification(&self) -> bool {
        let mut stored = self.notify.stored_notifications.load(Ordering::Acquire);
        while stored > 0 {
            // br-asupersync-fu402k: success ordering must be AcqRel.
            // notify_one stores a notification with Release (around
            // line 215) so subsequent producers/consumers form a
            // happens-before chain through stored_notifications.
            // Acquire on the consume side is required to OBSERVE the
            // produced value — that part was already correct. But the
            // CAS that decrements is itself a producer for any
            // subsequent observer that reads the lower count via
            // Acquire (e.g., a later notify_one finding the counter
            // back at zero and re-storing): without Release on the
            // consume side, the consumer's prior writes are NOT
            // released to that observer, so the consumer's
            // post-notification work can be reordered behind the
            // producer's load. AcqRel restores both sides of the
            // synchronization edge.
            //
            // Failure ordering stays Relaxed: a failed CAS does not
            // form a happens-before edge — the next loop iteration
            // re-reads with Acquire on its own.
            match self.notify.stored_notifications.compare_exchange_weak(
                stored,
                stored - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => stored = actual,
            }
        }
        false
    }

    #[inline]
    fn poll_init(&mut self, cx: &Context<'_>) -> Poll<()> {
        // A waiter only starts "waiting" on first poll, not when the future is
        // constructed. Capture the current broadcast generation now so
        // notify_waiters() remains edge-triggered for already-polled waiters
        // instead of spuriously waking futures that were created earlier but
        // never polled.
        let observed_generation = match self.generation_capture {
            GenerationCapture::OnFirstPoll => self.notify.generation.load(Ordering::Acquire),
            GenerationCapture::Armed(generation) => generation,
        };
        self.initial_generation = observed_generation;

        // Lock-free fast path: consume a stored notify token.
        if self.try_consume_stored_notification() {
            return self.mark_done();
        }

        // A custom RawWaker clone may re-enter this Notify or panic. Prepare
        // it before locking, then re-check every readiness condition below.
        let mut incoming_waker = Some(cx.waker().clone());
        let ready = {
            let mut waiters = self.notify.waiters.lock();

            // Re-check conditions under waiter lock to close races with concurrent notifiers.
            let current_gen = self.notify.generation.load(Ordering::Acquire);
            if current_gen != observed_generation || self.try_consume_stored_notification() {
                // Commit completion before an unused Waker payload is retired:
                // its destructor is arbitrary user code and may panic.
                self.state = NotifiedState::Done;
                true
            } else {
                // Reserve before moving the Waker so allocation unwind cannot
                // destroy its payload while the waiter mutex is held.
                waiters.reserve_for_insert();
                let (index, slot_epoch) = waiters.insert(WaiterEntry {
                    waker: Some(
                        incoming_waker
                            .take()
                            .expect("Notify registration waker must be available"),
                    ),
                    active_prev: NO_ACTIVE_WAITER,
                    active_next: NO_ACTIVE_WAITER,
                    notified: false,
                    generation: observed_generation,
                    broadcast_covered_peer: false,
                    slot_epoch: 0, // overwritten by insert()
                });
                self.waiter_index = Some((index, slot_epoch));
                self.state = NotifiedState::Waiting;
                false
            }
        };

        // An unused clone can own arbitrary safe Drop state. Retire it only
        // after the waiter mutex has been released and state is committed.
        drop(incoming_waker);
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    #[inline]
    fn poll_waiting(&mut self, cx: &Context<'_>) -> Poll<()> {
        // Lock-free fast path check.
        let current_gen = self.notify.generation.load(Ordering::Acquire);
        let gen_changed = current_gen != self.initial_generation;

        if let Some((index, slot_epoch)) = self.waiter_index {
            // Avoid cloning on the already-observed generation-completion
            // path. Otherwise clone before locking so custom RawWaker code
            // cannot re-enter the waiter mutex.
            let mut incoming_waker = (!gen_changed).then(|| cx.waker().clone());
            let mut retired_waker = None;
            let completed = {
                let mut waiters = self.notify.waiters.lock();

                // Re-check generation under lock if it wasn't already changed.
                let is_gen_changed = gen_changed
                    || self.notify.generation.load(Ordering::Acquire) != self.initial_generation;

                // br-asupersync-bu4r7l: verify the slot still belongs to us
                // before reading or removing. If the slot was freed and
                // reused by a different waiter, the epoch will not match
                // and we must abandon our recorded index without touching
                // the foreign entry. Such an abandonment is treated as
                // "this future is done" — the caller will see no spurious
                // wakeup and the new occupant is left intact.
                let slot_owned_by_us = index < waiters.entries.len()
                    && waiters.entries[index].slot_epoch == slot_epoch;

                if slot_owned_by_us {
                    let entry_notified = waiters.entries[index].notified;

                    if is_gen_changed || entry_notified {
                        retired_waker = waiters.remove(index);
                        self.waiter_index = None;
                        self.state = NotifiedState::Done;
                        true
                    } else {
                        // Replace ownership under the lock, but defer destruction
                        // of the prior or unused Waker until after unlocking.
                        match &mut waiters.entries[index].waker {
                            Some(existing) if existing.will_wake(cx.waker()) => {}
                            Some(existing) => {
                                retired_waker = Some(std::mem::replace(
                                    existing,
                                    incoming_waker
                                        .take()
                                        .expect("Notify replacement waker must be available"),
                                ));
                            }
                            None => {
                                unreachable!(
                                    "waker is never None while notified is false for a live Notified future"
                                );
                            }
                        }
                        false
                    }
                } else {
                    // Slot was reused by a different waiter — our entry is
                    // gone. Treat as completed (we cannot prove our wakeup
                    // didn't fire and were processed by some other path).
                    self.waiter_index = None;
                    self.state = NotifiedState::Done;
                    true
                }
            };

            drop(retired_waker);
            drop(incoming_waker);
            if completed {
                return Poll::Ready(());
            }
        } else if gen_changed {
            return self.mark_done();
        }

        Poll::Pending
    }
}

impl Future for Notified<'_> {
    type Output = ();

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.state {
            NotifiedState::Init => self.poll_init(cx),
            NotifiedState::Waiting => self.poll_waiting(cx),
            // Preserve completion on re-poll instead of panicking in library code.
            NotifiedState::Done => Poll::Ready(()),
        }
    }
}

impl Drop for Notified<'_> {
    fn drop(&mut self) {
        if self.state == NotifiedState::Waiting {
            if let Some((index, slot_epoch)) = self.waiter_index.take() {
                let mut waiters = self.notify.waiters.lock();
                let generation_advanced =
                    self.notify.generation.load(Ordering::Acquire) != self.initial_generation;

                // br-asupersync-bu4r7l: verify the slot still belongs to
                // us BEFORE reading or removing. Without this check, a
                // slot that was freed and reused by a later waiter would
                // be misidentified — at best we'd mis-pass a baton, at
                // worst we'd remove() the foreign entry and silently
                // consume the new waiter's wakeup.
                let slot_owned_by_us = index < waiters.entries.len()
                    && waiters.entries[index].slot_epoch == slot_epoch;

                if !slot_owned_by_us {
                    // The slot has been reclaimed by a later insert.
                    // Our waiter entry no longer exists; there is
                    // nothing for us to remove and no baton for us to
                    // pass. Whatever notification was destined for our
                    // original entry has already been processed (or
                    // re-stored by the previous remover). Drop quietly.
                    return;
                }

                let entry = &waiters.entries[index];
                let was_notified = entry.notified;
                let notified_generation = entry.generation;
                let broadcast_covered_peer = entry.broadcast_covered_peer;

                let retired_waker = waiters.remove(index);

                if was_notified {
                    let was_broadcast_notify = notified_generation != self.initial_generation;
                    if was_broadcast_notify {
                        // A broadcast already covered this waiter, even if an earlier
                        // notify_one had already taken its waker. Do not mint a
                        // replacement notify_one token on cancellation.
                        drop(waiters);
                        drop(retired_waker);
                        return;
                    }

                    // It was woken by notify_one, but cancelled!
                    // If a later broadcast already covered the original waiter set,
                    // only hand the baton to a post-broadcast waiter. Otherwise use
                    // the normal baton semantics, which store the notification when
                    // no waiter exists.
                    if generation_advanced {
                        self.notify
                            .pass_baton_after_broadcast(waiters, !broadcast_covered_peer);
                    } else {
                        self.notify.pass_baton(waiters);
                    }
                    // Baton state and any selected wake are committed before a
                    // retired payload destructor is allowed to run or panic.
                    drop(retired_waker);
                } else {
                    drop(waiters);
                    drop(retired_waker);
                }
            }
        }
    }
}

#[cfg(test)]
include!("notify_tests.rs");
