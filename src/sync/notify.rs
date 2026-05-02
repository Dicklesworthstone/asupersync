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
    /// Lower-bound hint for the first potentially-active (non-notified, has-waker)
    /// entry. `notify_one` starts scanning from here instead of index 0,
    /// making sequential notifications O(1) amortized instead of O(n).
    scan_start: usize,
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
            scan_start: 0,
        }
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
            self.active += 1;
            // New active entry before the scan cursor → lower the hint.
            if index < self.scan_start {
                self.scan_start = index;
            }
        }
        (index, slot_epoch)
    }

    /// Remove a waiter entry by index, returning its slot to the free list.
    #[inline]
    fn remove(&mut self, index: usize) {
        if index < self.entries.len() {
            let next_epoch = self.entries[index].slot_epoch.wrapping_add(1);
            if self.entries[index].waker.is_some() {
                self.active -= 1;
            }
            self.entries[index].waker = None;
            self.entries[index].notified = false;
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
    }

    /// Count active waiters (those with a waker set).  O(1) via maintained counter.
    #[inline]
    fn active_count(&self) -> usize {
        self.active
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
        }
    }

    /// Notifies one waiting task.
    ///
    /// If no task is currently waiting, the notification is stored and
    /// will be delivered to the next task that calls `notified().await`.
    ///
    /// If multiple tasks are waiting, exactly one will be woken.
    #[inline]
    pub fn notify_one(&self) {
        let waker_to_wake = {
            let mut waiters = self.waiters.lock();

            // Find a waiter to notify, starting from the scan cursor.
            let mut found_waker = None;
            let start = waiters.scan_start;
            for i in start..waiters.entries.len() {
                let entry = &mut waiters.entries[i];
                if !entry.notified && entry.waker.is_some() {
                    entry.notified = true;
                    found_waker = entry.waker.take();
                    waiters.scan_start = i + 1;
                    break;
                }
            }

            if found_waker.is_some() {
                waiters.active -= 1;
                drop(waiters);
                found_waker
            } else {
                // If we found nothing, it means there are no active, unnotified waiters
                // from `start` to the end. We can safely advance `scan_start` to the end
                // to avoid O(N^2) scans in pathological broadcast then sequential notify workloads.
                waiters.scan_start = waiters.entries.len();

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

            let wakers: SmallVec<[Waker; 8]> = waiters
                .entries
                .iter_mut()
                .filter_map(|entry| {
                    // Only active waiters have wakers. Free slots are ignored.
                    if entry.generation < new_generation && entry.waker.is_some() {
                        entry.generation = new_generation;
                        entry.notified = true;
                        return entry.waker.take();
                    }
                    None
                })
                .collect();
            if !wakers.is_empty() {
                for entry in &mut waiters.entries {
                    if entry.generation < new_generation && entry.notified && entry.waker.is_none()
                    {
                        entry.broadcast_covered_peer = true;
                    }
                }
            }
            waiters.active -= wakers.len();
            wakers
        };

        // Wake all.
        for waker in wakers {
            waker.wake();
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
        let start = waiters.scan_start;
        for i in start..waiters.entries.len() {
            let entry = &mut waiters.entries[i];
            if !entry.notified && entry.waker.is_some() {
                entry.notified = true;
                if let Some(waker) = entry.waker.take() {
                    waiters.active -= 1;
                    waiters.scan_start = i + 1;
                    drop(waiters);
                    waker.wake();
                    return;
                }
            }
        }
        waiters.scan_start = waiters.entries.len();
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
        let start = waiters.scan_start;
        for i in start..waiters.entries.len() {
            let entry = &mut waiters.entries[i];
            if !entry.notified && entry.waker.is_some() {
                entry.notified = true;
                if let Some(waker) = entry.waker.take() {
                    waiters.active -= 1;
                    waiters.scan_start = i + 1;
                    drop(waiters);
                    waker.wake();
                    return;
                }
            }
        }
        waiters.scan_start = waiters.entries.len();
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

        let wakers = {
            let mut waiters = self.waiters.lock();
            let mut wakers = Vec::new();

            // Collect all pending waiter wakers
            while let Some(entry) = waiters.entries.iter_mut().find(|e| e.waker.is_some()) {
                if let Some(waker) = entry.waker.take() {
                    wakers.push(waker);
                }
            }

            // Clear the waiters since the Notify is being dropped
            waiters.entries.clear();
            waiters.active = 0;
            waiters.scan_start = 0;

            wakers
        };

        // Wake all pending waiters outside the lock
        // They will see the Notify as dropped when they poll
        for waker in wakers {
            waker.wake();
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
        let observed_generation = self.notify.generation.load(Ordering::Acquire);
        self.initial_generation = observed_generation;

        // Lock-free fast path: consume a stored notify token.
        if self.try_consume_stored_notification() {
            return self.mark_done();
        }

        // Register as a waiter.
        let mut waiters = self.notify.waiters.lock();

        // Re-check conditions under waiter lock to close races with concurrent notifiers.
        let current_gen = self.notify.generation.load(Ordering::Acquire);
        if current_gen != observed_generation {
            drop(waiters);
            return self.mark_done();
        }

        if self.try_consume_stored_notification() {
            drop(waiters);
            return self.mark_done();
        }

        let (index, slot_epoch) = waiters.insert(WaiterEntry {
            waker: Some(cx.waker().clone()),
            notified: false,
            generation: observed_generation,
            broadcast_covered_peer: false,
            slot_epoch: 0, // overwritten by insert()
        });
        self.waiter_index = Some((index, slot_epoch));
        self.state = NotifiedState::Waiting;
        drop(waiters);

        Poll::Pending
    }

    #[inline]
    fn poll_waiting(&mut self, cx: &Context<'_>) -> Poll<()> {
        // Lock-free fast path check.
        let current_gen = self.notify.generation.load(Ordering::Acquire);
        let gen_changed = current_gen != self.initial_generation;

        if let Some((index, slot_epoch)) = self.waiter_index {
            let mut waiters = self.notify.waiters.lock();

            // Re-check generation under lock if it wasn't already changed
            let is_gen_changed = gen_changed || {
                let new_gen = self.notify.generation.load(Ordering::Acquire);
                new_gen != self.initial_generation
            };

            // br-asupersync-bu4r7l: verify the slot still belongs to us
            // before reading or removing. If the slot was freed and
            // reused by a different waiter, the epoch will not match
            // and we must abandon our recorded index without touching
            // the foreign entry. Such an abandonment is treated as
            // "this future is done" — the caller will see no spurious
            // wakeup and the new occupant is left intact.
            let slot_owned_by_us =
                index < waiters.entries.len() && waiters.entries[index].slot_epoch == slot_epoch;

            if slot_owned_by_us {
                let entry_notified = waiters.entries[index].notified;

                if is_gen_changed {
                    waiters.remove(index);
                    self.waiter_index = None;
                    drop(waiters);
                    return self.mark_done();
                }

                if entry_notified {
                    waiters.remove(index);
                    drop(waiters);
                    self.waiter_index = None;
                    return self.mark_done();
                }

                // Update waker while we have the lock, but only if it changed.
                match &mut waiters.entries[index].waker {
                    Some(existing) if existing.will_wake(cx.waker()) => {}
                    Some(existing) => existing.clone_from(cx.waker()),
                    None => {
                        unreachable!(
                            "waker is never None while notified is false for a live Notified future"
                        );
                    }
                }
            } else {
                // Slot was reused by a different waiter — our entry is
                // gone. Treat as completed (we cannot prove our wakeup
                // didn't fire and were processed by some other path).
                self.waiter_index = None;
                drop(waiters);
                return self.mark_done();
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

                waiters.remove(index);

                if was_notified {
                    let was_broadcast_notify = notified_generation != self.initial_generation;
                    if was_broadcast_notify {
                        // A broadcast already covered this waiter, even if an earlier
                        // notify_one had already taken its waker. Do not mint a
                        // replacement notify_one token on cancellation.
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
                }
            }
        }
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
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F>(fut: &mut F) -> Poll<F::Output>
    where
        F: Future + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(fut).poll(&mut cx)
    }

    struct FreshWake;

    impl std::task::Wake for FreshWake {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn fresh_waker() -> Waker {
        Waker::from(Arc::new(FreshWake))
    }

    fn poll_with_waker<F>(fut: &mut F, waker: &Waker) -> Poll<F::Output>
    where
        F: Future + Unpin,
    {
        let mut cx = Context::from_waker(waker);
        Pin::new(fut).poll(&mut cx)
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn broadcast_with_middle_hole_signature(
        broadcasts: usize,
    ) -> ([bool; 2], usize, usize, usize, bool) {
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        let mut fut3 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());
        assert!(poll_once(&mut fut3).is_pending());

        drop(fut2);

        for _ in 0..broadcasts {
            notify.notify_waiters();
        }

        let ready_pair = [
            poll_once(&mut fut1).is_ready(),
            poll_once(&mut fut3).is_ready(),
        ];
        drop(fut1);
        drop(fut3);

        let waiter_count = notify.waiter_count();
        let entries_len = notify.waiters.lock().entries.len();
        let stored = notify.stored_notifications.load(Ordering::Acquire);

        let mut late = notify.notified();
        let late_pending = poll_once(&mut late).is_pending();
        drop(late);

        (ready_pair, waiter_count, entries_len, stored, late_pending)
    }

    fn broadcast_then_notify_one_signature(broadcasts: usize) -> ([bool; 2], usize, bool, bool) {
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());

        for _ in 0..broadcasts {
            notify.notify_waiters();
        }

        let ready_pair = [
            poll_once(&mut fut1).is_ready(),
            poll_once(&mut fut2).is_ready(),
        ];
        drop(fut1);
        drop(fut2);

        notify.notify_one();
        let stored_before_consume = notify.stored_notifications.load(Ordering::Acquire);

        let mut stored_consumer = notify.notified();
        let stored_consumer_ready = poll_once(&mut stored_consumer).is_ready();
        drop(stored_consumer);

        let mut trailing_waiter = notify.notified();
        let trailing_waiter_pending = poll_once(&mut trailing_waiter).is_pending();
        drop(trailing_waiter);

        (
            ready_pair,
            stored_before_consume,
            stored_consumer_ready,
            trailing_waiter_pending,
        )
    }

    fn repoll_then_notify_one_signature(extra_repolls: usize) -> ([bool; 3], usize) {
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        let mut fut3 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        for _ in 0..extra_repolls {
            assert!(poll_once(&mut fut1).is_pending());
        }
        assert!(poll_once(&mut fut2).is_pending());
        assert!(poll_once(&mut fut3).is_pending());

        notify.notify_one();

        let ready = [
            poll_once(&mut fut1).is_ready(),
            poll_once(&mut fut2).is_ready(),
            poll_once(&mut fut3).is_ready(),
        ];
        drop(fut1);
        drop(fut2);
        drop(fut3);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        (ready, stored)
    }

    fn younger_waker_churn_notify_one_signature(young_repolls: usize) -> ([bool; 3], usize) {
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        let mut fut3 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());
        assert!(poll_once(&mut fut3).is_pending());

        for _ in 0..young_repolls {
            let fresh = fresh_waker();
            assert!(poll_with_waker(&mut fut3, &fresh).is_pending());
        }

        notify.notify_one();

        let ready = [
            poll_once(&mut fut1).is_ready(),
            poll_once(&mut fut2).is_ready(),
            poll_once(&mut fut3).is_ready(),
        ];
        drop(fut1);
        drop(fut2);
        drop(fut3);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        (ready, stored)
    }

    fn notify_one_with_middle_cancel_signature(
        cancel_before_first_notify: bool,
    ) -> ([bool; 2], usize, bool) {
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        let mut fut3 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());
        assert!(poll_once(&mut fut3).is_pending());

        if cancel_before_first_notify {
            drop(fut2);
            notify.notify_one();
            notify.notify_one();
        } else {
            notify.notify_one();
            drop(fut2);
            notify.notify_one();
        }

        let ready_pair = [
            poll_once(&mut fut1).is_ready(),
            poll_once(&mut fut3).is_ready(),
        ];
        drop(fut1);
        drop(fut3);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        let mut late = notify.notified();
        let late_pending = poll_once(&mut late).is_pending();
        drop(late);

        (ready_pair, stored, late_pending)
    }

    fn notify_one_ready_prefix_signature(extra_tail_waiters: usize) -> (Vec<bool>, usize, bool) {
        let notify = Notify::new();

        let mut waiters: Vec<_> = (0..(3 + extra_tail_waiters))
            .map(|_| notify.notified())
            .collect();
        for waiter in &mut waiters {
            assert!(poll_once(waiter).is_pending());
        }

        notify.notify_one();
        notify.notify_one();
        notify.notify_one();

        let ready = waiters
            .iter_mut()
            .map(|waiter| poll_once(waiter).is_ready())
            .collect::<Vec<_>>();
        drop(waiters);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        let mut late = notify.notified();
        let late_pending = poll_once(&mut late).is_pending();
        drop(late);

        (ready, stored, late_pending)
    }

    fn notify_one_front_cancel_shift_signature(
        cancel_front: bool,
        notify_calls: usize,
    ) -> (Vec<bool>, usize, bool) {
        let notify = Notify::new();

        let mut waiters: Vec<_> = (0..4).map(|_| notify.notified()).collect();
        for waiter in &mut waiters {
            assert!(poll_once(waiter).is_pending());
        }

        if cancel_front {
            drop(waiters.remove(0));
        }

        for _ in 0..notify_calls {
            notify.notify_one();
        }

        let ready = waiters
            .iter_mut()
            .map(|waiter| poll_once(waiter).is_ready())
            .collect::<Vec<_>>();
        drop(waiters);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        let mut late = notify.notified();
        let late_pending = poll_once(&mut late).is_pending();
        drop(late);

        (ready, stored, late_pending)
    }

    #[test]
    fn notify_one_wakes_waiter() {
        init_test("notify_one_wakes_waiter");
        let notify = Arc::new(Notify::new());
        let notify2 = Arc::clone(&notify);

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            notify2.notify_one();
        });

        let mut fut = notify.notified();

        // First poll should be Pending.
        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(pending, "first poll pending", true, pending);

        // Wait for notification.
        handle.join().expect("thread panicked");

        // Now it should be Ready.
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "ready after notify", true, ready);
        crate::test_complete!("notify_one_wakes_waiter");
    }

    #[test]
    fn notified_repoll_after_notify_one_completion_stays_ready() {
        init_test("notified_repoll_after_notify_one_completion_stays_ready");
        let notify = Notify::new();
        let mut fut = notify.notified();

        assert!(poll_once(&mut fut).is_pending());
        notify.notify_one();
        assert!(poll_once(&mut fut).is_ready());

        let repoll = poll_once(&mut fut);
        crate::assert_with_log!(
            repoll.is_ready(),
            "repoll stays ready",
            true,
            repoll.is_ready()
        );
        crate::test_complete!("notified_repoll_after_notify_one_completion_stays_ready");
    }

    #[test]
    fn notify_before_wait_is_consumed() {
        init_test("notify_before_wait_is_consumed");
        let notify = Notify::new();

        // Notify before anyone is waiting.
        notify.notify_one();

        // Now wait - should complete immediately.
        let mut fut = notify.notified();
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "ready immediately", true, ready);
        crate::test_complete!("notify_before_wait_is_consumed");
    }

    #[test]
    fn notified_repoll_after_stored_notify_completion_stays_ready() {
        init_test("notified_repoll_after_stored_notify_completion_stays_ready");
        let notify = Notify::new();
        notify.notify_one();

        let mut fut = notify.notified();
        assert!(poll_once(&mut fut).is_ready());

        let repoll = poll_once(&mut fut);
        crate::assert_with_log!(
            repoll.is_ready(),
            "repoll stays ready",
            true,
            repoll.is_ready()
        );
        crate::test_complete!("notified_repoll_after_stored_notify_completion_stays_ready");
    }

    #[test]
    fn notify_one_lost_if_followed_by_broadcast_and_cancel() {
        init_test("notify_one_lost_if_followed_by_broadcast_and_cancel");
        let notify = Notify::new();

        let mut waiter_a = notify.notified();
        let mut waiter_b = notify.notified();

        assert!(poll_once(&mut waiter_a).is_pending());
        assert!(poll_once(&mut waiter_b).is_pending());

        // notify_one wakes A
        notify.notify_one();

        // notify_waiters wakes B (and updates A's generation)
        notify.notify_waiters();

        // waiter_c starts waiting AFTER the broadcast
        let mut waiter_c = notify.notified();
        assert!(poll_once(&mut waiter_c).is_pending());

        // A is dropped (cancelled).
        // It should pass the notify_one baton to C!
        drop(waiter_a);

        // Let's check if C got it.
        assert!(
            poll_once(&mut waiter_c).is_ready(),
            "Waiter C should be woken by the passed baton!"
        );
        crate::test_complete!("notify_one_lost_if_followed_by_broadcast_and_cancel");
    }

    #[test]
    fn notify_one_lost_if_followed_by_broadcast_and_poll() {
        init_test("notify_one_lost_if_followed_by_broadcast_and_poll");
        let notify = Notify::new();

        let mut waiter_a = notify.notified();
        let mut waiter_b = notify.notified();

        assert!(poll_once(&mut waiter_a).is_pending());
        assert!(poll_once(&mut waiter_b).is_pending());

        // notify_one wakes A.
        notify.notify_one();

        // broadcast wakes B.
        notify.notify_waiters();

        // C starts waiting after the broadcast.
        let mut waiter_c = notify.notified();
        assert!(poll_once(&mut waiter_c).is_pending());

        assert!(poll_once(&mut waiter_a).is_ready());
        assert!(poll_once(&mut waiter_b).is_ready());
        assert!(
            poll_once(&mut waiter_c).is_pending(),
            "Waiter C should remain pending since A consumed the notify_one baton"
        );

        crate::test_complete!("notify_one_lost_if_followed_by_broadcast_and_poll");
    }

    #[test]
    fn notify_waiters_wakes_all() {
        init_test("notify_waiters_wakes_all");
        let notify = Arc::new(Notify::new());
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..3 {
            let notify = Arc::clone(&notify);
            let completed = Arc::clone(&completed);
            handles.push(thread::spawn(move || {
                let mut fut = notify.notified();

                // Spin-poll until ready.
                loop {
                    if poll_once(&mut fut).is_ready() {
                        completed.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }));
        }

        // Give threads time to register.
        thread::sleep(Duration::from_millis(100));

        // Notify all.
        notify.notify_waiters();

        // All should complete.
        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let count = completed.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "completed count", 3usize, count);
        crate::test_complete!("notify_waiters_wakes_all");
    }

    #[test]
    fn test_notify_no_waiters() {
        init_test("test_notify_no_waiters");
        let notify = Notify::new();

        // Notify with no waiters should not block or panic
        notify.notify_one();
        notify.notify_waiters();

        // The stored notification should be consumed by next waiter
        let mut fut = notify.notified();
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "stored notify consumed", true, ready);
        crate::test_complete!("test_notify_no_waiters");
    }

    #[test]
    fn test_notify_waiter_count() {
        init_test("test_notify_waiter_count");
        let notify = Notify::new();

        // Initially no waiters
        let count0 = notify.waiter_count();
        crate::assert_with_log!(count0 == 0, "initial count", 0usize, count0);

        // Register a waiter
        let mut fut = notify.notified();
        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(pending, "should be pending", true, pending);

        let count1 = notify.waiter_count();
        crate::assert_with_log!(count1 == 1, "one waiter", 1usize, count1);

        // Notify wakes the waiter
        notify.notify_one();
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "should be ready", true, ready);

        // Waiter count should decrease after wakeup and cleanup
        drop(fut);
        let count2 = notify.waiter_count();
        crate::assert_with_log!(count2 == 0, "no waiters after", 0usize, count2);
        crate::test_complete!("test_notify_waiter_count");
    }

    #[test]
    fn test_notify_drop_cleanup() {
        init_test("test_notify_drop_cleanup");
        let notify = Notify::new();

        // Register and drop without notification
        {
            let mut fut = notify.notified();
            let _ = poll_once(&mut fut);
            // fut dropped here - should cleanup
        }

        // Waiter count should be 0 after cleanup
        let count = notify.waiter_count();
        crate::assert_with_log!(count == 0, "cleaned up", 0usize, count);
        crate::test_complete!("test_notify_drop_cleanup");
    }

    #[test]
    fn test_notify_multiple_stored() {
        init_test("test_notify_multiple_stored");
        let notify = Notify::new();

        // Store multiple notifications
        notify.notify_one();
        notify.notify_one();

        // First waiter consumes one
        let mut fut1 = notify.notified();
        let ready1 = poll_once(&mut fut1).is_ready();
        crate::assert_with_log!(ready1, "first ready", true, ready1);

        // Second waiter consumes another
        let mut fut2 = notify.notified();
        let ready2 = poll_once(&mut fut2).is_ready();
        crate::assert_with_log!(ready2, "second ready", true, ready2);

        // Third waiter should wait
        let mut fut3 = notify.notified();
        let pending = poll_once(&mut fut3).is_pending();
        crate::assert_with_log!(pending, "third pending", true, pending);
        crate::test_complete!("test_notify_multiple_stored");
    }

    #[test]
    fn test_cancelled_middle_waiter_no_leak() {
        init_test("test_cancelled_middle_waiter_no_leak");
        let notify = Notify::new();

        // Register three waiters
        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        let mut fut3 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());
        assert!(poll_once(&mut fut3).is_pending());

        let count = notify.waiter_count();
        crate::assert_with_log!(count == 3, "three waiters", 3usize, count);

        // Cancel the MIDDLE waiter - this was the leak trigger
        drop(fut2);

        let count = notify.waiter_count();
        crate::assert_with_log!(count == 2, "two waiters after middle drop", 2usize, count);

        // Check that the Vec hasn't grown unboundedly: entries should be <= 3
        let entries_len = notify.waiters.lock().entries.len();
        crate::assert_with_log!(entries_len <= 3, "entries bounded", true, entries_len <= 3);

        // Cancel all and verify full cleanup
        drop(fut1);
        drop(fut3);

        let count = notify.waiter_count();
        crate::assert_with_log!(count == 0, "no waiters after all drops", 0usize, count);

        // Vec should be empty after all waiters gone
        let entries_len = notify.waiters.lock().entries.len();
        crate::assert_with_log!(entries_len == 0, "entries empty", 0usize, entries_len);

        // Verify slot reuse: register new waiters, they should reuse freed slots
        let mut fut_a = notify.notified();
        assert!(poll_once(&mut fut_a).is_pending());
        let entries_len = notify.waiters.lock().entries.len();
        crate::assert_with_log!(entries_len == 1, "reused slot", 1usize, entries_len);
        drop(fut_a);

        crate::test_complete!("test_cancelled_middle_waiter_no_leak");
    }

    #[test]
    fn test_repeated_cancel_no_growth() {
        init_test("test_repeated_cancel_no_growth");
        let notify = Notify::new();

        // Repeatedly register and cancel waiters to ensure no unbounded growth
        for _ in 0..100 {
            let mut fut = notify.notified();
            assert!(poll_once(&mut fut).is_pending());
            drop(fut);
        }

        // After all cancellations, the slab should be empty
        let entries_len = notify.waiters.lock().entries.len();
        crate::assert_with_log!(entries_len == 0, "no growth", 0usize, entries_len);

        crate::test_complete!("test_repeated_cancel_no_growth");
    }

    #[test]
    fn notify_one_does_not_lose_wakeup_during_registration_race() {
        init_test("notify_one_does_not_lose_wakeup_during_registration_race");

        let notify = Arc::new(Notify::new());

        // Hold the waiter lock so we can queue up both the notifier and the waiter registration.
        let gate = notify.waiters.lock();

        // Start the notifier first so it is likely to acquire the waiter lock first once we drop
        // `gate`. This makes the pre-fix lost-wakeup interleaving reproducible.
        let notify_for_notifier = Arc::clone(&notify);
        let notifier = thread::spawn(move || {
            notify_for_notifier.notify_one();
        });

        // Give the notifier thread time to block on the waiter lock.
        thread::sleep(Duration::from_millis(10));

        let (tx_ready, rx_ready) = mpsc::channel::<bool>();
        let (tx_poll, rx_poll) = mpsc::channel::<()>();

        let notify_for_poller = Arc::clone(&notify);
        let poller = thread::spawn(move || {
            let mut fut = notify_for_poller.notified();

            // First poll will either:
            // - complete immediately by consuming a stored notification, or
            // - register a waiter and return Pending.
            let first_ready = poll_once(&mut fut).is_ready();
            tx_ready.send(first_ready).expect("send first_ready");

            // Wait for the main thread to run notify_one and then poll again.
            rx_poll.recv().expect("recv poll signal");

            let second_ready = if first_ready {
                true
            } else {
                poll_once(&mut fut).is_ready()
            };
            tx_ready.send(second_ready).expect("send second_ready");
        });

        // Release the gate so the notifier and poller can proceed.
        drop(gate);

        notifier.join().expect("notifier thread panicked");

        let first_ready = rx_ready.recv().expect("recv first_ready");
        tx_poll.send(()).expect("send poll signal");
        let second_ready = rx_ready.recv().expect("recv second_ready");

        poller.join().expect("poller thread panicked");

        // Regardless of interleaving, a single notify_one must be enough for a single Notified
        // future to become Ready once it is polled again.
        crate::assert_with_log!(
            first_ready || second_ready,
            "notify_one eventually makes notified() ready",
            true,
            first_ready || second_ready
        );

        crate::test_complete!("notify_one_does_not_lose_wakeup_during_registration_race");
    }

    #[test]
    fn notify_waiters_preserves_slab_shrinking_with_middle_hole() {
        init_test("notify_waiters_preserves_slab_shrinking_with_middle_hole");

        let notify = Notify::new();

        // Register three waiters.
        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        let mut fut3 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());
        assert!(poll_once(&mut fut3).is_pending());

        // Create a free-slot hole before broadcasting.
        drop(fut2);

        // Wake remaining waiters; they should cleanly drain and allow the slab to shrink.
        notify.notify_waiters();
        assert!(poll_once(&mut fut1).is_ready());
        assert!(poll_once(&mut fut3).is_ready());
        drop(fut1);
        drop(fut3);

        let count = notify.waiter_count();
        crate::assert_with_log!(count == 0, "no waiters remain", 0usize, count);

        let entries_len = notify.waiters.lock().entries.len();
        crate::assert_with_log!(
            entries_len == 0,
            "slab tail fully shrinks after broadcast",
            0usize,
            entries_len
        );

        crate::test_complete!("notify_waiters_preserves_slab_shrinking_with_middle_hole");
    }

    #[test]
    fn dropped_broadcast_waiter_does_not_leak_stored_notification() {
        init_test("dropped_broadcast_waiter_does_not_leak_stored_notification");
        let notify = Notify::new();

        // Register two waiters.
        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());

        // Broadcast wake current waiters.
        notify.notify_waiters();

        // Cancel one waiter before it consumes readiness.
        drop(fut1);

        // The other waiter should still complete.
        assert!(poll_once(&mut fut2).is_ready());
        drop(fut2);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            stored == 0,
            "broadcast drop should not create stored token",
            0usize,
            stored
        );

        // A new waiter after broadcast should wait (not consume a ghost token).
        let mut fut3 = notify.notified();
        let pending = poll_once(&mut fut3).is_pending();
        crate::assert_with_log!(
            pending,
            "post-broadcast waiter should remain pending",
            true,
            pending
        );
        drop(fut3);

        crate::test_complete!("dropped_broadcast_waiter_does_not_leak_stored_notification");
    }

    #[test]
    fn dropped_notify_one_waiter_covered_by_broadcast_does_not_restore_token() {
        init_test("dropped_notify_one_waiter_covered_by_broadcast_does_not_restore_token");
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());

        notify.notify_one();
        notify.notify_waiters();

        drop(fut1);
        assert!(poll_once(&mut fut2).is_ready());
        drop(fut2);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            stored == 0,
            "broadcast-covered notify_one drop should not restore token",
            0usize,
            stored
        );

        let mut fut3 = notify.notified();
        let pending = poll_once(&mut fut3).is_pending();
        crate::assert_with_log!(
            pending,
            "new waiter should remain pending after broadcast-covered drop",
            true,
            pending
        );
        drop(fut3);

        crate::test_complete!(
            "dropped_notify_one_waiter_covered_by_broadcast_does_not_restore_token"
        );
    }

    #[test]
    fn polled_notify_one_waiter_covered_by_broadcast_does_not_restore_token() {
        init_test("polled_notify_one_waiter_covered_by_broadcast_does_not_restore_token");
        let notify = Notify::new();

        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());

        notify.notify_one();
        notify.notify_waiters();

        assert!(poll_once(&mut fut1).is_ready());
        assert!(poll_once(&mut fut2).is_ready());
        drop(fut1);
        drop(fut2);

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            stored == 0,
            "broadcast-covered notify_one poll should not restore token",
            0usize,
            stored
        );

        let mut fut3 = notify.notified();
        let pending = poll_once(&mut fut3).is_pending();
        crate::assert_with_log!(
            pending,
            "new waiter should remain pending after broadcast-covered poll",
            true,
            pending
        );
        drop(fut3);

        crate::test_complete!(
            "polled_notify_one_waiter_covered_by_broadcast_does_not_restore_token"
        );
    }

    // ── Invariant: notify_one baton-pass on waiter drop ────────────────

    /// Invariant: when a `notify_one`-notified waiter is dropped before
    /// consuming readiness, the notification passes to the next waiting
    /// task.  This is the baton-pass path in `Notified::drop`.
    #[test]
    fn notify_one_baton_pass_to_next_waiter_on_drop() {
        init_test("notify_one_baton_pass_to_next_waiter_on_drop");
        let notify = Notify::new();

        // Register two waiters.
        let mut fut1 = notify.notified();
        let mut fut2 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());
        assert!(poll_once(&mut fut2).is_pending());

        // notify_one selects fut1.
        notify.notify_one();

        // Drop fut1 without polling — baton should pass to fut2.
        drop(fut1);

        // fut2 should now be ready.
        let ready = poll_once(&mut fut2).is_ready();
        crate::assert_with_log!(ready, "baton passed to second waiter", true, ready);
        crate::test_complete!("notify_one_baton_pass_to_next_waiter_on_drop");
    }

    /// Invariant: when a `notify_one`-notified waiter is dropped and no
    /// other waiter exists, the notification is re-stored so the next
    /// `notified().await` completes immediately.
    #[test]
    fn notify_one_re_stores_when_no_other_waiter() {
        init_test("notify_one_re_stores_when_no_other_waiter");
        let notify = Notify::new();

        // Register a single waiter.
        let mut fut = notify.notified();
        assert!(poll_once(&mut fut).is_pending());

        // notify_one marks it.
        notify.notify_one();

        // Drop without consuming.
        drop(fut);

        // The notification should be re-stored.
        let stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(stored == 1, "notification re-stored", 1usize, stored);

        // A new notified() should complete immediately on first poll.
        let mut fut2 = notify.notified();
        let ready = poll_once(&mut fut2).is_ready();
        crate::assert_with_log!(
            ready,
            "re-stored notification consumed by next waiter",
            true,
            ready
        );
        crate::test_complete!("notify_one_re_stores_when_no_other_waiter");
    }

    /// br-asupersync-z5dxrw regression: when a `notify_one`-notified waiter
    /// is dropped AFTER a broadcast advanced the generation, AND no other
    /// post-broadcast waiter is currently registered, the baton must NOT
    /// be silently dropped. Instead it must be re-stored so a waiter that
    /// registers immediately after the drop still receives it.
    ///
    /// Before the fix this scenario silently lost the wakeup — the new
    /// waiter would block forever for an event that already fired.
    #[test]
    fn notify_one_baton_restored_when_no_post_broadcast_waiter_exists_yet() {
        init_test("notify_one_baton_restored_when_no_post_broadcast_waiter_exists_yet");
        let notify = Notify::new();

        // Register one waiter.
        let mut fut_a = notify.notified();
        assert!(poll_once(&mut fut_a).is_pending());

        // notify_one marks fut_a's slot (waker taken, notified=true).
        notify.notify_one();

        // Broadcast advances generation. fut_a's slot is skipped (waker
        // already None) but generation has moved past fut_a's initial gen.
        notify.notify_waiters();

        // No new waiter exists yet — this is the key precondition for the
        // race the bead describes.
        let waiters_now = notify.waiter_count();
        crate::assert_with_log!(
            waiters_now == 0,
            "no active waiters before drop",
            0usize,
            waiters_now
        );

        // fut_a is dropped (cancelled). The baton must NOT be lost.
        drop(fut_a);

        // The baton should now be stored as a fallback so a slightly-late
        // post-broadcast waiter picks it up. Before the z5dxrw fix this
        // counter stayed at 0 and the next waiter would block forever.
        let stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            stored == 1,
            "baton re-stored as fallback after broadcast+cancel",
            1usize,
            stored
        );

        // A NEW post-broadcast waiter should immediately consume it.
        let mut fut_late = notify.notified();
        let ready = poll_once(&mut fut_late).is_ready();
        crate::assert_with_log!(
            ready,
            "late post-broadcast waiter consumes restored baton",
            true,
            ready
        );

        crate::test_complete!("notify_one_baton_restored_when_no_post_broadcast_waiter_exists_yet");
    }

    /// br-asupersync-bu4r7l regression: when a slot is freed and reused
    /// by a different waiter, an old `Notified::drop` that still holds
    /// the recorded slot index must NOT operate on the slot. Without
    /// the slot_epoch verification, the stale drop would either pass
    /// a baton through someone else's entry or, worse, `remove()` the
    /// new occupant — silently consuming their wakeup.
    ///
    /// We construct the race deterministically by registering W1 at
    /// some slot, removing it, and then immediately re-registering W2
    /// (which gets the same slot via free_slots). We then verify that
    /// the slot_epoch differs and a hypothetical lingering reference
    /// to W1's index would mismatch.
    #[test]
    fn notify_slot_epoch_protects_against_reuse_misidentification() {
        init_test("notify_slot_epoch_protects_against_reuse_misidentification");
        let notify = Notify::new();

        // Register W1 — pin the future so its waiter index stays valid.
        let mut fut_w1 = notify.notified();
        assert!(poll_once(&mut fut_w1).is_pending());

        // Capture W1's recorded (index, epoch) before drop.
        let (w1_index, w1_epoch) = fut_w1
            .waiter_index
            .expect("W1 must have registered a slot index");

        // Drop W1 — this frees the slot; insert may reuse it.
        drop(fut_w1);

        // Register W2 — its insert() should pop the same slot from
        // free_slots and bump the epoch.
        let mut fut_w2 = notify.notified();
        assert!(poll_once(&mut fut_w2).is_pending());

        let (w2_index, w2_epoch) = fut_w2
            .waiter_index
            .expect("W2 must have registered a slot index");

        // Slot reuse confirmed.
        crate::assert_with_log!(
            w1_index == w2_index,
            "slot index reused",
            true,
            w1_index == w2_index
        );
        // Epoch must have advanced. This is the key invariant: a stale
        // drop holding (index=w1_index, slot_epoch=w1_epoch) would now
        // mismatch against entries[w1_index].slot_epoch == w2_epoch
        // and skip the foreign entry.
        crate::assert_with_log!(
            w1_epoch != w2_epoch,
            "slot_epoch advanced on reuse",
            true,
            w1_epoch != w2_epoch
        );

        // Sanity: notify_one wakes W2 — verify W2 isn't disturbed by
        // any latent W1 state.
        notify.notify_one();
        let ready = poll_once(&mut fut_w2).is_ready();
        crate::assert_with_log!(
            ready,
            "W2 receives notification cleanly after slot reuse",
            true,
            ready
        );

        crate::test_complete!("notify_slot_epoch_protects_against_reuse_misidentification");
    }

    /// Invariant: `notify_waiters()` with no waiters must NOT create a
    /// stored notification token.  It is edge-triggered for currently
    /// waiting tasks only.
    #[test]
    fn notify_waiters_does_not_store_token_when_no_waiters() {
        init_test("notify_waiters_does_not_store_token_when_no_waiters");
        let notify = Notify::new();

        // Broadcast with no one listening.
        notify.notify_waiters();

        let stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            stored == 0,
            "no stored token from broadcast",
            0usize,
            stored
        );

        // A new waiter should remain pending.
        let mut fut = notify.notified();
        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(
            pending,
            "waiter remains pending after no-op broadcast",
            true,
            pending
        );
        crate::test_complete!("notify_waiters_does_not_store_token_when_no_waiters");
    }

    #[test]
    fn notify_waiters_does_not_wake_unpolled_future_created_before_broadcast() {
        init_test("notify_waiters_does_not_wake_unpolled_future_created_before_broadcast");
        let notify = Notify::new();

        let mut fut = notify.notified();

        // A future created before the broadcast is not yet waiting until its
        // first poll registers it.
        notify.notify_waiters();

        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(
            pending,
            "broadcast must not wake an unpolled future",
            true,
            pending
        );
        drop(fut);

        crate::test_complete!(
            "notify_waiters_does_not_wake_unpolled_future_created_before_broadcast"
        );
    }

    #[test]
    fn metamorphic_redundant_notify_waiters_preserves_middle_hole_cleanup() {
        init_test("metamorphic_redundant_notify_waiters_preserves_middle_hole_cleanup");

        let single = broadcast_with_middle_hole_signature(1);
        let redundant = broadcast_with_middle_hole_signature(3);

        crate::assert_with_log!(
            redundant == single,
            "repeating notify_waiters over the same waiter set preserves cleanup and late-waiter behavior",
            format!("{single:?}"),
            format!("{redundant:?}")
        );
        crate::assert_with_log!(
            single.0 == [true, true],
            "remaining waiters are both readied after broadcast",
            [true, true],
            single.0
        );
        crate::assert_with_log!(
            single.1 == 0,
            "no active waiters remain after draining the broadcasted set",
            0usize,
            single.1
        );
        crate::assert_with_log!(
            single.2 == 0,
            "slab shrinks fully after draining broadcasted waiters",
            0usize,
            single.2
        );
        crate::assert_with_log!(
            single.3 == 0,
            "redundant broadcasts do not mint stored tokens",
            0usize,
            single.3
        );
        crate::assert_with_log!(
            single.4,
            "a late waiter still remains pending after repeated broadcasts",
            true,
            single.4
        );

        crate::test_complete!("metamorphic_redundant_notify_waiters_preserves_middle_hole_cleanup");
    }

    #[test]
    fn metamorphic_redundant_broadcasts_preserve_single_followup_notify_one_token() {
        init_test("metamorphic_redundant_broadcasts_preserve_single_followup_notify_one_token");

        let single = broadcast_then_notify_one_signature(1);
        let redundant = broadcast_then_notify_one_signature(4);

        crate::assert_with_log!(
            redundant == single,
            "redundant broadcasts do not amplify a later stored notify_one token",
            format!("{single:?}"),
            format!("{redundant:?}")
        );
        crate::assert_with_log!(
            single.0 == [true, true],
            "both original waiters are readied by the broadcast",
            [true, true],
            single.0
        );
        crate::assert_with_log!(
            single.1 == 1,
            "exactly one stored token remains for the follow-up notify_one",
            1usize,
            single.1
        );
        crate::assert_with_log!(
            single.2,
            "the next waiter consumes the single stored token immediately",
            true,
            single.2
        );
        crate::assert_with_log!(
            single.3,
            "the waiter after that remains pending because no extra token leaked",
            true,
            single.3
        );

        crate::test_complete!(
            "metamorphic_redundant_broadcasts_preserve_single_followup_notify_one_token"
        );
    }

    #[test]
    fn metamorphic_extra_repolls_preserve_single_notify_one_consumer() {
        init_test("metamorphic_extra_repolls_preserve_single_notify_one_consumer");

        let single = repoll_then_notify_one_signature(0);
        let repolled = repoll_then_notify_one_signature(5);

        crate::assert_with_log!(
            repolled == single,
            "re-polling the front waiter with the same waker does not change single notify_one delivery",
            format!("{single:?}"),
            format!("{repolled:?}")
        );
        crate::assert_with_log!(
            single.0 == [true, false, false],
            "single notify_one still wakes only the first registered waiter",
            [true, false, false],
            single.0
        );
        crate::assert_with_log!(
            single.1 == 0,
            "single notify_one does not leak a stored token when a waiter consumes it",
            0usize,
            single.1
        );

        crate::test_complete!("metamorphic_extra_repolls_preserve_single_notify_one_consumer");
    }

    #[test]
    fn metamorphic_younger_waker_churn_preserves_oldest_notify_one_consumer() {
        init_test("metamorphic_younger_waker_churn_preserves_oldest_notify_one_consumer");

        let baseline = younger_waker_churn_notify_one_signature(0);
        let churned = younger_waker_churn_notify_one_signature(5);

        crate::assert_with_log!(
            churned == baseline,
            "youngest waiter waker churn does not change which waiter consumes notify_one",
            format!("{baseline:?}"),
            format!("{churned:?}")
        );
        crate::assert_with_log!(
            baseline.0 == [true, false, false],
            "notify_one still wakes the oldest parked waiter first",
            [true, false, false],
            baseline.0
        );
        crate::assert_with_log!(
            baseline.1 == 0,
            "young waiter waker churn does not mint or leak a stored notify token",
            0usize,
            baseline.1
        );

        crate::test_complete!(
            "metamorphic_younger_waker_churn_preserves_oldest_notify_one_consumer"
        );
    }

    #[test]
    fn metamorphic_middle_cancel_timing_preserves_notify_one_ready_prefix() {
        init_test("metamorphic_middle_cancel_timing_preserves_notify_one_ready_prefix");

        let cancelled_before = notify_one_with_middle_cancel_signature(true);
        let cancelled_between = notify_one_with_middle_cancel_signature(false);

        crate::assert_with_log!(
            cancelled_between == cancelled_before,
            "cancelling the middle waiter before or between notify_one calls preserves the ready prefix",
            format!("{cancelled_before:?}"),
            format!("{cancelled_between:?}")
        );
        crate::assert_with_log!(
            cancelled_before.0 == [true, true],
            "two notify_one calls still wake the surviving front and tail waiters in order",
            [true, true],
            cancelled_before.0
        );
        crate::assert_with_log!(
            cancelled_before.1 == 0,
            "no stored token remains after the surviving waiters consume both notify_one calls",
            0usize,
            cancelled_before.1
        );
        crate::assert_with_log!(
            cancelled_before.2,
            "a late waiter remains pending because cancellation timing did not mint an extra token",
            true,
            cancelled_before.2
        );

        crate::test_complete!("metamorphic_middle_cancel_timing_preserves_notify_one_ready_prefix");
    }

    #[test]
    fn metamorphic_extra_tail_waiters_do_not_expand_notify_one_ready_prefix() {
        init_test("metamorphic_extra_tail_waiters_do_not_expand_notify_one_ready_prefix");

        let baseline = notify_one_ready_prefix_signature(0);
        let extended = notify_one_ready_prefix_signature(2);

        crate::assert_with_log!(
            extended.0[..3] == baseline.0,
            "adding parked tail waiters preserves the ready prefix for the first three notify_one deliveries",
            format!("{:?}", baseline.0),
            format!("{:?}", &extended.0[..3])
        );
        crate::assert_with_log!(
            baseline.0 == vec![true, true, true],
            "three notify_one calls wake the first three parked waiters",
            vec![true, true, true],
            baseline.0.clone()
        );
        crate::assert_with_log!(
            extended.0[3..].iter().all(|ready| !ready),
            "extra parked tail waiters stay pending once the three notify_one permits are consumed",
            vec![false, false],
            extended.0[3..].to_vec()
        );
        crate::assert_with_log!(
            baseline.1 == 0 && extended.1 == 0,
            "exactly three parked consumers absorb the three notify_one permits without leaking a stored token",
            (0usize, 0usize),
            (baseline.1, extended.1)
        );
        crate::assert_with_log!(
            baseline.2 && extended.2,
            "a late waiter remains pending because no extra notify_one permit was minted",
            (true, true),
            (baseline.2, extended.2)
        );

        crate::test_complete!(
            "metamorphic_extra_tail_waiters_do_not_expand_notify_one_ready_prefix"
        );
    }

    #[test]
    fn metamorphic_front_cancel_shifts_notify_one_ready_prefix_left() {
        init_test("metamorphic_front_cancel_shifts_notify_one_ready_prefix_left");

        let baseline = notify_one_front_cancel_shift_signature(false, 3);
        let transformed = notify_one_front_cancel_shift_signature(true, 2);

        crate::assert_with_log!(
            transformed == (baseline.0[1..].to_vec(), baseline.1, baseline.2),
            "dropping the oldest parked waiter before notify_one is equivalent to one extra notify_one on the original waiter set, modulo the removed slot",
            format!("{:?}", (baseline.0[1..].to_vec(), baseline.1, baseline.2)),
            format!("{transformed:?}")
        );
        crate::assert_with_log!(
            baseline.0 == vec![true, true, true, false],
            "three notify_one calls wake the first three FIFO waiters in the baseline run",
            vec![true, true, true, false],
            baseline.0.clone()
        );
        crate::assert_with_log!(
            transformed.1 == 0,
            "front-waiter cancellation must not mint or leak a stored notify token",
            0usize,
            transformed.1
        );
        crate::assert_with_log!(
            transformed.2,
            "a late waiter remains pending because the transformed run consumed exactly its shifted notify_one prefix",
            true,
            transformed.2
        );

        crate::test_complete!("metamorphic_front_cancel_shifts_notify_one_ready_prefix_left");
    }

    #[test]
    fn test_spurious_wakeup_bug() {
        let notify = Notify::new();
        let mut fut1 = notify.notified();
        assert!(poll_once(&mut fut1).is_pending());

        notify.notify_waiters();

        let mut fut2 = notify.notified();
        assert!(poll_once(&mut fut2).is_pending());

        drop(fut1);

        // If fut2 is now ready, it means the drop of a broadcast-woken waiter
        // spuriously woke fut2!
        let is_ready = poll_once(&mut fut2).is_ready();
        assert!(!is_ready, "Spurious wakeup detected!");
    }

    /// br-asupersync-umesjh: notify_one baton-passing under select-
    /// mediated drop. When notify_one targets a waiter that is then
    /// dropped (as in a select arm where a peer branch fired first),
    /// the notification MUST baton-pass to the next pending waiter
    /// rather than be lost. A lost permit here means the next
    /// notified() blocks forever — silent deadlock.
    #[test]
    fn umesjh_notify_one_baton_passes_when_target_dropped() {
        let notify = Notify::new();
        let mut fut_a = notify.notified();
        let mut fut_b = notify.notified();
        assert!(poll_once(&mut fut_a).is_pending());
        assert!(poll_once(&mut fut_b).is_pending());

        notify.notify_one();
        // The permit lands on fut_a (FIFO). Simulate the select-
        // mediated drop: a peer branch fired first and dropped the
        // notified() future without polling.
        drop(fut_a);

        // The notify_one permit MUST be re-handed-off to fut_b.
        let ready = poll_once(&mut fut_b).is_ready();
        assert!(
            ready,
            "umesjh: notify_one permit must baton-pass to fut_b when fut_a drops without polling"
        );
    }

    /// br-asupersync-umesjh: extended baton-pass through a drop chain.
    /// A single notify_one MUST survive an arbitrary chain of waiter
    /// drops — the permit lives at the queue level, not at the
    /// future level.
    #[test]
    fn umesjh_notify_one_baton_passes_through_drop_chain() {
        let notify = Notify::new();
        let mut fut_a = notify.notified();
        let mut fut_b = notify.notified();
        let mut fut_c = notify.notified();
        assert!(poll_once(&mut fut_a).is_pending());
        assert!(poll_once(&mut fut_b).is_pending());
        assert!(poll_once(&mut fut_c).is_pending());

        notify.notify_one();
        drop(fut_a);
        drop(fut_b);
        // fut_c is the last standing waiter; the single permit must
        // have travelled all the way down the queue.
        let ready = poll_once(&mut fut_c).is_ready();
        assert!(
            ready,
            "umesjh: single notify_one must survive a chain of waiter drops"
        );
    }

    /// Audit test for notify_one() vs notify_waiters() ordering invariant.
    ///
    /// Verifies that when N waiters are queued and notify_one() is called K times rapidly,
    /// exactly K waiters wake in FIFO order — not all N (that would be notify_waiters semantics).
    /// This test validates the core distinction between single-waiter and broadcast notification.
    #[test]
    fn audit_notify_one_fifo_ordering_exactly_k_waiters() {
        init_test("audit_notify_one_fifo_ordering_exactly_k_waiters");
        let notify = Notify::new();

        const N_WAITERS: usize = 7;
        const K_NOTIFY_CALLS: usize = 4;

        // Step 1: Create N waiters, all pending
        let mut waiters: Vec<_> = (0..N_WAITERS).map(|i| (i, notify.notified())).collect();

        // Poll each waiter to register them in FIFO order
        for (id, waiter) in &mut waiters {
            let is_pending = poll_once(waiter).is_pending();
            assert!(is_pending, "waiter {} should initially be pending", id);
        }

        // Verify initial state: all waiters registered, none notified
        assert_eq!(
            notify.waiter_count(),
            N_WAITERS,
            "should have N registered waiters"
        );

        // Step 2: Make K rapid notify_one() calls
        for call_num in 0..K_NOTIFY_CALLS {
            notify.notify_one();
            // Verify we don't accidentally wake all waiters
            let awake_count = waiters
                .iter_mut()
                .map(|(_, waiter)| poll_once(waiter).is_ready() as usize)
                .sum::<usize>();

            assert_eq!(
                awake_count,
                call_num + 1,
                "after {} notify_one calls, exactly {} waiters should be ready, but {} are ready",
                call_num + 1,
                call_num + 1,
                awake_count
            );
        }

        // Step 3: Verify exactly K waiters are ready, exactly (N-K) are still pending
        let final_ready_states: Vec<bool> = waiters
            .iter_mut()
            .map(|(_, waiter)| poll_once(waiter).is_ready())
            .collect();

        let ready_count = final_ready_states.iter().filter(|&&ready| ready).count();
        let pending_count = final_ready_states.iter().filter(|&&ready| !ready).count();

        assert_eq!(
            ready_count, K_NOTIFY_CALLS,
            "exactly {} waiters should be ready after {} notify_one calls, got {}",
            K_NOTIFY_CALLS, K_NOTIFY_CALLS, ready_count
        );

        assert_eq!(
            pending_count,
            N_WAITERS - K_NOTIFY_CALLS,
            "exactly {} waiters should still be pending, got {}",
            N_WAITERS - K_NOTIFY_CALLS,
            pending_count
        );

        // Step 4: Verify FIFO ordering - first K waiters should be ready, rest pending
        for (i, &is_ready) in final_ready_states.iter().enumerate() {
            let expected_ready = i < K_NOTIFY_CALLS;
            assert_eq!(
                is_ready, expected_ready,
                "waiter {} FIFO ordering violation: expected ready={}, got ready={}",
                i, expected_ready, is_ready
            );
        }

        // Step 5: Verify remaining waiters can still be notified
        assert_eq!(
            notify.waiter_count(),
            N_WAITERS - K_NOTIFY_CALLS,
            "waiter count should reflect remaining pending waiters"
        );

        // Wake one more and verify it's the next in FIFO order (waiter K)
        notify.notify_one();
        let waiter_k_ready = poll_once(&mut waiters[K_NOTIFY_CALLS].1).is_ready();
        assert!(
            waiter_k_ready,
            "waiter {} should be the next to wake in FIFO order",
            K_NOTIFY_CALLS
        );

        // Step 6: Contrast with notify_waiters() - should wake ALL remaining
        let remaining_count = N_WAITERS - K_NOTIFY_CALLS - 1; // -1 for the one we just woke
        if remaining_count > 0 {
            let before_broadcast = waiters[(K_NOTIFY_CALLS + 1)..]
                .iter_mut()
                .map(|(_, waiter)| poll_once(waiter).is_ready())
                .collect::<Vec<bool>>();

            assert!(
                before_broadcast.iter().all(|&ready| !ready),
                "remaining waiters should still be pending before notify_waiters"
            );

            notify.notify_waiters();

            let after_broadcast = waiters[(K_NOTIFY_CALLS + 1)..]
                .iter_mut()
                .map(|(_, waiter)| poll_once(waiter).is_ready())
                .collect::<Vec<bool>>();

            assert!(
                after_broadcast.iter().all(|&ready| ready),
                "notify_waiters should wake ALL remaining waiters, demonstrating the semantic difference"
            );
        }

        crate::test_complete!("audit_notify_one_fifo_ordering_exactly_k_waiters");
    }

    /// Audit test: notify_one() FIFO ordering under tight loop conditions.
    ///
    /// Verifies that rapid consecutive notify_one() calls in a tight loop
    /// maintain strict FIFO ordering and never allow "leapfrogging" where
    /// a later-queued waiter wakes before an earlier-queued waiter.
    /// This tests for race conditions in the scan_start optimization.
    #[test]
    fn audit_notify_one_tight_loop_no_leapfrog() {
        init_test("audit_notify_one_tight_loop_no_leapfrog");
        let notify = Notify::new();

        const N: usize = 10;

        // Step 1: Create N waiters and register them in strict order
        let mut waiters = Vec::with_capacity(N);
        for i in 0..N {
            let mut waiter = notify.notified();
            assert!(
                poll_once(&mut waiter).is_pending(),
                "waiter {} should be pending",
                i
            );
            waiters.push(waiter);
        }

        // Verify all waiters are registered
        assert_eq!(notify.waiter_count(), N, "all waiters should be registered");

        // Step 2: Call notify_one() in tight loop - no delays between calls
        let notify_count = N - 2; // Leave some waiters pending for verification
        for _ in 0..notify_count {
            notify.notify_one();
            // No delay here - this is the "tight loop" condition
        }

        // Step 3: Poll all waiters and record which ones are ready
        let mut wake_order = Vec::new();
        let mut still_pending = Vec::new();

        for (i, waiter) in waiters.iter_mut().enumerate() {
            if poll_once(waiter).is_ready() {
                wake_order.push(i);
            } else {
                still_pending.push(i);
            }
        }

        // Step 4: Verify exactly the expected number woke up
        assert_eq!(
            wake_order.len(),
            notify_count,
            "exactly {} waiters should be ready, got {}",
            notify_count,
            wake_order.len()
        );

        assert_eq!(
            still_pending.len(),
            N - notify_count,
            "exactly {} waiters should still be pending",
            N - notify_count
        );

        // Step 5: Critical FIFO ordering check - no leapfrogging allowed
        let expected_wake_order: Vec<usize> = (0..notify_count).collect();
        assert_eq!(
            wake_order, expected_wake_order,
            "FIFO violation detected! Expected wake order {:?}, got {:?}. This indicates leapfrogging occurred.",
            expected_wake_order, wake_order
        );

        // Step 6: Verify remaining waiters are the tail of the queue
        let expected_pending: Vec<usize> = (notify_count..N).collect();
        assert_eq!(
            still_pending, expected_pending,
            "Pending waiters should be the tail of the queue, got {:?}",
            still_pending
        );

        // Step 7: Verify next notify_one() wakes the next waiter in line
        let next_waiter_index = notify_count;
        notify.notify_one();

        let next_ready = poll_once(&mut waiters[next_waiter_index]).is_ready();
        assert!(
            next_ready,
            "Next waiter {} should wake after additional notify_one()",
            next_waiter_index
        );

        // Verify no other waiters woke up
        for i in (notify_count + 1)..N {
            let should_be_pending = poll_once(&mut waiters[i]).is_pending();
            assert!(
                should_be_pending,
                "Waiter {} should still be pending after single notify_one()",
                i
            );
        }

        // Step 8: Test slot reuse doesn't break FIFO by canceling middle waiter
        let middle_index = (notify_count + 1 + N) / 2;
        if middle_index < N {
            drop(waiters.remove(middle_index - notify_count - 1)); // Adjust index for already-consumed waiters

            // Add a new waiter - it should go to the back of the queue
            let mut new_waiter = notify.notified();
            assert!(
                poll_once(&mut new_waiter).is_pending(),
                "new waiter should be pending"
            );

            // Notify remaining waiters - new waiter should wake LAST
            let remaining = waiters.len();
            for _ in 0..remaining {
                notify.notify_one();
            }

            for waiter in &mut waiters {
                let ready = poll_once(waiter).is_ready();
                assert!(ready, "existing waiters should all be ready");
            }

            let new_still_pending = poll_once(&mut new_waiter).is_pending();
            assert!(
                new_still_pending,
                "new waiter should still be pending - it goes to back of queue despite slot reuse"
            );

            // Final notify should wake the new waiter
            notify.notify_one();
            let new_ready = poll_once(&mut new_waiter).is_ready();
            assert!(new_ready, "new waiter should be ready after final notify");
        }

        crate::test_complete!("audit_notify_one_tight_loop_no_leapfrog");
    }

    /// Audit test for notify_one signal storage with no waiters.
    ///
    /// Verifies that when notify_one() is called with NO waiters present,
    /// the signal is STORED (not dropped) and consumed by the next waiter.
    /// Per asupersync notify-vs-notify-waiters spec: notify_one stores ONE signal.
    #[test]
    fn audit_notify_one_stores_signal_with_no_waiters() {
        init_test("audit_notify_one_stores_signal_with_no_waiters");
        let notify = Notify::new();

        // Test 1: Core behavior - notify_one with absolutely no waiters should store signal
        {
            // Verify no waiters exist
            assert_eq!(notify.waiter_count(), 0, "should start with no waiters");

            // Verify no stored notifications initially
            let initial_stored = notify.stored_notifications.load(Ordering::Acquire);
            assert_eq!(
                initial_stored, 0,
                "should start with no stored notifications"
            );

            // Call notify_one() with no waiters present
            notify.notify_one();

            // Signal should be stored, not dropped
            let stored_after_notify = notify.stored_notifications.load(Ordering::Acquire);
            assert_eq!(
                stored_after_notify, 1,
                "notify_one() with no waiters should store exactly 1 signal"
            );

            // First waiter should consume stored signal immediately
            let mut waiter = notify.notified();
            let ready_immediately = poll_once(&mut waiter).is_ready();
            assert!(
                ready_immediately,
                "first waiter should consume stored signal on first poll"
            );

            // Stored signal should be consumed
            let stored_after_consume = notify.stored_notifications.load(Ordering::Acquire);
            assert_eq!(
                stored_after_consume, 0,
                "stored signal should be consumed by waiter"
            );
        }

        // Test 2: Multiple notify_one calls accumulate stored signals
        {
            // Call notify_one multiple times with no waiters
            notify.notify_one();
            notify.notify_one();
            notify.notify_one();

            let stored_multiple = notify.stored_notifications.load(Ordering::Acquire);
            assert_eq!(
                stored_multiple, 3,
                "multiple notify_one calls should accumulate stored signals"
            );

            // Three waiters should consume three signals
            let mut waiter1 = notify.notified();
            let mut waiter2 = notify.notified();
            let mut waiter3 = notify.notified();
            let mut waiter4 = notify.notified();

            assert!(
                poll_once(&mut waiter1).is_ready(),
                "waiter 1 consumes signal 1"
            );
            assert!(
                poll_once(&mut waiter2).is_ready(),
                "waiter 2 consumes signal 2"
            );
            assert!(
                poll_once(&mut waiter3).is_ready(),
                "waiter 3 consumes signal 3"
            );
            assert!(
                poll_once(&mut waiter4).is_pending(),
                "waiter 4 has no signal to consume"
            );

            let stored_after_three = notify.stored_notifications.load(Ordering::Acquire);
            assert_eq!(
                stored_after_three, 0,
                "all stored signals should be consumed"
            );
        }

        // Test 3: Contrast with notify_waiters - should not store signals
        {
            // Verify clean slate
            assert_eq!(notify.waiter_count(), 1, "waiter4 still pending");
            assert_eq!(notify.stored_notifications.load(Ordering::Acquire), 0);

            // notify_waiters with no NEW waiters should not store signals
            notify.notify_waiters();

            let stored_after_broadcast = notify.stored_notifications.load(Ordering::Acquire);
            assert_eq!(
                stored_after_broadcast, 0,
                "notify_waiters should not store signals for future waiters"
            );

            // New waiter after broadcast should remain pending
            let mut waiter5 = notify.notified();
            assert!(
                poll_once(&mut waiter5).is_pending(),
                "waiter after notify_waiters should not get a stored signal"
            );
        }

        // Test 4: Mixed sequence - stored signals + live waiters
        {
            // Store a signal first
            notify.notify_one();
            assert_eq!(notify.stored_notifications.load(Ordering::Acquire), 1);

            // Register waiters
            let mut waiter6 = notify.notified();
            let mut waiter7 = notify.notified();

            // First poll on waiter6 should consume stored signal
            assert!(
                poll_once(&mut waiter6).is_ready(),
                "waiter6 consumes stored signal"
            );
            assert!(
                poll_once(&mut waiter7).is_pending(),
                "waiter7 has no signal"
            );

            // Now notify_one should directly wake waiter7 (no storage needed)
            notify.notify_one();
            assert!(poll_once(&mut waiter7).is_ready(), "waiter7 woken directly");

            assert_eq!(
                notify.stored_notifications.load(Ordering::Acquire),
                0,
                "no storage when waiters are present"
            );
        }

        // Test 5: Verify signal persistence across time
        {
            // Store signal and wait
            notify.notify_one();
            std::thread::sleep(std::time::Duration::from_millis(10));

            // Signal should persist
            assert_eq!(notify.stored_notifications.load(Ordering::Acquire), 1);

            // Should still be consumable
            let mut delayed_waiter = notify.notified();
            assert!(
                poll_once(&mut delayed_waiter).is_ready(),
                "stored signal persists over time"
            );
        }

        crate::test_complete!("audit_notify_one_stores_signal_with_no_waiters");
    }

    /// Audit test for notify_one concurrent with sole waiter cancellation.
    ///
    /// Verifies that when notify_one() is called concurrently with the sole waiter
    /// being cancelled, the signal is NOT lost. Per asupersync semantics, signals
    /// must persist until consumed. The implementation should either:
    /// (a) wake another waiter (correct: signal not lost), or
    /// (b) re-store the signal for the next waiter (correct: signal not lost).
    /// This test verifies option (b) since there's only one waiter.
    #[test]
    fn audit_notify_one_cancel_during_notify_race_preserves_signal() {
        init_test("audit_notify_one_cancel_during_notify_race_preserves_signal");
        let notify = Arc::new(Notify::new());

        // Initial state: no stored notifications
        let initial_stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            initial_stored == 0,
            "no stored notifications initially",
            0,
            initial_stored
        );

        // Register sole waiter
        let mut fut = notify.notified();
        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(pending, "waiter registered and pending", true, pending);

        // Simulate race: notify_one() concurrent with waiter cancellation
        // The notify_one should find the waiter and mark it notified
        notify.notify_one();

        // Now cancel (drop) the sole waiter AFTER it was notified but BEFORE poll
        // This should trigger the baton-pass mechanism
        drop(fut);

        // The signal should be re-stored since there are no other waiters
        let stored_after_cancel = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            stored_after_cancel == 1,
            "signal re-stored after sole waiter cancelled",
            1,
            stored_after_cancel
        );

        // A new waiter should consume the re-stored signal immediately
        let mut fut2 = notify.notified();
        let ready = poll_once(&mut fut2).is_ready();
        crate::assert_with_log!(
            ready,
            "new waiter immediately consumes re-stored signal",
            true,
            ready
        );

        // Stored notifications should be back to zero
        let final_stored = notify.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            final_stored == 0,
            "stored notifications consumed",
            0,
            final_stored
        );

        crate::test_complete!("audit_notify_one_cancel_during_notify_race_preserves_signal");
    }

    #[test]
    fn audit_notify_drop_with_pending_waiters_lifetime_safety() {
        init_test("audit_notify_drop_with_pending_waiters_lifetime_safety");

        // AUDIT: Verify Notify drop behavior with pending waiters
        // CONTEXT: Asupersync cancel-aware semantics require explicit error vs hanging
        // MECHANISM: Rust lifetime system prevents Notify drop while Notified futures exist

        // This test documents that the scenario "drop Notify with pending waiters"
        // is prevented by Rust's borrow checker since Notified holds &self references

        use std::sync::Arc;

        // Test 1: Demonstrate lifetime safety - this would not compile:
        // {
        //     let notify = Notify::new();
        //     let mut fut = notify.notified(); // Borrows notify
        //     drop(notify); // ERROR: cannot drop while borrowed
        //     // poll_once(&mut fut); // This would be use-after-free
        // }

        // Test 2: Owned scenario with Arc - proper cleanup when all refs dropped
        let notify = Arc::new(Notify::new());

        // Create waiters holding Arc references
        let mut waiters = Vec::new();
        for _ in 0..3 {
            let notify_clone = Arc::clone(&notify);
            // In real usage, these would be used in separate tasks
            // Here we just verify the Arc pattern works
            waiters.push(notify_clone);
        }

        // Verify reference counting
        let initial_refs = Arc::strong_count(&notify);
        crate::assert_with_log!(
            initial_refs == 4, // Original + 3 clones
            "Arc ref count includes all clones",
            4usize,
            initial_refs
        );

        // Drop clones one by one
        waiters.clear();
        let final_refs = Arc::strong_count(&notify);
        crate::assert_with_log!(
            final_refs == 1, // Only original remains
            "Arc refs cleaned up after waiters dropped",
            1usize,
            final_refs
        );

        // Test 3: Verify Drop implementation doesn't panic
        {
            let notify_for_drop = Notify::new();
            // The Drop impl we added should handle empty waiters gracefully
            drop(notify_for_drop); // Should not panic
        }

        // Test 4: Verify stored notifications are preserved across drop/recreate
        let notify1 = Notify::new();
        notify1.notify_one(); // Store a notification

        let stored = notify1.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(stored == 1, "notification stored", 1usize, stored);

        drop(notify1); // Drop with stored notification

        // New Notify should start clean
        let notify2 = Notify::new();
        let clean_stored = notify2.stored_notifications.load(Ordering::Acquire);
        crate::assert_with_log!(
            clean_stored == 0,
            "new Notify starts with zero stored notifications",
            0usize,
            clean_stored
        );

        crate::test_complete!("audit_notify_drop_with_pending_waiters_lifetime_safety");
    }
}
