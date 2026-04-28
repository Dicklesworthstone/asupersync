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
    free_slots: SmallVec<[usize; 4]>,
    /// Number of active waiters (those with a waker set). Maintained
    /// incrementally so `active_count()` is O(1) instead of a linear scan.
    active: usize,
    /// Lower-bound hint for the first potentially-active (non-notified, has-waker)
    /// entry. `notify_one` starts scanning from here instead of index 0,
    /// making sequential notifications O(1) amortized instead of O(n).
    scan_start: usize,
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
            if let Some(idx) = self.free_slots.pop() {
                if idx < self.entries.len() {
                    // br-asupersync-bu4r7l: bump the slot's epoch BEFORE
                    // overwriting so any prior `Notified` that still
                    // holds the old (idx, prev_epoch) tuple sees a
                    // mismatch on its Drop and skips the now-foreign
                    // entry. wrapping_add tolerates the (astronomically
                    // unlikely) wrap-around without panic.
                    let prev_epoch = self.entries[idx].slot_epoch;
                    let new_epoch = prev_epoch.wrapping_add(1);
                    entry.slot_epoch = new_epoch;
                    self.entries[idx] = entry;
                    break (idx, new_epoch);
                }
                // idx >= len means this slot was truncated away during a previous shrink.
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
            if self.entries[index].waker.is_some() {
                self.active -= 1;
            }
            self.entries[index].waker = None;
            self.entries[index].notified = false;
            self.free_slots.push(index);
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
                    // Only process active, unnotified waiters. Free slots are ignored.
                    if entry.generation < new_generation && entry.waker.is_some() {
                        entry.generation = new_generation;
                        entry.notified = true;
                        return entry.waker.take();
                    }
                    None
                })
                .collect();
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

    /// Passes a `notify_one` baton to a post-broadcast waiter, falling back
    /// to a stored notification when none exists yet.
    ///
    /// Used when a later broadcast already covered the original waiter set
    /// but a post-broadcast waiter (existing OR about-to-register) may still
    /// need the in-flight `notify_one` baton.
    ///
    /// br-asupersync-z5dxrw: previously this dropped the baton when no
    /// post-broadcast waiter was present at scan time. That created a lost-
    /// wakeup race — a waiter registering microseconds after the scan would
    /// wait indefinitely for an event that already fired. We now always
    /// fall back to `stored_notifications.fetch_add(1)` so a slightly-late
    /// waiter still picks up the baton on next poll. The cost is at most
    /// one spurious wake on a future unrelated waiter, which is preferable
    /// to a deadlock.
    #[inline]
    fn pass_baton_if_waiter_exists(&self, mut waiters: parking_lot::MutexGuard<'_, WaiterSlab>) {
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
}

impl Default for Notify {
    #[inline]
    fn default() -> Self {
        Self::new()
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
                        self.notify.pass_baton_if_waiter_exists(waiters);
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
    use std::sync::mpsc;
    use std::sync::Arc;
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
}
