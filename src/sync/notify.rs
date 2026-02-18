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
    entries: Vec<WaiterEntry>,
    /// Free-slot indices for reuse. SmallVec<4> avoids heap allocation for
    /// the common case of few concurrent waiters.
    free_slots: SmallVec<[usize; 4]>,
    /// Number of active waiters (those with a waker set). Maintained
    /// incrementally so `active_count()` is O(1) instead of a linear scan.
    active: usize,
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
}

impl WaiterSlab {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            free_slots: SmallVec::new(),
            active: 0,
        }
    }

    /// Insert a waiter entry, reusing a free slot if available.
    #[inline]
    fn insert(&mut self, entry: WaiterEntry) -> usize {
        if entry.waker.is_some() {
            self.active += 1;
        }
        if let Some(index) = self.free_slots.pop() {
            self.entries[index] = entry;
            index
        } else {
            let index = self.entries.len();
            self.entries.push(entry);
            index
        }
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
            let tail_idx = self.entries.len() - 1;
            self.entries.pop();
            // Remove tail_idx from free_slots since the slot no longer exists.
            if let Some(pos) = self.free_slots.iter().position(|&i| i == tail_idx) {
                self.free_slots.swap_remove(pos);
            }
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
    pub fn notify_one(&self) {
        let mut waiters = self.waiters.lock();

        // Find a waiter to notify.
        let mut found_waker = None;
        for entry in &mut waiters.entries {
            if !entry.notified && entry.waker.is_some() {
                entry.notified = true;
                found_waker = entry.waker.take();
                break;
            }
        }

        if let Some(waker) = found_waker {
            waiters.active -= 1;
            drop(waiters); // Release lock before waking.
            waker.wake();
            return;
        }

        // No waiters found, store the notification.
        //
        // Important: keep the waiter lock held while incrementing `stored_notifications` so a
        // waiter can't observe `stored_notifications == 0`, then register, and miss the stored
        // notification (lost wakeup).
        self.stored_notifications.fetch_add(1, Ordering::Release);
    }

    /// Notifies all waiting tasks.
    ///
    /// This wakes all tasks that are currently waiting. Tasks that
    /// start waiting after this call will not be affected.
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
                    // Only mark active waiters as notified. Marking free slab slots
                    // (`waker == None`) can pin tail entries and prevent shrinking.
                    if let Some(waker) = entry.waker.take() {
                        entry.notified = true;
                        // Mark this waiter as broadcast-notified to avoid turning
                        // a cancelled broadcast waiter into a stored notify_one token.
                        entry.generation = new_generation;
                        Some(waker)
                    } else {
                        None
                    }
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
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        let waiters = self.waiters.lock();
        waiters.active_count()
    }
}

impl Default for Notify {
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
    waiter_index: Option<usize>,
    initial_generation: u64,
}

impl Future for Notified<'_> {
    type Output = ();

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.state {
            NotifiedState::Init => {
                // Check for stored notification.
                let mut stored = self.notify.stored_notifications.load(Ordering::Acquire);
                while stored > 0 {
                    match self.notify.stored_notifications.compare_exchange_weak(
                        stored,
                        stored - 1,
                        Ordering::Release,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }
                        Err(actual) => stored = actual,
                    }
                }

                // Check if generation changed (notify_waiters called).
                let current_gen = self.notify.generation.load(Ordering::Acquire);
                if current_gen != self.initial_generation {
                    self.state = NotifiedState::Done;
                    return Poll::Ready(());
                }

                // Register as a waiter.
                let mut waiters = self.notify.waiters.lock();

                // Re-check stored notifications and generation while holding the waiter lock.
                // This closes races where a notifier runs between the lock-free checks above and
                // the waiter registration below.
                {
                    let mut stored = self.notify.stored_notifications.load(Ordering::Acquire);
                    while stored > 0 {
                        match self.notify.stored_notifications.compare_exchange_weak(
                            stored,
                            stored - 1,
                            Ordering::Release,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                drop(waiters);
                                self.state = NotifiedState::Done;
                                return Poll::Ready(());
                            }
                            Err(actual) => stored = actual,
                        }
                    }
                }

                let current_gen = self.notify.generation.load(Ordering::Acquire);
                if current_gen != self.initial_generation {
                    drop(waiters);
                    self.state = NotifiedState::Done;
                    return Poll::Ready(());
                }

                let index = waiters.insert(WaiterEntry {
                    waker: Some(cx.waker().clone()),
                    notified: false,
                    generation: self.initial_generation,
                });
                self.waiter_index = Some(index);
                self.state = NotifiedState::Waiting;
                drop(waiters);

                Poll::Pending
            }
            NotifiedState::Waiting => {
                // Check if generation changed.
                let current_gen = self.notify.generation.load(Ordering::Acquire);
                if current_gen != self.initial_generation {
                    self.cleanup();
                    self.state = NotifiedState::Done;
                    return Poll::Ready(());
                }

                // Check if we were notified.
                if let Some(index) = self.waiter_index {
                    let mut waiters = self.notify.waiters.lock();

                    if index < waiters.entries.len() {
                        if waiters.entries[index].notified {
                            drop(waiters); // Release lock before cleanup.
                            self.cleanup();
                            self.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }
                        // Update waker while we have the lock, but only if it changed.
                        match &mut waiters.entries[index].waker {
                            Some(existing) if existing.will_wake(cx.waker()) => {}
                            Some(existing) => existing.clone_from(cx.waker()),
                            slot @ None => *slot = Some(cx.waker().clone()),
                        }
                    } else {
                        // Entry was popped by tail shrinking. This only
                        // happens if our waker was taken by notify_one/notify_waiters,
                        // which means we were notified.
                        drop(waiters); // Release lock.
                        self.waiter_index = None; // Entry no longer exists.
                        self.state = NotifiedState::Done;
                        return Poll::Ready(());
                    }
                }

                Poll::Pending
            }
            NotifiedState::Done => Poll::Ready(()),
        }
    }
}

impl Notified<'_> {
    /// Cleanup waiter registration.
    fn cleanup(&mut self) {
        if let Some(index) = self.waiter_index.take() {
            let mut waiters = self.notify.waiters.lock();

            waiters.remove(index);
            drop(waiters);
        }
    }
}

impl Drop for Notified<'_> {
    fn drop(&mut self) {
        if self.state == NotifiedState::Waiting {
            if let Some(index) = self.waiter_index.take() {
                let mut waiters = self.notify.waiters.lock();

                // Check if notify_one() selected us before we remove the entry.
                let (was_notified, notified_generation) = if index < waiters.entries.len() {
                    let entry = &waiters.entries[index];
                    (entry.notified, entry.generation)
                } else {
                    (false, self.initial_generation)
                };

                waiters.remove(index);

                if was_notified {
                    let was_broadcast_notify = notified_generation != self.initial_generation;
                    if was_broadcast_notify {
                        // notify_waiters is edge-triggered for currently waiting tasks only.
                        // If a broadcast-notified waiter is cancelled, do not convert that
                        // event into a stored token for future waiters.
                        return;
                    }

                    // We were marked notified by notify_one() but the future was
                    // dropped before consuming it (e.g. cancelled by select!).
                    // Pass the notification to the next waiter to prevent a lost
                    // wakeup — same baton-passing pattern as LockFuture::drop.
                    for entry in &mut waiters.entries {
                        if !entry.notified && entry.waker.is_some() {
                            entry.notified = true;
                            if let Some(waker) = entry.waker.take() {
                                drop(waiters);
                                waker.wake();
                                return;
                            }
                        }
                    }
                    // No active waiter found — re-store the notification so the
                    // next call to notified().await receives it.
                    self.notify
                        .stored_notifications
                        .fetch_add(1, Ordering::Release);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::task::Wake;
    use std::thread;
    use std::time::Duration;

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
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

            let second_ready = poll_once(&mut fut).is_ready();
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
}
