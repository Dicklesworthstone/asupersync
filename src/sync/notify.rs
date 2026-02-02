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

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;
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
    waiters: StdMutex<WaiterSlab>,
}

/// Slab-like storage for waiters that reuses freed slots to prevent
/// unbounded Vec growth when cancelled waiters leave holes in the middle.
#[derive(Debug)]
struct WaiterSlab {
    entries: Vec<WaiterEntry>,
    free_slots: Vec<usize>,
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
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            free_slots: Vec::new(),
        }
    }

    /// Insert a waiter entry, reusing a free slot if available.
    fn insert(&mut self, entry: WaiterEntry) -> usize {
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
    fn remove(&mut self, index: usize) {
        if index < self.entries.len() {
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

    /// Count active waiters (those with a waker set).
    fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.waker.is_some()).count()
    }
}

impl Notify {
    /// Creates a new `Notify` in the empty state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            stored_notifications: AtomicUsize::new(0),
            waiters: StdMutex::new(WaiterSlab::new()),
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
        let mut waiters = match self.waiters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Find a waiter to notify.
        for entry in &mut waiters.entries {
            if !entry.notified && entry.waker.is_some() {
                entry.notified = true;
                if let Some(waker) = entry.waker.take() {
                    drop(waiters); // Release lock before waking.
                    waker.wake();
                    return;
                }
            }
        }

        // No waiters found, store the notification.
        drop(waiters);
        self.stored_notifications.fetch_add(1, Ordering::SeqCst);
    }

    /// Notifies all waiting tasks.
    ///
    /// This wakes all tasks that are currently waiting. Tasks that
    /// start waiting after this call will not be affected.
    pub fn notify_waiters(&self) {
        // Increment generation to signal all waiters.
        self.generation.fetch_add(1, Ordering::SeqCst);

        // Collect all wakers.
        let wakers: Vec<Waker> = {
            let mut waiters = match self.waiters.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };

            waiters
                .entries
                .iter_mut()
                .filter_map(|entry| {
                    entry.notified = true;
                    entry.waker.take()
                })
                .collect()
        };

        // Wake all.
        for waker in wakers {
            waker.wake();
        }
    }

    /// Returns the number of tasks currently waiting.
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        let waiters = match self.waiters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
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

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.state {
            NotifiedState::Init => {
                // Check for stored notification.
                loop {
                    let stored = self.notify.stored_notifications.load(Ordering::SeqCst);
                    if stored > 0 {
                        if self
                            .notify
                            .stored_notifications
                            .compare_exchange(
                                stored,
                                stored - 1,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_ok()
                        {
                            self.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }
                        // Retry on CAS failure.
                        continue;
                    }
                    break;
                }

                // Check if generation changed (notify_waiters called).
                let current_gen = self.notify.generation.load(Ordering::Acquire);
                if current_gen != self.initial_generation {
                    self.state = NotifiedState::Done;
                    return Poll::Ready(());
                }

                // Register as a waiter.
                let mut waiters = match self.notify.waiters.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };

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
                    let mut waiters = match self.notify.waiters.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };

                    if index < waiters.entries.len() {
                        if waiters.entries[index].notified {
                            drop(waiters); // Release lock before cleanup.
                            self.cleanup();
                            self.state = NotifiedState::Done;
                            return Poll::Ready(());
                        }
                        // Update waker while we have the lock.
                        waiters.entries[index].waker = Some(cx.waker().clone());
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
            let mut waiters = match self.notify.waiters.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };

            waiters.remove(index);
            drop(waiters);
        }
    }
}

impl Drop for Notified<'_> {
    fn drop(&mut self) {
        if self.state == NotifiedState::Waiting {
            self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;
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
        {
            let waiters = notify.waiters.lock().unwrap();
            let entries_len = waiters.entries.len();
            crate::assert_with_log!(entries_len <= 3, "entries bounded", true, entries_len <= 3);
        }

        // Cancel all and verify full cleanup
        drop(fut1);
        drop(fut3);

        let count = notify.waiter_count();
        crate::assert_with_log!(count == 0, "no waiters after all drops", 0usize, count);

        // Vec should be empty after all waiters gone
        {
            let waiters = notify.waiters.lock().unwrap();
            let entries_len = waiters.entries.len();
            crate::assert_with_log!(entries_len == 0, "entries empty", 0usize, entries_len);
        }

        // Verify slot reuse: register new waiters, they should reuse freed slots
        let mut fut_a = notify.notified();
        assert!(poll_once(&mut fut_a).is_pending());
        {
            let waiters = notify.waiters.lock().unwrap();
            let entries_len = waiters.entries.len();
            crate::assert_with_log!(entries_len == 1, "reused slot", 1usize, entries_len);
        }
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
        {
            let waiters = notify.waiters.lock().unwrap();
            let entries_len = waiters.entries.len();
            crate::assert_with_log!(entries_len == 0, "no growth", 0usize, entries_len);
        }

        crate::test_complete!("test_repeated_cancel_no_growth");
    }
}
