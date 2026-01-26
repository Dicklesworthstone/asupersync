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
    waiters: StdMutex<Vec<WaiterEntry>>,
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

impl Notify {
    /// Creates a new `Notify` in the empty state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            stored_notifications: AtomicUsize::new(0),
            waiters: StdMutex::new(Vec::new()),
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
        for entry in waiters.iter_mut() {
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
        waiters.iter().filter(|e| e.waker.is_some()).count()
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

                let index = waiters.len();
                waiters.push(WaiterEntry {
                    waker: Some(cx.waker().clone()),
                    notified: false,
                    generation: self.initial_generation,
                });
                self.waiter_index = Some(index);
                self.state = NotifiedState::Waiting;

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
                    let notified = {
                        let mut waiters = match self.notify.waiters.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };

                        if index < waiters.len() && waiters[index].notified {
                            true
                        } else {
                            // Update waker while we have the lock.
                            if index < waiters.len() {
                                waiters[index].waker = Some(cx.waker().clone());
                            }
                            false
                        }
                    }; // Lock released here before cleanup.

                    if notified {
                        self.cleanup();
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

            if index < waiters.len() {
                waiters[index].waker = None;
            }

            // Clean up empty entries from the end.
            while waiters.last().is_some_and(|e| e.waker.is_none()) {
                waiters.pop();
            }
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
}
