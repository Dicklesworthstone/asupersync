//! Lazy initialization cell with async support.
//!
//! [`OnceCell`] provides a cell that can be initialized exactly once,
//! with support for async initialization functions.
//!
//! # Cancel Safety
//!
//! - `get_or_init`: If cancelled during initialization, the cell remains
//!   uninitialized and a future caller can try again.
//! - `get_or_try_init`: Same as above, with error handling.
//! - Racing initializers: Only one will succeed; others will wait or
//!   get the initialized value.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex, OnceLock};
use std::task::{Context, Poll, Waker};

/// State values for OnceCell.
const UNINIT: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;

/// Error returned when a OnceCell operation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnceCellError {
    /// The cell is already initialized.
    AlreadyInitialized,
    /// Initialization was cancelled.
    Cancelled,
}

impl fmt::Display for OnceCellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "once cell already initialized"),
            Self::Cancelled => write!(f, "once cell initialization cancelled"),
        }
    }
}

impl std::error::Error for OnceCellError {}

/// A queued waiter for cell initialization.
#[derive(Debug)]
struct InitWaiter {
    waker: Waker,
    /// Flag indicating whether this waiter is still queued.
    queued: Arc<AtomicBool>,
}

/// Internal state holding waiters.
struct WaiterState {
    waiters: Vec<InitWaiter>,
}

/// A cell that can be initialized exactly once.
///
/// `OnceCell` provides a way to lazily initialize a value, potentially
/// using an async initialization function. Once initialized, the value
/// can be accessed immutably.
///
/// # Example
///
/// ```ignore
/// static CONFIG: OnceCell<Config> = OnceCell::new();
///
/// async fn get_config() -> &'static Config {
///     CONFIG.get_or_init(|| async {
///         load_config().await
///     }).await
/// }
/// ```
pub struct OnceCell<T> {
    /// Current state (UNINIT, INITIALIZING, or INITIALIZED).
    state: AtomicU8,
    /// The value (using OnceLock for safe &T access).
    value: OnceLock<T>,
    /// Waiters for async notification.
    waiters: StdMutex<WaiterState>,
    /// Condition variable for blocking waiters.
    cvar: Condvar,
}

impl<T> OnceCell<T> {
    /// Creates a new uninitialized `OnceCell`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(UNINIT),
            value: OnceLock::new(),
            waiters: StdMutex::new(WaiterState {
                waiters: Vec::new(),
            }),
            cvar: Condvar::new(),
        }
    }

    /// Creates a new `OnceCell` with the given value.
    #[must_use]
    pub fn with_value(value: T) -> Self {
        let cell = Self::new();
        let _ = cell.value.set(value);
        cell.state.store(INITIALIZED, Ordering::Release);
        cell
    }

    /// Returns `true` if the cell has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.state.load(Ordering::Acquire) == INITIALIZED
    }

    /// Gets the value if initialized.
    ///
    /// Returns `None` if the cell is not yet initialized.
    #[must_use]
    pub fn get(&self) -> Option<&T> {
        if self.is_initialized() {
            self.value.get()
        } else {
            None
        }
    }

    /// Sets the value if not already initialized.
    ///
    /// Returns `Err(value)` if the cell is already initialized.
    pub fn set(&self, value: T) -> Result<(), T> {
        match self
            .state
            .compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                // We are the initializer. Store the value.
                let _ = self.value.set(value);
                self.state.store(INITIALIZED, Ordering::Release);
                self.cvar.notify_all();
                self.wake_all();
                Ok(())
            }
            Err(_) => Err(value),
        }
    }

    /// Gets the value, initializing it synchronously if necessary.
    ///
    /// If the cell is uninitialized, `f` is called to create the value.
    /// If multiple threads call this concurrently, only one will run the
    /// initialization function; others will block waiting for the result.
    pub fn get_or_init_blocking<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        // Fast path: already initialized.
        if self.is_initialized() {
            return self.value.get().expect("value should be set");
        }

        // Wrap in Option so we can consume the FnOnce at most once inside a
        // retry loop (needed when a prior initializer is cancelled).
        let mut init_fn = Some(f);

        loop {
            match self.state.compare_exchange(
                UNINIT,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We are the initializer.
                    let f = init_fn.take().expect("init closure available");
                    let value = f();
                    let _ = self.value.set(value);
                    self.state.store(INITIALIZED, Ordering::Release);
                    self.cvar.notify_all();
                    self.wake_all();
                    return self.value.get().expect("just initialized");
                }
                Err(INITIALIZED) => {
                    return self.value.get().expect("already initialized");
                }
                Err(_) => {
                    // Another thread is initializing. Wait for it.
                    self.wait_for_init_blocking();
                    if self.is_initialized() {
                        return self.value.get().expect("should be initialized after wait");
                    }
                    // The initializer was cancelled — state is back to UNINIT.
                    // Loop to retry the CAS and potentially become the initializer.
                }
            }
        }
    }

    /// Gets the value, initializing it if necessary (async version).
    ///
    /// If the cell is uninitialized, `f` is called to create the value.
    /// If multiple tasks call this concurrently, only one will run the
    /// initialization function; others will wait for the result.
    ///
    /// # Cancel Safety
    ///
    /// If the initialization future is cancelled, the cell remains
    /// uninitialized and a future caller can try again.
    #[allow(clippy::future_not_send)]
    pub async fn get_or_init<F, Fut>(&self, f: F) -> &T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        // Fast path: already initialized.
        if self.is_initialized() {
            return self.value.get().expect("value should be set");
        }

        // Wrap in Option so we can consume the FnOnce at most once inside a
        // retry loop (needed when a prior initializer is cancelled).
        let mut init_fn = Some(f);

        loop {
            match self.state.compare_exchange(
                UNINIT,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We are the initializer.
                    let f = init_fn.take().expect("init closure available");
                    let mut guard = InitGuard {
                        cell: self,
                        completed: false,
                    };

                    let value = f().await;

                    // Store value and mark complete.
                    let _ = self.value.set(value);
                    self.state.store(INITIALIZED, Ordering::Release);
                    guard.completed = true;
                    drop(guard); // Guard checks `completed` — won't reset state.

                    self.cvar.notify_all();
                    self.wake_all();
                    return self.value.get().expect("just initialized");
                }
                Err(INITIALIZED) => {
                    return self.value.get().expect("already initialized");
                }
                Err(_) => {
                    // Another task is initializing. Wait for it.
                    WaitInit {
                        cell: self,
                        waiter: None,
                    }
                    .await;

                    // Check whether initialization actually succeeded.
                    if self.is_initialized() {
                        return self.value.get().expect("should be initialized after wait");
                    }
                    // The initializer was cancelled — state is back to UNINIT.
                    // Loop to retry the CAS and potentially become the initializer.
                }
            }
        }
    }

    /// Gets the value, initializing it with a fallible function if necessary.
    ///
    /// If the cell is uninitialized, `f` is called to create the value.
    /// If `f` returns an error, the cell remains uninitialized.
    ///
    /// # Cancel Safety
    ///
    /// If the initialization future is cancelled or returns an error,
    /// the cell remains uninitialized and a future caller can try again.
    #[allow(clippy::future_not_send)]
    pub async fn get_or_try_init<F, Fut, E>(&self, f: F) -> Result<&T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        // Fast path: already initialized.
        if self.is_initialized() {
            return Ok(self.value.get().expect("value should be set"));
        }

        // Wrap in Option so we can consume the FnOnce at most once inside a
        // retry loop (needed when a prior initializer is cancelled).
        let mut init_fn = Some(f);

        loop {
            // Try to become the initializer.
            match self.state.compare_exchange(
                UNINIT,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We are the initializer.
                    // Create a guard to reset state if we're cancelled or fail.
                    let mut guard = InitGuard {
                        cell: self,
                        completed: false,
                    };

                    let f = init_fn.take().expect("init closure available");
                    match f().await {
                        Ok(value) => {
                            // Store value and mark complete.
                            let _ = self.value.set(value);
                            self.state.store(INITIALIZED, Ordering::Release);
                            guard.completed = true;
                            drop(guard); // Guard checks `completed` — won't reset state.

                            self.cvar.notify_all();
                            self.wake_all();
                            return Ok(self.value.get().expect("just initialized"));
                        }
                        Err(e) => {
                            // Guard resets state to UNINIT and wakes waiters on drop.
                            drop(guard);
                            return Err(e);
                        }
                    }
                }
                Err(INITIALIZED) => {
                    // Already initialized (race).
                    return Ok(self.value.get().expect("already initialized"));
                }
                Err(INITIALIZING) => {
                    // Another task is initializing. Wait for it.
                    WaitInit {
                        cell: self,
                        waiter: None,
                    }
                    .await;
                    // The other task might have failed, check state.
                    if self.is_initialized() {
                        return Ok(self.value.get().expect("should be initialized"));
                    }
                    // The other task failed. Loop and retry the CAS.
                }
                Err(_) => unreachable!("invalid state"),
            }
        }
    }

    /// Takes the value out of the cell, leaving it uninitialized.
    ///
    /// Returns `None` if the cell is not initialized.
    pub fn take(&mut self) -> Option<T> {
        if self.is_initialized() {
            self.state.store(UNINIT, Ordering::Release);
            self.value.take()
        } else {
            None
        }
    }

    /// Consumes the cell, returning the contained value.
    ///
    /// Returns `None` if the cell is not initialized.
    pub fn into_inner(self) -> Option<T> {
        self.value.into_inner()
    }

    /// Block until initialized.
    fn wait_for_init_blocking(&self) {
        let mut guard = match self.waiters.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        while self.state.load(Ordering::Acquire) == INITIALIZING {
            let (new_guard, _) = self
                .cvar
                .wait_timeout(guard, std::time::Duration::from_millis(10))
                .expect("condvar wait failed");
            guard = new_guard;
        }
        drop(guard);
    }

    /// Wakes all async waiters.
    fn wake_all(&self) {
        let wakers: Vec<(Waker, Arc<AtomicBool>)> = {
            let mut guard = match self.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard
                .waiters
                .drain(..)
                .map(|w| (w.waker, w.queued))
                .collect()
        };

        for (waker, queued) in wakers {
            queued.store(false, Ordering::Release);
            waker.wake();
        }
    }

    /// Registers a waker for async waiting with tracking to prevent unbounded growth.
    fn register_waker(
        &self,
        waker: &Waker,
        waiter_flag: Option<&Arc<AtomicBool>>,
    ) -> Option<Arc<AtomicBool>> {
        let mut guard = match self.waiters.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let result = match waiter_flag {
            Some(flag) if !flag.load(Ordering::Acquire) => {
                // We were woken but not ready yet - re-register
                flag.store(true, Ordering::Release);
                guard.waiters.push(InitWaiter {
                    waker: waker.clone(),
                    queued: Arc::clone(flag),
                });
                None
            }
            Some(flag) => {
                // Already queued: refresh to the latest task waker.
                if let Some(existing) = guard.waiters.iter_mut().find(|entry| {
                    Arc::ptr_eq(&entry.queued, flag) && entry.queued.load(Ordering::Acquire)
                }) {
                    existing.waker.clone_from(waker);
                }
                None
            }
            None => {
                // First time - create new waiter
                let flag = Arc::new(AtomicBool::new(true));
                guard.waiters.push(InitWaiter {
                    waker: waker.clone(),
                    queued: Arc::clone(&flag),
                });
                Some(flag)
            }
        };
        drop(guard);
        result
    }
}

impl<T> Default for OnceCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("OnceCell");
        match self.get() {
            Some(v) => d.field("value", v),
            None => d.field("value", &format_args!("<uninitialized>")),
        };
        d.finish()
    }
}

impl<T: Clone> Clone for OnceCell<T> {
    fn clone(&self) -> Self {
        self.get()
            .map_or_else(Self::new, |value| Self::with_value(value.clone()))
    }
}

impl<T: PartialEq> PartialEq for OnceCell<T> {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<T: Eq> Eq for OnceCell<T> {}

impl<T> From<T> for OnceCell<T> {
    fn from(value: T) -> Self {
        Self::with_value(value)
    }
}

/// Guard that resets state to UNINIT and wakes waiters if initialization is
/// cancelled (i.e. the initializing future is dropped before completion).
struct InitGuard<'a, T> {
    cell: &'a OnceCell<T>,
    completed: bool,
}

impl<T> Drop for InitGuard<'_, T> {
    fn drop(&mut self) {
        if !self.completed {
            // Reset state to allow another attempt.
            self.cell.state.store(UNINIT, Ordering::Release);
            // Wake all waiters so they can retry instead of hanging forever.
            self.cell.cvar.notify_all();
            self.cell.wake_all();
        }
    }
}

/// Future that waits for initialization to complete.
struct WaitInit<'a, T> {
    cell: &'a OnceCell<T>,
    /// Tracks whether we've registered a waiter to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl<T> Future for WaitInit<'_, T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let state = self.cell.state.load(Ordering::Acquire);
        if state == INITIALIZING {
            if let Some(new_waiter) = self.cell.register_waker(cx.waker(), self.waiter.as_ref()) {
                self.waiter = Some(new_waiter);
            }
            // Double-check after registering.
            if self.cell.state.load(Ordering::Acquire) == INITIALIZING {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        } else {
            Poll::Ready(())
        }
    }
}

impl<T> Drop for WaitInit<'_, T> {
    fn drop(&mut self) {
        if let Some(waiter) = self.waiter.as_ref() {
            // Remove canceled waiter registrations immediately so repeated
            // cancel/drop cycles don't accumulate until wake_all() drains.
            waiter.store(false, Ordering::Release);
            let mut guard = match self.cell.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard
                .waiters
                .retain(|entry| !Arc::ptr_eq(&entry.queued, waiter));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use futures_lite::future::{block_on, pending};
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        struct NoopWaker;

        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
            fn wake_by_ref(self: &Arc<Self>) {}
        }

        Waker::from(Arc::new(NoopWaker))
    }

    #[derive(Default)]
    struct CountWaker {
        wakes: AtomicUsize,
    }

    impl CountWaker {
        fn count(&self) -> usize {
            self.wakes.load(Ordering::SeqCst)
        }
    }

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn new_cell_is_uninitialized() {
        init_test("new_cell_is_uninitialized");
        let cell: OnceCell<i32> = OnceCell::new();
        crate::assert_with_log!(
            !cell.is_initialized(),
            "not initialized",
            false,
            cell.is_initialized()
        );
        crate::assert_with_log!(cell.get().is_none(), "get none", true, cell.get().is_none());
        crate::test_complete!("new_cell_is_uninitialized");
    }

    #[test]
    fn with_value_is_initialized() {
        init_test("with_value_is_initialized");
        let cell = OnceCell::with_value(42);
        crate::assert_with_log!(
            cell.is_initialized(),
            "initialized",
            true,
            cell.is_initialized()
        );
        crate::assert_with_log!(cell.get() == Some(&42), "get value", Some(&42), cell.get());
        crate::test_complete!("with_value_is_initialized");
    }

    #[test]
    fn set_initializes_cell() {
        init_test("set_initializes_cell");
        let cell: OnceCell<i32> = OnceCell::new();
        let set_ok = cell.set(42).is_ok();
        crate::assert_with_log!(set_ok, "set ok", true, set_ok);
        crate::assert_with_log!(
            cell.is_initialized(),
            "initialized",
            true,
            cell.is_initialized()
        );
        crate::assert_with_log!(cell.get() == Some(&42), "get value", Some(&42), cell.get());
        crate::test_complete!("set_initializes_cell");
    }

    #[test]
    fn set_twice_fails() {
        init_test("set_twice_fails");
        let cell = OnceCell::new();
        let first_ok = cell.set(1).is_ok();
        let second_err = cell.set(2).is_err();
        crate::assert_with_log!(first_ok, "first set ok", true, first_ok);
        crate::assert_with_log!(second_err, "second set err", true, second_err);
        crate::assert_with_log!(
            cell.get() == Some(&1),
            "value unchanged",
            Some(&1),
            cell.get()
        );
        crate::test_complete!("set_twice_fails");
    }

    #[test]
    fn get_or_init_blocking_initializes_once() {
        init_test("get_or_init_blocking_initializes_once");
        let cell: OnceCell<i32> = OnceCell::new();
        let counter = AtomicUsize::new(0);

        let result = cell.get_or_init_blocking(|| {
            counter.fetch_add(1, Ordering::SeqCst);
            42
        });
        crate::assert_with_log!(*result == 42, "first result", 42, *result);
        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) == 1,
            "counter",
            1usize,
            counter.load(Ordering::SeqCst)
        );

        // Second call should return cached value.
        let result = cell.get_or_init_blocking(|| {
            counter.fetch_add(1, Ordering::SeqCst);
            100
        });
        crate::assert_with_log!(*result == 42, "cached result", 42, *result);
        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) == 1,
            "counter",
            1usize,
            counter.load(Ordering::SeqCst)
        );
        crate::test_complete!("get_or_init_blocking_initializes_once");
    }

    #[test]
    fn get_or_init_cancelled_leaves_uninitialized() {
        init_test("get_or_init_cancelled_leaves_uninitialized");
        let cell: OnceCell<u32> = OnceCell::new();

        let mut fut = Box::pin(cell.get_or_init(|| async { pending::<u32>().await }));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Future::poll(fut.as_mut(), &mut cx);
        crate::assert_with_log!(poll.is_pending(), "init pending", true, poll.is_pending());

        drop(fut);

        let still_uninit = !cell.is_initialized();
        crate::assert_with_log!(
            still_uninit,
            "cell uninitialized after cancel",
            true,
            still_uninit
        );

        let value = block_on(cell.get_or_init(|| async { 7 }));
        crate::assert_with_log!(*value == 7, "init after cancel", 7u32, *value);
        crate::test_complete!("get_or_init_cancelled_leaves_uninitialized");
    }

    /// Regression test for bd-ar5hz: waiter must not panic when the initializer
    /// is cancelled. Instead, the waiter should retry and eventually succeed.
    #[test]
    fn get_or_init_waiter_retries_after_cancelled_init() {
        init_test("get_or_init_waiter_retries_after_cancelled_init");
        let cell: OnceCell<u32> = OnceCell::new();

        // Task A: start init with a future that will never complete.
        let mut init_fut = Box::pin(cell.get_or_init(|| async { pending::<u32>().await }));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Future::poll(init_fut.as_mut(), &mut cx);
        assert!(poll.is_pending(), "init should be pending");

        // Task B: a waiter that will be parked because A is INITIALIZING.
        let mut waiter_fut = Box::pin(cell.get_or_init(|| async { 99u32 }));
        let poll_b = Future::poll(waiter_fut.as_mut(), &mut cx);
        assert!(
            poll_b.is_pending(),
            "waiter should be pending while init in progress"
        );

        // Cancel task A — InitGuard should reset to UNINIT and wake B.
        drop(init_fut);

        // Task B should now retry (not panic) and initialize the cell.
        let poll_b2 = Future::poll(waiter_fut.as_mut(), &mut cx);
        assert!(
            poll_b2.is_ready(),
            "waiter should complete after cancelled init"
        );
        assert_eq!(
            cell.get(),
            Some(&99),
            "cell should be initialized by waiter"
        );
        crate::test_complete!("get_or_init_waiter_retries_after_cancelled_init");
    }

    #[test]
    fn get_or_init_waiter_refreshes_queued_waker() {
        init_test("get_or_init_waiter_refreshes_queued_waker");
        let cell: OnceCell<u32> = OnceCell::new();

        // Task A starts initialization and stays pending.
        let mut init_fut = Box::pin(cell.get_or_init(|| async { pending::<u32>().await }));
        let noop = noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        assert!(Future::poll(init_fut.as_mut(), &mut noop_cx).is_pending());

        // Task B waits on initialization and is first polled with waker A.
        let mut waiter_fut = Box::pin(cell.get_or_init(|| async { 7u32 }));
        let wake_counter_first = Arc::new(CountWaker::default());
        let wake_counter_second = Arc::new(CountWaker::default());
        let task_waker_first = Waker::from(Arc::clone(&wake_counter_first));
        let task_waker_second = Waker::from(Arc::clone(&wake_counter_second));

        let mut cx_a = Context::from_waker(&task_waker_first);
        assert!(Future::poll(waiter_fut.as_mut(), &mut cx_a).is_pending());

        // Poll again with a different waker while still queued; this should refresh.
        let mut cx_b = Context::from_waker(&task_waker_second);
        assert!(Future::poll(waiter_fut.as_mut(), &mut cx_b).is_pending());

        // Cancel Task A: waiters are woken. The queued waiter should wake waker B, not stale A.
        drop(init_fut);

        crate::assert_with_log!(
            wake_counter_second.count() > 0,
            "latest waker was notified",
            true,
            wake_counter_second.count() > 0
        );
        crate::assert_with_log!(
            wake_counter_first.count() == 0,
            "stale waker not notified",
            0usize,
            wake_counter_first.count()
        );
        crate::test_complete!("get_or_init_waiter_refreshes_queued_waker");
    }

    #[test]
    fn get_or_init_cancelled_waiters_do_not_accumulate() {
        init_test("get_or_init_cancelled_waiters_do_not_accumulate");
        let cell: OnceCell<u32> = OnceCell::new();

        // Hold cell in INITIALIZING so waiters will queue.
        let mut init_fut = Box::pin(cell.get_or_init(|| async { pending::<u32>().await }));
        let noop = noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        assert!(Future::poll(init_fut.as_mut(), &mut noop_cx).is_pending());

        // Repeatedly create + cancel waiters while initialization is pending.
        for _ in 0..128 {
            let mut waiter_fut = Box::pin(cell.get_or_init(|| async { 11u32 }));
            assert!(Future::poll(waiter_fut.as_mut(), &mut noop_cx).is_pending());
            drop(waiter_fut);
        }

        let queued_waiters = cell
            .waiters
            .lock()
            .expect("waiters lock poisoned")
            .waiters
            .len();
        crate::assert_with_log!(
            queued_waiters == 0,
            "canceled waiters are removed immediately",
            0usize,
            queued_waiters
        );

        drop(init_fut);
        crate::test_complete!("get_or_init_cancelled_waiters_do_not_accumulate");
    }

    #[test]
    fn get_or_try_init_cancelled_leaves_uninitialized() {
        init_test("get_or_try_init_cancelled_leaves_uninitialized");
        let cell: OnceCell<u32> = OnceCell::new();

        let mut fut = Box::pin(
            cell.get_or_try_init(|| async { pending::<Result<u32, &'static str>>().await }),
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Future::poll(fut.as_mut(), &mut cx);
        assert!(poll.is_pending(), "init should be pending");

        drop(fut);

        assert!(
            !cell.is_initialized(),
            "cell should remain uninitialized after cancellation"
        );

        let value = block_on(cell.get_or_try_init(|| async { Ok::<_, ()>(7) })).expect("init ok");
        assert_eq!(*value, 7);
        crate::test_complete!("get_or_try_init_cancelled_leaves_uninitialized");
    }

    /// Regression: waiter must retry after a cancelled fallible initializer.
    #[test]
    fn get_or_try_init_waiter_retries_after_cancelled_init() {
        init_test("get_or_try_init_waiter_retries_after_cancelled_init");
        let cell: OnceCell<u32> = OnceCell::new();

        // Task A: start init with a future that will never complete.
        let mut init_fut = Box::pin(
            cell.get_or_try_init(|| async { pending::<Result<u32, &'static str>>().await }),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Future::poll(init_fut.as_mut(), &mut cx);
        assert!(poll.is_pending(), "init should be pending");

        // Task B: a waiter that will be parked because A is INITIALIZING.
        let mut waiter_fut = Box::pin(cell.get_or_try_init(|| async { Ok::<_, ()>(99u32) }));
        let poll_b = Future::poll(waiter_fut.as_mut(), &mut cx);
        assert!(
            poll_b.is_pending(),
            "waiter should be pending while init in progress"
        );

        // Cancel task A — InitGuard should reset to UNINIT and wake B.
        drop(init_fut);

        // Task B should now retry and initialize the cell.
        let poll_b2 = Future::poll(waiter_fut.as_mut(), &mut cx);
        match poll_b2 {
            Poll::Ready(Ok(value)) => assert_eq!(*value, 99),
            Poll::Ready(Err(err)) => panic!("unexpected error: {err:?}"),
            Poll::Pending => panic!("waiter should have completed after cancel"),
        }

        crate::test_complete!("get_or_try_init_waiter_retries_after_cancelled_init");
    }

    #[test]
    fn get_or_try_init_error_leaves_uninitialized() {
        init_test("get_or_try_init_error_leaves_uninitialized");
        let cell: OnceCell<u32> = OnceCell::new();

        let err = block_on(cell.get_or_try_init(|| async { Err::<u32, &str>("boom") }));
        assert_eq!(err, Err("boom"));
        assert!(
            !cell.is_initialized(),
            "cell should remain uninitialized after error"
        );

        let value = block_on(cell.get_or_try_init(|| async { Ok::<_, ()>(42) })).expect("init ok");
        assert_eq!(*value, 42);
        crate::test_complete!("get_or_try_init_error_leaves_uninitialized");
    }

    /// Regression test for bd-ar5hz (blocking variant): blocking waiter must
    /// not panic when an async initializer is cancelled.
    #[test]
    fn get_or_init_blocking_retries_after_cancelled_async_init() {
        init_test("get_or_init_blocking_retries_after_cancelled_async_init");
        let cell = Arc::new(OnceCell::<u32>::new());

        // Start an async init that will be cancelled.
        let mut init_fut = Box::pin(cell.get_or_init(|| async { pending::<u32>().await }));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Future::poll(init_fut.as_mut(), &mut cx);
        assert!(poll.is_pending());

        // Spawn a blocking waiter that should not panic.
        let cell2 = Arc::clone(&cell);
        let handle = thread::spawn(move || {
            // This will block until state leaves INITIALIZING, then retry.
            *cell2.get_or_init_blocking(|| 42)
        });

        // Give the thread time to enter wait_for_init_blocking.
        thread::sleep(std::time::Duration::from_millis(20));

        // Cancel the async init — state resets to UNINIT, cvar notified.
        drop(init_fut);

        let value = handle.join().expect("blocking waiter panicked");
        assert_eq!(
            value, 42,
            "blocking waiter should have initialized the cell"
        );
        assert!(cell.is_initialized());
        crate::test_complete!("get_or_init_blocking_retries_after_cancelled_async_init");
    }

    #[test]
    fn concurrent_init_only_runs_once() {
        init_test("concurrent_init_only_runs_once");
        let cell = Arc::new(OnceCell::<i32>::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let cell = Arc::clone(&cell);
            let counter = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                let result = cell.get_or_init_blocking(|| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(std::time::Duration::from_millis(10));
                    42
                });
                crate::assert_with_log!(*result == 42, "result", 42, *result);
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) == 1,
            "counter",
            1usize,
            counter.load(Ordering::SeqCst)
        );
        crate::test_complete!("concurrent_init_only_runs_once");
    }

    #[test]
    fn take_resets_cell() {
        init_test("take_resets_cell");
        let mut cell = OnceCell::with_value(42);
        let taken = cell.take();
        crate::assert_with_log!(taken == Some(42), "take value", Some(42), taken);
        crate::assert_with_log!(
            !cell.is_initialized(),
            "not initialized",
            false,
            cell.is_initialized()
        );
        crate::assert_with_log!(cell.get().is_none(), "get none", true, cell.get().is_none());
        crate::test_complete!("take_resets_cell");
    }

    #[test]
    fn into_inner_extracts_value() {
        init_test("into_inner_extracts_value");
        let cell = OnceCell::with_value(42);
        let inner = cell.into_inner();
        crate::assert_with_log!(inner == Some(42), "into_inner", Some(42), inner);
        crate::test_complete!("into_inner_extracts_value");
    }

    #[test]
    fn clone_copies_value() {
        init_test("clone_copies_value");
        let cell = OnceCell::with_value(42);
        let cloned = cell;
        crate::assert_with_log!(
            cloned.get() == Some(&42),
            "cloned value",
            Some(&42),
            cloned.get()
        );
        crate::test_complete!("clone_copies_value");
    }

    #[test]
    fn debug_shows_value() {
        init_test("debug_shows_value");
        let cell = OnceCell::with_value(42);
        let debug_text = format!("{cell:?}");
        crate::assert_with_log!(
            debug_text.contains("42"),
            "debug shows value",
            true,
            debug_text.contains("42")
        );
        crate::test_complete!("debug_shows_value");
    }
}
