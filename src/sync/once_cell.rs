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

use smallvec::SmallVec;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Condvar, Mutex as StdMutex, OnceLock};
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
    /// Stable waiter identity for refresh/removal without per-waiter allocation.
    id: u64,
}

/// Internal state holding waiters.
struct WaiterState {
    waiters: SmallVec<[InitWaiter; 4]>,
    next_waiter_id: u64,
    cancellation_count: u64,
}

#[cfg(test)]
struct BlockingWaitHook {
    entered_tx: std::sync::mpsc::Sender<()>,
    release_rx: StdMutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl BlockingWaitHook {
    fn run(&self) {
        self.entered_tx
            .send(())
            .expect("blocking wait hook should report entry");
        self.release_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv()
            .expect("blocking wait hook should be released");
    }
}

#[cfg(test)]
static BLOCKING_WAIT_HOOK: OnceLock<StdMutex<Option<std::sync::Arc<BlockingWaitHook>>>> =
    OnceLock::new();

#[cfg(test)]
fn run_blocking_wait_hook() {
    let hook = BLOCKING_WAIT_HOOK
        .get_or_init(|| StdMutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(hook) = hook {
        hook.run();
    }
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
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(UNINIT),
            value: OnceLock::new(),
            waiters: StdMutex::new(WaiterState {
                waiters: SmallVec::new(),
                next_waiter_id: 0,
                cancellation_count: 0,
            }),
            cvar: Condvar::new(),
        }
    }

    /// Creates a new `OnceCell` with the given value.
    #[inline]
    #[must_use]
    pub fn with_value(value: T) -> Self {
        let cell = Self::new();
        let _ = cell.value.set(value);
        cell.state.store(INITIALIZED, Ordering::Release);
        cell
    }

    /// Returns `true` if the cell has been initialized.
    #[inline]
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.state.load(Ordering::Acquire) == INITIALIZED
    }

    /// Gets the value if initialized.
    ///
    /// Returns `None` if the cell is not yet initialized.
    #[inline]
    #[must_use]
    pub fn get(&self) -> Option<&T> {
        if self.is_initialized() {
            self.value.get()
        } else {
            None
        }
    }

    /// Returns a deterministic, redacted snapshot of cell initialization pressure.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, primitive_id: u64) -> crate::sync::SyncTelemetrySnapshot {
        let state_value = self.state.load(Ordering::Acquire);
        let waiters = match self.waiters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state_label = match state_value {
            UNINIT => "uninitialized",
            INITIALIZING => "initializing",
            INITIALIZED => "initialized",
            _ => "unknown",
        };
        crate::sync::SyncTelemetrySnapshot {
            primitive_id,
            primitive_kind: "once_cell",
            capacity: 1,
            occupied_units: usize::from(state_value != UNINIT),
            available_units: usize::from(state_value == UNINIT),
            waiter_count: waiters.waiters.len(),
            generation: 0,
            state: state_label,
            cancellation_count: waiters.cancellation_count,
            closed: state_value == INITIALIZED,
        }
    }

    /// Sets the value if not already initialized.
    ///
    /// Returns `Err(value)` if the cell is already initialized or if another
    /// thread/task is currently initializing the cell. This ensures the method
    /// never blocks the OS thread, avoiding deadlocks in async contexts.
    #[inline]
    pub fn set(&self, value: T) -> Result<(), T> {
        loop {
            match self.state.compare_exchange_weak(
                UNINIT,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We are the initializer. Store the value.
                    let _ = self.value.set(value);
                    self.transition_out_of_initializing(INITIALIZED);
                    return Ok(());
                }
                Err(INITIALIZED | INITIALIZING) => return Err(value),
                Err(UNINIT) => {} // Spurious failure, try again
                Err(_) => unreachable!("invalid state"),
            }
        }
    }

    /// Gets the value, initializing it synchronously if necessary.
    ///
    /// If the cell is uninitialized, `f` is called to create the value.
    /// If multiple threads call this concurrently, only one will run the
    /// initialization function; others will block waiting for the result.
    #[inline]
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
            match self.state.compare_exchange_weak(
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
                    let value = f();
                    let _ = self.value.set(value);
                    guard.completed = true;
                    drop(guard);
                    self.transition_out_of_initializing(INITIALIZED);
                    return self.value.get().expect("just initialized");
                }
                Err(INITIALIZED) => {
                    return self.value.get().expect("already initialized");
                }
                Err(UNINIT) => {} // Spurious failure, try again
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
    #[inline]
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
            match self.state.compare_exchange_weak(
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
                    guard.completed = true;
                    drop(guard); // Guard checks `completed` — won't reset state.
                    self.transition_out_of_initializing(INITIALIZED);
                    return self.value.get().expect("just initialized");
                }
                Err(INITIALIZED) => {
                    return self.value.get().expect("already initialized");
                }
                Err(UNINIT) => {} // Spurious failure, try again
                Err(_) => {
                    // Another task is initializing. Wait for it.
                    WaitInit {
                        cell: self,
                        waiter_id: None,
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
    #[inline]
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
            match self.state.compare_exchange_weak(
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
                            guard.completed = true;
                            drop(guard); // Guard checks `completed` — won't reset state.
                            self.transition_out_of_initializing(INITIALIZED);
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
                        waiter_id: None,
                    }
                    .await;
                    // The other task might have failed, check state.
                    if self.is_initialized() {
                        return Ok(self.value.get().expect("should be initialized"));
                    }
                    // The other task failed. Loop and retry the CAS.
                }
                Err(UNINIT) => {} // Spurious failure, try again
                Err(_) => unreachable!("invalid state"),
            }
        }
    }

    /// Takes the value out of the cell, leaving it uninitialized.
    ///
    /// Returns `None` if the cell is not initialized.
    #[inline]
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
    #[inline]
    pub fn into_inner(self) -> Option<T> {
        self.value.into_inner()
    }

    /// Waits for initialization to complete.
    ///
    /// Returns immediately if the cell is already initialized.
    /// If another task is initializing, waits for it to complete.
    ///
    /// # Cancel Safety
    ///
    /// This operation is cancel-safe: if cancelled while waiting,
    /// returns `Err(OnceCellError::Cancelled)` immediately.
    ///
    /// # Errors
    ///
    /// Returns `Err(OnceCellError::Cancelled)` if the supplied `Cx` is
    /// cancelled before initialization completes.
    #[inline]
    #[allow(clippy::future_not_send)]
    pub async fn wait<Caps>(&self, cx: &crate::cx::Cx<Caps>) -> Result<(), OnceCellError> {
        // Fast path: already initialized
        if self.is_initialized() {
            return Ok(());
        }

        CancelAwareWaitInit {
            cell: self,
            cx,
            waiter_id: None,
        }
        .await
    }

    /// Block until initialized.
    fn wait_for_init_blocking(&self) {
        let mut guard = match self.waiters.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        while self.state.load(Ordering::Acquire) == INITIALIZING {
            #[cfg(test)]
            run_blocking_wait_hook();
            guard = match self.cvar.wait(guard) {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        drop(guard);
    }

    fn transition_out_of_initializing(&self, new_state: u8) {
        let wakers: SmallVec<[Waker; 4]> = {
            let mut guard = match self.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.state.store(new_state, Ordering::Release);
            guard.waiters.drain(..).map(|waiter| waiter.waker).collect()
        };
        self.cvar.notify_all();
        for waker in wakers {
            waker.wake();
        }
    }

    /// Registers a waker for async waiting with waiter-id tracking to prevent
    /// unbounded queue growth.
    fn register_waker(&self, waker: &Waker, waiter_id: &mut Option<u64>) {
        let mut guard = match self.waiters.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(id) = *waiter_id {
            // Still queued: refresh to the latest task waker.
            if let Some(existing) = guard.waiters.iter_mut().find(|entry| entry.id == id) {
                if !existing.waker.will_wake(waker) {
                    existing.waker.clone_from(waker);
                }
            } else {
                // Dequeued while still waiting; re-register.
                let new_id = guard.next_waiter_id;
                guard.next_waiter_id = guard.next_waiter_id.wrapping_add(1);
                guard.waiters.push(InitWaiter {
                    waker: waker.clone(),
                    id: new_id,
                });
                *waiter_id = Some(new_id);
            }
        } else {
            // First time: create new waiter id.
            let id = guard.next_waiter_id;
            guard.next_waiter_id = guard.next_waiter_id.wrapping_add(1);
            guard.waiters.push(InitWaiter {
                waker: waker.clone(),
                id,
            });
            *waiter_id = Some(id);
        }
        drop(guard);
    }

    fn remove_waiter_for_cancellation(&self, waiter_id: u64) {
        let mut guard = match self.waiters.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(pos) = guard.waiters.iter().position(|entry| entry.id == waiter_id) {
            guard.waiters.swap_remove(pos);
            guard.cancellation_count = guard.cancellation_count.saturating_add(1);
        }
    }
}

impl<T> Default for OnceCell<T> {
    #[inline]
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
    #[inline]
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
            self.cell.transition_out_of_initializing(UNINIT);
        }
    }
}

/// Future that waits for initialization to complete.
struct WaitInit<'a, T> {
    cell: &'a OnceCell<T>,
    /// Tracks registered waiter identity to prevent unbounded queue growth.
    waiter_id: Option<u64>,
}

impl<T> Future for WaitInit<'_, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let state = this.cell.state.load(Ordering::Acquire);
        if state == INITIALIZING {
            this.cell.register_waker(cx.waker(), &mut this.waiter_id);
            // Double-check after registering.
            if this.cell.state.load(Ordering::Acquire) == INITIALIZING {
                Poll::Pending
            } else {
                // Do not clear waiter_id here. If state changed after register_waker
                // but before transition_out_of_initializing drained the queue, Drop must remove it to
                // prevent memory leaks.
                Poll::Ready(())
            }
        } else {
            Poll::Ready(())
        }
    }
}

impl<T> Drop for WaitInit<'_, T> {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            // Remove canceled waiter registrations immediately so repeated
            // cancel/drop cycles don't accumulate until transition_out_of_initializing() drains.
            self.cell.remove_waiter_for_cancellation(waiter_id);
        }
    }
}

/// Cancel-aware future that waits for initialization to complete.
struct CancelAwareWaitInit<'a, T, Caps = crate::cx::cap::All> {
    cell: &'a OnceCell<T>,
    cx: &'a crate::cx::Cx<Caps>,
    /// Tracks registered waiter identity to prevent unbounded queue growth.
    waiter_id: Option<u64>,
}

impl<T, Caps> std::future::Future for CancelAwareWaitInit<'_, T, Caps> {
    type Output = Result<(), OnceCellError>;

    fn poll(self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Check cancellation first
        if this.cx.checkpoint().is_err() {
            return Poll::Ready(Err(OnceCellError::Cancelled));
        }

        let state = this.cell.state.load(Ordering::Acquire);
        if state == INITIALIZING {
            this.cell
                .register_waker(task_cx.waker(), &mut this.waiter_id);
            // Double-check after registering.
            if this.cell.state.load(Ordering::Acquire) == INITIALIZING {
                // Check cancellation again after registering waker
                if this.cx.checkpoint().is_err() {
                    return Poll::Ready(Err(OnceCellError::Cancelled));
                }
                Poll::Pending
            } else {
                // Do not clear waiter_id here for same reason as WaitInit
                Poll::Ready(Ok(()))
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl<T, Caps> Drop for CancelAwareWaitInit<'_, T, Caps> {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            // Remove canceled waiter registrations immediately
            self.cell.remove_waiter_for_cancellation(waiter_id);
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
    use futures_lite::future::{block_on, pending};
    use proptest::prelude::*;
    use std::future::{Future, poll_fn};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Poll, Waker};
    use std::thread;

    struct BlockingWaitHookGuard;

    impl Drop for BlockingWaitHookGuard {
        fn drop(&mut self) {
            let mut guard = BLOCKING_WAIT_HOOK
                .get_or_init(|| StdMutex::new(None))
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = None;
        }
    }

    /// Serializes tests that spawn threads which may call `wait_for_init_blocking`
    /// (and thus `run_blocking_wait_hook`), preventing cross-test interference
    /// through the global `BLOCKING_WAIT_HOOK` static.
    static BLOCKING_TEST_SERIALIZER: StdMutex<()> = StdMutex::new(());

    fn acquire_blocking_test_lock() -> std::sync::MutexGuard<'static, ()> {
        BLOCKING_TEST_SERIALIZER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn install_blocking_wait_hook(hook: std::sync::Arc<BlockingWaitHook>) -> BlockingWaitHookGuard {
        let mut guard = BLOCKING_WAIT_HOOK
            .get_or_init(|| StdMutex::new(None))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(hook);
        BlockingWaitHookGuard
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
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

    use std::task::Wake;
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn wait_accepts_detached_no_cap_context() {
        init_test("wait_accepts_detached_no_cap_context");
        let cell = OnceCell::new();
        let cx = crate::cx::Cx::<crate::cx::cap::None>::detached_cancel_context();

        cell.set(47).expect("set should succeed");
        block_on(cell.wait(&cx)).expect("wait should accept cap::None Cx");

        crate::assert_with_log!(
            cell.get() == Some(&47),
            "cell value",
            Some(47),
            cell.get().copied()
        );
        crate::test_complete!("wait_accepts_detached_no_cap_context");
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
    fn set_returns_err_immediately_when_inflight_initializer_running() {
        init_test("set_returns_err_immediately_when_inflight_initializer_running");
        let _lock = acquire_blocking_test_lock();
        let cell = Arc::new(OnceCell::<u32>::new());
        let gate = Arc::new(std::sync::Barrier::new(2));

        let cell_for_init = Arc::clone(&cell);
        let gate_for_init = Arc::clone(&gate);
        let init_handle = thread::spawn(move || {
            *cell_for_init.get_or_init_blocking(|| {
                gate_for_init.wait();
                thread::sleep(std::time::Duration::from_millis(25));
                7
            })
        });

        // Ensure initializer has entered and is in-flight before calling set.
        gate.wait();

        let set_result = cell.set(9);
        crate::assert_with_log!(
            set_result == Err(9),
            "set should return Err immediately when inflight init is running",
            Err::<(), u32>(9),
            set_result
        );

        let init_value = init_handle.join().expect("initializer panicked");
        crate::assert_with_log!(init_value == 7, "initializer value", 7u32, init_value);
        crate::assert_with_log!(
            cell.get() == Some(&7),
            "cell keeps inflight initializer result",
            Some(&7),
            cell.get()
        );
        crate::test_complete!("set_returns_err_immediately_when_inflight_initializer_running");
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

    proptest! {
        #[test]
        fn metamorphic_initialization_path_preserves_visibility_surface(
            value in any::<u32>(),
            fallback in any::<u32>(),
        ) {
            let eager_cell = OnceCell::with_value(value);

            let set_cell = OnceCell::new();
            prop_assert_eq!(set_cell.set(value), Ok(()));

            let async_cell = OnceCell::new();
            let async_value = block_on(async_cell.get_or_init(|| async move { value }));
            prop_assert_eq!(*async_value, value);

            let blocking_cell = OnceCell::new();
            let blocking_value = blocking_cell.get_or_init_blocking(|| value);
            prop_assert_eq!(*blocking_value, value);

            for cell in [&eager_cell, &set_cell, &async_cell, &blocking_cell] {
                prop_assert!(cell.is_initialized());
                prop_assert_eq!(cell.get(), Some(&value));

                let async_probe_runs = Arc::new(AtomicUsize::new(0));
                let async_probe_counter = Arc::clone(&async_probe_runs);
                let observed_async = block_on(cell.get_or_init(|| async move {
                    async_probe_counter.fetch_add(1, Ordering::SeqCst);
                    fallback
                }));
                prop_assert_eq!(*observed_async, value);
                prop_assert_eq!(async_probe_runs.load(Ordering::SeqCst), 0);

                let blocking_probe_runs = Arc::new(AtomicUsize::new(0));
                let blocking_probe_counter = Arc::clone(&blocking_probe_runs);
                let observed_blocking = cell.get_or_init_blocking(|| {
                    blocking_probe_counter.fetch_add(1, Ordering::SeqCst);
                    fallback
                });
                prop_assert_eq!(*observed_blocking, value);
                prop_assert_eq!(blocking_probe_runs.load(Ordering::SeqCst), 0);

                let cloned = cell.clone();
                prop_assert!(cloned.is_initialized());
                prop_assert_eq!(cloned.get(), Some(&value));
            }
        }

        #[test]
        fn metamorphic_async_cancellation_recovery_matches_fresh_success_surface(
            value in any::<u32>(),
            fallback in any::<u32>(),
        ) {
            let recovered = OnceCell::new();
            let fresh = OnceCell::new();

            let mut cancelled_init = Box::pin(recovered.get_or_init(|| async { pending::<u32>().await }));
            let noop = noop_waker();
            let mut cx = Context::from_waker(&noop);
            prop_assert!(Future::poll(cancelled_init.as_mut(), &mut cx).is_pending());
            drop(cancelled_init);

            prop_assert!(!recovered.is_initialized());

            let recovered_value = block_on(recovered.get_or_init(|| async move { value }));
            let fresh_value = block_on(fresh.get_or_init(|| async move { value }));

            let ignored_probe_runs = Arc::new(AtomicUsize::new(0));
            let ignored_probe_counter = Arc::clone(&ignored_probe_runs);
            let recovered_again = block_on(recovered.get_or_init(|| async move {
                ignored_probe_counter.fetch_add(1, Ordering::SeqCst);
                fallback
            }));

            prop_assert_eq!(*recovered_value, *fresh_value);
            prop_assert_eq!(*recovered_again, value);
            prop_assert_eq!(ignored_probe_runs.load(Ordering::SeqCst), 0);
            prop_assert_eq!(recovered.get(), fresh.get());
            prop_assert!(recovered.is_initialized());
        }
    }

    fn run_async_waiter_race_case(fallbacks: &[u32]) -> (Vec<u32>, usize, Option<u32>) {
        let cell: OnceCell<u32> = OnceCell::new();
        let release_winner = Arc::new(AtomicBool::new(false));
        let fallback_runs = Arc::new(AtomicUsize::new(0));
        let winner_value = 41u32;

        let release_for_init = Arc::clone(&release_winner);
        let mut init_fut = Box::pin(cell.get_or_init(move || {
            let release_for_init = Arc::clone(&release_for_init);
            async move {
                poll_fn(move |_| {
                    if release_for_init.load(Ordering::SeqCst) {
                        Poll::Ready(winner_value)
                    } else {
                        Poll::Pending
                    }
                })
                .await
            }
        }));

        let noop = noop_waker();
        let mut cx = Context::from_waker(&noop);
        assert!(Future::poll(init_fut.as_mut(), &mut cx).is_pending());

        let mut waiters = Vec::with_capacity(fallbacks.len());
        for &fallback in fallbacks {
            let fallback_runs = Arc::clone(&fallback_runs);
            waiters.push(Box::pin(cell.get_or_init(move || {
                let fallback_runs = Arc::clone(&fallback_runs);
                async move {
                    fallback_runs.fetch_add(1, Ordering::SeqCst);
                    fallback
                }
            })));
        }

        for waiter in &mut waiters {
            assert!(Future::poll(waiter.as_mut(), &mut cx).is_pending());
        }

        release_winner.store(true, Ordering::SeqCst);

        let mut observed = Vec::with_capacity(fallbacks.len() + 1);
        match Future::poll(init_fut.as_mut(), &mut cx) {
            Poll::Ready(value) => observed.push(*value),
            Poll::Pending => panic!("winner should complete after release"),
        }

        for waiter in &mut waiters {
            match Future::poll(waiter.as_mut(), &mut cx) {
                Poll::Ready(value) => observed.push(*value),
                Poll::Pending => panic!("waiter should observe the winner once initialized"),
            }
        }

        (
            observed,
            fallback_runs.load(Ordering::SeqCst),
            cell.get().copied(),
        )
    }

    fn run_async_waiter_cancel_subset_case(
        fallbacks: &[u32],
        cancelled_waiters: usize,
    ) -> (Vec<u32>, usize, usize, Option<u32>) {
        assert!(cancelled_waiters <= fallbacks.len());

        let cell: OnceCell<u32> = OnceCell::new();
        let release_winner = Arc::new(AtomicBool::new(false));
        let fallback_runs = Arc::new(AtomicUsize::new(0));
        let winner_value = 41u32;

        let release_for_init = Arc::clone(&release_winner);
        let mut init_fut = Box::pin(cell.get_or_init(move || {
            let release_for_init = Arc::clone(&release_for_init);
            async move {
                poll_fn(move |_| {
                    if release_for_init.load(Ordering::SeqCst) {
                        Poll::Ready(winner_value)
                    } else {
                        Poll::Pending
                    }
                })
                .await
            }
        }));

        let noop = noop_waker();
        let mut cx = Context::from_waker(&noop);
        assert!(Future::poll(init_fut.as_mut(), &mut cx).is_pending());

        let mut waiters = Vec::with_capacity(fallbacks.len());
        for &fallback in fallbacks {
            let fallback_runs = Arc::clone(&fallback_runs);
            waiters.push(Box::pin(cell.get_or_init(move || {
                let fallback_runs = Arc::clone(&fallback_runs);
                async move {
                    fallback_runs.fetch_add(1, Ordering::SeqCst);
                    fallback
                }
            })));
        }

        for waiter in &mut waiters {
            assert!(Future::poll(waiter.as_mut(), &mut cx).is_pending());
        }

        for _ in 0..cancelled_waiters {
            drop(waiters.pop().expect("cancelled waiter must exist"));
        }

        let queued_waiters_after_cancel = cell
            .waiters
            .lock()
            .expect("waiters lock poisoned")
            .waiters
            .len();
        assert_eq!(
            queued_waiters_after_cancel,
            fallbacks.len() - cancelled_waiters,
            "cancelled waiters should be removed immediately"
        );

        release_winner.store(true, Ordering::SeqCst);

        let mut observed = Vec::with_capacity(waiters.len() + 1);
        match Future::poll(init_fut.as_mut(), &mut cx) {
            Poll::Ready(value) => observed.push(*value),
            Poll::Pending => panic!("winner should complete after release"),
        }

        for waiter in &mut waiters {
            match Future::poll(waiter.as_mut(), &mut cx) {
                Poll::Ready(value) => observed.push(*value),
                Poll::Pending => panic!("surviving waiter should observe the winner"),
            }
        }

        let queued_waiters_after_release = cell
            .waiters
            .lock()
            .expect("waiters lock poisoned")
            .waiters
            .len();

        (
            observed,
            fallback_runs.load(Ordering::SeqCst),
            queued_waiters_after_release,
            cell.get().copied(),
        )
    }

    #[test]
    fn metamorphic_async_waiters_converge_on_winner_without_running_fallbacks() {
        init_test("metamorphic_async_waiters_converge_on_winner_without_running_fallbacks");
        let cell: OnceCell<u32> = OnceCell::new();
        let release_winner = Arc::new(AtomicBool::new(false));
        let fallback_runs = Arc::new(AtomicUsize::new(0));
        let winner_value = 41u32;

        let release_for_init = Arc::clone(&release_winner);
        let mut init_fut = Box::pin(cell.get_or_init(move || {
            let release_for_init = Arc::clone(&release_for_init);
            async move {
                poll_fn(move |_| {
                    if release_for_init.load(Ordering::SeqCst) {
                        Poll::Ready(winner_value)
                    } else {
                        Poll::Pending
                    }
                })
                .await
            }
        }));

        let noop = noop_waker();
        let mut cx = Context::from_waker(&noop);
        assert!(Future::poll(init_fut.as_mut(), &mut cx).is_pending());

        let mut waiters = Vec::new();
        for fallback in [7u32, 13, 21, 34] {
            let fallback_runs = Arc::clone(&fallback_runs);
            waiters.push(Box::pin(cell.get_or_init(move || {
                let fallback_runs = Arc::clone(&fallback_runs);
                async move {
                    fallback_runs.fetch_add(1, Ordering::SeqCst);
                    fallback
                }
            })));
        }

        for waiter in &mut waiters {
            assert!(Future::poll(waiter.as_mut(), &mut cx).is_pending());
        }

        release_winner.store(true, Ordering::SeqCst);

        match Future::poll(init_fut.as_mut(), &mut cx) {
            Poll::Ready(value) => assert_eq!(*value, winner_value),
            Poll::Pending => panic!("winner should complete after release"),
        }

        for waiter in &mut waiters {
            match Future::poll(waiter.as_mut(), &mut cx) {
                Poll::Ready(value) => assert_eq!(*value, winner_value),
                Poll::Pending => panic!("waiter should observe the winner once initialized"),
            }
        }

        assert_eq!(fallback_runs.load(Ordering::SeqCst), 0);
        assert_eq!(cell.get(), Some(&winner_value));
        crate::test_complete!(
            "metamorphic_async_waiters_converge_on_winner_without_running_fallbacks"
        );
    }

    #[test]
    fn metamorphic_async_get_or_init_surface_is_invariant_to_racer_count() {
        init_test("metamorphic_async_get_or_init_surface_is_invariant_to_racer_count");

        let baseline = run_async_waiter_race_case(&[]);
        assert_eq!(baseline.0, vec![41]);
        assert_eq!(baseline.1, 0);
        assert_eq!(baseline.2, Some(41));

        for fallbacks in [
            &[7u32][..],
            &[7u32, 13, 21, 34][..],
            &[5u32, 8, 13, 21, 34, 55, 89, 144][..],
        ] {
            let amplified = run_async_waiter_race_case(fallbacks);
            assert_eq!(amplified.1, 0, "fallback initializers must stay dormant");
            assert_eq!(amplified.2, baseline.2, "winner visibility must be stable");
            assert_eq!(amplified.0.len(), fallbacks.len() + 1);
            assert!(
                amplified.0.iter().all(|&value| value == baseline.0[0]),
                "all racers should observe the same winner: {:?}",
                amplified.0
            );
        }

        crate::test_complete!("metamorphic_async_get_or_init_surface_is_invariant_to_racer_count");
    }

    #[test]
    fn metamorphic_async_get_or_init_surface_is_invariant_to_cancelled_waiter_subset() {
        init_test("metamorphic_async_get_or_init_surface_is_invariant_to_cancelled_waiter_subset");

        let fallbacks = [7u32, 13, 21, 34, 55];
        let baseline = run_async_waiter_cancel_subset_case(&fallbacks, 0);
        assert_eq!(baseline.1, 0, "fallback initializers must stay dormant");
        assert_eq!(baseline.2, 0, "all waiter registrations should be drained");
        assert_eq!(baseline.3, Some(41));
        assert_eq!(baseline.0.len(), fallbacks.len() + 1);
        assert!(baseline.0.iter().all(|&value| value == baseline.0[0]));

        for cancelled_waiters in 1..=fallbacks.len() {
            let transformed = run_async_waiter_cancel_subset_case(&fallbacks, cancelled_waiters);
            assert_eq!(transformed.1, 0, "fallback initializers must stay dormant");
            assert_eq!(
                transformed.2, 0,
                "all waiter registrations should be drained"
            );
            assert_eq!(
                transformed.3, baseline.3,
                "winner visibility must be stable after waiter cancellation"
            );
            assert_eq!(transformed.0.len(), fallbacks.len() + 1 - cancelled_waiters);
            assert!(
                transformed.0.iter().all(|&value| value == baseline.0[0]),
                "surviving racers should observe the same winner: {:?}",
                transformed.0
            );
        }

        crate::test_complete!(
            "metamorphic_async_get_or_init_surface_is_invariant_to_cancelled_waiter_subset"
        );
    }

    #[test]
    fn metamorphic_async_panic_recovery_preserves_no_poison_surface() {
        init_test("metamorphic_async_panic_recovery_preserves_no_poison_surface");

        let recovered = OnceCell::<u32>::new();
        let fresh = OnceCell::<u32>::new();
        let panic_gate = Arc::new(AtomicBool::new(false));
        let recovery_runs = Arc::new(AtomicUsize::new(0));
        let expected = 55u32;

        let panic_gate_for_init = Arc::clone(&panic_gate);
        let mut panicking_init = Box::pin(recovered.get_or_init(move || {
            let panic_gate_for_init = Arc::clone(&panic_gate_for_init);
            async move {
                poll_fn(move |_| {
                    if panic_gate_for_init.load(Ordering::SeqCst) {
                        panic!("boom");
                    }
                    Poll::Pending
                })
                .await
            }
        }));

        let recovery_runs_for_waiter = Arc::clone(&recovery_runs);
        let mut waiter = Box::pin(recovered.get_or_init(move || {
            let recovery_runs_for_waiter = Arc::clone(&recovery_runs_for_waiter);
            async move {
                recovery_runs_for_waiter.fetch_add(1, Ordering::SeqCst);
                expected
            }
        }));

        let noop = noop_waker();
        let mut cx = Context::from_waker(&noop);

        assert!(Future::poll(panicking_init.as_mut(), &mut cx).is_pending());
        assert!(Future::poll(waiter.as_mut(), &mut cx).is_pending());
        assert_eq!(recovered.state.load(Ordering::Acquire), INITIALIZING);
        assert_eq!(
            recovered
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiters
                .len(),
            1,
            "the waiter should be registered while the first initializer is inflight"
        );

        panic_gate.store(true, Ordering::SeqCst);
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Future::poll(panicking_init.as_mut(), &mut cx)
        }));
        assert!(
            panic_result.is_err(),
            "initializer panic should propagate to the initiating caller"
        );

        assert_eq!(
            recovered.state.load(Ordering::Acquire),
            UNINIT,
            "panic recovery must reset the cell to the uninitialized state"
        );
        assert!(!recovered.is_initialized());
        assert_eq!(recovered.get(), None);
        assert_eq!(
            recovered
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiters
                .len(),
            0,
            "panic recovery must drain queued waiter registrations"
        );

        let recovered_value = match Future::poll(waiter.as_mut(), &mut cx) {
            Poll::Ready(value) => *value,
            Poll::Pending => panic!("waiter should retry and initialize after panic recovery"),
        };
        let fresh_value = *block_on(fresh.get_or_init(|| async move { expected }));

        assert_eq!(
            recovery_runs.load(Ordering::SeqCst),
            1,
            "exactly one recovery initializer should run"
        );
        assert_eq!(recovered_value, fresh_value);
        assert_eq!(recovered.get(), fresh.get());
        assert_eq!(recovered.is_initialized(), fresh.is_initialized());
        assert_eq!(recovered.state.load(Ordering::Acquire), INITIALIZED);
        assert_eq!(
            recovered
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiters
                .len(),
            0,
            "the recovery path must not leave behind waiter state"
        );

        crate::test_complete!("metamorphic_async_panic_recovery_preserves_no_poison_surface");
    }

    #[test]
    fn metamorphic_blocking_contenders_converge_on_single_observable_winner() {
        init_test("metamorphic_blocking_contenders_converge_on_single_observable_winner");
        let _lock = acquire_blocking_test_lock();

        for candidates in [
            &[11u32, 17][..],
            &[5u32, 8, 13][..],
            &[2u32, 3, 5, 8, 13][..],
        ] {
            let cell = Arc::new(OnceCell::<u32>::new());
            let start_gate = Arc::new(std::sync::Barrier::new(candidates.len()));
            let init_runs = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::with_capacity(candidates.len());

            for &candidate in candidates {
                let cell = Arc::clone(&cell);
                let start_gate = Arc::clone(&start_gate);
                let init_runs = Arc::clone(&init_runs);
                handles.push(thread::spawn(move || {
                    start_gate.wait();
                    *cell.get_or_init_blocking(|| {
                        init_runs.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(std::time::Duration::from_millis(5));
                        candidate
                    })
                }));
            }

            let observed: Vec<u32> = handles
                .into_iter()
                .map(|handle| handle.join().expect("thread panicked"))
                .collect();
            let winner = observed[0];

            assert!(
                observed.iter().all(|&value| value == winner),
                "all contenders should observe the same winner: {observed:?}"
            );
            assert_eq!(
                init_runs.load(Ordering::SeqCst),
                1,
                "exactly one initializer should run"
            );
            assert_eq!(cell.get(), Some(&winner));

            let probe_runs = Arc::new(AtomicUsize::new(0));
            let probe_counter = Arc::clone(&probe_runs);
            let cached = cell.get_or_init_blocking(|| {
                probe_counter.fetch_add(1, Ordering::SeqCst);
                999
            });
            assert_eq!(*cached, winner);
            assert_eq!(probe_runs.load(Ordering::SeqCst), 0);
        }

        crate::test_complete!(
            "metamorphic_blocking_contenders_converge_on_single_observable_winner"
        );
    }

    #[test]
    fn metamorphic_blocking_panic_recovery_matches_fresh_success_surface() {
        init_test("metamorphic_blocking_panic_recovery_matches_fresh_success_surface");
        let _lock = acquire_blocking_test_lock();
        let recovered = Arc::new(OnceCell::<u32>::new());
        let fresh = OnceCell::<u32>::new();
        let expected = 55u32;

        let recovered_for_panic = Arc::clone(&recovered);
        let panic_handle = thread::spawn(move || {
            let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = recovered_for_panic.get_or_init_blocking(|| -> u32 { panic!("boom") });
            }));
            assert!(
                panic_result.is_err(),
                "initializer panic should be captured"
            );
        });
        panic_handle.join().expect("panic thread panicked");

        let recovered_value = *recovered.get_or_init_blocking(|| expected);
        let fresh_value = *fresh.get_or_init_blocking(|| expected);

        assert_eq!(recovered_value, fresh_value);
        assert_eq!(recovered.get(), fresh.get());
        assert_eq!(recovered.is_initialized(), fresh.is_initialized());
        crate::test_complete!("metamorphic_blocking_panic_recovery_matches_fresh_success_surface");
    }

    proptest! {
        #[test]
        fn metamorphic_try_init_error_recovery_matches_direct_success(
            value in any::<u32>(),
            fallback in any::<u32>(),
        ) {
            let recovered = OnceCell::new();
            let fresh = OnceCell::new();

            prop_assert_eq!(
                block_on(recovered.get_or_try_init(|| async { Err::<u32, &'static str>("boom") })),
                Err("boom")
            );
            prop_assert!(!recovered.is_initialized());

            let recovered_value = block_on(recovered.get_or_try_init(|| async move {
                Ok::<u32, &'static str>(value)
            }))
            .expect("recovery init should succeed");
            let fresh_value = block_on(fresh.get_or_try_init(|| async move {
                Ok::<u32, &'static str>(value)
            }))
            .expect("fresh init should succeed");

            let ignored_probe_runs = Arc::new(AtomicUsize::new(0));
            let ignored_probe_counter = Arc::clone(&ignored_probe_runs);
            let recovered_again = block_on(recovered.get_or_try_init(|| async move {
                ignored_probe_counter.fetch_add(1, Ordering::SeqCst);
                Ok::<u32, &'static str>(fallback)
            }))
            .expect("subsequent reads should observe the recovered value");

            prop_assert_eq!(*recovered_value, *fresh_value);
            prop_assert_eq!(*recovered_again, value);
            prop_assert_eq!(ignored_probe_runs.load(Ordering::SeqCst), 0);
            prop_assert_eq!(recovered.get(), fresh.get());
            prop_assert!(recovered.is_initialized());
        }
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
        let _lock = acquire_blocking_test_lock();
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
    fn get_or_init_blocking_does_not_miss_cancel_notify_between_check_and_wait() {
        init_test("get_or_init_blocking_does_not_miss_cancel_notify_between_check_and_wait");
        let _lock = acquire_blocking_test_lock();
        let cell = Arc::new(OnceCell::<u32>::new());

        let (init_started_tx, init_started_rx) = std::sync::mpsc::channel();
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
        let (cancel_started_tx, cancel_started_rx) = std::sync::mpsc::channel();

        let cell_for_init = Arc::clone(&cell);
        let init_handle = thread::spawn(move || {
            let mut init_fut =
                Box::pin(cell_for_init.get_or_init(|| async { pending::<u32>().await }));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(Future::poll(init_fut.as_mut(), &mut cx).is_pending());
            init_started_tx
                .send(())
                .expect("init thread should report startup");
            cancel_rx
                .recv()
                .expect("main thread should request cancellation");
            cancel_started_tx
                .send(())
                .expect("init thread should report imminent cancellation");
            drop(init_fut);
        });

        init_started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("async initializer should enter INITIALIZING");

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let _hook_guard = install_blocking_wait_hook(std::sync::Arc::new(BlockingWaitHook {
            entered_tx,
            release_rx: StdMutex::new(release_rx),
        }));

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let cell_for_waiter = Arc::clone(&cell);
        let waiter_handle = thread::spawn(move || {
            let value = *cell_for_waiter.get_or_init_blocking(|| 42);
            done_tx
                .send(value)
                .expect("waiter thread should report initialization result");
        });

        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("blocking waiter should reach the pre-wait hook");
        cancel_tx
            .send(())
            .expect("main thread should be able to request cancellation");
        cancel_started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("init thread should start cancellation while waiter is paused");
        release_tx
            .send(())
            .expect("main thread should release the waiter into condvar wait");

        let value = done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("blocking waiter should not miss the cancellation wakeup");
        assert_eq!(value, 42);
        assert!(cell.is_initialized());

        waiter_handle.join().expect("waiter thread panicked");
        init_handle.join().expect("init thread panicked");
        crate::test_complete!(
            "get_or_init_blocking_does_not_miss_cancel_notify_between_check_and_wait"
        );
    }

    #[test]
    fn get_or_init_blocking_panic_resets_state() {
        init_test("get_or_init_blocking_panic_resets_state");
        let _lock = acquire_blocking_test_lock();
        let cell = Arc::new(OnceCell::<u32>::new());

        let cell_for_panic = Arc::clone(&cell);
        let handle = thread::spawn(move || {
            let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = cell_for_panic.get_or_init_blocking(|| -> u32 { panic!("boom") });
            }));
            crate::assert_with_log!(
                panic_result.is_err(),
                "initializer panic captured",
                true,
                panic_result.is_err()
            );
        });

        handle.join().expect("panic thread panicked");

        crate::assert_with_log!(
            !cell.is_initialized(),
            "cell remains uninitialized after panic",
            false,
            cell.is_initialized()
        );

        let value = cell.get_or_init_blocking(|| 55);
        crate::assert_with_log!(*value == 55, "recovery init", 55u32, *value);
        crate::test_complete!("get_or_init_blocking_panic_resets_state");
    }

    #[test]
    fn wait_for_init_blocking_recovers_from_poisoned_condvar_wait() {
        init_test("wait_for_init_blocking_recovers_from_poisoned_condvar_wait");
        let _lock = acquire_blocking_test_lock();
        let cell = Arc::new(OnceCell::<u32>::new());
        cell.state.store(INITIALIZING, Ordering::Release);

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cell
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional poison");
        }));

        let waiter = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                cell.wait_for_init_blocking();
            })
        };

        thread::sleep(std::time::Duration::from_millis(20));
        cell.state.store(UNINIT, Ordering::Release);
        cell.cvar.notify_all();

        let waiter_joined = waiter.join();
        crate::assert_with_log!(
            waiter_joined.is_ok(),
            "poisoned condvar wait should recover without panic",
            true,
            waiter_joined.is_ok()
        );
        crate::test_complete!("wait_for_init_blocking_recovers_from_poisoned_condvar_wait");
    }

    #[test]
    fn concurrent_init_only_runs_once() {
        init_test("concurrent_init_only_runs_once");
        let _lock = acquire_blocking_test_lock();
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
        let cloned = cell.clone();
        crate::assert_with_log!(
            cell.get() == Some(&42),
            "original value retained after clone",
            Some(&42),
            cell.get()
        );
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

    /// Invariant: if `get_or_try_init` returns an error, the cell remains
    /// UNINIT and a subsequent caller can succeed.
    #[test]
    fn get_or_try_init_error_resets_state() {
        init_test("get_or_try_init_error_resets_state");
        let cell = OnceCell::<u32>::new();

        let result: Result<&u32, &str> = block_on(cell.get_or_try_init(|| async { Err("fail") }));
        let is_err = result.is_err();
        crate::assert_with_log!(is_err, "first init fails", true, is_err);

        let still_uninit = !cell.is_initialized();
        crate::assert_with_log!(still_uninit, "cell UNINIT after error", true, still_uninit);

        // A second caller with a successful init should work.
        let val = block_on(cell.get_or_try_init(|| async { Ok::<u32, &str>(42) }));
        crate::assert_with_log!(val == Ok(&42), "second init ok", true, val == Ok(&42));

        crate::test_complete!("get_or_try_init_error_resets_state");
    }

    // =========================================================================
    // Pure data-type tests (wave 42 – CyanBarn)
    // =========================================================================

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn once_cell_error_debug_clone_copy_eq_display() {
        let already = OnceCellError::AlreadyInitialized;
        let cancelled = OnceCellError::Cancelled;
        let copied = already;
        let cloned = already.clone(); // intentional: exercises Clone on Copy type
        assert_eq!(copied, cloned);
        assert_eq!(copied, OnceCellError::AlreadyInitialized);
        assert_ne!(already, cancelled);
        assert!(format!("{already:?}").contains("AlreadyInitialized"));
        assert!(already.to_string().contains("already initialized"));
        assert!(cancelled.to_string().contains("cancelled"));
    }

    // =========================================================================
    // Metamorphic property: Init-then-get equivalence under concurrent races
    // =========================================================================

    #[test]
    fn metamorphic_init_then_get_equivalence_under_concurrent_first_init_race() {
        init_test("metamorphic_init_then_get_equivalence_under_concurrent_first_init_race");

        // Property: When multiple threads race to initialize the same OnceCell,
        // exactly one initialization function executes, and all callers (both
        // the winner and all waiters) observe the exact same value.
        //
        // Metamorphic relationship: Varying the number of concurrent initializers
        // or their individual values should NOT change which value all threads
        // eventually observe - only the race winner's value should be visible.

        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Test with different numbers of concurrent initializers
        for num_racers in [2, 3, 5, 8, 13] {
            let cell = Arc::new(OnceCell::<u32>::new());
            let init_count = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            // Each racer attempts to initialize with a unique value
            for racer_id in 0..num_racers {
                let cell_ref = Arc::clone(&cell);
                let counter = Arc::clone(&init_count);
                let unique_value = (racer_id + 1) * 100; // 100, 200, 300, ...

                let handle = std::thread::spawn(move || {
                    let observed_value = cell_ref.get_or_init_blocking(|| {
                        // Track that this init function was called
                        counter.fetch_add(1, Ordering::SeqCst);
                        unique_value
                    });
                    *observed_value
                });
                handles.push(handle);
            }

            // Collect all observed values
            let mut observed_values = Vec::new();
            for handle in handles {
                let value = handle.join().expect("thread should not panic");
                observed_values.push(value);
            }

            // METAMORPHIC ASSERTIONS:

            // 1. Exactly one initialization function executed
            let actual_init_calls = init_count.load(Ordering::SeqCst);
            assert_eq!(
                actual_init_calls, 1,
                "RACE VIOLATION: {} init functions executed, expected exactly 1 (racers={})",
                actual_init_calls, num_racers
            );

            // 2. All threads observed the same value (init-then-get equivalence)
            let first_observed = observed_values[0];
            assert!(
                observed_values.iter().all(|&v| v == first_observed),
                "EQUIVALENCE VIOLATION: Threads observed different values: {:?} (racers={})",
                observed_values,
                num_racers
            );

            // 3. The observed value must be one of the racer's intended values
            let intended_values: Vec<u32> = (0..num_racers).map(|i| (i + 1) * 100).collect();
            assert!(
                intended_values.contains(&first_observed),
                "CONSISTENCY VIOLATION: Observed value {} not in intended set {:?}",
                first_observed,
                intended_values
            );

            // 4. Cell remains initialized with the same value for subsequent calls
            let subsequent_value = *cell.get_or_init_blocking(|| {
                panic!("init should not be called again on initialized cell")
            });
            assert_eq!(
                subsequent_value, first_observed,
                "PERSISTENCE VIOLATION: Subsequent get returned different value"
            );
        }

        crate::test_complete!(
            "metamorphic_init_then_get_equivalence_under_concurrent_first_init_race"
        );
    }

    /// Audit test for concurrent get_or_init panic recovery semantics.
    ///
    /// Verifies that when N tasks race on get_or_init() and the initializer panics,
    /// the SECOND attempt re-runs the initializer (correct) rather than returning
    /// a poisoned cell forever (incorrect for asupersync semantics).
    #[test]
    fn audit_concurrent_get_or_init_panic_recovery() {
        init_test("audit_concurrent_get_or_init_panic_recovery");
        let cell = Arc::new(OnceCell::<u32>::new());
        let panic_gate = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(std::sync::Barrier::new(4)); // 3 racers + main thread

        // Spawn 3 racing tasks that will all try to initialize
        let handles: Vec<_> = (0..3)
            .map(|task_id| {
                let cell = Arc::clone(&cell);
                let panic_gate = Arc::clone(&panic_gate);
                let barrier = Arc::clone(&barrier);

                thread::spawn(move || {
                    // Wait for all racers to be ready
                    barrier.wait();

                    // First task will panic, others will retry
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        cell.get_or_init_blocking(|| {
                            if task_id == 0 && !panic_gate.load(Ordering::SeqCst) {
                                // First attempt panics
                                panic_gate.store(true, Ordering::SeqCst);
                                panic!("boom");
                            }
                            // Subsequent attempts succeed
                            42u32
                        })
                    }));

                    match result {
                        Ok(value) => *value,
                        Err(_) => {
                            // If we panicked, try again - this should work
                            *cell.get_or_init_blocking(|| 42u32)
                        }
                    }
                })
            })
            .collect();

        // Start the race
        barrier.wait();

        // Collect results from all tasks
        let results: Vec<u32> = handles
            .into_iter()
            .map(|h| h.join().expect("task should complete"))
            .collect();

        // Verify all tasks got the same value (cell was properly initialized)
        assert!(
            results.iter().all(|&v| v == 42),
            "all tasks should see same value: {:?}",
            results
        );

        // Verify the cell is properly initialized
        assert!(
            cell.is_initialized(),
            "cell should be initialized after panic recovery"
        );
        assert_eq!(
            *cell.get().unwrap(),
            42,
            "cell should contain correct value"
        );

        // Verify state is INITIALIZED, not poisoned
        assert_eq!(
            cell.state.load(Ordering::Acquire),
            INITIALIZED,
            "cell should be in INITIALIZED state"
        );

        // Verify subsequent access works normally
        let final_value = cell
            .get_or_init_blocking(|| panic!("should not be called on already-initialized cell"));
        assert_eq!(*final_value, 42, "subsequent access should work normally");

        crate::test_complete!("audit_concurrent_get_or_init_panic_recovery");
    }

    /// Audit test: OnceCell cancellation semantics - when a task is cancelled while
    /// running the initializer, the next task sees the cell as uninitialized (correct)
    /// and can re-run init, rather than hanging (incorrect deadlock).
    ///
    /// This test verifies asupersync's cancel-aware semantics: cancellation must not
    /// leave the OnceCell in a permanently broken state.
    #[test]
    fn audit_once_cell_cancellation_allows_reinitialization() {
        init_test("audit_once_cell_cancellation_allows_reinitialization");
        let cell: OnceCell<u32> = OnceCell::new();

        // Step 1: Start initialization with a future that never completes
        let mut cancelled_init = Box::pin(cell.get_or_init(|| async {
            // This future will be cancelled - it never resolves
            pending::<u32>().await
        }));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll once to start the initialization process
        let initial_poll = Future::poll(cancelled_init.as_mut(), &mut cx);
        crate::assert_with_log!(
            initial_poll.is_pending(),
            "initial init should be pending",
            true,
            initial_poll.is_pending()
        );

        // Verify cell is in INITIALIZING state
        crate::assert_with_log!(
            !cell.is_initialized(),
            "cell should not be initialized yet",
            false,
            cell.is_initialized()
        );
        crate::assert_with_log!(
            cell.state.load(Ordering::Acquire) == INITIALIZING,
            "cell should be in INITIALIZING state",
            INITIALIZING,
            cell.state.load(Ordering::Acquire)
        );

        // Step 2: Start a second task that will wait for the first
        let mut waiter_init = Box::pin(cell.get_or_init(|| async { 42u32 }));
        let waiter_poll = Future::poll(waiter_init.as_mut(), &mut cx);
        crate::assert_with_log!(
            waiter_poll.is_pending(),
            "waiter should be pending while first init runs",
            true,
            waiter_poll.is_pending()
        );

        // Step 3: Cancel the first initializer (simulates task cancellation)
        drop(cancelled_init);

        // Step 4: Verify cancel-aware semantics - cell should be back to UNINIT
        let state_after_cancel = cell.state.load(Ordering::Acquire);
        crate::assert_with_log!(
            state_after_cancel == UNINIT,
            "cell should be UNINIT after cancellation",
            UNINIT,
            state_after_cancel
        );

        crate::assert_with_log!(
            !cell.is_initialized(),
            "cell should not be initialized after cancellation",
            false,
            cell.is_initialized()
        );

        // Step 5: Critical test - waiter should NOT deadlock, should complete
        let waiter_retry = Future::poll(waiter_init.as_mut(), &mut cx);
        crate::assert_with_log!(
            waiter_retry.is_ready(),
            "waiter should complete after cancelled init (no deadlock)",
            true,
            waiter_retry.is_ready()
        );

        // Step 6: Verify successful re-initialization
        crate::assert_with_log!(
            cell.is_initialized(),
            "cell should be initialized by waiter",
            true,
            cell.is_initialized()
        );

        let final_value = cell.get().expect("cell should have value");
        crate::assert_with_log!(
            *final_value == 42,
            "cell should contain waiter's value",
            42u32,
            *final_value
        );

        // Step 7: Verify subsequent access works normally
        let subsequent_value =
            block_on(cell.get_or_init(|| async {
                panic!("should not be called on already-initialized cell")
            }));
        crate::assert_with_log!(
            *subsequent_value == 42,
            "subsequent access should return existing value",
            42u32,
            *subsequent_value
        );

        // Step 8: Test multiple cancellation + recovery cycles
        let cell2: OnceCell<String> = OnceCell::new();

        // Cancel 3 initializers in a row
        for cycle in 0..3 {
            let mut temp_init = Box::pin(cell2.get_or_init(|| async { pending::<String>().await }));

            let poll_result = Future::poll(temp_init.as_mut(), &mut cx);
            crate::assert_with_log!(
                poll_result.is_pending(),
                &format!("cycle {} init should be pending", cycle),
                true,
                poll_result.is_pending()
            );

            drop(temp_init); // Cancel

            crate::assert_with_log!(
                !cell2.is_initialized(),
                &format!("cycle {} cell should remain uninit after cancel", cycle),
                false,
                cell2.is_initialized()
            );
        }

        // Final successful initialization
        let final_init_value = block_on(cell2.get_or_init(|| async { "success".to_string() }));
        crate::assert_with_log!(
            final_init_value == "success",
            "final init should succeed after multiple cancellations",
            "success",
            final_init_value.as_str()
        );

        crate::test_complete!("audit_once_cell_cancellation_allows_reinitialization");
    }

    #[test]
    fn audit_once_cell_panic_retry_behavior() {
        init_test("audit_once_cell_panic_retry_behavior");

        // AUDIT: Verify OnceCell remains retryable rather than poisoned after initializer panic
        // CONTEXT: Asupersync design principle - structured concurrency with graceful error recovery
        // MECHANISM: InitGuard::Drop resets cell to UNINIT on panic via transition_out_of_initializing(UNINIT)

        let cell = OnceCell::new();

        // First attempt: initializer panics
        let panic_result = std::panic::catch_unwind(|| {
            block_on(cell.get_or_init(|| async { panic!("first attempt fails") }))
        });
        crate::assert_with_log!(
            panic_result.is_err(),
            "First init should have panicked",
            true,
            panic_result.is_err()
        );

        // Cell should be retryable - NOT permanently poisoned
        let success_value = block_on(cell.get_or_init(|| async { 42 }));
        crate::assert_with_log!(
            success_value == &42,
            "Second init should succeed after panic",
            &42,
            success_value
        );

        // Third attempt should return the successfully initialized value
        let cached_value = block_on(cell.get_or_init(|| async { panic!("should not be called") }));
        crate::assert_with_log!(
            cached_value == &42,
            "Third access should return cached value",
            &42,
            cached_value
        );

        // Verify the value is properly stored
        crate::assert_with_log!(
            cell.get() == Some(&42),
            "get() should return the initialized value",
            Some(&42),
            cell.get()
        );

        crate::test_complete!("audit_once_cell_panic_retry_behavior");
    }

    #[test]
    fn audit_once_cell_set_vs_get_or_init_race_first_write_wins() {
        init_test("audit_once_cell_set_vs_get_or_init_race_first_write_wins");

        // AUDIT: Verify OnceCell set() vs get_or_init() race implements first-write-wins
        // CONTEXT: Asupersync spec requires deterministic behavior when racing initialization
        // MECHANISM: Both operations CAS UNINIT→INITIALIZING; winner proceeds, loser adapts

        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Phase 1: Test set() wins race (fast set vs slow get_or_init)
        let cell1 = Arc::new(OnceCell::new());
        let set_won = Arc::new(AtomicBool::new(false));

        let cell_for_set = Arc::clone(&cell1);
        let set_won_flag = Arc::clone(&set_won);

        // Simulate race: set() should win and get_or_init() should return set value
        let set_result = cell_for_set.set(100u32);
        set_won_flag.store(set_result.is_ok(), Ordering::SeqCst);

        // get_or_init() should return the set value, not run initializer
        let mut initializer_ran = false;
        let get_or_init_result = block_on(cell1.get_or_init(|| async {
            initializer_ran = true;
            200u32 // This should not be the final value
        }));

        crate::assert_with_log!(
            set_won.load(Ordering::SeqCst),
            "set() should succeed in race",
            true,
            set_won.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            *get_or_init_result == 100,
            "get_or_init() should return set() value",
            100u32,
            *get_or_init_result
        );
        crate::assert_with_log!(
            !initializer_ran,
            "get_or_init() initializer should not run",
            false,
            initializer_ran
        );

        // Phase 2: Test get_or_init() wins race (slow set vs fast get_or_init)
        let cell2 = Arc::new(OnceCell::new());

        // Start get_or_init first
        let get_or_init_result = block_on(cell2.get_or_init(|| async { 300u32 }));

        // set() should fail since cell is already initialized
        let set_result = cell2.set(400u32);

        crate::assert_with_log!(
            *get_or_init_result == 300,
            "get_or_init() should succeed when winning race",
            300u32,
            *get_or_init_result
        );
        crate::assert_with_log!(
            set_result.is_err(),
            "set() should fail when losing race",
            true,
            set_result.is_err()
        );
        if let Err(rejected_value) = set_result {
            crate::assert_with_log!(
                rejected_value == 400,
                "set() should return rejected value",
                400u32,
                rejected_value
            );
        }

        // Phase 3: Test multiple get_or_init() racing (only one should run initializer)
        let cell3 = Arc::new(OnceCell::new());
        let init_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();

        for i in 0..5 {
            let cell_clone = Arc::clone(&cell3);
            let counter_clone = Arc::clone(&init_count);
            let handle = std::thread::spawn(move || {
                *block_on(cell_clone.get_or_init(|| async {
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                    500u32 + i // Only winner's value should be used
                }))
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle.join().expect("thread should complete");
            results.push(result);
        }

        // All results should be the same (winner's value)
        let first_result = results[0];
        let all_same = results.iter().all(|&x| x == first_result);
        crate::assert_with_log!(
            all_same,
            "all get_or_init() calls should return same value",
            true,
            all_same
        );

        let init_count_final = init_count.load(Ordering::SeqCst);
        crate::assert_with_log!(
            init_count_final == 1,
            "only one initializer should run in race",
            1usize,
            init_count_final
        );

        // Phase 4: Test set() vs already-initialized (immediate error)
        let cell4 = OnceCell::with_value(600u32);
        let late_set_result = cell4.set(700u32);

        crate::assert_with_log!(
            late_set_result.is_err(),
            "set() fails on already-initialized cell",
            true,
            late_set_result.is_err()
        );
        crate::assert_with_log!(
            cell4.get() == Some(&600),
            "cell retains original value after failed set",
            Some(&600),
            cell4.get()
        );

        crate::test_complete!("audit_once_cell_set_vs_get_or_init_race_first_write_wins");
    }

    /// Audit test: concurrent set+get happens-before relationship.
    ///
    /// When one task calls set(v) and another concurrently calls get(),
    /// the writer's value must be visible to the reader as soon as set()
    /// returns. This tests the Release-Acquire memory ordering on state field.
    ///
    /// Memory ordering bug would manifest as: set() returns Ok(()), but
    /// concurrent get() returns None due to lack of proper synchronization.
    #[test]
    fn audit_concurrent_set_get_happens_before_relationship() {
        init_test("audit_concurrent_set_get_happens_before_relationship");

        // Stress test with multiple iterations to catch ordering violations
        for iteration in 0..1000 {
            let cell = std::sync::Arc::new(OnceCell::<u64>::new());
            let cell_reader = cell.clone();
            let cell_writer = cell.clone();

            // Barrier to synchronize thread start
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let barrier_reader = barrier.clone();
            let barrier_writer = barrier.clone();

            // Flag to track when set() completes
            let set_completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let set_completed_reader = set_completed.clone();
            let set_completed_writer = set_completed.clone();

            let expected_value = 42u64 + iteration as u64;

            // Writer thread: calls set()
            let writer = std::thread::spawn(move || {
                barrier_writer.wait();
                let result = cell_writer.set(expected_value);
                // Memory barrier: set() completion must be visible to reader
                set_completed_writer.store(true, std::sync::atomic::Ordering::Release);
                result
            });

            // Reader thread: calls get() after set() completes
            let reader = std::thread::spawn(move || {
                barrier_reader.wait();

                // Spin until set() completes with proper synchronization
                while !set_completed_reader.load(std::sync::atomic::Ordering::Acquire) {
                    std::hint::spin_loop();
                }

                // At this point, set() has completed. The happens-before relationship
                // established by Release-Acquire on state field means get() MUST
                // see the written value immediately.
                cell_reader.get().copied()
            });

            let set_result = writer.join().expect("writer thread panicked");
            let get_result = reader.join().expect("reader thread panicked");

            // Verify set() succeeded
            crate::assert_with_log!(
                set_result.is_ok(),
                &format!("iteration {}: set() succeeded", iteration),
                true,
                set_result.is_ok()
            );

            // CRITICAL: verify happens-before - get() must see set() value immediately
            crate::assert_with_log!(
                get_result == Some(expected_value),
                &format!(
                    "iteration {}: get() sees set() value immediately after set() completes",
                    iteration
                ),
                Some(expected_value),
                get_result
            );

            // Additional verification: the cell is properly initialized
            let final_state_check = cell.get();
            crate::assert_with_log!(
                final_state_check == Some(&expected_value),
                &format!("iteration {}: final state consistent", iteration),
                Some(&expected_value),
                final_state_check
            );
        }

        crate::test_complete!("audit_concurrent_set_get_happens_before_relationship");
    }

    /// Audit test: OnceCell wait cancellation during initialization.
    ///
    /// When a task waits for OnceCell initialization and its context is cancelled,
    /// the wait should be cancel-aware and return immediately with cancellation error
    /// rather than continuing to wait indefinitely.
    #[test]
    fn audit_once_cell_wait_cancel_aware_semantics() {
        crate::test_utils::init_test_logging();

        let cell = OnceCell::<u32>::new();

        // Test 1: Verify cancellation during wait
        let cx = crate::cx::Cx::for_testing();

        // Start a slow initializer that will block
        let cell_clone = std::sync::Arc::new(cell);
        let init_cell = cell_clone.clone();
        let wait_cell = cell_clone.clone();

        // Spawn initializer that takes a long time
        std::thread::spawn(move || {
            block_on(async {
                let _ = init_cell
                    .get_or_init(|| async {
                        // Simulate slow initialization
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        42u32
                    })
                    .await;
            });
        });

        // Give initializer time to start
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Test that cancellation during wait works
        let _wait_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(async {
                // Cancel the context
                cx.cancel_fast(crate::types::CancelKind::User);

                // This should return with cancellation error, not wait indefinitely
                // DEFECT: Currently this may not check cancellation properly
                let start = std::time::Instant::now();
                let result = wait_cell.get_or_init(|| async { 99u32 }).await;
                let duration = start.elapsed();

                // Should return quickly due to cancellation, not wait for slow init
                (result, duration)
            })
        }));

        // The test should complete quickly if cancellation works correctly
        // If it hangs, the WaitInit future is not checking cancellation context

        crate::test_complete!("audit_once_cell_wait_cancel_aware_semantics");
    }

    #[test]
    fn audit_once_cell_set_atomicity_concurrent_access() {
        // Audit: OnceCell::set atomicity under concurrent access.
        // When two tasks call set(v1) and set(v2) concurrently on empty cell,
        // exactly ONE wins (linearizable) and the other returns Err without overwriting.

        init_test("audit_once_cell_set_atomicity_concurrent_access");

        const NUM_ITERATIONS: usize = 1000;
        const NUM_THREADS: usize = 8;

        for iteration in 0..NUM_ITERATIONS {
            let cell = std::sync::Arc::new(OnceCell::<u32>::new());
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(NUM_THREADS));
            let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|thread_id| {
                    let cell = cell.clone();
                    let barrier = barrier.clone();
                    let results = results.clone();

                    std::thread::spawn(move || {
                        // Synchronize all threads to maximize contention
                        barrier.wait();

                        // Each thread tries to set a unique value
                        let value = (thread_id as u32) + 1000;
                        let result = cell.set(value);

                        // Record result
                        results
                            .lock()
                            .unwrap()
                            .push((thread_id, value, result.is_ok()));
                    })
                })
                .collect();

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("thread should not panic");
            }

            // Analyze results for atomicity properties
            let results = results.lock().unwrap();
            let winners: Vec<_> = results.iter().filter(|(_, _, won)| *won).collect();
            let losers: Vec<_> = results.iter().filter(|(_, _, won)| !*won).collect();

            // ATOMICITY PROPERTY 1: Exactly one winner
            crate::assert_with_log!(
                winners.len() == 1,
                &format!("iteration {}: exactly one thread should win", iteration),
                1,
                winners.len()
            );

            // ATOMICITY PROPERTY 2: All others lose
            crate::assert_with_log!(
                losers.len() == NUM_THREADS - 1,
                &format!(
                    "iteration {}: exactly {} threads should lose",
                    iteration,
                    NUM_THREADS - 1
                ),
                NUM_THREADS - 1,
                losers.len()
            );

            // ATOMICITY PROPERTY 3: Winner's value is stored
            if let Some((_, winner_value, _)) = winners.first() {
                let stored_value = cell.get().expect("cell should be initialized");
                crate::assert_with_log!(
                    stored_value == winner_value,
                    &format!(
                        "iteration {}: stored value should match winner's value",
                        iteration
                    ),
                    *winner_value,
                    *stored_value
                );
            }

            // ATOMICITY PROPERTY 4: Cell is initialized after the race
            crate::assert_with_log!(
                cell.is_initialized(),
                &format!(
                    "iteration {}: cell should be initialized after race",
                    iteration
                ),
                true,
                cell.is_initialized()
            );

            // LINEARIZABILITY PROPERTY: No partial writes occurred
            // The cell either contains exactly one of the attempted values,
            // or is uninitialized (impossible after successful set)
            let stored_value = *cell.get().expect("cell should have value");
            let attempted_values: Vec<u32> = results.iter().map(|(_, val, _)| *val).collect();

            crate::assert_with_log!(
                attempted_values.contains(&stored_value),
                &format!(
                    "iteration {}: stored value {} must be one of attempted values {:?}",
                    iteration, stored_value, attempted_values
                ),
                true,
                attempted_values.contains(&stored_value)
            );
        }

        crate::test_complete!("audit_once_cell_set_atomicity_concurrent_access");
    }

    #[test]
    fn audit_once_cell_set_no_overwrite() {
        // Audit: OnceCell::set never overwrites existing value.
        // Sequential calls to set() after initialization should all fail.

        init_test("audit_once_cell_set_no_overwrite");

        let cell = OnceCell::new();

        // Initial set should succeed
        let first_result = cell.set(42u32);
        crate::assert_with_log!(
            first_result.is_ok(),
            "first set() should succeed on empty cell",
            true,
            first_result.is_ok()
        );

        crate::assert_with_log!(
            cell.get() == Some(&42),
            "cell should contain first value",
            Some(&42),
            cell.get()
        );

        // Subsequent sets should fail and return the rejected value
        for attempt in 1..=10 {
            let rejected_value = 1000 + attempt;
            let result = cell.set(rejected_value);

            crate::assert_with_log!(
                result.is_err(),
                &format!("set attempt {} should fail on initialized cell", attempt),
                true,
                result.is_err()
            );

            if let Err(returned_value) = result {
                crate::assert_with_log!(
                    returned_value == rejected_value,
                    &format!(
                        "attempt {}: returned value should match rejected value",
                        attempt
                    ),
                    rejected_value,
                    returned_value
                );
            }

            // Original value should remain unchanged
            crate::assert_with_log!(
                cell.get() == Some(&42),
                &format!(
                    "attempt {}: original value should remain unchanged",
                    attempt
                ),
                Some(&42),
                cell.get()
            );
        }

        crate::test_complete!("audit_once_cell_set_no_overwrite");
    }

    #[test]
    fn audit_set_get_happens_before_ordering() {
        crate::test_utils::init_test_logging();

        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::thread;

        // Stress test: verify that OnceCell::set() and OnceCell::get() have proper
        // happens-before relationship via Release/Acquire ordering.
        //
        // When writer calls set(v) and it returns successfully, concurrent readers
        // calling get() MUST immediately see Some(v) due to Release/Acquire synchronization.
        // They must NEVER see None after set() has returned.

        let test_iterations = 1000;
        let mut successful_immediate_visibility = 0;
        let late_visibility_count = Arc::new(AtomicUsize::new(0));

        for iteration in 0..test_iterations {
            let cell = Arc::new(OnceCell::<u64>::new());
            let writer_finished = Arc::new(AtomicBool::new(false));
            let test_value = (iteration + 1) as u64 * 1000 + 42; // Unique value per iteration

            let cell_reader = Arc::clone(&cell);
            let writer_finished_reader = Arc::clone(&writer_finished);
            let late_visibility = Arc::clone(&late_visibility_count);

            // Reader thread: polls get() continuously after writer signals completion
            let reader_handle = thread::spawn(move || {
                // Wait for writer to signal completion
                while !writer_finished_reader.load(Ordering::Acquire) {
                    std::hint::spin_loop(); // Busy wait for tight timing
                }

                // Writer has finished set() - we should immediately see the value
                let mut poll_attempts = 0;
                loop {
                    poll_attempts += 1;

                    match cell_reader.get() {
                        Some(value) => {
                            if poll_attempts > 1 {
                                // Value became visible after 1+ polls - potential ordering issue
                                late_visibility.fetch_add(1, Ordering::SeqCst);
                            }
                            return (true, poll_attempts, *value);
                        }
                        None => {
                            if poll_attempts > 100 {
                                // Fail-safe: stop after 100 attempts
                                return (false, poll_attempts, 0);
                            }
                            // Small delay to avoid burning CPU
                            std::hint::spin_loop();
                        }
                    }
                }
            });

            // Writer thread: set the value and signal completion
            let cell_writer = Arc::clone(&cell);
            let writer_finished_clone = Arc::clone(&writer_finished);

            let writer_handle = thread::spawn(move || {
                let set_result = cell_writer.set(test_value);

                // Signal that set() has returned (Release/Acquire ensures this is visible)
                writer_finished_clone.store(true, Ordering::Release);

                set_result
            });

            // Wait for both threads
            let writer_result = writer_handle.join().expect("Writer thread should complete");
            let (reader_saw_value, poll_attempts, reader_value) =
                reader_handle.join().expect("Reader thread should complete");

            // Verify writer succeeded
            assert!(
                writer_result.is_ok(),
                "iteration {}: set() should succeed",
                iteration
            );

            // Verify reader saw the correct value
            if reader_saw_value {
                assert_eq!(
                    reader_value, test_value,
                    "iteration {}: reader should see the exact value writer set",
                    iteration
                );

                if poll_attempts == 1 {
                    successful_immediate_visibility += 1;
                }
            } else {
                panic!(
                    "iteration {}: reader never saw value after {} polls - possible ordering defect",
                    iteration, poll_attempts
                );
            }
        }

        let late_visibility_total = late_visibility_count.load(Ordering::SeqCst);
        let immediate_visibility_rate =
            (successful_immediate_visibility as f64) / (test_iterations as f64);

        // Set/Get ordering audit completed

        // Verify ordering guarantees
        if immediate_visibility_rate < 0.95 {
            panic!(
                "❌ ORDERING DEFECT: Only {:.1}% immediate visibility, {} late cases. \
                 Expected >95% immediate visibility due to Release/Acquire synchronization. \
                 This suggests set() and get() may be using relaxed ordering instead of Release/Acquire.",
                immediate_visibility_rate * 100.0,
                late_visibility_total
            );
        }

        if late_visibility_total > test_iterations / 10 {
            panic!(
                "❌ ORDERING DEFECT: {} late visibility cases (>{} threshold). \
                 After set() returns, get() should see the value immediately due to happens-before relationship.",
                late_visibility_total,
                test_iterations / 10
            );
        }

        // OnceCell set()/get() has correct Release/Acquire happens-before ordering

        crate::test_complete!("audit_set_get_happens_before_ordering");
    }

    #[test]
    fn audit_once_cell_wait_cancellation_behavior() {
        use crate::cx::Cx;
        use crate::types::CancelKind;
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        crate::test_utils::init_test_logging();

        // This test verifies that OnceCell::wait() is cancel-aware and returns
        // Err(Cancelled) immediately when the context is cancelled, rather than
        // hanging indefinitely.

        let cell = Arc::new(OnceCell::<u32>::new());

        // Test 1: Basic cancellation behavior
        {
            let cell_clone = cell.clone();
            let handle = thread::spawn(move || {
                block_on(async {
                    let cx = Cx::for_testing();

                    // Start slow initialization in background
                    let init_cell = cell_clone.clone();
                    let _init_handle = thread::spawn(move || {
                        block_on(async {
                            thread::sleep(Duration::from_millis(100));
                            let _ = init_cell.get_or_init(|| async { 42u32 }).await;
                        });
                    });

                    // Give initializer time to start
                    thread::sleep(Duration::from_millis(10));

                    // Cancel the context
                    cx.cancel_fast(CancelKind::User);

                    // wait() should return Cancelled immediately, not hang
                    let start = Instant::now();
                    let result = cell_clone.wait(&cx).await;
                    let duration = start.elapsed();

                    (result, duration)
                })
            });

            let (result, duration) = handle.join().expect("Test thread should complete");

            // Should get cancellation error
            match result {
                Err(OnceCellError::Cancelled) => {
                    // ✅ Correct behavior
                }
                Ok(()) => {
                    panic!(
                        "❌ DEFECT: wait() returned Ok(()) on cancelled context, expected Err(Cancelled)"
                    );
                }
                Err(other) => {
                    panic!(
                        "❌ DEFECT: wait() returned unexpected error {:?}, expected Err(Cancelled)",
                        other
                    );
                }
            }

            // Should return quickly (not hang for 100ms waiting for init)
            if duration > Duration::from_millis(50) {
                panic!(
                    "❌ DEFECT: wait() took {:?} to return on cancelled context, expected immediate return",
                    duration
                );
            }
        }

        // Test 2: wait() succeeds when cell is already initialized
        {
            let initialized_cell = OnceCell::with_value(99u32);
            block_on(async {
                let cx = Cx::for_testing();
                cx.cancel_fast(CancelKind::User); // Even with cancelled context

                let result = initialized_cell.wait(&cx).await;
                match result {
                    Ok(()) => {
                        // ✅ Correct - should succeed immediately for initialized cell
                    }
                    Err(e) => {
                        panic!("❌ DEFECT: wait() failed on initialized cell: {:?}", e);
                    }
                }
            });
        }

        // Test 3: Stress test - multiple waiters with cancellation
        {
            let stress_cell = Arc::new(OnceCell::<u32>::new());
            let iterations = 20;
            let mut handles = Vec::new();

            for i in 0..iterations {
                let stress_cell_clone = stress_cell.clone();
                let handle = thread::spawn(move || {
                    block_on(async {
                        let cx = Cx::for_testing();

                        // Cancel half the contexts
                        if i % 2 == 0 {
                            cx.cancel_fast(CancelKind::User);
                        }

                        let start = Instant::now();
                        let result = stress_cell_clone.wait(&cx).await;
                        let duration = start.elapsed();

                        (i, result, duration)
                    })
                });
                handles.push(handle);
            }

            // Initialize after starting waiters
            thread::sleep(Duration::from_millis(10));
            let _ = stress_cell.set(123);

            // Collect results
            let mut cancelled_count = 0;
            let mut success_count = 0;

            for handle in handles {
                let (waiter_id, result, duration) = handle.join().expect("Waiter should complete");

                if waiter_id % 2 == 0 {
                    // Should be cancelled
                    match result {
                        Err(OnceCellError::Cancelled) => {
                            cancelled_count += 1;
                            if duration > Duration::from_millis(30) {
                                panic!(
                                    "❌ DEFECT: Cancelled waiter {} took {:?}, expected quick return",
                                    waiter_id, duration
                                );
                            }
                        }
                        other => {
                            panic!(
                                "❌ DEFECT: Waiter {} with cancelled context got {:?}, expected Err(Cancelled)",
                                waiter_id, other
                            );
                        }
                    }
                } else {
                    // Should succeed
                    match result {
                        Ok(()) => {
                            success_count += 1;
                        }
                        Err(e) => {
                            panic!(
                                "❌ DEFECT: Non-cancelled waiter {} failed: {:?}",
                                waiter_id, e
                            );
                        }
                    }
                }
            }

            if cancelled_count != iterations / 2 || success_count != iterations / 2 {
                panic!(
                    "❌ DEFECT: Expected {} cancelled and {} success, got {} cancelled and {} success",
                    iterations / 2,
                    iterations / 2,
                    cancelled_count,
                    success_count
                );
            }
        }

        // OnceCell::wait() cancellation behavior verified

        crate::test_complete!("audit_once_cell_wait_cancellation_behavior");
    }

    /// Metamorphic Relation: Type Independence
    /// OnceCell behavior should be equivalent across isomorphic types.
    /// MR: f_cell<T>(transform(x)) ≡ transform(f_cell<U>(x)) for isomorphic T,U
    #[test]
    fn mr_type_independence_preserves_behavior() {
        init_test("mr_type_independence_preserves_behavior");

        // Test equivalent behavior between u32 and String representations
        let value = 42u32;
        let string_value = value.to_string();

        // Path 1: Initialize u32 cell, then transform
        let u32_cell = OnceCell::new();
        let u32_result = u32_cell.get_or_init_blocking(|| value);
        let u32_to_string = u32_result.to_string();

        // Path 2: Initialize String cell directly
        let string_cell = OnceCell::new();
        let string_result = string_cell.get_or_init_blocking(|| string_value.clone());

        // MR: Both paths should yield equivalent observable results
        assert_eq!(
            u32_to_string, *string_result,
            "Type-independent paths should yield equivalent results"
        );
        assert_eq!(
            u32_cell.is_initialized(),
            string_cell.is_initialized(),
            "Initialization state should be equivalent across types"
        );

        // Test with async paths
        let async_u32_cell = OnceCell::new();
        let async_string_cell = OnceCell::new();

        let async_u32 = block_on(async_u32_cell.get_or_init(|| async { value }));
        let async_string = block_on(async_string_cell.get_or_init(|| async { string_value }));

        assert_eq!(
            async_u32.to_string(),
            *async_string,
            "Async initialization should preserve type equivalence"
        );

        crate::test_complete!("mr_type_independence_preserves_behavior");
    }

    /// Metamorphic Relation: Observation Consistency
    /// Multiple ways of observing OnceCell state should always be consistent.
    /// MR: get().is_some() ≡ is_initialized() AND get().is_some() ≡ (get() == get())
    proptest! {
        #[test]
        fn mr_observation_consistency_across_access_methods(
            value in any::<i64>(),
            use_async in any::<bool>(),
        ) {
            let cell = OnceCell::new();

            // Initialize the cell using either sync or async method
            if use_async {
                let _ = block_on(cell.get_or_init(|| async { value }));
            } else {
                let _ = cell.get_or_init_blocking(|| value);
            }

            // MR1: get().is_some() ≡ is_initialized()
            prop_assert_eq!(cell.get().is_some(), cell.is_initialized(),
                "get() availability must match is_initialized() state");

            // MR2: Multiple get() calls must return identical results
            let first_get = cell.get();
            let second_get = cell.get();
            prop_assert_eq!(first_get, second_get,
                "Multiple get() calls must return identical results");

            // MR3: get() result must match get_or_init result (no init function called)
            let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter_clone = Arc::clone(&counter);
            let get_or_init_result = cell.get_or_init_blocking(|| {
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                value + 1 // Different value to detect if erroneously called
            });

            prop_assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0,
                "get_or_init should not call init function on initialized cell");
            prop_assert_eq!(cell.get().unwrap(), get_or_init_result,
                "get() and get_or_init() results must be identical for initialized cell");
        }
    }

    /// Metamorphic Relation: Concurrent Access Equivalence
    /// Concurrent readers should observe identical state regardless of timing.
    /// MR: concurrent_reads(cell) → all identical results
    #[test]
    fn mr_concurrent_access_equivalence() {
        init_test("mr_concurrent_access_equivalence");

        let cell = Arc::new(OnceCell::new());
        let init_value = 123u64;

        // Initialize the cell
        let _ = cell.get_or_init_blocking(|| init_value);

        // Spawn multiple concurrent readers
        let num_readers = 10;
        let barrier = Arc::new(std::sync::Barrier::new(num_readers));
        let results = Arc::new(StdMutex::new(Vec::new()));

        let handles: Vec<_> = (0..num_readers)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                let results = Arc::clone(&results);

                thread::spawn(move || {
                    // Wait for all readers to be ready
                    barrier.wait();

                    // All readers access simultaneously
                    let observed = cell.get().copied();
                    let is_init = cell.is_initialized();

                    results.lock().unwrap().push((observed, is_init));
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let results = results.lock().unwrap();

        // MR: All concurrent readers must observe identical state
        let first_result = &results[0];
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                result, first_result,
                "Reader {} observed different state than reader 0: {:?} vs {:?}",
                i, result, first_result
            );
        }

        assert_eq!(
            first_result.0,
            Some(init_value),
            "All readers should observe the initialized value"
        );
        assert!(
            first_result.1,
            "All readers should observe initialized state"
        );

        crate::test_complete!("mr_concurrent_access_equivalence");
    }

    /// Metamorphic Relation: Initialization Function Independence
    /// Different functions producing equivalent values should yield equivalent cells.
    /// MR: OnceCell.init(f) ≡ OnceCell.init(g) when f() = g()
    proptest! {
        #[allow(clippy::clone_on_copy, clippy::let_and_return)]
        #[test]
        fn mr_initialization_function_independence(value in any::<u32>()) {
            // Create equivalent functions that produce the same value.
            // The redundant-looking forms are intentional: the MR is that
            // syntactically distinct closures with the same value behavior
            // yield equivalent cells.
            let func1 = || value;
            let func2 = || { let v = value; v };
            let func3 = || value.clone();

            let cell1 = OnceCell::new();
            let cell2 = OnceCell::new();
            let cell3 = OnceCell::new();

            let result1 = cell1.get_or_init_blocking(func1);
            let result2 = cell2.get_or_init_blocking(func2);
            let result3 = cell3.get_or_init_blocking(func3);

            // MR: All cells should have equivalent observable state
            prop_assert_eq!(*result1, *result2,
                "Equivalent functions should produce equivalent cell values");
            prop_assert_eq!(*result2, *result3,
                "Equivalent functions should produce equivalent cell values");

            prop_assert_eq!(cell1.is_initialized(), cell2.is_initialized(),
                "Equivalent functions should produce equivalent initialization state");
            prop_assert_eq!(cell2.is_initialized(), cell3.is_initialized(),
                "Equivalent functions should produce equivalent initialization state");

            prop_assert_eq!(cell1.get(), cell2.get(),
                "get() results should be equivalent across equivalent init functions");
            prop_assert_eq!(cell2.get(), cell3.get(),
                "get() results should be equivalent across equivalent init functions");
        }
    }

    /// Metamorphic Relation: Clone State Preservation
    /// Cloned cells should maintain all observable properties of the original.
    /// MR: clone(cell) exhibits identical behavior to cell
    proptest! {
        #[test]
        fn mr_clone_preserves_all_observable_properties(
            value in any::<i32>(),
            init_method in 0u8..4,
        ) {
            let original = OnceCell::new();

            // Initialize using different methods
            match init_method {
                0 => { let _ = original.set(value); },
                1 => { let _ = original.get_or_init_blocking(|| value); },
                2 => { let _ = block_on(original.get_or_init(|| async { value })); },
                _ => { /* Test uninitialized case */ },
            }

            let cloned = original.clone();

            // MR: All observable properties must be preserved
            prop_assert_eq!(original.is_initialized(), cloned.is_initialized(),
                "Clone must preserve initialization state");

            prop_assert_eq!(original.get(), cloned.get(),
                "Clone must preserve value accessibility");

            if original.is_initialized() {
                prop_assert_eq!(original.get().unwrap(), cloned.get().unwrap(),
                    "Clone must preserve exact value when initialized");
            }

            // Test that both behave identically to further operations.
            // `OnceCell::clone` produces an independent cell (deep value
            // clone, see the `Clone` impl above), so for the uninitialized
            // case both `get_or_init_blocking` calls run their closure.
            // Both closures therefore produce the SAME probe value, so the
            // equality assertion below holds in both the already-initialized
            // and uninitialized branches, and `wrapping_add` keeps the
            // arithmetic safe across the full `i32` range proptest samples.
            let probe_value = value.wrapping_add(100);
            let probe_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let probe1 = Arc::clone(&probe_counter);
            let original_probe = original.get_or_init_blocking(|| {
                probe1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                probe_value
            });

            let probe2 = Arc::clone(&probe_counter);
            let cloned_probe = cloned.get_or_init_blocking(|| {
                probe2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                probe_value
            });

            prop_assert_eq!(*original_probe, *cloned_probe,
                "Clone and original should respond identically to get_or_init");

            // Initialized cases (set / blocking init / async init) leave both
            // cells already initialized, so neither closure runs (count 0).
            // The uninitialized case starts both cells empty and independent,
            // so both closures run (count 2). A regression where `clone`
            // started sharing inner state would surface here as count == 1.
            let expected_probe_count = if init_method == 3 { 2 } else { 0 };
            prop_assert_eq!(probe_counter.load(std::sync::atomic::Ordering::SeqCst),
                expected_probe_count,
                "Clone and original should call init functions consistently");
        }
    }
}
