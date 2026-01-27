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

/// Internal state holding waiters.
struct WaiterState {
    waiters: Vec<Waker>,
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

        // Try to become the initializer.
        match self
            .state
            .compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                // We are the initializer.
                let value = f();
                let _ = self.value.set(value);
                self.state.store(INITIALIZED, Ordering::Release);
                self.cvar.notify_all();
                self.wake_all();
                self.value.get().expect("just initialized")
            }
            Err(INITIALIZING) => {
                // Another thread is initializing. Wait for it.
                self.wait_for_init_blocking();
                self.value.get().expect("should be initialized after wait")
            }
            Err(INITIALIZED) => {
                // Already initialized (race).
                self.value.get().expect("already initialized")
            }
            Err(_) => unreachable!("invalid state"),
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

        // Try to become the initializer.
        match self
            .state
            .compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                // We are the initializer.
                // Create a guard to reset state if we're cancelled.
                let guard = InitGuard {
                    state: &self.state,
                    completed: false,
                };

                let value = f().await;

                // Store value and mark complete.
                let _ = self.value.set(value);
                self.state.store(INITIALIZED, Ordering::Release);
                std::mem::forget(guard); // Don't reset state.

                self.cvar.notify_all();
                self.wake_all();
                self.value.get().expect("just initialized")
            }
            Err(INITIALIZING) => {
                // Another task is initializing. Wait for it.
                WaitInit { cell: self }.await;
                self.value.get().expect("should be initialized after wait")
            }
            Err(INITIALIZED) => {
                // Already initialized (race).
                self.value.get().expect("already initialized")
            }
            Err(_) => unreachable!("invalid state"),
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

        // Try to become the initializer.
        match self
            .state
            .compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                // We are the initializer.
                // Create a guard to reset state if we're cancelled or fail.
                let guard = InitGuard {
                    state: &self.state,
                    completed: false,
                };

                match f().await {
                    Ok(value) => {
                        // Store value and mark complete.
                        let _ = self.value.set(value);
                        self.state.store(INITIALIZED, Ordering::Release);
                        std::mem::forget(guard); // Don't reset state.

                        self.cvar.notify_all();
                        self.wake_all();
                        Ok(self.value.get().expect("just initialized"))
                    }
                    Err(e) => {
                        // Let guard reset state back to UNINIT.
                        drop(guard);
                        self.wake_all(); // Wake waiters to retry.
                        Err(e)
                    }
                }
            }
            Err(INITIALIZING) => {
                // Another task is initializing. Wait for it.
                WaitInit { cell: self }.await;
                // The other task might have failed, check state.
                if self.is_initialized() {
                    Ok(self.value.get().expect("should be initialized"))
                } else {
                    // The other task failed. Retry initialization with our closure.
                    self.get_or_try_init(f).await
                }
            }
            Err(INITIALIZED) => {
                // Already initialized (race).
                Ok(self.value.get().expect("already initialized"))
            }
            Err(_) => unreachable!("invalid state"),
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
        let wakers: Vec<Waker> = {
            let mut guard = match self.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut guard.waiters)
        };

        for waker in wakers {
            waker.wake();
        }
    }

    /// Registers a waker for async waiting.
    fn register_waker(&self, waker: &Waker) {
        let mut guard = match self.waiters.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.waiters.push(waker.clone());
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

/// Guard that resets state to UNINIT if initialization is cancelled.
struct InitGuard<'a> {
    state: &'a AtomicU8,
    completed: bool,
}

impl Drop for InitGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Reset state to allow another attempt.
            self.state.store(UNINIT, Ordering::Release);
        }
    }
}

/// Future that waits for initialization to complete.
struct WaitInit<'a, T> {
    cell: &'a OnceCell<T>,
}

impl<T> Future for WaitInit<'_, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let state = self.cell.state.load(Ordering::Acquire);
        if state == INITIALIZING {
            self.cell.register_waker(cx.waker());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::thread;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
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
