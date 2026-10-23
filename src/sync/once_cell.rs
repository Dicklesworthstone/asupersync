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

use crate::cx::CancelWakerToken;

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
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnceCellTestHookPoint {
    BeforeWaiterRegistration,
    AfterTelemetryStateLoad,
}

#[cfg(test)]
struct OnceCellTestHook {
    target_cell: usize,
    point: OnceCellTestHookPoint,
    entered_tx: std::sync::mpsc::Sender<bool>,
    release_rx: StdMutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl OnceCellTestHook {
    fn run(&self, cell_addr: usize, point: OnceCellTestHookPoint, waiters_lock_held: bool) {
        if self.target_cell != cell_addr || self.point != point {
            return;
        }
        self.entered_tx
            .send(waiters_lock_held)
            .expect("OnceCell test hook should report entry");
        self.release_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv()
            .expect("OnceCell test hook should be released");
    }
}

#[cfg(test)]
static ONCE_CELL_TEST_HOOK: OnceLock<StdMutex<Option<std::sync::Arc<OnceCellTestHook>>>> =
    OnceLock::new();

#[cfg(test)]
fn run_once_cell_test_hook(
    cell_addr: usize,
    point: OnceCellTestHookPoint,
    waiters_lock_held: bool,
) {
    let hook = ONCE_CELL_TEST_HOOK
        .get_or_init(|| StdMutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(hook) = hook {
        hook.run(cell_addr, point, waiters_lock_held);
    }
}

#[cfg(test)]
struct BlockingWaitHook {
    target_cell: usize,
    entered_tx: std::sync::mpsc::Sender<()>,
    release_rx: StdMutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl BlockingWaitHook {
    fn run(&self, cell_addr: usize) {
        if self.target_cell != cell_addr {
            return;
        }
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
fn run_blocking_wait_hook(cell_addr: usize) {
    let hook = BLOCKING_WAIT_HOOK
        .get_or_init(|| StdMutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(hook) = hook {
        hook.run(cell_addr);
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
        let waiters = match self.waiters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state_value = self.state.load(Ordering::Acquire);
        #[cfg(test)]
        run_once_cell_test_hook(
            std::ptr::from_ref(self).cast::<()>() as usize,
            OnceCellTestHookPoint::AfterTelemetryStateLoad,
            self.waiters.try_lock().is_err(),
        );
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
    /// Returns `Err(value)` if the cell is already initialized.
    ///
    /// If another thread/task is currently initializing the cell, this method
    /// waits until that attempt completes or cancels. A completed initializer
    /// causes `set` to return `Err(value)`; a cancelled initializer leaves the
    /// cell uninitialized, so `set` retries and can become the initializer.
    ///
    /// # Blocking — do not call from async context that shares a thread with the initializer
    ///
    /// This is a **synchronous, blocking** method: while another initialization
    /// is in flight it parks the calling OS thread on a condvar until that
    /// initializer finishes. If the in-flight initializer is an **async** task
    /// (`get_or_init(async { ... }).await` suspended mid-`await`) running on the
    /// **same** OS thread as this `set` call — always the case on a
    /// current-thread runtime — the condvar wait blocks the only thread that
    /// could ever resume that initializer, and **both deadlock permanently**.
    ///
    /// From async code, initialize with [`get_or_init`](Self::get_or_init)
    /// (which yields rather than blocks) instead of `set`, or only call `set`
    /// before any async initializer can be in flight.
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
                Err(INITIALIZED) => return Err(value),
                Err(INITIALIZING) => {
                    self.wait_for_init_blocking();
                    if self.is_initialized() {
                        return Err(value);
                    }
                }
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
    ///
    /// # Blocking — do not call from async context that shares a thread with the initializer
    ///
    /// This has the same hazard as [`set`](Self::set). While another
    /// initialization is in flight, it parks the calling OS thread on a condvar
    /// until that initializer finishes. If the in-flight initializer is an
    /// **async** task (`get_or_init(async { ... }).await` suspended
    /// mid-`await`) running on the **same** OS thread as this call — always the
    /// case on a current-thread runtime — the condvar wait blocks the only
    /// thread that could ever resume that initializer, and **both deadlock
    /// permanently**.
    ///
    /// From async code, use [`get_or_init`](Self::get_or_init), which yields
    /// rather than blocks.
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

    /// Gets the value, initializing it if necessary, and stops waiting when
    /// `cx` is cancelled.
    ///
    /// This is [`get_or_init`](Self::get_or_init) for callers that must
    /// honor cancellation. While another task's initializer is in flight,
    /// `get_or_init` stays parked until that initializer finishes, however
    /// long it takes, so a cancelled region cannot drain. This method returns
    /// `Err(OnceCellError::Cancelled)` as soon as `cx` is cancelled instead.
    ///
    /// A caller that is already cancelled when it would start initializing
    /// returns the same error without calling `f`. A caller that becomes the
    /// initializer runs `f` as `get_or_init` does; `f` observes `cx` itself.
    /// If another initializer is cancelled, this caller retries and may
    /// become the initializer.
    ///
    /// # Errors
    ///
    /// Returns `Err(OnceCellError::Cancelled)` if `cx` is cancelled before a
    /// value is available.
    #[inline]
    #[allow(clippy::future_not_send)]
    pub async fn get_or_init_cx<Caps, F, Fut>(
        &self,
        cx: &crate::cx::Cx<Caps>,
        f: F,
    ) -> Result<&T, OnceCellError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        if self.is_initialized() {
            return Ok(self.value.get().expect("value should be set"));
        }

        let mut init_fn = Some(f);

        loop {
            if cx.checkpoint().is_err() {
                return Err(OnceCellError::Cancelled);
            }
            match self.state.compare_exchange_weak(
                UNINIT,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let f = init_fn.take().expect("init closure available");
                    let mut guard = InitGuard {
                        cell: self,
                        completed: false,
                    };

                    let value = f().await;

                    let _ = self.value.set(value);
                    guard.completed = true;
                    drop(guard);
                    self.transition_out_of_initializing(INITIALIZED);
                    return Ok(self.value.get().expect("just initialized"));
                }
                Err(INITIALIZED) => {
                    return Ok(self.value.get().expect("already initialized"));
                }
                Err(UNINIT) => {} // Spurious failure, try again
                Err(_) => {
                    CancelAwareWaitInit {
                        cell: self,
                        cx,
                        waiter_id: None,
                        cancel_waker: None,
                        settle_when_uninit: true,
                    }
                    .await?;
                    if self.is_initialized() {
                        return Ok(self.value.get().expect("should be initialized after wait"));
                    }
                    // The initializer was cancelled. Retry the CAS.
                }
            }
        }
    }

    /// Gets the value with a fallible initializer, stopping the wait when
    /// `cx` is cancelled.
    ///
    /// This combines the retry semantics of [`get_or_try_init`](Self::get_or_try_init)
    /// with the cancellation-aware waiting of [`get_or_init_cx`](Self::get_or_init_cx).
    /// The outer result reports cancellation; the inner result preserves the
    /// initializer's error type without requiring a conversion from
    /// [`OnceCellError`]:
    ///
    /// - `Ok(Ok(value))`: the cell is initialized.
    /// - `Ok(Err(error))`: this caller's initializer failed; the cell remains
    ///   uninitialized and another caller may retry.
    /// - `Err(OnceCellError::Cancelled)`: cancellation was observed before this
    ///   caller started initializing or while it waited for another initializer.
    ///
    /// A value already available on entry is returned even when `cx` is
    /// cancelled. An error from another caller's initializer is not shared:
    /// this caller retries and may run its own `f` instead.
    ///
    /// # Cancel Safety
    ///
    /// Cancelling a waiting caller removes only its own waiter; it does not
    /// cancel the initializer owned by another caller. Once this caller starts
    /// `f`, the initializer itself must observe `cx`, just as with
    /// [`get_or_init_cx`](Self::get_or_init_cx). This method does not interrupt
    /// an initializer or discard its returned value/error after cancellation.
    /// Dropping or unwinding the initialization future resets the cell and
    /// wakes other callers so they can retry.
    ///
    /// # Errors
    ///
    /// Returns an outer `Err(OnceCellError::Cancelled)` if cancellation is
    /// observed before initialization starts or while waiting. Returns
    /// `Ok(Err(error))` when this caller's initializer returns an error.
    #[inline]
    #[allow(clippy::future_not_send)]
    pub async fn get_or_try_init_cx<Caps, F, Fut, E>(
        &self,
        cx: &crate::cx::Cx<Caps>,
        f: F,
    ) -> Result<Result<&T, E>, OnceCellError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if self.is_initialized() {
            return Ok(Ok(self.value.get().expect("value should be set")));
        }

        let mut init_fn = Some(f);
        loop {
            if cx.checkpoint().is_err() {
                return Err(OnceCellError::Cancelled);
            }
            match self.state.compare_exchange_weak(
                UNINIT,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let mut guard = InitGuard {
                        cell: self,
                        completed: false,
                    };
                    let f = init_fn.take().expect("init closure available");
                    match f().await {
                        Ok(value) => {
                            let _ = self.value.set(value);
                            guard.completed = true;
                            drop(guard);
                            self.transition_out_of_initializing(INITIALIZED);
                            return Ok(Ok(self.value.get().expect("just initialized")));
                        }
                        Err(error) => {
                            drop(guard);
                            return Ok(Err(error));
                        }
                    }
                }
                Err(INITIALIZED) => {
                    return Ok(Ok(self.value.get().expect("already initialized")));
                }
                Err(INITIALIZING) => {
                    CancelAwareWaitInit {
                        cell: self,
                        cx,
                        waiter_id: None,
                        cancel_waker: None,
                        settle_when_uninit: true,
                    }
                    .await?;
                    if self.is_initialized() {
                        return Ok(Ok(self
                            .value
                            .get()
                            .expect("should be initialized after wait")));
                    }
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

    /// Waits for the cell to become initialized.
    ///
    /// Returns immediately if the cell is already initialized.
    /// If the cell is uninitialized or another task is initializing it, waits
    /// until a value is set.
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
            cancel_waker: None,
            settle_when_uninit: false,
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
            run_blocking_wait_hook(std::ptr::from_ref(self).cast::<()>() as usize);
            guard = match self.cvar.wait(guard) {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        drop(guard);
    }

    fn transition_out_of_initializing(&self, new_state: u8) {
        let waiters = {
            let mut guard = match self.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.state.store(new_state, Ordering::Release);
            std::mem::take(&mut guard.waiters)
        };
        self.cvar.notify_all();
        if waiters.is_empty() {
            return;
        }

        // The state transition and queue drain have committed. One callback
        // must not prevent later detached waiters from observing that state.
        // InitGuard also calls this while an initializer is unwinding; keep
        // that original panic authoritative instead of starting a second one.
        let already_unwinding = std::thread::panicking();
        let mut first_panic = None;
        for waiter in waiters {
            let waker = waiter.waker;
            // Retain the owner across wake_by_ref so a safe Wake callback and
            // its final-owner destructor cannot panic in the same unwind.
            let notified =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake_by_ref()));
            let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker)));
            for payload in [notified, retired].into_iter().filter_map(Result::err) {
                if !already_unwinding && first_panic.is_none() {
                    first_panic = Some(payload);
                } else {
                    // An opaque panic payload can itself panic on drop.
                    // Leak only secondary payloads to preserve fanout and
                    // the original failure, as in semaphore wake cleanup.
                    std::mem::forget(payload);
                }
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }

    /// Registers a waker for async waiting with waiter-id tracking to prevent
    /// unbounded queue growth.
    fn register_waker_while<F>(
        &self,
        waker: &Waker,
        waiter_id: &mut Option<u64>,
        should_wait: F,
    ) -> bool
    where
        F: FnOnce(u8) -> bool,
    {
        // A custom RawWaker clone may allocate or panic. Clone before locking so
        // neither clone callbacks nor unwinding can run through the waiter mutex.
        let mut incoming_waker = Some(waker.clone());
        #[cfg(test)]
        run_once_cell_test_hook(
            std::ptr::from_ref(self).cast::<()>() as usize,
            OnceCellTestHookPoint::BeforeWaiterRegistration,
            false,
        );
        let (registered, retired_waker) = {
            let mut guard = match self.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if !should_wait(self.state.load(Ordering::Acquire)) {
                *waiter_id = None;
                drop(guard);
                drop(incoming_waker);
                return false;
            }
            let mut retired_waker = None;

            if let Some(id) = *waiter_id {
                // Still queued: refresh to the latest task waker.
                if let Some(existing) = guard.waiters.iter_mut().find(|entry| entry.id == id) {
                    if !existing.waker.will_wake(waker) {
                        retired_waker = Some(std::mem::replace(
                            &mut existing.waker,
                            incoming_waker
                                .take()
                                .expect("OnceCell replacement waker must be available"),
                        ));
                    }
                } else {
                    // Dequeued while still waiting; re-register. Reserve before
                    // moving the Waker so allocation failure cannot destroy its
                    // payload while the waiter mutex is held.
                    guard.waiters.reserve(1);
                    let new_id = guard.next_waiter_id;
                    guard.waiters.push(InitWaiter {
                        waker: incoming_waker
                            .take()
                            .expect("OnceCell registration waker must be available"),
                        id: new_id,
                    });
                    guard.next_waiter_id = guard.next_waiter_id.wrapping_add(1);
                    *waiter_id = Some(new_id);
                }
            } else {
                // First time: create new waiter id.
                guard.waiters.reserve(1);
                let id = guard.next_waiter_id;
                guard.waiters.push(InitWaiter {
                    waker: incoming_waker
                        .take()
                        .expect("OnceCell registration waker must be available"),
                    id,
                });
                guard.next_waiter_id = guard.next_waiter_id.wrapping_add(1);
                *waiter_id = Some(id);
            }

            (true, retired_waker)
        };

        // Safe Wake payload destructors may re-enter this OnceCell. Both the
        // replaced Waker and an unused pre-clone must retire after unlocking.
        drop(retired_waker);
        drop(incoming_waker);
        registered
    }

    fn remove_waiter_for_cancellation(&self, waiter_id: u64) {
        let retired_waiter = {
            let mut guard = match self.waiters.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(pos) = guard.waiters.iter().position(|entry| entry.id == waiter_id) else {
                return;
            };
            let retired_waiter = guard.waiters.swap_remove(pos);
            guard.cancellation_count = guard.cancellation_count.saturating_add(1);
            retired_waiter
        };

        // Dropping a Waker can destroy arbitrary user-provided Wake state.
        // Complete queue accounting and release the mutex first.
        drop(retired_waiter);
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
            let registered =
                this.cell
                    .register_waker_while(cx.waker(), &mut this.waiter_id, |current| {
                        current == INITIALIZING
                    });
            // Double-check after registering.
            if registered && this.cell.state.load(Ordering::Acquire) == INITIALIZING {
                Poll::Pending
            } else {
                // If the transition raced after registration, it drained the
                // queue under the same mutex. A refused registration clears
                // waiter_id before returning.
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
#[derive(Debug)]
struct OnceCellCancelWaker {
    waker: Waker,
    token: CancelWakerToken,
}

struct CancelAwareWaitInit<'a, T, Caps = crate::cx::cap::All> {
    cell: &'a OnceCell<T>,
    cx: &'a crate::cx::Cx<Caps>,
    /// Tracks registered waiter identity to prevent unbounded queue growth.
    waiter_id: Option<u64>,
    /// Tracks the task waker registered with the cancellation context.
    cancel_waker: Option<OnceCellCancelWaker>,
    /// Also settle when an in-flight initializer is cancelled and the cell is
    /// uninitialized again, so the caller can retry and become the
    /// initializer. `wait` keeps waiting for a value instead.
    settle_when_uninit: bool,
}

impl<T, Caps> CancelAwareWaitInit<'_, T, Caps> {
    fn refresh_cancel_waker(&mut self, waker: &Waker) {
        let same_local_waker = self
            .cancel_waker
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        let incoming_waker = (!same_local_waker).then(|| waker.clone());
        let previous_token = self
            .cancel_waker
            .as_ref()
            .map(|registered| registered.token);
        let token = self.cx.refresh_cancel_waker(previous_token, waker);
        let retired_waker = if let Some(incoming_waker) = incoming_waker {
            self.cancel_waker.replace(OnceCellCancelWaker {
                waker: incoming_waker,
                token,
            })
        } else {
            self.cancel_waker
                .as_mut()
                .expect("same local Waker requires an existing registration")
                .token = token;
            None
        };
        drop(retired_waker);
    }

    fn clear_cancel_waker(&mut self) {
        let Some(registered) = self.cancel_waker.take() else {
            return;
        };
        self.cx.clear_cancel_waker(registered.token);
        drop(registered);
    }
}

impl<T, Caps> std::future::Future for CancelAwareWaitInit<'_, T, Caps> {
    type Output = Result<(), OnceCellError>;

    fn poll(self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let settle_when_uninit = this.settle_when_uninit;
        let settled =
            move |state: u8| state == INITIALIZED || (settle_when_uninit && state == UNINIT);

        if settled(this.cell.state.load(Ordering::Acquire)) {
            this.clear_cancel_waker();
            return Poll::Ready(Ok(()));
        }

        if this.cx.checkpoint().is_err() {
            this.clear_cancel_waker();
            return Poll::Ready(Err(OnceCellError::Cancelled));
        }

        this.refresh_cancel_waker(task_cx.waker());

        let registered =
            this.cell
                .register_waker_while(task_cx.waker(), &mut this.waiter_id, |state| {
                    !settled(state)
                });

        if !registered || settled(this.cell.state.load(Ordering::Acquire)) {
            this.clear_cancel_waker();
            return Poll::Ready(Ok(()));
        }

        if this.cx.checkpoint().is_err() {
            this.clear_cancel_waker();
            return Poll::Ready(Err(OnceCellError::Cancelled));
        }

        Poll::Pending
    }
}

impl<T, Caps> Drop for CancelAwareWaitInit<'_, T, Caps> {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            // Remove canceled waiter registrations immediately
            self.cell.remove_waiter_for_cancellation(waiter_id);
        }
        self.clear_cancel_waker();
    }
}

#[cfg(test)]
#[path = "once_cell_inline_tests.rs"]
mod tests;
