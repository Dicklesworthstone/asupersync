//! Coordinated shutdown controller using sync primitives.
//!
//! Provides a centralized mechanism for initiating and propagating shutdown
//! signals throughout an application. Uses our sync primitives (Notify) to
//! coordinate without external dependencies.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{SignalKind, signal};
use crate::sync::Notify;
use crate::tracing_compat::{info, warn};

/// Internal state shared between controller and receivers.
#[derive(Debug)]
struct ShutdownState {
    /// Tracks whether shutdown has been initiated.
    initiated: AtomicBool,
    /// Ensures signal listeners are only installed once per controller.
    signal_listeners_started: AtomicBool,
    /// Notifier for broadcast notifications.
    notify: Notify,
}

/// Controller for coordinated graceful shutdown.
///
/// This provides a clean way to propagate shutdown signals through an application.
/// Multiple receivers can subscribe to receive shutdown notifications.
///
/// # Example
///
/// ```ignore
/// use asupersync::signal::ShutdownController;
///
/// async fn run_server() {
///     let controller = ShutdownController::new();
///     let mut receiver = controller.subscribe();
///
///     // Spawn a task that will receive the shutdown signal
///     let handle = async move {
///         receiver.wait().await;
///         println!("Shutting down...");
///     };
///
///     // Later, initiate shutdown
///     controller.shutdown();
/// }
/// ```
#[derive(Debug)]
pub struct ShutdownController {
    /// Shared state between controller and receivers.
    state: Arc<ShutdownState>,
}

/// Internal state shared between reload controller and receivers.
#[derive(Debug)]
struct ReloadState {
    /// Monotone reload request sequence.
    requests: std::sync::atomic::AtomicU64,
    /// Ensures the SIGHUP listener is installed at most once per controller.
    signal_listener_started: AtomicBool,
    /// Notifier for reload request broadcasts.
    notify: Notify,
}

/// Controller for SIGHUP-style configuration reload notifications.
///
/// Reloads are independent from shutdown. Calling [`request_reload`](Self::request_reload)
/// or receiving SIGHUP through [`listen_for_sighup`](Self::listen_for_sighup)
/// increments a monotone reload sequence and wakes subscribed receivers, but it
/// never marks a [`ShutdownController`] as shutting down.
#[derive(Debug)]
pub struct ReloadController {
    /// Shared state between controller and receivers.
    state: Arc<ReloadState>,
}

impl ReloadController {
    /// Creates a new reload controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(ReloadState {
                requests: std::sync::atomic::AtomicU64::new(0),
                signal_listener_started: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Gets a receiver for future reload notifications.
    ///
    /// The receiver starts after the current reload sequence, so it observes
    /// reloads requested after subscription rather than replaying historical
    /// requests.
    #[must_use]
    pub fn subscribe(&self) -> ReloadReceiver {
        ReloadReceiver {
            state: Arc::clone(&self.state),
            seen_requests: self.reload_count(),
        }
    }

    /// Requests a reload and returns the new reload sequence number.
    ///
    /// This wakes all receivers waiting for a reload notification. The request
    /// is event-like, not sticky: receivers created after this call start after
    /// the returned sequence.
    pub fn request_reload(&self) -> u64 {
        Self::trigger_reload_state(&self.state)
    }

    /// Returns the number of reload requests recorded by this controller.
    #[must_use]
    pub fn reload_count(&self) -> u64 {
        self.state.requests.load(Ordering::Acquire)
    }

    /// Installs an opt-in SIGHUP listener for this reload controller.
    ///
    /// The listener is Unix-only because SIGHUP has no portable Windows
    /// equivalent. Unsupported platforms return a deterministic
    /// [`io::ErrorKind::Unsupported`] error.
    ///
    /// Calling this method more than once is idempotent.
    pub fn listen_for_sighup(self: &Arc<Self>) -> io::Result<()> {
        if self
            .state
            .signal_listener_started
            .swap(true, Ordering::AcqRel)
        {
            return Ok(());
        }

        match Self::spawn_sighup_listener(Arc::downgrade(&self.state)) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.state
                    .signal_listener_started
                    .store(false, Ordering::Release);
                Err(err)
            }
        }
    }

    fn trigger_reload_state(state: &ReloadState) -> u64 {
        let sequence = state.requests.fetch_add(1, Ordering::AcqRel) + 1;
        info!(reload_sequence = sequence, "reload requested");
        state.notify.notify_waiters();
        sequence
    }

    #[cfg(unix)]
    fn spawn_sighup_listener(state: std::sync::Weak<ReloadState>) -> io::Result<()> {
        let mut stream = signal(SignalKind::hangup())?;
        std::thread::Builder::new()
            .name("asupersync-reload-sighup".to_string())
            .spawn(move || {
                while futures_lite::future::block_on(stream.recv()).is_some() {
                    let Some(state) = state.upgrade() else {
                        break;
                    };
                    Self::trigger_reload_state(&state);
                }
            })
            .map(|_| ())
    }

    #[cfg(not(unix))]
    fn spawn_sighup_listener(_state: std::sync::Weak<ReloadState>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SIGHUP reload listener is only supported on Unix",
        ))
    }
}

impl Default for ReloadController {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ReloadController {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

/// Outcome of handling one reload request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome<E> {
    /// The reload handler completed successfully.
    Completed {
        /// Reload sequence handled by the caller.
        sequence: u64,
    },
    /// The reload handler returned an error.
    Failed {
        /// Reload sequence handled by the caller.
        sequence: u64,
        /// Error returned by the handler.
        error: E,
    },
    /// Reload handling was cancelled before completion.
    Cancelled {
        /// Reload sequence that was cancelled, or `None` if shutdown won
        /// before a reload request was selected.
        sequence: Option<u64>,
    },
}

/// Receiver for reload notifications.
///
/// A receiver observes a monotone sequence of reload requests. If several
/// reloads arrive before the receiver is polled again, repeated calls to
/// [`wait`](Self::wait) drain the pending sequence numbers without losing
/// notifications.
#[derive(Debug)]
pub struct ReloadReceiver {
    /// Shared state with the controller.
    state: Arc<ReloadState>,
    /// Last reload sequence observed by this receiver.
    seen_requests: u64,
}

impl ReloadReceiver {
    /// Waits for the next reload request and returns its sequence number.
    pub async fn wait(&mut self) -> u64 {
        let state = Arc::clone(&self.state);
        loop {
            let current = state.requests.load(Ordering::Acquire);
            if current > self.seen_requests {
                self.seen_requests = self.seen_requests.saturating_add(1);
                return self.seen_requests;
            }

            let mut notified = std::pin::pin!(state.notify.notified());
            std::future::poll_fn(|cx| {
                let current = state.requests.load(Ordering::Acquire);
                if current > self.seen_requests
                    || std::future::Future::poll(notified.as_mut(), cx).is_ready()
                {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            })
            .await;
        }
    }

    /// Returns the last reload sequence this receiver has observed.
    #[must_use]
    pub fn seen_reload_count(&self) -> u64 {
        self.seen_requests
    }

    /// Waits for one reload request and runs the supplied async handler.
    ///
    /// Structured tracing records the requested sequence, successful
    /// completion, handler failure, and cancellation if the returned future is
    /// dropped while the handler is still running.
    pub async fn handle_next_reload<F, Fut, E>(&mut self, handler: F) -> ReloadOutcome<E>
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let sequence = self.wait().await;
        let mut guard = ReloadAttemptGuard::new(sequence);
        match handler(sequence).await {
            Ok(()) => {
                guard.finish();
                info!(reload_sequence = sequence, "reload completed");
                ReloadOutcome::Completed { sequence }
            }
            Err(error) => {
                guard.finish();
                warn!(reload_sequence = sequence, "reload failed");
                ReloadOutcome::Failed { sequence, error }
            }
        }
    }

    /// Waits for the next reload request unless shutdown is signalled first.
    ///
    /// Returns `Some(sequence)` when a reload request is selected and `None`
    /// when shutdown wins the race. Both underlying waits are cancel-safe, so
    /// dropping this future does not consume either notification.
    pub async fn wait_or_shutdown(&mut self, shutdown: &mut ShutdownReceiver) -> Option<u64> {
        let mut reload_wait = std::pin::pin!(self.wait());
        let mut shutdown_wait = std::pin::pin!(shutdown.wait());

        std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(sequence) = Future::poll(reload_wait.as_mut(), cx) {
                return std::task::Poll::Ready(Some(sequence));
            }

            if Future::poll(shutdown_wait.as_mut(), cx).is_ready() {
                return std::task::Poll::Ready(None);
            }

            std::task::Poll::Pending
        })
        .await
    }

    /// Waits for one reload request and runs the handler unless shutdown wins.
    ///
    /// Shutdown before a reload request returns [`ReloadOutcome::Cancelled`]
    /// with no sequence. Shutdown while a handler is running cancels that
    /// handler future, records a structured cancellation event, and returns
    /// [`ReloadOutcome::Cancelled`] for the selected sequence.
    pub async fn handle_next_reload_or_shutdown<F, Fut, E>(
        &mut self,
        shutdown: &mut ShutdownReceiver,
        handler: F,
    ) -> ReloadOutcome<E>
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let Some(sequence) = self.wait_or_shutdown(shutdown).await else {
            warn!(reload_sequence = 0_u64, "reload cancelled");
            return ReloadOutcome::Cancelled { sequence: None };
        };

        let mut guard = ReloadAttemptGuard::new(sequence);
        let mut handler = std::pin::pin!(handler(sequence));
        let mut shutdown_wait = std::pin::pin!(shutdown.wait());

        match std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(result) = Future::poll(handler.as_mut(), cx) {
                return std::task::Poll::Ready(Some(result));
            }

            if Future::poll(shutdown_wait.as_mut(), cx).is_ready() {
                return std::task::Poll::Ready(None);
            }

            std::task::Poll::Pending
        })
        .await
        {
            Some(Ok(())) => {
                guard.finish();
                info!(reload_sequence = sequence, "reload completed");
                ReloadOutcome::Completed { sequence }
            }
            Some(Err(error)) => {
                guard.finish();
                warn!(reload_sequence = sequence, "reload failed");
                ReloadOutcome::Failed { sequence, error }
            }
            None => {
                guard.finish();
                warn!(reload_sequence = sequence, "reload cancelled");
                ReloadOutcome::Cancelled {
                    sequence: Some(sequence),
                }
            }
        }
    }
}

impl Clone for ReloadReceiver {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            seen_requests: self.seen_requests,
        }
    }
}

#[derive(Debug)]
struct ReloadAttemptGuard {
    sequence: u64,
    finished: bool,
}

impl ReloadAttemptGuard {
    fn new(sequence: u64) -> Self {
        Self {
            sequence,
            finished: false,
        }
    }

    fn finish(&mut self) {
        self.finished = true;
    }
}

impl Drop for ReloadAttemptGuard {
    fn drop(&mut self) {
        if !self.finished && self.sequence > 0 {
            warn!(reload_sequence = self.sequence, "reload cancelled");
        }
    }
}

impl ShutdownController {
    /// Creates a new shutdown controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(ShutdownState {
                initiated: AtomicBool::new(false),
                signal_listeners_started: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Gets a handle for receiving shutdown notifications.
    ///
    /// Multiple receivers can be created and they will all be notified
    /// when shutdown is initiated.
    #[must_use]
    pub fn subscribe(&self) -> ShutdownReceiver {
        ShutdownReceiver {
            state: Arc::clone(&self.state),
        }
    }

    /// Initiates shutdown.
    ///
    /// This wakes all receivers that are currently waiting for shutdown.
    /// The shutdown state is persistent - once initiated, it cannot be reset.
    pub fn shutdown(&self) {
        Self::trigger_shutdown_state(&self.state);
    }

    /// Checks if shutdown has been initiated.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.state.initiated.load(Ordering::Acquire)
    }

    /// Spawns a background task to listen for shutdown signals.
    ///
    /// This is a convenience method that sets up signal handling
    /// (when available) to automatically trigger shutdown.
    ///
    /// # Note
    ///
    /// The listeners are installed at most once per controller. When a watched
    /// signal arrives, the controller transitions to shutdown just as if
    /// [`ShutdownController::shutdown`] had been called manually.
    pub fn listen_for_signals(self: &Arc<Self>) {
        if self
            .state
            .signal_listeners_started
            .swap(true, Ordering::AcqRel)
        {
            return;
        }

        let state = Arc::downgrade(&self.state);
        let mut installed = false;

        for kind in watched_signal_kinds() {
            if Self::spawn_signal_listener(state.clone(), kind).is_ok() {
                installed = true;
            }
        }

        if !installed {
            self.state
                .signal_listeners_started
                .store(false, Ordering::Release);
        }
    }

    fn trigger_shutdown_state(state: &ShutdownState) {
        if state
            .initiated
            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            state.notify.notify_waiters();
        }
    }

    fn spawn_signal_listener(
        state: std::sync::Weak<ShutdownState>,
        kind: SignalKind,
    ) -> std::io::Result<()> {
        let mut stream = signal(kind)?;
        std::thread::Builder::new()
            .name(format!(
                "asupersync-shutdown-{}",
                kind.name().to_ascii_lowercase()
            ))
            .spawn(move || {
                if futures_lite::future::block_on(stream.recv()).is_some()
                    && let Some(state) = state.upgrade()
                {
                    Self::trigger_shutdown_state(&state);
                }
            })
            .map(|_| ())
    }
}

#[cfg(unix)]
fn watched_signal_kinds() -> [SignalKind; 2] {
    [SignalKind::interrupt(), SignalKind::terminate()]
}

#[cfg(windows)]
fn watched_signal_kinds() -> [SignalKind; 3] {
    [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::quit(),
    ]
}

#[cfg(not(any(unix, windows)))]
fn watched_signal_kinds() -> [SignalKind; 0] {
    []
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ShutdownController {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

/// Receiver for shutdown notifications.
///
/// This is a handle that can wait for shutdown to be initiated.
/// Multiple receivers can be created from a single controller.
#[derive(Debug)]
pub struct ShutdownReceiver {
    /// Shared state with the controller.
    state: Arc<ShutdownState>,
}

impl ShutdownReceiver {
    /// Waits for shutdown to be initiated.
    ///
    /// This method returns immediately if shutdown has already been initiated.
    /// Otherwise, it waits until the controller's `shutdown()` method is called.
    pub async fn wait(&mut self) {
        let state = Arc::clone(&self.state);
        loop {
            if state.initiated.load(Ordering::Acquire) {
                return;
            }

            let mut notified = std::pin::pin!(state.notify.notified());
            std::future::poll_fn(|cx| {
                if std::future::Future::poll(notified.as_mut(), cx).is_ready()
                    || state.initiated.load(Ordering::Acquire)
                {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            })
            .await;

            if state.initiated.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// Checks if shutdown has been initiated.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.state.initiated.load(Ordering::Acquire)
    }
}

impl Clone for ShutdownReceiver {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
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
    use super::super::SignalKind;
    use super::super::signal::inject_test_signal;
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;
    #[cfg(unix)]
    use std::time::Instant;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F: std::future::Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        std::pin::Pin::new(fut).poll(&mut cx)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(unix)]
    fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        condition()
    }

    #[test]
    fn shutdown_controller_initial_state() {
        init_test("shutdown_controller_initial_state");
        let controller = ShutdownController::new();
        let shutting_down = controller.is_shutting_down();
        crate::assert_with_log!(
            !shutting_down,
            "controller not shutting down",
            false,
            shutting_down
        );

        let receiver = controller.subscribe();
        let rx_shutdown = receiver.is_shutting_down();
        crate::assert_with_log!(
            !rx_shutdown,
            "receiver not shutting down",
            false,
            rx_shutdown
        );
        crate::test_complete!("shutdown_controller_initial_state");
    }

    #[test]
    fn shutdown_controller_initiates() {
        init_test("shutdown_controller_initiates");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        controller.shutdown();

        let ctrl_shutdown = controller.is_shutting_down();
        crate::assert_with_log!(
            ctrl_shutdown,
            "controller shutting down",
            true,
            ctrl_shutdown
        );
        let rx_shutdown = receiver.is_shutting_down();
        crate::assert_with_log!(rx_shutdown, "receiver shutting down", true, rx_shutdown);
        crate::test_complete!("shutdown_controller_initiates");
    }

    #[test]
    fn shutdown_only_once() {
        init_test("shutdown_only_once");
        let controller = ShutdownController::new();

        // Multiple shutdown calls should be idempotent.
        controller.shutdown();
        controller.shutdown();
        controller.shutdown();

        let shutting_down = controller.is_shutting_down();
        crate::assert_with_log!(shutting_down, "shutting down", true, shutting_down);
        crate::test_complete!("shutdown_only_once");
    }

    #[test]
    fn multiple_receivers() {
        init_test("multiple_receivers");
        let controller = ShutdownController::new();
        let rx1 = controller.subscribe();
        let rx2 = controller.subscribe();
        let rx3 = controller.subscribe();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(!rx1_shutdown, "rx1 not shutting down", false, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(!rx2_shutdown, "rx2 not shutting down", false, rx2_shutdown);
        let rx3_shutdown = rx3.is_shutting_down();
        crate::assert_with_log!(!rx3_shutdown, "rx3 not shutting down", false, rx3_shutdown);

        controller.shutdown();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(rx1_shutdown, "rx1 shutting down", true, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(rx2_shutdown, "rx2 shutting down", true, rx2_shutdown);
        let rx3_shutdown = rx3.is_shutting_down();
        crate::assert_with_log!(rx3_shutdown, "rx3 shutting down", true, rx3_shutdown);
        crate::test_complete!("multiple_receivers");
    }

    #[test]
    fn receiver_wait_after_shutdown() {
        init_test("receiver_wait_after_shutdown");
        let controller = ShutdownController::new();
        let mut receiver = controller.subscribe();

        controller.shutdown();

        // Wait should return immediately.
        let mut fut = Box::pin(receiver.wait());
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "wait ready", true, ready);
        crate::test_complete!("receiver_wait_after_shutdown");
    }

    #[test]
    fn receiver_wait_before_shutdown() {
        init_test("receiver_wait_before_shutdown");
        let controller = Arc::new(ShutdownController::new());
        let controller2 = Arc::clone(&controller);
        let mut receiver = controller.subscribe();

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            controller2.shutdown();
        });

        // First poll should be pending.
        let mut fut = Box::pin(receiver.wait());
        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(pending, "wait pending", true, pending);

        // Wait for shutdown.
        handle.join().expect("thread panicked");

        // Now should be ready.
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "wait ready", true, ready);
        crate::test_complete!("receiver_wait_before_shutdown");
    }

    #[test]
    fn receiver_clone() {
        init_test("receiver_clone");
        let controller = ShutdownController::new();
        let rx1 = controller.subscribe();
        let rx2 = rx1.clone();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(!rx1_shutdown, "rx1 not shutting down", false, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(!rx2_shutdown, "rx2 not shutting down", false, rx2_shutdown);

        controller.shutdown();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(rx1_shutdown, "rx1 shutting down", true, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(rx2_shutdown, "rx2 shutting down", true, rx2_shutdown);
        crate::test_complete!("receiver_clone");
    }

    #[test]
    fn receiver_clone_preserves_state() {
        init_test("receiver_clone_preserves_state");
        let controller = ShutdownController::new();
        controller.shutdown();

        let rx1 = controller.subscribe();
        let rx2 = rx1.clone();

        // Both should see shutdown already initiated.
        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(rx1_shutdown, "rx1 shutting down", true, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(rx2_shutdown, "rx2 shutting down", true, rx2_shutdown);
        crate::test_complete!("receiver_clone_preserves_state");
    }

    #[test]
    fn controller_clone() {
        init_test("controller_clone");
        let controller1 = ShutdownController::new();
        let controller2 = controller1.clone();
        let receiver = controller1.subscribe();

        // Shutdown via clone.
        controller2.shutdown();

        // All should see it.
        let ctrl1 = controller1.is_shutting_down();
        crate::assert_with_log!(ctrl1, "controller1 shutting down", true, ctrl1);
        let ctrl2 = controller2.is_shutting_down();
        crate::assert_with_log!(ctrl2, "controller2 shutting down", true, ctrl2);
        let rx_shutdown = receiver.is_shutting_down();
        crate::assert_with_log!(rx_shutdown, "receiver shutting down", true, rx_shutdown);
        crate::test_complete!("controller_clone");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn listen_for_signals_triggers_shutdown() {
        init_test("listen_for_signals_triggers_shutdown");
        let controller = Arc::new(ShutdownController::new());
        let mut receiver = controller.subscribe();

        controller.listen_for_signals();
        inject_test_signal(SignalKind::terminate()).expect("test signal injection");

        let mut fut = Box::pin(receiver.wait());
        for _ in 0..50 {
            if poll_once(&mut fut).is_ready() {
                let shutting_down = controller.is_shutting_down();
                crate::assert_with_log!(
                    shutting_down,
                    "controller shutting down via signal listener",
                    true,
                    shutting_down
                );
                crate::test_complete!("listen_for_signals_triggers_shutdown");
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        crate::assert_with_log!(
            false,
            "signal listener triggered shutdown before timeout",
            true,
            false
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn listen_for_signals_is_idempotent() {
        init_test("listen_for_signals_is_idempotent");
        let controller = Arc::new(ShutdownController::new());

        controller.listen_for_signals();
        controller.listen_for_signals();

        let started = controller
            .state
            .signal_listeners_started
            .load(Ordering::Acquire);
        crate::assert_with_log!(started, "signal listeners installed once", true, started);

        controller.shutdown();
        let shutting_down = controller.is_shutting_down();
        crate::assert_with_log!(
            shutting_down,
            "manual shutdown still works",
            true,
            shutting_down
        );
        crate::test_complete!("listen_for_signals_is_idempotent");
    }

    #[test]
    fn reload_controller_request_wakes_receiver_without_shutdown() {
        init_test("reload_controller_request_wakes_receiver_without_shutdown");
        let reload = ReloadController::new();
        let shutdown = ShutdownController::new();
        let mut reload_rx = reload.subscribe();
        let shutdown_rx = shutdown.subscribe();

        let sequence = reload.request_reload();
        crate::assert_with_log!(sequence == 1, "reload sequence", 1, sequence);

        let mut fut = Box::pin(reload_rx.wait());
        let observed = futures_lite::future::block_on(fut.as_mut());
        crate::assert_with_log!(observed == 1, "receiver observed sequence", 1, observed);
        crate::assert_with_log!(
            !shutdown.is_shutting_down(),
            "reload does not trigger shutdown controller",
            false,
            shutdown.is_shutting_down()
        );
        crate::assert_with_log!(
            !shutdown_rx.is_shutting_down(),
            "reload does not trigger shutdown receiver",
            false,
            shutdown_rx.is_shutting_down()
        );
        crate::test_complete!("reload_controller_request_wakes_receiver_without_shutdown");
    }

    #[test]
    fn reload_receiver_drains_queued_sequences() {
        init_test("reload_receiver_drains_queued_sequences");
        let reload = ReloadController::new();
        let mut receiver = reload.subscribe();

        reload.request_reload();
        reload.request_reload();

        let first = futures_lite::future::block_on(receiver.wait());
        let second = futures_lite::future::block_on(receiver.wait());
        crate::assert_with_log!(first == 1, "first reload sequence", 1, first);
        crate::assert_with_log!(second == 2, "second reload sequence", 2, second);
        crate::assert_with_log!(
            receiver.seen_reload_count() == 2,
            "receiver seen sequence",
            2,
            receiver.seen_reload_count()
        );
        crate::test_complete!("reload_receiver_drains_queued_sequences");
    }

    #[test]
    fn reload_receiver_invokes_handler_and_reports_outcome() {
        init_test("reload_receiver_invokes_handler_and_reports_outcome");
        let reload = ReloadController::new();
        let mut receiver = reload.subscribe();

        reload.request_reload();
        let completed =
            futures_lite::future::block_on(receiver.handle_next_reload(|sequence| async move {
                crate::assert_with_log!(sequence == 1, "handler sequence", 1, sequence);
                Ok::<(), &'static str>(())
            }));
        crate::assert_with_log!(
            completed == ReloadOutcome::Completed { sequence: 1 },
            "handler completed",
            ReloadOutcome::<&'static str>::Completed { sequence: 1 },
            completed
        );

        reload.request_reload();
        let failed =
            futures_lite::future::block_on(receiver.handle_next_reload(|_sequence| async {
                Err::<(), &'static str>("reload failed")
            }));
        crate::assert_with_log!(
            failed
                == ReloadOutcome::Failed {
                    sequence: 2,
                    error: "reload failed"
                },
            "handler failed",
            ReloadOutcome::Failed {
                sequence: 2,
                error: "reload failed"
            },
            failed
        );
        crate::test_complete!("reload_receiver_invokes_handler_and_reports_outcome");
    }

    #[test]
    fn reload_wait_or_shutdown_returns_none_when_shutdown_wins() {
        init_test("reload_wait_or_shutdown_returns_none_when_shutdown_wins");
        let reload = ReloadController::new();
        let shutdown = ShutdownController::new();
        let mut reload_rx = reload.subscribe();
        let mut shutdown_rx = shutdown.subscribe();

        shutdown.shutdown();

        let observed = futures_lite::future::block_on(reload_rx.wait_or_shutdown(&mut shutdown_rx));
        crate::assert_with_log!(
            observed.is_none(),
            "shutdown wins before reload request",
            None::<u64>,
            observed
        );
        crate::assert_with_log!(
            reload_rx.seen_reload_count() == 0,
            "no reload sequence consumed",
            0,
            reload_rx.seen_reload_count()
        );
        crate::test_complete!("reload_wait_or_shutdown_returns_none_when_shutdown_wins");
    }

    #[test]
    fn reload_handler_reports_cancelled_when_shutdown_wins() {
        init_test("reload_handler_reports_cancelled_when_shutdown_wins");
        let reload = ReloadController::new();
        let shutdown = ShutdownController::new();
        let mut reload_rx = reload.subscribe();
        let mut shutdown_rx = shutdown.subscribe();

        reload.request_reload();
        shutdown.shutdown();

        let outcome = futures_lite::future::block_on(reload_rx.handle_next_reload_or_shutdown(
            &mut shutdown_rx,
            |sequence| {
                crate::assert_with_log!(sequence == 1, "handler sequence", 1, sequence);
                std::future::pending::<Result<(), &'static str>>()
            },
        ));
        crate::assert_with_log!(
            outcome == ReloadOutcome::<&'static str>::Cancelled { sequence: Some(1) },
            "shutdown cancels pending reload handler",
            ReloadOutcome::<&'static str>::Cancelled { sequence: Some(1) },
            outcome
        );
        crate::test_complete!("reload_handler_reports_cancelled_when_shutdown_wins");
    }

    #[cfg(unix)]
    #[test]
    fn sighup_triggers_reload_only_and_sigterm_triggers_shutdown() {
        init_test("sighup_triggers_reload_only_and_sigterm_triggers_shutdown");
        let reload = Arc::new(ReloadController::new());
        let shutdown = Arc::new(ShutdownController::new());
        let mut reload_rx = reload.subscribe();
        let mut shutdown_rx = shutdown.subscribe();

        let listener_installed = reload.listen_for_sighup().is_ok();
        crate::assert_with_log!(
            listener_installed,
            "install SIGHUP listener",
            true,
            listener_installed
        );
        if !listener_installed {
            return;
        }
        let shutdown_watches_sighup = watched_signal_kinds().contains(&SignalKind::hangup());
        crate::assert_with_log!(
            !shutdown_watches_sighup,
            "shutdown listener excludes SIGHUP",
            false,
            shutdown_watches_sighup
        );

        let sighup_injected = inject_test_signal(SignalKind::hangup()).is_ok();
        crate::assert_with_log!(sighup_injected, "inject SIGHUP", true, sighup_injected);
        if !sighup_injected {
            return;
        }
        if !wait_until(|| reload.reload_count() > 0) {
            crate::assert_with_log!(false, "SIGHUP triggered reload before timeout", true, false);
            return;
        }

        let mut reload_fut = Box::pin(reload_rx.wait());
        let reload_sequence = match poll_once(&mut reload_fut) {
            Poll::Ready(sequence) => sequence,
            Poll::Pending => {
                crate::assert_with_log!(
                    false,
                    "SIGHUP triggered reload before timeout",
                    true,
                    false
                );
                return;
            }
        };
        crate::assert_with_log!(
            reload_sequence == 1,
            "SIGHUP triggers reload sequence",
            1,
            reload_sequence
        );
        crate::assert_with_log!(
            !shutdown.is_shutting_down(),
            "SIGHUP does not trigger shutdown",
            false,
            shutdown.is_shutting_down()
        );

        shutdown.listen_for_signals();
        let sigterm_injected = inject_test_signal(SignalKind::terminate()).is_ok();
        crate::assert_with_log!(sigterm_injected, "inject SIGTERM", true, sigterm_injected);
        if !sigterm_injected {
            return;
        }
        let mut fut = Box::pin(shutdown_rx.wait());
        if wait_until(|| poll_once(&mut fut).is_ready()) {
            crate::assert_with_log!(
                shutdown.is_shutting_down(),
                "SIGTERM triggers shutdown",
                true,
                shutdown.is_shutting_down()
            );
            crate::test_complete!("sighup_triggers_reload_only_and_sigterm_triggers_shutdown");
            return;
        }

        crate::assert_with_log!(
            false,
            "SIGTERM triggered shutdown before timeout",
            true,
            false
        );
    }

    #[test]
    fn shutdown_sequence_snapshot_scrubbed() {
        let controller = ShutdownController::new();
        let rx_a = controller.subscribe();
        let rx_b = controller.subscribe();

        let before = json!({
            "controller": controller.is_shutting_down(),
            "receivers": [
                {"receiver": "[RX_A]", "shutting_down": rx_a.is_shutting_down()},
                {"receiver": "[RX_B]", "shutting_down": rx_b.is_shutting_down()},
            ],
        });

        controller.shutdown();

        insta::assert_json_snapshot!(
            "shutdown_sequence_scrubbed",
            json!({
                "before": before,
                "after": {
                    "controller": controller.is_shutting_down(),
                    "receivers": [
                        {"receiver": "[RX_A]", "shutting_down": rx_a.is_shutting_down()},
                        {"receiver": "[RX_B]", "shutting_down": rx_b.is_shutting_down()},
                    ],
                }
            })
        );
    }
}
