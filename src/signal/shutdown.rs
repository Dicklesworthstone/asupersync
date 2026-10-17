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
/// ```
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

    /// Installs an opt-in SIGHUP listener thread for this controller.
    ///
    /// Spawns a dedicated OS thread on Unix blocking on SIGHUP events.
    /// Unsupported platforms return `io::ErrorKind::Unsupported`.
    /// The thread exits once the controller is dropped and a signal arrives.
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
                // Enroll before the check: a broadcast between them still wakes us.
                if std::future::Future::poll(notified.as_mut(), cx).is_ready()
                    || state.requests.load(Ordering::Acquire) > self.seen_requests
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

    /// Spawns dedicated OS threads to listen for shutdown signals.
    ///
    /// Sets up signal handling to automatically trigger shutdown upon
    /// receiving any watched OS signal (SIGINT, SIGTERM, or BREAK).
    ///
    /// # Lifecycle and Invariants
    ///
    /// - Spawns 2 OS threads on Unix, 3 on Windows (one per signal kind).
    /// - One-shot: the first signal arrival transitions the controller.
    /// - If signal registration fails, no listener thread is retained.
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
#[path = "shutdown_inline_tests.rs"]
mod tests;
