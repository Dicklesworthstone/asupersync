//! Coordinated shutdown controller using sync primitives.
//!
//! Provides a centralized mechanism for initiating and propagating shutdown
//! signals throughout an application. Uses our sync primitives (Notify) to
//! coordinate without external dependencies.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{SignalKind, signal};
use crate::sync::Notify;

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
        // Create the notification future first to avoid missing a shutdown
        // that happens between the check and registration.
        let notified = self.state.notify.notified();

        // Check if already shut down.
        if self.is_shutting_down() {
            return;
        }

        // Wait for notification.
        notified.await;
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
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::super::SignalKind;
    use super::super::signal::inject_test_signal;
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;

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
