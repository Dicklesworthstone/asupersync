//! Coordinated shutdown controller using sync primitives.
//!
//! Provides a centralized mechanism for initiating and propagating shutdown
//! signals throughout an application. Uses our sync primitives (Notify) to
//! coordinate without external dependencies.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::sync::Notify;

/// Internal state shared between controller and receivers.
#[derive(Debug)]
struct ShutdownState {
    /// Tracks whether shutdown has been initiated.
    initiated: AtomicBool,
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
        // Only initiate once.
        if self
            .state
            .initiated
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // Wake all waiters.
            self.state.notify.notify_waiters();
        }
    }

    /// Checks if shutdown has been initiated.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.state.initiated.load(Ordering::SeqCst)
    }

    /// Spawns a background task to listen for shutdown signals.
    ///
    /// This is a convenience method that sets up signal handling
    /// (when available) to automatically trigger shutdown.
    ///
    /// # Note
    ///
    /// In Phase 0, signal handling is not available, so this method
    /// only sets up the controller for manual shutdown calls.
    pub fn listen_for_signals(self: &Arc<Self>) {
        // Phase 0: Signal handling not available.
        // In Phase 1, this will:
        // - Register SIGTERM handler
        // - Register SIGINT/Ctrl+C handler
        // - Call self.shutdown() when signal received
        //
        // For now, this is a no-op. Applications should call
        // shutdown() manually or use their own signal handling.
    }
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
        // Check if already shut down.
        if self.is_shutting_down() {
            return;
        }

        // Wait for notification.
        self.state.notify.notified().await;
    }

    /// Checks if shutdown has been initiated.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.state.initiated.load(Ordering::SeqCst)
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
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
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
}
