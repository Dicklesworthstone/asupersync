//! Shutdown coordination for HTTP server lifecycle.
//!
//! This module provides [`ShutdownSignal`] for coordinating graceful server shutdown
//! with drain timeouts and phase tracking. It builds on the lower-level
//! [`ShutdownController`] by adding drain-phase
//! awareness and timeout semantics.

use crate::cx::Cx;
use crate::signal::{ShutdownController, ShutdownReceiver};
use crate::sync::Notify;
use crate::time::{Sleep, TimerDriverHandle, sleep_until, wall_now};
use crate::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(test)]
thread_local! {
    static TRIGGER_IMMEDIATE_PRE_PHASE_HOOK:
        std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_trigger_immediate_pre_phase_hook() {
    TRIGGER_IMMEDIATE_PRE_PHASE_HOOK.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_trigger_immediate_pre_phase_hook() {}

#[derive(Clone)]
enum ShutdownTimeSource {
    WallClock,
    TimerDriver(TimerDriverHandle),
    Custom(fn() -> Time),
}

impl ShutdownTimeSource {
    fn capture_from_current() -> Self {
        Cx::current()
            .and_then(|cx| cx.timer_driver())
            .map_or(Self::WallClock, Self::TimerDriver)
    }

    fn now(&self) -> Time {
        match self {
            Self::WallClock => wall_now(),
            Self::TimerDriver(driver) => driver.now(),
            Self::Custom(time_getter) => time_getter(),
        }
    }
}

/// Phases of a graceful server shutdown.
///
/// Shutdown proceeds through these phases in order:
/// 1. [`Running`](ShutdownPhase::Running) — normal operation
/// 2. [`Draining`](ShutdownPhase::Draining) — stopped accepting, waiting for in-flight
/// 3. [`ForceClosing`](ShutdownPhase::ForceClosing) — drain timeout exceeded, force-closing
/// 4. [`Stopped`](ShutdownPhase::Stopped) — all connections closed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShutdownPhase {
    /// Normal operation — accepting connections and processing requests.
    Running = 0,
    /// Stopped accepting new connections; waiting for in-flight requests to complete.
    Draining = 1,
    /// Drain timeout exceeded; force-closing remaining connections.
    ForceClosing = 2,
    /// All connections closed; server fully stopped.
    Stopped = 3,
}

impl ShutdownPhase {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Running,
            1 => Self::Draining,
            2 => Self::ForceClosing,
            _ => Self::Stopped,
        }
    }
}

impl std::fmt::Display for ShutdownPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Draining => write!(f, "Draining"),
            Self::ForceClosing => write!(f, "ForceClosing"),
            Self::Stopped => write!(f, "Stopped"),
        }
    }
}

/// Statistics collected during shutdown.
#[derive(Debug, Clone)]
pub struct ShutdownStats {
    /// Number of connections that completed gracefully during drain.
    pub drained: usize,
    /// Number of connections force-closed after the drain timeout.
    pub force_closed: usize,
    /// Total shutdown duration.
    pub duration: Duration,
}

/// Internal state shared between the signal and its subscribers.
struct SignalState {
    phase: AtomicU8,
    controller: ShutdownController,
    phase_notify: Notify,
    time_source: ShutdownTimeSource,
    has_drain_deadline: AtomicBool,
    drain_deadline: AtomicU64,
    has_drain_start: AtomicBool,
    drain_start: AtomicU64,
}

/// Broadcast signal for server shutdown coordination.
///
/// `ShutdownSignal` wraps the lower-level [`ShutdownController`] with
/// shutdown-phase tracking and drain timeout awareness. Handlers can check
/// whether the server is draining to add `Connection: close` headers or
/// reject new work.
///
/// # Example
///
/// ```ignore
/// use asupersync::server::ShutdownSignal;
/// use std::time::Duration;
///
/// let signal = ShutdownSignal::new();
///
/// // In the accept loop:
/// if signal.is_draining() {
///     break; // stop accepting
/// }
///
/// // Initiate shutdown with a 30-second drain period:
/// signal.begin_drain(Duration::from_secs(30));
/// ```
#[derive(Clone)]
pub struct ShutdownSignal {
    state: Arc<SignalState>,
}

impl ShutdownSignal {
    fn duration_to_nanos(duration: Duration) -> u64 {
        duration.as_nanos().min(u128::from(u64::MAX)) as u64
    }

    /// Creates a new shutdown signal in the [`Running`](ShutdownPhase::Running) phase.
    #[must_use]
    pub fn new() -> Self {
        Self::with_time_source(ShutdownTimeSource::capture_from_current())
    }

    /// Creates a new shutdown signal with a custom time source.
    #[must_use]
    pub fn with_time_getter(time_getter: fn() -> Time) -> Self {
        Self::with_time_source(ShutdownTimeSource::Custom(time_getter))
    }

    fn with_time_source(time_source: ShutdownTimeSource) -> Self {
        Self {
            state: Arc::new(SignalState {
                phase: AtomicU8::new(ShutdownPhase::Running as u8),
                controller: ShutdownController::new(),
                phase_notify: Notify::new(),
                time_source,
                has_drain_deadline: AtomicBool::new(false),
                drain_deadline: AtomicU64::new(0),
                has_drain_start: AtomicBool::new(false),
                drain_start: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn current_time(&self) -> Time {
        self.state.time_source.now()
    }

    pub(crate) async fn wait_until(&self, deadline: Time) {
        match &self.state.time_source {
            ShutdownTimeSource::TimerDriver(driver) => {
                Sleep::with_timer_driver(deadline, driver.clone()).await;
            }
            ShutdownTimeSource::Custom(time_getter) => {
                Sleep::with_time_getter(deadline, *time_getter).await;
            }
            ShutdownTimeSource::WallClock => {
                sleep_until(deadline).await;
            }
        }
    }

    /// Returns the current shutdown phase.
    #[must_use]
    pub fn phase(&self) -> ShutdownPhase {
        ShutdownPhase::from_u8(self.state.phase.load(Ordering::Acquire))
    }

    /// Returns `true` if the server is in the draining phase.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.phase() == ShutdownPhase::Draining
    }

    /// Returns `true` if shutdown has been initiated (draining or later).
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.phase() != ShutdownPhase::Running
    }

    /// Returns `true` if the server has fully stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.phase() == ShutdownPhase::Stopped
    }

    /// Returns the drain deadline, if one has been set.
    #[must_use]
    pub fn drain_deadline(&self) -> Option<Time> {
        self.state
            .has_drain_deadline
            .load(Ordering::Acquire)
            .then(|| Time::from_nanos(self.state.drain_deadline.load(Ordering::Acquire)))
    }

    /// Subscribes to the underlying shutdown controller for async waiting.
    #[must_use]
    pub fn subscribe(&self) -> ShutdownReceiver {
        self.state.controller.subscribe()
    }

    /// Begins the drain phase with the given timeout.
    ///
    /// Transitions from `Running` to `Draining` and sets a drain deadline.
    /// The caller should stop accepting new connections after this call.
    ///
    /// Returns `false` if shutdown was already initiated.
    #[must_use]
    pub fn begin_drain(&self, timeout: Duration) -> bool {
        let result = self.state.phase.compare_exchange(
            ShutdownPhase::Running as u8,
            ShutdownPhase::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if result.is_ok() {
            let now = self.current_time();
            let deadline = now.saturating_add_nanos(Self::duration_to_nanos(timeout));
            self.state
                .drain_deadline
                .store(deadline.as_nanos(), Ordering::Release);
            self.state.has_drain_deadline.store(true, Ordering::Release);
            self.state
                .drain_start
                .store(now.as_nanos(), Ordering::Release);
            self.state.has_drain_start.store(true, Ordering::Release);
            self.state.controller.shutdown();
            self.state.phase_notify.notify_waiters();
            true
        } else {
            false
        }
    }

    /// Transitions to the force-closing phase.
    ///
    /// Called when the drain timeout has expired and remaining connections
    /// must be terminated. Returns `false` if not currently draining.
    #[must_use]
    pub fn begin_force_close(&self) -> bool {
        let result = self.state.phase.compare_exchange(
            ShutdownPhase::Draining as u8,
            ShutdownPhase::ForceClosing as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if result.is_ok() {
            self.state.phase_notify.notify_waiters();
            true
        } else {
            false
        }
    }

    /// Marks the server as fully stopped.
    ///
    /// Called when all connections have been closed.
    ///
    /// Also trips the underlying shutdown controller so subscribers blocked on
    /// [`ShutdownReceiver::wait`] wake even if the server reaches `Stopped`
    /// without first entering the drain phase.
    pub fn mark_stopped(&self) {
        self.state
            .phase
            .store(ShutdownPhase::Stopped as u8, Ordering::Release);
        self.state.controller.shutdown();
        self.state.phase_notify.notify_waiters();
    }

    /// Waits until the shutdown phase reaches or passes the target phase.
    ///
    /// This method is race-free: it guarantees that it will not miss a phase
    /// transition that occurs concurrently.
    pub async fn wait_for_phase(&self, target: ShutdownPhase) {
        loop {
            let notified = self.state.phase_notify.notified();
            if self.phase() as u8 >= target as u8 {
                return;
            }
            notified.await;
        }
    }

    /// Returns the time when drain began, if applicable.
    #[must_use]
    pub fn drain_start(&self) -> Option<Time> {
        self.state
            .has_drain_start
            .load(Ordering::Acquire)
            .then(|| Time::from_nanos(self.state.drain_start.load(Ordering::Acquire)))
    }

    /// Collects shutdown statistics.
    ///
    /// Call after `mark_stopped()` to get the final stats. The `drained` count
    /// is the number of connections that completed gracefully, and `force_closed`
    /// is the number that were force-closed after the drain timeout.
    ///
    /// # Arguments
    ///
    /// * `drained` — Number of connections that completed during drain phase.
    /// * `force_closed` — Number of connections force-closed after timeout.
    #[must_use]
    pub fn collect_stats(&self, drained: usize, force_closed: usize) -> ShutdownStats {
        let duration = self.drain_start().map_or(Duration::ZERO, |start| {
            let now = self.current_time();
            Duration::from_nanos(now.duration_since(start))
        });
        ShutdownStats {
            drained,
            force_closed,
            duration,
        }
    }

    /// Triggers an immediate stop (skips drain phase).
    ///
    /// This transitions directly to [`ShutdownPhase::ForceClosing`], records a
    /// zero-length drain deadline at the current time, and wakes drain waiters.
    /// Call [`mark_stopped`](Self::mark_stopped) once all connections have
    /// actually closed to reach the terminal [`ShutdownPhase::Stopped`] phase.
    ///
    /// Useful for hard shutdowns or test scenarios.
    pub fn trigger_immediate(&self) {
        if self.phase() == ShutdownPhase::Stopped {
            self.state.controller.shutdown();
            self.state.phase_notify.notify_waiters();
            return;
        }
        let now = self.current_time();
        run_trigger_immediate_pre_phase_hook();
        self.state
            .phase
            .fetch_max(ShutdownPhase::ForceClosing as u8, Ordering::AcqRel);
        if self.phase() == ShutdownPhase::Stopped {
            self.state.controller.shutdown();
            self.state.phase_notify.notify_waiters();
            return;
        }
        self.state
            .drain_deadline
            .store(now.as_nanos(), Ordering::Release);
        self.state.has_drain_deadline.store(true, Ordering::Release);
        if !self.state.has_drain_start.load(Ordering::Acquire) {
            self.state
                .drain_start
                .store(now.as_nanos(), Ordering::Release);
            self.state.has_drain_start.store(true, Ordering::Release);
        }
        self.state.controller.shutdown();
        self.state.phase_notify.notify_waiters();
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownSignal")
            .field("phase", &self.phase())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.store(nanos, Ordering::Relaxed);
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.load(Ordering::Relaxed))
    }

    fn set_trigger_immediate_pre_phase_hook(hook: Option<Box<dyn FnMut()>>) {
        TRIGGER_IMMEDIATE_PRE_PHASE_HOOK.with(|slot| {
            *slot.borrow_mut() = hook;
        });
    }

    struct FlagWaker(Arc<AtomicBool>);

    impl std::task::Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn initial_state_is_running() {
        init_test("initial_state_is_running");
        let signal = ShutdownSignal::new();
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "phase",
            ShutdownPhase::Running,
            signal.phase()
        );
        crate::assert_with_log!(
            !signal.is_draining(),
            "not draining",
            false,
            signal.is_draining()
        );
        crate::assert_with_log!(
            !signal.is_shutting_down(),
            "not shutting down",
            false,
            signal.is_shutting_down()
        );
        crate::assert_with_log!(
            !signal.is_stopped(),
            "not stopped",
            false,
            signal.is_stopped()
        );
        crate::test_complete!("initial_state_is_running");
    }

    #[test]
    fn begin_drain_transitions_to_draining() {
        init_test("begin_drain_transitions_to_draining");
        let signal = ShutdownSignal::new();
        let initiated = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "phase",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.is_draining(),
            "is draining",
            true,
            signal.is_draining()
        );
        crate::assert_with_log!(
            signal.is_shutting_down(),
            "is shutting down",
            true,
            signal.is_shutting_down()
        );
        let has_deadline = signal.drain_deadline().is_some();
        crate::assert_with_log!(has_deadline, "has deadline", true, has_deadline);
        crate::test_complete!("begin_drain_transitions_to_draining");
    }

    #[test]
    fn begin_drain_idempotent() {
        init_test("begin_drain_idempotent");
        let signal = ShutdownSignal::new();
        let first = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(first, "first drain", true, first);

        let second = signal.begin_drain(Duration::from_secs(60));
        crate::assert_with_log!(!second, "second drain rejected", false, second);

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "still draining",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::test_complete!("begin_drain_idempotent");
    }

    #[test]
    fn with_time_getter_controls_deadline_and_duration() {
        init_test("with_time_getter_controls_deadline_and_duration");
        set_test_time(0);
        let signal = ShutdownSignal::with_time_getter(test_time);

        let initiated = signal.begin_drain(Duration::from_nanos(25));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(0)),
            "drain start uses injected clock",
            Some(Time::from_nanos(0)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(25)),
            "deadline uses injected clock",
            Some(Time::from_nanos(25)),
            signal.drain_deadline()
        );

        set_test_time(80);
        let stats = signal.collect_stats(2, 1);
        crate::assert_with_log!(
            stats.duration == Duration::from_nanos(80),
            "duration uses injected clock",
            Duration::from_nanos(80),
            stats.duration
        );
        crate::test_complete!("with_time_getter_controls_deadline_and_duration");
    }

    #[test]
    fn new_captures_timer_driver_from_current_context() {
        init_test("new_captures_timer_driver_from_current_context");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(42)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 0),
            TaskId::new_for_test(9, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver),
            None,
        );

        let signal = {
            let _guard = Cx::set_current(Some(cx));
            ShutdownSignal::new()
        };

        let initiated = signal.begin_drain(Duration::from_secs(3));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_secs(42)),
            "captured driver sets drain start",
            Some(Time::from_secs(42)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_secs(45)),
            "captured driver sets drain deadline",
            Some(Time::from_secs(45)),
            signal.drain_deadline()
        );

        virtual_clock.advance(7_000_000_000);
        let stats = signal.collect_stats(1, 0);
        crate::assert_with_log!(
            stats.duration == Duration::from_secs(7),
            "captured driver sets stats duration",
            Duration::from_secs(7),
            stats.duration
        );
        crate::test_complete!("new_captures_timer_driver_from_current_context");
    }

    #[test]
    fn wait_until_uses_captured_timer_driver_without_ambient_context() {
        init_test("wait_until_uses_captured_timer_driver_without_ambient_context");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 1),
            TaskId::new_for_test(9, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );

        let signal = {
            let _guard = Cx::set_current(Some(cx));
            ShutdownSignal::new()
        };
        let _no_cx = Cx::set_current(None);

        let waker = std::task::Waker::noop();
        let mut task_cx = std::task::Context::from_waker(waker);
        let deadline = Time::from_secs(12);
        let mut wait = std::pin::pin!(signal.wait_until(deadline));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "wait is pending before deadline",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer_driver.pending_count() == 1,
            "captured timer driver owns registration",
            1,
            timer_driver.pending_count()
        );

        virtual_clock.advance(1_000_000_000);
        let fired_before_deadline = timer_driver.process_timers();
        crate::assert_with_log!(
            fired_before_deadline == 0,
            "timer does not fire before deadline",
            0,
            fired_before_deadline
        );

        virtual_clock.advance(1_000_000_000);
        let fired_at_deadline = timer_driver.process_timers();
        crate::assert_with_log!(
            fired_at_deadline == 1,
            "captured timer driver fires at deadline",
            1,
            fired_at_deadline
        );

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "wait becomes ready after captured timer fires",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer_driver.pending_count() == 0,
            "registration clears after completion",
            0,
            timer_driver.pending_count()
        );
        crate::test_complete!("wait_until_uses_captured_timer_driver_without_ambient_context");
    }

    #[test]
    fn wait_until_with_time_getter_wakes_after_logical_clock_advance() {
        init_test("wait_until_with_time_getter_wakes_after_logical_clock_advance");
        set_test_time(0);
        let signal = ShutdownSignal::with_time_getter(test_time);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = std::task::Waker::from(Arc::new(FlagWaker(Arc::clone(&woke))));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let deadline = Time::from_secs(10);
        let mut wait = std::pin::pin!(signal.wait_until(deadline));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "wait is pending before deadline",
            true,
            first_poll.is_pending()
        );

        set_test_time(deadline.as_nanos());
        let wait_deadline = std::time::Instant::now() + Duration::from_millis(100);
        while !woke.load(Ordering::SeqCst) && std::time::Instant::now() < wait_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }

        let woke = woke.load(Ordering::SeqCst);
        crate::assert_with_log!(woke, "wait woke after logical advance", true, woke);

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "wait becomes ready after logical deadline",
            true,
            second_poll.is_ready()
        );
        crate::test_complete!("wait_until_with_time_getter_wakes_after_logical_clock_advance");
    }

    #[test]
    fn force_close_from_draining() {
        init_test("force_close_from_draining");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);

        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "phase",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::test_complete!("force_close_from_draining");
    }

    #[test]
    fn force_close_only_from_draining() {
        init_test("force_close_only_from_draining");
        let signal = ShutdownSignal::new();

        // Can't force close from Running
        let forced = signal.begin_force_close();
        crate::assert_with_log!(!forced, "can't force from running", false, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "still running",
            ShutdownPhase::Running,
            signal.phase()
        );
        crate::test_complete!("force_close_only_from_draining");
    }

    #[test]
    fn mark_stopped() {
        init_test("mark_stopped");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);
        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        signal.mark_stopped();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::assert_with_log!(signal.is_stopped(), "is stopped", true, signal.is_stopped());
        crate::test_complete!("mark_stopped");
    }

    #[test]
    fn trigger_immediate_skips_drain() {
        init_test("trigger_immediate_skips_drain");
        let signal = ShutdownSignal::new();
        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "force-closing immediately",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::assert_with_log!(
            !signal.is_stopped(),
            "not stopped until mark_stopped",
            false,
            signal.is_stopped()
        );
        crate::test_complete!("trigger_immediate_skips_drain");
    }

    #[test]
    fn trigger_immediate_records_force_close_metadata_without_prior_drain() {
        init_test("trigger_immediate_records_force_close_metadata_without_prior_drain");
        set_test_time(123);
        let signal = ShutdownSignal::with_time_getter(test_time);

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(123)),
            "immediate start uses injected clock",
            Some(Time::from_nanos(123)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(123)),
            "immediate deadline is current time",
            Some(Time::from_nanos(123)),
            signal.drain_deadline()
        );
        crate::test_complete!("trigger_immediate_records_force_close_metadata_without_prior_drain");
    }

    #[test]
    fn trigger_immediate_does_not_regress_stopped_phase() {
        init_test("trigger_immediate_does_not_regress_stopped_phase");
        let signal = ShutdownSignal::new();
        signal.mark_stopped();

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped phase preserved",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::test_complete!("trigger_immediate_does_not_regress_stopped_phase");
    }

    #[test]
    fn trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped() {
        init_test("trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped");
        let signal = ShutdownSignal::new();
        let hook_signal = signal.clone();
        set_trigger_immediate_pre_phase_hook(Some(Box::new(move || {
            hook_signal.mark_stopped();
        })));

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "interleaved mark_stopped keeps terminal phase",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.is_stopped(),
            "signal remains stopped after interleaving",
            true,
            signal.is_stopped()
        );
        crate::test_complete!(
            "trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped"
        );
    }

    #[test]
    fn trigger_immediate_overrides_interleaved_begin_drain_metadata() {
        init_test("trigger_immediate_overrides_interleaved_begin_drain_metadata");
        set_test_time(123);
        let signal = ShutdownSignal::with_time_getter(test_time);
        let hook_signal = signal.clone();
        set_trigger_immediate_pre_phase_hook(Some(Box::new(move || {
            let began = hook_signal.begin_drain(Duration::from_secs(30));
            assert!(began, "hook begin_drain should succeed");
        })));

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "interleaved begin_drain still reaches force-closing",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(123)),
            "original drain start is retained",
            Some(Time::from_nanos(123)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(123)),
            "immediate trigger overwrites graceful-drain deadline",
            Some(Time::from_nanos(123)),
            signal.drain_deadline()
        );
        crate::test_complete!("trigger_immediate_overrides_interleaved_begin_drain_metadata");
    }

    #[test]
    fn subscribe_receives_shutdown() {
        init_test("subscribe_receives_shutdown");
        let signal = ShutdownSignal::new();
        let receiver = signal.subscribe();

        let not_shutting = receiver.is_shutting_down();
        crate::assert_with_log!(!not_shutting, "not shutting", false, not_shutting);

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        let shutting = receiver.is_shutting_down();
        crate::assert_with_log!(shutting, "shutting down", true, shutting);
        crate::test_complete!("subscribe_receives_shutdown");
    }

    #[test]
    fn display_formatting() {
        init_test("display_formatting");
        let cases = [
            (ShutdownPhase::Running, "Running"),
            (ShutdownPhase::Draining, "Draining"),
            (ShutdownPhase::ForceClosing, "ForceClosing"),
            (ShutdownPhase::Stopped, "Stopped"),
        ];
        for (phase, expected) in cases {
            let actual = format!("{phase}");
            crate::assert_with_log!(actual == expected, "phase display", expected, actual);
        }
        crate::test_complete!("display_formatting");
    }

    #[test]
    fn clone_shares_state() {
        init_test("clone_shares_state");
        let signal = ShutdownSignal::new();
        let cloned = signal.clone();

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        crate::assert_with_log!(
            cloned.is_draining(),
            "clone sees drain",
            true,
            cloned.is_draining()
        );
        crate::test_complete!("clone_shares_state");
    }

    // ====================================================================
    // Async integration tests
    // ====================================================================

    #[test]
    fn phase_changed_fires_on_drain() {
        init_test("phase_changed_fires_on_drain");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let signal2 = signal.clone();

            // Spawn a thread that will begin drain after a short delay
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let began = signal2.begin_drain(Duration::from_secs(30));
                assert!(began, "begin drain should succeed");
            });

            // Wait for the phase change
            signal.wait_for_phase(ShutdownPhase::Draining).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::Draining,
                "phase after drain",
                ShutdownPhase::Draining,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_drain");
    }

    #[test]
    fn phase_changed_fires_on_force_close() {
        init_test("phase_changed_fires_on_force_close");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let began = signal.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "begin drain", true, began);

            let signal2 = signal.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let forced = signal2.begin_force_close();
                assert!(forced, "force close should succeed");
            });

            signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::ForceClosing,
                "phase after force close",
                ShutdownPhase::ForceClosing,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_force_close");
    }

    #[test]
    fn phase_changed_fires_on_mark_stopped() {
        init_test("phase_changed_fires_on_mark_stopped");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let began = signal.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "begin drain", true, began);
            let forced = signal.begin_force_close();
            crate::assert_with_log!(forced, "force close", true, forced);

            let signal2 = signal.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                signal2.mark_stopped();
            });

            signal.wait_for_phase(ShutdownPhase::Stopped).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::Stopped,
                "phase after stopped",
                ShutdownPhase::Stopped,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_mark_stopped");
    }

    #[test]
    fn phase_changed_fires_on_immediate() {
        init_test("phase_changed_fires_on_immediate");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let signal2 = signal.clone();

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                signal2.trigger_immediate();
            });

            signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::ForceClosing,
                "phase after immediate",
                ShutdownPhase::ForceClosing,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_immediate");
    }

    #[test]
    fn full_lifecycle_phase_transitions() {
        init_test("full_lifecycle_phase_transitions");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();

            // Phase 1: Running
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Running,
                "starts running",
                ShutdownPhase::Running,
                signal.phase()
            );

            // Phase 2: Draining (triggered from another thread)
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let began = sig.begin_drain(Duration::from_secs(1));
                    assert!(began, "begin drain should succeed");
                });
                signal.wait_for_phase(ShutdownPhase::Draining).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::Draining,
                    "draining",
                    ShutdownPhase::Draining,
                    p
                );
                h.join().expect("thread panicked");
            }

            // Phase 3: ForceClosing
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let forced = sig.begin_force_close();
                    assert!(forced, "force close should succeed");
                });
                signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::ForceClosing,
                    "force closing",
                    ShutdownPhase::ForceClosing,
                    p
                );
                h.join().expect("thread panicked");
            }

            // Phase 4: Stopped
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    sig.mark_stopped();
                });
                signal.wait_for_phase(ShutdownPhase::Stopped).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::Stopped,
                    "stopped",
                    ShutdownPhase::Stopped,
                    p
                );
                h.join().expect("thread panicked");
            }
        });
        crate::test_complete!("full_lifecycle_phase_transitions");
    }

    #[test]
    fn subscriber_receives_drain_signal() {
        init_test("subscriber_receives_drain_signal");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let mut receiver = signal.subscribe();

            let not_shutting = receiver.is_shutting_down();
            crate::assert_with_log!(!not_shutting, "not shutting down", false, not_shutting);

            // Trigger drain from thread
            let sig = signal.clone();
            let h = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                let began = sig.begin_drain(Duration::from_secs(30));
                assert!(began, "begin drain should succeed");
            });

            // Wait for the underlying signal
            receiver.wait().await;

            let shutting = receiver.is_shutting_down();
            crate::assert_with_log!(shutting, "is shutting down", true, shutting);

            h.join().expect("thread panicked");
        });
        crate::test_complete!("subscriber_receives_drain_signal");
    }

    #[test]
    fn subscriber_receives_mark_stopped_without_prior_drain() {
        init_test("subscriber_receives_mark_stopped_without_prior_drain");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let mut receiver = signal.subscribe();
            let signal2 = signal.clone();

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                signal2.mark_stopped();
            });

            receiver.wait().await;

            let shutting = receiver.is_shutting_down();
            crate::assert_with_log!(shutting, "receiver sees shutdown", true, shutting);
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Stopped,
                "phase after mark_stopped",
                ShutdownPhase::Stopped,
                signal.phase()
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("subscriber_receives_mark_stopped_without_prior_drain");
    }

    // ====================================================================
    // Stats collection tests
    // ====================================================================

    #[test]
    fn collect_stats_before_drain() {
        init_test("collect_stats_before_drain");
        let signal = ShutdownSignal::new();

        let stats = signal.collect_stats(0, 0);
        crate::assert_with_log!(stats.drained == 0, "drained", 0, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 0,
            "force_closed",
            0,
            stats.force_closed
        );
        // Duration should be zero since drain hasn't started
        crate::assert_with_log!(
            stats.duration == Duration::ZERO,
            "duration zero",
            Duration::ZERO,
            stats.duration
        );
        crate::test_complete!("collect_stats_before_drain");
    }

    #[test]
    fn collect_stats_after_drain() {
        init_test("collect_stats_after_drain");
        let signal = ShutdownSignal::new();

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        // Small sleep to ensure measurable duration
        std::thread::sleep(Duration::from_millis(5));

        let stats = signal.collect_stats(10, 3);
        crate::assert_with_log!(stats.drained == 10, "drained", 10, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 3,
            "force_closed",
            3,
            stats.force_closed
        );

        let nonzero = stats.duration > Duration::ZERO;
        crate::assert_with_log!(nonzero, "nonzero duration", true, nonzero);
        crate::test_complete!("collect_stats_after_drain");
    }

    #[test]
    fn drain_start_tracking() {
        init_test("drain_start_tracking");
        let signal = ShutdownSignal::new();

        let before = signal.drain_start();
        crate::assert_with_log!(
            before.is_none(),
            "no start before drain",
            true,
            before.is_none()
        );

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        let after = signal.drain_start();
        crate::assert_with_log!(after.is_some(), "start after drain", true, after.is_some());
        crate::test_complete!("drain_start_tracking");
    }

    #[test]
    fn concurrent_begin_drain_only_one_wins() {
        init_test("concurrent_begin_drain_only_one_wins");
        let signal = ShutdownSignal::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let sig = signal.clone();
            let b = std::sync::Arc::clone(&barrier);
            let w = std::sync::Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                b.wait();
                if sig.begin_drain(Duration::from_secs(30)) {
                    w.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }));
        }

        barrier.wait();
        for h in handles {
            h.join().expect("thread panicked");
        }

        let winner_count = winners.load(std::sync::atomic::Ordering::Relaxed);
        crate::assert_with_log!(winner_count == 1, "exactly one winner", 1, winner_count);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "phase is draining",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::test_complete!("concurrent_begin_drain_only_one_wins");
    }

    #[test]
    fn mark_stopped_from_draining_skips_force_close() {
        init_test("mark_stopped_from_draining_skips_force_close");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        // Directly mark stopped without going through ForceClosing
        signal.mark_stopped();
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped from draining",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::test_complete!("mark_stopped_from_draining_skips_force_close");
    }

    #[test]
    fn shutdown_phase_debug_clone_copy_eq() {
        let p = ShutdownPhase::Draining;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Draining"), "{dbg}");
        let copied: ShutdownPhase = p;
        let cloned = p;
        assert_eq!(copied, cloned);
        assert_ne!(p, ShutdownPhase::Running);
    }

    #[test]
    fn shutdown_stats_debug_clone() {
        let s = ShutdownStats {
            drained: 5,
            force_closed: 1,
            duration: Duration::from_secs(3),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ShutdownStats"), "{dbg}");
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }
}
