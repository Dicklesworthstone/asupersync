//! Sleep future for delaying execution.
//!
//! The [`Sleep`] future completes after a deadline has passed.
//! It works with both wall clock time (production) and virtual time (lab).
//!
//! # Timer Driver Integration
//!
//! When a timer driver is available via `Cx::current()`, Sleep registers
//! with the driver's timer wheel for efficient wakeups. Without one, wall-clock
//! sleeps share a fallback timer; a custom injected clock may use a helper thread.

use crate::cx::Cx;
use crate::time::{TimerDriverHandle, TimerHandle};
use crate::trace::TraceEvent;
use crate::types::{CancelKind, Time};
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

#[cfg(not(target_arch = "wasm32"))]
static START_TIME: OnceLock<Instant> = OnceLock::new();
const CUSTOM_TIME_GETTER_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Returns the canonical process epoch shared by every wall-clock-based time
/// source in the runtime.
///
/// Both `wall_now`'s capability-free fallback path AND the production
/// [`WallClock`](super::driver::WallClock) (the timer driver the deadline
/// monitor reads) must measure elapsed time from the *same* `Instant`.
/// Otherwise a `Time` produced by one is not comparable to a `Time` produced by
/// the other: e.g. a request-budget deadline computed via `wall_now()` (which
/// may hit this fallback when no timer-driver `Cx` is current) is compared by
/// the deadline monitor against `timer_driver.now()`. If the two anchor to
/// different epochs the skew equals the gap between their creation instants, so
/// once process uptime exceeds the request timeout every such request is born
/// already past its deadline and is cancelled immediately.
///
/// Anchoring both to this single `OnceLock` makes `wall_now` honor its
/// documented contract — "elapsed since the first call to any time-related
/// function in this module" — regardless of which branch it takes. Whichever
/// time source is constructed first (typically the driver's `WallClock` at
/// runtime startup) claims the epoch; all later ones share it.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn process_epoch() -> Instant {
    *START_TIME.get_or_init(Instant::now)
}

#[cfg(target_arch = "wasm32")]
/// Process epoch is unsupported on wasm32.
#[must_use]
pub fn process_epoch() -> Instant {
    panic!("std::time::Instant is unsupported on wasm32")
}

#[cfg(target_arch = "wasm32")]
/// Returns monotonic nanoseconds since first call on wasm32 targets.
#[must_use]
pub(crate) fn wasm_monotonic_nanos() -> u64 {
    static START_MS: OnceLock<f64> = OnceLock::new();
    static LAST_NANOS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let start = *START_MS.get_or_init(js_sys::Date::now);
    let elapsed_ms = (js_sys::Date::now() - start).max(0.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let nanos = (elapsed_ms * 1_000_000.0) as u64;
    LAST_NANOS.fetch_max(nanos, Ordering::Relaxed).max(nanos)
}

#[derive(Debug)]
struct FallbackThread {
    stop: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    thread: std::thread::Thread,
    join: std::thread::JoinHandle<()>,
}

#[inline]
fn request_stop_fallback(fallback: &FallbackThread) {
    fallback.stop.store(true, Ordering::Release);
    fallback.thread.unpark();
}

#[inline]
fn take_finished_fallbacks(state: &mut SleepState) -> Vec<std::thread::JoinHandle<()>> {
    let mut finished = Vec::new();

    // Move logically completed but not yet fully exited threads to zombies
    if let Some(fallback) = state.fallback.as_ref() {
        if fallback.completed.load(Ordering::Acquire) {
            if let Some(fallback) = state.fallback.take() {
                state.zombie_fallbacks.push(fallback.join);
            }
        } else if fallback.join.is_finished() {
            if let Some(fallback) = state.fallback.take() {
                finished.push(fallback.join);
            }
        }
    }

    let mut i = 0;
    while i < state.zombie_fallbacks.len() {
        if state.zombie_fallbacks[i].is_finished() {
            finished.push(state.zombie_fallbacks.remove(i));
        } else {
            i += 1;
        }
    }

    finished
}

#[inline]
fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Process-global shared fallback timer (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5).
///
/// A `Sleep` polled with no bound or ambient (`Cx`) timer driver used to spawn a
/// dedicated OS thread *per Sleep* to drive its deadline. A heavy consumer that
/// drives futures off the runtime's worker threads (so `Cx::current()` is `None`)
/// therefore paid a `pthread_create`/`pthread_exit` for every timeout — the
/// thread-per-`sleep` churn the frankenterm-gui profile caught (~37/sec).
///
/// This shared driver replaces that with ONE process-lifetime pump thread that
/// owns the standard wall-clock [`TimerDriver`](super::driver::TimerDriver) and
/// services every off-`Cx` sleep through the same wheel the runtime uses. It is
/// started lazily on the first off-`Cx` wall-clock sleep and never joined.
struct GlobalFallbackTimer {
    driver: TimerDriverHandle,
    pump: std::thread::Thread,
}

static GLOBAL_FALLBACK: OnceLock<GlobalFallbackTimer> = OnceLock::new();

/// Idle park used by the pump when no timers are pending. It only bounds how
/// long the pump sleeps when the wheel is empty; an arriving timer unparks the
/// pump immediately (see `arm` handling in `Sleep::poll`), so this does not
/// delay any registered deadline.
const FALLBACK_PUMP_IDLE_PARK: Duration = Duration::from_millis(250);

/// Returns the process-global shared fallback timer, starting its pump thread on
/// first use.
fn global_fallback_timer() -> &'static GlobalFallbackTimer {
    GLOBAL_FALLBACK.get_or_init(|| {
        let driver = TimerDriverHandle::with_wall_clock();
        let pump_driver = driver.clone();
        // One shared pump replaces N per-Sleep threads; count it once so the
        // `timer_threads_spawned` churn signal reflects reality (1, not N).
        crate::runtime::metrics::record_timer_thread_spawned();
        // ubs:ignore - intentional process-lifetime daemon timer pump shared by all off-Cx sleeps
        let handle = std::thread::Builder::new()
            .name("asupersync-fallback-timer".to_string())
            .spawn(move || fallback_pump_loop(&pump_driver))
            .expect("spawn shared fallback timer pump");
        GlobalFallbackTimer {
            driver,
            pump: handle.thread().clone(),
        }
    })
}

/// The shared fallback pump loop: fire due timers, then park until the next
/// deadline (or `FALLBACK_PUMP_IDLE_PARK` when the wheel is empty). A newly
/// armed sleep unparks this thread, so the park is recomputed against the
/// sooner deadline without busy-polling.
fn fallback_pump_loop(driver: &TimerDriverHandle) -> ! {
    loop {
        let _ = driver.process_timers();
        let park = match driver.next_deadline() {
            Some(deadline) => {
                let now = driver.now().as_nanos();
                let dl = deadline.as_nanos();
                if dl > now {
                    Duration::from_nanos(dl - now)
                } else {
                    // Already due; loop to fire it without parking.
                    continue;
                }
            }
            None => FALLBACK_PUMP_IDLE_PARK,
        };
        std::thread::park_timeout(park);
    }
}

/// Whether `handle` is the process-global shared fallback driver.
#[inline]
fn is_global_fallback_driver(handle: &TimerDriverHandle) -> bool {
    GLOBAL_FALLBACK
        .get()
        .is_some_and(|global| global.driver.ptr_eq(handle))
}

/// br-asupersync-runtime-cpu-overhaul-5vt09v.3.5: fired-once flag for the
/// "no timer driver, falling back to the shared fallback timer" diagnostic.
///
/// The shared fallback timer (above) is a *valid* path for runtimes legitimately
/// built without a timer driver, so taking it is not an error and must not panic
/// (that would break standalone `sleep()` usage and the off-`Cx` fallback tests).
/// But it is *also* exactly the symptom of a mis-configured consumer that forgot
/// to install a timer driver (the frankenterm churn). We therefore surface it as
/// a one-time WARN so the fallback shows up in logs instead of running silently,
/// matching the established `br-asupersync-9nn568` fallback-warn idiom in
/// `runtime::scheduler::three_lane`.
static FALLBACK_TIMER_WARNED: AtomicBool = AtomicBool::new(false);

/// Returns `true` exactly once for a given flag — the first caller observes the
/// `false -> true` transition, every later caller observes `true`. Factored out
/// so the warn-once semantics can be unit-tested deterministically against a
/// local flag without depending on process-global state or a `tracing`
/// subscriber.
#[inline]
fn claim_first_call(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::Relaxed)
}

/// Emit the missing-timer-driver WARN at most once per process.
///
/// Called when a `Sleep` is polled with neither a bound nor an ambient (`Cx`)
/// timer driver and routes through the process-global shared fallback timer.
#[inline]
fn warn_missing_timer_driver_once() {
    if claim_first_call(&FALLBACK_TIMER_WARNED) {
        crate::tracing_compat::warn!(
            target: "asupersync::time::sleep",
            "br-asupersync-runtime-cpu-overhaul-5vt09v.3.5: a Sleep was polled with no bound or \
             ambient (Cx) timer driver; routing through the process-global shared fallback timer. \
             Install a timer driver so timers are driven by the runtime's worker/wheel and stay \
             replay-deterministic in the lab runtime: run sleeps inside a runtime task \
             (RuntimeBuilder installs a wall-clock driver by default and tasks inherit it via Cx), \
             or build the runtime with RuntimeBuilder::enable_time()."
        );
    }
}

/// Returns the current wall clock time.
///
/// This function returns the elapsed time since the first call to any
/// time-related function in this module. It is suitable for production
/// use where real wall clock time is needed.
///
/// **Capability-aware**: First attempts to route through the current `Cx` context
/// and timer driver when available, only falling back to direct `Instant::now()`
/// when no capability context is present. This preserves the "no ambient authority"
/// invariant while still providing a fallback for contexts without capabilities.
///
/// For virtual time in tests/lab runtime, use a timer driver's `now()` method.
#[must_use]
#[inline]
pub fn wall_now() -> Time {
    // First try to route through current Cx capabilities if available
    if let Some(current_cx) = crate::cx::Cx::current() {
        if let Some(timer_driver) = current_cx.timer_driver() {
            return timer_driver.now();
        }
        // A Cx without a timer driver must fall through to the raw wall-clock
        // path. Calling `Cx::now()` here would recurse back through this helper.
    }

    // Absolute fallback: no Cx context or capabilities available.
    // This preserves compatibility for truly capability-free contexts. The
    // epoch is the shared process epoch so this branch stays comparable with
    // the production `WallClock` timer driver (see `process_epoch`).
    #[cfg(not(target_arch = "wasm32"))]
    {
        let start = process_epoch();
        let now = Instant::now();
        if now < start {
            Time::ZERO
        } else {
            let elapsed = now.duration_since(start);
            Time::from_nanos(duration_to_nanos(elapsed))
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Time::from_nanos(wasm_monotonic_nanos())
    }
}

#[derive(Debug)]
struct SleepState {
    waker: Option<Waker>,
    /// Background timing thread used when no timer driver is present.
    fallback: Option<FallbackThread>,
    /// Threads that have been asked to stop but haven't been joined yet.
    zombie_fallbacks: Vec<std::thread::JoinHandle<()>>,
    /// Handle to the registered timer in the timer driver.
    timer_handle: Option<TimerHandle>,
    /// Timer driver used to register the current handle.
    timer_driver: Option<TimerDriverHandle>,
    /// True when the current registration was CLAMPED because the true deadline
    /// exceeds the driver's timer horizon: the wheel will fire early at the
    /// horizon as a re-arm signal, so `Future::poll` must re-register for the
    /// remaining duration instead of completing. A latched fire with
    /// `registered_partial == false` is authoritative completion, even across a
    /// driver migration whose clock reads before the deadline
    /// (br-asupersync-sleep-horizon-early-youlxs).
    registered_partial: bool,
}

#[derive(Debug)]
struct ReadyWaker {
    ready: Arc<AtomicBool>,
    inner: Waker,
}

use std::task::Wake;
impl Wake for ReadyWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.ready.store(true, Ordering::Release);
        self.inner.wake_by_ref();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
        self.inner.wake_by_ref();
    }
}

#[inline]
fn readiness_waker(ready: Arc<AtomicBool>, inner: Waker) -> Waker {
    Waker::from(Arc::new(ReadyWaker { ready, inner }))
}

/// A future that completes after a specified deadline.
///
/// `Sleep` is the core primitive for time-based delays. It can be awaited
/// to pause execution until the deadline has passed.
///
/// # Time Sources
///
/// By default, `Sleep` checks time at each poll. The actual time source
/// depends on the runtime context:
/// - Production: Uses wall clock time
/// - Lab runtime: Uses virtual time
///
/// For standalone use without a runtime, you can provide a time getter.
///
/// # Cancellation
///
/// Under a task context, an explicit cancellation request (anything but a
/// timeout or deadline) completes a pending `Sleep` early, so the task reaches
/// its next checkpoint instead of waiting out the deadline. A `Sleep` first
/// polled after the request completes after one trip through the scheduler,
/// so a loop that awaits sleeps and never checks for cancellation keeps
/// yielding once per turn until it does. Inside a masked section the sleep
/// runs to its deadline.
///
/// # Cancel Safety
///
/// `Sleep` is cancel-safe. Dropping it simply stops the wait with no
/// side effects. It can be recreated with the same or a different deadline.
///
/// # Example
///
/// ```no_run
/// use asupersync::Cx;
/// use asupersync::time::{sleep, sleep_until};
/// use asupersync::types::Time;
/// use std::time::Duration;
///
/// async fn pause(cx: &Cx) {
///     // Sleep for 100 milliseconds, measured from the task's current time
///     sleep(cx.now(), Duration::from_millis(100)).await;
///
///     // Sleep until a specific time
///     sleep_until(Time::from_secs(5)).await;
/// }
/// ```
#[derive(Debug)]
pub struct Sleep {
    /// The deadline when this sleep completes.
    deadline: Time,
    /// Optional time getter for standalone use.
    /// When None, uses a default mechanism (currently instant check).
    pub(crate) time_getter: Option<fn() -> Time>,
    /// Optional explicit timer driver for capability-bound waits.
    ///
    /// When present, polling does not consult `Cx::current()` for timer
    /// registration or time reads.
    bound_timer_driver: Option<TimerDriverHandle>,
    /// Whether this sleep has been polled at least once.
    /// Used for tracing/debugging.
    polled: std::sync::atomic::AtomicBool,
    /// Whether this sleep has already completed and not yet been reset.
    completed: std::sync::atomic::AtomicBool,
    /// Whether a timer/fallback wake has already made this sleep ready.
    ready: Arc<AtomicBool>,
    /// Shared state for background waiter thread.
    state: Arc<Mutex<SleepState>>,
}

impl Sleep {
    /// Creates a new `Sleep` that completes at the given deadline.
    ///
    /// # Arguments
    ///
    /// * `deadline` - The absolute time when this sleep completes
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Sleep;
    /// use asupersync::types::Time;
    ///
    /// let sleep = Sleep::new(Time::from_secs(5));
    /// assert_eq!(sleep.deadline(), Time::from_secs(5));
    /// ```
    #[must_use]
    #[inline]
    pub fn new(deadline: Time) -> Self {
        Self {
            deadline,
            time_getter: None,
            bound_timer_driver: None,
            polled: std::sync::atomic::AtomicBool::new(false),
            completed: std::sync::atomic::AtomicBool::new(false),
            ready: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                fallback: None,
                zombie_fallbacks: Vec::new(),
                timer_handle: None,
                timer_driver: None,
                registered_partial: false,
            })),
        }
    }

    /// Creates a `Sleep` that completes after the given duration from `now`.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `duration` - How long to sleep
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Sleep;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let now = Time::from_secs(10);
    /// let sleep = Sleep::after(now, Duration::from_secs(5));
    /// assert_eq!(sleep.deadline(), Time::from_secs(15));
    /// ```
    #[must_use]
    #[inline]
    pub fn after(now: Time, duration: Duration) -> Self {
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        Self::new(deadline)
    }

    /// Creates a `Sleep` with a custom time getter function.
    ///
    /// This is useful for testing or when you need to control the time source.
    /// The deadline belongs to this clock, even when a runtime timer driver is
    /// available. The driver schedules the remaining duration in its own clock
    /// domain; its wake only completes the sleep after this getter reaches the
    /// deadline.
    ///
    /// # Arguments
    ///
    /// * `deadline` - The deadline when this sleep completes
    /// * `time_getter` - Function that returns the current time
    #[inline]
    #[must_use]
    pub fn with_time_getter(deadline: Time, time_getter: fn() -> Time) -> Self {
        Self {
            deadline,
            time_getter: Some(time_getter),
            bound_timer_driver: None,
            polled: std::sync::atomic::AtomicBool::new(false),
            completed: std::sync::atomic::AtomicBool::new(false),
            ready: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                fallback: None,
                zombie_fallbacks: Vec::new(),
                timer_handle: None,
                timer_driver: None,
                registered_partial: false,
            })),
        }
    }

    /// Creates a `Sleep` that is permanently bound to an explicit timer driver.
    ///
    /// This preserves capability-correct timing when the creator needs the
    /// future to keep using the captured driver even if it is later polled
    /// outside that creator's ambient `Cx`.
    #[inline]
    #[must_use]
    pub(crate) fn with_timer_driver(deadline: Time, timer_driver: TimerDriverHandle) -> Self {
        Self {
            deadline,
            time_getter: None,
            bound_timer_driver: Some(timer_driver),
            polled: std::sync::atomic::AtomicBool::new(false),
            completed: std::sync::atomic::AtomicBool::new(false),
            ready: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                fallback: None,
                zombie_fallbacks: Vec::new(),
                timer_handle: None,
                timer_driver: None,
                registered_partial: false,
            })),
        }
    }

    /// Returns the deadline for this sleep.
    #[inline]
    #[must_use]
    pub const fn deadline(&self) -> Time {
        self.deadline
    }

    /// Returns the remaining duration until the deadline.
    ///
    /// Returns `Duration::ZERO` if the deadline has passed.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time to compare against
    #[inline]
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        if now >= self.deadline {
            Duration::ZERO
        } else {
            let nanos = self.deadline.as_nanos().saturating_sub(now.as_nanos());
            Duration::from_nanos(nanos)
        }
    }

    /// Checks if the deadline has elapsed.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time to compare against
    #[inline]
    #[must_use]
    pub fn is_elapsed(&self, now: Time) -> bool {
        now >= self.deadline
    }

    /// Resets this sleep to a new deadline.
    ///
    /// This can be used to reuse a `Sleep` instance without allocating a new one.
    /// Any registered timer is cancelled and will be re-registered on next poll.
    #[inline]
    pub fn reset(&mut self, deadline: Time) {
        self.deadline = deadline;
        self.polled
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.completed
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.ready = Arc::new(AtomicBool::new(false));
        let (handle, driver, fallback_handles) = {
            let mut state = self.state.lock();
            state.waker = None;
            let mut handles = std::mem::take(&mut state.zombie_fallbacks);
            if let Some(fallback) = state.fallback.take() {
                request_stop_fallback(&fallback);
                handles.push(fallback.join);
            }
            // The new deadline gets a fresh registration on the next poll; clear
            // the clamp flag so it is recomputed rather than left stale
            // (br-asupersync-sleep-horizon-early-youlxs).
            state.registered_partial = false;
            (
                state.timer_handle.take(),
                state.timer_driver.take(),
                handles,
            )
        };

        // Join finished threads, park the rest: never block, never detach (GH #80).
        crate::runtime::spawn_blocking::reap_threads(fallback_handles);

        // Cancel any existing timer - will be re-registered on next poll
        if let (Some(handle), Some(driver)) = (handle, driver) {
            let trace = Cx::current().and_then(|current| current.trace_buffer());
            if let Some(trace) = trace.as_ref() {
                let now = driver.now();
                trace.record_event(|seq| TraceEvent::timer_cancelled(seq, now, handle.id()));
            }
            let _ = driver.cancel(&handle);
        }
    }

    /// Resets this sleep to complete after the given duration from `now`.
    ///
    /// Any registered timer is cancelled and will be re-registered on next poll.
    #[inline]
    pub fn reset_after(&mut self, now: Time, duration: Duration) {
        self.reset(now.saturating_add_nanos(duration_to_nanos(duration)));
    }

    /// Returns true if this sleep has been polled at least once.
    #[must_use]
    #[inline]
    pub fn was_polled(&self) -> bool {
        self.polled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Gets the current time using the configured time getter or default.
    #[inline]
    fn current_time(&self) -> Time {
        self.time_getter.map_or_else(wall_now, |getter| getter())
    }

    fn timer_driver_for_poll(&self) -> Option<TimerDriverHandle> {
        self.bound_timer_driver
            .clone()
            .or_else(|| Cx::current().and_then(|current| current.timer_driver()))
    }

    pub(crate) fn has_timer_driver_for_poll(&self) -> bool {
        self.bound_timer_driver.is_some()
            || Cx::current()
                .and_then(|current| current.timer_driver())
                .is_some()
    }

    /// Detach every resource owned by the current wait without blocking the
    /// executor. A completed future may legally remain allocated indefinitely,
    /// so terminal cleanup cannot be deferred to `Drop`.
    fn take_active_registration(
        &self,
    ) -> (
        Option<TimerHandle>,
        Option<TimerDriverHandle>,
        Vec<std::thread::JoinHandle<()>>,
    ) {
        let mut state = self.state.lock();
        state.waker = None;
        state.registered_partial = false;

        let mut fallback_handles = std::mem::take(&mut state.zombie_fallbacks);
        if let Some(fallback) = state.fallback.take() {
            request_stop_fallback(&fallback);
            fallback_handles.push(fallback.join);
        }

        (
            state.timer_handle.take(),
            state.timer_driver.take(),
            fallback_handles,
        )
    }

    fn cancel_active_registration(&self) {
        let (handle, driver, fallback_handles) = self.take_active_registration();

        // Joining a running fallback thread would block the executor, and dropping
        // its handle would detach a thread that is exiting (GitHub #80): reap it.
        crate::runtime::spawn_blocking::reap_threads(fallback_handles);

        if let (Some(handle), Some(driver)) = (handle, driver) {
            let trace = Cx::current().and_then(|current| current.trace_buffer());
            if let Some(trace) = trace.as_ref() {
                let now = driver.now();
                trace.record_event(|seq| TraceEvent::timer_cancelled(seq, now, handle.id()));
            }
            let _ = driver.cancel(&handle);
        }
    }

    fn complete_ready_registration(&self, now: Time, timer_driver: Option<TimerDriverHandle>) {
        let (handle, driver, fallback_handles) = self.take_active_registration();

        // See `cancel_active_registration`: terminal completion must release
        // task references promptly without synchronously joining OS threads.
        crate::runtime::spawn_blocking::reap_threads(fallback_handles);

        if let Some(handle) = handle {
            let driver = driver.or(timer_driver);
            let trace = Cx::current().and_then(|current| current.trace_buffer());
            if let Some(trace) = trace.as_ref() {
                let fired_at = if self.time_getter.is_some() {
                    driver.as_ref().map_or(now, TimerDriverHandle::now)
                } else {
                    now.max(self.deadline)
                };
                trace.record_event(|seq| TraceEvent::timer_fired(seq, fired_at, handle.id()));
            }
            if let Some(driver) = driver {
                let _ = driver.cancel(&handle);
            }
        }
    }

    /// Returns whether this sleep uses a custom time source.
    #[inline]
    #[must_use]
    pub const fn has_custom_time_getter(&self) -> bool {
        self.time_getter.is_some()
    }

    /// Polls this sleep with an explicit time value.
    ///
    /// This is useful when you want to control the time source manually
    /// rather than using the built-in time getter.
    ///
    /// Returns `Poll::Ready(())` if the deadline has passed.
    pub fn poll_with_time(&self, now: Time) -> Poll<()> {
        assert!(
            !self.completed.load(std::sync::atomic::Ordering::Acquire),
            "Sleep polled after completion"
        );
        self.polled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Ordinary sleeps preserve an authoritative timer fire across driver
        // migration. A custom clock still owns its deadline: a runtime wake
        // only asks us to check that clock again. Clamped-wheel early fires are
        // intercepted by `poll_inner` before reaching this check.
        if self.take_elapsed_wake(now) || now >= self.deadline {
            self.completed
                .store(true, std::sync::atomic::Ordering::Release);
            self.complete_ready_registration(now, self.timer_driver_for_poll());
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Polls a timeout's deadline without mistaking owner cancellation for
    /// elapsed time. Only this timer skips the cancellation checkpoint; its
    /// wrapped operation can still observe cancellation and finish cleanup.
    pub(crate) fn poll_deadline(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_inner(cx, false)
    }

    pub(crate) fn poll_ready_with_time(&self, now: Time) -> Poll<()> {
        assert!(
            !self.completed.load(std::sync::atomic::Ordering::Acquire),
            "Sleep polled after completion"
        );
        if self.take_elapsed_wake(now) || now >= self.deadline {
            self.polled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.completed
                .store(true, std::sync::atomic::Ordering::Release);
            self.complete_ready_registration(now, self.timer_driver_for_poll());
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Sleep {
    /// Consume a driver wake without allowing its clock to complete a custom
    /// deadline. Retire a spent registration so the next poll can re-arm it.
    fn take_elapsed_wake(&self, now: Time) -> bool {
        if !self.ready.swap(false, Ordering::AcqRel) {
            return false;
        }
        if self.time_getter.is_some() && now < self.deadline {
            self.cancel_active_registration();
            return false;
        }
        true
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_inner(cx, true)
    }
}

impl Sleep {
    #[allow(clippy::too_many_lines)]
    fn poll_inner(self: Pin<&mut Self>, cx: &mut Context<'_>, cancel_aware: bool) -> Poll<()> {
        assert!(
            !self.completed.load(std::sync::atomic::Ordering::Acquire),
            "Sleep polled after completion"
        );

        // `Sleep` is a cancellation point when it runs under an ambient task
        // context. Cancellation publication wakes the parked task through the
        // scheduler's task Waker; the follow-up poll must then acknowledge the
        // request and complete the wait instead of re-parking until the timer's
        // original deadline. This is especially important for current-thread
        // runtimes: no second worker exists to make unrelated progress while a
        // parent waits for an aborted sleeping child to join.
        //
        // `Sleep` has no error output, so early readiness is the only compatible
        // way to deliver an explicit cancellation. Deadline/timeout cancellation
        // is intentionally excluded: request-budget combinators own that outcome,
        // and letting the handler continue after its sleep would turn a timeout
        // into a successful response. The surrounding task may run its normal
        // cleanup before returning. Terminal cleanup below cancels the registered
        // timer immediately; a completed future may outlive the surrounding task.
        if cancel_aware
            && Cx::current().is_some_and(|current| {
                current.is_cancel_requested()
                    && !current.cancelled_by(CancelKind::Timeout)
                    && !current.cancelled_by(CancelKind::Deadline)
                    && current.checkpoint().is_err()
            })
        {
            // A Sleep first polled after its task was cancelled completes only
            // after one trip through the scheduler. A loop that awaits a fresh
            // Sleep each turn and never checks for cancellation would otherwise
            // find every Sleep ready at once and spin inside a single poll,
            // pinning its worker (a current_thread runtime freezes) where no
            // cleanup budget can reach it (br-asupersync-2u7bpm). A Sleep that
            // was already parked completes at once, as before.
            if !self.polled.swap(true, std::sync::atomic::Ordering::Relaxed) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.completed
                .store(true, std::sync::atomic::Ordering::Release);
            self.cancel_active_registration();
            return Poll::Ready(());
        }

        // Prefer an explicitly bound timer driver; otherwise use the ambient
        // runtime driver when one exists.
        let (ambient_timer_driver, trace) = Cx::current().map_or_else(
            || (None, None),
            |current| (current.timer_driver(), current.trace_buffer()),
        );
        let timer_driver = self
            .bound_timer_driver
            .clone()
            .or_else(|| ambient_timer_driver.clone())
            .or_else(|| {
                // No bound or ambient (Cx) driver. For the common wall-clock
                // case, route through the process-global shared fallback timer
                // instead of spawning an OS thread per Sleep
                // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5). A custom
                // logical clock (`time_getter`) keeps the short-poll thread
                // fallback below, since the wall-clock shared driver cannot
                // observe an injected clock.
                self.time_getter.is_none().then(|| {
                    // Defense-in-depth: surface the missing timer driver once so a
                    // mis-configured consumer is caught in logs instead of silently
                    // running on the fallback
                    // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5).
                    warn_missing_timer_driver_once();
                    global_fallback_timer().driver.clone()
                })
            });
        let now = if let Some(timer) = self.bound_timer_driver.as_ref() {
            timer.now()
        } else if self.time_getter.is_some() {
            self.current_time()
        } else {
            timer_driver
                .as_ref()
                .map_or_else(|| self.current_time(), TimerDriverHandle::now)
        };

        // Intercept a CLAMPED-wheel early fire before poll_with_time. When the
        // true deadline exceeds the driver horizon, the wheel fires the readiness
        // latch early at the horizon purely as a re-arm signal (wheel.rs
        // `register`); `registered_partial` records that the current registration
        // was clamped. Only then do we consume the latch and drop the spent
        // handle so the Pending path below re-registers for the remaining
        // duration. For ordinary sleeps, a NON-partial latched fire remains
        // authoritative across driver migration or fallback→driver transitions.
        // Custom clocks are rechecked by poll_with_time even after that wake
        // (br-asupersync-sleep-horizon-early-youlxs).
        if now < self.deadline {
            let mut state = self.state.lock();
            if state.registered_partial && self.ready.swap(false, Ordering::AcqRel) {
                if let Some(handle) = state.timer_handle.take() {
                    let driver = state.timer_driver.clone().or_else(|| timer_driver.clone());
                    if let Some(driver) = driver {
                        if let Some(trace) = trace.as_ref() {
                            trace.record_event(|seq| {
                                TraceEvent::timer_cancelled(seq, driver.now(), handle.id())
                            });
                        }
                        let _ = driver.cancel(&handle);
                    }
                }
            }
        }

        match self.poll_with_time(now) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => {
                let mut state = self.state.lock();
                let finished_handles = take_finished_fallbacks(&mut state);
                let waker_changed = !state
                    .waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()));

                if waker_changed {
                    state.waker = Some(cx.waker().clone());
                }

                // Prefer timer driver over background thread
                if let Some(timer) = timer_driver.as_ref() {
                    // If a fallback thread exists, request it stop. We don't join here
                    // (poll must not block); Drop/reset will join.
                    if let Some(fallback) = state.fallback.take() {
                        request_stop_fallback(&fallback);
                        state.zombie_fallbacks.push(fallback.join);
                    }

                    // If we switched drivers, cancel the old timer handle first.
                    // Check if we need to cancel before taking any references.
                    let needs_cancel = state
                        .timer_driver
                        .as_ref()
                        .is_some_and(|prev| !timer.ptr_eq(prev));
                    if needs_cancel {
                        // Take both the old driver and handle to avoid borrow conflicts.
                        // The old handle is consumed by cancel(); a new one will be
                        // registered below.
                        let old_driver = state.timer_driver.take();
                        let old_handle = state.timer_handle.take();
                        if let (Some(prev_driver), Some(handle)) = (old_driver, old_handle) {
                            if let Some(trace) = trace.as_ref() {
                                trace.record_event(|seq| {
                                    TraceEvent::timer_cancelled(seq, prev_driver.now(), handle.id())
                                });
                            }
                            let _ = prev_driver.cancel(&handle);
                        }
                        // Note: timer_handle is now None; the code below will
                        // register a fresh handle on the new driver.
                    }

                    state.timer_driver = Some(timer.clone());

                    // Custom deadlines and runtime timers can have different
                    // epochs. Schedule only the remaining custom duration on
                    // the driver's clock, then recheck the custom getter on wake.
                    let timer_now = if self.time_getter.is_some() {
                        timer.now()
                    } else {
                        now
                    };
                    let timer_deadline = if self.time_getter.is_some() {
                        timer_now.saturating_add_nanos(
                            self.deadline.as_nanos().saturating_sub(now.as_nanos()),
                        )
                    } else {
                        self.deadline
                    };

                    // Record whether THIS registration may be clamped: the wheel fires
                    // early at its current 1 ms tick plus `max_timer_duration`, and that
                    // tick can be up to 1 ms behind `now`, so the horizon here is one
                    // tick shorter (br-asupersync-m85zfi LOW 2). Computed at registration
                    // so the flag matches the actual handle, not a later recomputation
                    // (br-asupersync-sleep-horizon-early-youlxs).
                    let horizon_ns = u64::try_from(timer.max_timer_duration().as_nanos())
                        .map_or(u64::MAX, |ns| ns.saturating_sub(1_000_000));
                    let registered_partial =
                        timer_deadline > timer_now.saturating_add_nanos(horizon_ns);

                    let mut armed = false;
                    if state.timer_handle.is_none() {
                        // Register new timer
                        let handle = timer.register(
                            timer_deadline,
                            readiness_waker(Arc::clone(&self.ready), cx.waker().clone()),
                        );
                        if let Some(trace) = trace.as_ref() {
                            trace.record_event(|seq| {
                                TraceEvent::timer_scheduled(
                                    seq,
                                    timer_now,
                                    handle.id(),
                                    timer_deadline,
                                )
                            });
                        }
                        state.timer_handle = Some(handle);
                        state.registered_partial = registered_partial;
                        armed = true;
                    } else if waker_changed {
                        // Update existing timer with new waker
                        if let Some(handle) = state.timer_handle.take() {
                            let old_id = handle.id();
                            let mut new_handle = timer.update(
                                &handle,
                                timer_deadline,
                                readiness_waker(Arc::clone(&self.ready), cx.waker().clone()),
                            );
                            // `update` returns a handle the wheel has already
                            // retired unchanged and registers nothing: the timer
                            // fired after this poll checked `ready`, and its wake
                            // goes to the previous waker only. Wake this poller if
                            // the fire has landed; otherwise register this waker
                            // afresh, so the fire still reaches it
                            // (br-asupersync-2u7bpm L3). Compare whole handles:
                            // a successful update reuses the slab id with a new
                            // generation.
                            if new_handle == handle {
                                if self.ready.load(Ordering::Acquire) {
                                    cx.waker().wake_by_ref();
                                } else {
                                    new_handle = timer.register(
                                        timer_deadline,
                                        readiness_waker(
                                            Arc::clone(&self.ready),
                                            cx.waker().clone(),
                                        ),
                                    );
                                }
                            }
                            if let Some(trace) = trace.as_ref() {
                                trace.record_event(|seq| {
                                    TraceEvent::timer_cancelled(seq, timer_now, old_id)
                                });
                                trace.record_event(|seq| {
                                    TraceEvent::timer_scheduled(
                                        seq,
                                        timer_now,
                                        new_handle.id(),
                                        timer_deadline,
                                    )
                                });
                            }
                            state.timer_handle = Some(new_handle);
                            state.registered_partial = registered_partial;
                            armed = true;
                        }
                    }

                    // If this Sleep just (re)armed on the process-global shared
                    // fallback timer, wake its pump so it re-parks to the
                    // possibly-sooner next deadline. Arming a sooner timer MUST
                    // unpark the pump or the wakeup waits for the prior park.
                    if armed && is_global_fallback_driver(timer) {
                        global_fallback_timer().pump.unpark();
                    }
                } else {
                    // No timer driver; cancel any existing registration.
                    if let Some(prev_driver) = state.timer_driver.take() {
                        if let Some(old_handle) = state.timer_handle.take() {
                            if let Some(trace) = trace.as_ref() {
                                trace.record_event(|seq| {
                                    TraceEvent::timer_cancelled(
                                        seq,
                                        prev_driver.now(),
                                        old_handle.id(),
                                    )
                                });
                            }
                            let _ = prev_driver.cancel(&old_handle);
                        }
                    }

                    if state.fallback.is_none() {
                        // Fallback: spawn background thread for timing.
                        //
                        // The JoinHandle is kept, never joined while the thread runs (poll must
                        // not block) and never detached: detaching an exiting thread can fault
                        // on glibc < 2.43 (GitHub #80). spawn_blocking::reap_threads reaps it.
                        let deadline = self.deadline;
                        let getter = self.time_getter.unwrap_or(wall_now);
                        let polls_custom_time_getter = self.time_getter.is_some();
                        let state_clone = Arc::clone(&self.state);

                        let stop = Arc::new(AtomicBool::new(false));
                        let stop_for_thread = Arc::clone(&stop);
                        let completed = Arc::new(AtomicBool::new(false));
                        let completed_for_thread = Arc::clone(&completed);
                        let ready_for_thread = Arc::clone(&self.ready);
                        crate::runtime::metrics::record_timer_thread_spawned();
                        // ubs:ignore - the JoinHandle is kept and reaped (reap_threads), not joined in poll
                        let handle = std::thread::spawn(move || {
                            // Allow prompt cancellation via `unpark()`.
                            while !stop_for_thread.load(Ordering::Acquire) {
                                let current = getter();
                                if current >= deadline {
                                    break;
                                }
                                let remaining =
                                    deadline.as_nanos().saturating_sub(current.as_nanos());
                                let mut park_dur = Duration::from_nanos(remaining);
                                if polls_custom_time_getter {
                                    // Custom logical clocks can jump forward without any
                                    // timer-driver wakeup. Poll them on short real-time slices
                                    // so the future becomes ready promptly after the injected
                                    // clock advances instead of sleeping until wall time catches up.
                                    park_dur = park_dur.min(CUSTOM_TIME_GETTER_POLL_INTERVAL);
                                }
                                std::thread::park_timeout(park_dur);
                            }

                            if stop_for_thread.load(Ordering::Acquire) {
                                return;
                            }

                            ready_for_thread.store(true, Ordering::Release);
                            let waker = {
                                let mut state = state_clone.lock();
                                // Reset/completion detaches without joining. A
                                // retired thread can therefore reach this point
                                // after a replacement registration installed a
                                // new waker. Only the still-current fallback may
                                // consume that shared waker.
                                let current = state
                                    .fallback
                                    .as_ref()
                                    .map(|fallback| Arc::clone(&fallback.stop));
                                fallback_waker_for_completion(
                                    current.as_ref(),
                                    &stop_for_thread,
                                    &mut state.waker,
                                )
                            };
                            if let Some(waker) = waker {
                                waker.wake();
                            }
                            completed_for_thread.store(true, Ordering::Release);
                        });
                        let thread = handle.thread().clone();
                        state.fallback = Some(FallbackThread {
                            stop,
                            completed,
                            thread,
                            join: handle,
                        });
                    }
                }

                drop(state);
                // Cleanly reap finished threads instead of detaching them.
                // Since they are verified finished, join() will not block.
                for handle in finished_handles {
                    let _ = handle.join();
                }

                Poll::Pending
            }
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.cancel_active_registration();
    }
}

#[inline]
fn fallback_waker_for_completion(
    current: Option<&Arc<AtomicBool>>,
    registration: &Arc<AtomicBool>,
    waker: &mut Option<Waker>,
) -> Option<Waker> {
    if current.is_some_and(|current| Arc::ptr_eq(current, registration)) {
        waker.take()
    } else {
        // The registration was detached by reset, completion, or a switch to
        // a timer driver after its final stop check. Its ready latch is still
        // authoritative across a driver transition, so preserve wake delivery;
        // cloning avoids stealing the replacement registration's waker. After
        // reset this is merely a permitted spurious wake of the reused future.
        waker.clone()
    }
}

impl Clone for Sleep {
    fn clone(&self) -> Self {
        Self {
            deadline: self.deadline,
            time_getter: self.time_getter,
            bound_timer_driver: self.bound_timer_driver.clone(),
            polled: std::sync::atomic::AtomicBool::new(false), // Fresh clone hasn't been polled
            completed: std::sync::atomic::AtomicBool::new(false),
            ready: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                fallback: None,
                zombie_fallbacks: Vec::new(),
                timer_handle: None, // Fresh clone has no timer registration
                timer_driver: None,
                registered_partial: false,
            })),
        }
    }
}

/// Creates a `Sleep` future that completes after the given duration.
///
/// This function requires a current time to compute the deadline.
/// For use without explicit time, see [`sleep_until`].
///
/// # Arguments
///
/// * `now` - The current time
/// * `duration` - How long to sleep
///
/// # Example
///
/// ```
/// use asupersync::time::sleep;
/// use asupersync::types::Time;
/// use std::time::Duration;
///
/// let now = Time::from_secs(10);
/// let sleep_future = sleep(now, Duration::from_millis(100));
/// assert_eq!(sleep_future.deadline(), Time::from_nanos(10_100_000_000));
/// ```
#[must_use]
#[inline]
pub fn sleep(now: Time, duration: Duration) -> Sleep {
    Sleep::after(now, duration)
}

/// Creates a `Sleep` future that completes at the given deadline.
///
/// # Arguments
///
/// * `deadline` - The absolute time when the sleep completes
///
/// # Example
///
/// ```
/// use asupersync::time::sleep_until;
/// use asupersync::types::Time;
///
/// let sleep_future = sleep_until(Time::from_secs(5));
/// assert_eq!(sleep_future.deadline(), Time::from_secs(5));
/// ```
#[must_use]
#[inline]
pub fn sleep_until(deadline: Time) -> Sleep {
    Sleep::new(deadline)
}

#[cfg(test)]
#[path = "sleep_inline_tests.rs"]
mod tests;
