//! Sleep future for delaying execution.
//!
//! The [`Sleep`] future completes after a deadline has passed.
//! It works with both wall clock time (production) and virtual time (lab).
//!
//! # Timer Driver Integration
//!
//! When a timer driver is available via `Cx::current()`, Sleep registers
//! with the driver's timer wheel for efficient wakeups. Without a driver,
//! Sleep falls back to spawning an OS thread for timing (less efficient).

use crate::cx::Cx;
use crate::time::{TimerDriverHandle, TimerHandle};
use crate::trace::TraceEvent;
use crate::types::Time;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

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
#[must_use]
pub fn process_epoch() -> Instant {
    *START_TIME.get_or_init(Instant::now)
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
             replay-deterministic in the lab runtime (RuntimeBuilder installs one by default, or \
             call RuntimeBuilder::enable_time() / Sleep::with_timer_driver(...))."
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
    let start = process_epoch();
    let now = Instant::now();
    if now < start {
        Time::ZERO
    } else {
        let elapsed = now.duration_since(start);
        Time::from_nanos(duration_to_nanos(elapsed))
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
/// # Cancel Safety
///
/// `Sleep` is cancel-safe. Dropping it simply stops the wait with no
/// side effects. It can be recreated with the same or a different deadline.
///
/// # Example
///
/// ```ignore
/// use asupersync::time::sleep;
/// use std::time::Duration;
///
/// // Sleep for 100 milliseconds
/// sleep(Duration::from_millis(100)).await;
///
/// // Sleep until a specific time
/// use asupersync::time::sleep_until;
/// use asupersync::types::Time;
/// sleep_until(Time::from_secs(5)).await;
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
            let mut handles = std::mem::take(&mut state.zombie_fallbacks);
            if let Some(fallback) = state.fallback.take() {
                request_stop_fallback(&fallback);
                handles.push(fallback.join);
            }
            (
                state.timer_handle.take(),
                state.timer_driver.take(),
                handles,
            )
        };

        // Intentionally detach threads to avoid blocking the executor
        drop(fallback_handles);

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
        self.deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        self.polled
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.completed
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.ready = Arc::new(AtomicBool::new(false));
        let (handle, driver, fallback_handles) = {
            let mut state = self.state.lock();
            let mut handles = std::mem::take(&mut state.zombie_fallbacks);
            if let Some(fallback) = state.fallback.take() {
                request_stop_fallback(&fallback);
                handles.push(fallback.join);
            }
            (
                state.timer_handle.take(),
                state.timer_driver.take(),
                handles,
            )
        };

        // Intentionally detach threads to avoid blocking the executor
        drop(fallback_handles);

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

    fn complete_ready_registration(&self, now: Time, timer_driver: Option<TimerDriverHandle>) {
        let (handle, driver) = {
            let mut state = self.state.lock();
            (state.timer_handle.take(), state.timer_driver.clone())
        };
        if let Some(handle) = handle {
            let trace = Cx::current().and_then(|current| current.trace_buffer());
            if let Some(trace) = trace.as_ref() {
                let fired_at = now.max(self.deadline);
                trace.record_event(|seq| TraceEvent::timer_fired(seq, fired_at, handle.id()));
            }
            if let Some(driver) = driver.or(timer_driver) {
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
        if self.ready.swap(false, Ordering::AcqRel) || now >= self.deadline {
            self.completed
                .store(true, std::sync::atomic::Ordering::Release);
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    pub(crate) fn poll_ready_with_time(&self, now: Time) -> Poll<()> {
        assert!(
            !self.completed.load(std::sync::atomic::Ordering::Acquire),
            "Sleep polled after completion"
        );
        if self.ready.swap(false, Ordering::AcqRel) || now >= self.deadline {
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

impl Future for Sleep {
    type Output = ();

    #[allow(clippy::too_many_lines)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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

        match self.poll_with_time(now) {
            Poll::Ready(()) => {
                // Cancel any registered timer on completion.
                self.complete_ready_registration(now, timer_driver.clone());
                Poll::Ready(())
            }
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

                    let mut armed = false;
                    if state.timer_handle.is_none() {
                        // Register new timer
                        let handle = timer.register(
                            self.deadline,
                            readiness_waker(Arc::clone(&self.ready), cx.waker().clone()),
                        );
                        if let Some(trace) = trace.as_ref() {
                            trace.record_event(|seq| {
                                TraceEvent::timer_scheduled(seq, now, handle.id(), self.deadline)
                            });
                        }
                        state.timer_handle = Some(handle);
                        armed = true;
                    } else if waker_changed {
                        // Update existing timer with new waker
                        if let Some(handle) = state.timer_handle.take() {
                            let old_id = handle.id();
                            let new_handle = timer.update(
                                &handle,
                                self.deadline,
                                readiness_waker(Arc::clone(&self.ready), cx.waker().clone()),
                            );
                            if let Some(trace) = trace.as_ref() {
                                trace.record_event(|seq| {
                                    TraceEvent::timer_cancelled(seq, now, old_id)
                                });
                                trace.record_event(|seq| {
                                    TraceEvent::timer_scheduled(
                                        seq,
                                        now,
                                        new_handle.id(),
                                        self.deadline,
                                    )
                                });
                            }
                            state.timer_handle = Some(new_handle);
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
                        // IMPORTANT: We intentionally drop the JoinHandle (detaching the thread)
                        // rather than joining it, so we don't block the executor. OS threads
                        // naturally clean themselves up upon exit.
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
                        // ubs:ignore - intentional detach by dropping JoinHandle in Drop to avoid blocking executor
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
                            let waker = state_clone.lock().waker.take();
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
        let (handle, driver, fallback_handles) = {
            let mut state = self.state.lock();
            // Clear waker to release task reference immediately, preventing
            // unbounded lifetime extension if background thread is running.
            state.waker = None;
            let mut handles = std::mem::take(&mut state.zombie_fallbacks);
            if let Some(fallback) = state.fallback.take() {
                request_stop_fallback(&fallback);
                handles.push(fallback.join);
            }
            (
                state.timer_handle.take(),
                state.timer_driver.take(),
                handles,
            )
        };

        // Intentionally detach threads to avoid blocking the executor
        drop(fallback_handles);

        if let (Some(handle), Some(driver)) = (handle, driver) {
            let trace = Cx::current().and_then(|current| current.trace_buffer());
            if let Some(trace) = trace.as_ref() {
                let now = driver.now();
                trace.record_event(|seq| TraceEvent::timer_cancelled(seq, now, handle.id()));
            }
            let _ = driver.cancel(&handle);
        }
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
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::task::{Context, Waker};

    // =========================================================================
    // Construction Tests
    // =========================================================================

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    static CURRENT_TIME: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn wall_now_falls_back_when_current_cx_has_no_timer_driver() {
        init_test("wall_now_falls_back_when_current_cx_has_no_timer_driver");

        let cx = Cx::new(
            RegionId::new_for_test(0, 6),
            TaskId::new_for_test(0, 6),
            Budget::INFINITE,
        );
        let _guard = Cx::set_current(Some(cx));

        let first = wall_now();
        let second = wall_now();

        crate::assert_with_log!(
            second >= first,
            "wall clock remains monotonic",
            true,
            second >= first
        );
        crate::test_complete!("wall_now_falls_back_when_current_cx_has_no_timer_driver");
    }

    /// Regression: the production [`WallClock`](crate::time::driver::WallClock)
    /// timer driver and `wall_now()`'s capability-free fallback must measure
    /// elapsed time from the *same* process epoch.
    ///
    /// Before the fix each `WallClock::new()` captured its own
    /// `Instant::now()` epoch, distinct from `wall_now()`'s `START_TIME`
    /// fallback epoch. A request-budget deadline computed via `wall_now()` was
    /// then evaluated by the deadline monitor against `timer_driver.now()` on a
    /// *different* epoch; once process uptime exceeded the request timeout every
    /// such request was born already past its deadline and cancelled
    /// immediately — surfacing as spurious "pool acquire cancelled" DB failures
    /// under load.
    #[test]
    fn wall_clock_instances_share_process_epoch() {
        use crate::time::driver::{TimeSource, WallClock};
        init_test("wall_clock_instances_share_process_epoch");

        let first = WallClock::new();
        std::thread::sleep(Duration::from_millis(20));
        let second = WallClock::new();

        let a = first.now().as_nanos();
        let b = second.now().as_nanos();

        // Same shared epoch => readings taken back-to-back agree within a small
        // delta, NOT separated by the 20ms gap a per-instance epoch produces.
        let delta = a.abs_diff(b);
        crate::assert_with_log!(
            delta < 5_000_000,
            "WallClock instances share one process epoch (delta < 5ms)",
            true,
            delta < 5_000_000
        );
        // The later clock measures from the earlier shared epoch, so it observes
        // the 20ms that elapsed before it was even constructed.
        crate::assert_with_log!(
            b >= 15_000_000,
            "later WallClock observes pre-construction elapsed time",
            true,
            b >= 15_000_000
        );
        crate::test_complete!("wall_clock_instances_share_process_epoch");
    }

    fn get_time() -> Time {
        Time::from_nanos(CURRENT_TIME.load(Ordering::SeqCst))
    }

    #[test]
    fn new_creates_sleep_with_deadline() {
        init_test("new_creates_sleep_with_deadline");
        let sleep = Sleep::new(Time::from_secs(5));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            sleep.deadline()
        );
        crate::assert_with_log!(!sleep.was_polled(), "not polled", false, sleep.was_polled());
        crate::test_complete!("new_creates_sleep_with_deadline");
    }

    #[test]
    fn after_computes_deadline() {
        init_test("after_computes_deadline");
        let now = Time::from_secs(10);
        let sleep = Sleep::after(now, Duration::from_secs(5));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(15),
            "deadline",
            Time::from_secs(15),
            sleep.deadline()
        );
        crate::test_complete!("after_computes_deadline");
    }

    #[test]
    fn after_saturates() {
        init_test("after_saturates");
        let now = Time::from_nanos(u64::MAX - 1000);
        let sleep = Sleep::after(now, Duration::from_secs(1));
        crate::assert_with_log!(
            sleep.deadline() == Time::MAX,
            "deadline",
            Time::MAX,
            sleep.deadline()
        );
        crate::test_complete!("after_saturates");
    }

    #[test]
    fn sleep_function() {
        init_test("sleep_function");
        let now = Time::from_millis(100);
        let s = sleep(now, Duration::from_millis(50));
        crate::assert_with_log!(
            s.deadline() == Time::from_millis(150),
            "deadline",
            Time::from_millis(150),
            s.deadline()
        );
        crate::test_complete!("sleep_function");
    }

    #[test]
    fn sleep_until_function() {
        init_test("sleep_until_function");
        let s = sleep_until(Time::from_secs(42));
        crate::assert_with_log!(
            s.deadline() == Time::from_secs(42),
            "deadline",
            Time::from_secs(42),
            s.deadline()
        );
        crate::test_complete!("sleep_until_function");
    }

    // =========================================================================
    // Time Getter Tests
    // =========================================================================

    #[test]
    fn with_time_getter() {
        init_test("with_time_getter");
        CURRENT_TIME.store(0, Ordering::SeqCst);

        let sleep = Sleep::with_time_getter(Time::from_secs(5), get_time);

        // Time is 0, should be pending
        let elapsed = sleep.is_elapsed(get_time());
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);

        // Advance time past deadline
        CURRENT_TIME.store(6_000_000_000, Ordering::SeqCst);
        let elapsed = sleep.is_elapsed(get_time());
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("with_time_getter");
    }

    #[test]
    fn custom_time_getter_wakes_promptly_after_logical_time_advance() {
        init_test("custom_time_getter_wakes_promptly_after_logical_time_advance");
        CURRENT_TIME.store(0, Ordering::SeqCst);

        let woken = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woken));
        let mut task_cx = Context::from_waker(&waker);
        let mut sleep = Sleep::with_time_getter(Time::from_secs(10), get_time);

        let first = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first pending",
            true,
            first.is_pending()
        );

        CURRENT_TIME.store(Time::from_secs(10).as_nanos(), Ordering::SeqCst);

        let wait_deadline = Instant::now() + Duration::from_millis(500);
        while !woken.load(Ordering::SeqCst) && Instant::now() < wait_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }

        let woke = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(woke, "waker fired", true, woke);

        let second = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("custom_time_getter_wakes_promptly_after_logical_time_advance");
    }

    // =========================================================================
    // is_elapsed and remaining Tests
    // =========================================================================

    #[test]
    fn is_elapsed_before_deadline() {
        init_test("is_elapsed_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(5));
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);
        crate::test_complete!("is_elapsed_before_deadline");
    }

    #[test]
    fn is_elapsed_at_deadline() {
        init_test("is_elapsed_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(10));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("is_elapsed_at_deadline");
    }

    #[test]
    fn is_elapsed_after_deadline() {
        init_test("is_elapsed_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(15));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("is_elapsed_after_deadline");
    }

    #[test]
    fn remaining_before_deadline() {
        init_test("remaining_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(7));
        crate::assert_with_log!(
            remaining == Duration::from_secs(3),
            "remaining",
            Duration::from_secs(3),
            remaining
        );
        crate::test_complete!("remaining_before_deadline");
    }

    #[test]
    fn remaining_at_deadline() {
        init_test("remaining_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(10));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_at_deadline");
    }

    #[test]
    fn remaining_after_deadline() {
        init_test("remaining_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(15));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_after_deadline");
    }

    // =========================================================================
    // poll_with_time Tests
    // =========================================================================

    #[test]
    fn poll_with_time_before_deadline() {
        init_test("poll_with_time_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());
        crate::test_complete!("poll_with_time_before_deadline");
    }

    #[test]
    fn poll_with_time_at_deadline() {
        init_test("poll_with_time_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_at_deadline");
    }

    #[test]
    fn poll_with_time_after_deadline() {
        init_test("poll_with_time_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(15));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_after_deadline");
    }

    #[test]
    fn poll_with_time_zero_deadline() {
        init_test("poll_with_time_zero_deadline");
        let sleep = Sleep::new(Time::ZERO);
        let poll = sleep.poll_with_time(Time::ZERO);
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_zero_deadline");
    }

    #[test]
    fn poll_ready_with_time_before_deadline_does_not_register() {
        init_test("poll_ready_with_time_before_deadline_does_not_register");
        let sleep = Sleep::new(Time::from_secs(10));

        let poll = sleep.poll_ready_with_time(Time::from_secs(5));

        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(!sleep.was_polled(), "not polled", false, sleep.was_polled());
        let state = sleep.state.lock();
        crate::assert_with_log!(
            state.timer_handle.is_none(),
            "timer handle absent",
            true,
            state.timer_handle.is_none()
        );
        crate::assert_with_log!(
            state.fallback.is_none(),
            "fallback absent",
            true,
            state.fallback.is_none()
        );
        crate::test_complete!("poll_ready_with_time_before_deadline_does_not_register");
    }

    #[test]
    fn poll_ready_with_time_at_deadline_completes() {
        init_test("poll_ready_with_time_at_deadline_completes");
        let sleep = Sleep::new(Time::from_secs(10));

        let poll = sleep.poll_ready_with_time(Time::from_secs(10));

        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());
        crate::test_complete!("poll_ready_with_time_at_deadline_completes");
    }

    #[test]
    fn poll_with_time_repoll_after_completion_panics() {
        init_test("poll_with_time_repoll_after_completion_panics");
        let sleep = Sleep::new(Time::from_secs(10));

        let first = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let repoll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sleep.poll_with_time(Time::from_secs(10));
        }));
        crate::assert_with_log!(repoll.is_err(), "repoll panics", true, repoll.is_err());

        crate::test_complete!("poll_with_time_repoll_after_completion_panics");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_changes_deadline() {
        init_test("reset_changes_deadline");
        let mut sleep = Sleep::new(Time::from_secs(10));

        // Poll it
        let _ = sleep.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());

        // Reset
        sleep.reset(Time::from_secs(20));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(20),
            "deadline",
            Time::from_secs(20),
            sleep.deadline()
        );
        crate::assert_with_log!(
            !sleep.was_polled(),
            "reset clears polled",
            false,
            sleep.was_polled()
        ); // Reset clears polled flag
        crate::test_complete!("reset_changes_deadline");
    }

    #[test]
    fn reset_after_changes_deadline() {
        init_test("reset_after_changes_deadline");
        let mut sleep = Sleep::new(Time::from_secs(10));
        sleep.reset_after(Time::from_secs(5), Duration::from_secs(3));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(8),
            "deadline",
            Time::from_secs(8),
            sleep.deadline()
        );
        crate::test_complete!("reset_after_changes_deadline");
    }

    #[test]
    fn reset_after_completion_allows_sleep_reuse() {
        init_test("reset_after_completion_allows_sleep_reuse");
        let mut sleep = Sleep::new(Time::from_secs(10));

        let first = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        sleep.reset(Time::from_secs(20));

        let second = sleep.poll_with_time(Time::from_secs(15));
        crate::assert_with_log!(
            second.is_pending(),
            "pending after reset before deadline",
            true,
            second.is_pending()
        );

        let third = sleep.poll_with_time(Time::from_secs(20));
        crate::assert_with_log!(
            third.is_ready(),
            "ready after reset",
            true,
            third.is_ready()
        );

        crate::test_complete!("reset_after_completion_allows_sleep_reuse");
    }

    // =========================================================================
    // Timer Driver Integration Tests
    // =========================================================================

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn waker_that_sets(flag: Arc<AtomicBool>) -> Waker {
        struct FlagWaker {
            flag: Arc<AtomicBool>,
        }

        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }
        }

        Waker::from(Arc::new(FlagWaker { flag }))
    }

    #[test]
    fn drop_cancels_timer_registration() {
        init_test("drop_cancels_timer_registration");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut sleep).poll(&mut cx);
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "timer registered",
            1,
            timer.pending_count()
        );

        drop(sleep);

        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer cancelled on drop",
            0,
            timer.pending_count()
        );
        crate::test_complete!("drop_cancels_timer_registration");
    }

    #[test]
    fn reset_cancels_old_timer_and_re_registers_on_poll() {
        init_test("reset_cancels_old_timer_and_re_registers_on_poll");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_secs(5));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "first timer registration",
            1,
            timer.pending_count()
        );

        sleep.reset(Time::from_secs(10));
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "reset cancels previous timer",
            0,
            timer.pending_count()
        );
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(10),
            "deadline updated on reset",
            Time::from_secs(10),
            sleep.deadline()
        );

        let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            second_poll.is_pending(),
            "second poll pending after reset",
            true,
            second_poll.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "timer re-registered after reset",
            1,
            timer.pending_count()
        );

        clock.set(Time::from_secs(9));
        let fired_before_deadline = timer.process_timers();
        crate::assert_with_log!(
            fired_before_deadline == 0,
            "no timers fire before new deadline",
            0,
            fired_before_deadline
        );

        clock.set(Time::from_secs(10));
        let _ = timer.process_timers();
        let ready_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            ready_poll.is_ready(),
            "sleep ready at reset deadline",
            true,
            ready_poll.is_ready()
        );
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer registration cleared on completion",
            0,
            timer.pending_count()
        );

        crate::test_complete!("reset_cancels_old_timer_and_re_registers_on_poll");
    }

    #[test]
    #[should_panic(expected = "Sleep polled after completion")]
    fn future_repoll_after_completion_panics() {
        init_test("future_repoll_after_completion_panics");

        let mut sleep = Sleep::new(Time::from_secs(0));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let _ = Pin::new(&mut sleep).poll(&mut task_cx);

        crate::test_complete!("future_repoll_after_completion_panics");
    }

    #[test]
    fn poll_with_new_timer_driver_migrates_registration() {
        init_test("poll_with_new_timer_driver_migrates_registration");

        let clock1 = Arc::new(VirtualClock::new());
        let timer1 = TimerDriverHandle::with_virtual_clock(clock1);
        let cx1 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer1.clone()),
            None,
        );
        let _guard1 = Cx::set_current(Some(cx1));

        let mut sleep = Sleep::after(timer1.now(), Duration::from_secs(5));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer1.pending_count() == 1,
            "timer1 has registration",
            1,
            timer1.pending_count()
        );

        let clock2 = Arc::new(VirtualClock::new());
        let timer2 = TimerDriverHandle::with_virtual_clock(clock2);
        let cx2 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 2),
            TaskId::new_for_test(0, 2),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer2.clone()),
            None,
        );
        {
            let _guard2 = Cx::set_current(Some(cx2));

            let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                second_poll.is_pending(),
                "second poll pending on new driver",
                true,
                second_poll.is_pending()
            );
            crate::assert_with_log!(
                timer1.pending_count() == 0,
                "timer1 registration canceled after migration",
                0,
                timer1.pending_count()
            );
            crate::assert_with_log!(
                timer2.pending_count() == 1,
                "timer2 owns migrated registration",
                1,
                timer2.pending_count()
            );

            drop(sleep);
            crate::assert_with_log!(
                timer2.pending_count() == 0,
                "drop cancels migrated timer registration",
                0,
                timer2.pending_count()
            );
        }

        crate::test_complete!("poll_with_new_timer_driver_migrates_registration");
    }

    #[test]
    fn poll_after_timer_fire_stays_ready_across_driver_migration() {
        init_test("poll_after_timer_fire_stays_ready_across_driver_migration");

        let clock1 = Arc::new(VirtualClock::new());
        let timer1 = TimerDriverHandle::with_virtual_clock(clock1.clone());
        let cx1 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 3),
            TaskId::new_for_test(0, 3),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer1.clone()),
            None,
        );
        let _guard1 = Cx::set_current(Some(cx1));

        let mut sleep = Sleep::after(timer1.now(), Duration::from_secs(5));
        let woke = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woke));
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );

        clock1.set(Time::from_secs(6));
        let fired = timer1.process_timers();
        crate::assert_with_log!(fired == 1, "old driver fires timer once", 1usize, fired);
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "timer wake reached task waker",
            true,
            woke.load(Ordering::SeqCst)
        );

        let clock2 = Arc::new(VirtualClock::new());
        let timer2 = TimerDriverHandle::with_virtual_clock(clock2);
        let cx2 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 4),
            TaskId::new_for_test(0, 4),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer2.clone()),
            None,
        );
        let _guard2 = Cx::set_current(Some(cx2));

        let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "fired timer remains ready on new driver",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer2.pending_count() == 0,
            "new driver does not re-arm an already fired sleep",
            0,
            timer2.pending_count()
        );

        crate::test_complete!("poll_after_timer_fire_stays_ready_across_driver_migration");
    }

    #[test]
    fn poll_after_fallback_wake_stays_ready_on_driver() {
        init_test("poll_after_fallback_wake_stays_ready_on_driver");

        let _guard = Cx::set_current(None);

        let mut sleep = Sleep::after(wall_now(), Duration::from_millis(10));
        let woke = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woke));
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );

        let start = Instant::now();
        while !woke.load(Ordering::SeqCst) && start.elapsed() < Duration::from_millis(250) {
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "fallback thread wakes task",
            true,
            woke.load(Ordering::SeqCst)
        );

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 5),
            TaskId::new_for_test(0, 5),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard2 = Cx::set_current(Some(cx));

        let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "fallback wake remains ready after driver appears",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "driver does not re-arm an already fired fallback sleep",
            0,
            timer.pending_count()
        );

        crate::test_complete!("poll_after_fallback_wake_stays_ready_on_driver");
    }

    // =========================================================================
    // Clone Tests
    // =========================================================================

    #[test]
    fn clone_copies_deadline() {
        init_test("clone_copies_deadline");
        let original = Sleep::new(Time::from_secs(10));
        let cloned = original.clone();
        crate::assert_with_log!(
            original.deadline() == Time::from_secs(10),
            "original deadline",
            Time::from_secs(10),
            original.deadline()
        );
        crate::assert_with_log!(
            cloned.deadline() == Time::from_secs(10),
            "cloned deadline",
            Time::from_secs(10),
            cloned.deadline()
        );
        crate::test_complete!("clone_copies_deadline");
    }

    #[test]
    fn clone_has_fresh_polled_flag() {
        init_test("clone_has_fresh_polled_flag");
        let original = Sleep::new(Time::from_secs(10));
        let _ = original.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(
            original.was_polled(),
            "original polled",
            true,
            original.was_polled()
        );

        let cloned = original.clone();
        crate::assert_with_log!(
            original.was_polled(),
            "original still polled",
            true,
            original.was_polled()
        );
        crate::assert_with_log!(
            !cloned.was_polled(),
            "cloned not polled",
            false,
            cloned.was_polled()
        );
        crate::test_complete!("clone_has_fresh_polled_flag");
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn zero_duration_sleep() {
        init_test("zero_duration_sleep");
        let now = Time::from_secs(10);
        let sleep = sleep(now, Duration::ZERO);
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            sleep.deadline()
        );

        // Should be immediately ready
        let poll = sleep.poll_with_time(now);
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("zero_duration_sleep");
    }

    #[test]
    fn max_time_deadline() {
        init_test("max_time_deadline");
        let sleep = Sleep::new(Time::MAX);
        let poll = sleep.poll_with_time(Time::from_secs(1000));
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());

        // Only ready at MAX
        let poll = sleep.poll_with_time(Time::MAX);
        crate::assert_with_log!(poll.is_ready(), "ready at max", true, poll.is_ready());
        crate::test_complete!("max_time_deadline");
    }

    #[test]
    fn time_zero_deadline() {
        init_test("time_zero_deadline");
        let sleep = Sleep::new(Time::ZERO);

        // Any non-zero time is past deadline
        let poll = sleep.poll_with_time(Time::from_nanos(1));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("time_zero_deadline");
    }

    // =========================================================================
    // Metamorphic Testing: Sleep Cancel Relations
    // =========================================================================

    /// MR1: Cancellation idempotency - reset(reset(sleep)) ≡ reset(sleep)
    /// Tests that multiple resets to the same deadline are equivalent to a single reset.
    #[test]
    fn mr_cancel_idempotency() {
        init_test("mr_cancel_idempotency");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 100),
            TaskId::new_for_test(0, 100),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let initial_deadline = Time::from_secs(10);
        let reset_deadline = Time::from_secs(20);

        // Create two identical sleeps
        let mut sleep1 = Sleep::new(initial_deadline);
        let mut sleep2 = Sleep::new(initial_deadline);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Poll both to register timers
        let _ = Pin::new(&mut sleep1).poll(&mut task_cx);
        let _ = Pin::new(&mut sleep2).poll(&mut task_cx);

        // Reset once vs reset twice to same deadline
        sleep1.reset(reset_deadline); // Single reset
        sleep2.reset(reset_deadline); // Double reset (first)
        sleep2.reset(reset_deadline); // Double reset (second)

        // Both should behave identically
        crate::assert_with_log!(
            sleep1.deadline() == sleep2.deadline(),
            "deadlines equal after reset idempotency",
            sleep1.deadline(),
            sleep2.deadline()
        );
        crate::assert_with_log!(
            sleep1.was_polled() == sleep2.was_polled(),
            "polled state equal after reset idempotency",
            sleep1.was_polled(),
            sleep2.was_polled()
        );

        // Both should poll identically
        let poll1 = Pin::new(&mut sleep1).poll(&mut task_cx);
        let poll2 = Pin::new(&mut sleep2).poll(&mut task_cx);
        crate::assert_with_log!(
            poll1.is_pending() && poll2.is_pending(),
            "both pending after reset idempotency",
            true,
            poll1.is_pending() && poll2.is_pending()
        );

        // Fire both and check they complete identically
        clock.set(reset_deadline);
        let _ = timer.process_timers();
        let final1 = Pin::new(&mut sleep1).poll(&mut task_cx);
        let final2 = Pin::new(&mut sleep2).poll(&mut task_cx);
        crate::assert_with_log!(
            final1.is_ready() && final2.is_ready(),
            "both ready after timer fires",
            true,
            final1.is_ready() && final2.is_ready()
        );

        crate::test_complete!("mr_cancel_idempotency");
    }

    /// MR2: Cancel after fire is no-op
    /// Tests that operations on a completed Sleep have no effect.
    #[test]
    fn mr_cancel_after_fire_noop() {
        init_test("mr_cancel_after_fire_noop");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 101),
            TaskId::new_for_test(0, 101),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let deadline = Time::from_secs(5);
        let mut sleep = Sleep::new(deadline);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Poll to register timer
        let initial = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            initial.is_pending(),
            "initial poll pending",
            true,
            initial.is_pending()
        );

        // Fire the timer
        clock.set(deadline);
        let _ = timer.process_timers();
        let fired = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            fired.is_ready(),
            "sleep ready after timer fires",
            true,
            fired.is_ready()
        );

        // After completion, timer should be deregistered
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "no timers pending after completion",
            0,
            timer.pending_count()
        );

        // Now test that reset after completion works (creates fresh timer)
        let new_deadline = Time::from_secs(10);
        sleep.reset(new_deadline);
        crate::assert_with_log!(
            sleep.deadline() == new_deadline,
            "deadline updated after reset",
            new_deadline,
            sleep.deadline()
        );
        crate::assert_with_log!(
            !sleep.was_polled(),
            "polled flag cleared after reset",
            false,
            sleep.was_polled()
        );

        // Should be able to use normally after reset
        let after_reset = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            after_reset.is_pending(),
            "pending after reset on completed sleep",
            true,
            after_reset.is_pending()
        );

        crate::test_complete!("mr_cancel_after_fire_noop");
    }

    /// MR3: Reset-after-cancel yields fresh timer
    /// Tests that reset() creates a completely independent timer registration.
    #[test]
    fn mr_reset_after_cancel_fresh() {
        init_test("mr_reset_after_cancel_fresh");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 102),
            TaskId::new_for_test(0, 102),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let original_deadline = Time::from_secs(5);
        let reset_deadline = Time::from_secs(15);
        let mut sleep = Sleep::new(original_deadline);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Register original timer
        let _ = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "original timer registered",
            1,
            timer.pending_count()
        );

        // Reset cancels old timer and prepares for new one
        sleep.reset(reset_deadline);
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "reset cancels original timer",
            0,
            timer.pending_count()
        );
        crate::assert_with_log!(
            sleep.deadline() == reset_deadline,
            "deadline updated by reset",
            reset_deadline,
            sleep.deadline()
        );

        // Poll registers new timer
        let after_reset = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            after_reset.is_pending(),
            "pending after reset",
            true,
            after_reset.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "new timer registered after reset",
            1,
            timer.pending_count()
        );

        // Original deadline should not fire the reset timer
        clock.set(original_deadline);
        let original_fires = timer.process_timers();
        crate::assert_with_log!(
            original_fires == 0,
            "original deadline does not fire reset timer",
            0,
            original_fires
        );
        let still_pending = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            still_pending.is_pending(),
            "sleep still pending at original deadline",
            true,
            still_pending.is_pending()
        );

        // Reset deadline should fire
        clock.set(reset_deadline);
        let reset_fires = timer.process_timers();
        crate::assert_with_log!(
            reset_fires == 1,
            "reset deadline fires timer",
            1,
            reset_fires
        );
        let ready = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            ready.is_ready(),
            "sleep ready at reset deadline",
            true,
            ready.is_ready()
        );

        crate::test_complete!("mr_reset_after_cancel_fresh");
    }

    /// MR4: N sleeps with same deadline fire in deterministic order under LabRuntime
    /// Tests that timer firing order is consistent across multiple identical sleeps.
    #[test]
    fn mr_deterministic_order_same_deadline() {
        init_test("mr_deterministic_order_same_deadline");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 103),
            TaskId::new_for_test(0, 103),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let shared_deadline = Time::from_secs(10);
        let mut sleeps = Vec::new();
        let mut woke_flags = Vec::new();

        // Create multiple sleeps with same deadline and register them
        for i in 0..5 {
            let mut sleep = Sleep::new(shared_deadline);
            let woke = Arc::new(AtomicBool::new(false));
            let waker = waker_that_sets(Arc::clone(&woke));
            let mut task_cx = Context::from_waker(&waker);

            // Register each timer in order
            let poll = Pin::new(&mut sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                poll.is_pending(),
                &format!("sleep {} pending", i),
                true,
                poll.is_pending()
            );

            sleeps.push(sleep);
            woke_flags.push(woke);
        }

        crate::assert_with_log!(
            timer.pending_count() == 5,
            "all timers registered",
            5,
            timer.pending_count()
        );

        // Fire all timers at deadline
        clock.set(shared_deadline);
        let fired_count = timer.process_timers();
        crate::assert_with_log!(
            fired_count == 5,
            "all timers fire at deadline",
            5,
            fired_count
        );

        // All wakers should fire
        for (i, woke) in woke_flags.iter().enumerate() {
            crate::assert_with_log!(
                woke.load(Ordering::SeqCst),
                &format!("waker {} fired", i),
                true,
                woke.load(Ordering::SeqCst)
            );
        }

        // All sleeps should be ready when polled with fresh context
        for (i, sleep) in sleeps.iter_mut().enumerate() {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let ready = Pin::new(sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                ready.is_ready(),
                &format!("sleep {} ready after timer fire", i),
                true,
                ready.is_ready()
            );
        }

        crate::assert_with_log!(
            timer.pending_count() == 0,
            "no pending timers after completion",
            0,
            timer.pending_count()
        );

        crate::test_complete!("mr_deterministic_order_same_deadline");
    }

    /// MR5: Drop cancellation removes from wheel atomically
    /// Tests that dropping a Sleep cleanly removes its timer registration.
    #[test]
    fn mr_drop_removes_atomically() {
        init_test("mr_drop_removes_atomically");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 104),
            TaskId::new_for_test(0, 104),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer starts empty",
            0,
            timer.pending_count()
        );

        // Scope to control when Sleep is dropped
        {
            let mut sleep = Sleep::new(Time::from_secs(10));
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);

            // Register timer
            let poll = Pin::new(&mut sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                poll.is_pending(),
                "sleep pending after registration",
                true,
                poll.is_pending()
            );
            crate::assert_with_log!(
                timer.pending_count() == 1,
                "timer registered",
                1,
                timer.pending_count()
            );

            // Test timer is functional
            clock.set(Time::from_secs(5));
            let midway_fires = timer.process_timers();
            crate::assert_with_log!(
                midway_fires == 0,
                "timer does not fire before deadline",
                0,
                midway_fires
            );

            // Sleep will be dropped here, should cancel timer
        }

        // Verify timer was cancelled on drop
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer cancelled on drop",
            0,
            timer.pending_count()
        );

        // Verify timer wheel is clean - no spurious fires
        clock.set(Time::from_secs(10));
        let dropped_fires = timer.process_timers();
        crate::assert_with_log!(
            dropped_fires == 0,
            "no spurious fires after drop",
            0,
            dropped_fires
        );

        clock.set(Time::from_secs(15));
        let later_fires = timer.process_timers();
        crate::assert_with_log!(
            later_fires == 0,
            "timer wheel remains clean",
            0,
            later_fires
        );

        crate::test_complete!("mr_drop_removes_atomically");
    }

    /// Composite MR: Cancellation composition properties
    /// Tests that combinations of operations preserve metamorphic relations.
    #[test]
    fn mr_cancellation_composition() {
        init_test("mr_cancellation_composition");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 105),
            TaskId::new_for_test(0, 105),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Test: clone + reset preserves independence
        let original = Sleep::new(Time::from_secs(5));
        let mut cloned = original.clone();

        let _ = Pin::new(&mut cloned).poll(&mut task_cx);
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "cloned sleep registers independently",
            1,
            timer.pending_count()
        );

        cloned.reset(Time::from_secs(10));
        crate::assert_with_log!(
            original.deadline() == Time::from_secs(5),
            "original unaffected by clone reset",
            Time::from_secs(5),
            original.deadline()
        );
        crate::assert_with_log!(
            cloned.deadline() == Time::from_secs(10),
            "cloned deadline updated",
            Time::from_secs(10),
            cloned.deadline()
        );

        // Test: multiple resets + drop is equivalent to single drop
        let mut sleep1 = Sleep::new(Time::from_secs(1));
        let mut sleep2 = Sleep::new(Time::from_secs(1));

        let _ = Pin::new(&mut sleep1).poll(&mut task_cx);
        let _ = Pin::new(&mut sleep2).poll(&mut task_cx);
        crate::assert_with_log!(
            timer.pending_count() == 2,
            "reset clone was cancelled; direct sleeps registered",
            2,
            timer.pending_count()
        );

        // sleep1: reset multiple times then drop
        sleep1.reset(Time::from_secs(2));
        sleep1.reset(Time::from_secs(3));
        sleep1.reset(Time::from_secs(4));
        drop(sleep1);

        // sleep2: drop directly
        drop(sleep2);

        // Both should result in same timer state (only cloned sleep remains)
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "multiple resets + drop ≡ direct drop",
            0,
            timer.pending_count()
        );

        crate::test_complete!("mr_cancellation_composition");
    }

    #[test]
    fn off_cx_wall_clock_sleep_completes_via_shared_fallback() {
        init_test("off_cx_wall_clock_sleep_completes_via_shared_fallback");
        // No Cx is set on this thread, so Cx::current() is None: a wall-clock
        // sleep must route through the process-global shared fallback timer
        // (not a per-Sleep OS thread) and still fire
        // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5).
        crate::assert_with_log!(
            Cx::current().is_none(),
            "no ambient Cx",
            true,
            Cx::current().is_none()
        );
        let mut s = sleep(wall_now(), Duration::from_millis(20));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let give_up = Instant::now() + Duration::from_secs(2);
        loop {
            if Pin::new(&mut s).poll(&mut cx).is_ready() {
                break;
            }
            crate::assert_with_log!(
                Instant::now() < give_up,
                "off-Cx sleep fired within 2s",
                true,
                Instant::now() < give_up
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::test_complete!("off_cx_wall_clock_sleep_completes_via_shared_fallback");
    }

    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn off_cx_sleeps_share_one_fallback_thread() {
        init_test("off_cx_sleeps_share_one_fallback_thread");
        // N off-Cx wall-clock sleeps must register with the single shared
        // fallback driver, NOT spawn one OS thread each (the churn this fix
        // targets). Counters are process-global and the suite runs in parallel,
        // so assert robust bounds: registrations grow by >= N (they used the
        // driver), and thread spawns grow by < N (not one-per-sleep).
        let n: u64 = 8;
        let before = crate::runtime::metrics::snapshot();
        for _ in 0..n {
            let mut s = sleep(wall_now(), Duration::from_millis(5));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let give_up = Instant::now() + Duration::from_secs(2);
            loop {
                if Pin::new(&mut s).poll(&mut cx).is_ready() {
                    break;
                }
                assert!(Instant::now() < give_up, "off-Cx sleep stalled");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let after = crate::runtime::metrics::snapshot();
        let registered = after.timers_registered - before.timers_registered;
        let spawned = after.timer_threads_spawned - before.timer_threads_spawned;
        crate::assert_with_log!(
            registered >= n,
            "off-Cx sleeps registered with shared driver",
            true,
            registered >= n
        );
        crate::assert_with_log!(
            spawned < n,
            "shared pump, not one thread per sleep",
            true,
            spawned < n
        );
        crate::test_complete!("off_cx_sleeps_share_one_fallback_thread");
    }

    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn sleep_with_driver_registers_without_spawning_thread() {
        init_test("sleep_with_driver_registers_without_spawning_thread");
        // Positive counterpart to the off-Cx fallback tests: a Sleep polled WITH
        // a bound timer driver must register on the wheel and spawn ZERO OS
        // threads. This is the premise of the whole fix — when a driver IS
        // installed (the normal RuntimeBuilder / enable_time path) there is no
        // per-Sleep churn (br-asupersync-runtime-cpu-overhaul-5vt09v.3.6).
        let driver = TimerDriverHandle::with_wall_clock();
        let deadline = Time::from_nanos(
            driver.now().as_nanos() + duration_to_nanos(Duration::from_millis(100)),
        );
        let before = crate::runtime::metrics::snapshot();
        let mut s = Sleep::with_timer_driver(deadline, driver.clone());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        // First poll registers on the wheel and returns Pending (no thread spawn).
        let first = Pin::new(&mut s).poll(&mut cx);
        crate::assert_with_log!(
            first.is_pending(),
            "driver-backed sleep pending on first poll",
            true,
            first.is_pending()
        );
        let mid = crate::runtime::metrics::snapshot();
        let spawned = mid.timer_threads_spawned - before.timer_threads_spawned;
        crate::assert_with_log!(
            spawned == 0,
            "driver-backed sleep spawns no OS thread",
            0u64,
            spawned
        );
        let registered = mid.timers_registered - before.timers_registered;
        crate::assert_with_log!(
            registered >= 1,
            "driver-backed sleep registered on the wheel",
            true,
            registered >= 1
        );
        // Drive it to completion through the (passive) wall-clock driver so the
        // registration is cleaned up and we prove it still fires.
        let give_up = Instant::now() + Duration::from_secs(2);
        loop {
            let _ = driver.process_timers();
            if Pin::new(&mut s).poll(&mut cx).is_ready() {
                break;
            }
            assert!(Instant::now() < give_up, "driver-backed sleep stalled");
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::test_complete!("sleep_with_driver_registers_without_spawning_thread");
    }

    #[test]
    fn missing_timer_driver_warns_exactly_once() {
        init_test("missing_timer_driver_warns_exactly_once");
        // The fallback warn must fire on the FIRST take and never again
        // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5). Test the once-claim
        // primitive against a LOCAL flag so the assertion is deterministic and
        // independent of process-global state / parallel test ordering (the real
        // call site uses the module-global FALLBACK_TIMER_WARNED, which other
        // off-Cx tests may have already flipped).
        let flag = AtomicBool::new(false);
        let first = claim_first_call(&flag);
        crate::assert_with_log!(first, "first call claims the warn", true, first);
        // Every subsequent call must observe the flag already set.
        for _ in 0..5 {
            let again = claim_first_call(&flag);
            crate::assert_with_log!(!again, "subsequent calls do not re-warn", false, again);
        }
        // Calling the real warn helper must not panic regardless of whether the
        // process-global flag was already consumed by another test.
        warn_missing_timer_driver_once();
        warn_missing_timer_driver_once();
        crate::test_complete!("missing_timer_driver_warns_exactly_once");
    }
}
