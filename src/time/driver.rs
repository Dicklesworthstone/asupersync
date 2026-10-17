//! Timer driver for managing sleep/timeout registration.
//!
//! The timer driver provides the time source and manages timer registrations
//! using a hierarchical timing wheel. It supports both production (wall clock)
//! and virtual (lab) time.

use crate::runtime::reactor::Reactor;
use crate::types::Time;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::Waker;
use std::time::Duration;

use super::wheel::{CoalescingConfig, TimerWheel, TimerWheelConfig, WakerBatch};

#[inline]
fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Time source abstraction for getting the current time.
///
/// This trait allows the timer driver to work with both wall clock time
/// (production) and virtual time (lab testing).
pub trait TimeSource: Send + Sync {
    /// Returns the current time.
    fn now(&self) -> Time;
}

/// Wall clock time source for production use.
///
/// Uses `std::time::Instant` internally, converting to our `Time` type.
/// The epoch is the shared process epoch (see `sleep::process_epoch`),
/// NOT a fresh `Instant::now()` per instance, so that `WallClock::now()` and
/// `wall_now()`'s fallback path return the same `Time` for the same wall
/// moment. This keeps deadlines computed via `wall_now()` (e.g. request
/// budgets) comparable with the timer-driver clock the deadline monitor reads.
#[derive(Debug)]
pub struct WallClock {
    /// The shared process epoch this clock measures elapsed time from.
    epoch: std::time::Instant,
}

impl WallClock {
    /// Creates a new wall clock time source anchored to the shared process
    /// epoch.
    ///
    /// All `WallClock` instances share one epoch (the first wall-clock time
    /// source or `wall_now()` fallback to run claims it). This guarantees the
    /// production timer driver and `wall_now()` agree, preventing skewed
    /// deadline evaluation. See `sleep::process_epoch`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: super::sleep::process_epoch(),
        }
    }
}

impl Default for WallClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for WallClock {
    fn now(&self) -> Time {
        let elapsed = self.epoch.elapsed();
        Time::from_nanos(duration_to_nanos_saturating(elapsed))
    }
}

/// Browser-oriented monotonic clock configuration.
///
/// The browser clock adapter ingests host time samples (for example
/// `performance.now()`) and maps them onto Asupersync `Time` while:
///
/// - preserving monotonicity even if host samples regress,
/// - smoothing tiny jitter via a minimum-step floor, and
/// - bounding large catch-up jumps (for background-tab throttling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserClockConfig {
    /// Maximum monotonic advancement applied per host sample.
    ///
    /// Set to `Duration::ZERO` to disable capping and apply full deltas.
    pub max_forward_step: Duration,
    /// Minimum delta applied immediately; smaller deltas are accumulated.
    pub jitter_floor: Duration,
}

impl Default for BrowserClockConfig {
    fn default() -> Self {
        Self {
            max_forward_step: Duration::from_millis(250),
            jitter_floor: Duration::from_millis(1),
        }
    }
}

/// Browser monotonic clock built from host time samples.
///
/// This clock is intended for browser scheduler/timer adapters. Call
/// [`observe_host_time`](Self::observe_host_time) from host callbacks to feed
/// new host samples into the clock.
///
/// Suspension mitigation:
/// - call [`suspend`](Self::suspend) when the tab/page is hidden,
/// - call [`resume`](Self::resume) when visible again (first sample rebases).
#[derive(Debug)]
pub struct BrowserMonotonicClock {
    now: AtomicU64,
    paused: AtomicBool,
    paused_at: AtomicU64,
    has_host_sample: AtomicBool,
    last_host_sample: AtomicU64,
    pending_catch_up_ns: AtomicU64,
    max_forward_step_ns: u64,
    jitter_floor_ns: u64,
    /// Host time read on every [`TimeSource::now`] when nothing else feeds
    /// this clock ([`Self::host_sampled`]).
    host_sampler: Option<fn() -> u64>,
}

impl BrowserMonotonicClock {
    /// Creates a browser monotonic clock with explicit policy.
    #[must_use]
    pub fn new(config: BrowserClockConfig) -> Self {
        Self {
            now: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            paused_at: AtomicU64::new(0),
            has_host_sample: AtomicBool::new(false),
            last_host_sample: AtomicU64::new(0),
            pending_catch_up_ns: AtomicU64::new(0),
            max_forward_step_ns: duration_to_nanos_saturating(config.max_forward_step),
            jitter_floor_ns: duration_to_nanos_saturating(config.jitter_floor),
            host_sampler: None,
        }
    }

    /// A clock that feeds itself: every [`TimeSource::now`] observes
    /// `sampler`'s host nanoseconds first, through
    /// [`Self::observe_host_nanos`], so the forward-step and suspend policy
    /// still apply.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn with_host_sampler(config: BrowserClockConfig, sampler: fn() -> u64) -> Self {
        Self {
            host_sampler: Some(sampler),
            ..Self::new(config)
        }
    }

    /// The clock a wasm32 runtime's timer driver reads. `RuntimeBuilder`
    /// keeps no handle to its clock, so nothing would call
    /// [`Self::observe_host_time`], and a clock from [`Self::default`] stays
    /// at zero: no nonzero sleep or timeout would ever fire
    /// (br-asupersync-combinator-time-audit-fqdvqn item 5).
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn host_sampled() -> Self {
        Self::with_host_sampler(
            BrowserClockConfig::default(),
            crate::time::wasm_monotonic_nanos,
        )
    }

    /// Ingests a host-time sample and updates monotonic time.
    ///
    /// The first sample only establishes a host baseline and does not advance
    /// runtime time.
    pub fn observe_host_time(&self, host: Duration) -> Time {
        let host_ns = duration_to_nanos_saturating(host);
        self.observe_host_nanos(host_ns)
    }

    /// Ingests a host-time sample in nanoseconds.
    pub fn observe_host_nanos(&self, host_ns: u64) -> Time {
        if self.paused.load(Ordering::Acquire) {
            return Time::from_nanos(self.paused_at.load(Ordering::Acquire));
        }

        // Rebase on first sample (or first sample after resume) without jump.
        if self
            .has_host_sample
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.last_host_sample.store(host_ns, Ordering::Release);
            return self.current();
        }

        // Clamp regressions by tracking the max host sample seen.
        let previous_host = self.last_host_sample.fetch_max(host_ns, Ordering::AcqRel);
        let host_delta = host_ns.saturating_sub(previous_host);

        let mut current_pending = self.pending_catch_up_ns.load(Ordering::Acquire);
        loop {
            let combined_delta = host_delta.saturating_add(current_pending);

            if combined_delta < self.jitter_floor_ns {
                match self.pending_catch_up_ns.compare_exchange_weak(
                    current_pending,
                    combined_delta,
                    Ordering::Release,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return self.current(),
                    Err(actual) => {
                        current_pending = actual;
                        continue;
                    }
                }
            }

            let applied = if self.max_forward_step_ns == 0 {
                combined_delta
            } else {
                combined_delta.min(self.max_forward_step_ns)
            };
            let new_pending = combined_delta.saturating_sub(applied);

            match self.pending_catch_up_ns.compare_exchange_weak(
                current_pending,
                new_pending,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return self.advance_now(applied),
                Err(actual) => {
                    current_pending = actual;
                    // continue loop to retry with new pending value
                }
            }
        }
    }

    /// Freezes clock advancement while hidden/throttled.
    pub fn suspend(&self) {
        let now = self.now.load(Ordering::Acquire);
        self.paused_at.store(now, Ordering::Release);
        self.paused.store(true, Ordering::Release);
    }

    /// Resumes clock advancement.
    ///
    /// Resuming clears host baseline and pending catch-up so the next host
    /// sample rebases instead of producing a giant jump.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        self.has_host_sample.store(false, Ordering::Release);
        self.pending_catch_up_ns.store(0, Ordering::Release);
    }

    /// Returns true when the browser clock is suspended.
    #[must_use]
    #[inline]
    pub fn is_suspended(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// Returns pending deferred advancement.
    #[must_use]
    #[inline]
    pub fn pending_catch_up(&self) -> Duration {
        Duration::from_nanos(self.pending_catch_up_ns.load(Ordering::Acquire))
    }

    /// The clock's time, without sampling the host.
    fn current(&self) -> Time {
        if self.paused.load(Ordering::Acquire) {
            Time::from_nanos(self.paused_at.load(Ordering::Acquire))
        } else {
            Time::from_nanos(self.now.load(Ordering::Acquire))
        }
    }

    fn advance_now(&self, delta: u64) -> Time {
        if delta == 0 {
            return self.current();
        }

        let mut current = self.now.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(delta);
            match self
                .now
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Time::from_nanos(next),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Default for BrowserMonotonicClock {
    fn default() -> Self {
        Self::new(BrowserClockConfig::default())
    }
}

impl TimeSource for BrowserMonotonicClock {
    fn now(&self) -> Time {
        match self.host_sampler {
            Some(sampler) => self.observe_host_nanos(sampler()),
            None => self.current(),
        }
    }
}

/// Virtual time source for lab testing.
///
/// Time only advances when explicitly told to do so, enabling
/// deterministic testing of time-dependent code.
///
/// # Example
///
/// ```
/// use asupersync::time::{TimeSource, VirtualClock};
/// use asupersync::types::Time;
///
/// let clock = VirtualClock::new();
/// assert_eq!(clock.now(), Time::ZERO);
///
/// clock.advance(1_000_000_000); // 1 second
/// assert_eq!(clock.now(), Time::from_secs(1));
/// ```
#[derive(Debug, Default)]
pub struct VirtualClock {
    /// Current time in nanoseconds.
    now: AtomicU64,
    /// When true, `now()` returns the frozen time and `advance`/`advance_to`
    /// are no-ops. The frozen time is captured at the moment `pause()` is called.
    paused: AtomicBool,
    /// Frozen time snapshot captured when the clock is paused.
    frozen_at: AtomicU64,
}

impl VirtualClock {
    /// Creates a new virtual clock starting at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a virtual clock starting at the given time.
    #[must_use]
    pub fn starting_at(time: Time) -> Self {
        Self {
            now: AtomicU64::new(time.as_nanos()),
            paused: AtomicBool::new(false),
            frozen_at: AtomicU64::new(time.as_nanos()),
        }
    }

    /// Advances time by the given number of nanoseconds.
    ///
    /// No-op when the clock is paused.
    pub fn advance(&self, nanos: u64) {
        if !self.paused.load(Ordering::Acquire) {
            let mut current = self.now.load(Ordering::Acquire);
            loop {
                let next = current.saturating_add(nanos);
                match self.now.compare_exchange_weak(
                    current,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
        }
    }

    /// Advances time to the given absolute time.
    ///
    /// If the target time is in the past, or the clock is paused, this is a no-op.
    pub fn advance_to(&self, time: Time) {
        if self.paused.load(Ordering::Acquire) {
            return;
        }
        let target = time.as_nanos();
        let mut current = self.now.load(Ordering::Acquire);
        while current < target {
            match self.now.compare_exchange_weak(
                current,
                target,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Sets the current time (for testing).
    pub fn set(&self, time: Time) {
        let nanos = time.as_nanos();
        self.now.store(nanos, Ordering::Release);
        if self.paused.load(Ordering::Acquire) {
            self.frozen_at.store(nanos, Ordering::Release);
        }
    }

    /// Pauses the clock, freezing `now()` at the current time.
    ///
    /// While paused, `advance()` and `advance_to()` are no-ops.
    /// Call `resume()` to unfreeze.
    pub fn pause(&self) {
        let current = self.now.load(Ordering::Acquire);
        self.frozen_at.store(current, Ordering::Release);
        self.paused.store(true, Ordering::Release);
    }

    /// Resumes a paused clock.
    ///
    /// The clock continues from the time it was paused at (no jump).
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }

    /// Returns true if the clock is paused.
    #[must_use]
    #[inline]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }
}

impl TimeSource for VirtualClock {
    fn now(&self) -> Time {
        if self.paused.load(Ordering::Acquire) {
            Time::from_nanos(self.frozen_at.load(Ordering::Acquire))
        } else {
            Time::from_nanos(self.now.load(Ordering::Acquire))
        }
    }
}

pub use super::wheel::TimerHandle;

/// Timer driver that manages timer registrations and fires them.
///
/// The driver maintains a hierarchical timing wheel ordered by deadline.
/// When `process_timers` is called, all expired timers have their wakers called.
///
/// # Thread Safety
///
/// The driver is thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```
/// use asupersync::time::{TimerDriver, VirtualClock};
/// use asupersync::types::Time;
/// use std::sync::Arc;
///
/// let clock = Arc::new(VirtualClock::new());
/// let driver = TimerDriver::with_clock(clock.clone());
///
/// // In a real scenario, you'd register timers via Sleep futures
/// // and process them in your event loop.
/// ```
#[derive(Debug)]
pub struct TimerDriver<T: TimeSource = VirtualClock> {
    /// The time source.
    clock: std::sync::Arc<T>,
    /// Timing wheel (protected by mutex for thread safety).
    wheel: Mutex<TimerWheel>,
    /// Conservative deadline observed by reactor pollers. Accessed only while
    /// holding `wheel`; cancellation may leave an earlier, harmless value.
    observed_deadline: AtomicU64,
    /// True while the wheel holds an active timer. Written only while holding
    /// `wheel`, after every change to its active set, so `process_timers` can
    /// skip the lock when nothing can expire.
    armed: AtomicBool,
    /// Weak registrations avoid cycles through reactor task wakers and allow
    /// an explicitly shared timer driver to notify more than one runtime.
    deadline_reactors: Mutex<Vec<Weak<dyn Reactor>>>,
}

impl<T: TimeSource> TimerDriver<T> {
    /// Creates a new timer driver with the given time source.
    #[must_use]
    pub fn with_clock(clock: std::sync::Arc<T>) -> Self {
        Self::with_clock_and_config(
            clock,
            TimerWheelConfig::default(),
            CoalescingConfig::default(),
        )
    }

    /// Creates a timer driver whose wheel uses `config` for its overflow
    /// limits and `coalescing` for wakeup batching.
    ///
    /// With coalescing enabled, the timers of one coalescing window fire
    /// together at the end of that window: never before a timer's deadline,
    /// at most one window after it (br-asupersync-7yq1pv). [`Self::with_clock`]
    /// keeps coalescing off.
    #[must_use]
    pub fn with_clock_and_config(
        clock: std::sync::Arc<T>,
        config: TimerWheelConfig,
        coalescing: CoalescingConfig,
    ) -> Self {
        let now = clock.now();
        Self {
            clock,
            wheel: Mutex::new(
                TimerWheel::with_config(now, config, coalescing).with_deferred_waker_drops(),
            ),
            observed_deadline: AtomicU64::new(u64::MAX),
            armed: AtomicBool::new(false),
            deadline_reactors: Mutex::new(Vec::new()),
        }
    }

    /// Publishes whether `wheel` (whose lock the caller holds) has an active
    /// timer.
    #[inline]
    fn publish_armed(&self, wheel: &TimerWheel) {
        self.armed.store(!wheel.is_empty(), Ordering::Release);
    }

    /// Releases the wheel lock, then drops the wakers of the entries the
    /// wheel discarded (cancelled, stale or cleared) while it was held. A
    /// waker can own the last reference to a task whose drop cancels a timer
    /// here; dropped under the lock, that re-entry would deadlock
    /// (br-asupersync-m85zfi LOW 5).
    fn unlock(mut wheel: parking_lot::MutexGuard<'_, TimerWheel>) {
        let dropped = wheel.take_dropped_wakers();
        drop(wheel);
        drop(dropped);
    }

    /// Returns the current time from the underlying clock.
    #[inline]
    #[must_use]
    pub fn now(&self) -> Time {
        self.clock.now()
    }

    /// Registers a timer to fire at the given deadline.
    ///
    /// Returns a handle that can be used to identify the timer.
    /// The waker will be called when `process_timers` is called
    /// and the deadline has passed.
    pub fn register(&self, deadline: Time, waker: Waker) -> TimerHandle {
        let mut wheel = self.wheel.lock();
        let now = self.clock.now();
        wheel.synchronize(now);
        crate::runtime::metrics::record_timer_registered();
        let handle = wheel.register(deadline, waker);
        self.publish_armed(&wheel);
        let earlier = self.advance_reactor_deadline(&mut wheel, deadline);
        Self::unlock(wheel);
        if earlier {
            self.wake_deadline_reactors();
        }
        handle
    }

    /// Updates an existing timer registration with a new deadline and waker.
    ///
    /// This doesn't actually remove the old entry from the heap (to avoid O(n)
    /// removal), but it does cancel the active handle before registering a new
    /// one. If the supplied handle is already stale/inactive, the update fails
    /// closed and leaves the wheel unchanged.
    pub fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle {
        let mut wheel = self.wheel.lock();
        let now = self.clock.now();
        wheel.synchronize(now);
        let (updated, earlier) = if wheel.cancel(handle) {
            crate::runtime::metrics::record_timer_cancelled();
            crate::runtime::metrics::record_timer_registered();
            let updated = wheel.register(deadline, waker);
            (updated, self.advance_reactor_deadline(&mut wheel, deadline))
        } else {
            (*handle, false)
        };
        self.publish_armed(&wheel);
        Self::unlock(wheel);
        if earlier {
            self.wake_deadline_reactors();
        }
        updated
    }

    /// Publish an earlier wake point without scanning all pending timers on
    /// every insertion. The next poller's full query refreshes this floor.
    fn advance_reactor_deadline(&self, wheel: &mut TimerWheel, deadline: Time) -> bool {
        let effective =
            if wheel.coalescing_config().enabled {
                // Adding a timer can make a coalescing group ready before its raw
                // deadline. This optional policy needs the wheel's exact answer.
                wheel.next_deadline().unwrap_or(deadline)
            } else {
                deadline.min(wheel.current_time().saturating_add_nanos(
                    duration_to_nanos_saturating(wheel.config().max_timer_duration),
                ))
            };
        let previous = self.observed_deadline.load(Ordering::Relaxed);
        if effective.as_nanos() < previous {
            self.observed_deadline
                .store(effective.as_nanos(), Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn register_deadline_reactor(&self, reactor: Weak<dyn Reactor>) {
        let mut reactors = self.deadline_reactors.lock();
        reactors.retain(|registered| registered.strong_count() != 0);
        if !reactors
            .iter()
            .any(|registered| registered.ptr_eq(&reactor))
        {
            reactors.push(reactor);
        }
    }

    fn wake_deadline_reactors(&self) {
        let mut live = smallvec::SmallVec::<[Arc<dyn Reactor>; 2]>::new();
        {
            let mut reactors = self.deadline_reactors.lock();
            reactors.retain(|reactor| {
                if let Some(reactor) = reactor.upgrade() {
                    live.push(reactor);
                    true
                } else {
                    false
                }
            });
        }
        // A backend may re-enter the timer driver. Release both locks first,
        // and do not let a custom backend panic prevent other runtimes waking.
        for reactor in live {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reactor.wake()));
        }
    }

    /// Cancels an existing timer registration.
    ///
    /// Returns true if the timer was active and is now cancelled.
    pub fn cancel(&self, handle: &TimerHandle) -> bool {
        let cancelled = {
            let mut wheel = self.wheel.lock();
            let cancelled = wheel.cancel(handle);
            self.publish_armed(&wheel);
            Self::unlock(wheel);
            cancelled
        };
        if cancelled {
            crate::runtime::metrics::record_timer_cancelled();
        }
        cancelled
    }

    /// Returns the next deadline that will fire, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Time> {
        let mut wheel = self.wheel.lock();
        let now = self.clock.now();
        wheel.synchronize(now);
        let deadline = wheel.next_deadline().map(|deadline| deadline.max(now));
        self.observed_deadline
            .store(deadline.map_or(u64::MAX, Time::as_nanos), Ordering::Relaxed);
        Self::unlock(wheel);
        deadline
    }

    /// Processes all expired timers, calling their wakers.
    ///
    /// Returns the number of timers fired.
    pub fn process_timers(&self) -> usize {
        // Collect expired entries while holding the lock, then release it
        // before waking to prevent potential deadlocks if wakers try to
        // re-enter the timer driver.
        let expired_wakers = self.collect_expired();
        let fired = expired_wakers.len();
        if fired > 0 {
            crate::runtime::metrics::record_timers_fired(fired as u64);
        }

        // Wake them outside the lock. Catch panics to ensure all
        // wakers are attempted even if one panics.
        for waker in expired_wakers {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
        }

        fired
    }

    /// Helper to collect expired wakers while holding the lock.
    ///
    /// Schedulers process timers before every dispatch. With no timer
    /// registered nothing can expire, so neither the lock nor the clock is
    /// taken: every registration synchronizes the wheel to the clock itself,
    /// and an empty wheel jumps straight to the new time
    /// (br-asupersync-issue65-criticisms-kpmoy5.1.3). A registration that
    /// races this check is seen by a later dispatch, exactly as if this check
    /// had taken the lock just before it. Workers size their park with
    /// [`Self::next_deadline`], which takes the lock, so the race cannot
    /// strand a timer behind a park.
    #[inline]
    #[allow(clippy::significant_drop_tightening)]
    fn collect_expired(&self) -> WakerBatch {
        if !self.armed.load(Ordering::Acquire) {
            return WakerBatch::new();
        }
        let mut wheel = self.wheel.lock();
        if wheel.is_empty() {
            return WakerBatch::new();
        }
        let expired = wheel.collect_expired(self.clock.now());
        self.publish_armed(&wheel);
        Self::unlock(wheel);
        expired
    }

    /// Returns the number of pending timers.
    #[inline]
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.wheel.lock().len()
    }

    /// Returns true if there are no pending timers.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wheel.lock().is_empty()
    }

    /// Clears all pending timers without firing them.
    pub fn clear(&self) {
        let mut wheel = self.wheel.lock();
        wheel.clear();
        self.publish_armed(&wheel);
        Self::unlock(wheel);
    }
}

impl TimerDriver<VirtualClock> {
    /// Creates a new timer driver with a virtual clock.
    ///
    /// This is the default for testing and lab use.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(std::sync::Arc::new(VirtualClock::new()))
    }
}

impl Default for TimerDriver<VirtualClock> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TimerDriverHandle - Shared handle for timer driver access
// =============================================================================

/// Trait abstracting timer driver operations for use with trait objects.
///
/// This allows the runtime to create either wall-clock or virtual-clock
/// based drivers while consumers use a unified handle type.
pub trait TimerDriverApi: Send + Sync + std::fmt::Debug {
    /// Returns the current time.
    fn now(&self) -> Time;

    /// Registers a timer to fire at the given deadline.
    fn register(&self, deadline: Time, waker: Waker) -> TimerHandle;

    /// Updates an existing timer with a new deadline and waker.
    fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle;

    /// Cancels an existing timer.
    fn cancel(&self, handle: &TimerHandle) -> bool;

    /// Returns the next deadline that will fire.
    fn next_deadline(&self) -> Option<Time>;

    /// Processes expired timers, calling their wakers.
    fn process_timers(&self) -> usize;

    /// Returns the number of pending timers.
    fn pending_count(&self) -> usize;

    /// Returns true if no timers are pending.
    fn is_empty(&self) -> bool;

    /// Returns the maximum timer duration this driver can represent. A
    /// registration whose deadline exceeds `now + max_timer_duration` is clamped
    /// to fire EARLY at the horizon (see `TimerWheel::register`); callers that
    /// need the true deadline must detect the clamp and re-register
    /// (br-asupersync-sleep-horizon-early-youlxs).
    fn max_timer_duration(&self) -> std::time::Duration;
}

impl<T: TimeSource + std::fmt::Debug + 'static> TimerDriverApi for TimerDriver<T> {
    fn now(&self) -> Time {
        Self::now(self)
    }

    fn register(&self, deadline: Time, waker: Waker) -> TimerHandle {
        Self::register(self, deadline, waker)
    }

    fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle {
        Self::update(self, handle, deadline, waker)
    }

    fn cancel(&self, handle: &TimerHandle) -> bool {
        Self::cancel(self, handle)
    }

    fn next_deadline(&self) -> Option<Time> {
        Self::next_deadline(self)
    }

    fn process_timers(&self) -> usize {
        Self::process_timers(self)
    }

    fn pending_count(&self) -> usize {
        Self::pending_count(self)
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }

    fn max_timer_duration(&self) -> std::time::Duration {
        self.wheel.lock().config().max_timer_duration
    }
}

// Keep runtime wake registration private. Public TimerDriverApi implementors
// gain no new required method, and TimerDriverHandle stays one Arc wide.
trait NativeTimerDriverApi: TimerDriverApi {
    fn register_deadline_reactor(&self, reactor: Weak<dyn Reactor>);
}

impl<T: TimeSource + std::fmt::Debug + 'static> NativeTimerDriverApi for TimerDriver<T> {
    fn register_deadline_reactor(&self, reactor: Weak<dyn Reactor>) {
        Self::register_deadline_reactor(self, reactor);
    }
}

/// Shared handle to a timer driver.
///
/// This wrapper provides cloneable access to the runtime's timer driver
/// from async contexts. It abstracts over the concrete time source
/// (wall clock vs virtual clock) using a trait object.
///
/// # Example
///
/// ```ignore
/// use asupersync::time::TimerDriverHandle;
///
/// // Get handle from current context
/// if let Some(timer) = Cx::current().and_then(|cx| cx.timer_driver()) {
///     let deadline = timer.now() + Duration::from_secs(1);
///     let handle = timer.register(deadline, waker);
/// }
/// ```
#[derive(Clone)]
pub struct TimerDriverHandle {
    inner: Arc<dyn NativeTimerDriverApi>,
}

impl std::fmt::Debug for TimerDriverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerDriverHandle")
            .field("pending_count", &self.inner.pending_count())
            .finish()
    }
}

impl TimerDriverHandle {
    /// Creates a new handle wrapping the given timer driver.
    #[inline]
    pub fn new<T: TimeSource + std::fmt::Debug + 'static>(driver: Arc<TimerDriver<T>>) -> Self {
        Self { inner: driver }
    }

    /// Returns true if two handles refer to the same underlying driver.
    #[inline]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn register_deadline_reactor(&self, reactor: Weak<dyn Reactor>) {
        self.inner.register_deadline_reactor(reactor);
    }

    /// Creates a handle with a wall clock timer driver for production use.
    #[must_use]
    pub fn with_wall_clock() -> Self {
        let clock = Arc::new(WallClock::new());
        let driver = Arc::new(TimerDriver::with_clock(clock));
        Self::new(driver)
    }

    /// Creates a wall-clock timer driver that batches nearby wakeups.
    ///
    /// The timers of one `coalescing` window fire together at the end of that
    /// window, so a sleep never wakes before its deadline and can wake up to
    /// one window after it. Install it with
    /// [`RuntimeBuilder::with_timer_driver`](crate::runtime::RuntimeBuilder::with_timer_driver)
    /// (br-asupersync-7yq1pv):
    ///
    /// ```
    /// use asupersync::runtime::RuntimeBuilder;
    /// use asupersync::time::{CoalescingConfig, TimerDriverHandle};
    /// use std::time::Duration;
    ///
    /// let timers = TimerDriverHandle::with_wall_clock_coalescing(
    ///     CoalescingConfig::enabled_with_window(Duration::from_millis(1)),
    /// );
    /// let runtime = RuntimeBuilder::new().with_timer_driver(timers).build()?;
    /// # drop(runtime);
    /// # Ok::<(), asupersync::Error>(())
    /// ```
    #[must_use]
    pub fn with_wall_clock_coalescing(coalescing: CoalescingConfig) -> Self {
        let clock = Arc::new(WallClock::new());
        let driver = Arc::new(TimerDriver::with_clock_and_config(
            clock,
            TimerWheelConfig::default(),
            coalescing,
        ));
        Self::new(driver)
    }

    /// Creates a handle with a virtual clock timer driver for testing.
    #[must_use]
    pub fn with_virtual_clock(clock: Arc<VirtualClock>) -> Self {
        let driver = Arc::new(TimerDriver::with_clock(clock));
        Self::new(driver)
    }

    /// Creates a handle with a browser-monotonic timer driver.
    #[must_use]
    pub fn with_browser_clock(clock: Arc<BrowserMonotonicClock>) -> Self {
        let driver = Arc::new(TimerDriver::with_clock(clock));
        Self::new(driver)
    }

    /// Returns the current time from the timer driver.
    #[inline]
    #[must_use]
    pub fn now(&self) -> Time {
        self.inner.now()
    }

    /// Registers a timer to fire at the given deadline.
    ///
    /// Returns a handle that can be used to cancel or update the timer.
    #[inline]
    #[must_use]
    pub fn register(&self, deadline: Time, waker: Waker) -> TimerHandle {
        self.inner.register(deadline, waker)
    }

    /// Updates an existing timer with a new deadline and waker.
    #[inline]
    #[must_use]
    pub fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle {
        self.inner.update(handle, deadline, waker)
    }

    /// Cancels an existing timer.
    ///
    /// Returns true if the timer was active and is now cancelled.
    #[inline]
    #[must_use]
    pub fn cancel(&self, handle: &TimerHandle) -> bool {
        self.inner.cancel(handle)
    }

    /// Returns the maximum timer duration before this driver clamps a
    /// registration to fire early at the horizon
    /// (br-asupersync-sleep-horizon-early-youlxs).
    #[inline]
    #[must_use]
    pub fn max_timer_duration(&self) -> std::time::Duration {
        self.inner.max_timer_duration()
    }

    /// Returns the next deadline that will fire, if any.
    #[inline]
    #[must_use]
    pub fn next_deadline(&self) -> Option<Time> {
        self.inner.next_deadline()
    }

    /// Processes all expired timers, calling their wakers.
    ///
    /// Returns the number of timers fired.
    #[inline]
    #[must_use]
    pub fn process_timers(&self) -> usize {
        self.inner.process_timers()
    }

    /// Returns the number of pending timers.
    #[inline]
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// Returns true if no timers are pending.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
#[path = "driver_inline_tests.rs"]
mod tests;
