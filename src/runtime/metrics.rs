//! Lightweight, feature-gated runtime instrumentation counters.
//!
//! This module is the measurement substrate for the scheduler/timer
//! CPU-efficiency overhaul (epic `asupersync-runtime-cpu-overhaul-5vt09v`).
//! You cannot prove a scheduler or timer fix without before/after numbers, and
//! the only externally visible signal (OS thread count) is far too coarse and
//! noisy. These counters expose the precise internal events the epic targets:
//! thread-per-`sleep` churn, `sched_yield` busy-spin, worker park/unpark
//! traffic, and the live timer population.
//!
//! # Zero cost when disabled
//!
//! Every counter and every `record_*` helper is gated behind the
//! `runtime-metrics` Cargo feature. When the feature is **off** (the default,
//! and what ships in release builds), each `record_*` call inlines to an empty
//! body and [`snapshot`] returns an all-zero [`Metrics`]. There is no static,
//! no atomic, and no instruction emitted on the hot path. The benchmark harness
//! (`asupersync-runtime-cpu-overhaul-5vt09v.2`) and the unit/e2e tests turn the
//! feature on to read and assert the counters.
//!
//! # Ordering
//!
//! The atomics use [`Ordering::Relaxed`]. These counters are diagnostics, not
//! synchronization primitives: a reader only needs an eventually-consistent
//! tally, never a happens-before edge to the work being counted. Relaxed keeps
//! the instrumentation as close to free as an atomic increment can be.
//!
//! # Reading the counters
//!
//! Counters are process-global and monotonic (except the derived
//! [`Metrics::active_timers`] gauge). Tests and the bench should read a
//! [`snapshot`] before driving work and another after, then assert on the
//! *delta*. That pattern is robust to other tests incrementing the same global
//! counters in parallel; relying on absolute values is not.

#[cfg(feature = "runtime-metrics")]
use core::sync::atomic::{AtomicU64, Ordering};

/// A point-in-time copy of the runtime instrumentation counters.
///
/// Obtain one with [`snapshot`]. All fields are cumulative since process start
/// except [`active_timers`](Self::active_timers), which is a derived gauge of
/// timers that have been registered but not yet fired or cancelled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metrics {
    /// OS threads spawned solely to drive a `Sleep`/timer future to completion.
    ///
    /// This is the headline churn signal. The thread-per-`sleep` fallback in
    /// `time::sleep` increments it on every spawn; after Lever 1 (the shared
    /// timer subsystem) lands, this should stay `0` under the bench workload.
    pub timer_threads_spawned: u64,
    /// `sched_yield`/`thread::yield_now` calls in a worker's idle backoff path.
    ///
    /// On an idle core `sched_yield` returns immediately, so a yield-loop is a
    /// hot spin that burns a core for nothing. After Lever 2 (bounded
    /// spin-then-park) this should be `0` in the idle path.
    pub sched_yield_calls: u64,
    /// Bounded `hint::spin_loop` iterations a worker performs before parking.
    ///
    /// Wired by Lever 2; the cheap in-userspace pause that replaces
    /// `sched_yield`. A non-zero value here paired with a zero
    /// [`sched_yield_calls`](Self::sched_yield_calls) is the success shape.
    pub worker_spins: u64,
    /// Times a worker parked (blocked) waiting for work or a timer deadline.
    pub worker_parks: u64,
    /// Times a worker was unparked (signalled) by an enqueue/wake.
    pub worker_unparks: u64,
    /// Timers registered with the timer driver (cumulative).
    ///
    /// Used together with [`timers_fired`](Self::timers_fired) and
    /// [`timers_cancelled`](Self::timers_cancelled) to derive
    /// [`active_timers`](Self::active_timers).
    pub timers_registered: u64,
    /// Timers that fired (their deadline elapsed and waker was woken).
    pub timers_fired: u64,
    /// Timers cancelled before firing (e.g. a `Sleep` dropped early).
    ///
    /// A cancellation leak (Lever 1.3) shows up as `active_timers` failing to
    /// return to baseline after the futures that armed the timers are gone.
    pub timers_cancelled: u64,
    /// Gauge of registered-but-not-yet-resolved timers.
    ///
    /// Derived as `timers_registered - (timers_fired + timers_cancelled)`,
    /// saturating at `0`. Catches cancellation leaks: it must return to its
    /// pre-register value once every armed timer has fired or been cancelled.
    pub active_timers: u64,
}

impl core::fmt::Display for Metrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "timer_threads_spawned={} sched_yield_calls={} worker_spins={} \
             worker_parks={} worker_unparks={} timers_registered={} \
             timers_fired={} timers_cancelled={} active_timers={}",
            self.timer_threads_spawned,
            self.sched_yield_calls,
            self.worker_spins,
            self.worker_parks,
            self.worker_unparks,
            self.timers_registered,
            self.timers_fired,
            self.timers_cancelled,
            self.active_timers,
        )
    }
}

#[cfg(feature = "runtime-metrics")]
struct Counters {
    timer_threads_spawned: AtomicU64,
    sched_yield_calls: AtomicU64,
    worker_spins: AtomicU64,
    worker_parks: AtomicU64,
    worker_unparks: AtomicU64,
    timers_registered: AtomicU64,
    timers_fired: AtomicU64,
    timers_cancelled: AtomicU64,
}

#[cfg(feature = "runtime-metrics")]
static COUNTERS: Counters = Counters {
    timer_threads_spawned: AtomicU64::new(0),
    sched_yield_calls: AtomicU64::new(0),
    worker_spins: AtomicU64::new(0),
    worker_parks: AtomicU64::new(0),
    worker_unparks: AtomicU64::new(0),
    timers_registered: AtomicU64::new(0),
    timers_fired: AtomicU64::new(0),
    timers_cancelled: AtomicU64::new(0),
};

/// Record that an OS thread was spawned to drive a timer/`Sleep` future.
///
/// Wired at the thread-per-`sleep` fallback in `time::sleep`. No-op unless the
/// `runtime-metrics` feature is enabled.
#[inline]
pub fn record_timer_thread_spawned() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS
        .timer_threads_spawned
        .fetch_add(1, Ordering::Relaxed);
}

/// Record a `sched_yield`/`thread::yield_now` call in a worker idle backoff.
///
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_sched_yield() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.sched_yield_calls.fetch_add(1, Ordering::Relaxed);
}

/// Record one bounded `hint::spin_loop` iteration in a worker pre-park spin.
///
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_worker_spin() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.worker_spins.fetch_add(1, Ordering::Relaxed);
}

/// Record that a worker parked (blocked) waiting for work or a deadline.
///
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_worker_park() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.worker_parks.fetch_add(1, Ordering::Relaxed);
}

/// Record that a worker was unparked (signalled) by an enqueue/wake.
///
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_worker_unpark() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.worker_unparks.fetch_add(1, Ordering::Relaxed);
}

/// Record that a timer was registered with the timer driver.
///
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_timer_registered() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.timers_registered.fetch_add(1, Ordering::Relaxed);
}

/// Record that `count` timers fired (deadline elapsed, wakers woken).
///
/// Accepts a batch count because the driver expires many timers per wake.
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_timers_fired(count: u64) {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.timers_fired.fetch_add(count, Ordering::Relaxed);
    #[cfg(not(feature = "runtime-metrics"))]
    let _ = count;
}

/// Record that a timer was cancelled before firing (e.g. a dropped `Sleep`).
///
/// No-op unless the `runtime-metrics` feature is enabled.
#[inline]
pub fn record_timer_cancelled() {
    #[cfg(feature = "runtime-metrics")]
    COUNTERS.timers_cancelled.fetch_add(1, Ordering::Relaxed);
}

/// Read the current runtime instrumentation counters.
///
/// Returns an all-zero [`Metrics`] when the `runtime-metrics` feature is
/// disabled. Compare two snapshots (before/after) and assert on the delta
/// rather than absolute values; the counters are process-global.
#[must_use]
pub fn snapshot() -> Metrics {
    #[cfg(feature = "runtime-metrics")]
    {
        let registered = COUNTERS.timers_registered.load(Ordering::Relaxed);
        let fired = COUNTERS.timers_fired.load(Ordering::Relaxed);
        let cancelled = COUNTERS.timers_cancelled.load(Ordering::Relaxed);
        Metrics {
            timer_threads_spawned: COUNTERS.timer_threads_spawned.load(Ordering::Relaxed),
            sched_yield_calls: COUNTERS.sched_yield_calls.load(Ordering::Relaxed),
            worker_spins: COUNTERS.worker_spins.load(Ordering::Relaxed),
            worker_parks: COUNTERS.worker_parks.load(Ordering::Relaxed),
            worker_unparks: COUNTERS.worker_unparks.load(Ordering::Relaxed),
            timers_registered: registered,
            timers_fired: fired,
            timers_cancelled: cancelled,
            active_timers: registered.saturating_sub(fired.saturating_add(cancelled)),
        }
    }
    #[cfg(not(feature = "runtime-metrics"))]
    {
        Metrics::default()
    }
}

/// Reset all counters to zero.
///
/// Only available with the `runtime-metrics` feature. Intended for
/// single-threaded test/bench harnesses that want absolute reads from a known
/// baseline; in a multi-threaded test process prefer the snapshot-delta pattern
/// instead, because a concurrent test can observe the reset.
#[cfg(feature = "runtime-metrics")]
pub fn reset() {
    COUNTERS.timer_threads_spawned.store(0, Ordering::Relaxed);
    COUNTERS.sched_yield_calls.store(0, Ordering::Relaxed);
    COUNTERS.worker_spins.store(0, Ordering::Relaxed);
    COUNTERS.worker_parks.store(0, Ordering::Relaxed);
    COUNTERS.worker_unparks.store(0, Ordering::Relaxed);
    COUNTERS.timers_registered.store(0, Ordering::Relaxed);
    COUNTERS.timers_fired.store(0, Ordering::Relaxed);
    COUNTERS.timers_cancelled.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With the feature off, the API is a no-op and `snapshot()` is all-zero.
    #[cfg(not(feature = "runtime-metrics"))]
    #[test]
    fn snapshot_is_zero_when_feature_disabled() {
        record_timer_thread_spawned();
        record_sched_yield();
        record_worker_spin();
        record_worker_park();
        record_worker_unpark();
        record_timer_registered();
        record_timers_fired(5);
        record_timer_cancelled();
        assert_eq!(snapshot(), Metrics::default());
    }

    /// With the feature on, each `record_*` helper moves its own counter.
    ///
    /// The counters are process-global and the lib test suite runs in parallel,
    /// so other tests (e.g. scheduler/timer tests driving a real runtime) may
    /// bump these concurrently. We therefore assert MONOTONIC LOWER BOUNDS on
    /// the delta (`>=`): a counter can only be observed to move forward, so
    /// `after >= before + my_calls` is robust to concurrent increments while
    /// still proving each helper drives its intended counter.
    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn record_helpers_increment_their_counters() {
        let before = snapshot();

        record_timer_thread_spawned();
        record_sched_yield();
        record_sched_yield();
        record_worker_spin();
        record_worker_park();
        record_worker_unpark();
        record_timer_registered();
        record_timer_registered();
        record_timer_registered();
        record_timers_fired(2);
        record_timer_cancelled();

        let after = snapshot();
        assert!(after.timer_threads_spawned >= before.timer_threads_spawned + 1);
        assert!(after.sched_yield_calls >= before.sched_yield_calls + 2);
        assert!(after.worker_spins >= before.worker_spins + 1);
        assert!(after.worker_parks >= before.worker_parks + 1);
        assert!(after.worker_unparks >= before.worker_unparks + 1);
        assert!(after.timers_registered >= before.timers_registered + 3);
        assert!(after.timers_fired >= before.timers_fired + 2);
        assert!(after.timers_cancelled >= before.timers_cancelled + 1);
    }

    /// `active_timers` is always the saturating-consistent derivation of the
    /// other three timer counters in the SAME snapshot, and never underflows.
    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn active_timers_is_consistent_and_saturating() {
        record_timer_registered();
        record_timers_fired(1);
        let m = snapshot();
        // snapshot() derives active_timers from exactly these returned fields,
        // so this holds by construction and proves the saturating derivation.
        assert_eq!(
            m.active_timers,
            m.timers_registered
                .saturating_sub(m.timers_fired.saturating_add(m.timers_cancelled))
        );
    }

    /// `Display` renders every counter (used by the bench human summary).
    #[test]
    fn display_lists_all_counters() {
        let s = format!("{}", Metrics::default());
        for key in [
            "timer_threads_spawned",
            "sched_yield_calls",
            "worker_spins",
            "worker_parks",
            "worker_unparks",
            "timers_registered",
            "timers_fired",
            "timers_cancelled",
            "active_timers",
        ] {
            assert!(s.contains(key), "Display missing {key}: {s}");
        }
    }
}
