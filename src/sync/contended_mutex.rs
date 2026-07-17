//! Feature-gated contention-instrumented mutex.
//!
//! When the `lock-metrics` feature is enabled, `ContendedMutex<T>` wraps
//! `std::sync::Mutex<T>` and tracks wait time, hold time, contention count,
//! and total acquisitions. When disabled, it's a zero-cost wrapper.
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::sync::ContendedMutex;
//!
//! let m = ContendedMutex::new("tasks", 42);
//! {
//!     let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
//!     // use *guard
//! }
//!
//! #[cfg(feature = "lock-metrics")]
//! {
//!     let snap = m.snapshot();
//!     println!("acquisitions: {}", snap.acquisitions);
//! }
//! ```

// LockResult, MutexGuard, PoisonError used in inner modules via std::sync::*.

/// Snapshot of lock contention metrics.
#[derive(Debug, Clone, Default)]
pub struct LockMetricsSnapshot {
    /// Human-readable name for this lock (e.g., "tasks", "regions").
    pub name: &'static str,
    /// Total number of successful lock acquisitions.
    pub acquisitions: u64,
    /// Number of acquisitions where the lock was already held (contended).
    pub contentions: u64,
    /// Cumulative nanoseconds spent waiting to acquire the lock.
    pub wait_ns: u64,
    /// Cumulative nanoseconds the lock was held.
    pub hold_ns: u64,
    /// Maximum single wait duration in nanoseconds.
    pub max_wait_ns: u64,
    /// Maximum single hold duration in nanoseconds.
    pub max_hold_ns: u64,
    /// Exact p95 wait duration in nanoseconds for observed acquisitions.
    pub p95_wait_ns: u64,
    /// Exact p999 wait duration in nanoseconds for observed acquisitions.
    pub p999_wait_ns: u64,
    /// Exact p95 hold duration in nanoseconds for observed guards.
    pub p95_hold_ns: u64,
    /// Exact p999 hold duration in nanoseconds for observed guards.
    pub p999_hold_ns: u64,
    /// Instrumentation mode used to produce this snapshot.
    pub instrumentation_mode: &'static str,
}

// ── Feature-gated implementation ──────────────────────────────────────────

#[cfg(feature = "lock-metrics")]
mod inner {
    use super::LockMetricsSnapshot;
    use crate::sync::lock_ordering::{self, LockModule, LockRank};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};
    use std::time::Instant;

    /// Metrics counters split into two cache lines to avoid false sharing.
    /// Lock-path counters (acquisitions, contentions, wait_ns, max_wait_ns) are
    /// updated during lock(); unlock-path counters (hold_ns, max_hold_ns) are
    /// updated during drop(Guard). Exact samples are feature-gated with this
    /// instrumentation mode so the default build stays on the no-op path.
    #[derive(Debug, Default)]
    #[repr(C, align(64))]
    struct Metrics {
        // ── Cache line 1: updated on lock() ──
        acquisitions: AtomicU64,
        contentions: AtomicU64,
        wait_ns: AtomicU64,
        max_wait_ns: AtomicU64,
        // Pad to 64 bytes (4 × 8 = 32 bytes of data, 32 bytes padding)
        _pad: [u8; 32],
        // ── Cache line 2: updated on drop(Guard) ──
        hold_ns: AtomicU64,
        max_hold_ns: AtomicU64,
        wait_samples: Mutex<Vec<u64>>,
        hold_samples: Mutex<Vec<u64>>,
    }

    const MAX_SAMPLES: usize = 10000; // Prevent unbounded growth

    impl Metrics {
        fn update_max(current: &AtomicU64, value: u64) {
            current.fetch_max(value, Ordering::Relaxed);
        }

        fn record_acquire(&self, wait_ns: u64, contended: bool) {
            // All wait-domain counters are mutated while holding the
            // wait_samples lock, which is the single coherence boundary shared
            // with snapshot() and reset() (uqm6ex). Updating the atomics and the
            // sample population under one lock makes each acquisition an atomic
            // (count, sum, max, samples) transition, so a reader can never
            // observe a percentile above the max or a nonzero count with an
            // empty sample set.
            let mut samples = self
                .wait_samples
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.acquisitions.fetch_add(1, Ordering::Relaxed);
            self.wait_ns.fetch_add(wait_ns, Ordering::Relaxed);
            Self::update_max(&self.max_wait_ns, wait_ns);
            if contended {
                self.contentions.fetch_add(1, Ordering::Relaxed);
            }

            // Bound sample collection to prevent memory leak.
            if samples.len() >= MAX_SAMPLES {
                // Remove oldest samples to maintain bound (FIFO eviction).
                samples.drain(0..MAX_SAMPLES / 4);
            }
            samples.push(wait_ns);
        }

        fn record_hold(&self, hold_ns: u64) {
            // Hold-domain counters share the hold_samples lock as their
            // coherence boundary (uqm6ex); see record_acquire for the rationale.
            let mut samples = self
                .hold_samples
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.hold_ns.fetch_add(hold_ns, Ordering::Relaxed);
            Self::update_max(&self.max_hold_ns, hold_ns);

            // Bound sample collection to prevent memory leak.
            if samples.len() >= MAX_SAMPLES {
                // Remove oldest samples to maintain bound (FIFO eviction).
                samples.drain(0..MAX_SAMPLES / 4);
            }
            samples.push(hold_ns);
        }

        /// Computes an exact percentile from an already-sorted (ascending),
        /// frozen sample population. Both percentiles for a domain are computed
        /// from the *same* frozen population, so `p95 <= p999` holds by
        /// construction because the rank is monotonic in the numerator/
        /// denominator ratio (uqm6ex).
        fn percentile_from_sorted(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
            if sorted.is_empty() {
                return 0;
            }
            let last_index = sorted.len() - 1;
            let rank = last_index
                .saturating_mul(numerator)
                .saturating_add(denominator / 2)
                / denominator;
            sorted[rank.min(last_index)]
        }

        fn snapshot(&self, name: &'static str) -> LockMetricsSnapshot {
            // Freeze each domain's population once, under the same lock that
            // record_*/reset use, so the counters and the samples are read as a
            // single coherent tuple. Both percentiles are derived from that one
            // frozen population and the max is read inside the same critical
            // section, guaranteeing p95 <= p999 <= max (uqm6ex). The clone is
            // taken under the lock but sorted after releasing it to keep the
            // critical section short.
            let acquisitions;
            let contentions;
            let wait_ns;
            let max_wait_ns;
            let mut wait_frozen;
            {
                let samples = self
                    .wait_samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                acquisitions = self.acquisitions.load(Ordering::Relaxed);
                contentions = self.contentions.load(Ordering::Relaxed);
                wait_ns = self.wait_ns.load(Ordering::Relaxed);
                max_wait_ns = self.max_wait_ns.load(Ordering::Relaxed);
                wait_frozen = samples.clone();
            }
            wait_frozen.sort_unstable();
            let p95_wait_ns = Self::percentile_from_sorted(&wait_frozen, 95, 100);
            let p999_wait_ns = Self::percentile_from_sorted(&wait_frozen, 999, 1000);

            let hold_ns;
            let max_hold_ns;
            let mut hold_frozen;
            {
                let samples = self
                    .hold_samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                hold_ns = self.hold_ns.load(Ordering::Relaxed);
                max_hold_ns = self.max_hold_ns.load(Ordering::Relaxed);
                hold_frozen = samples.clone();
            }
            hold_frozen.sort_unstable();
            let p95_hold_ns = Self::percentile_from_sorted(&hold_frozen, 95, 100);
            let p999_hold_ns = Self::percentile_from_sorted(&hold_frozen, 999, 1000);

            LockMetricsSnapshot {
                name,
                acquisitions,
                contentions,
                wait_ns,
                hold_ns,
                max_wait_ns,
                max_hold_ns,
                p95_wait_ns,
                p999_wait_ns,
                p95_hold_ns,
                p999_hold_ns,
                instrumentation_mode: "opt_in_lock_metrics",
            }
        }

        fn reset(&self) {
            // Reset each domain under its sample lock so a concurrent recorder
            // cannot interleave between zeroing the counters and clearing the
            // samples (uqm6ex). Because record_*/snapshot use the same lock,
            // the store+clear pair is observed atomically; Relaxed ordering
            // suffices since the Mutex provides the happens-before edges.
            {
                let mut samples = self
                    .wait_samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                self.acquisitions.store(0, Ordering::Relaxed);
                self.contentions.store(0, Ordering::Relaxed);
                self.wait_ns.store(0, Ordering::Relaxed);
                self.max_wait_ns.store(0, Ordering::Relaxed);
                samples.clear();
            }
            {
                let mut samples = self
                    .hold_samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                self.hold_ns.store(0, Ordering::Relaxed);
                self.max_hold_ns.store(0, Ordering::Relaxed);
                samples.clear();
            }
        }
    }

    /// Contention-instrumented mutex. Tracks wait/hold time and contention.
    #[derive(Debug)]
    pub struct ContendedMutex<T> {
        inner: Mutex<T>,
        metrics: Metrics,
        name: &'static str,
        rank: Option<LockRank>,
        module: LockModule,
    }

    impl<T> ContendedMutex<T> {
        /// Creates a new instrumented mutex with the given name and value.
        pub fn new(name: &'static str, value: T) -> Self {
            let policy = lock_ordering::enforce_lock_name_policy(name);
            Self {
                inner: Mutex::new(value),
                metrics: Metrics::default(),
                name,
                rank: policy.rank(),
                module: policy.module(),
            }
        }

        /// Acquires the mutex, tracking contention metrics.
        pub fn lock(&self) -> LockResult<ContendedMutexGuard<'_, T>> {
            // Check lock ordering before acquisition (debug builds only)
            if let Some(rank) = self.rank {
                lock_ordering::check_acquire_with_module(self.name, rank, self.module);
            }

            let start = Instant::now();

            let (result, contended) = match self.inner.try_lock() {
                Ok(guard) => (Ok(guard), false),
                Err(std::sync::TryLockError::Poisoned(poison)) => (Err(poison), false),
                Err(std::sync::TryLockError::WouldBlock) => (self.inner.lock(), true),
            };

            // Use consistent timing: capture acquisition time once
            let acquired_at = Instant::now();
            let wait_ns =
                u64::try_from(acquired_at.duration_since(start).as_nanos()).unwrap_or(u64::MAX);

            self.metrics.record_acquire(wait_ns, contended);

            // Record lock acquisition for ordering tracking
            if let Some(rank) = self.rank {
                lock_ordering::record_acquire_with_module(self.name, rank, self.module);
            }

            match result {
                Ok(guard) => Ok(ContendedMutexGuard {
                    guard: Some(guard),
                    acquired_at,
                    metrics: &self.metrics,
                    name: self.name,
                    rank: self.rank,
                    module: self.module,
                }),
                Err(poison) => Err(PoisonError::new(ContendedMutexGuard {
                    guard: Some(poison.into_inner()),
                    acquired_at,
                    metrics: &self.metrics,
                    name: self.name,
                    rank: self.rank,
                    module: self.module,
                })),
            }
        }

        /// Attempts to acquire the mutex without blocking.
        pub fn try_lock(
            &self,
        ) -> Result<ContendedMutexGuard<'_, T>, std::sync::TryLockError<ContendedMutexGuard<'_, T>>>
        {
            match self.inner.try_lock() {
                Ok(guard) => {
                    // Validate lock ordering WITHOUT unwinding through the live
                    // raw guard: a lock-order panic here would drop `guard`
                    // mid-unwind and poison otherwise-untouched data. Catch the
                    // diagnostic, drop the guard cleanly (the thread is no longer
                    // unwinding after catch_unwind), then re-raise it identically
                    // (br-asupersync-czdhfs). Checking before try_lock is wrong
                    // because a WouldBlock must remain an ordinary result.
                    if let Some(rank) = self.rank {
                        let (name, module) = (self.name, self.module);
                        if let Err(payload) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                lock_ordering::check_acquire_with_module(name, rank, module);
                            }))
                        {
                            drop(guard);
                            std::panic::resume_unwind(payload);
                        }
                        lock_ordering::record_acquire_with_module(name, rank, module);
                    }

                    let acquired_at = Instant::now();
                    self.metrics.record_acquire(0, false);
                    Ok(ContendedMutexGuard {
                        guard: Some(guard),
                        acquired_at,
                        metrics: &self.metrics,
                        name: self.name,
                        rank: self.rank,
                        module: self.module,
                    })
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    Err(std::sync::TryLockError::WouldBlock)
                }
                Err(std::sync::TryLockError::Poisoned(poison)) => {
                    if let Some(rank) = self.rank {
                        lock_ordering::check_acquire_with_module(self.name, rank, self.module);
                        lock_ordering::record_acquire_with_module(self.name, rank, self.module);
                    }
                    let acquired_at = Instant::now();
                    self.metrics.record_acquire(0, false);
                    Err(std::sync::TryLockError::Poisoned(PoisonError::new(
                        ContendedMutexGuard {
                            guard: Some(poison.into_inner()),
                            acquired_at,
                            metrics: &self.metrics,
                            name: self.name,
                            rank: self.rank,
                            module: self.module,
                        },
                    )))
                }
            }
        }

        /// Returns a snapshot of the current metrics.
        pub fn snapshot(&self) -> LockMetricsSnapshot {
            self.metrics.snapshot(self.name)
        }

        /// Resets all metrics to zero.
        pub fn reset_metrics(&self) {
            self.metrics.reset();
        }

        /// Returns the lock name.
        pub fn name(&self) -> &'static str {
            self.name
        }
    }

    /// Guard that tracks hold time on drop.
    pub struct ContendedMutexGuard<'a, T> {
        guard: Option<MutexGuard<'a, T>>,
        acquired_at: Instant,
        metrics: &'a Metrics,
        name: &'static str,
        rank: Option<LockRank>,
        module: LockModule,
    }

    impl<T> std::ops::Deref for ContendedMutexGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.guard.as_ref().expect("guard used after drop")
        }
    }

    impl<T> std::ops::DerefMut for ContendedMutexGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.guard.as_mut().expect("guard used after drop")
        }
    }

    impl<T> Drop for ContendedMutexGuard<'_, T> {
        fn drop(&mut self) {
            let hold_ns = u64::try_from(self.acquired_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
            // Drop the inner guard (releases the mutex) BEFORE updating metrics
            // to minimize the critical section length.
            drop(self.guard.take());

            // Record lock release for ordering tracking
            if let Some(rank) = self.rank {
                lock_ordering::record_release_with_module(self.name, rank, self.module);
            }

            self.metrics.record_hold(hold_ns);
        }
    }

    impl<T: std::fmt::Debug> std::fmt::Debug for ContendedMutexGuard<'_, T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ContendedMutexGuard")
                .field("data", &self.guard)
                .finish()
        }
    }
}

// ── No-op implementation (feature disabled) ───────────────────────────────

#[cfg(not(feature = "lock-metrics"))]
mod inner {
    use super::LockMetricsSnapshot;
    use crate::sync::lock_ordering::{self, LockRank};
    use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

    /// Zero-cost mutex wrapper (metrics disabled).
    #[derive(Debug)]
    pub struct ContendedMutex<T> {
        inner: Mutex<T>,
        name: &'static str,
        rank: Option<LockRank>,
    }

    impl<T> ContendedMutex<T> {
        /// Creates a new mutex with the given name and value.
        #[inline]
        pub fn new(name: &'static str, value: T) -> Self {
            let rank = lock_ordering::rank_for_lock_name(name);
            Self {
                inner: Mutex::new(value),
                name,
                rank,
            }
        }

        /// Acquires the mutex (no instrumentation).
        #[inline]
        pub fn lock(&self) -> LockResult<ContendedMutexGuard<'_, T>> {
            // Check lock ordering before acquisition (debug builds only)
            if let Some(rank) = self.rank {
                lock_ordering::check_acquire(self.name, rank);
            }

            match self.inner.lock() {
                Ok(guard) => {
                    // Record lock acquisition for ordering tracking
                    if let Some(rank) = self.rank {
                        lock_ordering::record_acquire(self.name, rank);
                    }
                    Ok(ContendedMutexGuard {
                        guard,
                        name: self.name,
                        rank: self.rank,
                    })
                }
                Err(poison) => {
                    // Record lock acquisition even for poisoned mutex
                    if let Some(rank) = self.rank {
                        lock_ordering::record_acquire(self.name, rank);
                    }
                    Err(PoisonError::new(ContendedMutexGuard {
                        guard: poison.into_inner(),
                        name: self.name,
                        rank: self.rank,
                    }))
                }
            }
        }

        /// Attempts to acquire the mutex without blocking.
        pub fn try_lock(
            &self,
        ) -> Result<ContendedMutexGuard<'_, T>, std::sync::TryLockError<ContendedMutexGuard<'_, T>>>
        {
            match self.inner.try_lock() {
                Ok(guard) => {
                    // See the lock-metrics arm: run the panic-based order check
                    // WITHOUT holding the raw guard across the unwind, so an
                    // order violation cannot poison otherwise-untouched data
                    // (br-asupersync-czdhfs). `check_acquire` is a no-op here in
                    // release (no-metrics), so the catch_unwind of the empty
                    // closure is optimized away.
                    if let Some(rank) = self.rank {
                        let name = self.name;
                        if let Err(payload) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                lock_ordering::check_acquire(name, rank);
                            }))
                        {
                            drop(guard);
                            std::panic::resume_unwind(payload);
                        }
                        lock_ordering::record_acquire(name, rank);
                    }
                    Ok(ContendedMutexGuard {
                        guard,
                        name: self.name,
                        rank: self.rank,
                    })
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    Err(std::sync::TryLockError::WouldBlock)
                }
                Err(std::sync::TryLockError::Poisoned(poison)) => {
                    if let Some(rank) = self.rank {
                        lock_ordering::check_acquire(self.name, rank);
                        lock_ordering::record_acquire(self.name, rank);
                    }
                    Err(std::sync::TryLockError::Poisoned(PoisonError::new(
                        ContendedMutexGuard {
                            guard: poison.into_inner(),
                            name: self.name,
                            rank: self.rank,
                        },
                    )))
                }
            }
        }

        /// Returns an empty snapshot (metrics disabled).
        pub fn snapshot(&self) -> LockMetricsSnapshot {
            LockMetricsSnapshot {
                name: self.name,
                instrumentation_mode: "disabled",
                ..Default::default()
            }
        }

        /// No-op (metrics disabled).
        pub fn reset_metrics(&self) {}

        /// Returns the lock name.
        pub fn name(&self) -> &'static str {
            self.name
        }
    }

    /// Zero-cost guard wrapper (metrics disabled).
    pub struct ContendedMutexGuard<'a, T> {
        guard: MutexGuard<'a, T>,
        name: &'static str,
        rank: Option<LockRank>,
    }

    impl<T> std::ops::Deref for ContendedMutexGuard<'_, T> {
        type Target = T;
        #[inline]
        fn deref(&self) -> &T {
            &self.guard
        }
    }

    impl<T> std::ops::DerefMut for ContendedMutexGuard<'_, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            &mut self.guard
        }
    }

    impl<T> Drop for ContendedMutexGuard<'_, T> {
        fn drop(&mut self) {
            // Record lock release for ordering tracking
            if let Some(rank) = self.rank {
                lock_ordering::record_release(self.name, rank);
            }
        }
    }

    impl<T: std::fmt::Debug> std::fmt::Debug for ContendedMutexGuard<'_, T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ContendedMutexGuard")
                .field("data", &*self.guard)
                .finish()
        }
    }
}

pub use inner::{ContendedMutex, ContendedMutexGuard};

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    #[cfg(feature = "lock-metrics")]
    use crate::sync::lock_ordering;
    use std::sync::Arc;
    #[cfg(feature = "lock-metrics")]
    use std::thread;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn basic_lock_unlock() {
        init_test("basic_lock_unlock");
        let m = ContendedMutex::new("unknown", 42);
        {
            let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            crate::assert_with_log!(*guard == 42, "value", 42, *guard);
            drop(guard);
        }
        crate::test_complete!("basic_lock_unlock");
    }

    #[test]
    fn mutate_through_guard() {
        init_test("mutate_through_guard");
        let m = ContendedMutex::new("unknown", 0);
        {
            let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = 99;
        }
        let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::assert_with_log!(*guard == 99, "mutated value", 99, *guard);
        drop(guard);
        crate::test_complete!("mutate_through_guard");
    }

    #[test]
    fn try_lock_succeeds_when_free() {
        init_test("try_lock_succeeds_when_free");
        let m = ContendedMutex::new("unknown", 42);
        let guard = m.try_lock().expect("should succeed");
        crate::assert_with_log!(*guard == 42, "try_lock value", 42, *guard);
        drop(guard);
        crate::test_complete!("try_lock_succeeds_when_free");
    }

    #[test]
    fn try_lock_fails_when_held() {
        init_test("try_lock_fails_when_held");
        let m = ContendedMutex::new("unknown", 42);
        let _guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_err = m.try_lock().is_err();
        crate::assert_with_log!(is_err, "try_lock fails", true, is_err);
        crate::test_complete!("try_lock_fails_when_held");
    }

    #[test]
    fn snapshot_returns_name() {
        init_test("snapshot_returns_name");
        let m = ContendedMutex::new("unknown", 0);
        let snap = m.snapshot();
        crate::assert_with_log!(snap.name == "unknown", "name", "unknown", snap.name);
        crate::test_complete!("snapshot_returns_name");
    }

    #[test]
    fn name_accessor() {
        init_test("name_accessor");
        let m = ContendedMutex::new("tasks", 0);
        crate::assert_with_log!(m.name() == "tasks", "name", "tasks", m.name());
        crate::test_complete!("name_accessor");
    }

    #[test]
    fn reset_metrics_no_panic() {
        init_test("reset_metrics_no_panic");
        let m = ContendedMutex::new("unknown", 0);
        {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        m.reset_metrics();
        let snap = m.snapshot();
        // After reset, metrics should be zero (when feature enabled) or always zero
        crate::assert_with_log!(
            snap.acquisitions == 0,
            "acquisitions after reset",
            0u64,
            snap.acquisitions
        );
        crate::test_complete!("reset_metrics_no_panic");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_track_acquisitions() {
        init_test("metrics_track_acquisitions");
        let m = ContendedMutex::new("unknown", 0);
        for _ in 0..10 {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.acquisitions == 10,
            "acquisitions",
            10u64,
            snap.acquisitions
        );
        crate::test_complete!("metrics_track_acquisitions");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_track_hold_time() {
        init_test("metrics_track_hold_time");
        let m = ContendedMutex::new("unknown", 0);
        {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let snap = m.snapshot();
        // Hold time should be at least 4ms (allowing for timing variance)
        crate::assert_with_log!(
            snap.hold_ns >= 4_000_000,
            "hold_ns >= 4ms",
            true,
            snap.hold_ns >= 4_000_000
        );
        crate::assert_with_log!(
            snap.max_hold_ns >= 4_000_000,
            "max_hold_ns >= 4ms",
            true,
            snap.max_hold_ns >= 4_000_000
        );
        crate::test_complete!("metrics_track_hold_time");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_track_contention() {
        init_test("metrics_track_contention");
        let m = Arc::new(ContendedMutex::new("unknown", 0));

        // Hold the lock while another thread tries to acquire
        let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let m2 = Arc::clone(&m);
        let handle = thread::spawn(move || {
            let _g = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        });

        // Give the other thread time to contend
        thread::sleep(std::time::Duration::from_millis(10));
        drop(guard);
        handle.join().expect("thread panicked");

        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.contentions >= 1,
            "contentions >= 1",
            true,
            snap.contentions >= 1
        );
        crate::assert_with_log!(snap.wait_ns > 0, "wait_ns > 0", true, snap.wait_ns > 0);
        crate::test_complete!("metrics_track_contention");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn reset_clears_all_metrics() {
        init_test("reset_clears_all_metrics");
        let m = ContendedMutex::new("unknown", 0);
        {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let before = m.snapshot();
        crate::assert_with_log!(
            before.acquisitions == 1,
            "before reset",
            1u64,
            before.acquisitions
        );

        m.reset_metrics();
        let after = m.snapshot();
        crate::assert_with_log!(
            after.acquisitions == 0,
            "after reset acquisitions",
            0u64,
            after.acquisitions
        );
        crate::assert_with_log!(
            after.hold_ns == 0,
            "after reset hold_ns",
            0u64,
            after.hold_ns
        );
        crate::test_complete!("reset_clears_all_metrics");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn poisoned_lock_does_not_count_as_contention() {
        init_test("poisoned_lock_does_not_count_as_contention");
        let m = Arc::new(ContendedMutex::new("unknown", 0u8));
        let m2 = Arc::clone(&m);

        let poisoner = thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional poison");
        });
        let _ = poisoner.join();

        let poison_err = m.lock().expect_err("lock should be poisoned");
        drop(poison_err.into_inner());

        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.contentions == 0,
            "poison is not contention",
            0u64,
            snap.contentions
        );
        crate::test_complete!("poisoned_lock_does_not_count_as_contention");
    }

    // Covers both `mod inner` configs: run under `cargo test` (no-metrics arm,
    // check active via debug_assertions) and `cargo test --features lock-metrics`
    // (lock-metrics arm). Gated so it is only compiled where the ordering check
    // and clear_held_locks exist (br-asupersync-czdhfs).
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn try_lock_order_violation_does_not_poison_lower_mutex() {
        use crate::sync::lock_ordering;
        init_test("try_lock_order_violation_does_not_poison_lower_mutex");
        lock_ordering::clear_held_locks();
        let high = ContendedMutex::new("tasks", 100u32); // Tasks rank (higher)
        let low = ContendedMutex::new("regions_table", 7u32); // Regions rank (lower)
        let high_guard = high.lock().expect("acquire higher rank");

        // Holding Tasks and try_lock-ing Regions inverts the hierarchy, raising
        // ASUP-E205. The raw `low` guard must be dropped cleanly (not mid-unwind)
        // before the diagnostic is re-raised.
        let inverted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = low.try_lock();
        }));
        assert!(
            inverted.is_err(),
            "inverted try_lock must raise the lock-order diagnostic"
        );

        // Release the higher rank + reset held tracking; the lower mutex must
        // still lock with unchanged data — proving the order panic did NOT poison
        // it (a poisoning drop would leave `try_lock` returning Poisoned).
        drop(high_guard);
        lock_ordering::clear_held_locks();
        match low.try_lock() {
            Ok(guard) => assert_eq!(*guard, 7u32, "lower mutex data unchanged"),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                panic!("lower mutex was poisoned by the lock-order panic")
            }
            Err(std::sync::TryLockError::WouldBlock) => panic!("unexpected WouldBlock"),
        }
        lock_ordering::clear_held_locks();
        crate::test_complete!("try_lock_order_violation_does_not_poison_lower_mutex");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn poisoned_ranked_lock_release_clears_lock_order_state() {
        init_test("poisoned_ranked_lock_release_clears_lock_order_state");
        lock_ordering::clear_held_locks();

        let m = Arc::new(ContendedMutex::new("tasks", 0u8));
        let m2 = Arc::clone(&m);

        let poisoner = thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional poison");
        });
        let _ = poisoner.join();

        let poison_err = m.lock().expect_err("lock should be poisoned");
        let guard = poison_err.into_inner();

        let held_locks = lock_ordering::current_held_locks();
        crate::assert_with_log!(
            held_locks
                .get(&lock_ordering::LockRank::Tasks)
                .map_or(0, Vec::len)
                == 1,
            "poisoned guard acquire is tracked",
            1usize,
            held_locks
                .get(&lock_ordering::LockRank::Tasks)
                .map_or(0, Vec::len)
        );

        drop(guard);

        crate::assert_with_log!(
            lock_ordering::current_held_locks().is_empty(),
            "poisoned guard drop clears held locks",
            true,
            lock_ordering::current_held_locks().is_empty()
        );
        crate::assert_with_log!(
            lock_ordering::current_held_ranks().is_empty(),
            "poisoned guard drop clears held ranks",
            true,
            lock_ordering::current_held_ranks().is_empty()
        );
        crate::test_complete!("poisoned_ranked_lock_release_clears_lock_order_state");
    }

    // =========================================================================
    // Wave 33: Data-type trait coverage
    // =========================================================================

    #[test]
    fn lock_metrics_snapshot_debug_clone_default() {
        let snap = LockMetricsSnapshot::default();
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("LockMetricsSnapshot"));
        assert_eq!(snap.acquisitions, 0);
        assert_eq!(snap.contentions, 0);
        assert_eq!(snap.wait_ns, 0);
        assert_eq!(snap.hold_ns, 0);
        assert_eq!(snap.max_wait_ns, 0);
        assert_eq!(snap.max_hold_ns, 0);
        assert_eq!(snap.p95_wait_ns, 0);
        assert_eq!(snap.p999_wait_ns, 0);
        assert_eq!(snap.p95_hold_ns, 0);
        assert_eq!(snap.p999_hold_ns, 0);
        let cloned = snap.clone();
        assert_eq!(cloned.name, snap.name);
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_snapshot_reports_tail_latencies() {
        init_test("metrics_snapshot_reports_tail_latencies");
        let m = ContendedMutex::new("tasks", 0u32);

        for _ in 0..4 {
            let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard += 1;
        }

        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.instrumentation_mode == "opt_in_lock_metrics",
            "instrumentation mode",
            "opt_in_lock_metrics",
            snap.instrumentation_mode
        );
        crate::assert_with_log!(
            snap.acquisitions == 4,
            "acquisitions",
            4u64,
            snap.acquisitions
        );
        crate::assert_with_log!(
            snap.p95_wait_ns <= snap.max_wait_ns,
            "p95 wait <= max wait",
            true,
            snap.p95_wait_ns <= snap.max_wait_ns
        );
        crate::assert_with_log!(
            snap.p999_wait_ns <= snap.max_wait_ns,
            "p999 wait <= max wait",
            true,
            snap.p999_wait_ns <= snap.max_wait_ns
        );
        crate::assert_with_log!(
            snap.p95_hold_ns <= snap.max_hold_ns,
            "p95 hold <= max hold",
            true,
            snap.p95_hold_ns <= snap.max_hold_ns
        );
        crate::assert_with_log!(
            snap.p999_hold_ns <= snap.max_hold_ns,
            "p999 hold <= max hold",
            true,
            snap.p999_hold_ns <= snap.max_hold_ns
        );
        crate::test_complete!("metrics_snapshot_reports_tail_latencies");
    }

    /// Regression for uqm6ex: every snapshot must observe a coherent
    /// `p95 <= p999 <= max` tuple for both the wait and hold domains, even
    /// while recorders and resets run concurrently. Before the fix, snapshot()
    /// cloned each population separately per percentile and read the max
    /// outside the sample lock, so an interleaved record could yield
    /// `p95 > p999` and a torn reset could zero the max while a larger sample
    /// survived (`p999 > max`).
    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_snapshot_and_reset_coherent_under_concurrency() {
        use std::sync::atomic::{AtomicBool, Ordering as AtOrd};

        init_test("metrics_snapshot_and_reset_coherent_under_concurrency");
        let m = Arc::new(ContendedMutex::new("tasks", 0u64));
        let stop = Arc::new(AtomicBool::new(false));

        // Four recorders hammer the lock: each acquire records a wait sample and
        // each guard drop records a hold sample.
        let mut recorders = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&m);
            let stop = Arc::clone(&stop);
            recorders.push(thread::spawn(move || {
                while !stop.load(AtOrd::Relaxed) {
                    let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    *guard = guard.wrapping_add(1);
                    drop(guard);
                }
            }));
        }

        // A resetter periodically clears the metrics, exercising the store+clear
        // atomicity of reset() against the recorders and the snapshotter.
        let resetter = {
            let m = Arc::clone(&m);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut i = 0u32;
                while !stop.load(AtOrd::Relaxed) {
                    i = i.wrapping_add(1);
                    if i.is_multiple_of(64) {
                        m.reset_metrics();
                    }
                    std::hint::spin_loop();
                }
            })
        };

        // Snapshot repeatedly and assert coherence on every read.
        for _ in 0..2000 {
            let snap = m.snapshot();
            crate::assert_with_log!(
                snap.p95_wait_ns <= snap.p999_wait_ns,
                "p95_wait <= p999_wait under concurrency",
                true,
                snap.p95_wait_ns <= snap.p999_wait_ns
            );
            crate::assert_with_log!(
                snap.p999_wait_ns <= snap.max_wait_ns,
                "p999_wait <= max_wait under concurrency",
                true,
                snap.p999_wait_ns <= snap.max_wait_ns
            );
            crate::assert_with_log!(
                snap.p95_hold_ns <= snap.p999_hold_ns,
                "p95_hold <= p999_hold under concurrency",
                true,
                snap.p95_hold_ns <= snap.p999_hold_ns
            );
            crate::assert_with_log!(
                snap.p999_hold_ns <= snap.max_hold_ns,
                "p999_hold <= max_hold under concurrency",
                true,
                snap.p999_hold_ns <= snap.max_hold_ns
            );
        }

        stop.store(true, AtOrd::Relaxed);
        for h in recorders {
            let _ = h.join();
        }
        let _ = resetter.join();

        // Linearizable reset: with recorders quiesced, a final reset zeroes
        // every counter and clears both sample populations coherently.
        m.reset_metrics();
        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.acquisitions == 0,
            "reset zeroes acquisitions",
            0u64,
            snap.acquisitions
        );
        crate::assert_with_log!(
            snap.max_wait_ns == 0,
            "reset zeroes max_wait_ns",
            0u64,
            snap.max_wait_ns
        );
        crate::assert_with_log!(
            snap.max_hold_ns == 0,
            "reset zeroes max_hold_ns",
            0u64,
            snap.max_hold_ns
        );
        crate::assert_with_log!(
            snap.p999_wait_ns == 0,
            "reset clears wait samples",
            0u64,
            snap.p999_wait_ns
        );
        crate::assert_with_log!(
            snap.p999_hold_ns == 0,
            "reset clears hold samples",
            0u64,
            snap.p999_hold_ns
        );
        crate::test_complete!("metrics_snapshot_and_reset_coherent_under_concurrency");
    }

    #[test]
    fn contended_mutex_debug() {
        let m = ContendedMutex::new("unknown", 42_i32);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ContendedMutex"));
    }

    #[test]
    fn contended_mutex_guard_debug() {
        let m = ContendedMutex::new("unknown", 42_i32);
        let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("ContendedMutexGuard"));
        drop(guard);
    }

    #[test]
    fn try_lock_returns_poisoned_after_panic() {
        init_test("try_lock_returns_poisoned_after_panic");
        let m = Arc::new(ContendedMutex::new("unknown", 7u32));
        let m2 = Arc::clone(&m);
        let poisoner = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("deliberate poison");
        });
        let _ = poisoner.join();

        let result = m.try_lock();
        let is_poisoned = matches!(result, Err(std::sync::TryLockError::Poisoned(_)));
        crate::assert_with_log!(is_poisoned, "try_lock returns Poisoned", true, is_poisoned);

        // Recover data through the poison error.
        if let Err(std::sync::TryLockError::Poisoned(pe)) = m.try_lock() {
            let guard = pe.into_inner();
            crate::assert_with_log!(*guard == 7, "data preserved", 7u32, *guard);
        }
        crate::test_complete!("try_lock_returns_poisoned_after_panic");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn hold_time_recorded_on_panic_in_critical_section() {
        init_test("hold_time_recorded_on_panic_in_critical_section");
        let m = Arc::new(ContendedMutex::new("unknown", 0u32));
        let m2 = Arc::clone(&m);

        let handle = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::thread::sleep(std::time::Duration::from_millis(5));
            panic!("panic while holding guard");
        });
        let _ = handle.join();

        // Guard::drop should have recorded hold time even though thread panicked.
        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.hold_ns >= 4_000_000,
            "hold_ns recorded despite panic",
            true,
            snap.hold_ns >= 4_000_000
        );
        crate::test_complete!("hold_time_recorded_on_panic_in_critical_section");
    }
}
