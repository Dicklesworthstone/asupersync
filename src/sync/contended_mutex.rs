//! Feature-gated contention-instrumented mutex.
//!
//! When the `lock-metrics` feature is enabled, `ContendedMutex<T>` wraps
//! `std::sync::Mutex<T>` and tracks wait time, hold time, contention count,
//! and total acquisitions. When disabled, it's a zero-cost wrapper.
//!
//! # Usage
//!
//! ```
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
    /// Number of retained most-recent wait samples used for wait percentiles.
    /// Zero means instrumentation is disabled or no wait samples are retained.
    pub wait_percentile_sample_count: u64,
    /// Exact p95 wait duration in nanoseconds over the retained most-recent
    /// wait-sample suffix.
    pub p95_wait_ns: u64,
    /// Exact p999 wait duration in nanoseconds over the retained most-recent
    /// wait-sample suffix.
    pub p999_wait_ns: u64,
    /// Number of retained most-recent hold samples used for hold percentiles.
    /// Zero means instrumentation is disabled or no hold samples are retained.
    pub hold_percentile_sample_count: u64,
    /// Exact p95 hold duration in nanoseconds over the retained most-recent
    /// hold-sample suffix.
    pub p95_hold_ns: u64,
    /// Exact p999 hold duration in nanoseconds over the retained most-recent
    /// hold-sample suffix.
    pub p999_hold_ns: u64,
    /// Instrumentation mode used to produce this snapshot.
    pub instrumentation_mode: &'static str,
}

// ── Feature-gated implementation ──────────────────────────────────────────

#[cfg(feature = "lock-metrics")]
mod inner {
    use super::LockMetricsSnapshot;
    use crate::sync::lock_ordering::{self, LockModule, LockRank};
    use std::collections::VecDeque;
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
        wait_samples: Mutex<VecDeque<u64>>,
        hold_samples: Mutex<VecDeque<u64>>,
    }

    const MAX_SAMPLES: usize = 10_000;

    impl Metrics {
        fn update_max(current: &AtomicU64, value: u64) {
            current.fetch_max(value, Ordering::Relaxed);
        }

        /// Retain the exact most-recent sample suffix with O(1) FIFO eviction.
        fn record_sample(samples: &mut VecDeque<u64>, sample: u64) {
            if samples.len() == MAX_SAMPLES {
                let evicted = samples.pop_front();
                debug_assert!(evicted.is_some());
            } else if samples.capacity() == 0 {
                // Reserve the whole window on the first sample: growing it by
                // doubling would allocate on the lock path the feature measures.
                samples.reserve_exact(MAX_SAMPLES);
            }
            samples.push_back(sample);
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

            Self::record_sample(&mut samples, wait_ns);
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

            Self::record_sample(&mut samples, hold_ns);
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
            // section, guaranteeing p95 <= p999 <= max (uqm6ex). The frozen
            // copy is taken under the lock but sorted after releasing it to
            // keep the critical section short.
            let acquisitions;
            let contentions;
            let wait_ns;
            let max_wait_ns;
            let mut wait_frozen: Vec<u64>;
            {
                let samples = self
                    .wait_samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                acquisitions = self.acquisitions.load(Ordering::Relaxed);
                contentions = self.contentions.load(Ordering::Relaxed);
                wait_ns = self.wait_ns.load(Ordering::Relaxed);
                max_wait_ns = self.max_wait_ns.load(Ordering::Relaxed);
                wait_frozen = samples.iter().copied().collect();
            }
            let wait_percentile_sample_count = u64::try_from(wait_frozen.len()).unwrap_or(u64::MAX);
            wait_frozen.sort_unstable();
            let p95_wait_ns = Self::percentile_from_sorted(&wait_frozen, 95, 100);
            let p999_wait_ns = Self::percentile_from_sorted(&wait_frozen, 999, 1000);

            let hold_ns;
            let max_hold_ns;
            let mut hold_frozen: Vec<u64>;
            {
                let samples = self
                    .hold_samples
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                hold_ns = self.hold_ns.load(Ordering::Relaxed);
                max_hold_ns = self.max_hold_ns.load(Ordering::Relaxed);
                hold_frozen = samples.iter().copied().collect();
            }
            let hold_percentile_sample_count = u64::try_from(hold_frozen.len()).unwrap_or(u64::MAX);
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
                wait_percentile_sample_count,
                p95_wait_ns,
                p999_wait_ns,
                hold_percentile_sample_count,
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

    #[cfg(test)]
    mod tests {
        use super::{MAX_SAMPLES, Metrics};

        #[test]
        fn the_sample_window_is_reserved_once_on_the_first_sample() {
            let metrics = Metrics::default();
            metrics.record_acquire(1, false);
            let reserved = metrics.wait_samples.lock().unwrap().capacity();
            assert!(reserved >= MAX_SAMPLES, "reserved {reserved}");
            for sample in 0..(MAX_SAMPLES as u64 + 10) {
                metrics.record_acquire(sample, false);
            }
            assert_eq!(metrics.wait_samples.lock().unwrap().capacity(), reserved);
        }

        #[test]
        fn percentile_horizon_reports_retained_suffix_and_all_history_counters() {
            let metrics = Metrics::default();

            for _ in 0..2_500 {
                metrics.record_acquire(1_000, true);
                metrics.record_hold(1_000);
            }
            for _ in 0..7_500 {
                metrics.record_acquire(1, false);
                metrics.record_hold(1);
            }

            let full = metrics.snapshot("percentile_horizon");
            assert_eq!(full.wait_percentile_sample_count, 10_000);
            assert_eq!(full.hold_percentile_sample_count, 10_000);
            assert_eq!(full.p95_wait_ns, 1_000);
            assert_eq!(full.p999_wait_ns, 1_000);
            assert_eq!(full.p95_hold_ns, 1_000);
            assert_eq!(full.p999_hold_ns, 1_000);

            for _ in 0..2_500 {
                metrics.record_acquire(1, false);
                metrics.record_hold(1);
            }

            let evicted = metrics.snapshot("percentile_horizon");
            assert_eq!(evicted.wait_percentile_sample_count, 10_000);
            assert_eq!(evicted.hold_percentile_sample_count, 10_000);
            assert_eq!(evicted.p95_wait_ns, 1);
            assert_eq!(evicted.p999_wait_ns, 1);
            assert_eq!(evicted.p95_hold_ns, 1);
            assert_eq!(evicted.p999_hold_ns, 1);

            assert_eq!(evicted.acquisitions, 12_500);
            assert_eq!(evicted.contentions, 2_500);
            assert_eq!(evicted.wait_ns, 2_510_000);
            assert_eq!(evicted.max_wait_ns, 1_000);
            assert_eq!(evicted.hold_ns, 2_510_000);
            assert_eq!(evicted.max_hold_ns, 1_000);
        }

        #[test]
        fn sample_rings_replace_fifo_one_at_a_time_across_wraps() {
            let metrics = Metrics::default();
            let max_samples = u64::try_from(MAX_SAMPLES).expect("sample bound fits u64");

            for sample in 0..max_samples {
                metrics.record_acquire(sample, false);
                metrics.record_hold(sample);
            }

            let wait_capacity = metrics
                .wait_samples
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .capacity();
            let hold_capacity = metrics
                .hold_samples
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .capacity();

            metrics.record_acquire(max_samples, false);
            metrics.record_hold(max_samples);
            {
                let samples = metrics
                    .wait_samples
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(samples.len(), MAX_SAMPLES);
                assert_eq!(samples.capacity(), wait_capacity);
                assert_eq!(samples.front().copied(), Some(1));
                assert_eq!(samples.back().copied(), Some(max_samples));
            }
            {
                let samples = metrics
                    .hold_samples
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(samples.len(), MAX_SAMPLES);
                assert_eq!(samples.capacity(), hold_capacity);
                assert_eq!(samples.front().copied(), Some(1));
                assert_eq!(samples.back().copied(), Some(max_samples));
            }

            let total_samples = max_samples * 3 + 17;
            for sample in (max_samples + 1)..total_samples {
                metrics.record_acquire(sample, false);
                metrics.record_hold(sample);
            }

            let expected_front = total_samples - max_samples;
            let expected_back = total_samples - 1;
            {
                let samples = metrics
                    .wait_samples
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(samples.len(), MAX_SAMPLES);
                assert_eq!(samples.capacity(), wait_capacity);
                assert_eq!(samples.front().copied(), Some(expected_front));
                assert_eq!(samples.back().copied(), Some(expected_back));
            }
            {
                let samples = metrics
                    .hold_samples
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(samples.len(), MAX_SAMPLES);
                assert_eq!(samples.capacity(), hold_capacity);
                assert_eq!(samples.front().copied(), Some(expected_front));
                assert_eq!(samples.back().copied(), Some(expected_back));
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
        ///
        /// # Panics
        ///
        /// Panics if `name` is outside the lock-name policy (see `lock_ordering::enforce_lock_name_policy`).
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
        ///
        /// Note: When the `lock-metrics` feature is enabled, panics if `name` is outside
        /// the lock-name policy (see `lock_ordering::enforce_lock_name_policy`).
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
#[path = "contended_mutex_inline_tests.rs"]
mod tests;
