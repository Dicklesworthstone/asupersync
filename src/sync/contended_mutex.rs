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
//!     let guard = m.lock().expect("poisoned");
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
}

// ── Feature-gated implementation ──────────────────────────────────────────

#[cfg(feature = "lock-metrics")]
mod inner {
    use super::LockMetricsSnapshot;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};
    use std::time::Instant;

    #[derive(Debug)]
    struct Metrics {
        acquisitions: AtomicU64,
        contentions: AtomicU64,
        wait_ns: AtomicU64,
        hold_ns: AtomicU64,
        max_wait_ns: AtomicU64,
        max_hold_ns: AtomicU64,
    }

    impl Default for Metrics {
        fn default() -> Self {
            Self {
                acquisitions: AtomicU64::new(0),
                contentions: AtomicU64::new(0),
                wait_ns: AtomicU64::new(0),
                hold_ns: AtomicU64::new(0),
                max_wait_ns: AtomicU64::new(0),
                max_hold_ns: AtomicU64::new(0),
            }
        }
    }

    impl Metrics {
        fn update_max(current: &AtomicU64, value: u64) {
            let mut old = current.load(Ordering::Relaxed);
            while value > old {
                match current.compare_exchange_weak(
                    old,
                    value,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => old = actual,
                }
            }
        }
    }

    /// Contention-instrumented mutex. Tracks wait/hold time and contention.
    #[derive(Debug)]
    pub struct ContendedMutex<T> {
        inner: Mutex<T>,
        metrics: Metrics,
        name: &'static str,
    }

    impl<T> ContendedMutex<T> {
        /// Creates a new instrumented mutex with the given name and value.
        pub fn new(name: &'static str, value: T) -> Self {
            Self {
                inner: Mutex::new(value),
                metrics: Metrics::default(),
                name,
            }
        }

        /// Acquires the mutex, tracking contention metrics.
        pub fn lock(&self) -> LockResult<ContendedMutexGuard<'_, T>> {
            let start = Instant::now();
            let contended = self.inner.try_lock().is_err();

            let result = self.inner.lock();
            let wait_ns = start.elapsed().as_nanos() as u64;

            self.metrics.acquisitions.fetch_add(1, Ordering::Relaxed);
            self.metrics.wait_ns.fetch_add(wait_ns, Ordering::Relaxed);
            Metrics::update_max(&self.metrics.max_wait_ns, wait_ns);

            if contended {
                self.metrics.contentions.fetch_add(1, Ordering::Relaxed);
            }

            match result {
                Ok(guard) => Ok(ContendedMutexGuard {
                    guard: Some(guard),
                    acquired_at: Instant::now(),
                    metrics: &self.metrics,
                }),
                Err(poison) => Err(PoisonError::new(ContendedMutexGuard {
                    guard: Some(poison.into_inner()),
                    acquired_at: Instant::now(),
                    metrics: &self.metrics,
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
                    self.metrics.acquisitions.fetch_add(1, Ordering::Relaxed);
                    Ok(ContendedMutexGuard {
                        guard: Some(guard),
                        acquired_at: Instant::now(),
                        metrics: &self.metrics,
                    })
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    Err(std::sync::TryLockError::WouldBlock)
                }
                Err(std::sync::TryLockError::Poisoned(poison)) => Err(
                    std::sync::TryLockError::Poisoned(PoisonError::new(ContendedMutexGuard {
                        guard: Some(poison.into_inner()),
                        acquired_at: Instant::now(),
                        metrics: &self.metrics,
                    })),
                ),
            }
        }

        /// Returns a snapshot of the current metrics.
        pub fn snapshot(&self) -> LockMetricsSnapshot {
            LockMetricsSnapshot {
                name: self.name,
                acquisitions: self.metrics.acquisitions.load(Ordering::Relaxed),
                contentions: self.metrics.contentions.load(Ordering::Relaxed),
                wait_ns: self.metrics.wait_ns.load(Ordering::Relaxed),
                hold_ns: self.metrics.hold_ns.load(Ordering::Relaxed),
                max_wait_ns: self.metrics.max_wait_ns.load(Ordering::Relaxed),
                max_hold_ns: self.metrics.max_hold_ns.load(Ordering::Relaxed),
            }
        }

        /// Resets all metrics to zero.
        pub fn reset_metrics(&self) {
            self.metrics.acquisitions.store(0, Ordering::Relaxed);
            self.metrics.contentions.store(0, Ordering::Relaxed);
            self.metrics.wait_ns.store(0, Ordering::Relaxed);
            self.metrics.hold_ns.store(0, Ordering::Relaxed);
            self.metrics.max_wait_ns.store(0, Ordering::Relaxed);
            self.metrics.max_hold_ns.store(0, Ordering::Relaxed);
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
            let hold_ns = self.acquired_at.elapsed().as_nanos() as u64;
            self.metrics.hold_ns.fetch_add(hold_ns, Ordering::Relaxed);
            Metrics::update_max(&self.metrics.max_hold_ns, hold_ns);
            // Drop the inner guard (releases the mutex).
            drop(self.guard.take());
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
    use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

    /// Zero-cost mutex wrapper (metrics disabled).
    #[derive(Debug)]
    pub struct ContendedMutex<T> {
        inner: Mutex<T>,
        name: &'static str,
    }

    impl<T> ContendedMutex<T> {
        /// Creates a new mutex with the given name and value.
        #[inline]
        pub fn new(name: &'static str, value: T) -> Self {
            Self {
                inner: Mutex::new(value),
                name,
            }
        }

        /// Acquires the mutex (no instrumentation).
        #[inline]
        pub fn lock(&self) -> LockResult<ContendedMutexGuard<'_, T>> {
            match self.inner.lock() {
                Ok(guard) => Ok(ContendedMutexGuard { guard }),
                Err(poison) => Err(PoisonError::new(ContendedMutexGuard {
                    guard: poison.into_inner(),
                })),
            }
        }

        /// Attempts to acquire the mutex without blocking.
        pub fn try_lock(
            &self,
        ) -> Result<ContendedMutexGuard<'_, T>, std::sync::TryLockError<ContendedMutexGuard<'_, T>>>
        {
            match self.inner.try_lock() {
                Ok(guard) => Ok(ContendedMutexGuard { guard }),
                Err(std::sync::TryLockError::WouldBlock) => {
                    Err(std::sync::TryLockError::WouldBlock)
                }
                Err(std::sync::TryLockError::Poisoned(poison)) => Err(
                    std::sync::TryLockError::Poisoned(PoisonError::new(ContendedMutexGuard {
                        guard: poison.into_inner(),
                    })),
                ),
            }
        }

        /// Returns an empty snapshot (metrics disabled).
        pub fn snapshot(&self) -> LockMetricsSnapshot {
            LockMetricsSnapshot {
                name: self.name,
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
        let m = ContendedMutex::new("test", 42);
        {
            let guard = m.lock().expect("poisoned");
            crate::assert_with_log!(*guard == 42, "value", 42, *guard);
            drop(guard);
        }
        crate::test_complete!("basic_lock_unlock");
    }

    #[test]
    fn mutate_through_guard() {
        init_test("mutate_through_guard");
        let m = ContendedMutex::new("test", 0);
        {
            let mut guard = m.lock().expect("poisoned");
            *guard = 99;
        }
        let guard = m.lock().expect("poisoned");
        crate::assert_with_log!(*guard == 99, "mutated value", 99, *guard);
        drop(guard);
        crate::test_complete!("mutate_through_guard");
    }

    #[test]
    fn try_lock_succeeds_when_free() {
        init_test("try_lock_succeeds_when_free");
        let m = ContendedMutex::new("test", 42);
        let guard = m.try_lock().expect("should succeed");
        crate::assert_with_log!(*guard == 42, "try_lock value", 42, *guard);
        drop(guard);
        crate::test_complete!("try_lock_succeeds_when_free");
    }

    #[test]
    fn try_lock_fails_when_held() {
        init_test("try_lock_fails_when_held");
        let m = ContendedMutex::new("test", 42);
        let _guard = m.lock().expect("poisoned");
        let is_err = m.try_lock().is_err();
        crate::assert_with_log!(is_err, "try_lock fails", true, is_err);
        crate::test_complete!("try_lock_fails_when_held");
    }

    #[test]
    fn snapshot_returns_name() {
        init_test("snapshot_returns_name");
        let m = ContendedMutex::new("my-shard", 0);
        let snap = m.snapshot();
        crate::assert_with_log!(snap.name == "my-shard", "name", "my-shard", snap.name);
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
        let m = ContendedMutex::new("test", 0);
        {
            let _g = m.lock().expect("poisoned");
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
        let m = ContendedMutex::new("test", 0);
        for _ in 0..10 {
            let _g = m.lock().expect("poisoned");
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
        let m = ContendedMutex::new("test", 0);
        {
            let _g = m.lock().expect("poisoned");
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
        let m = Arc::new(ContendedMutex::new("test", 0));

        // Hold the lock while another thread tries to acquire
        let guard = m.lock().expect("poisoned");

        let m2 = Arc::clone(&m);
        let handle = thread::spawn(move || {
            let _g = m2.lock().expect("poisoned");
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
        let m = ContendedMutex::new("test", 0);
        {
            let _g = m.lock().expect("poisoned");
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
}
