//! Profiling instrumentation for waker allocation hot paths.
//!
//! This module provides instrumentation for understanding allocation patterns
//! and performance characteristics of waker operations.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global waker allocation metrics for profiling.
pub struct WakerMetrics {
    /// Total waker allocations (Arc<TaskWaker>)
    pub waker_allocations: AtomicU64,
    /// Total wake operations
    pub wake_operations: AtomicU64,
    /// Total drain operations
    pub drain_operations: AtomicU64,
    /// Total task deduplication hits
    pub dedup_hits: AtomicU64,
    /// Total lock acquisitions on woken set
    pub lock_acquisitions: AtomicU64,
}

static WAKER_METRICS: WakerMetrics = WakerMetrics {
    waker_allocations: AtomicU64::new(0),
    wake_operations: AtomicU64::new(0),
    drain_operations: AtomicU64::new(0),
    dedup_hits: AtomicU64::new(0),
    lock_acquisitions: AtomicU64::new(0),
};

/// Snapshot of waker allocation metrics at a point in time.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakerMetricsSnapshot {
    pub waker_allocations: u64,
    pub wake_operations: u64,
    pub drain_operations: u64,
    pub dedup_hits: u64,
    pub lock_acquisitions: u64,
}

/// Returns current waker allocation metrics.
#[cfg(test)]
#[inline]
pub fn get_waker_metrics() -> WakerMetricsSnapshot {
    WakerMetricsSnapshot {
        waker_allocations: WAKER_METRICS.waker_allocations.load(Ordering::Relaxed),
        wake_operations: WAKER_METRICS.wake_operations.load(Ordering::Relaxed),
        drain_operations: WAKER_METRICS.drain_operations.load(Ordering::Relaxed),
        dedup_hits: WAKER_METRICS.dedup_hits.load(Ordering::Relaxed),
        lock_acquisitions: WAKER_METRICS.lock_acquisitions.load(Ordering::Relaxed),
    }
}

/// Resets waker allocation metrics to zero.
#[cfg(test)]
pub fn reset_waker_metrics() {
    WAKER_METRICS.waker_allocations.store(0, Ordering::Relaxed);
    WAKER_METRICS.wake_operations.store(0, Ordering::Relaxed);
    WAKER_METRICS.drain_operations.store(0, Ordering::Relaxed);
    WAKER_METRICS.dedup_hits.store(0, Ordering::Relaxed);
    WAKER_METRICS.lock_acquisitions.store(0, Ordering::Relaxed);
}

/// Profile sentinel for waker allocation operations.
#[inline(never)]
pub(super) fn profile_waker_allocation() {
    WAKER_METRICS
        .waker_allocations
        .fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for wake operations.
#[inline(never)]
pub(super) fn profile_wake_operation() {
    WAKER_METRICS
        .wake_operations
        .fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for drain operations.
#[inline(never)]
pub(super) fn profile_drain_operation() {
    WAKER_METRICS
        .drain_operations
        .fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for deduplication hits.
#[inline(never)]
pub(super) fn profile_dedup_hit() {
    WAKER_METRICS.dedup_hits.fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for lock acquisitions.
#[inline(never)]
pub(super) fn profile_lock_acquisition() {
    WAKER_METRICS
        .lock_acquisitions
        .fetch_add(1, Ordering::Relaxed);
}

/// Environment check for profiling instrumentation.
/// Returns true if WAKER_PROFILING env var is set.
#[inline]
pub fn profiling_enabled() -> bool {
    std::env::var("WAKER_PROFILING").is_ok()
}

/// Macro for conditional profiling instrumentation.
macro_rules! profile {
    ($sentinel:expr) => {
        if $crate::runtime::waker::waker_profiling::profiling_enabled() {
            $sentinel();
        }
    };
}

pub(crate) use profile;

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

    #[test]
    fn test_waker_metrics() {
        reset_waker_metrics();

        let initial = get_waker_metrics();
        assert_eq!(initial.waker_allocations, 0);
        assert_eq!(initial.wake_operations, 0);

        // Simulate some operations
        profile_waker_allocation();
        profile_wake_operation();
        profile_dedup_hit();
        profile_lock_acquisition();

        let after = get_waker_metrics();
        assert_eq!(after.waker_allocations, 1);
        assert_eq!(after.wake_operations, 1);
        assert_eq!(after.dedup_hits, 1);
        assert_eq!(after.lock_acquisitions, 1);

        reset_waker_metrics();
        let reset = get_waker_metrics();
        assert_eq!(reset.waker_allocations, 0);
    }
}
