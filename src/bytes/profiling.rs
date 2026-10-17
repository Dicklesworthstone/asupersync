//! Profiling instrumentation for bytes allocation hot paths.
//!
//! This module provides instrumentation for understanding allocation patterns
//! and performance characteristics of Bytes/BytesMut operations.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global allocation counters for profiling.
pub struct AllocationMetrics {
    /// Total Bytes allocations (`Arc<Vec<u8>>`)
    pub bytes_allocations: AtomicU64,
    /// Total BytesMut allocations
    pub bytes_mut_allocations: AtomicU64,
    /// Total BytesMut growth operations (reallocation)
    pub bytes_mut_growth: AtomicU64,
    /// Total bytes copied in split_to operations
    pub split_to_copies: AtomicU64,
    /// Total freeze operations (BytesMut -> Bytes)
    pub freeze_operations: AtomicU64,
}

static ALLOCATION_METRICS: AllocationMetrics = AllocationMetrics {
    bytes_allocations: AtomicU64::new(0),
    bytes_mut_allocations: AtomicU64::new(0),
    bytes_mut_growth: AtomicU64::new(0),
    split_to_copies: AtomicU64::new(0),
    freeze_operations: AtomicU64::new(0),
};

/// Returns current allocation metrics.
#[inline]
pub fn get_allocation_metrics() -> AllocationSnapshot {
    AllocationSnapshot {
        bytes_allocations: ALLOCATION_METRICS.bytes_allocations.load(Ordering::Relaxed),
        bytes_mut_allocations: ALLOCATION_METRICS
            .bytes_mut_allocations
            .load(Ordering::Relaxed),
        bytes_mut_growth: ALLOCATION_METRICS.bytes_mut_growth.load(Ordering::Relaxed),
        split_to_copies: ALLOCATION_METRICS.split_to_copies.load(Ordering::Relaxed),
        freeze_operations: ALLOCATION_METRICS.freeze_operations.load(Ordering::Relaxed),
    }
}

/// Resets allocation metrics to zero.
pub fn reset_allocation_metrics() {
    ALLOCATION_METRICS
        .bytes_allocations
        .store(0, Ordering::Relaxed);
    ALLOCATION_METRICS
        .bytes_mut_allocations
        .store(0, Ordering::Relaxed);
    ALLOCATION_METRICS
        .bytes_mut_growth
        .store(0, Ordering::Relaxed);
    ALLOCATION_METRICS
        .split_to_copies
        .store(0, Ordering::Relaxed);
    ALLOCATION_METRICS
        .freeze_operations
        .store(0, Ordering::Relaxed);
}

/// Snapshot of allocation metrics at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationSnapshot {
    /// Total Bytes allocations observed at snapshot time.
    pub bytes_allocations: u64,
    /// Total BytesMut allocations observed at snapshot time.
    pub bytes_mut_allocations: u64,
    /// Total BytesMut growth operations observed at snapshot time.
    pub bytes_mut_growth: u64,
    /// Total bytes copied by split_to-style operations.
    pub split_to_copies: u64,
    /// Total BytesMut freeze operations observed at snapshot time.
    pub freeze_operations: u64,
}

/// Profile sentinel for Bytes allocation operations.
#[inline(never)]
fn _profile_bytes_allocation() {
    ALLOCATION_METRICS
        .bytes_allocations
        .fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for BytesMut allocation operations.
#[inline(never)]
fn _profile_bytes_mut_allocation() {
    ALLOCATION_METRICS
        .bytes_mut_allocations
        .fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for BytesMut growth operations.
#[inline(never)]
fn _profile_bytes_mut_growth() {
    ALLOCATION_METRICS
        .bytes_mut_growth
        .fetch_add(1, Ordering::Relaxed);
}

/// Profile sentinel for split_to copy operations.
#[inline(never)]
fn _profile_split_to_copy(bytes_copied: usize) {
    ALLOCATION_METRICS
        .split_to_copies
        .fetch_add(bytes_copied as u64, Ordering::Relaxed);
}

/// Profile sentinel for freeze operations.
#[allow(clippy::used_underscore_items)]
#[inline(never)]
fn _profile_freeze_operation() {
    ALLOCATION_METRICS
        .freeze_operations
        .fetch_add(1, Ordering::Relaxed);
}

use std::sync::atomic::AtomicU8;

static PROFILING_ENABLED: AtomicU8 = AtomicU8::new(0); // 0 = uninit, 1 = true, 2 = false

/// Environment check for profiling instrumentation.
/// Returns true if BYTES_PROFILING env var is set.
#[inline]
pub fn profiling_enabled() -> bool {
    let mut val = PROFILING_ENABLED.load(Ordering::Relaxed);
    if val == 0 {
        val = if std::env::var("BYTES_PROFILING").is_ok() {
            1
        } else {
            2
        };
        PROFILING_ENABLED.store(val, Ordering::Relaxed);
    }
    val == 1
}

/// Macro for conditional profiling instrumentation.
#[allow(unused_macros)]
macro_rules! profile {
    ($sentinel:expr) => {
        if crate::bytes::profiling::profiling_enabled() {
            $sentinel;
        }
    };
    ($sentinel:expr, $arg:expr) => {
        if crate::bytes::profiling::profiling_enabled() {
            $sentinel($arg);
        }
    };
}

#[allow(unused_imports)]
pub(crate) use profile;

#[cfg(test)]
#[path = "profiling_inline_tests.rs"]
mod tests;
