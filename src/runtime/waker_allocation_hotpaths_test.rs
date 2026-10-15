//! Test demonstrating waker allocation hot paths.
//!
//! These tests intentionally assert deterministic behavior instead of printing
//! timing measurements. Performance baselines belong in benches or artifacts;
//! unit tests should fail on semantic regressions.

use super::{WakeSource, WakerState};
use crate::types::TaskId;
use crate::util::ArenaIndex;
use std::sync::Arc;

#[cfg(feature = "waker-profiling")]
use super::waker_profiling::{get_waker_metrics, profiling_enabled, reset_waker_metrics};

#[cfg(feature = "waker-profiling")]
fn lock_metrics() -> std::sync::MutexGuard<'static, ()> {
    static METRICS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    METRICS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn task_id(n: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(n, 0))
}

#[test]
fn hotpath_waker_creation_drains_every_unique_task_once() {
    #[cfg(feature = "waker-profiling")]
    let _metrics_guard = lock_metrics();
    #[cfg(feature = "waker-profiling")]
    reset_waker_metrics();

    const TASK_COUNT: u32 = 128;
    let state = Arc::new(WakerState::new());
    let wakers: Vec<_> = (0..TASK_COUNT)
        .map(|i| state.waker_for(task_id(i)))
        .collect();

    for waker in &wakers {
        waker.wake_by_ref();
    }

    let woken = state.drain_woken();
    let expected: Vec<_> = (0..TASK_COUNT).map(task_id).collect();
    assert_eq!(woken, expected);
    assert!(!state.has_woken());

    #[cfg(feature = "waker-profiling")]
    if profiling_enabled() {
        let metrics = get_waker_metrics();
        assert_eq!(metrics.waker_allocations, u64::from(TASK_COUNT));
        assert_eq!(metrics.wake_operations, u64::from(TASK_COUNT));
        assert_eq!(metrics.drain_operations, 1);
        assert_eq!(metrics.dedup_hits, 0);
    }
}

#[test]
fn hotpath_repeated_wakes_are_deduplicated_until_drain() {
    #[cfg(feature = "waker-profiling")]
    let _metrics_guard = lock_metrics();
    #[cfg(feature = "waker-profiling")]
    reset_waker_metrics();

    const WAKE_COUNT: u32 = 128;
    let state = Arc::new(WakerState::new());
    let waker = state.waker_for(task_id(1));

    for _ in 0..WAKE_COUNT {
        waker.wake_by_ref();
    }

    assert_eq!(state.drain_woken(), vec![task_id(1)]);
    assert!(state.drain_woken().is_empty());

    #[cfg(feature = "waker-profiling")]
    if profiling_enabled() {
        let metrics = get_waker_metrics();
        assert_eq!(metrics.waker_allocations, 1);
        assert_eq!(metrics.wake_operations, u64::from(WAKE_COUNT));
        assert_eq!(metrics.dedup_hits, u64::from(WAKE_COUNT - 1));
        assert_eq!(metrics.drain_operations, 2);
    }
}

#[test]
fn hotpath_cloned_wakers_share_the_same_task_slot() {
    #[cfg(feature = "waker-profiling")]
    let _metrics_guard = lock_metrics();
    #[cfg(feature = "waker-profiling")]
    reset_waker_metrics();

    let state = Arc::new(WakerState::new());
    let waker = state.waker_for(task_id(7));
    let clones: Vec<_> = (0..16).map(|_| waker.clone()).collect();

    for cloned_waker in &clones {
        cloned_waker.wake_by_ref();
    }

    assert_eq!(state.drain_woken(), vec![task_id(7)]);

    #[cfg(feature = "waker-profiling")]
    if profiling_enabled() {
        let metrics = get_waker_metrics();
        assert_eq!(metrics.waker_allocations, 1);
        assert_eq!(metrics.wake_operations, 16);
        assert_eq!(metrics.dedup_hits, 15);
    }
}

#[test]
fn hotpath_wake_source_types_preserve_task_identity() {
    #[cfg(feature = "waker-profiling")]
    let _metrics_guard = lock_metrics();
    #[cfg(feature = "waker-profiling")]
    reset_waker_metrics();

    let state = Arc::new(WakerState::new());
    let wakers = [
        state.waker_for_source(task_id(1), WakeSource::Timer),
        state.waker_for_source(task_id(2), WakeSource::Io { fd: 42 }),
        state.waker_for_source(task_id(3), WakeSource::Explicit),
        state.waker_for(task_id(4)),
    ];

    for waker in &wakers {
        waker.wake_by_ref();
    }

    assert_eq!(
        state.drain_woken(),
        vec![task_id(1), task_id(2), task_id(3), task_id(4)]
    );
}
