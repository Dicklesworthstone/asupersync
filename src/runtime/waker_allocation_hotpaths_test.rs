//! Test demonstrating waker allocation hot paths.
//!
//! This test serves as a baseline measurement for profiling waker allocation patterns.

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use crate::runtime::waker::{WakerState, WakeSource};
    use crate::types::TaskId;
    use crate::util::ArenaIndex;
    use std::time::Instant;
    use std::sync::Arc;

    #[cfg(feature = "waker-profiling")]
    use crate::runtime::waker_profiling::{get_waker_metrics, reset_waker_metrics};

    fn task_id(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    /// Baseline test for waker creation patterns.
    /// This measures allocation behavior under different creation scenarios.
    #[test]
    fn hotpath_waker_creation() {
        #[cfg(feature = "waker-profiling")]
        reset_waker_metrics();

        let start = Instant::now();

        // Test Case 1: Burst waker creation
        let state = Arc::new(WakerState::new());
        let mut wakers = Vec::with_capacity(1000);

        for i in 0..1000 {
            let waker = state.waker_for(task_id(i));
            wakers.push(waker);
        }

        let creation_duration = start.elapsed();
        println!("Waker creation (1000 wakers): {:?}", creation_duration);

        // Test Case 2: Use all wakers
        let start = Instant::now();
        for waker in &wakers {
            waker.wake_by_ref();
        }
        let wake_duration = start.elapsed();
        println!("Waker wake operations (1000): {:?}", wake_duration);

        // Test Case 3: Drain results
        let start = Instant::now();
        let woken = state.drain_woken();
        let drain_duration = start.elapsed();
        println!("Drain woken ({}): {:?}", woken.len(), drain_duration);

        #[cfg(feature = "waker-profiling")]
        {
            let metrics = get_waker_metrics();
            println!("Waker allocation metrics: {:?}", metrics);
        }
    }

    /// Baseline test for waker reuse patterns.
    #[test]
    fn hotpath_waker_reuse() {
        #[cfg(feature = "waker-profiling")]
        reset_waker_metrics();

        let state = Arc::new(WakerState::new());

        // Test Case 1: Create once, use many times
        let start = Instant::now();
        let waker = state.waker_for(task_id(1));

        for _ in 0..1000 {
            waker.wake_by_ref();
            let _woken = state.drain_woken();
        }

        let reuse_duration = start.elapsed();
        println!("Waker reuse (1000 ops): {:?}", reuse_duration);

        // Test Case 2: Clone waker and use clones
        let start = Instant::now();
        let mut cloned_wakers = Vec::with_capacity(100);

        for _ in 0..100 {
            cloned_wakers.push(waker.clone());
        }

        for cloned_waker in &cloned_wakers {
            cloned_waker.wake_by_ref();
        }
        let _final_woken = state.drain_woken();

        let clone_duration = start.elapsed();
        println!("Waker cloning and use (100 clones): {:?}", clone_duration);

        #[cfg(feature = "waker-profiling")]
        {
            let metrics = get_waker_metrics();
            println!("Reuse allocation metrics: {:?}", metrics);
        }
    }

    /// Baseline test for wake storm scenarios.
    #[test]
    fn hotpath_wake_storms() {
        #[cfg(feature = "waker-profiling")]
        reset_waker_metrics();

        let start = Instant::now();

        // Create many wakers for different tasks
        let state = Arc::new(WakerState::new());
        let wakers: Vec<_> = (0..100)
            .map(|i| state.waker_for(task_id(i)))
            .collect();

        // Wake storm: all wakers fire multiple times
        for _ in 0..10 {
            for waker in &wakers {
                waker.wake_by_ref();
            }
        }

        let storm_duration = start.elapsed();
        println!("Wake storm (100 wakers × 10 rounds): {:?}", storm_duration);

        let woken = state.drain_woken();
        println!("Final woken count: {}", woken.len());

        #[cfg(feature = "waker-profiling")]
        {
            let metrics = get_waker_metrics();
            println!("Wake storm metrics: {:?}", metrics);
        }
    }

    /// Test for different wake source types allocation patterns.
    #[test]
    fn hotpath_wake_source_types() {
        #[cfg(feature = "waker-profiling")]
        reset_waker_metrics();

        let state = Arc::new(WakerState::new());

        let start = Instant::now();

        // Create wakers with different source types
        let timer_wakers: Vec<_> = (0..250)
            .map(|i| state.waker_for_source(task_id(i), WakeSource::Timer))
            .collect();

        let io_wakers: Vec<_> = (250..500)
            .map(|i| state.waker_for_source(
                task_id(i),
                WakeSource::Io { fd: (i % 100) as i32 }
            ))
            .collect();

        let explicit_wakers: Vec<_> = (500..750)
            .map(|i| state.waker_for_source(task_id(i), WakeSource::Explicit))
            .collect();

        let unknown_wakers: Vec<_> = (750..1000)
            .map(|i| state.waker_for(task_id(i)))
            .collect();

        let creation_duration = start.elapsed();
        println!("Mixed source type creation (1000 wakers): {:?}", creation_duration);

        // Use all wakers
        let start = Instant::now();
        for waker in timer_wakers.iter()
            .chain(io_wakers.iter())
            .chain(explicit_wakers.iter())
            .chain(unknown_wakers.iter())
        {
            waker.wake_by_ref();
        }
        let wake_duration = start.elapsed();
        println!("Mixed source wake operations: {:?}", wake_duration);

        let woken = state.drain_woken();
        println!("Mixed source woken count: {}", woken.len());

        #[cfg(feature = "waker-profiling")]
        {
            let final_metrics = get_waker_metrics();
            println!("Mixed source metrics: {:?}", final_metrics);
        }
    }
}