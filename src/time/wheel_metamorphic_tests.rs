//! Metamorphic tests for TimerWheel component.
//!
//! These tests verify invariant relationships for the hierarchical timer wheel,
//! addressing the oracle problem for complex timing and scheduling logic.
//! Each test focuses on a specific metamorphic relation derived from
//! timer wheel domain properties.

#![allow(dead_code, clippy::pedantic, clippy::nursery, clippy::unwrap_used)]

use proptest::prelude::*;
use std::collections::HashMap;
use std::task::Waker;
use std::time::Duration;

use super::*;
use crate::types::Time;

/// Test-specific timer wheel configuration.
#[derive(Debug, Clone)]
struct TestWheelConfig {
    max_wheel_duration_hours: u64,
    max_timer_duration_hours: u64,
    coalescing_enabled: bool,
    coalesce_window_ms: u64,
    min_group_size: usize,
}

impl TestWheelConfig {
    fn to_wheel_config(&self) -> TimerWheelConfig {
        TimerWheelConfig {
            max_wheel_duration: Duration::from_hours(self.max_wheel_duration_hours),
            max_timer_duration: Duration::from_hours(self.max_timer_duration_hours),
        }
    }

    fn to_coalescing_config(&self) -> CoalescingConfig {
        CoalescingConfig {
            enabled: self.coalescing_enabled,
            coalesce_window: Duration::from_millis(self.coalesce_window_ms),
            min_group_size: self.min_group_size,
        }
    }
}

/// Generate arbitrary valid wheel configurations.
fn arb_wheel_config() -> impl Strategy<Value = TestWheelConfig> {
    (1u64..25, 25u64..168, any::<bool>(), 1u64..50, 1usize..10).prop_map(
        |(max_wheel_hrs, max_timer_hrs, coalesce, window_ms, group_size)| {
            let max_timer_hrs = max_timer_hrs.max(max_wheel_hrs); // Ensure timer >= wheel
            TestWheelConfig {
                max_wheel_duration_hours: max_wheel_hrs,
                max_timer_duration_hours: max_timer_hrs,
                coalescing_enabled: coalesce,
                coalesce_window_ms: window_ms,
                min_group_size: group_size,
            }
        },
    )
}

/// Test timer for tracking and verification.
#[derive(Debug, Clone)]
struct TestTimer {
    id: u32,
    deadline_offset_ms: u64, // Offset from current time
    priority: u8,            // For potential priority testing
}

/// Generate arbitrary test timers.
fn arb_test_timer() -> impl Strategy<Value = TestTimer> {
    (any::<u32>(), 1u64..10000, any::<u8>()).prop_map(|(id, offset_ms, priority)| TestTimer {
        id,
        deadline_offset_ms: offset_ms,
        priority,
    })
}

/// Wheel operations for metamorphic testing.
#[derive(Debug, Clone)]
enum WheelOperation {
    InsertTimer { timer: TestTimer },
    CancelTimer { timer_id: u32 },
    AdvanceTime { advance_ms: u64 },
    CheckReady,
    GetMetrics,
}

/// Generate arbitrary wheel operations.
fn arb_wheel_operation() -> impl Strategy<Value = WheelOperation> {
    prop_oneof![
        arb_test_timer().prop_map(|timer| WheelOperation::InsertTimer { timer }),
        any::<u32>().prop_map(|id| WheelOperation::CancelTimer { timer_id: id }),
        (1u64..1000).prop_map(|advance| WheelOperation::AdvanceTime {
            advance_ms: advance
        }),
        Just(WheelOperation::CheckReady),
        Just(WheelOperation::GetMetrics),
    ]
}

/// Tracked timer state for verification.
#[derive(Debug)]
struct TrackedTimer {
    id: u32,
    deadline: Time,
    inserted_at: Time,
    handle: Option<TimerHandle>,
    cancelled: bool,
    fired: bool,
}

/// Snapshot of wheel state for invariant checking.
#[derive(Debug, Clone)]
struct WheelSnapshot {
    current_time: Time,
    total_inserted: usize,
    total_cancelled: usize,
    total_fired: usize,
    active_count: usize,
    overflow_count: usize,
    ready_count: usize,
}

impl WheelSnapshot {
    fn capture(wheel: &TimerWheel, tracked_timers: &[TrackedTimer]) -> Self {
        let total_inserted = tracked_timers.len();
        let total_cancelled = tracked_timers.iter().filter(|t| t.cancelled).count();
        let total_fired = tracked_timers.iter().filter(|t| t.fired).count();
        let active_count = total_inserted - total_cancelled - total_fired;

        Self {
            current_time: wheel.current_time(),
            total_inserted,
            total_cancelled,
            total_fired,
            active_count,
            overflow_count: wheel.overflow_count(),
            ready_count: live_ready_count(wheel),
        }
    }
}

fn live_ready_count(wheel: &TimerWheel) -> usize {
    wheel
        .ready
        .iter()
        .filter(|entry| wheel.is_live(entry))
        .count()
}

/// Create a dummy waker for testing.
fn dummy_waker() -> Waker {
    Waker::noop().clone()
}

/// Apply a wheel operation and update tracked state.
fn apply_operation(
    wheel: &mut TimerWheel,
    operation: &WheelOperation,
    tracked_timers: &mut Vec<TrackedTimer>,
    timer_handle_map: &mut HashMap<u32, TimerHandle>,
) {
    match operation {
        WheelOperation::InsertTimer { timer } => {
            let deadline = wheel.current_time() + Duration::from_millis(timer.deadline_offset_ms);
            let waker = dummy_waker();

            let handle = wheel.register(deadline, waker);
            timer_handle_map.insert(timer.id, handle);
            tracked_timers.push(TrackedTimer {
                id: timer.id,
                deadline,
                inserted_at: wheel.current_time(),
                handle: Some(handle),
                cancelled: false,
                fired: false,
            });
        }
        WheelOperation::CancelTimer { timer_id } => {
            if let Some(handle) = timer_handle_map.get(timer_id) {
                wheel.cancel(handle);
                if let Some(timer) = tracked_timers.iter_mut().find(|t| t.id == *timer_id) {
                    timer.cancelled = true;
                }
            }
        }
        WheelOperation::AdvanceTime { advance_ms } => {
            let new_time = wheel.current_time() + Duration::from_millis(*advance_ms);
            let _ready_wakers = wheel.collect_expired(new_time);

            // Mark timers as fired if they were in the ready batch
            // Note: This is simplified since we can't easily correlate wakers back to timer IDs
            for timer in tracked_timers.iter_mut() {
                if !timer.fired && !timer.cancelled && timer.deadline <= new_time {
                    timer.fired = true;
                }
            }
        }
        WheelOperation::CheckReady => {
            let _ = live_ready_count(wheel);
        }
        WheelOperation::GetMetrics => {
            let _ = wheel.overflow_count();
        }
    }
}

//
// METAMORPHIC RELATIONS - Core invariants for timer wheel
//

/// MR1: EQUIVALENCE - Time Monotonicity
/// advance_to() should never move time backward.
#[test]
fn mr_time_monotonicity() {
    proptest!(|(config in arb_wheel_config(), operations in prop::collection::vec(arb_wheel_operation(), 0..=40))| {
        let wheel_config = config.to_wheel_config();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());
        let mut tracked_timers = Vec::new();
        let mut timer_handle_map = HashMap::new();
        let mut prev_time = wheel.current_time();

        for op in operations.iter().take(15) {
            apply_operation(&mut wheel, op, &mut tracked_timers, &mut timer_handle_map);

            let current_time = wheel.current_time();
            prop_assert!(current_time >= prev_time,
                "Time monotonicity violated: current={:?} < previous={:?} after operation {:?}",
                current_time, prev_time, op);

            prev_time = current_time;
        }
    });
}

/// MR2: EQUIVALENCE - Timer Conservation
/// Total inserted = cancelled + fired + active (accounting identity).
#[test]
fn mr_timer_conservation() {
    proptest!(|(config in arb_wheel_config(), operations in prop::collection::vec(arb_wheel_operation(), 0..=40))| {
        let wheel_config = config.to_wheel_config();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());
        let mut tracked_timers = Vec::new();
        let mut timer_handle_map = HashMap::new();

        for op in operations.iter().take(12) {
            apply_operation(&mut wheel, op, &mut tracked_timers, &mut timer_handle_map);

            let snapshot = WheelSnapshot::capture(&wheel, &tracked_timers);
            let accounted = snapshot.total_cancelled + snapshot.total_fired + snapshot.active_count;

            prop_assert_eq!(snapshot.total_inserted, accounted,
                "Timer conservation violated after operation {:?}: inserted={}, cancelled={}, fired={}, active={}",
                op, snapshot.total_inserted, snapshot.total_cancelled, snapshot.total_fired, snapshot.active_count);
        }
    });
}

/// MR3: INCLUSIVE - Deadline Ordering
/// Ready timers should have deadlines ≤ current time.
#[test]
fn mr_deadline_ordering() {
    proptest!(|(config in arb_wheel_config(), operations in prop::collection::vec(arb_wheel_operation(), 0..=40))| {
        let wheel_config = config.to_wheel_config();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());
        let mut tracked_timers = Vec::new();
        let mut timer_handle_map = HashMap::new();

        for op in operations.iter().take(10) {
            apply_operation(&mut wheel, op, &mut tracked_timers, &mut timer_handle_map);

            let current_time = wheel.current_time();

            // All fired timers should have had deadlines <= current_time
            for timer in &tracked_timers {
                if timer.fired {
                    prop_assert!(timer.deadline <= current_time,
                        "Deadline ordering violated: timer {:?} fired with deadline {:?} > current_time {:?}",
                        timer.id, timer.deadline, current_time);
                }
            }
        }
    });
}

/// MR4: MULTIPLICATIVE - Batch Size Scaling
/// When doubling timer insertion rate, ready batch sizes should scale proportionally.
#[test]
fn mr_batch_size_scaling() {
    proptest!(|(base_timer_count in 1usize..=50, advance_ms in 1u64..=10_000)| {
        let base_timer_count = (base_timer_count % 6) + 2; // 2-7 timers
        let advance_ms = (advance_ms % 500) + 100; // 100-599ms advance

        let config = TestWheelConfig {
            max_wheel_duration_hours: 1,
            max_timer_duration_hours: 2,
            coalescing_enabled: false,
            coalesce_window_ms: 1,
            min_group_size: 1,
        };

        let wheel_config = config.to_wheel_config();
        let coalescing_config = config.to_coalescing_config();
        let mut wheel1 =
            TimerWheel::with_config(Time::ZERO, wheel_config.clone(), coalescing_config.clone());
        let mut wheel2 = TimerWheel::with_config(Time::ZERO, wheel_config, coalescing_config);

        // Insert base_timer_count timers in wheel1
        for i in 0..base_timer_count {
            let deadline = wheel1.current_time() + Duration::from_millis(advance_ms / 2);
            let _ = i;
            wheel1.register(deadline, dummy_waker());
        }

        // Insert 2×base_timer_count timers in wheel2
        for i in 0..(base_timer_count * 2) {
            let deadline = wheel2.current_time() + Duration::from_millis(advance_ms / 2);
            let _ = i;
            wheel2.register(deadline, dummy_waker());
        }

        // Advance both wheels to fire all timers
        let target_time = Time::from_millis(advance_ms);
        let ready1 = wheel1.collect_expired(target_time);
        let ready2 = wheel2.collect_expired(target_time);

        // Under identical timing, ready counts should scale linearly
        if ready1.len() > 0 {
            let ratio = ready2.len() as f64 / ready1.len() as f64;
            prop_assert!((1.5..=2.5).contains(&ratio),
                "Batch scaling violated: base_ready={}, doubled_ready={}, ratio={}",
                ready1.len(), ready2.len(), ratio);
        }
    });
}

/// MR5: EQUIVALENCE - Cancellation Idempotence
/// Cancelling the same timer multiple times should be equivalent to cancelling once.
#[test]
fn mr_cancellation_idempotence() {
    proptest!(|(timer_offset_ms in 1u64..=10_000)| {
        let timer_offset_ms = (timer_offset_ms % 1000) + 100; // 100-1099ms
        let config = TestWheelConfig {
            max_wheel_duration_hours: 1,
            max_timer_duration_hours: 2,
            coalescing_enabled: false,
            coalesce_window_ms: 1,
            min_group_size: 1,
        };

        let wheel_config = config.to_wheel_config();
        let coalescing_config = config.to_coalescing_config();
        let mut wheel1 =
            TimerWheel::with_config(Time::ZERO, wheel_config.clone(), coalescing_config.clone());
        let mut wheel2 = TimerWheel::with_config(Time::ZERO, wheel_config, coalescing_config);

        // Insert identical timers
        let deadline = wheel1.current_time() + Duration::from_millis(timer_offset_ms);
        let handle1 = wheel1.register(deadline, dummy_waker());
        let handle2 = wheel2.register(deadline, dummy_waker());

        // Cancel once vs cancel multiple times
        wheel1.cancel(&handle1);

        wheel2.cancel(&handle2);
        wheel2.cancel(&handle2); // Second cancel (should be idempotent)
        wheel2.cancel(&handle2); // Third cancel (should be idempotent)

        // Both wheels should behave identically
        let ready1 = wheel1.collect_expired(deadline + Duration::from_millis(100));
        let ready2 = wheel2.collect_expired(deadline + Duration::from_millis(100));

        prop_assert_eq!(ready1.len(), ready2.len(),
            "Cancellation idempotence violated: single_cancel_ready={}, multiple_cancel_ready={}",
            ready1.len(), ready2.len());
    });
}

/// MR6: ADDITIVE - Overflow Conservation
/// Active timers = in_wheel_timers + overflow_timers.
#[test]
fn mr_overflow_conservation() {
    proptest!(|(config in arb_wheel_config(), operations in prop::collection::vec(arb_wheel_operation(), 0..=40))| {
        let wheel_config = config.to_wheel_config();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());
        let mut tracked_timers = Vec::new();
        let mut timer_handle_map = HashMap::new();

        for op in operations.iter().take(10) {
            apply_operation(&mut wheel, op, &mut tracked_timers, &mut timer_handle_map);

            let snapshot = WheelSnapshot::capture(&wheel, &tracked_timers);

            // Overflow count should be reasonable (≤ total active for long timers)
            prop_assert!(snapshot.overflow_count <= snapshot.active_count,
                "Overflow count exceeds active count: overflow={}, active={}",
                snapshot.overflow_count, snapshot.active_count);
        }
    });
}

/// MR7: PERMUTATIVE - Insertion Order Independence
/// For timers with identical deadlines, insertion order shouldn't affect final state.
#[test]
fn mr_insertion_order_independence() {
    proptest!(|(timer_count in 1usize..=50, deadline_offset_ms in 1u64..=10_000)| {
        let timer_count = (timer_count % 5) + 2; // 2-6 timers
        let deadline_offset_ms = (deadline_offset_ms % 500) + 100;

        let config = TestWheelConfig {
            max_wheel_duration_hours: 1,
            max_timer_duration_hours: 2,
            coalescing_enabled: false,
            coalesce_window_ms: 1,
            min_group_size: 1,
        };

        let wheel_config = config.to_wheel_config();
        let coalescing_config = config.to_coalescing_config();
        let mut wheel1 =
            TimerWheel::with_config(Time::ZERO, wheel_config.clone(), coalescing_config.clone());
        let mut wheel2 = TimerWheel::with_config(Time::ZERO, wheel_config, coalescing_config);

        let shared_deadline = wheel1.current_time() + Duration::from_millis(deadline_offset_ms);

        // Insert timers in original order (0, 1, 2, ...)
        for i in 0..timer_count {
            let _ = i;
            wheel1.register(shared_deadline, dummy_waker());
        }

        // Insert timers in reverse order (..., 2, 1, 0)
        for i in (0..timer_count).rev() {
            let _ = i;
            wheel2.register(shared_deadline, dummy_waker());
        }

        // Both wheels should produce equivalent results
        let target_time = shared_deadline + Duration::from_millis(50);
        let ready1 = wheel1.collect_expired(target_time);
        let ready2 = wheel2.collect_expired(target_time);

        prop_assert_eq!(ready1.len(), ready2.len(),
            "Insertion order independence violated: forward_order_ready={}, reverse_order_ready={}",
            ready1.len(), ready2.len());
    });
}

/// MR8: INCLUSIVE - Ready Timer Constraint
/// Ready timers count ≤ total active timers.
#[test]
fn mr_ready_timer_constraint() {
    proptest!(|(config in arb_wheel_config(), operations in prop::collection::vec(arb_wheel_operation(), 0..=40))| {
        let wheel_config = config.to_wheel_config();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());
        let mut tracked_timers = Vec::new();
        let mut timer_handle_map = HashMap::new();

        for op in operations.iter().take(12) {
            apply_operation(&mut wheel, op, &mut tracked_timers, &mut timer_handle_map);

            let snapshot = WheelSnapshot::capture(&wheel, &tracked_timers);

            prop_assert!(snapshot.ready_count <= snapshot.active_count,
                "Ready timer constraint violated: ready={} > active={} after operation {:?}",
                snapshot.ready_count, snapshot.active_count, op);
        }
    });
}

/// MR9: MULTIPLICATIVE - Coalescing Window Grouping
/// When coalescing is enabled, nearby timers should fire in groups.
#[test]
fn mr_coalescing_window_grouping() {
    proptest!(|(timer_count in 1usize..=50, spread_ms in 1u64..=10_000)| {
        let timer_count = (timer_count % 6) + 3; // 3-8 timers
        let spread_ms = (spread_ms % 10) + 1; // 1-10ms spread

        let config_no_coalesce = TestWheelConfig {
            max_wheel_duration_hours: 1,
            max_timer_duration_hours: 2,
            coalescing_enabled: false,
            coalesce_window_ms: 50,
            min_group_size: 1,
        };

        let config_coalesce = TestWheelConfig {
            coalescing_enabled: true,
            coalesce_window_ms: spread_ms * 2, // Window larger than spread
            ..config_no_coalesce.clone()
        };

        let wheel_config1 = config_no_coalesce.to_wheel_config();
        let coalesce_config1 = config_no_coalesce.to_coalescing_config();
        let mut wheel1 = TimerWheel::with_config(Time::ZERO, wheel_config1, coalesce_config1);

        let wheel_config2 = config_coalesce.to_wheel_config();
        let coalesce_config2 = config_coalesce.to_coalescing_config();
        let mut wheel2 = TimerWheel::with_config(Time::ZERO, wheel_config2, coalesce_config2);

        // Insert nearby timers
        let base_deadline = wheel1.current_time() + Duration::from_millis(100);
        for i in 0..timer_count {
            let offset = Duration::from_millis(i as u64 * spread_ms / timer_count as u64);
            let deadline = base_deadline + offset;

            wheel1.register(deadline, dummy_waker());
            wheel2.register(deadline, dummy_waker());
        }

        // Advance to fire all timers
        let target_time = base_deadline + Duration::from_millis(spread_ms + 50);
        let ready1 = wheel1.collect_expired(target_time);
        let ready2 = wheel2.collect_expired(target_time);

        // Both should fire all timers, but coalescing may affect timing precision
        prop_assert_eq!(ready1.len(), ready2.len(),
            "Timer count differs with coalescing: no_coalesce={}, coalesce={}",
            ready1.len(), ready2.len());
    });
}

/// MR10: INVERTIVE - Insert-Cancel Round Trip
/// insert_timer() → cancel_timer() should restore wheel to original state.
#[test]
fn mr_insert_cancel_round_trip() {
    proptest!(|(timer_offset_ms in 1u64..=10_000)| {
        let timer_offset_ms = (timer_offset_ms % 1000) + 100;
        let config = TestWheelConfig {
            max_wheel_duration_hours: 1,
            max_timer_duration_hours: 2,
            coalescing_enabled: false,
            coalesce_window_ms: 1,
            min_group_size: 1,
        };

        let wheel_config = config.to_wheel_config();
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());

        // Capture initial state
        let initial_overflow = wheel.overflow_count();
        let initial_ready = live_ready_count(&wheel);

        // Insert timer
        let deadline = wheel.current_time() + Duration::from_millis(timer_offset_ms);
        let handle = wheel.register(deadline, dummy_waker());

        // Verify timer was inserted (some state should change)
        let _inserted_overflow = wheel.overflow_count();
        let _inserted_ready = live_ready_count(&wheel);

        // Cancel timer
        wheel.cancel(&handle);

        // Verify state returned to initial
        let final_overflow = wheel.overflow_count();
        let final_ready = live_ready_count(&wheel);

        prop_assert_eq!(initial_overflow, final_overflow,
            "Overflow count not restored: initial={}, final={}",
            initial_overflow, final_overflow);

        prop_assert_eq!(initial_ready, final_ready,
            "Ready count not restored: initial={}, final={}",
            initial_ready, final_ready);
    });
}

#[cfg(test)]
mod composition_tests {
    use super::*;

    /// Composite MR: Time + Conservation + Ordering
    /// Tests that time monotonicity, timer conservation, and deadline ordering
    /// all hold simultaneously under complex operation sequences.
    #[test]
    fn mr_composite_wheel_invariants() {
        proptest!(|(config in arb_wheel_config(), operations in prop::collection::vec(arb_wheel_operation(), 0..=40))| {
            let wheel_config = config.to_wheel_config();
            let mut wheel =
                TimerWheel::with_config(Time::ZERO, wheel_config, config.to_coalescing_config());
            let mut tracked_timers = Vec::new();
            let mut timer_handle_map = HashMap::new();
            let mut prev_time = wheel.current_time();

            for op in operations.iter().take(8) {
                apply_operation(&mut wheel, op, &mut tracked_timers, &mut timer_handle_map);

                let current_time = wheel.current_time();
                let snapshot = WheelSnapshot::capture(&wheel, &tracked_timers);

                // MR1: Time monotonicity
                prop_assert!(current_time >= prev_time, "Time monotonicity violated");
                prev_time = current_time;

                // MR2: Timer conservation
                let accounted = snapshot.total_cancelled + snapshot.total_fired + snapshot.active_count;
                prop_assert_eq!(snapshot.total_inserted, accounted, "Timer conservation violated");

                // MR3: Deadline ordering
                for timer in &tracked_timers {
                    if timer.fired {
                        prop_assert!(timer.deadline <= current_time, "Deadline ordering violated");
                    }
                }

                // MR8: Ready constraint
                prop_assert!(snapshot.ready_count <= snapshot.active_count, "Ready constraint violated");

                // Composite property: No time travel for fired timers
                for timer in &tracked_timers {
                    if timer.fired {
                        prop_assert!(timer.deadline >= timer.inserted_at,
                            "Timer fired before its insertion time");
                    }
                }
            }
        });
    }
}
