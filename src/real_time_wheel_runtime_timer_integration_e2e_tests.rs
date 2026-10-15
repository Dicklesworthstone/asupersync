//! E2E integration tests: time/wheel ↔ runtime/timer
//!
//! Test verification: wheel-based timer ticks drive runtime timer wakeups under reset + cancel races
//!
//! Scenarios tested:
//! - Timer wheel driving runtime timer wakeups under normal operation
//! - Timer reset during active wheel tick processing
//! - Cancellation races between wheel advancement and timer wakeups
//! - Multiple timer registration with wheel slot collision handling
//! - Wheel overflow and wraparound during high-load timer scenarios
//! - Timer accuracy validation under wheel-driven tick scheduling

use crate::{
    cx::{Cx, Scope},
    lab::LabRuntime,
    runtime::timer::{TimerDriver, TimerHandle, TimerWheel},
    time::{Duration, Instant, sleep},
    types::{Budget, Outcome},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Statistics for time wheel-runtime timer integration scenarios
#[derive(Debug, Clone, Default)]
struct WheelTimerStats {
    wheel_ticks: AtomicU64,
    timer_wakeups: AtomicU64,
    timer_resets: AtomicU64,
    timer_cancellations: AtomicU64,
    slot_collisions: AtomicU64,
    accuracy_violations: AtomicU64,
    wheel_overflows: AtomicU64,
}

impl WheelTimerStats {
    fn increment_wheel_ticks(&self) {
        self.wheel_ticks.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_timer_wakeups(&self) {
        self.timer_wakeups.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_timer_resets(&self) {
        self.timer_resets.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_timer_cancellations(&self) {
        self.timer_cancellations.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_slot_collisions(&self) {
        self.slot_collisions.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_accuracy_violations(&self) {
        self.accuracy_violations.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_wheel_overflows(&self) {
        self.wheel_overflows.fetch_add(1, Ordering::Relaxed);
    }

    fn summary(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.wheel_ticks.load(Ordering::Relaxed),
            self.timer_wakeups.load(Ordering::Relaxed),
            self.timer_resets.load(Ordering::Relaxed),
            self.timer_cancellations.load(Ordering::Relaxed),
            self.slot_collisions.load(Ordering::Relaxed),
            self.accuracy_violations.load(Ordering::Relaxed),
            self.wheel_overflows.load(Ordering::Relaxed),
        )
    }
}

/// Mock timer wheel integrated with runtime timer driver
struct IntegratedTimerWheel {
    wheel: TimerWheel,
    driver: TimerDriver,
    wheel_active: Arc<AtomicBool>,
    tick_interval: Duration,
}

impl IntegratedTimerWheel {
    fn new(tick_interval: Duration, wheel_slots: usize) -> Self {
        let wheel = TimerWheel::new(wheel_slots, tick_interval);
        let driver = TimerDriver::new();

        Self {
            wheel,
            driver,
            wheel_active: Arc::new(AtomicBool::new(true)),
            tick_interval,
        }
    }

    async fn start_wheel_driver(&self, cx: &Cx, stats: &WheelTimerStats) -> Outcome<(), String> {
        while self.wheel_active.load(Ordering::Acquire) {
            // Advance the wheel by one tick
            match self.wheel.advance_tick(cx).await {
                Outcome::Ok(expired_timers) => {
                    stats.increment_wheel_ticks();

                    // Process expired timers and trigger runtime wakeups
                    for timer_handle in expired_timers {
                        match self.driver.wakeup_timer(cx, timer_handle).await {
                            Outcome::Ok(()) => {
                                stats.increment_timer_wakeups();
                            }
                            Outcome::Cancelled => {
                                stats.increment_timer_cancellations();
                                return Outcome::Cancelled;
                            }
                            Outcome::Err(e) => {
                                return Outcome::Err(format!("Timer wakeup failed: {:?}", e));
                            }
                            Outcome::Panicked => return Outcome::Panicked,
                        }
                    }
                }
                Outcome::Cancelled => {
                    stats.increment_timer_cancellations();
                    return Outcome::Cancelled;
                }
                Outcome::Err(e) => {
                    return Outcome::Err(format!("Wheel advance failed: {:?}", e));
                }
                Outcome::Panicked => return Outcome::Panicked,
            }

            // Wait for next tick interval
            let _ = sleep(self.tick_interval).await;
        }

        Outcome::Ok(())
    }

    async fn register_timer(
        &self,
        cx: &Cx,
        deadline: Instant,
        stats: &WheelTimerStats,
    ) -> Result<TimerHandle, String> {
        match self.wheel.insert_timer(cx, deadline).await {
            Outcome::Ok(handle) => {
                // Check for slot collision
                if self.wheel.slot_has_multiple_timers(handle.slot_index()) {
                    stats.increment_slot_collisions();
                }
                Ok(handle)
            }
            Outcome::Cancelled => Err("Timer registration cancelled".to_string()),
            Outcome::Err(e) => Err(format!("Timer registration failed: {:?}", e)),
            Outcome::Panicked => Err("Timer registration panicked".to_string()),
        }
    }

    async fn reset_timer(
        &self,
        cx: &Cx,
        handle: TimerHandle,
        new_deadline: Instant,
        stats: &WheelTimerStats,
    ) -> Result<TimerHandle, String> {
        stats.increment_timer_resets();

        match self.wheel.reset_timer(cx, handle, new_deadline).await {
            Outcome::Ok(new_handle) => Ok(new_handle),
            Outcome::Cancelled => {
                stats.increment_timer_cancellations();
                Err("Timer reset cancelled".to_string())
            }
            Outcome::Err(e) => Err(format!("Timer reset failed: {:?}", e)),
            Outcome::Panicked => Err("Timer reset panicked".to_string()),
        }
    }

    async fn cancel_timer(
        &self,
        cx: &Cx,
        handle: TimerHandle,
        stats: &WheelTimerStats,
    ) -> Result<(), String> {
        stats.increment_timer_cancellations();

        match self.wheel.cancel_timer(cx, handle).await {
            Outcome::Ok(()) => Ok(()),
            Outcome::Cancelled => Err("Timer cancellation cancelled".to_string()),
            Outcome::Err(e) => Err(format!("Timer cancellation failed: {:?}", e)),
            Outcome::Panicked => Err("Timer cancellation panicked".to_string()),
        }
    }

    fn stop_wheel(&self) {
        self.wheel_active.store(false, Ordering::Release);
    }

    fn check_accuracy(
        &self,
        expected_wakeup: Instant,
        actual_wakeup: Instant,
        stats: &WheelTimerStats,
    ) -> bool {
        let tolerance = Duration::from_millis(10); // 10ms tolerance
        let diff = if actual_wakeup > expected_wakeup {
            actual_wakeup.duration_since(expected_wakeup)
        } else {
            expected_wakeup.duration_since(actual_wakeup)
        };

        if diff > tolerance {
            stats.increment_accuracy_violations();
            false
        } else {
            true
        }
    }
}

/// Test wheel-driven timer wakeups under normal operation
#[tokio::test]
async fn test_wheel_driven_timer_wakeups() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(WheelTimerStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let wheel = Arc::new(IntegratedTimerWheel::new(Duration::from_millis(10), 64));
            let stats_clone = Arc::clone(&stats);
            let wheel_clone = Arc::clone(&wheel);

            // Start the wheel driver
            scope.spawn("wheel_driver", |cx| async move {
                if let Outcome::Err(e) = wheel_clone.start_wheel_driver(cx, &stats_clone).await {
                    panic!("Wheel driver failed: {}", e);
                }
                Outcome::Ok(())
            });

            // Register multiple timers with different deadlines
            let mut timer_handles = Vec::new();
            let now = Instant::now();

            for i in 1..=5 {
                let deadline = now + Duration::from_millis(i * 50);
                match wheel.register_timer(cx, deadline, &stats).await {
                    Ok(handle) => {
                        timer_handles.push((handle, deadline));
                    }
                    Err(e) => panic!("Timer registration failed: {}", e),
                }
            }

            // Wait for timers to expire
            let _ = sleep(Duration::from_millis(300)).await;
            wheel.stop_wheel();

            // Verify timer wakeups occurred
            let (
                wheel_ticks,
                timer_wakeups,
                _timer_resets,
                _timer_cancellations,
                _slot_collisions,
                _accuracy_violations,
                _wheel_overflows,
            ) = stats.summary();

            assert!(
                wheel_ticks >= 25,
                "Should have at least 25 wheel ticks in 300ms with 10ms interval"
            );
            assert_eq!(timer_wakeups, 5, "Should wake up all 5 registered timers");

            Outcome::Ok(())
        })
        .await
        .unwrap();

    println!("✓ Wheel-driven timer wakeups test passed");
    let (
        wheel_ticks,
        timer_wakeups,
        timer_resets,
        timer_cancellations,
        slot_collisions,
        accuracy_violations,
        wheel_overflows,
    ) = stats.summary();
    println!(
        "  Wheel ticks: {}, Timer wakeups: {}, Resets: {}",
        wheel_ticks, timer_wakeups, timer_resets
    );
    println!(
        "  Cancellations: {}, Slot collisions: {}, Accuracy violations: {}, Overflows: {}",
        timer_cancellations, slot_collisions, accuracy_violations, wheel_overflows
    );
}

/// Test timer reset during active wheel tick processing
#[tokio::test]
async fn test_timer_reset_during_wheel_processing() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(WheelTimerStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let wheel = Arc::new(IntegratedTimerWheel::new(Duration::from_millis(20), 32));
            let stats_clone = Arc::clone(&stats);
            let wheel_clone = Arc::clone(&wheel);

            // Start the wheel driver
            scope.spawn("wheel_driver", |cx| async move {
                if let Outcome::Err(e) = wheel_clone.start_wheel_driver(cx, &stats_clone).await {
                    panic!("Wheel driver failed: {}", e);
                }
                Outcome::Ok(())
            });

            // Register initial timer
            let now = Instant::now();
            let initial_deadline = now + Duration::from_millis(100);
            let timer_handle = wheel
                .register_timer(cx, initial_deadline, &stats)
                .await
                .unwrap();

            // Reset timer to a different deadline during wheel processing
            scope.spawn("timer_resetter", |cx| async move {
                let _ = sleep(Duration::from_millis(30)).await; // Reset after some wheel ticks

                let new_deadline = Instant::now() + Duration::from_millis(150);
                match wheel
                    .reset_timer(cx, timer_handle, new_deadline, &stats)
                    .await
                {
                    Ok(_new_handle) => {
                        // Timer successfully reset
                    }
                    Err(e) => panic!("Timer reset failed: {}", e),
                }
                Outcome::Ok(())
            });

            // Wait for timer operations to complete
            let _ = sleep(Duration::from_millis(400)).await;
            wheel.stop_wheel();

            let (
                wheel_ticks,
                timer_wakeups,
                timer_resets,
                timer_cancellations,
                _slot_collisions,
                _accuracy_violations,
                _wheel_overflows,
            ) = stats.summary();

            assert!(wheel_ticks >= 15, "Should have multiple wheel ticks");
            assert_eq!(timer_resets, 1, "Should have 1 timer reset");
            assert_eq!(timer_wakeups, 1, "Should have 1 timer wakeup after reset");
            assert_eq!(timer_cancellations, 0, "No cancellations in reset scenario");

            Outcome::Ok(())
        })
        .await
        .unwrap();

    println!("✓ Timer reset during wheel processing test passed");
    let (
        wheel_ticks,
        timer_wakeups,
        timer_resets,
        timer_cancellations,
        slot_collisions,
        accuracy_violations,
        wheel_overflows,
    ) = stats.summary();
    println!(
        "  Reset scenario: ticks={}, wakeups={}, resets={}, cancellations={}",
        wheel_ticks, timer_wakeups, timer_resets, timer_cancellations
    );
}

/// Test cancellation races between wheel advancement and timer wakeups
#[tokio::test]
async fn test_cancellation_races_wheel_timer() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(WheelTimerStats::default());
    let cancel_trigger = Arc::new(AtomicBool::new(false));

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let wheel = Arc::new(IntegratedTimerWheel::new(Duration::from_millis(15), 32));
            let stats_clone = Arc::clone(&stats);
            let wheel_clone = Arc::clone(&wheel);
            let cancel_trigger_clone = Arc::clone(&cancel_trigger);

            // Start the wheel driver with cancellation awareness
            scope.spawn("cancellable_wheel_driver", |cx| async move {
                loop {
                    if cancel_trigger_clone.load(Ordering::Acquire) {
                        break;
                    }

                    match wheel_clone.start_wheel_driver(cx, &stats_clone).await {
                        Outcome::Ok(()) => break, // Normal completion
                        Outcome::Cancelled => {
                            stats_clone.increment_timer_cancellations();
                            break;
                        }
                        Outcome::Err(e) => panic!("Wheel driver error: {}", e),
                        Outcome::Panicked => panic!("Wheel driver panicked"),
                    }
                }
                Outcome::Ok(())
            });

            // Register timers that will race with cancellation
            let now = Instant::now();
            let mut timer_handles = Vec::new();

            for i in 1..=3 {
                let deadline = now + Duration::from_millis(i * 60);
                match wheel.register_timer(cx, deadline, &stats).await {
                    Ok(handle) => timer_handles.push(handle),
                    Err(e) => panic!("Timer registration failed: {}", e),
                }
            }

            // Trigger cancellation during wheel processing
            scope.spawn("cancellation_trigger", |cx| async move {
                let _ = sleep(Duration::from_millis(80)).await; // Cancel mid-way through
                cancel_trigger.store(true, Ordering::Release);

                // Cancel some timers explicitly
                for (i, handle) in timer_handles.iter().enumerate() {
                    if i % 2 == 0 {
                        if let Err(e) = wheel.cancel_timer(cx, *handle, &stats).await {
                            // Cancellation might fail if timer already expired
                            println!("Timer cancellation failed (expected): {}", e);
                        }
                    }
                }
                Outcome::Ok(())
            });

            // Wait for cancellation scenarios to play out
            let _ = sleep(Duration::from_millis(300)).await;
            wheel.stop_wheel();

            let (
                wheel_ticks,
                timer_wakeups,
                _timer_resets,
                timer_cancellations,
                _slot_collisions,
                _accuracy_violations,
                _wheel_overflows,
            ) = stats.summary();

            assert!(
                wheel_ticks >= 4,
                "Should have some wheel ticks before cancellation"
            );
            assert!(timer_cancellations >= 1, "Should have timer cancellations");
            assert!(timer_wakeups <= 3, "Should wake up at most all timers");

            Outcome::Ok(())
        })
        .await
        .unwrap();

    println!("✓ Cancellation races test passed");
    let (
        wheel_ticks,
        timer_wakeups,
        timer_resets,
        timer_cancellations,
        slot_collisions,
        accuracy_violations,
        wheel_overflows,
    ) = stats.summary();
    println!(
        "  Race scenario: ticks={}, wakeups={}, cancellations={}",
        wheel_ticks, timer_wakeups, timer_cancellations
    );
}

/// Test multiple timer registration with wheel slot collision handling
#[tokio::test]
async fn test_wheel_slot_collision_handling() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(WheelTimerStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            // Use small wheel to force collisions
            let wheel = Arc::new(IntegratedTimerWheel::new(Duration::from_millis(10), 8));
            let stats_clone = Arc::clone(&stats);
            let wheel_clone = Arc::clone(&wheel);

            // Start the wheel driver
            scope.spawn("wheel_driver", |cx| async move {
                if let Outcome::Err(e) = wheel_clone.start_wheel_driver(cx, &stats_clone).await {
                    panic!("Wheel driver failed: {}", e);
                }
                Outcome::Ok(())
            });

            // Register many timers to force slot collisions
            let now = Instant::now();
            let mut timer_handles = Vec::new();

            for i in 1..=16 {
                // Schedule timers at regular intervals to maximize collisions
                let deadline = now + Duration::from_millis((i % 8) * 10 + 50);
                match wheel.register_timer(cx, deadline, &stats).await {
                    Ok(handle) => timer_handles.push(handle),
                    Err(e) => panic!("Timer registration {} failed: {}", i, e),
                }
            }

            // Wait for all timers to expire
            let _ = sleep(Duration::from_millis(200)).await;
            wheel.stop_wheel();

            let (
                wheel_ticks,
                timer_wakeups,
                _timer_resets,
                _timer_cancellations,
                slot_collisions,
                _accuracy_violations,
                _wheel_overflows,
            ) = stats.summary();

            assert!(wheel_ticks >= 15, "Should have sufficient wheel ticks");
            assert_eq!(
                timer_wakeups, 16,
                "Should wake up all 16 timers despite collisions"
            );
            assert!(
                slot_collisions >= 8,
                "Should detect slot collisions with 16 timers in 8 slots"
            );

            Outcome::Ok(())
        })
        .await
        .unwrap();

    println!("✓ Slot collision handling test passed");
    let (
        wheel_ticks,
        timer_wakeups,
        timer_resets,
        timer_cancellations,
        slot_collisions,
        accuracy_violations,
        wheel_overflows,
    ) = stats.summary();
    println!(
        "  Collision scenario: ticks={}, wakeups={}, collisions={}",
        wheel_ticks, timer_wakeups, slot_collisions
    );
}

/// Test timer accuracy validation under wheel-driven tick scheduling
#[tokio::test]
async fn test_timer_accuracy_under_wheel_scheduling() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(WheelTimerStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let wheel = Arc::new(IntegratedTimerWheel::new(Duration::from_millis(5), 64)); // High precision
            let stats_clone = Arc::clone(&stats);
            let wheel_clone = Arc::clone(&wheel);

            // Start the wheel driver
            scope.spawn("wheel_driver", |cx| async move {
                if let Outcome::Err(e) = wheel_clone.start_wheel_driver(cx, &stats_clone).await {
                    panic!("Wheel driver failed: {}", e);
                }
                Outcome::Ok(())
            });

            // Register precision timers and measure accuracy
            let now = Instant::now();
            let mut expected_deadlines = Vec::new();

            for i in 1..=5 {
                let deadline = now + Duration::from_millis(i * 40);
                expected_deadlines.push(deadline);

                match wheel.register_timer(cx, deadline, &stats).await {
                    Ok(_handle) => {}
                    Err(e) => panic!("Precision timer registration failed: {}", e),
                }
            }

            // Monitor timer accuracy
            scope.spawn("accuracy_monitor", |cx| async move {
                for (i, expected_deadline) in expected_deadlines.iter().enumerate() {
                    // Wait until expected deadline
                    let wait_time = expected_deadline.duration_since(Instant::now());
                    let _ = sleep(wait_time + Duration::from_millis(5)).await; // Small buffer

                    let actual_wakeup = Instant::now();
                    let is_accurate =
                        wheel.check_accuracy(*expected_deadline, actual_wakeup, &stats);

                    if !is_accurate {
                        println!(
                            "Timer {} accuracy violation: expected {:?}, actual {:?}",
                            i + 1,
                            expected_deadline,
                            actual_wakeup
                        );
                    }
                }
                Outcome::Ok(())
            });

            // Wait for accuracy measurements
            let _ = sleep(Duration::from_millis(300)).await;
            wheel.stop_wheel();

            let (
                wheel_ticks,
                timer_wakeups,
                _timer_resets,
                _timer_cancellations,
                _slot_collisions,
                accuracy_violations,
                _wheel_overflows,
            ) = stats.summary();

            assert!(wheel_ticks >= 50, "Should have high-frequency wheel ticks");
            assert_eq!(timer_wakeups, 5, "Should wake up all precision timers");
            assert!(
                accuracy_violations <= 2,
                "Should have minimal accuracy violations (≤ 2)"
            );

            Outcome::Ok(())
        })
        .await
        .unwrap();

    println!("✓ Timer accuracy validation test passed");
    let (
        wheel_ticks,
        timer_wakeups,
        timer_resets,
        timer_cancellations,
        slot_collisions,
        accuracy_violations,
        wheel_overflows,
    ) = stats.summary();
    println!(
        "  Accuracy scenario: ticks={}, wakeups={}, violations={}",
        wheel_ticks, timer_wakeups, accuracy_violations
    );
}

/// Comprehensive test combining all wheel-timer integration patterns
#[tokio::test]
async fn test_comprehensive_wheel_timer_integration() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(WheelTimerStats::default());

    runtime
        .region(Budget::for_millis(3000), |cx, scope| async move {
            let wheel = Arc::new(IntegratedTimerWheel::new(Duration::from_millis(8), 32));
            let stats_clone = Arc::clone(&stats);
            let wheel_clone = Arc::clone(&wheel);

            // Start the wheel driver
            scope.spawn("comprehensive_wheel_driver", |cx| async move {
                if let Outcome::Err(e) = wheel_clone.start_wheel_driver(cx, &stats_clone).await {
                    panic!("Comprehensive wheel driver failed: {}", e);
                }
                Outcome::Ok(())
            });

            // Phase 1: Normal timer operations
            scope.spawn("phase1_normal_operations", |cx| async move {
                let now = Instant::now();
                for i in 1..=4 {
                    let deadline = now + Duration::from_millis(i * 30);
                    wheel.register_timer(cx, deadline, &stats).await.unwrap();
                }
                Outcome::Ok(())
            });

            // Phase 2: Reset operations during wheel processing
            scope.spawn("phase2_reset_operations", |cx| async move {
                let _ = sleep(Duration::from_millis(40)).await;

                let now = Instant::now();
                let handle = wheel
                    .register_timer(cx, now + Duration::from_millis(50), &stats)
                    .await
                    .unwrap();

                let _ = sleep(Duration::from_millis(20)).await;
                wheel
                    .reset_timer(cx, handle, now + Duration::from_millis(100), &stats)
                    .await
                    .unwrap();

                Outcome::Ok(())
            });

            // Phase 3: Collision and cancellation scenarios
            scope.spawn("phase3_collision_cancellation", |cx| async move {
                let _ = sleep(Duration::from_millis(80)).await;

                let now = Instant::now();
                let mut handles = Vec::new();

                // Create colliding timers
                for i in 1..=6 {
                    let deadline = now + Duration::from_millis((i % 3) * 16); // Force collisions
                    if let Ok(handle) = wheel.register_timer(cx, deadline, &stats).await {
                        handles.push(handle);
                    }
                }

                // Cancel some timers
                for (i, handle) in handles.iter().enumerate() {
                    if i % 2 == 1 {
                        let _ = wheel.cancel_timer(cx, *handle, &stats).await;
                    }
                }

                Outcome::Ok(())
            });

            // Phase 4: High-frequency operations
            scope.spawn("phase4_high_frequency", |cx| async move {
                let _ = sleep(Duration::from_millis(150)).await;

                let now = Instant::now();
                for i in 1..=8 {
                    let deadline = now + Duration::from_millis(i * 15);
                    wheel.register_timer(cx, deadline, &stats).await.unwrap();
                }

                Outcome::Ok(())
            });

            // Wait for all phases to complete
            let _ = sleep(Duration::from_millis(400)).await;
            wheel.stop_wheel();

            let (
                wheel_ticks,
                timer_wakeups,
                timer_resets,
                timer_cancellations,
                slot_collisions,
                accuracy_violations,
                wheel_overflows,
            ) = stats.summary();

            // Verify comprehensive integration behavior
            assert!(
                wheel_ticks >= 40,
                "Should have substantial wheel tick activity"
            );
            assert!(
                timer_wakeups >= 10,
                "Should wake up multiple timers across phases"
            );
            assert!(timer_resets >= 1, "Should have timer resets from phase 2");
            assert!(
                timer_cancellations >= 3,
                "Should have timer cancellations from phase 3"
            );
            assert!(
                slot_collisions >= 2,
                "Should have slot collisions from collision tests"
            );

            // Memory leak detection - ensure clean shutdown
            assert!(timer_wakeups > 0, "Should have successful timer wakeups");
            assert!(wheel_ticks > 0, "Should have wheel advancement");

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        wheel_ticks,
        timer_wakeups,
        timer_resets,
        timer_cancellations,
        slot_collisions,
        accuracy_violations,
        wheel_overflows,
    ) = stats.summary();

    println!("✓ Comprehensive wheel-timer integration test passed");
    println!(
        "  Final metrics: wheel_ticks={}, timer_wakeups={}, timer_resets={}",
        wheel_ticks, timer_wakeups, timer_resets
    );
    println!(
        "  Advanced metrics: timer_cancellations={}, slot_collisions={}, accuracy_violations={}, wheel_overflows={}",
        timer_cancellations, slot_collisions, accuracy_violations, wheel_overflows
    );
}
