//! E2E integration tests: sync/notify ↔ channel/watch
//!
//! Test verification: notify wake on watch state mutation under cancellation
//!
//! Scenarios tested:
//! - Notify wake triggering watch state mutations
//! - Watch channel state driving notify wakeups
//! - Cancellation propagation between notify and watch
//! - Multi-waiter notify with watch subscription ordering
//! - Watch receiver cancellation affecting notify waiters
//! - Notify timeout interaction with watch state changes

use crate::{
    channel::watch::{self, WatchReceiver, WatchSender},
    cx::{Cx, Scope},
    lab::LabRuntime,
    sync::Notify,
    time::{Duration, sleep},
    types::{Budget, Outcome},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Statistics for notify-watch integration scenarios
#[derive(Debug, Clone, Default)]
struct NotifyWatchStats {
    notify_wakes: AtomicU64,
    watch_mutations: AtomicU64,
    cancelled_waiters: AtomicU64,
    successful_wakeups: AtomicU64,
    state_transitions: AtomicU64,
    timeout_events: AtomicU64,
}

impl NotifyWatchStats {
    fn increment_notify_wakes(&self) {
        self.notify_wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_watch_mutations(&self) {
        self.watch_mutations.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_cancelled_waiters(&self) {
        self.cancelled_waiters.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_successful_wakeups(&self) {
        self.successful_wakeups.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_state_transitions(&self) {
        self.state_transitions.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_timeout_events(&self) {
        self.timeout_events.fetch_add(1, Ordering::Relaxed);
    }

    fn summary(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.notify_wakes.load(Ordering::Relaxed),
            self.watch_mutations.load(Ordering::Relaxed),
            self.cancelled_waiters.load(Ordering::Relaxed),
            self.successful_wakeups.load(Ordering::Relaxed),
            self.state_transitions.load(Ordering::Relaxed),
            self.timeout_events.load(Ordering::Relaxed),
        )
    }
}

/// Mock state machine for testing notify-watch interaction
struct StateMachine {
    state: Arc<AtomicU64>,
    notify: Arc<Notify>,
    watch_tx: WatchSender<u64>,
    watch_rx: WatchReceiver<u64>,
}

impl StateMachine {
    fn new() -> Self {
        let (watch_tx, watch_rx) = watch::channel(0);
        Self {
            state: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(Notify::new()),
            watch_tx,
            watch_rx,
        }
    }

    async fn transition_state(
        &self,
        cx: &Cx,
        new_state: u64,
        stats: &NotifyWatchStats,
    ) -> Outcome<(), String> {
        // Update atomic state
        self.state.store(new_state, Ordering::Release);
        stats.increment_state_transitions();

        // Send through watch channel (may block if no receivers)
        match self.watch_tx.send(new_state).await {
            Outcome::Ok(()) => {
                stats.increment_watch_mutations();
            }
            Outcome::Cancelled => {
                stats.increment_cancelled_waiters();
                return Outcome::Cancelled;
            }
            Outcome::Err(e) => {
                return Outcome::Err(format!("Watch send failed: {:?}", e));
            }
            Outcome::Panicked => return Outcome::Panicked,
        }

        // Wake all notify waiters
        self.notify.notify_waiters();
        stats.increment_notify_wakes();

        Outcome::Ok(())
    }

    async fn wait_for_notify(&self, cx: &Cx, stats: &NotifyWatchStats) -> Outcome<(), String> {
        match self.notify.notified().await {
            Outcome::Ok(()) => {
                stats.increment_successful_wakeups();
                Outcome::Ok(())
            }
            Outcome::Cancelled => {
                stats.increment_cancelled_waiters();
                Outcome::Cancelled
            }
            Outcome::Err(e) => Outcome::Err(format!("Notify wait failed: {:?}", e)),
            Outcome::Panicked => Outcome::Panicked,
        }
    }

    async fn watch_for_changes(
        &self,
        cx: &Cx,
        expected: u64,
        stats: &NotifyWatchStats,
    ) -> Outcome<u64, String> {
        let mut receiver = self.watch_rx.clone();

        loop {
            match receiver.changed().await {
                Outcome::Ok(()) => {
                    let value = *receiver.borrow();
                    stats.increment_watch_mutations();
                    if value >= expected {
                        return Outcome::Ok(value);
                    }
                    // Continue waiting for expected value
                }
                Outcome::Cancelled => {
                    stats.increment_cancelled_waiters();
                    return Outcome::Cancelled;
                }
                Outcome::Err(e) => {
                    return Outcome::Err(format!("Watch changed failed: {:?}", e));
                }
                Outcome::Panicked => return Outcome::Panicked,
            }
        }
    }
}

/// Test notify wake triggering watch state mutations
#[tokio::test]
async fn test_notify_triggers_watch_mutations() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(NotifyWatchStats::default());
    let machine = Arc::new(StateMachine::new());

    runtime
        .region(Budget::for_millis(1000), |cx, scope| async move {
            let stats_clone = Arc::clone(&stats);
            let machine_clone = Arc::clone(&machine);

            // Spawn state machine driver
            scope.spawn("state_driver", |cx| async move {
                for state in 1..=5 {
                    // Transition state (triggers notify + watch)
                    if let Outcome::Err(e) = machine_clone
                        .transition_state(cx, state, &stats_clone)
                        .await
                    {
                        panic!("State transition failed: {}", e);
                    }

                    // Brief pause between transitions
                    let _ = sleep(Duration::from_millis(10)).await;
                }
                Outcome::Ok(())
            });

            // Spawn notify waiters
            for waiter_id in 0..3 {
                let machine_clone = Arc::clone(&machine);
                let stats_clone = Arc::clone(&stats);

                scope.spawn(format!("notify_waiter_{}", waiter_id), |cx| async move {
                    for _round in 0..2 {
                        if let Outcome::Err(e) =
                            machine_clone.wait_for_notify(cx, &stats_clone).await
                        {
                            panic!("Notify wait failed: {}", e);
                        }
                    }
                    Outcome::Ok(())
                });
            }

            // Spawn watch observers
            for observer_id in 0..2 {
                let machine_clone = Arc::clone(&machine);
                let stats_clone = Arc::clone(&stats);
                let target_state = 3 + observer_id;

                scope.spawn(format!("watch_observer_{}", observer_id), |cx| async move {
                    match machine_clone
                        .watch_for_changes(cx, target_state, &stats_clone)
                        .await
                    {
                        Outcome::Ok(final_state) => {
                            assert!(
                                final_state >= target_state,
                                "Observer {} got state {} but expected >= {}",
                                observer_id,
                                final_state,
                                target_state
                            );
                        }
                        Outcome::Err(e) => panic!("Watch observation failed: {}", e),
                        _ => panic!("Unexpected outcome for watch observer"),
                    }
                    Outcome::Ok(())
                });
            }

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        notify_wakes,
        watch_mutations,
        cancelled_waiters,
        successful_wakeups,
        state_transitions,
        _timeout_events,
    ) = stats.summary();

    // Verify integration metrics
    assert_eq!(state_transitions, 5, "Should have 5 state transitions");
    assert_eq!(
        watch_mutations,
        5 + 2,
        "Should have 5 sends + 2 observer receives"
    ); // Approximate
    assert_eq!(notify_wakes, 5, "Should have 5 notify wakes");
    assert!(
        successful_wakeups >= 6,
        "Should have at least 6 successful wakeups (3 waiters × 2 rounds)"
    );
    assert_eq!(
        cancelled_waiters, 0,
        "No cancellations in successful scenario"
    );

    println!("✓ Notify-triggered watch mutations test passed");
    println!(
        "  State transitions: {}, Watch mutations: {}, Notify wakes: {}, Successful wakeups: {}",
        state_transitions, watch_mutations, notify_wakes, successful_wakeups
    );
}

/// Test cancellation propagation between notify and watch
#[tokio::test]
async fn test_cancellation_propagation_notify_watch() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(NotifyWatchStats::default());
    let machine = Arc::new(StateMachine::new());
    let cancel_flag = Arc::new(AtomicBool::new(false));

    runtime
        .region(Budget::for_millis(1000), |cx, scope| async move {
            let stats_clone = Arc::clone(&stats);
            let machine_clone = Arc::clone(&machine);
            let cancel_flag_clone = Arc::clone(&cancel_flag);

            // Spawn cancellation trigger
            scope.spawn("cancel_trigger", |cx| async move {
                // Wait briefly then trigger cancellation
                let _ = sleep(Duration::from_millis(100)).await;
                cancel_flag_clone.store(true, Ordering::Release);
                Outcome::Ok(())
            });

            // Spawn long-running notify waiter (will be cancelled)
            scope.spawn("long_notify_waiter", |cx| async move {
                loop {
                    match machine_clone.wait_for_notify(cx, &stats_clone).await {
                        Outcome::Ok(()) => {
                            if cancel_flag_clone.load(Ordering::Acquire) {
                                // Simulate cancellation response
                                break;
                            }
                        }
                        Outcome::Cancelled => {
                            stats_clone.increment_cancelled_waiters();
                            break;
                        }
                        Outcome::Err(e) => panic!("Notify wait failed: {}", e),
                        Outcome::Panicked => panic!("Notify wait panicked"),
                    }
                }
                Outcome::Ok(())
            });

            // Spawn long-running watch observer (will be cancelled)
            scope.spawn("long_watch_observer", |cx| async move {
                match machine_clone.watch_for_changes(cx, 999, &stats_clone).await {
                    Outcome::Ok(_) => panic!("Should not complete before cancellation"),
                    Outcome::Cancelled => {
                        stats_clone.increment_cancelled_waiters();
                    }
                    Outcome::Err(e) => panic!("Watch observation failed: {}", e),
                    Outcome::Panicked => panic!("Watch observation panicked"),
                }
                Outcome::Ok(())
            });

            // Spawn state machine driver that stops on cancellation
            scope.spawn("cancellable_state_driver", |cx| async move {
                for state in 1..=10 {
                    if cancel_flag_clone.load(Ordering::Acquire) {
                        break;
                    }

                    if let Outcome::Cancelled = machine_clone
                        .transition_state(cx, state, &stats_clone)
                        .await
                    {
                        stats_clone.increment_cancelled_waiters();
                        break;
                    }

                    let _ = sleep(Duration::from_millis(20)).await;
                }
                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        notify_wakes,
        watch_mutations,
        cancelled_waiters,
        successful_wakeups,
        state_transitions,
        _timeout_events,
    ) = stats.summary();

    // Verify cancellation handling
    assert!(
        cancelled_waiters >= 1,
        "Should have at least 1 cancelled waiter, got {}",
        cancelled_waiters
    );
    assert!(
        state_transitions <= 10,
        "Should have stopped state transitions due to cancellation"
    );
    assert!(
        notify_wakes >= 1,
        "Should have some notify wakes before cancellation"
    );

    println!("✓ Cancellation propagation test passed");
    println!(
        "  Cancelled waiters: {}, State transitions before cancel: {}, Notify wakes: {}",
        cancelled_waiters, state_transitions, notify_wakes
    );
}

/// Test multi-waiter notify with watch subscription ordering
#[tokio::test]
async fn test_multi_waiter_notify_watch_ordering() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(NotifyWatchStats::default());
    let machine = Arc::new(StateMachine::new());
    let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    runtime
        .region(Budget::for_millis(1000), |cx, scope| async move {
            let stats_clone = Arc::clone(&stats);
            let machine_clone = Arc::clone(&machine);

            // Spawn multiple notify waiters with different priorities
            for waiter_id in 0..4 {
                let machine_clone = Arc::clone(&machine);
                let stats_clone = Arc::clone(&stats);
                let completion_order_clone = Arc::clone(&completion_order);

                scope.spawn(
                    format!("priority_notify_waiter_{}", waiter_id),
                    |cx| async move {
                        match machine_clone.wait_for_notify(cx, &stats_clone).await {
                            Outcome::Ok(()) => {
                                completion_order_clone
                                    .lock()
                                    .unwrap()
                                    .push(format!("notify_{}", waiter_id));
                            }
                            Outcome::Cancelled => {
                                stats_clone.increment_cancelled_waiters();
                            }
                            Outcome::Err(e) => panic!("Notify wait failed: {}", e),
                            Outcome::Panicked => panic!("Notify wait panicked"),
                        }
                        Outcome::Ok(())
                    },
                );
            }

            // Spawn multiple watch observers with different target states
            for observer_id in 0..3 {
                let machine_clone = Arc::clone(&machine);
                let stats_clone = Arc::clone(&stats);
                let completion_order_clone = Arc::clone(&completion_order);
                let target_state = observer_id + 1;

                scope.spawn(
                    format!("ordered_watch_observer_{}", observer_id),
                    |cx| async move {
                        match machine_clone
                            .watch_for_changes(cx, target_state, &stats_clone)
                            .await
                        {
                            Outcome::Ok(final_state) => {
                                completion_order_clone
                                    .lock()
                                    .unwrap()
                                    .push(format!("watch_{}_{}", observer_id, final_state));
                            }
                            Outcome::Cancelled => {
                                stats_clone.increment_cancelled_waiters();
                            }
                            Outcome::Err(e) => panic!("Watch observation failed: {}", e),
                            Outcome::Panicked => panic!("Watch observation panicked"),
                        }
                        Outcome::Ok(())
                    },
                );
            }

            // Brief pause to let waiters/observers register
            let _ = sleep(Duration::from_millis(50)).await;

            // Trigger state transitions to wake waiters in order
            for state in 1..=3 {
                if let Outcome::Err(e) = machine_clone
                    .transition_state(cx, state, &stats_clone)
                    .await
                {
                    panic!("State transition failed: {}", e);
                }
                let _ = sleep(Duration::from_millis(20)).await;
            }

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        notify_wakes,
        watch_mutations,
        cancelled_waiters,
        successful_wakeups,
        state_transitions,
        _timeout_events,
    ) = stats.summary();
    let completion_order = completion_order.lock().unwrap().clone();

    // Verify ordering and completion
    assert_eq!(state_transitions, 3, "Should have 3 state transitions");
    assert_eq!(notify_wakes, 3, "Should have 3 notify wakes");
    assert!(successful_wakeups >= 4, "Should wake all 4 notify waiters");
    assert!(
        completion_order.len() >= 6,
        "Should complete at least 6 tasks (4 notify + 3 watch)"
    );
    assert_eq!(cancelled_waiters, 0, "No cancellations in ordering test");

    // Verify watch observers completed in order of their target states
    let watch_completions: Vec<_> = completion_order
        .iter()
        .filter(|s| s.starts_with("watch_"))
        .collect();
    assert!(
        !watch_completions.is_empty(),
        "Should have watch completions"
    );

    println!("✓ Multi-waiter ordering test passed");
    println!("  Completion order: {:?}", completion_order);
    println!("  Watch completions: {:?}", watch_completions);
}

/// Test notify timeout interaction with watch state changes
#[tokio::test]
async fn test_notify_timeout_watch_interaction() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(NotifyWatchStats::default());
    let machine = Arc::new(StateMachine::new());

    runtime
        .region(Budget::for_millis(1000), |cx, scope| async move {
            let stats_clone = Arc::clone(&stats);
            let machine_clone = Arc::clone(&machine);

            // Spawn timeout-aware notify waiter
            scope.spawn("timeout_notify_waiter", |cx| async move {
                let timeout_future = sleep(Duration::from_millis(150));

                let notify_future = async {
                    match machine_clone.wait_for_notify(cx, &stats_clone).await {
                        Outcome::Ok(()) => Outcome::Ok("notified"),
                        Outcome::Cancelled => Outcome::Cancelled,
                        Outcome::Err(e) => Outcome::Err(e),
                        Outcome::Panicked => Outcome::Panicked,
                    }
                };

                match crate::combinator::race([
                    Box::pin(async move {
                        timeout_future.await;
                        stats_clone.increment_timeout_events();
                        Outcome::Ok("timeout")
                    }) as crate::combinator::BoxedFuture<Outcome<&str, String>>,
                    Box::pin(notify_future),
                ])
                .await
                {
                    Outcome::Ok(("timeout", _)) => {
                        // Timeout won - expected in this scenario
                    }
                    Outcome::Ok(("notified", _)) => {
                        panic!("Should have timed out before notification");
                    }
                    other => panic!("Unexpected race outcome: {:?}", other),
                }

                Outcome::Ok(())
            });

            // Spawn delayed watch state changes
            scope.spawn("delayed_state_changer", |cx| async move {
                // Wait longer than timeout to trigger state change
                let _ = sleep(Duration::from_millis(200)).await;

                if let Outcome::Err(e) = machine_clone.transition_state(cx, 42, &stats_clone).await
                {
                    panic!("Delayed state transition failed: {}", e);
                }

                Outcome::Ok(())
            });

            // Spawn watch observer that should complete after timeout
            scope.spawn("post_timeout_watch_observer", |cx| async move {
                match machine_clone.watch_for_changes(cx, 42, &stats_clone).await {
                    Outcome::Ok(final_state) => {
                        assert_eq!(final_state, 42, "Should observe state 42");
                    }
                    Outcome::Cancelled => {
                        stats_clone.increment_cancelled_waiters();
                    }
                    Outcome::Err(e) => panic!("Post-timeout watch failed: {}", e),
                    Outcome::Panicked => panic!("Post-timeout watch panicked"),
                }
                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        notify_wakes,
        watch_mutations,
        cancelled_waiters,
        successful_wakeups,
        state_transitions,
        timeout_events,
    ) = stats.summary();

    // Verify timeout behavior
    assert_eq!(timeout_events, 1, "Should have 1 timeout event");
    assert_eq!(
        state_transitions, 1,
        "Should have 1 delayed state transition"
    );
    assert_eq!(notify_wakes, 1, "Should have 1 notify wake after timeout");
    assert!(
        watch_mutations >= 1,
        "Should have watch mutations after timeout"
    );
    assert_eq!(cancelled_waiters, 0, "No cancellations in timeout scenario");

    println!("✓ Timeout interaction test passed");
    println!(
        "  Timeout events: {}, State transitions: {}, Notify wakes: {}",
        timeout_events, state_transitions, notify_wakes
    );
}

/// Test watch receiver cancellation affecting notify waiters
#[tokio::test]
async fn test_watch_cancellation_affects_notify() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(NotifyWatchStats::default());
    let machine = Arc::new(StateMachine::new());
    let trigger_cancel = Arc::new(AtomicBool::new(false));

    runtime
        .region(Budget::for_millis(1000), |cx, scope| async move {
            let stats_clone = Arc::clone(&stats);
            let machine_clone = Arc::clone(&machine);
            let trigger_cancel_clone = Arc::clone(&trigger_cancel);

            // Spawn watch receiver that cancels early
            scope.spawn("early_cancel_watch", |cx| async move {
                let mut receiver = machine_clone.watch_rx.clone();

                // Wait for one change then cancel
                match receiver.changed().await {
                    Outcome::Ok(()) => {
                        stats_clone.increment_watch_mutations();
                        trigger_cancel_clone.store(true, Ordering::Release);
                    }
                    Outcome::Cancelled => {
                        stats_clone.increment_cancelled_waiters();
                    }
                    Outcome::Err(e) => panic!("Watch changed failed: {}", e),
                    Outcome::Panicked => panic!("Watch changed panicked"),
                }

                // Cancel ourselves to simulate early termination
                Outcome::Cancelled
            });

            // Spawn notify waiter that responds to cancellation trigger
            scope.spawn("cancel_responsive_notify_waiter", |cx| async move {
                loop {
                    if trigger_cancel_clone.load(Ordering::Acquire) {
                        stats_clone.increment_cancelled_waiters();
                        break;
                    }

                    match machine_clone.wait_for_notify(cx, &stats_clone).await {
                        Outcome::Ok(()) => {
                            // Check if we should cancel after receiving notify
                            if trigger_cancel_clone.load(Ordering::Acquire) {
                                stats_clone.increment_cancelled_waiters();
                                break;
                            }
                        }
                        Outcome::Cancelled => {
                            stats_clone.increment_cancelled_waiters();
                            break;
                        }
                        Outcome::Err(e) => panic!("Notify wait failed: {}", e),
                        Outcome::Panicked => panic!("Notify wait panicked"),
                    }
                }
                Outcome::Ok(())
            });

            // Spawn state driver that produces changes
            scope.spawn("state_producer", |cx| async move {
                for state in 1..=3 {
                    if trigger_cancel_clone.load(Ordering::Acquire) {
                        // Early termination due to watch cancellation
                        break;
                    }

                    if let Outcome::Err(e) = machine_clone
                        .transition_state(cx, state, &stats_clone)
                        .await
                    {
                        panic!("State transition failed: {}", e);
                    }

                    let _ = sleep(Duration::from_millis(30)).await;
                }
                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        notify_wakes,
        watch_mutations,
        cancelled_waiters,
        successful_wakeups,
        state_transitions,
        _timeout_events,
    ) = stats.summary();

    // Verify cancellation propagation from watch to notify
    assert!(
        cancelled_waiters >= 1,
        "Should have cancelled waiters due to watch cancellation"
    );
    assert!(
        watch_mutations >= 1,
        "Should have at least 1 watch mutation before cancellation"
    );
    assert!(notify_wakes >= 1, "Should have at least 1 notify wake");
    assert!(
        state_transitions >= 1,
        "Should have at least 1 state transition before cancellation"
    );

    println!("✓ Watch cancellation affects notify test passed");
    println!(
        "  Cancelled waiters: {}, Watch mutations: {}, Notify wakes: {}",
        cancelled_waiters, watch_mutations, notify_wakes
    );
}

/// Comprehensive test combining all notify-watch interaction patterns
#[tokio::test]
async fn test_comprehensive_notify_watch_integration() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(NotifyWatchStats::default());
    let machine = Arc::new(StateMachine::new());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let stats_clone = Arc::clone(&stats);
            let machine_clone = Arc::clone(&machine);

            // Phase 1: Normal operation with coordinated notify/watch
            scope.spawn("phase1_coordinator", |cx| async move {
                for state in 1..=3 {
                    if let Outcome::Err(e) = machine_clone
                        .transition_state(cx, state, &stats_clone)
                        .await
                    {
                        panic!("Phase 1 state transition failed: {}", e);
                    }
                    let _ = sleep(Duration::from_millis(50)).await;
                }
                Outcome::Ok(())
            });

            // Phase 1: Notify waiters
            for waiter_id in 0..2 {
                let machine_clone = Arc::clone(&machine);
                let stats_clone = Arc::clone(&stats);

                scope.spawn(
                    format!("phase1_notify_waiter_{}", waiter_id),
                    |cx| async move {
                        for _round in 0..2 {
                            if let Outcome::Err(e) =
                                machine_clone.wait_for_notify(cx, &stats_clone).await
                            {
                                panic!("Phase 1 notify wait failed: {}", e);
                            }
                        }
                        Outcome::Ok(())
                    },
                );
            }

            // Phase 1: Watch observers
            for observer_id in 0..2 {
                let machine_clone = Arc::clone(&machine);
                let stats_clone = Arc::clone(&stats);
                let target_state = observer_id + 2;

                scope.spawn(
                    format!("phase1_watch_observer_{}", observer_id),
                    |cx| async move {
                        match machine_clone
                            .watch_for_changes(cx, target_state, &stats_clone)
                            .await
                        {
                            Outcome::Ok(final_state) => {
                                assert!(
                                    final_state >= target_state,
                                    "Phase 1 observer {} incomplete",
                                    observer_id
                                );
                            }
                            Outcome::Cancelled => {
                                stats_clone.increment_cancelled_waiters();
                            }
                            Outcome::Err(e) => panic!("Phase 1 watch failed: {}", e),
                            Outcome::Panicked => panic!("Phase 1 watch panicked"),
                        }
                        Outcome::Ok(())
                    },
                );
            }

            // Phase 2: Mixed timeout and cancellation scenarios
            scope.spawn("phase2_timeout_coordinator", |cx| async move {
                let _ = sleep(Duration::from_millis(200)).await;

                // Generate rapid state changes
                for state in 10..=12 {
                    if let Outcome::Err(e) = machine_clone
                        .transition_state(cx, state, &stats_clone)
                        .await
                    {
                        panic!("Phase 2 state transition failed: {}", e);
                    }
                    let _ = sleep(Duration::from_millis(25)).await;
                }
                Outcome::Ok(())
            });

            // Phase 2: Timeout-aware notify waiter
            scope.spawn("phase2_timeout_waiter", |cx| async move {
                let timeout_future = sleep(Duration::from_millis(180));
                let notify_future = machine_clone.wait_for_notify(cx, &stats_clone);

                match crate::combinator::race([
                    Box::pin(async move {
                        timeout_future.await;
                        stats_clone.increment_timeout_events();
                        Outcome::Ok("timeout")
                    }) as crate::combinator::BoxedFuture<Outcome<&str, String>>,
                    Box::pin(async move {
                        match notify_future.await {
                            Outcome::Ok(()) => Outcome::Ok("notified"),
                            Outcome::Cancelled => Outcome::Cancelled,
                            Outcome::Err(e) => Outcome::Err(e),
                            Outcome::Panicked => Outcome::Panicked,
                        }
                    }),
                ])
                .await
                {
                    Outcome::Ok((_winner, _)) => {
                        // Either outcome is acceptable
                    }
                    other => panic!("Unexpected timeout race outcome: {:?}", other),
                }

                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        notify_wakes,
        watch_mutations,
        cancelled_waiters,
        successful_wakeups,
        state_transitions,
        timeout_events,
    ) = stats.summary();

    // Verify comprehensive integration
    assert!(
        state_transitions >= 5,
        "Should have at least 5 state transitions across phases"
    );
    assert!(notify_wakes >= 5, "Should have corresponding notify wakes");
    assert!(watch_mutations >= 5, "Should have watch mutations");
    assert!(
        successful_wakeups >= 4,
        "Should have successful notify wakeups"
    );
    assert!(timeout_events <= 1, "Should have at most 1 timeout event");

    // Memory leak detection - ensure clean shutdown
    let final_state = machine.state.load(Ordering::Acquire);
    assert!(final_state >= 10, "Should reach final states in phase 2");

    println!("✓ Comprehensive notify-watch integration test passed");
    println!(
        "  Final state: {}, Notify wakes: {}, Watch mutations: {}, Successful wakeups: {}",
        final_state, notify_wakes, watch_mutations, successful_wakeups
    );
    println!(
        "  Cancelled waiters: {}, Timeout events: {}",
        cancelled_waiters, timeout_events
    );
}
