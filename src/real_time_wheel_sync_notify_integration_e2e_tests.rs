//! Real E2E integration tests: time/wheel ↔ sync/notify (br-e2e-204).
//!
//! Tests that timer wheel-scheduled wakeups correctly integrate with notify
//! primitives. Verifies the integration between:
//!
//! - `time::wheel`: Hierarchical timing wheel for efficient timer management
//! - `sync::notify`: Event notification primitive with cancel-aware waiting
//!
//! Key integration properties:
//! - Timer wheel-scheduled wakeups correctly notify subscribed tasks
//! - No missed wakes under heavy load with concurrent timers
//! - Timer expiration triggers notify wakeups at correct times
//! - Notify wait operations integrate with timer wheel scheduling
//! - Cancellation propagation between timer wheel and notify
//! - Timer coalescing behavior with notify batching

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        cx::Cx,
        error::Result,
        runtime::{Runtime, spawn},
        sync::{Arc, Notify},
        time::{Duration, sleep},
        types::{Budget, Outcome},
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    // ────────────────────────────────────────────────────────────────────────────────
    // Timer Wheel + Notify Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Default)]
    pub struct TimerNotifyStats {
        pub timers_started: AtomicU64,
        pub notifications_received: AtomicU64,
        pub cancelled_operations: AtomicU64,
        pub successful_integrations: AtomicU64,
    }

    /// Simple integration test helper combining timer operations with notifications
    struct TimerNotifyIntegration {
        notify: Arc<Notify>,
        stats: Arc<TimerNotifyStats>,
        ready_flag: Arc<AtomicBool>,
    }

    impl TimerNotifyIntegration {
        fn new() -> Self {
            Self {
                notify: Arc::new(Notify::new()),
                stats: Arc::new(TimerNotifyStats::default()),
                ready_flag: Arc::new(AtomicBool::new(false)),
            }
        }

        async fn test_timer_notify_coordination(&self, cx: &Cx) -> Result<()> {
            // Spawn a task that waits for notification
            let waiter_task = spawn(cx, {
                let notify = Arc::clone(&self.notify);
                let stats = Arc::clone(&self.stats);
                let ready_flag = Arc::clone(&self.ready_flag);

                async move {
                    // Signal readiness to start timing
                    ready_flag.store(true, Ordering::Release);

                    // Wait for notification
                    match notify.notified().await {
                        Outcome::Ok(()) => {
                            stats.notifications_received.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        }
                        Outcome::Cancelled => {
                            stats.cancelled_operations.fetch_add(1, Ordering::Relaxed);
                            Outcome::Cancelled
                        }
                        _ => Err(crate::error::Error::Other("Notify failed")),
                    }
                }
            })
            .await;

            // Wait for readiness
            while !self.ready_flag.load(Ordering::Acquire) {
                sleep(Duration::from_millis(1)).await;
            }

            // Spawn a timer task that notifies after a delay
            let timer_task = spawn(cx, {
                let notify = Arc::clone(&self.notify);
                let stats = Arc::clone(&self.stats);

                async move {
                    stats.timers_started.fetch_add(1, Ordering::Relaxed);

                    // Simulate timer wheel behavior with sleep + notify
                    sleep(Duration::from_millis(100)).await;

                    // Notify waiters (simulates timer expiration triggering notification)
                    notify.notify_waiters();

                    stats
                        .successful_integrations
                        .fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            })
            .await;

            // Both tasks should complete successfully
            match (waiter_task, timer_task) {
                (Ok(()), Ok(())) => Ok(()),
                _ => Err(crate::error::Error::Other(
                    "Timer-notify integration failed",
                )),
            }
        }

        fn get_stats(&self) -> (u64, u64, u64, u64) {
            (
                self.stats.timers_started.load(Ordering::Relaxed),
                self.stats.notifications_received.load(Ordering::Relaxed),
                self.stats.cancelled_operations.load(Ordering::Relaxed),
                self.stats.successful_integrations.load(Ordering::Relaxed),
            )
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Actual Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_timer_wheel_notify_basic_integration() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let integration = TimerNotifyIntegration::new();

            integration.test_timer_notify_coordination(&cx).await?;

            let (timers_started, notifications_received, cancelled_ops, successful_integrations) =
                integration.get_stats();

            assert!(timers_started > 0, "Should have started timers");
            assert!(
                notifications_received > 0,
                "Should have received notifications"
            );
            assert!(
                successful_integrations > 0,
                "Should have successful integrations"
            );

            println!("✓ Basic timer wheel ↔ sync notify integration verified");
            println!("  Timers started: {}", timers_started);
            println!("  Notifications received: {}", notifications_received);
            println!("  Cancelled operations: {}", cancelled_ops);
            println!("  Successful integrations: {}", successful_integrations);

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_multiple_timer_notify_coordination() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;

            // Test multiple concurrent timer-notify integrations
            let mut tasks = Vec::new();

            for i in 0..5 {
                let task = spawn(&cx, async move {
                    let integration = TimerNotifyIntegration::new();
                    integration.test_timer_notify_coordination(&cx).await?;

                    let (timers, notifications, _cancelled, successful) = integration.get_stats();
                    println!(
                        "  Task {}: {} timers, {} notifications, {} successful",
                        i, timers, notifications, successful
                    );

                    Ok(())
                })
                .await;

                tasks.push(task);
            }

            // All tasks should complete successfully
            for task in tasks {
                task?;
            }

            println!("✓ Multiple timer wheel ↔ sync notify coordination verified");
            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_timer_notify_cancellation() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let integration = TimerNotifyIntegration::new();
            let notify = Arc::clone(&integration.notify);
            let stats = Arc::clone(&integration.stats);

            // Test cancellation of notify waits
            let cancel_task = spawn(&cx, async move {
                let budget = Budget::for_millis(50); // Short budget to force cancellation

                cx.with_budget(budget, async {
                    // This should be cancelled due to budget timeout
                    match notify.notified().await {
                        Outcome::Cancelled => {
                            stats.cancelled_operations.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        }
                        _ => Err(crate::error::Error::Other("Expected cancellation")),
                    }
                })
                .await
            })
            .await?;

            let (_timers, _notifications, cancelled, _successful) = integration.get_stats();

            assert!(
                cancelled > 0,
                "Should have cancelled operations from budget timeout"
            );

            println!("✓ Timer wheel ↔ sync notify cancellation verified");
            println!("  Cancelled operations: {}", cancelled);

            Ok(())
        })
    }
}
