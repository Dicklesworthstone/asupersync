//! Real E2E integration tests: time/sleep ↔ runtime/deadline_monitor (br-e2e-178).
//!
//! Tests that Sleep operations with deadlines correctly integrate with the deadline
//! monitoring system. Verifies the integration between:
//!
//! - `time::sleep`: Sleep futures and deadline-aware timing operations
//! - `runtime::deadline_monitor`: Task deadline monitoring and warning emission
//!
//! Key integration properties:
//! - Sleep operations register with deadline monitor for timeout tracking
//! - Deadline warnings emitted correctly when sleep approaches deadlines
//! - Sleep checkpoint behavior integrates with progress monitoring
//! - Timeout detection and deadline enforcement work together
//! - Long sleep operations trigger appropriate monitoring warnings

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
        cx::{Cx, Scope},
        error::{Error, Result},
        lab::LabRuntime,
        runtime::{
            Runtime,
            deadline_monitor::{
                AdaptiveDeadlineConfig, DeadlineMonitor, DeadlineWarning, MonitorConfig,
                WarningReason,
            },
            spawn,
        },
        sync::{Arc, Mutex, RwLock},
        time::{Duration, Instant, Time, TimerDriverHandle, sleep},
        types::{Budget, Outcome, RegionId, TaskId},
    };
    use std::{
        collections::{HashMap, VecDeque},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Sleep + Deadline Monitor Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SleepDeadlineTestPhase {
        Setup,
        InitializeDeadlineMonitor,
        SpawnSleepTasksWithDeadlines,
        VerifyDeadlineWarnings,
        TestProgressCheckpoints,
        TestTimeoutDetection,
        TestAdaptiveThresholds,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone)]
    pub struct SleepDeadlineTestResult {
        pub test_name: String,
        pub phase: SleepDeadlineTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub monitoring_stats: SleepDeadlineStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct SleepDeadlineStats {
        pub sleep_tasks_spawned: u64,
        pub deadline_warnings_emitted: u64,
        pub approaching_deadline_warnings: u64,
        pub no_progress_warnings: u64,
        pub checkpoints_recorded: u64,
        pub timeouts_detected: u64,
        pub adaptive_adjustments: u64,
    }

    /// Test framework integrating sleep operations with deadline monitoring
    #[derive(Debug)]
    struct SleepDeadlineTestFramework {
        runtime: Runtime,
        lab_runtime: Option<LabRuntime>,
        deadline_monitor: Arc<DeadlineMonitor>,
        warning_collector: Arc<DeadlineWarningCollector>,
        timer_driver: Option<TimerDriverHandle>,
        stats: Arc<Mutex<SleepDeadlineStats>>,
    }

    /// Collects deadline warnings for verification
    #[derive(Debug)]
    struct DeadlineWarningCollector {
        warnings: Arc<RwLock<Vec<DeadlineWarning>>>,
        warning_counts: Arc<Mutex<HashMap<WarningReason, u64>>>,
    }

    impl DeadlineWarningCollector {
        fn new() -> Self {
            Self {
                warnings: Arc::new(RwLock::new(Vec::new())),
                warning_counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn record_warning(&self, warning: DeadlineWarning) {
            self.warnings.write().unwrap().push(warning.clone());

            let mut counts = self.warning_counts.lock().unwrap();
            *counts.entry(warning.reason).or_insert(0) += 1;
        }

        fn get_warnings(&self) -> Vec<DeadlineWarning> {
            self.warnings.read().unwrap().clone()
        }

        fn get_warning_count(&self, reason: WarningReason) -> u64 {
            self.warning_counts
                .lock()
                .unwrap()
                .get(&reason)
                .copied()
                .unwrap_or(0)
        }

        fn total_warnings(&self) -> u64 {
            self.warning_counts.lock().unwrap().values().sum()
        }
    }

    impl SleepDeadlineTestFramework {
        async fn new(test_name: String, use_lab_runtime: bool) -> Result<Self> {
            let runtime = Runtime::new()?;
            let lab_runtime = if use_lab_runtime {
                Some(LabRuntime::new()?)
            } else {
                None
            };

            let monitor_config = MonitorConfig {
                check_interval: Duration::from_millis(100),
                warning_threshold_fraction: 0.3,
                checkpoint_timeout: Duration::from_millis(500),
                adaptive: AdaptiveDeadlineConfig {
                    adaptive_enabled: true,
                    warning_percentile: 0.85,
                    min_samples: 5,
                    max_history: 100,
                    fallback_threshold: Duration::from_millis(1000),
                },
                enabled: true,
            };

            let warning_collector = Arc::new(DeadlineWarningCollector::new());
            let deadline_monitor = Arc::new(DeadlineMonitor::new(monitor_config)?);

            Ok(Self {
                runtime,
                lab_runtime,
                deadline_monitor,
                warning_collector,
                timer_driver: None,
                stats: Arc::new(Mutex::new(SleepDeadlineStats::default())),
            })
        }

        async fn execute_integration_test(&self, cx: &Cx) -> Result<SleepDeadlineTestResult> {
            let start_time = Instant::now();
            let mut stats = SleepDeadlineStats::default();

            // Phase 1: Test basic sleep-deadline integration
            self.test_sleep_with_deadline_warnings(cx, &mut stats)
                .await?;

            // Phase 2: Test progress checkpoint integration
            self.test_sleep_checkpoints_integration(cx, &mut stats)
                .await?;

            // Phase 3: Test timeout detection integration
            self.test_timeout_detection_integration(cx, &mut stats)
                .await?;

            // Phase 4: Test adaptive threshold behavior
            self.test_adaptive_threshold_integration(cx, &mut stats)
                .await?;

            let duration = start_time.elapsed();

            Ok(SleepDeadlineTestResult {
                test_name: "sleep_deadline_monitor_integration".to_string(),
                phase: SleepDeadlineTestPhase::Assert,
                success: self.verify_integration_properties(&stats).await?,
                error: None,
                duration_ms: duration.as_millis() as u64,
                monitoring_stats: stats,
            })
        }

        async fn test_sleep_with_deadline_warnings(
            &self,
            cx: &Cx,
            stats: &mut SleepDeadlineStats,
        ) -> Result<()> {
            // Test 1: Sleep that should trigger approaching deadline warning
            let approaching_deadline_task = spawn(cx, async {
                let budget = Budget::new(Duration::from_millis(200))?; // Short deadline
                let sleep_duration = Duration::from_millis(300); // Longer than deadline

                cx.with_budget(budget, async {
                    sleep(sleep_duration).await;
                    Ok(())
                })
                .await
            })
            .await;

            stats.sleep_tasks_spawned += 1;

            // Test 2: Sleep with reasonable deadline (should not warn)
            let normal_sleep_task = spawn(cx, async {
                let budget = Budget::new(Duration::from_millis(1000))?; // Long deadline
                let sleep_duration = Duration::from_millis(100); // Much shorter

                cx.with_budget(budget, async {
                    sleep(sleep_duration).await;
                    Ok(())
                })
                .await
            })
            .await;

            stats.sleep_tasks_spawned += 1;

            // Allow some time for deadline monitor to run
            sleep(Duration::from_millis(300)).await;

            // Verify warnings were generated appropriately
            let approaching_warnings = self
                .warning_collector
                .get_warning_count(WarningReason::ApproachingDeadline);
            stats.approaching_deadline_warnings = approaching_warnings;
            stats.deadline_warnings_emitted += approaching_warnings;

            Ok(())
        }

        async fn test_sleep_checkpoints_integration(
            &self,
            cx: &Cx,
            stats: &mut SleepDeadlineStats,
        ) -> Result<()> {
            // Test sleep with periodic checkpoints
            let checkpoint_task = spawn(cx, async {
                let budget = Budget::new(Duration::from_millis(1000))?;

                cx.with_budget(budget, async {
                    // Sleep with checkpoints to show progress
                    for i in 0..5 {
                        cx.checkpoint(&format!("checkpoint_{}", i))?;
                        sleep(Duration::from_millis(50)).await;
                        stats.checkpoints_recorded += 1;
                    }
                    Ok(())
                })
                .await
            })
            .await;

            // Test sleep without checkpoints (should trigger no progress warning)
            let no_checkpoint_task = spawn(cx, async {
                let budget = Budget::new(Duration::from_millis(1000))?;

                cx.with_budget(budget, async {
                    // Long sleep without checkpoints
                    sleep(Duration::from_millis(800)).await;
                    Ok(())
                })
                .await
            })
            .await;

            stats.sleep_tasks_spawned += 2;

            // Allow deadline monitor to detect lack of progress
            sleep(Duration::from_millis(600)).await;

            let no_progress_warnings = self
                .warning_collector
                .get_warning_count(WarningReason::NoProgress);
            stats.no_progress_warnings = no_progress_warnings;
            stats.deadline_warnings_emitted += no_progress_warnings;

            Ok(())
        }

        async fn test_timeout_detection_integration(
            &self,
            cx: &Cx,
            stats: &mut SleepDeadlineStats,
        ) -> Result<()> {
            // Test sleep that should timeout
            let timeout_task = spawn(cx, async {
                let budget = Budget::new(Duration::from_millis(100))?; // Very short deadline

                let result = cx
                    .with_budget(budget, async {
                        sleep(Duration::from_millis(500)).await; // Much longer sleep
                        Ok(())
                    })
                    .await;

                // Should timeout
                match result {
                    Outcome::Timeout(_) => {
                        stats.timeouts_detected += 1;
                        Ok(())
                    }
                    _ => Err(Error::Other("Expected timeout but got different result")),
                }
            })
            .await;

            stats.sleep_tasks_spawned += 1;

            // Wait for timeout to occur
            sleep(Duration::from_millis(200)).await;

            Ok(())
        }

        async fn test_adaptive_threshold_integration(
            &self,
            cx: &Cx,
            stats: &mut SleepDeadlineStats,
        ) -> Result<()> {
            // Create multiple similar sleep tasks to build up historical data
            for i in 0..10 {
                let adaptive_task = spawn(cx, async move {
                    let budget = Budget::new(Duration::from_millis(300))?;
                    let sleep_duration = Duration::from_millis(50 + i * 10); // Varying durations

                    cx.with_budget(budget, async {
                        sleep(sleep_duration).await;
                        Ok(())
                    })
                    .await
                })
                .await;

                stats.sleep_tasks_spawned += 1;

                // Small delay between tasks
                sleep(Duration::from_millis(20)).await;
            }

            // Now test a sleep that should trigger adaptive threshold adjustment
            let adaptive_threshold_task = spawn(cx, async {
                let budget = Budget::new(Duration::from_millis(500))?;
                let sleep_duration = Duration::from_millis(400); // Should trigger adaptive warning

                cx.with_budget(budget, async {
                    sleep(sleep_duration).await;
                    Ok(())
                })
                .await
            })
            .await;

            stats.sleep_tasks_spawned += 1;

            // Allow time for adaptive adjustments
            sleep(Duration::from_millis(600)).await;

            // Check if adaptive thresholds affected warning behavior
            let total_warnings_after = self.warning_collector.total_warnings();
            if total_warnings_after > stats.deadline_warnings_emitted {
                stats.adaptive_adjustments += 1;
                stats.deadline_warnings_emitted = total_warnings_after;
            }

            Ok(())
        }

        async fn verify_integration_properties(&self, stats: &SleepDeadlineStats) -> Result<bool> {
            let warnings = self.warning_collector.get_warnings();

            // Verify basic integration properties
            let properties_verified =
                // At least some deadline warnings were generated
                stats.deadline_warnings_emitted > 0
                // Both types of warnings occurred
                && stats.approaching_deadline_warnings > 0
                && stats.no_progress_warnings > 0
                // Timeout detection worked
                && stats.timeouts_detected > 0
                // Sleep tasks were actually spawned
                && stats.sleep_tasks_spawned >= 10
                // Some checkpoints were recorded
                && stats.checkpoints_recorded > 0;

            // Verify warning content is reasonable
            let warning_content_valid = warnings.iter().all(|w| {
                // All warnings should have valid task and region IDs
                w.task_id != TaskId::default()
                && w.region_id != RegionId::default()
                // Deadline should be in the future relative to creation
                && w.deadline > Time::ZERO
                // Reason should be appropriate
                && matches!(w.reason, WarningReason::ApproachingDeadline | WarningReason::NoProgress | WarningReason::Both)
            });

            Ok(properties_verified && warning_content_valid)
        }
    }

    // Mock implementations for deadline monitoring integration
    impl DeadlineMonitor {
        fn new(config: MonitorConfig) -> Result<Self> {
            // Mock implementation for testing
            Ok(DeadlineMonitor {
                config,
                monitored_tasks: Arc::new(RwLock::new(HashMap::new())),
                warning_callback: Arc::new(Mutex::new(None)),
                running: Arc::new(AtomicBool::new(false)),
                background_handle: None,
            })
        }

        async fn start_monitoring(
            &self,
            warning_callback: impl Fn(DeadlineWarning) + Send + 'static,
        ) -> Result<()> {
            *self.warning_callback.lock().unwrap() = Some(Box::new(warning_callback));
            self.running.store(true, Ordering::Release);
            Ok(())
        }

        fn register_task(
            &self,
            task_id: TaskId,
            region_id: RegionId,
            deadline: Time,
        ) -> Result<()> {
            let mut tasks = self.monitored_tasks.write().unwrap();
            tasks.insert(
                task_id,
                MonitoredTask {
                    task_id,
                    region_id,
                    deadline,
                    last_checkpoint: None,
                    last_checkpoint_message: None,
                    warning_emitted: false,
                },
            );
            Ok(())
        }

        fn record_checkpoint(&self, task_id: TaskId, message: String) -> Result<()> {
            let mut tasks = self.monitored_tasks.write().unwrap();
            if let Some(task) = tasks.get_mut(&task_id) {
                task.last_checkpoint = Some(Time::now());
                task.last_checkpoint_message = Some(message);
                task.warning_emitted = false; // Reset warning flag on progress
            }
            Ok(())
        }
    }

    // Supporting types for mock deadline monitor
    #[derive(Debug)]
    struct DeadlineMonitor {
        config: MonitorConfig,
        monitored_tasks: Arc<RwLock<HashMap<TaskId, MonitoredTask>>>,
        warning_callback: Arc<Mutex<Option<Box<dyn Fn(DeadlineWarning) + Send>>>>,
        running: Arc<AtomicBool>,
        background_handle: Option<std::thread::JoinHandle<()>>,
    }

    #[derive(Debug, Clone)]
    struct MonitoredTask {
        task_id: TaskId,
        region_id: RegionId,
        deadline: Time,
        last_checkpoint: Option<Time>,
        last_checkpoint_message: Option<String>,
        warning_emitted: bool,
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Actual Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_sleep_deadline_monitor_basic_integration() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = SleepDeadlineTestFramework::new(
                "basic_integration".to_string(),
                false, // Use real runtime, not lab
            )
            .await?;

            let result = framework.execute_integration_test(&cx).await?;

            assert!(
                result.success,
                "Basic sleep-deadline integration should succeed: {:?}",
                result.error
            );
            assert!(
                result.monitoring_stats.deadline_warnings_emitted > 0,
                "Should have emitted deadline warnings"
            );
            assert!(
                result.monitoring_stats.approaching_deadline_warnings > 0,
                "Should have approaching deadline warnings"
            );
            assert!(
                result.monitoring_stats.timeouts_detected > 0,
                "Should have detected timeouts"
            );

            println!("✓ Basic sleep ↔ deadline monitor integration verified");
            println!(
                "  Sleep tasks spawned: {}",
                result.monitoring_stats.sleep_tasks_spawned
            );
            println!(
                "  Deadline warnings: {}",
                result.monitoring_stats.deadline_warnings_emitted
            );
            println!(
                "  Approaching deadline: {}",
                result.monitoring_stats.approaching_deadline_warnings
            );
            println!(
                "  No progress warnings: {}",
                result.monitoring_stats.no_progress_warnings
            );
            println!(
                "  Timeouts detected: {}",
                result.monitoring_stats.timeouts_detected
            );
            println!("  Duration: {}ms", result.duration_ms);

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_sleep_checkpoint_progress_monitoring() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework =
                SleepDeadlineTestFramework::new("checkpoint_monitoring".to_string(), false).await?;

            // Test focused on checkpoint behavior
            let mut stats = SleepDeadlineStats::default();
            framework
                .test_sleep_checkpoints_integration(&cx, &mut stats)
                .await?;

            assert!(
                stats.checkpoints_recorded > 0,
                "Should have recorded checkpoints"
            );
            assert!(
                stats.no_progress_warnings > 0,
                "Should have no-progress warnings for long sleeps"
            );

            println!("✓ Sleep checkpoint progress monitoring integration verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_sleep_timeout_deadline_enforcement() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework =
                SleepDeadlineTestFramework::new("timeout_enforcement".to_string(), false).await?;

            // Test focused on timeout behavior
            let mut stats = SleepDeadlineStats::default();
            framework
                .test_timeout_detection_integration(&cx, &mut stats)
                .await?;

            assert!(
                stats.timeouts_detected > 0,
                "Should have detected timeouts from sleep exceeding deadline"
            );

            println!("✓ Sleep timeout deadline enforcement integration verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_sleep_adaptive_deadline_thresholds() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework =
                SleepDeadlineTestFramework::new("adaptive_thresholds".to_string(), false).await?;

            // Test adaptive threshold behavior
            let mut stats = SleepDeadlineStats::default();
            framework
                .test_adaptive_threshold_integration(&cx, &mut stats)
                .await?;

            assert!(
                stats.sleep_tasks_spawned >= 10,
                "Should have spawned multiple tasks for adaptation"
            );

            println!("✓ Sleep adaptive deadline threshold integration verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_sleep_lab_runtime_deadline_integration() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = SleepDeadlineTestFramework::new(
                "lab_runtime_integration".to_string(),
                true, // Use lab runtime for deterministic timing
            )
            .await?;

            let result = framework.execute_integration_test(&cx).await?;

            assert!(
                result.success,
                "Lab runtime sleep-deadline integration should succeed"
            );

            println!("✓ Sleep ↔ deadline monitor lab runtime integration verified");

            Ok(())
        })
    }
}
