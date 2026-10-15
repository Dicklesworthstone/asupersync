//! Real time/timer E2E tests with advanced deadline and interval behavior
//!
//! Tests deadline-monotone guarantees and interval-skip-on-late behavior
//! using real asupersync timer implementations. No mocks - validates
//! timing accuracy, deadline ordering, and interval skipping logic.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_timer_extended_e2e {
    use crate::combinator::{race, timeout};
    use crate::cx::{Cx, scope};
    use crate::runtime::{Runtime, spawn};
    use crate::time::{Deadline, Duration, Instant, Interval, sleep};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::sync::mpsc;

    /// Timer test harness with structured logging and timing validation
    struct TimerTestHarness {
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        timing_records: Arc<Mutex<Vec<TimingRecord>>>,
    }

    #[derive(Debug, Clone)]
    struct TimingRecord {
        timestamp: Instant,
        event_type: String,
        deadline: Option<Instant>,
        interval_seq: Option<u64>,
        actual_delay: Duration,
        expected_delay: Duration,
        skipped: bool,
    }

    impl TimerTestHarness {
        fn new() -> Self {
            Self {
                start_time: Instant::now(),
                log_entries: Arc::new(Mutex::new(Vec::new())),
                timing_records: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn log(&self, event: &str, data: Value) {
            let entry = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event": event,
                "data": data,
                "elapsed_ms": self.start_time.elapsed().as_millis()
            });
            eprintln!("{}", serde_json::to_string(&entry).unwrap());
            self.log_entries.lock().unwrap().push(entry);
        }

        fn record_timing(&self, record: TimingRecord) {
            self.timing_records.lock().unwrap().push(record);
        }

        fn get_timing_records(&self) -> Vec<TimingRecord> {
            self.timing_records.lock().unwrap().clone()
        }

        fn validate_deadline_monotonic(&self) -> Result<(), String> {
            let records = self.get_timing_records();

            let mut deadline_records: Vec<_> =
                records.iter().filter(|r| r.deadline.is_some()).collect();

            deadline_records.sort_by_key(|r| r.timestamp);

            for window in deadline_records.windows(2) {
                let earlier = &window[0];
                let later = &window[1];

                let earlier_deadline = earlier.deadline.unwrap();
                let later_deadline = later.deadline.unwrap();

                // Deadline-monotone property: if task A was submitted before task B,
                // and A's deadline ≤ B's deadline, then A should complete before or equal to B
                if earlier_deadline <= later_deadline {
                    // This is expected - no violation
                } else {
                    // A was submitted first but has a later deadline than B
                    // This is allowed, but B should complete before A
                    if earlier.timestamp <= later.timestamp {
                        return Err(format!(
                            "Deadline-monotone violation: task submitted at {:?} with deadline {:?} \
                             completed before task submitted at {:?} with earlier deadline {:?}",
                            earlier.timestamp, earlier_deadline, later.timestamp, later_deadline
                        ));
                    }
                }
            }

            Ok(())
        }

        fn validate_interval_skip_behavior(
            &self,
            expected_interval: Duration,
        ) -> Result<(), String> {
            let records = self.get_timing_records();

            let interval_records: Vec<_> = records
                .iter()
                .filter(|r| r.interval_seq.is_some())
                .collect();

            let mut prev_time: Option<Instant> = None;
            let mut expected_seq = 0u64;

            for record in &interval_records {
                if let Some(prev) = prev_time {
                    let actual_interval = record.timestamp.duration_since(prev);

                    // If the actual interval is significantly longer than expected,
                    // we should have skipped some intervals
                    let expected_skips =
                        (actual_interval.as_millis() / expected_interval.as_millis()) - 1;

                    if expected_skips > 0 && !record.skipped {
                        return Err(format!(
                            "Expected interval skip: actual interval {}ms, expected {}ms, \
                             should have skipped {} intervals but didn't",
                            actual_interval.as_millis(),
                            expected_interval.as_millis(),
                            expected_skips
                        ));
                    }

                    expected_seq += 1 + expected_skips as u64;
                } else {
                    expected_seq = 0;
                }

                // Verify sequence number accounts for skips
                if let Some(seq) = record.interval_seq {
                    if seq < expected_seq {
                        return Err(format!(
                            "Interval sequence error: got seq {}, expected at least {}",
                            seq, expected_seq
                        ));
                    }
                }

                prev_time = Some(record.timestamp);
            }

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_deadline_monotone_ordering() {
        let harness = Arc::new(TimerTestHarness::new());
        harness.log("test_start", json!({"test": "deadline_monotone_ordering"}));

        // Create deadlines in non-monotonic submission order
        let base_time = Instant::now();
        let deadline_1 = base_time + Duration::from_millis(300); // Later deadline
        let deadline_2 = base_time + Duration::from_millis(100); // Earlier deadline
        let deadline_3 = base_time + Duration::from_millis(200); // Middle deadline

        let completion_order = Arc::new(Mutex::new(Vec::new()));

        // Submit tasks in order: deadline_1 (300ms), deadline_2 (100ms), deadline_3 (200ms)
        let tasks = vec![
            (deadline_1, "task_1", 1),
            (deadline_2, "task_2", 2),
            (deadline_3, "task_3", 3),
        ];

        let mut handles = Vec::new();

        for (deadline, task_name, task_id) in tasks {
            let harness = Arc::clone(&harness);
            let completion_order = Arc::clone(&completion_order);

            let handle = spawn(async move {
                let start_time = Instant::now();

                // Sleep until deadline
                let sleep_duration = deadline.saturating_duration_since(start_time);
                sleep(sleep_duration).await;

                let completion_time = Instant::now();

                // Record timing
                harness.record_timing(TimingRecord {
                    timestamp: completion_time,
                    event_type: "deadline_completion".to_string(),
                    deadline: Some(deadline),
                    interval_seq: None,
                    actual_delay: completion_time.duration_since(start_time),
                    expected_delay: sleep_duration,
                    skipped: false,
                });

                completion_order
                    .lock()
                    .unwrap()
                    .push((task_id, completion_time, deadline));

                harness.log("task_completed", json!({
                    "task": task_name,
                    "task_id": task_id,
                    "deadline_ms": deadline.duration_since(base_time).as_millis(),
                    "actual_completion_ms": completion_time.duration_since(base_time).as_millis()
                }));
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await;
        }

        // Validate deadline-monotone ordering
        let validation_result = harness.validate_deadline_monotonic();
        assert!(
            validation_result.is_ok(),
            "Deadline-monotone validation failed: {:?}",
            validation_result
        );

        // Verify completion order respects deadlines
        let completions = completion_order.lock().unwrap();
        assert_eq!(completions.len(), 3, "All tasks should have completed");

        // Sort by completion time and verify deadline order
        let mut sorted_completions = completions.clone();
        sorted_completions.sort_by_key(|(_, completion_time, _)| *completion_time);

        // Should complete in deadline order: task_2 (100ms), task_3 (200ms), task_1 (300ms)
        assert_eq!(
            sorted_completions[0].0, 2,
            "Task 2 should complete first (earliest deadline)"
        );
        assert_eq!(
            sorted_completions[1].0, 3,
            "Task 3 should complete second (middle deadline)"
        );
        assert_eq!(
            sorted_completions[2].0, 1,
            "Task 1 should complete last (latest deadline)"
        );

        harness.log("test_result", json!({
            "passed": true,
            "completion_order": sorted_completions.iter().map(|(id, _, _)| id).collect::<Vec<_>>(),
            "message": "Deadline-monotone ordering validated successfully"
        }));
    }

    #[tokio::test]
    async fn test_interval_skip_on_late_behavior() {
        let harness = Arc::new(TimerTestHarness::new());
        harness.log("test_start", json!({"test": "interval_skip_on_late"}));

        let interval_duration = Duration::from_millis(100); // 100ms intervals
        let mut interval = Interval::new(interval_duration);

        let tick_count = Arc::new(AtomicUsize::new(0));
        let skip_count = Arc::new(AtomicUsize::new(0));

        let start_time = Instant::now();
        let test_duration = Duration::from_secs(2);

        let harness_clone = Arc::clone(&harness);
        let tick_count_clone = Arc::clone(&tick_count);
        let skip_count_clone = Arc::clone(&skip_count);

        let interval_task = spawn(async move {
            let mut expected_tick = 0u64;
            let mut last_tick_time = start_time;

            while start_time.elapsed() < test_duration {
                // Wait for next interval tick
                let tick_start = Instant::now();
                interval.tick().await;
                let tick_time = Instant::now();

                let tick_number = tick_count_clone.fetch_add(1, Ordering::Relaxed) as u64;
                let actual_interval = tick_time.duration_since(last_tick_time);

                // Determine if intervals were skipped
                let expected_intervals =
                    (actual_interval.as_millis() / interval_duration.as_millis()).max(1);
                let skipped = expected_intervals > 1;
                let skips = expected_intervals - 1;

                if skipped {
                    skip_count_clone.fetch_add(skips as usize, Ordering::Relaxed);
                }

                // Record timing
                harness_clone.record_timing(TimingRecord {
                    timestamp: tick_time,
                    event_type: "interval_tick".to_string(),
                    deadline: None,
                    interval_seq: Some(tick_number),
                    actual_delay: actual_interval,
                    expected_delay: interval_duration,
                    skipped,
                });

                harness_clone.log(
                    "interval_tick",
                    json!({
                        "tick": tick_number,
                        "actual_interval_ms": actual_interval.as_millis(),
                        "expected_interval_ms": interval_duration.as_millis(),
                        "skipped_intervals": skips,
                        "total_skips": skip_count_clone.load(Ordering::Relaxed)
                    }),
                );

                // Simulate some processing time to potentially cause late intervals
                if tick_number % 3 == 0 {
                    // Every 3rd tick, simulate longer processing
                    sleep(Duration::from_millis(150)).await;
                }

                last_tick_time = tick_time;
                expected_tick += expected_intervals;
            }
        });

        // Wait for the interval test to complete
        interval_task.await;

        let total_ticks = tick_count.load(Ordering::Relaxed);
        let total_skips = skip_count.load(Ordering::Relaxed);

        harness.log("test_summary", json!({
            "total_ticks": total_ticks,
            "total_skips": total_skips,
            "test_duration_ms": test_duration.as_millis(),
            "expected_ticks_without_skips": (test_duration.as_millis() / interval_duration.as_millis()) as usize
        }));

        // Validate interval skip behavior
        let validation_result = harness.validate_interval_skip_behavior(interval_duration);
        assert!(
            validation_result.is_ok(),
            "Interval skip validation failed: {:?}",
            validation_result
        );

        // Should have skipped some intervals due to simulated processing delays
        assert!(
            total_skips > 0,
            "Expected some interval skips due to processing delays"
        );

        // Should have fewer total ticks than naive expectation due to skipping
        let naive_expected_ticks =
            (test_duration.as_millis() / interval_duration.as_millis()) as usize;
        assert!(
            total_ticks < naive_expected_ticks,
            "Should have fewer ticks ({}) than naive expectation ({}) due to skipping",
            total_ticks,
            naive_expected_ticks
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "skips_detected": total_skips > 0,
                "timing_behavior_correct": total_ticks < naive_expected_ticks,
                "message": "Interval skip-on-late behavior validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_deadline_timeout_interaction() {
        let harness = Arc::new(TimerTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "deadline_timeout_interaction"}),
        );

        let timeout_duration = Duration::from_millis(200);
        let work_duration = Duration::from_millis(300); // Longer than timeout

        let start_time = Instant::now();

        // Test timeout vs deadline interaction
        let result = timeout(timeout_duration, async {
            let work_start = Instant::now();

            // Simulate work that takes longer than timeout
            sleep(work_duration).await;

            harness.record_timing(TimingRecord {
                timestamp: Instant::now(),
                event_type: "work_completed".to_string(),
                deadline: Some(start_time + timeout_duration),
                interval_seq: None,
                actual_delay: work_start.elapsed(),
                expected_delay: work_duration,
                skipped: false,
            });

            "work_completed"
        })
        .await;

        let total_time = start_time.elapsed();

        match result {
            Ok(_) => {
                // Work completed before timeout - unexpected
                harness.log(
                    "unexpected_completion",
                    json!({
                        "message": "Work completed before timeout",
                        "total_time_ms": total_time.as_millis()
                    }),
                );
                panic!("Work should have been cancelled by timeout");
            }
            Err(_) => {
                // Timeout occurred - expected behavior
                harness.log(
                    "timeout_occurred",
                    json!({
                        "timeout_ms": timeout_duration.as_millis(),
                        "actual_time_ms": total_time.as_millis(),
                        "work_duration_ms": work_duration.as_millis()
                    }),
                );

                // Validate timeout occurred at the right time
                assert!(
                    total_time >= timeout_duration,
                    "Timeout should occur after timeout duration"
                );
                assert!(
                    total_time < timeout_duration + Duration::from_millis(50),
                    "Timeout should occur promptly"
                );
            }
        }

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "timeout_behavior_correct": result.is_err(),
                "message": "Deadline timeout interaction validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_timer_race_deadline_priority() {
        let harness = Arc::new(TimerTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "timer_race_deadline_priority"}),
        );

        let base_time = Instant::now();

        // Create multiple timer tasks with different deadlines
        let tasks = vec![
            ("fast_task", Duration::from_millis(50)),
            ("medium_task", Duration::from_millis(100)),
            ("slow_task", Duration::from_millis(200)),
        ];

        let winner = race(
            sleep(tasks[0].1).then(|| async { tasks[0].0 }),
            race(
                sleep(tasks[1].1).then(|| async { tasks[1].0 }),
                sleep(tasks[2].1).then(|| async { tasks[2].0 }),
            )
            .then(|result| async move {
                match result {
                    Ok(name) => name,
                    Err(_) => "no_winner",
                }
            }),
        )
        .await;

        let race_time = base_time.elapsed();

        match winner {
            Ok(winning_task) => {
                harness.log(
                    "race_winner",
                    json!({
                        "winner": winning_task,
                        "race_time_ms": race_time.as_millis()
                    }),
                );

                // Should be the fastest task
                assert_eq!(
                    winning_task, "fast_task",
                    "Fastest task should win the race"
                );

                // Race time should be close to fastest task duration
                assert!(
                    race_time >= tasks[0].1,
                    "Race should take at least fast task duration"
                );
                assert!(
                    race_time < tasks[0].1 + Duration::from_millis(20),
                    "Race should complete promptly after fast task"
                );
            }
            Err(_) => {
                panic!("Race should have a winner");
            }
        }

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "fastest_task_won": true,
                "message": "Timer race deadline priority validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_timer_precision_under_load() {
        let harness = Arc::new(TimerTestHarness::new());
        harness.log("test_start", json!({"test": "timer_precision_under_load"}));

        let timer_duration = Duration::from_millis(100);
        let num_concurrent_timers = 20;
        let expected_completion_window = Duration::from_millis(20); // 20ms tolerance

        let start_time = Instant::now();
        let completion_times = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();

        // Create many concurrent timers
        for i in 0..num_concurrent_timers {
            let completion_times = Arc::clone(&completion_times);
            let harness = Arc::clone(&harness);

            let handle = spawn(async move {
                let timer_start = Instant::now();
                sleep(timer_duration).await;
                let completion_time = Instant::now();

                let actual_duration = completion_time.duration_since(timer_start);

                harness.record_timing(TimingRecord {
                    timestamp: completion_time,
                    event_type: format!("concurrent_timer_{}", i),
                    deadline: Some(timer_start + timer_duration),
                    interval_seq: None,
                    actual_delay: actual_duration,
                    expected_delay: timer_duration,
                    skipped: false,
                });

                completion_times
                    .lock()
                    .unwrap()
                    .push((i, completion_time, actual_duration));
            });

            handles.push(handle);
        }

        // Wait for all timers to complete
        for handle in handles {
            handle.await;
        }

        let completions = completion_times.lock().unwrap();
        let mut durations: Vec<Duration> = completions
            .iter()
            .map(|(_, _, duration)| *duration)
            .collect();
        durations.sort();

        // Calculate statistics
        let min_duration = durations.first().unwrap();
        let max_duration = durations.last().unwrap();
        let median_duration = durations[durations.len() / 2];
        let duration_spread = max_duration.saturating_sub(*min_duration);

        harness.log(
            "timer_precision_stats",
            json!({
                "num_timers": num_concurrent_timers,
                "target_duration_ms": timer_duration.as_millis(),
                "min_duration_ms": min_duration.as_millis(),
                "max_duration_ms": max_duration.as_millis(),
                "median_duration_ms": median_duration.as_millis(),
                "duration_spread_ms": duration_spread.as_millis(),
                "expected_window_ms": expected_completion_window.as_millis()
            }),
        );

        // Validate timer precision
        assert!(
            duration_spread <= expected_completion_window,
            "Timer precision under load failed: spread {}ms > expected {}ms",
            duration_spread.as_millis(),
            expected_completion_window.as_millis()
        );

        // All timers should complete close to target duration
        for (_, actual_duration) in durations.iter().enumerate() {
            let deviation = actual_duration
                .as_millis()
                .abs_diff(timer_duration.as_millis());
            assert!(
                deviation <= expected_completion_window.as_millis(),
                "Timer {} deviated by {}ms from target {}ms",
                actual_duration.as_millis(),
                deviation,
                timer_duration.as_millis()
            );
        }

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "precision_maintained": duration_spread <= expected_completion_window,
                "message": "Timer precision under load validated successfully"
            }),
        );
    }
}
