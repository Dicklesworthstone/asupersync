//! Metamorphic tests for deadline monitoring behavior.
//!
//! This module tests metamorphic properties of the deadline monitor:
//!
//! 1. **Time Scaling Invariance**: Scaling all time values uniformly preserves relative behavior
//! 2. **Threshold Proportionality**: Warning thresholds scale proportionally with task duration
//! 3. **Progress Monotonicity**: More recent progress should not increase warning urgency
//! 4. **History Order Independence**: Duration percentiles are order-independent
//! 5. **Configuration Consistency**: Adaptive vs fixed thresholds should be logically consistent

use super::deadline_monitor::{
    AdaptiveDeadlineConfig, DeadlineMonitor, DeadlineTaskSnapshot, MonitorConfig, WarningReason,
};
use crate::types::{RegionId, TaskId, Time};
use crate::util::ArenaIndex;
use std::sync::Arc;
use std::time::Duration;

/// Test fixture for creating consistent deadline monitoring scenarios.
struct DeadlineMonitorFixture {
    monitor: DeadlineMonitor,
    warnings: Arc<std::sync::Mutex<Vec<super::deadline_monitor::DeadlineWarning>>>,
}

impl DeadlineMonitorFixture {
    fn new(config: MonitorConfig) -> Self {
        let mut monitor = DeadlineMonitor::new(config);

        let warnings = Arc::new(std::sync::Mutex::new(Vec::new()));
        let warnings_capture = Arc::clone(&warnings);
        monitor.on_warning(move |warning| {
            warnings_capture
                .lock()
                .expect("warning capture mutex should not be poisoned")
                .push(warning);
        });

        Self { monitor, warnings }
    }

    fn create_task_snapshot(
        task_id: TaskId,
        region_id: RegionId,
        created_at: Time,
        deadline: Option<Time>,
        last_checkpoint: Option<Time>,
        checkpoint_count: u64,
    ) -> DeadlineTaskSnapshot {
        DeadlineTaskSnapshot::new_for_test(
            task_id,
            region_id,
            false,
            created_at,
            deadline,
            last_checkpoint,
            Some("test checkpoint".to_string()),
            checkpoint_count,
            Some("test".to_string()),
        )
    }

    fn get_warnings(&self) -> Vec<super::deadline_monitor::DeadlineWarning> {
        self.warnings
            .lock()
            .expect("warnings mutex should not be poisoned for get_warnings")
            .clone()
    }

    fn clear_warnings(&self) {
        self.warnings
            .lock()
            .expect("warnings mutex should not be poisoned for clear_warnings")
            .clear();
    }
}

/// Metamorphic Relation 1: Time Scaling Invariance
///
/// If we scale all time values (now, deadlines, checkpoints, intervals) by the same factor,
/// the warning behavior should be equivalent when considering the scaled timeline.
#[test]
fn time_scaling_invariance() {
    let base_config = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(5),
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };

    // Test scenario: Task approaching deadline
    let mut base_fixture = DeadlineMonitorFixture::new(base_config.clone());
    let mut scaled_fixture = DeadlineMonitorFixture::new(base_config);

    let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
    let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

    // Base timeline (nanoseconds)
    let base_created = Time::from_nanos(1_000_000_000); // 1 second
    let base_deadline = Time::from_nanos(5_000_000_000); // 5 seconds
    let base_now = Time::from_nanos(4_500_000_000); // 4.5 seconds (approaching deadline)
    let base_checkpoint = Time::from_nanos(3_000_000_000); // 3 seconds

    // Scaled timeline (2x scaling factor)
    let scale_factor = 2;
    let scaled_created = Time::from_nanos(base_created.as_nanos() * scale_factor);
    let scaled_deadline = Time::from_nanos(base_deadline.as_nanos() * scale_factor);
    let scaled_now = Time::from_nanos(base_now.as_nanos() * scale_factor);
    let scaled_checkpoint = Time::from_nanos(base_checkpoint.as_nanos() * scale_factor);

    // Run base scenario
    let base_task = DeadlineMonitorFixture::create_task_snapshot(
        task_id,
        region_id,
        base_created,
        Some(base_deadline),
        Some(base_checkpoint),
        1,
    );
    base_fixture.monitor.check_snapshots(base_now, [base_task]);
    let base_warnings = base_fixture.get_warnings();

    // Run scaled scenario
    let scaled_task = DeadlineMonitorFixture::create_task_snapshot(
        task_id,
        region_id,
        scaled_created,
        Some(scaled_deadline),
        Some(scaled_checkpoint),
        1,
    );
    scaled_fixture
        .monitor
        .check_snapshots(scaled_now, [scaled_task]);
    let scaled_warnings = scaled_fixture.get_warnings();

    // Metamorphic relation: Both should produce the same warning behavior
    assert_eq!(
        base_warnings.len(),
        scaled_warnings.len(),
        "Time scaling should preserve warning count"
    );

    if let (Some(base_warning), Some(scaled_warning)) =
        (base_warnings.first(), scaled_warnings.first())
    {
        assert_eq!(
            base_warning.reason, scaled_warning.reason,
            "Time scaling should preserve warning reason"
        );

        // Remaining time should scale proportionally
        let base_remaining_nanos = base_warning.remaining.as_nanos() as u64;
        let scaled_remaining_nanos = scaled_warning.remaining.as_nanos() as u64;
        let ratio = scaled_remaining_nanos as f64 / base_remaining_nanos as f64;

        assert!(
            (ratio - scale_factor as f64).abs() < 0.1,
            "Remaining time should scale by factor {}, got ratio {}",
            scale_factor,
            ratio
        );
    }
}

/// Metamorphic Relation 2: Threshold Proportionality
///
/// Warning thresholds should scale proportionally with task duration.
/// A task with 2x the duration should have 2x the absolute threshold at the same fraction.
#[test]
fn threshold_proportionality() {
    let config = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.2, // 20% threshold
        checkpoint_timeout: Duration::from_secs(10),
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };

    let mut fixture1 = DeadlineMonitorFixture::new(config.clone());
    let mut fixture2 = DeadlineMonitorFixture::new(config);

    let task_id1 = TaskId::from_arena(ArenaIndex::new(1, 0));
    let task_id2 = TaskId::from_arena(ArenaIndex::new(2, 0));
    let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

    // Task 1: 10 second duration
    let created1 = Time::from_nanos(0);
    let deadline1 = Time::from_nanos(10_000_000_000); // 10 seconds
    let warning_time1 = Time::from_nanos(8_000_000_000); // 8 seconds (80% elapsed, should warn)
    let checkpoint1 = Time::from_nanos(7_500_000_000); // Recent progress isolates deadline threshold

    // Task 2: 20 second duration (2x longer)
    let created2 = Time::from_nanos(0);
    let deadline2 = Time::from_nanos(20_000_000_000); // 20 seconds
    let warning_time2 = Time::from_nanos(16_000_000_000); // 16 seconds (80% elapsed, should warn)
    let checkpoint2 = Time::from_nanos(15_000_000_000); // Recent progress isolates deadline threshold

    let task1 = DeadlineMonitorFixture::create_task_snapshot(
        task_id1,
        region_id,
        created1,
        Some(deadline1),
        Some(checkpoint1),
        1,
    );

    let task2 = DeadlineMonitorFixture::create_task_snapshot(
        task_id2,
        region_id,
        created2,
        Some(deadline2),
        Some(checkpoint2),
        1,
    );

    // Both tasks should warn at their respective 80% marks
    fixture1.monitor.check_snapshots(warning_time1, [task1]);
    fixture2.monitor.check_snapshots(warning_time2, [task2]);

    let warnings1 = fixture1.get_warnings();
    let warnings2 = fixture2.get_warnings();

    // Metamorphic relation: Both should warn (proportional thresholds)
    assert_eq!(warnings1.len(), 1, "Task 1 should warn at 80% elapsed");
    assert_eq!(warnings2.len(), 1, "Task 2 should warn at 80% elapsed");
    assert_eq!(
        warnings1[0].reason, warnings2[0].reason,
        "Warning reasons should match"
    );

    // Remaining time should be proportional
    let remaining1 = warnings1[0].remaining.as_nanos() as u64;
    let remaining2 = warnings2[0].remaining.as_nanos() as u64;
    let ratio = remaining2 as f64 / remaining1 as f64;

    assert!(
        (ratio - 2.0).abs() < 0.1,
        "Remaining time should be 2x for 2x longer task, got ratio {}",
        ratio
    );
}

/// Metamorphic Relation 3: Progress Monotonicity
///
/// More recent checkpoint progress should not increase warning urgency.
/// If checkpoints advance, warnings should become less urgent, not more.
#[test]
fn progress_monotonicity() {
    let config = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(3),
        adaptive: AdaptiveDeadlineConfig::default(),
        enabled: true,
    };

    let mut fixture = DeadlineMonitorFixture::new(config);
    let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
    let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

    let created = Time::from_nanos(0);
    let deadline = Time::from_nanos(10_000_000_000); // 10 seconds
    let check_time = Time::from_nanos(8_000_000_000); // 8 seconds

    // Scenario 1: No recent checkpoint (should warn about no progress)
    let task_no_progress = DeadlineMonitorFixture::create_task_snapshot(
        task_id,
        region_id,
        created,
        Some(deadline),
        Some(Time::from_nanos(1_000_000_000)), // Old checkpoint at 1 second
        1,
    );

    fixture
        .monitor
        .check_snapshots(check_time, [task_no_progress]);
    let warnings_no_progress = fixture.get_warnings();

    fixture.clear_warnings();

    // Scenario 2: Recent checkpoint (should not warn about no progress)
    let task_with_progress = DeadlineMonitorFixture::create_task_snapshot(
        task_id,
        region_id,
        created,
        Some(deadline),
        Some(Time::from_nanos(7_000_000_000)), // Recent checkpoint at 7 seconds
        2,
    );

    fixture
        .monitor
        .check_snapshots(check_time, [task_with_progress]);
    let warnings_with_progress = fixture.get_warnings();

    // Metamorphic relation: Progress should reduce warning severity
    if let Some(_warning_no_progress) = warnings_no_progress.first() {
        if let Some(warning_with_progress) = warnings_with_progress.first() {
            // With progress, should not have NoProgress component in warning
            assert!(
                !matches!(
                    warning_with_progress.reason,
                    WarningReason::NoProgress | WarningReason::ApproachingDeadlineNoProgress
                ),
                "Recent progress should eliminate no-progress warnings"
            );
        } else {
            // Even better - no warning at all with recent progress
            assert!(true, "No warning with recent progress is optimal");
        }
    }

    // At minimum, warnings with progress should be no more severe than without
    assert!(
        warnings_with_progress.len() <= warnings_no_progress.len(),
        "Progress should not increase warning count"
    );
}

/// Metamorphic Relation 4: History Order Independence
///
/// For DurationHistory, the same set of durations should produce the same
/// percentile regardless of insertion order.
#[test]
fn duration_history_order_independence() {
    use super::deadline_monitor::MonitorConfig;

    let config_adaptive = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(5),
        adaptive: AdaptiveDeadlineConfig {
            adaptive_enabled: true,
            warning_percentile: 0.9,
            min_samples: 3,
            max_history: 1000,
            fallback_threshold: Duration::from_secs(30),
        },
        enabled: true,
    };

    let mut monitor1 = DeadlineMonitor::new(config_adaptive.clone());
    let mut monitor2 = DeadlineMonitor::new(config_adaptive.clone());

    let task_id1 = TaskId::from_arena(ArenaIndex::new(1, 0));
    let task_id2 = TaskId::from_arena(ArenaIndex::new(2, 0));

    // Same durations, different insertion orders
    let durations = [
        Duration::from_secs(5),
        Duration::from_secs(2),
        Duration::from_secs(8),
        Duration::from_secs(3),
        Duration::from_secs(7),
    ];

    let base_time = Time::from_nanos(0);

    // Insert in original order
    for &duration in &durations {
        monitor1.record_completion(
            task_id1,
            "test",
            duration,
            Some(base_time + duration),
            base_time + duration,
        );
    }

    // Insert in reverse order
    for &duration in durations.iter().rev() {
        monitor2.record_completion(
            task_id2,
            "test",
            duration,
            Some(base_time + duration),
            base_time + duration,
        );
    }

    // Now test adaptive warning thresholds with same total duration
    let _total_duration = Duration::from_secs(10);

    // Both monitors should have same history and produce same adaptive thresholds
    // We test this indirectly by checking that both produce the same warning behavior

    // Both should now produce equivalent adaptive thresholds
    let task_id_test1 = TaskId::from_arena(ArenaIndex::new(10, 0));
    let task_id_test2 = TaskId::from_arena(ArenaIndex::new(11, 0));
    let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

    let created = Time::from_nanos(0);
    let deadline = Time::from_nanos(10_000_000_000); // 10 seconds
    let now = Time::from_nanos(8_000_000_000); // 8 seconds (80% elapsed)

    let task1 = DeadlineMonitorFixture::create_task_snapshot(
        task_id_test1,
        region_id,
        created,
        Some(deadline),
        Some(created),
        1,
    );

    let task2 = DeadlineMonitorFixture::create_task_snapshot(
        task_id_test2,
        region_id,
        created,
        Some(deadline),
        Some(created),
        1,
    );

    // Create fixtures with existing monitors that have history
    let mut fixture1 = DeadlineMonitorFixture::new(config_adaptive.clone());
    let mut fixture2 = DeadlineMonitorFixture::new(config_adaptive);

    // Replace monitors with our history-loaded ones
    fixture1.monitor = monitor1;
    fixture2.monitor = monitor2;

    fixture1.monitor.check_snapshots(now, [task1]);
    fixture2.monitor.check_snapshots(now, [task2]);

    let warnings1 = fixture1.get_warnings();
    let warnings2 = fixture2.get_warnings();

    // Metamorphic relation: Same warning behavior regardless of history insertion order
    assert_eq!(
        warnings1.len(),
        warnings2.len(),
        "History insertion order should not affect warning count"
    );

    if let (Some(w1), Some(w2)) = (warnings1.first(), warnings2.first()) {
        assert_eq!(
            w1.reason, w2.reason,
            "History insertion order should not affect warning reason"
        );
    }
}

/// Metamorphic Relation 5: Configuration Consistency
///
/// When adaptive thresholding has insufficient history, it should fall back to
/// fixed thresholding and produce consistent results.
#[test]
fn adaptive_fallback_consistency() {
    // Fixed threshold configuration
    let config_fixed = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(5),
        adaptive: AdaptiveDeadlineConfig {
            adaptive_enabled: false,
            ..Default::default()
        },
        enabled: true,
    };

    // Adaptive configuration with insufficient samples (should use fallback)
    let config_adaptive_fallback = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.2,
        checkpoint_timeout: Duration::from_secs(5),
        adaptive: AdaptiveDeadlineConfig {
            adaptive_enabled: true,
            warning_percentile: 0.9,
            min_samples: 100, // Intentionally high to force fallback
            max_history: 1000,
            fallback_threshold: Duration::from_secs(2), // Same as 20% of 10s task
        },
        enabled: true,
    };

    let mut fixture_fixed = DeadlineMonitorFixture::new(config_fixed);
    let mut fixture_adaptive = DeadlineMonitorFixture::new(config_adaptive_fallback);

    let task_id1 = TaskId::from_arena(ArenaIndex::new(1, 0));
    let task_id2 = TaskId::from_arena(ArenaIndex::new(2, 0));
    let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

    let created = Time::from_nanos(0);
    let deadline = Time::from_nanos(10_000_000_000); // 10 seconds
    let now = Time::from_nanos(8_500_000_000); // 8.5 seconds (85% elapsed, should warn)

    let task_fixed = DeadlineMonitorFixture::create_task_snapshot(
        task_id1,
        region_id,
        created,
        Some(deadline),
        Some(created),
        1,
    );

    let task_adaptive = DeadlineMonitorFixture::create_task_snapshot(
        task_id2,
        region_id,
        created,
        Some(deadline),
        Some(created),
        1,
    );

    fixture_fixed.monitor.check_snapshots(now, [task_fixed]);
    fixture_adaptive
        .monitor
        .check_snapshots(now, [task_adaptive]);

    let warnings_fixed = fixture_fixed.get_warnings();
    let warnings_adaptive = fixture_adaptive.get_warnings();

    // Metamorphic relation: Adaptive fallback should behave like fixed threshold
    assert_eq!(
        warnings_fixed.len(),
        warnings_adaptive.len(),
        "Adaptive fallback should match fixed threshold behavior"
    );

    if let (Some(w1), Some(w2)) = (warnings_fixed.first(), warnings_adaptive.first()) {
        assert_eq!(
            w1.reason, w2.reason,
            "Adaptive fallback should produce same warning reason as fixed"
        );

        // Remaining time should be very similar
        let diff = (w1.remaining.as_nanos() as i64 - w2.remaining.as_nanos() as i64).abs();
        assert!(
            diff < 100_000_000, // Within 100ms
            "Adaptive fallback remaining time should match fixed threshold closely"
        );
    }
}

/// Integration test: Multiple metamorphic relations combined
#[test]
fn combined_metamorphic_properties() {
    let config = MonitorConfig {
        check_interval: Duration::from_secs(1),
        warning_threshold_fraction: 0.3,
        checkpoint_timeout: Duration::from_secs(4),
        adaptive: AdaptiveDeadlineConfig {
            adaptive_enabled: true,
            warning_percentile: 0.8,
            min_samples: 5,
            max_history: 100,
            fallback_threshold: Duration::from_secs(15),
        },
        enabled: true,
    };

    let mut fixture = DeadlineMonitorFixture::new(config);

    // Build up history first
    let base_time = Time::from_nanos(0);
    let history_durations = [
        Duration::from_secs(4),
        Duration::from_secs(6),
        Duration::from_secs(5),
        Duration::from_secs(8),
        Duration::from_secs(7),
        Duration::from_secs(9),
    ];

    for (i, &duration) in history_durations.iter().enumerate() {
        fixture.monitor.record_completion(
            TaskId::from_arena(ArenaIndex::new(i as u32, 0)),
            "integration",
            duration,
            Some(base_time + duration),
            base_time + duration,
        );
    }

    // Test with multiple scenarios that combine different metamorphic properties
    let scenarios = [
        // (created, deadline, now, checkpoint, expected_warning)
        (
            Time::from_nanos(0),
            Time::from_nanos(10_000_000_000),
            Time::from_nanos(9_000_000_000),       // 90% elapsed
            Some(Time::from_nanos(8_000_000_000)), // Recent checkpoint
            true,                                  // Should warn (approaching deadline)
        ),
        (
            Time::from_nanos(0),
            Time::from_nanos(20_000_000_000),       // 2x longer task
            Time::from_nanos(18_000_000_000),       // 90% elapsed
            Some(Time::from_nanos(16_000_000_000)), // Recent checkpoint
            true,                                   // Should warn (proportional behavior)
        ),
        (
            Time::from_nanos(0),
            Time::from_nanos(10_000_000_000),
            Time::from_nanos(5_000_000_000),       // 50% elapsed
            Some(Time::from_nanos(4_500_000_000)), // Very recent checkpoint
            false, // Should not warn (not close to deadline, recent progress)
        ),
    ];

    for (i, (created, deadline, now, checkpoint, expected_warning)) in scenarios.iter().enumerate()
    {
        fixture.clear_warnings();

        let task = DeadlineMonitorFixture::create_task_snapshot(
            TaskId::from_arena(ArenaIndex::new((100 + i) as u32, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            *created,
            Some(*deadline),
            *checkpoint,
            1,
        );

        fixture.monitor.check_snapshots(*now, [task]);
        let warnings = fixture.get_warnings();

        if *expected_warning {
            assert!(
                !warnings.is_empty(),
                "Scenario {} should produce warning",
                i
            );
        } else {
            assert!(
                warnings.is_empty(),
                "Scenario {} should not produce warning",
                i
            );
        }
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Property-based test for time scaling invariance
    proptest! {
        #[test]
        fn property_time_scaling_invariance(
            scale_factor in 2u64..100u64,
            base_deadline_secs in 5u64..3600u64,
            progress_fraction in 0.1f64..0.9f64,
        ) {
            let config = MonitorConfig::default();
            let mut fixture1 = DeadlineMonitorFixture::new(config.clone());
            let mut fixture2 = DeadlineMonitorFixture::new(config);

            let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
            let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

            // Base scenario
            let base_created = Time::from_nanos(0);
            let base_deadline = Time::from_nanos(base_deadline_secs * 1_000_000_000);
            let base_now = Time::from_nanos((base_deadline_secs as f64 * progress_fraction) as u64 * 1_000_000_000);

            // Scaled scenario
            let scaled_created = Time::from_nanos(0);
            let scaled_deadline = Time::from_nanos(base_deadline_secs * scale_factor * 1_000_000_000);
            let scaled_now = Time::from_nanos(
                ((base_deadline_secs * scale_factor) as f64
                    * progress_fraction
                    * 1_000_000_000.0) as u64,
            );

            let task1 = DeadlineMonitorFixture::create_task_snapshot(
                task_id, region_id, base_created, Some(base_deadline), Some(base_now), 1
            );
            let task2 = DeadlineMonitorFixture::create_task_snapshot(
                task_id, region_id, scaled_created, Some(scaled_deadline), Some(scaled_now), 1
            );

            fixture1.monitor.check_snapshots(base_now, [task1]);
            fixture2.monitor.check_snapshots(scaled_now, [task2]);

            let warnings1 = fixture1.get_warnings();
            let warnings2 = fixture2.get_warnings();

            // Time scaling should preserve warning behavior
            prop_assert_eq!(warnings1.len(), warnings2.len());

            if let (Some(w1), Some(w2)) = (warnings1.first(), warnings2.first()) {
                prop_assert_eq!(w1.reason, w2.reason);
            }
        }
    }
}
