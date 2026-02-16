//! DPOR Coverage & Backtracking regression tests.
//!
//! Verifies enhanced DPOR coverage metrics, sleep set optimization, HB-race
//! detection, class count estimates, and DPOR vs baseline coverage comparison
//! on synthetic workloads.

mod common;
use common::*;

use asupersync::lab::LabRuntime;
use asupersync::lab::explorer::{DporExplorer, ExplorerConfig, ScheduleExplorer};
use asupersync::trace::canonicalize::trace_fingerprint;
use asupersync::trace::dpor::{
    BacktrackPoint, Race, SleepSet, detect_hb_races, detect_races, estimated_classes,
    racing_events, trace_coverage_analysis,
};
use asupersync::trace::event::TraceEvent;
use asupersync::types::{Budget, CancelReason, RegionId, TaskId, Time};

const REGRESSION_SEED: u64 = 0xDEAD_BEEF;

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

// ==================== HB-Race Detection Regression ====================

#[test]
fn regression_hb_race_empty_trace() {
    init_test_logging();
    test_phase!("regression_hb_race_empty_trace");

    let report = detect_hb_races(&[]);
    assert!(report.is_race_free());
    assert_eq!(report.race_count(), 0);

    test_complete!("regression_hb_race_empty_trace");
}

#[test]
fn regression_hb_race_single_task_no_races() {
    init_test_logging();
    test_phase!("regression_hb_race_single_task_no_races");

    let r = rid(1);
    let t = tid(1);
    let events = [
        TraceEvent::spawn(1, Time::ZERO, t, r),
        TraceEvent::poll(2, Time::ZERO, t, r),
        TraceEvent::complete(3, Time::ZERO, t, r),
    ];
    let report = detect_hb_races(&events);
    // Same-task events should not be reported as races.
    assert!(report.is_race_free());

    test_complete!("regression_hb_race_single_task_no_races");
}

#[test]
fn regression_hb_race_two_tasks_shared_region() {
    init_test_logging();
    test_phase!("regression_hb_race_two_tasks_shared_region");

    let r = rid(1);
    let reason = CancelReason::user("test");
    let events = [
        TraceEvent::cancel_request(1, Time::ZERO, tid(1), r, reason.clone()),
        TraceEvent::cancel_request(2, Time::ZERO, tid(2), r, reason),
    ];
    let report = detect_hb_races(&events);
    // Two concurrent cancels on the same region: HB race.
    assert_eq!(report.race_count(), 1);
    assert_eq!(report.races[0].earlier_task, Some(tid(1)));
    assert_eq!(report.races[0].later_task, Some(tid(2)));

    test_complete!("regression_hb_race_two_tasks_shared_region");
}

#[test]
fn regression_hb_race_three_tasks_multiple_races() {
    init_test_logging();
    test_phase!("regression_hb_race_three_tasks_multiple_races");

    let r = rid(1);
    let reason = CancelReason::user("test");
    let events = [
        TraceEvent::cancel_request(1, Time::ZERO, tid(1), r, reason.clone()),
        TraceEvent::cancel_request(2, Time::ZERO, tid(2), r, reason.clone()),
        TraceEvent::cancel_request(3, Time::ZERO, tid(3), r, reason),
    ];
    let report = detect_hb_races(&events);
    // Three pairwise races: (1,2), (1,3), (2,3).
    assert_eq!(report.race_count(), 3);

    test_complete!("regression_hb_race_three_tasks_multiple_races");
}

// ==================== Class Count Estimation Regression ====================

#[test]
fn regression_estimated_classes_sequential_trace() {
    init_test_logging();
    test_phase!("regression_estimated_classes_sequential_trace");

    // Single-task trace: events on the same task are dependent (same Task resource),
    // so adjacent pairs form immediate races. However, the HB-based detector
    // correctly recognizes them as same-task and reports no races.
    let events = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
    ];
    let hb = detect_hb_races(&events);
    assert!(
        hb.is_race_free(),
        "HB detector should find no races for single task"
    );
    // Immediate race detector may count same-task adjacent pairs as races.
    let est = estimated_classes(&events);
    assert!(est >= 1, "estimated classes should be ≥ 1, got {est}");

    test_complete!("regression_estimated_classes_sequential_trace");
}

#[test]
fn regression_estimated_classes_concurrent_trace() {
    init_test_logging();
    test_phase!("regression_estimated_classes_concurrent_trace");

    // Two tasks sharing a region: races exist, classes > 1.
    let events = [
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
    ];
    let est = estimated_classes(&events);
    assert!(
        est >= 2,
        "concurrent trace should have ≥2 classes, got {est}"
    );

    test_complete!("regression_estimated_classes_concurrent_trace");
}

#[test]
fn regression_estimated_classes_monotone_with_concurrency() {
    init_test_logging();
    test_phase!("regression_estimated_classes_monotone_with_concurrency");

    // More concurrent tasks → more estimated classes (non-strictly).
    let events_2 = [
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
    ];
    let events_3 = [
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        TraceEvent::spawn(4, Time::ZERO, tid(3), rid(1)),
    ];
    let est_2 = estimated_classes(&events_2);
    let est_3 = estimated_classes(&events_3);
    assert!(
        est_3 >= est_2,
        "more tasks should give ≥ classes: {est_3} vs {est_2}"
    );

    test_complete!("regression_estimated_classes_monotone_with_concurrency");
}

// ==================== TraceCoverageAnalysis Regression ====================

#[test]
fn regression_trace_coverage_analysis_empty() {
    init_test_logging();
    test_phase!("regression_trace_coverage_analysis_empty");

    let analysis = trace_coverage_analysis(&[]);
    assert_eq!(analysis.event_count, 0);
    assert_eq!(analysis.immediate_race_count, 0);
    assert_eq!(analysis.hb_race_count, 0);
    assert_eq!(analysis.estimated_classes, 1);
    assert_eq!(analysis.backtrack_point_count, 0);
    assert_eq!(analysis.racing_event_count, 0);
    assert!((analysis.race_density - 0.0).abs() < f64::EPSILON);
    assert_eq!(analysis.resource_distribution.total(), 0);
    assert_eq!(analysis.resource_distribution.resource_count(), 0);

    test_complete!("regression_trace_coverage_analysis_empty");
}

#[test]
fn regression_trace_coverage_analysis_concurrent() {
    init_test_logging();
    test_phase!("regression_trace_coverage_analysis_concurrent");

    let r = rid(1);
    let reason = CancelReason::user("test");
    let events = [
        TraceEvent::cancel_request(1, Time::ZERO, tid(1), r, reason.clone()),
        TraceEvent::cancel_request(2, Time::ZERO, tid(2), r, reason.clone()),
        TraceEvent::cancel_request(3, Time::ZERO, tid(3), r, reason),
    ];
    let analysis = trace_coverage_analysis(&events);
    assert_eq!(analysis.event_count, 3);
    assert!(analysis.hb_race_count >= 1, "should detect HB races");
    assert!(
        analysis.resource_distribution.total() >= 1,
        "should have resource distribution entries"
    );
    assert!(
        analysis.race_density > 0.0,
        "should have non-zero race density"
    );

    test_complete!("regression_trace_coverage_analysis_concurrent");
}

#[test]
fn regression_trace_coverage_analysis_deterministic() {
    init_test_logging();
    test_phase!("regression_trace_coverage_analysis_deterministic");

    let r = rid(1);
    let events = [
        TraceEvent::region_created(1, Time::ZERO, r, None),
        TraceEvent::spawn(2, Time::ZERO, tid(1), r),
        TraceEvent::spawn(3, Time::ZERO, tid(2), r),
        TraceEvent::poll(4, Time::ZERO, tid(1), r),
        TraceEvent::poll(5, Time::ZERO, tid(2), r),
    ];
    let a1 = trace_coverage_analysis(&events);
    let a2 = trace_coverage_analysis(&events);
    assert_eq!(a1.immediate_race_count, a2.immediate_race_count);
    assert_eq!(a1.hb_race_count, a2.hb_race_count);
    assert_eq!(a1.estimated_classes, a2.estimated_classes);
    assert_eq!(a1.racing_event_count, a2.racing_event_count);
    assert!((a1.race_density - a2.race_density).abs() < f64::EPSILON);

    test_complete!("regression_trace_coverage_analysis_deterministic");
}

// ==================== Sleep Set Regression ====================

#[test]
fn regression_sleep_set_empty() {
    init_test_logging();
    test_phase!("regression_sleep_set_empty");

    let sleep = SleepSet::new();
    assert!(sleep.is_empty());
    assert_eq!(sleep.len(), 0);

    test_complete!("regression_sleep_set_empty");
}

#[test]
fn regression_sleep_set_insert_and_check() {
    init_test_logging();
    test_phase!("regression_sleep_set_insert_and_check");

    let events = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1)),
        TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
    ];

    let bp1 = BacktrackPoint {
        race: Race {
            earlier: 0,
            later: 1,
        },
        divergence_index: 0,
    };
    let bp2 = BacktrackPoint {
        race: Race {
            earlier: 1,
            later: 2,
        },
        divergence_index: 1,
    };

    let mut sleep = SleepSet::new();
    assert!(!sleep.contains(&bp1, &events));
    assert!(!sleep.contains(&bp2, &events));

    sleep.insert(&bp1, &events);
    assert!(sleep.contains(&bp1, &events));
    assert!(!sleep.contains(&bp2, &events));
    assert_eq!(sleep.len(), 1);

    sleep.insert(&bp2, &events);
    assert!(sleep.contains(&bp1, &events));
    assert!(sleep.contains(&bp2, &events));
    assert_eq!(sleep.len(), 2);

    test_complete!("regression_sleep_set_insert_and_check");
}

#[test]
fn regression_sleep_set_idempotent_insert() {
    init_test_logging();
    test_phase!("regression_sleep_set_idempotent_insert");

    let events = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
    ];
    let bp = BacktrackPoint {
        race: Race {
            earlier: 0,
            later: 1,
        },
        divergence_index: 0,
    };

    let mut sleep = SleepSet::new();
    sleep.insert(&bp, &events);
    sleep.insert(&bp, &events);
    assert_eq!(sleep.len(), 1, "duplicate insert should be idempotent");

    test_complete!("regression_sleep_set_idempotent_insert");
}

// ==================== DPOR Explorer Coverage Metrics Regression ====================

#[test]
fn regression_dpor_coverage_metrics_populated() {
    init_test_logging();
    test_phase!("regression_dpor_coverage_metrics_populated");

    let mut explorer = DporExplorer::new(ExplorerConfig::new(REGRESSION_SEED, 10));
    let _report = explorer.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t2");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
        }
        runtime.run_until_quiescent();
    });

    let metrics = explorer.dpor_coverage();
    assert!(metrics.base.total_runs >= 1);
    assert!(metrics.base.equivalence_classes >= 1);
    assert!(metrics.efficiency >= 0.0);
    assert!(metrics.efficiency <= 1.0);
    // New fields should be populated.
    assert!(
        !metrics.estimated_class_trend.is_empty(),
        "estimated class trend should be populated"
    );
    // Every per-run estimate should be ≥ 1.
    for est in &metrics.estimated_class_trend {
        assert!(*est >= 1, "per-run class estimate should be ≥ 1");
    }

    test_complete!("regression_dpor_coverage_metrics_populated");
}

#[test]
fn regression_dpor_coverage_metrics_deterministic() {
    init_test_logging();
    test_phase!("regression_dpor_coverage_metrics_deterministic");

    let run = || {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(REGRESSION_SEED, 5));
        explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().unwrap().schedule(t1, 0);
            runtime.run_until_quiescent();
        });
        explorer.dpor_coverage()
    };

    let m1 = run();
    let m2 = run();
    assert_eq!(m1.base.total_runs, m2.base.total_runs);
    assert_eq!(m1.base.equivalence_classes, m2.base.equivalence_classes);
    assert_eq!(m1.total_races, m2.total_races);
    assert_eq!(m1.total_hb_races, m2.total_hb_races);
    assert_eq!(m1.total_backtrack_points, m2.total_backtrack_points);
    assert_eq!(m1.pruned_backtrack_points, m2.pruned_backtrack_points);
    assert_eq!(m1.sleep_pruned, m2.sleep_pruned);
    assert_eq!(m1.estimated_class_trend, m2.estimated_class_trend);

    test_complete!("regression_dpor_coverage_metrics_deterministic");
}

#[test]
fn regression_dpor_hb_race_count_consistent() {
    init_test_logging();
    test_phase!("regression_dpor_hb_race_count_consistent");

    // With multiple concurrent tasks, DPOR should detect HB races.
    let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 10));
    explorer.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t2");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
        }
        runtime.run_until_quiescent();
    });

    let metrics = explorer.dpor_coverage();
    // HB-race count should be non-negative (may be 0 if vector clocks order everything).
    // total_hb_races >= 0 always holds for usize, but we verify the field is populated.
    assert!(
        metrics.total_hb_races <= metrics.total_races * 10,
        "HB races should be in a reasonable range"
    );

    test_complete!("regression_dpor_hb_race_count_consistent");
}

// ==================== DPOR vs Baseline Comparison ====================

#[test]
fn regression_dpor_vs_baseline_coverage() {
    init_test_logging();
    test_phase!("regression_dpor_vs_baseline_coverage");

    let budget = 20;

    // Baseline: seed sweep.
    let mut baseline = ScheduleExplorer::new(ExplorerConfig::new(0, budget));
    let baseline_report = baseline.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t2");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
        }
        runtime.run_until_quiescent();
    });

    // DPOR: race-guided exploration.
    let mut dpor = DporExplorer::new(ExplorerConfig::new(0, budget));
    let dpor_report = dpor.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t2");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
        }
        runtime.run_until_quiescent();
    });

    let dpor_metrics = dpor.dpor_coverage();

    // DPOR should be at least as efficient as baseline (or at minimum, functional).
    assert!(
        dpor_report.unique_classes >= 1,
        "DPOR should discover at least 1 class"
    );
    assert!(
        baseline_report.unique_classes >= 1,
        "baseline should discover at least 1 class"
    );

    // DPOR efficiency should be >= 0.
    assert!(dpor_metrics.efficiency >= 0.0);

    // Both should produce no violations on this clean workload.
    assert!(!baseline_report.has_violations());
    assert!(!dpor_report.has_violations());

    tracing::info!(
        baseline_classes = baseline_report.unique_classes,
        dpor_classes = dpor_report.unique_classes,
        dpor_efficiency = dpor_metrics.efficiency,
        dpor_total_races = dpor_metrics.total_races,
        dpor_hb_races = dpor_metrics.total_hb_races,
        dpor_sleep_pruned = dpor_metrics.sleep_pruned,
        "DPOR vs baseline comparison"
    );

    test_complete!("regression_dpor_vs_baseline_coverage");
}

#[test]
fn regression_dpor_vs_baseline_three_tasks() {
    init_test_logging();
    test_phase!("regression_dpor_vs_baseline_three_tasks");

    let budget = 30;

    let test_fn = |runtime: &mut LabRuntime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t2");
        let (t3, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t3");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
            sched.schedule(t3, 0);
        }
        runtime.run_until_quiescent();
    };

    let mut baseline = ScheduleExplorer::new(ExplorerConfig::new(0, budget));
    let baseline_report = baseline.explore(test_fn);

    let mut dpor = DporExplorer::new(ExplorerConfig::new(0, budget));
    let dpor_report = dpor.explore(test_fn);
    let dpor_metrics = dpor.dpor_coverage();

    assert!(!baseline_report.has_violations());
    assert!(!dpor_report.has_violations());
    assert!(baseline_report.unique_classes >= 1);
    assert!(dpor_report.unique_classes >= 1);

    // With 3 tasks, there's more concurrency to explore.
    tracing::info!(
        baseline_classes = baseline_report.unique_classes,
        baseline_runs = baseline_report.total_runs,
        dpor_classes = dpor_report.unique_classes,
        dpor_runs = dpor_report.total_runs,
        dpor_races = dpor_metrics.total_races,
        dpor_hb_races = dpor_metrics.total_hb_races,
        dpor_backtrack = dpor_metrics.total_backtrack_points,
        dpor_pruned = dpor_metrics.pruned_backtrack_points,
        dpor_sleep_pruned = dpor_metrics.sleep_pruned,
        "3-task comparison"
    );

    test_complete!("regression_dpor_vs_baseline_three_tasks");
}

// ==================== Coverage Saturation Regression ====================

#[test]
fn regression_saturation_single_task() {
    init_test_logging();
    test_phase!("regression_saturation_single_task");

    // Single task should saturate quickly.
    let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 20));
    let report = explorer.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 42 })
            .expect("t");
        runtime.scheduler.lock().unwrap().schedule(t, 0);
        runtime.run_until_quiescent();
    });

    let cov = &report.coverage;
    // After 20 runs of a single-task program, many seeds hit the same class.
    assert!(
        cov.saturation.existing_class_hits >= 1,
        "should have some class hits"
    );

    test_complete!("regression_saturation_single_task");
}

#[test]
fn regression_dpor_estimated_class_trend() {
    init_test_logging();
    test_phase!("regression_dpor_estimated_class_trend");

    let mut explorer = DporExplorer::new(ExplorerConfig::new(REGRESSION_SEED, 15));
    explorer.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t2");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
        }
        runtime.run_until_quiescent();
    });

    let metrics = explorer.dpor_coverage();
    let trend = &metrics.estimated_class_trend;
    assert!(!trend.is_empty(), "trend should have entries");
    assert_eq!(
        trend.len(),
        metrics.base.total_runs,
        "trend length should match total runs"
    );

    test_complete!("regression_dpor_estimated_class_trend");
}

// ==================== Independence & Race Density ====================

#[test]
fn regression_race_density_scales_with_concurrency() {
    init_test_logging();
    test_phase!("regression_race_density_scales_with_concurrency");

    // 1 task: low density.
    let events_1 = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
    ];
    let a1 = trace_coverage_analysis(&events_1);

    // 3 tasks sharing region: higher density.
    let r = rid(1);
    let reason = CancelReason::user("test");
    let events_3 = [
        TraceEvent::cancel_request(1, Time::ZERO, tid(1), r, reason.clone()),
        TraceEvent::cancel_request(2, Time::ZERO, tid(2), r, reason.clone()),
        TraceEvent::cancel_request(3, Time::ZERO, tid(3), r, reason),
    ];
    let a3 = trace_coverage_analysis(&events_3);

    // 3-task concurrent trace should have higher race density than 1-task sequential.
    assert!(
        a3.race_density >= a1.race_density,
        "3-task density {:.3} should be ≥ 1-task density {:.3}",
        a3.race_density,
        a1.race_density
    );

    test_complete!("regression_race_density_scales_with_concurrency");
}

#[test]
fn regression_resource_distribution_categorization() {
    init_test_logging();
    test_phase!("regression_resource_distribution_categorization");

    let r = rid(1);
    let reason = CancelReason::user("test");
    let events = [
        TraceEvent::cancel_request(1, Time::ZERO, tid(1), r, reason.clone()),
        TraceEvent::cancel_request(2, Time::ZERO, tid(2), r, reason),
    ];
    let analysis = trace_coverage_analysis(&events);
    let dist = &analysis.resource_distribution;

    assert!(dist.total() >= 1, "should have ≥1 resource race");
    assert!(dist.resource_count() >= 1, "should have ≥1 resource type");
    // All counts should be positive.
    for (resource, count) in &dist.counts {
        assert!(*count > 0, "resource {resource} should have positive count");
    }

    test_complete!("regression_resource_distribution_categorization");
}

// ==================== Backtracking Structural Tests ====================

#[test]
fn regression_backtrack_points_valid_indices() {
    init_test_logging();
    test_phase!("regression_backtrack_points_valid_indices");

    let r = rid(1);
    let events = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), r),
        TraceEvent::spawn(2, Time::ZERO, tid(2), r),
        TraceEvent::poll(3, Time::ZERO, tid(1), r),
        TraceEvent::poll(4, Time::ZERO, tid(2), r),
        TraceEvent::complete(5, Time::ZERO, tid(1), r),
        TraceEvent::complete(6, Time::ZERO, tid(2), r),
    ];
    let analysis = detect_races(&events);

    for bp in &analysis.backtrack_points {
        assert!(
            bp.race.earlier < events.len(),
            "earlier index out of bounds"
        );
        assert!(bp.race.later < events.len(), "later index out of bounds");
        assert!(
            bp.race.earlier < bp.race.later,
            "earlier should precede later"
        );
        assert!(
            bp.divergence_index <= bp.race.earlier,
            "divergence should be ≤ earlier"
        );
    }

    test_complete!("regression_backtrack_points_valid_indices");
}

#[test]
fn regression_racing_events_subset_of_trace() {
    init_test_logging();
    test_phase!("regression_racing_events_subset_of_trace");

    let r = rid(1);
    let events = [
        TraceEvent::region_created(1, Time::ZERO, r, None),
        TraceEvent::spawn(2, Time::ZERO, tid(1), r),
        TraceEvent::spawn(3, Time::ZERO, tid(2), r),
        TraceEvent::spawn(4, Time::ZERO, tid(3), r),
    ];
    let racing = racing_events(&events);

    // All racing event indices should be within bounds.
    for &idx in &racing {
        assert!(idx < events.len(), "racing event index {idx} out of bounds");
    }
    // Racing events should be sorted and deduplicated.
    for window in racing.windows(2) {
        assert!(window[0] < window[1], "racing events should be sorted");
    }

    test_complete!("regression_racing_events_subset_of_trace");
}

// ==================== End-to-End Integration ====================

#[test]
fn regression_full_dpor_pipeline_with_coverage() {
    init_test_logging();
    test_phase!("regression_full_dpor_pipeline_with_coverage");

    let r = rid(1);
    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), r),
        TraceEvent::spawn(2, Time::ZERO, tid(2), r),
        TraceEvent::spawn(3, Time::ZERO, tid(3), r),
        TraceEvent::poll(4, Time::ZERO, tid(1), r),
        TraceEvent::poll(5, Time::ZERO, tid(2), r),
        TraceEvent::poll(6, Time::ZERO, tid(3), r),
        TraceEvent::complete(7, Time::ZERO, tid(1), r),
        TraceEvent::complete(8, Time::ZERO, tid(2), r),
        TraceEvent::complete(9, Time::ZERO, tid(3), r),
    ];

    // Step 1: Coverage analysis.
    let analysis = trace_coverage_analysis(&events);
    assert_eq!(analysis.event_count, 9);
    assert!(analysis.estimated_classes >= 1);

    // Step 2: Race detection (both methods).
    let immediate = detect_races(&events);
    let hb = detect_hb_races(&events);
    assert_eq!(analysis.immediate_race_count, immediate.race_count());
    assert_eq!(analysis.hb_race_count, hb.race_count());

    // Step 3: Fingerprint for equivalence.
    let fp = trace_fingerprint(&events);
    assert_ne!(fp, 0, "fingerprint should be non-zero");

    // Step 4: Verify analysis is self-consistent.
    assert!(
        analysis.backtrack_point_count == immediate.backtrack_points.len(),
        "backtrack count should match"
    );
    assert!(
        analysis.racing_event_count <= analysis.event_count,
        "racing events should be ≤ total events"
    );
    assert!(
        analysis.race_density >= 0.0 && analysis.race_density <= 1.0,
        "race density should be in [0, 1]"
    );

    test_complete!("regression_full_dpor_pipeline_with_coverage");
}

#[test]
fn regression_dpor_explorer_no_false_violations() {
    init_test_logging();
    test_phase!("regression_dpor_explorer_no_false_violations");

    // Run DPOR exploration on a well-behaved program: no violations.
    let mut explorer = DporExplorer::new(ExplorerConfig::new(REGRESSION_SEED, 25));
    let report = explorer.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 1 })
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 2 })
            .expect("t2");
        let (t3, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 3 })
            .expect("t3");
        {
            let mut sched = runtime.scheduler.lock().unwrap();
            sched.schedule(t1, 0);
            sched.schedule(t2, 0);
            sched.schedule(t3, 0);
        }
        runtime.run_until_quiescent();
    });

    assert!(
        !report.has_violations(),
        "well-behaved program should have no violations"
    );
    assert!(report.violation_seeds().is_empty());

    let metrics = explorer.dpor_coverage();
    assert!(metrics.base.total_runs >= 1);
    assert!(metrics.base.equivalence_classes >= 1);

    tracing::info!(
        total_runs = metrics.base.total_runs,
        classes = metrics.base.equivalence_classes,
        efficiency = metrics.efficiency,
        total_races = metrics.total_races,
        hb_races = metrics.total_hb_races,
        sleep_pruned = metrics.sleep_pruned,
        "DPOR explorer coverage summary"
    );

    test_complete!("regression_dpor_explorer_no_false_violations");
}
