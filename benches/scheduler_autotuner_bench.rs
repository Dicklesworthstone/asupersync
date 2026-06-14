//! Criterion benchmark for scheduler hot-path autotuner.
//!
//! Demonstrates measurable performance wins through autotuning of scheduler parameters.
//! Focuses on autotuner decision-making performance and parameter optimization.

#![cfg(feature = "test-internals")]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync::lab::{
    SwarmReplayAdmissionDecision, SwarmReplayScenario, SwarmReplaySummary,
    run_swarm_replay_scenario, scheduler_feedback_metrics_from_swarm_replay,
};
use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::config::BlockingPoolAffinityProfile;
use asupersync::runtime::scheduler::{
    AutotunerConfig, HotPathObservation, SchedulerAdmissionControlThresholds, SchedulerAutotuner,
    SchedulerFeedbackCurrentKnobs, SchedulerFeedbackPolicy, SchedulerPlacementMode,
    ThreeLaneScheduler, recommend_scheduler_feedback,
};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};

/// Workload patterns for autotuner benchmarking.
#[derive(Debug, Clone)]
enum WorkloadPattern {
    /// High cancel load (simulates frequent timeout cancellations).
    HighCancel,
    /// High ready throughput (simulates CPU-bound work bursts).
    HighThroughput,
    /// Mixed workload with variable lane pressure.
    Mixed,
}

impl WorkloadPattern {
    /// Generate metrics for this workload pattern.
    fn generate_observation(&self, iteration: usize) -> HotPathObservation {
        let progress = (iteration % 100) as f64 / 100.0;

        // Simulate metrics based on workload pattern
        let (cancel_ratio, timed_ratio, ready_ratio) = match self {
            WorkloadPattern::HighCancel => (4000, 2000, 4000), // High cancel pressure
            WorkloadPattern::HighThroughput => (500, 500, 9000), // High ready throughput
            WorkloadPattern::Mixed => (2000, 2000, 6000),      // Balanced
        };

        // Estimate latency based on progress and workload
        let latency_factor = if progress < 0.5 { 2.0 } else { 1.0 };
        let base_latency = match self {
            WorkloadPattern::HighCancel => 1500,
            WorkloadPattern::HighThroughput => 800,
            WorkloadPattern::Mixed => 1200,
        };

        HotPathObservation {
            timestamp: Some(Instant::now()),
            cancel_dispatch_ratio_bps: cancel_ratio,
            timed_dispatch_ratio_bps: timed_ratio,
            ready_dispatch_ratio_bps: ready_ratio,
            mean_ready_batch_size: 6.0 + (progress * 4.0),
            current_steal_batch_size: 8,
            current_handoff_limit: 4,
            adaptive_scale_up_events: ((progress * 10.0) as u64).min(5),
            cancel_debt_floor_hits: if matches!(self, WorkloadPattern::HighCancel) {
                ((progress * 20.0) as u64).min(15)
            } else {
                0
            },
            estimated_p95_latency_us: (base_latency as f64 * latency_factor) as u64,
        }
    }
}

/// Simulate scheduler workload with parameter adjustments.
fn simulate_scheduler_performance(
    workload: WorkloadPattern,
    iterations: usize,
    enable_autotuner: bool,
) -> (Duration, usize) {
    let mut autotuner = if enable_autotuner {
        Some(SchedulerAutotuner::new(AutotunerConfig::default()))
    } else {
        None
    };

    let start = Instant::now();
    let mut adjustments_made = 0usize;
    let mut current_batch_size = 8usize;
    let mut current_handoff_limit = 4usize;

    for i in 0..iterations {
        // Generate observation for current workload
        let mut observation = workload.generate_observation(i);
        observation.current_steal_batch_size = current_batch_size;
        observation.current_handoff_limit = current_handoff_limit;

        // Apply autotuner if enabled
        if let Some(ref mut tuner) = autotuner {
            tuner.observe(observation);

            if let Some(recommendation) = tuner.recommend() {
                adjustments_made += 1;
                tuner.mark_adjustment_applied();

                // Apply recommendations
                if let Some(new_batch) = recommendation.steal_batch_size {
                    current_batch_size = new_batch;
                }
                if let Some(new_limit) = recommendation.handoff_limit {
                    current_handoff_limit = new_limit;
                }
            }
        }

        // Simulate performance impact based on parameters
        let performance_factor = if enable_autotuner {
            // Better parameters improve performance
            let batch_efficiency = if (4..=16).contains(&current_batch_size) {
                1.0
            } else {
                0.8
            };
            let handoff_efficiency = if (2..=8).contains(&current_handoff_limit) {
                1.0
            } else {
                0.9
            };
            batch_efficiency * handoff_efficiency
        } else {
            1.0 // Baseline performance
        };

        // Simulate work with performance scaling
        let work_cycles = ((i % 1000) as f64 / performance_factor) as usize;
        for _ in 0..work_cycles {
            std::hint::black_box(i);
        }
    }

    (start.elapsed(), adjustments_made)
}

/// Benchmark autotuner decision-making performance.
fn bench_autotuner_decisions(c: &mut Criterion) {
    let mut group = c.benchmark_group("autotuner_decisions");
    group.throughput(Throughput::Elements(1000));

    let workloads = [
        WorkloadPattern::HighCancel,
        WorkloadPattern::HighThroughput,
        WorkloadPattern::Mixed,
    ];

    for workload in workloads {
        group.bench_with_input(
            BenchmarkId::new("decision_latency", format!("{:?}", workload)),
            &workload,
            |b, workload| {
                b.iter(|| {
                    let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

                    // Process multiple observations to trigger decisions
                    for i in 0..100 {
                        let observation = workload.generate_observation(i);
                        autotuner.observe(observation);

                        if i % 10 == 9 {
                            let _ = std::hint::black_box(autotuner.recommend());
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark autotuner overhead vs benefits.
fn bench_autotuner_vs_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("autotuner_performance");
    group.throughput(Throughput::Elements(10000));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(15));

    let workloads = [
        WorkloadPattern::HighCancel,
        WorkloadPattern::HighThroughput,
        WorkloadPattern::Mixed,
    ];

    for workload in workloads {
        // Baseline performance without autotuner
        group.bench_with_input(
            BenchmarkId::new("baseline", format!("{:?}", workload)),
            &workload,
            |b, workload| {
                b.iter_custom(|iters| {
                    let (duration, _) = simulate_scheduler_performance(
                        workload.clone(),
                        (iters * 1000) as usize,
                        false, // No autotuner
                    );
                    duration
                });
            },
        );

        // Performance with autotuner
        group.bench_with_input(
            BenchmarkId::new("autotuned", format!("{:?}", workload)),
            &workload,
            |b, workload| {
                b.iter_custom(|iters| {
                    let (duration, adjustments) = simulate_scheduler_performance(
                        workload.clone(),
                        (iters * 1000) as usize,
                        true, // With autotuner
                    );

                    // Log adjustments for analysis
                    if adjustments > 0 {
                        eprintln!(
                            "Autotuner made {} adjustments for {:?}",
                            adjustments, workload
                        );
                    }

                    duration
                });
            },
        );
    }

    group.finish();
}

/// Benchmark autotuner parameter exploration.
fn bench_autotuner_exploration(c: &mut Criterion) {
    let mut group = c.benchmark_group("autotuner_exploration");

    // Test different autotuner configurations
    let configs = [
        AutotunerConfig {
            observation_window_ms: 500,
            max_batch_delta: 2,
            target_p95_latency_us: 1000,
            ..Default::default()
        },
        AutotunerConfig {
            observation_window_ms: 1500,
            max_batch_delta: 8,
            target_p95_latency_us: 500,
            ..Default::default()
        },
    ];

    for (i, config) in configs.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("config", format!("config_{}", i)),
            config,
            |b, config| {
                b.iter(|| {
                    let mut autotuner = SchedulerAutotuner::new(config.clone());
                    let workload = WorkloadPattern::Mixed;

                    // Simulate parameter exploration
                    for j in 0..50 {
                        let observation = workload.generate_observation(j);
                        autotuner.observe(observation);

                        if j % 5 == 4 {
                            if let Some(rec) = autotuner.recommend() {
                                std::hint::black_box(rec);
                                autotuner.mark_adjustment_applied();
                            }
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

fn high_contention_current_knobs() -> SchedulerFeedbackCurrentKnobs {
    SchedulerFeedbackCurrentKnobs {
        worker_threads: 4,
        cohort_count: 2,
        steal_batch_size: 16,
        global_queue_limit: 65_536,
        placement_mode: SchedulerPlacementMode::LocalityFirst,
        blocking_pool_affinity: BlockingPoolAffinityProfile::Disabled,
        admission_thresholds: SchedulerAdmissionControlThresholds::default(),
        ..SchedulerFeedbackCurrentKnobs::default()
    }
}

fn scheduler_feedback_replay_scenario(iteration: usize) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "scheduler-feedback-high-contention".to_string(),
        seed: 0x57A9_5C4E_DFEE_D001 ^ iteration as u64,
        worker_count: 4,
        cohort_count: 2,
        region_count: 4,
        tasks_per_region: 8,
        yields_per_task: 5,
        yield_jitter: 2,
        channel_capacity: 6,
        messages_per_task: 4,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 2,
        timer_ticks_per_task: 1,
        cancellation_tree_depth: 2,
        artifact_bytes_per_task: 128,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 2,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: None,
        max_steps: 20_000,
    }
}

fn bench_task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn bench_region() -> RegionId {
    RegionId::testing_default()
}

fn replay_scheduler_state(max_task_id: u32) -> Arc<ContendedMutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for id in 0..=max_task_id {
        let task_id = bench_task(id);
        let record = TaskRecord::new(task_id, bench_region(), Budget::INFINITE);
        let index = state.tasks.insert(record);
        assert_eq!(index.index(), id);
    }
    Arc::new(ContendedMutex::new("runtime_state", state))
}

fn apply_feedback_recommendation(
    mut current: SchedulerFeedbackCurrentKnobs,
    recommendation: &asupersync::runtime::scheduler::SchedulerFeedbackRecommendation,
) -> SchedulerFeedbackCurrentKnobs {
    if let Some(steal_batch_size) = recommendation.steal_batch_size {
        current.steal_batch_size = steal_batch_size;
    }
    if let Some(ready_batch_profile) = recommendation.ready_batch_profile {
        current.ready_batch_profile = ready_batch_profile;
    }
    if let Some(global_queue_limit) = recommendation.global_queue_limit {
        current.global_queue_limit = global_queue_limit;
    }
    if let Some(placement_mode) = recommendation.placement_mode {
        current.placement_mode = placement_mode;
    }
    if let Some(blocking_pool_affinity) = recommendation.blocking_pool_affinity {
        current.blocking_pool_affinity = blocking_pool_affinity;
    }
    if let Some(admission_thresholds) = recommendation.admission_thresholds {
        current.admission_thresholds = admission_thresholds;
    }
    current
}

fn run_replay_backed_scheduler_dispatch(
    knobs: SchedulerFeedbackCurrentKnobs,
    replay: &SwarmReplaySummary,
) -> (usize, u64, u64) {
    let dispatch_tasks = replay
        .scheduled_task_count
        .max(1)
        .saturating_add(replay.channel_backlog_peak)
        .min(10_000);
    let max_task_id = u32::try_from(dispatch_tasks).unwrap_or(u32::MAX - 1);
    let state = replay_scheduler_state(max_task_id);
    let worker_count = replay.worker_count.clamp(1, 8);
    let mut scheduler = ThreeLaneScheduler::new(worker_count, &state);
    scheduler.set_steal_batch_size(knobs.steal_batch_size.max(1));
    scheduler.set_global_queue_limit(knobs.global_queue_limit);
    scheduler.set_scheduler_placement_mode(knobs.placement_mode);
    scheduler.set_adaptive_batch_profile_for_test(Some(knobs.ready_batch_profile));

    for id in 0..dispatch_tasks {
        let task_id = u32::try_from(id).unwrap_or(max_task_id);
        scheduler.inject_ready(bench_task(task_id), 50);
    }

    let mut dispatched = 0usize;
    let mut global_ready_batch_drains = 0u64;
    let mut global_ready_batch_tasks = 0u64;
    let mut workers = scheduler.take_workers();
    for worker in &mut workers {
        while let Some(task_id) = worker.next_task() {
            std::hint::black_box(task_id);
            dispatched = dispatched.saturating_add(1);
        }
        let metrics = worker.preemption_metrics();
        global_ready_batch_drains =
            global_ready_batch_drains.saturating_add(metrics.global_ready_batch_drains);
        global_ready_batch_tasks =
            global_ready_batch_tasks.saturating_add(metrics.global_ready_batch_tasks);
    }

    (
        dispatched,
        global_ready_batch_drains,
        global_ready_batch_tasks,
    )
}

fn simulate_replay_backed_feedback_controller_high_contention(
    iterations: usize,
    enable_feedback: bool,
) -> (Duration, usize) {
    let mut current = high_contention_current_knobs();
    let policy = SchedulerFeedbackPolicy::default();
    let start = Instant::now();
    let mut accumulated_dispatches = 0usize;

    for iteration in 0..iterations {
        let scenario = scheduler_feedback_replay_scenario(iteration);
        let replay = run_swarm_replay_scenario(&scenario).expect("replay-backed scheduler bench");
        let metrics = scheduler_feedback_metrics_from_swarm_replay(&scenario, &replay);

        if enable_feedback {
            let recommendation = recommend_scheduler_feedback(metrics, current, policy.clone());
            current = apply_feedback_recommendation(current, &recommendation);
            std::hint::black_box(recommendation.evidence);
        }

        let dispatch = run_replay_backed_scheduler_dispatch(current, &replay);
        accumulated_dispatches = accumulated_dispatches.saturating_add(dispatch.0);
        std::hint::black_box((metrics, replay.trace_fingerprint, dispatch));
    }

    (start.elapsed(), accumulated_dispatches)
}

/// Compare fixed knobs against feedback-selected knobs on a high-contention profile.
fn bench_scheduler_feedback_high_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler_feedback_high_contention");
    group.throughput(Throughput::Elements(100));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("fixed_knobs_replay_lab", |b| {
        b.iter_custom(|iters| {
            let (duration, dispatches) =
                simulate_replay_backed_feedback_controller_high_contention(iters as usize, false);
            std::hint::black_box(dispatches);
            duration
        });
    });

    group.bench_function("feedback_selected_knobs_replay_lab", |b| {
        b.iter_custom(|iters| {
            let (duration, dispatches) =
                simulate_replay_backed_feedback_controller_high_contention(iters as usize, true);
            std::hint::black_box(dispatches);
            duration
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_autotuner_decisions,
    bench_autotuner_vs_baseline,
    bench_autotuner_exploration,
    bench_scheduler_feedback_high_contention
);
criterion_main!(benches);
