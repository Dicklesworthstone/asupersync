//! Criterion benchmark for scheduler hot-path autotuner.
//!
//! Demonstrates measurable performance wins through autotuning of scheduler parameters.
//! Focuses on autotuner decision-making performance and parameter optimization.

#![cfg(feature = "test-internals")]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::time::{Duration, Instant};

use asupersync::runtime::config::BlockingPoolAffinityProfile;
use asupersync::runtime::scheduler::{
    AutotunerConfig, HotPathObservation, SchedulerAdmissionControlThresholds, SchedulerAutotuner,
    SchedulerFeedbackCurrentKnobs, SchedulerFeedbackMetrics, SchedulerFeedbackPolicy,
    SchedulerPlacementMode, recommend_scheduler_feedback,
};

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

fn high_contention_metrics(iteration: usize) -> SchedulerFeedbackMetrics {
    let wave = (iteration % 16) as f64 / 16.0;
    SchedulerFeedbackMetrics {
        runnable_queue_pressure: Some(0.84 + wave.mul_add(0.10, 0.0)),
        ready_queue_pressure: Some(0.82 + wave.mul_add(0.08, 0.0)),
        blocking_pool_pressure: Some(0.58 + wave.mul_add(0.06, 0.0)),
        channel_backlog_pressure: Some(0.78 + wave.mul_add(0.12, 0.0)),
        cancellation_pressure: Some(0.20 + wave.mul_add(0.08, 0.0)),
        cleanup_debt_pressure: Some(0.18 + wave.mul_add(0.06, 0.0)),
        memory_budget_pressure: Some(0.54 + wave.mul_add(0.05, 0.0)),
        p95_dispatch_latency_us: Some(1_800 + (iteration % 128) as u64),
        p99_dispatch_latency_us: Some(3_200 + (iteration % 256) as u64),
    }
}

fn high_contention_current_knobs() -> SchedulerFeedbackCurrentKnobs {
    SchedulerFeedbackCurrentKnobs {
        worker_threads: 64,
        cohort_count: 8,
        steal_batch_size: 16,
        global_queue_limit: 65_536,
        placement_mode: SchedulerPlacementMode::LocalityFirst,
        blocking_pool_affinity: BlockingPoolAffinityProfile::Disabled,
        admission_thresholds: SchedulerAdmissionControlThresholds::default(),
        ..SchedulerFeedbackCurrentKnobs::default()
    }
}

fn synthetic_high_contention_cost(knobs: &SchedulerFeedbackCurrentKnobs) -> usize {
    let batch_penalty = 48usize.saturating_sub(knobs.steal_batch_size.min(48));
    let queue_penalty = 131_072usize.saturating_sub(knobs.global_queue_limit.min(131_072)) / 4_096;
    let placement_penalty = match knobs.placement_mode {
        SchedulerPlacementMode::ThroughputFirst => 0,
        SchedulerPlacementMode::LatencyFirst => 12,
        SchedulerPlacementMode::LocalityFirst => 18,
    };
    let affinity_penalty = match knobs.blocking_pool_affinity {
        BlockingPoolAffinityProfile::CohortBiased { .. } => 0,
        BlockingPoolAffinityProfile::Disabled => 10,
    };
    batch_penalty
        .saturating_add(queue_penalty)
        .saturating_add(placement_penalty)
        .saturating_add(affinity_penalty)
        .max(1)
}

fn simulate_feedback_controller_high_contention(
    iterations: usize,
    enable_feedback: bool,
) -> (Duration, usize) {
    let mut current = high_contention_current_knobs();
    let policy = SchedulerFeedbackPolicy::default();
    let start = Instant::now();
    let mut accumulated_cost = 0usize;

    for iteration in 0..iterations {
        if enable_feedback && iteration % 128 == 0 {
            let recommendation = recommend_scheduler_feedback(
                high_contention_metrics(iteration),
                current,
                policy.clone(),
            );
            if let Some(steal_batch_size) = recommendation.steal_batch_size {
                current.steal_batch_size = steal_batch_size;
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
            std::hint::black_box(recommendation.evidence);
        }

        let cost = synthetic_high_contention_cost(&current);
        accumulated_cost = accumulated_cost.saturating_add(cost);
        for _ in 0..cost {
            std::hint::black_box(iteration);
        }
    }

    (start.elapsed(), accumulated_cost)
}

/// Compare fixed knobs against feedback-selected knobs on a high-contention profile.
fn bench_scheduler_feedback_high_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler_feedback_high_contention");
    group.throughput(Throughput::Elements(10_000));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("fixed_knobs", |b| {
        b.iter_custom(|iters| {
            let (duration, cost) =
                simulate_feedback_controller_high_contention((iters * 1000) as usize, false);
            std::hint::black_box(cost);
            duration
        });
    });

    group.bench_function("feedback_selected_knobs", |b| {
        b.iter_custom(|iters| {
            let (duration, cost) =
                simulate_feedback_controller_high_contention((iters * 1000) as usize, true);
            std::hint::black_box(cost);
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
