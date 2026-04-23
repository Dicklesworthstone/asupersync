//! Trace recorder hot path performance profiling.
//!
//! This benchmark exercises the core `record_event()` hot path with realistic
//! workloads to identify performance bottlenecks in trace emission.

#![cfg(feature = "test-internals")]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use asupersync::trace::recorder::{TraceRecorder, RecorderConfig};
use asupersync::trace::replay::TraceMetadata;
use asupersync::types::{TaskId, Time, Severity, RegionId};

/// Mixed trace workload: typical patterns from lab runtime
struct TraceWorkload {
    pub name: &'static str,
    pub task_schedules: usize,
    pub time_advances: usize,
    pub rng_values: usize,
    pub io_events: usize,
}

const WORKLOADS: &[TraceWorkload] = &[
    TraceWorkload {
        name: "light",
        task_schedules: 100,
        time_advances: 50,
        rng_values: 200,
        io_events: 20,
    },
    TraceWorkload {
        name: "moderate",
        task_schedules: 1000,
        time_advances: 500,
        rng_values: 2000,
        io_events: 200,
    },
    TraceWorkload {
        name: "heavy",
        task_schedules: 10000,
        time_advances: 5000,
        rng_values: 20000,
        io_events: 2000,
    },
];

fn bench_trace_emit_hotpath(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_emit_hotpath");

    for workload in WORKLOADS {
        let total_events = workload.task_schedules + workload.time_advances +
                          workload.rng_values + workload.io_events;

        group.throughput(Throughput::Elements(total_events as u64));

        group.bench_with_input(
            BenchmarkId::new("record_mixed_events", workload.name),
            workload,
            |b, wl| {
                b.iter(|| {
                    let metadata = TraceMetadata::new(42);
                    let config = RecorderConfig::new()
                        .with_record_rng(true)
                        .with_record_wakers(true);
                    let mut recorder = TraceRecorder::with_config(metadata, config);

                    // Task scheduling events (hot path)
                    for i in 0..wl.task_schedules {
                        let task_id = TaskId::new_for_test(i as u32, 0);
                        black_box(recorder.record_task_scheduled(task_id, i as u64));
                    }

                    // Time advancement events (common)
                    for i in 0..wl.time_advances {
                        let from = Time::from_nanos(i as u64 * 1_000_000);
                        let to = Time::from_nanos((i + 1) as u64 * 1_000_000);
                        black_box(recorder.record_time_advanced(from, to));
                    }

                    // RNG values (very hot in some workloads)
                    for i in 0..wl.rng_values {
                        black_box(recorder.record_rng_value(i as u64));
                    }

                    // I/O events (moderate frequency)
                    for i in 0..wl.io_events {
                        black_box(recorder.record_io_ready(i as u64, true, false, false, false));
                    }

                    // Finish to force all event processing
                    black_box(recorder.finish());
                });
            },
        );
    }

    group.finish();
}

fn bench_record_event_microbench(c: &mut Criterion) {
    let mut group = c.benchmark_group("record_event_micro");

    // Micro-benchmark individual record methods
    let metadata = TraceMetadata::new(42);
    let config = RecorderConfig::new();

    group.bench_function("record_task_scheduled", |b| {
        b.iter(|| {
            let mut recorder = TraceRecorder::with_config(metadata.clone(), config.clone());
            for i in 0..1000 {
                let task_id = TaskId::new_for_test(i, 0);
                black_box(recorder.record_task_scheduled(task_id, i as u64));
            }
            black_box(recorder.finish());
        });
    });

    group.bench_function("record_rng_value", |b| {
        b.iter(|| {
            let mut recorder = TraceRecorder::with_config(metadata.clone(), config.clone());
            for i in 0..1000 {
                black_box(recorder.record_rng_value(i));
            }
            black_box(recorder.finish());
        });
    });

    group.bench_function("record_time_advanced", |b| {
        b.iter(|| {
            let mut recorder = TraceRecorder::with_config(metadata.clone(), config.clone());
            for i in 0..1000 {
                let from = Time::from_nanos(i * 1_000_000);
                let to = Time::from_nanos((i + 1) * 1_000_000);
                black_box(recorder.record_time_advanced(from, to));
            }
            black_box(recorder.finish());
        });
    });

    group.finish();
}

fn bench_recorder_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("recorder_overhead");

    // Compare enabled vs disabled recorder overhead
    group.bench_function("enabled_recorder_baseline", |b| {
        b.iter(|| {
            let metadata = TraceMetadata::new(42);
            let config = RecorderConfig::new();
            let mut recorder = TraceRecorder::with_config(metadata, config);

            for i in 0..100 {
                black_box(recorder.record_task_scheduled(TaskId::new_for_test(i, 0), i as u64));
            }
            black_box(recorder.finish());
        });
    });

    group.bench_function("disabled_recorder_baseline", |b| {
        b.iter(|| {
            let metadata = TraceMetadata::new(42);
            let config = RecorderConfig::disabled();
            let mut recorder = TraceRecorder::with_config(metadata, config);

            for i in 0..100 {
                black_box(recorder.record_task_scheduled(TaskId::new_for_test(i, 0), i as u64));
            }
            black_box(recorder.finish());
        });
    });

    group.finish();
}

criterion_group!(
    trace_recorder_benches,
    bench_trace_emit_hotpath,
    bench_record_event_microbench,
    bench_recorder_overhead
);
criterion_main!(trace_recorder_benches);