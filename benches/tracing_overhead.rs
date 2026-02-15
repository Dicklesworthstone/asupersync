//! Tracing overhead benchmarks.
//!
//! Measures the cost of tracing instrumentation on hot paths.
//! Run with and without `tracing-integration` feature to compare.

#![allow(missing_docs)]

use asupersync::runtime::RuntimeState;
use asupersync::trace::{
    CompactTaskId, CompressionMode, ReplayEvent, TraceFileConfig, TraceMetadata, TraceReader,
    TraceWriter,
};
use asupersync::types::Budget;
use criterion::{criterion_group, criterion_main, Criterion};
use std::path::Path;
use tempfile::NamedTempFile;

fn sample_trace_events(count: u64) -> Vec<ReplayEvent> {
    (0..count)
        .map(|i| ReplayEvent::TaskScheduled {
            task: CompactTaskId(i),
            at_tick: i,
        })
        .collect()
}

fn write_trace_file(path: &Path, config: TraceFileConfig, events: &[ReplayEvent]) {
    let mut writer = TraceWriter::create_with_config(path, config).expect("create trace writer");
    writer
        .write_metadata(&TraceMetadata::new(42))
        .expect("write metadata");
    for event in events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish trace writer");
}

fn bench_region_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracing_overhead");

    group.bench_function("create_root_region", |b| {
        b.iter(|| {
            let mut state = RuntimeState::new();
            // This triggers RegionRecord::new which has the span creation
            std::hint::black_box(state.create_root_region(Budget::INFINITE))
        });
    });

    group.finish();
}

fn bench_task_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracing_overhead");

    group.bench_function("create_task", |b| {
        b.iter(|| {
            let mut state = RuntimeState::new();
            let region = state.create_root_region(Budget::INFINITE);
            // This triggers Scope::spawn which has tracing
            // But we can't easily use Scope here without Cx.
            // RuntimeState::create_task also has tracing (debug!).
            std::hint::black_box(state.create_task(region, Budget::INFINITE, async { 42 }))
        });
    });

    group.finish();
}

fn bench_trace_write_uncompressed(c: &mut Criterion) {
    let events = sample_trace_events(10_000);
    let temp = NamedTempFile::new().expect("create temp file");
    let path = temp.path().to_path_buf();

    c.bench_function("trace_write_uncompressed", |b| {
        b.iter(|| {
            let config = TraceFileConfig::new().with_compression(CompressionMode::None);
            write_trace_file(&path, config, &events);
        });
    });
}

fn bench_trace_read_uncompressed(c: &mut Criterion) {
    let events = sample_trace_events(10_000);
    let temp = NamedTempFile::new().expect("create temp file");
    let path = temp.path().to_path_buf();

    write_trace_file(&path, TraceFileConfig::new(), &events);

    c.bench_function("trace_read_uncompressed", |b| {
        b.iter(|| {
            let reader = TraceReader::open(&path).expect("open trace reader");
            let loaded = reader.load_all().expect("load trace");
            std::hint::black_box(loaded.len());
        });
    });
}

#[cfg(feature = "trace-compression")]
fn bench_trace_write_lz4(c: &mut Criterion) {
    let events = sample_trace_events(10_000);
    let temp = NamedTempFile::new().expect("create temp file");
    let path = temp.path().to_path_buf();

    c.bench_function("trace_write_lz4", |b| {
        b.iter(|| {
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            write_trace_file(&path, config, &events);
        });
    });
}

#[cfg(feature = "trace-compression")]
fn bench_trace_read_lz4(c: &mut Criterion) {
    let events = sample_trace_events(10_000);
    let temp = NamedTempFile::new().expect("create temp file");
    let path = temp.path().to_path_buf();

    let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
    write_trace_file(&path, config, &events);

    c.bench_function("trace_read_lz4", |b| {
        b.iter(|| {
            let reader = TraceReader::open(&path).expect("open trace reader");
            let loaded = reader.load_all().expect("load trace");
            std::hint::black_box(loaded.len());
        });
    });
}

criterion_group!(
    benches,
    bench_region_creation,
    bench_task_creation,
    bench_trace_write_uncompressed,
    bench_trace_read_uncompressed
);

#[cfg(feature = "trace-compression")]
criterion_group!(
    compression_benches,
    bench_trace_write_lz4,
    bench_trace_read_lz4
);

#[cfg(feature = "trace-compression")]
criterion_main!(benches, compression_benches);

#[cfg(not(feature = "trace-compression"))]
criterion_main!(benches);
