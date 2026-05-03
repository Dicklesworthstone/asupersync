#![cfg(feature = "test-internals")]
#![allow(missing_docs)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::observability::otlp_trace_exporter::{
    BoundedExportQueue, LoadSheddingTraceExporter, MockOtlpHttpExporter, OtlpSpan, SpanBatch,
    TraceExporter,
};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn create_bench_batch(batch_id: u64, span_count: usize) -> SpanBatch {
    let spans = (0..span_count)
        .map(|i| OtlpSpan {
            span_id: format!("bench-span-{}-{}", batch_id, i),
            name: "bench_operation".to_string(),
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 1_000_001_000,
            attributes: vec![("service".to_string(), "bench".to_string())],
            trace_flags: Some(0x01),
        })
        .collect();

    SpanBatch {
        batch_id,
        spans,
        created_at: Instant::now(),
    }
}

fn bench_bounded_export_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("observability/otlp_trace_exporter_queue");
    group.throughput(Throughput::Elements(1));

    group.bench_function("enqueue_fast_path", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || (BoundedExportQueue::new(1024), create_bench_batch(1, 16)),
            |(queue, batch)| {
                let dropped = queue.enqueue(batch);
                assert!(dropped.is_none(), "fast path should not shed");
                assert_eq!(queue.len(), 1);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enqueue_with_shedding", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || {
                let queue = BoundedExportQueue::new(1);
                let oldest = create_bench_batch(1, 16);
                let newest = create_bench_batch(2, 32);
                assert!(queue.enqueue(oldest).is_none());
                (queue, newest)
            },
            |(queue, newest)| {
                let dropped = queue.enqueue(newest);
                assert_eq!(
                    dropped
                        .expect("saturated queue should evict oldest")
                        .batch_id,
                    1
                );
                assert_eq!(queue.len(), 1);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_multi_producer_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("observability/otlp_trace_exporter_multiproducer");

    for producer_count in [2usize, 4, 8] {
        group.throughput(Throughput::Elements(producer_count as u64 * 64));
        group.bench_with_input(
            BenchmarkId::from_parameter(producer_count),
            &producer_count,
            |b, &producer_count| {
                b.iter_batched(
                    || {
                        let exporter = Arc::new(LoadSheddingTraceExporter::new(
                            Box::new(MockOtlpHttpExporter::new(Duration::from_millis(0))),
                            128,
                            Duration::from_secs(1),
                        ));
                        let batches: Vec<Vec<SpanBatch>> = (0..producer_count)
                            .map(|producer_id| {
                                (0..64)
                                    .map(|batch_idx| {
                                        create_bench_batch(
                                            (producer_id * 1_000 + batch_idx) as u64,
                                            32,
                                        )
                                    })
                                    .collect()
                            })
                            .collect();
                        (exporter, batches)
                    },
                    |(exporter, batches)| {
                        let mut threads = Vec::with_capacity(producer_count);
                        for producer_batches in batches {
                            let exporter = Arc::clone(&exporter);
                            threads.push(thread::spawn(move || {
                                for batch in producer_batches {
                                    exporter.export(&batch).expect("benchmark export");
                                }
                            }));
                        }

                        for thread in threads {
                            thread.join().expect("benchmark producer thread");
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_bounded_export_queue,
    bench_multi_producer_export
);
criterion_main!(benches);
