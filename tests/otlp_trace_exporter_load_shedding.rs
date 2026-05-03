#![allow(missing_docs)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::observability::otlp_trace_exporter::{
    LoadSheddingTraceExporter, MockOtlpHttpExporter, OtlpSpan, SpanBatch, TraceExporter,
};

fn create_test_batch(batch_id: u64, span_count: usize) -> SpanBatch {
    let spans = (0..span_count)
        .map(|i| OtlpSpan {
            span_id: format!("span-{}-{}", batch_id, i),
            name: "test_operation".to_string(),
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 1_000_001_000,
            attributes: vec![("service".to_string(), "test".to_string())],
            trace_flags: Some(0x01),
        })
        .collect();

    SpanBatch {
        batch_id,
        spans,
        created_at: Instant::now(),
    }
}

#[test]
fn dropped_spans_count_matches_evicted_batch() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter), 1, Duration::from_secs(1));

    let small_batch = create_test_batch(1, 3);
    let large_batch = create_test_batch(2, 7);

    exporter
        .export(&small_batch)
        .expect("first export should succeed");
    exporter
        .export(&large_batch)
        .expect("replacement export should succeed");

    let stats = exporter.load_shedding_stats();
    assert_eq!(stats.queue_depth, 1, "queue should retain only one batch");
    assert_eq!(
        stats.dropped_batches, 1,
        "exactly one batch should be dropped"
    );
    assert_eq!(
        exporter.dropped_spans_count(),
        3,
        "dropped span metric must reflect the evicted batch size"
    );
}

#[test]
fn multi_producer_queue_accounting_under_load() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter = Arc::new(LoadSheddingTraceExporter::new(
        Box::new(mock_exporter.clone()),
        32,
        Duration::from_secs(1),
    ));

    let producer_count = 4usize;
    let batches_per_producer = 128usize;
    let spans_per_batch = 64usize;
    let submitted_batches = producer_count * batches_per_producer;
    let submitted_spans = submitted_batches * spans_per_batch;
    let enqueue_start = Instant::now();

    let mut producers = Vec::new();
    for producer_id in 0..producer_count {
        let exporter = Arc::clone(&exporter);
        producers.push(thread::spawn(move || {
            for batch_idx in 0..batches_per_producer {
                let batch_id = (producer_id * batches_per_producer + batch_idx) as u64;
                let batch = create_test_batch(batch_id, spans_per_batch);
                exporter
                    .export(&batch)
                    .expect("multi-producer export should succeed");
            }
        }));
    }

    for producer in producers {
        producer.join().expect("producer thread should not panic");
    }

    let enqueue_duration = enqueue_start.elapsed();
    let stats_before_drain = exporter.load_shedding_stats();
    let drain_start = Instant::now();
    let processed = exporter
        .process_queue()
        .expect("queue drain should succeed after producer burst");
    let drain_duration = drain_start.elapsed();
    let exported_batches = mock_exporter.exported_batches();
    let exported_batch_count = exported_batches.len();
    let exported_span_count = mock_exporter.exported_span_count();
    let dropped_batches = stats_before_drain.dropped_batches as usize;
    let dropped_spans = exporter.dropped_spans_count() as usize;

    assert_eq!(
        exported_batch_count + dropped_batches,
        submitted_batches,
        "every submitted batch must be either exported or counted as dropped"
    );
    assert_eq!(
        exported_span_count + dropped_spans,
        submitted_spans,
        "every submitted span must be either exported or counted as dropped"
    );
    assert_eq!(
        processed, exported_batch_count,
        "drain should process exactly the batches handed to the mock exporter"
    );

    println!("✅ MULTI-PRODUCER OTLP QUEUE AUDIT PASSED");
    println!("   Producers: {}", producer_count);
    println!("   Submitted batches: {}", submitted_batches);
    println!("   Exported batches: {}", exported_batch_count);
    println!("   Dropped batches: {}", dropped_batches);
    println!("   Submitted spans: {}", submitted_spans);
    println!("   Exported spans: {}", exported_span_count);
    println!("   Dropped spans: {}", dropped_spans);
    println!(
        "   Queue depth before drain: {}",
        stats_before_drain.queue_depth
    );
    println!("   Enqueue duration: {:?}", enqueue_duration);
    println!("   Shutdown drain duration: {:?}", drain_duration);
    println!("   Final invariant verdict: exported + dropped == submitted");
}
