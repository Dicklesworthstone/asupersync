#![allow(missing_docs)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::observability::otlp_trace_exporter::{
    LoadSheddingTraceExporter, MockOtlpHttpExporter, OtlpBrownoutAction, OtlpSpan, SpanBatch,
    TraceExporter,
};
use asupersync::runtime::resource_monitor::{
    DegradationLevel, OverloadBrownoutEvidence, OverloadBrownoutLedger, OverloadBrownoutPhase,
    OverloadBrownoutProfile, OverloadBrownoutReason, TailRiskAdmissionDecision,
};
use asupersync::runtime::scheduler::swarm_evidence::SchedulerEvidenceMetrics;

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

fn create_priority_batch(batch_id: u64, priorities: &[&str]) -> SpanBatch {
    let spans = priorities
        .iter()
        .enumerate()
        .map(|(i, priority)| OtlpSpan {
            span_id: format!("span-{}-{}", batch_id, i),
            name: "test_operation".to_string(),
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 1_000_001_000,
            attributes: vec![
                ("service".to_string(), "test".to_string()),
                ("otlp.priority".to_string(), (*priority).to_string()),
            ],
            trace_flags: Some(0x01),
        })
        .collect();

    SpanBatch {
        batch_id,
        spans,
        created_at: Instant::now(),
    }
}

fn sample_brownout_evidence() -> OverloadBrownoutEvidence {
    OverloadBrownoutEvidence {
        scheduler: Some(SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 12_000,
            wake_to_run_p95_ns: 162_000,
            wake_to_run_p99_ns: 228_000,
            queue_residency_p50_ns: 18_000,
            queue_residency_p95_ns: 196_000,
            queue_residency_p99_ns: 246_000,
            ready_backlog_p95: 166,
            ready_backlog_p99: 208,
            cancel_debt_p95: 42,
            cancel_debt_p99: 56,
            remote_steal_ratio_pct: Some(22),
            cross_cohort_wake_p99_ns: Some(252_000),
        }),
        memory_pressure_bps: Some(8_820),
        degradation_level: DegradationLevel::Moderate,
        outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
        previous_phase: OverloadBrownoutPhase::Observe,
        recovery_streak_windows: 0,
        already_shed_surfaces: Vec::new(),
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

#[test]
fn brownout_policy_drops_low_priority_spans_and_propagates_reasons() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 8, Duration::from_secs(1));

    let brownout = OverloadBrownoutLedger::evaluate(
        &sample_brownout_evidence(),
        &OverloadBrownoutProfile::default(),
    );
    assert_eq!(brownout.phase, OverloadBrownoutPhase::Degrade);

    let snapshot = exporter.update_brownout_policy(Some(&brownout));
    assert_eq!(snapshot.action, OtlpBrownoutAction::DropLowPriority);
    assert!(
        snapshot
            .shared_reason_codes
            .contains(&OverloadBrownoutReason::TailRiskOuterDefer)
    );

    let batch = create_priority_batch(11, &["low", "high", "low", "high", "high"]);
    exporter
        .export(&batch)
        .expect("degrade-mode export should succeed");
    exporter
        .process_queue()
        .expect("degrade-mode queue drain should succeed");

    let stats = exporter.load_shedding_stats();
    let exported_batches = mock_exporter.exported_batches();
    assert_eq!(stats.queue_depth, 0);
    assert_eq!(stats.dropped_batches, 0);
    assert_eq!(stats.brownout_dropped_spans, 2);
    assert_eq!(stats.retained_summary_spans, 0);
    assert_eq!(exported_batches.len(), 1);
    assert_eq!(exported_batches[0].spans.len(), 3);
    assert!(exported_batches[0].spans.iter().all(|span| {
        span.attributes
            .iter()
            .all(|(key, value)| key != "otlp.priority" || value != "low")
    }));
}

#[test]
fn brownout_policy_retains_summary_only_then_recovers_to_standalone_export() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 4, Duration::from_secs(1));

    let shed_optional = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            memory_pressure_bps: Some(9_450),
            degradation_level: DegradationLevel::Heavy,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
            ..sample_brownout_evidence()
        },
        &OverloadBrownoutProfile::default(),
    );
    assert_eq!(shed_optional.phase, OverloadBrownoutPhase::ShedOptional);

    let shed_snapshot = exporter.update_brownout_policy(Some(&shed_optional));
    assert_eq!(shed_snapshot.action, OtlpBrownoutAction::RetainSummaryOnly);
    assert!(
        shed_snapshot
            .shared_reason_codes
            .contains(&OverloadBrownoutReason::TailRiskOuterShed)
    );

    let retained_batch = create_priority_batch(21, &["high", "low", "high", "high"]);
    exporter
        .export(&retained_batch)
        .expect("summary-only brownout should not fail export");
    assert_eq!(exporter.process_queue().expect("drain after retain"), 0);

    let retained_stats = exporter.load_shedding_stats();
    assert_eq!(retained_stats.queue_depth, 0);
    assert_eq!(retained_stats.dropped_batches, 0);
    assert_eq!(retained_stats.brownout_dropped_spans, 0);
    assert_eq!(retained_stats.retained_summary_spans, 4);
    assert_eq!(mock_exporter.exported_span_count(), 0);

    let recovery_snapshot = exporter.update_brownout_policy(None);
    assert_eq!(recovery_snapshot.action, OtlpBrownoutAction::ExportAll);
    assert!(recovery_snapshot.fallback_used);
    assert!(recovery_snapshot.shared_reason_codes.is_empty());

    let recovered_batch = create_priority_batch(22, &["high", "high", "high"]);
    exporter
        .export(&recovered_batch)
        .expect("standalone fallback export should succeed");
    exporter
        .process_queue()
        .expect("drain after fallback recovery should succeed");

    assert_eq!(mock_exporter.exported_span_count(), 3);
    assert_eq!(exporter.load_shedding_stats().retained_summary_spans, 4);
}
