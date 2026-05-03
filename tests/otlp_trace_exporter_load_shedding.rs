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

fn create_flagged_priority_batch(batch_id: u64, priorities: &[(&str, Option<u8>)]) -> SpanBatch {
    let spans = priorities
        .iter()
        .enumerate()
        .map(|(i, (priority, trace_flags))| OtlpSpan {
            span_id: format!("span-{}-{}", batch_id, i),
            name: "test_operation".to_string(),
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 1_000_001_000,
            attributes: vec![
                ("service".to_string(), "test".to_string()),
                ("otlp.priority".to_string(), (*priority).to_string()),
            ],
            trace_flags: *trace_flags,
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

fn low_pressure_brownout_evidence(
    previous_phase: OverloadBrownoutPhase,
    recovery_streak_windows: u8,
) -> OverloadBrownoutEvidence {
    OverloadBrownoutEvidence {
        scheduler: Some(SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 8_000,
            wake_to_run_p95_ns: 14_000,
            wake_to_run_p99_ns: 24_000,
            queue_residency_p50_ns: 10_000,
            queue_residency_p95_ns: 16_000,
            queue_residency_p99_ns: 21_000,
            ready_backlog_p95: 4,
            ready_backlog_p99: 8,
            cancel_debt_p95: 1,
            cancel_debt_p99: 2,
            remote_steal_ratio_pct: Some(4),
            cross_cohort_wake_p99_ns: Some(28_000),
        }),
        memory_pressure_bps: Some(3_200),
        degradation_level: DegradationLevel::None,
        outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
        previous_phase,
        recovery_streak_windows,
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

#[test]
fn disabled_brownout_policy_matches_export_all_sampling_behavior() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 8, Duration::from_secs(1));

    let disabled = OverloadBrownoutLedger::evaluate(
        &sample_brownout_evidence(),
        &OverloadBrownoutProfile {
            enabled: false,
            ..OverloadBrownoutProfile::default()
        },
    );
    assert_eq!(disabled.phase, OverloadBrownoutPhase::Normal);

    let snapshot = exporter.update_brownout_policy(Some(&disabled));
    assert_eq!(snapshot.action, OtlpBrownoutAction::ExportAll);
    assert!(snapshot.fallback_used);
    assert!(
        snapshot
            .shared_reason_codes
            .contains(&OverloadBrownoutReason::Disabled)
    );

    let batch = create_flagged_priority_batch(
        31,
        &[
            ("low", Some(0x01)),
            ("high", Some(0x00)),
            ("high", Some(0x01)),
            ("low", None),
        ],
    );
    exporter
        .export(&batch)
        .expect("disabled brownout mode should not fail export");
    exporter
        .process_queue()
        .expect("disabled brownout mode should drain normally");

    let exported_batches = mock_exporter.exported_batches();
    assert_eq!(exported_batches.len(), 1);
    assert_eq!(exported_batches[0].spans.len(), 3);
    assert_eq!(
        exported_batches[0]
            .spans
            .iter()
            .filter(|span| {
                span.attributes
                    .iter()
                    .any(|(key, value)| key == "otlp.priority" && value == "low")
            })
            .count(),
        2,
        "disabled mode should export low-priority spans exactly like standalone mode"
    );
    assert_eq!(exporter.brownout_dropped_spans_count(), 0);
    assert_eq!(exporter.retained_summary_spans_count(), 0);
    assert_eq!(exporter.dropped_spans_count(), 0);
}

#[test]
fn brownout_and_queue_drops_do_not_double_count_same_span() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 1, Duration::from_secs(1));

    let brownout = OverloadBrownoutLedger::evaluate(
        &sample_brownout_evidence(),
        &OverloadBrownoutProfile::default(),
    );
    assert_eq!(brownout.phase, OverloadBrownoutPhase::Degrade);
    exporter.update_brownout_policy(Some(&brownout));

    let first_batch = create_priority_batch(41, &["high", "high", "high"]);
    let second_batch = create_priority_batch(42, &["low", "high", "low"]);
    exporter
        .export(&first_batch)
        .expect("first degrade-mode export should succeed");
    exporter
        .export(&second_batch)
        .expect("second degrade-mode export should succeed");
    exporter
        .process_queue()
        .expect("queue drain should succeed after mixed brownout drops");

    let total_sampled_spans = (first_batch.spans.len() + second_batch.spans.len()) as u64;
    let queue_dropped_spans = exporter.dropped_spans_count();
    let brownout_dropped_spans = exporter.brownout_dropped_spans_count();
    let exported_spans = mock_exporter.exported_span_count() as u64;

    assert_eq!(queue_dropped_spans, 3);
    assert_eq!(brownout_dropped_spans, 2);
    assert_eq!(exported_spans, 1);
    assert_eq!(
        queue_dropped_spans + brownout_dropped_spans + exported_spans,
        total_sampled_spans,
        "each sampled span must contribute to exactly one terminal accounting bucket"
    );
}

#[test]
fn recovery_hysteresis_is_idempotent_until_reenable_window_completes() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 4, Duration::from_secs(1));

    let recovering = OverloadBrownoutLedger::evaluate(
        &low_pressure_brownout_evidence(OverloadBrownoutPhase::Degrade, 0),
        &OverloadBrownoutProfile::default(),
    );
    assert_eq!(recovering.phase, OverloadBrownoutPhase::Recovery);

    let first_snapshot = exporter.update_brownout_policy(Some(&recovering));
    let second_snapshot = exporter.update_brownout_policy(Some(&recovering));
    assert_eq!(first_snapshot, second_snapshot);
    assert_eq!(first_snapshot.action, OtlpBrownoutAction::DropLowPriority);

    let reenabled = OverloadBrownoutLedger::evaluate(
        &low_pressure_brownout_evidence(OverloadBrownoutPhase::Degrade, 1),
        &OverloadBrownoutProfile::default(),
    );
    assert_eq!(reenabled.phase, OverloadBrownoutPhase::Normal);

    let reenabled_snapshot = exporter.update_brownout_policy(Some(&reenabled));
    assert_eq!(reenabled_snapshot.action, OtlpBrownoutAction::ExportAll);
    assert!(!reenabled_snapshot.fallback_used);

    let batch = create_priority_batch(51, &["low", "high"]);
    exporter
        .export(&batch)
        .expect("re-enabled exporter should accept export");
    exporter
        .process_queue()
        .expect("re-enabled exporter should drain normally");

    let exported_batches = mock_exporter.exported_batches();
    assert_eq!(exported_batches.len(), 1);
    assert_eq!(exported_batches[0].spans.len(), 2);
}

#[test]
fn missing_brownout_evidence_uses_conservative_fallback_reason_codes() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter.clone()), 4, Duration::from_secs(1));

    let missing_evidence = OverloadBrownoutLedger::evaluate(
        &OverloadBrownoutEvidence {
            scheduler: None,
            memory_pressure_bps: None,
            degradation_level: DegradationLevel::Moderate,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
            previous_phase: OverloadBrownoutPhase::Observe,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        },
        &OverloadBrownoutProfile::default(),
    );
    assert_eq!(missing_evidence.phase, OverloadBrownoutPhase::Degrade);
    assert!(missing_evidence.fallback_used);

    let snapshot = exporter.update_brownout_policy(Some(&missing_evidence));
    assert_eq!(snapshot.action, OtlpBrownoutAction::DropLowPriority);
    assert!(snapshot.fallback_used);
    assert!(
        snapshot
            .shared_reason_codes
            .contains(&OverloadBrownoutReason::MissingEvidenceFallback)
    );

    let batch = create_priority_batch(56, &["low", "high"]);
    exporter
        .export(&batch)
        .expect("missing-evidence fallback export should succeed");
    exporter
        .process_queue()
        .expect("missing-evidence fallback drain should succeed");

    let exported_batches = mock_exporter.exported_batches();
    assert_eq!(exported_batches.len(), 1);
    assert_eq!(exported_batches[0].spans.len(), 1);
    assert_eq!(exported_batches[0].spans[0].attributes[1].1, "high");
}

#[test]
fn exporter_metadata_surfaces_do_not_leak_span_attributes() {
    let mock_exporter = MockOtlpHttpExporter::new(Duration::from_millis(0));
    let exporter =
        LoadSheddingTraceExporter::new(Box::new(mock_exporter), 4, Duration::from_secs(1));

    let brownout = OverloadBrownoutLedger::evaluate(
        &sample_brownout_evidence(),
        &OverloadBrownoutProfile::default(),
    );
    exporter.update_brownout_policy(Some(&brownout));

    let batch = SpanBatch {
        batch_id: 61,
        spans: vec![OtlpSpan::new(
            "span-61-0".to_string(),
            "secret-bearing-operation".to_string(),
            1_000_000_000,
            1_000_001_000,
            vec![
                (
                    "authorization".to_string(),
                    "Bearer super-secret-token".to_string(),
                ),
                ("otlp.priority".to_string(), "low".to_string()),
            ],
        )],
        created_at: Instant::now(),
    };
    exporter
        .export(&batch)
        .expect("metadata redaction probe export should succeed");

    let snapshot_debug = format!("{:?}", exporter.brownout_policy_snapshot());
    let stats_debug = format!("{:?}", exporter.load_shedding_stats());

    for leaked_value in [
        "authorization",
        "Bearer super-secret-token",
        "secret-bearing-operation",
    ] {
        assert!(
            !snapshot_debug.contains(leaked_value),
            "policy snapshots must not leak span payload metadata"
        );
        assert!(
            !stats_debug.contains(leaked_value),
            "load shedding stats must not leak span payload metadata"
        );
    }
}
