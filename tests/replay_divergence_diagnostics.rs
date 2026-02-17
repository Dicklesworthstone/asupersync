#![allow(missing_docs)]
//! E2E tests for replay divergence diagnostics (bd-ahj21).
//!
//! Verifies that the divergence diagnostic pipeline produces structured,
//! actionable reports when replay execution diverges from a recorded trace.

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::trace::{
    diagnose_divergence, minimal_divergent_prefix, CompactTaskId, DiagnosticConfig,
    DivergenceCategory, ReplayEvent, ReplayTrace, TraceMetadata, TraceReplayer,
};
use asupersync::types::Budget;
use common::*;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

fn record_simple_trace() -> ReplayTrace {
    let config = LabConfig::new(42).with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let (task_a, _handle_a) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task a");
    let (task_b, _handle_b) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task b");

    runtime.scheduler.lock().schedule(task_a, 0);
    runtime.scheduler.lock().schedule(task_b, 0);

    runtime.run_until_quiescent();

    runtime.finish_replay_trace().expect("replay trace")
}

// =========================================================================
// Divergence Diagnostics E2E (bd-ahj21)
// =========================================================================

/// E2E test: record a trace, introduce a divergence, diagnose it with
/// structured diagnostics, verify the report and minimal prefix are correct,
/// and emit structured JSON output.
#[test]
#[allow(clippy::too_many_lines)]
fn e2e_divergence_diagnostics_structured_report() {
    init_test("e2e_divergence_diagnostics_structured_report");

    // Phase 1: Record a real trace from the Lab runtime.
    test_section!("record");
    let trace = record_simple_trace();
    let event_count = trace.len();
    tracing::info!(event_count, seed = trace.metadata.seed, "Recorded trace");
    assert!(
        event_count >= 2,
        "need at least 2 events for divergence test"
    );

    // Phase 2: Replay with a deliberate divergence.
    test_section!("introduce-divergence");
    let mut replayer = TraceReplayer::new(trace.clone());

    // Feed the first event correctly, then introduce a bad event.
    let first_event = trace.events[0].clone();
    replayer
        .verify_and_advance(&first_event)
        .expect("first event should match");

    // Create a divergent event based on the expected next event type.
    let expected = trace.events[1].clone();
    let bad_event = match &expected {
        ReplayEvent::TaskScheduled { at_tick, .. } => ReplayEvent::TaskScheduled {
            task: CompactTaskId(9999),
            at_tick: *at_tick,
        },
        ReplayEvent::TaskCompleted { task, .. } => ReplayEvent::TaskCompleted {
            task: *task,
            outcome: 99,
        },
        _ => ReplayEvent::RngSeed { seed: 0xBAD_5EED },
    };

    let divergence_err = replayer
        .verify(&bad_event)
        .expect_err("should detect divergence");
    tracing::info!(
        index = divergence_err.index,
        "Divergence detected at event {}",
        divergence_err.index
    );

    // Phase 3: Diagnose the divergence with structured diagnostics.
    test_section!("diagnose");
    let config = DiagnosticConfig {
        context_before: 5,
        context_after: 3,
        max_prefix_len: 0,
    };
    let report = diagnose_divergence(&trace, &divergence_err, &config);

    tracing::info!(
        category = ?report.category,
        divergence_index = report.divergence_index,
        trace_length = report.trace_length,
        progress_pct = report.replay_progress_pct,
        minimal_prefix_len = report.minimal_prefix_len,
        affected_tasks = report.affected.tasks.len(),
        affected_regions = report.affected.regions.len(),
        "Divergence report generated"
    );

    // Verify report fields.
    assert_with_log!(
        report.divergence_index == 1,
        "divergence at index 1",
        1usize,
        report.divergence_index
    );
    assert_with_log!(
        report.trace_length == event_count,
        "trace length in report",
        event_count,
        report.trace_length
    );
    assert_with_log!(
        report.replay_progress_pct > 0.0,
        "progress > 0%",
        "> 0.0",
        report.replay_progress_pct
    );
    assert_with_log!(
        !report.explanation.is_empty(),
        "explanation non-empty",
        "non-empty",
        report.explanation.len()
    );
    assert_with_log!(
        !report.suggestion.is_empty(),
        "suggestion non-empty",
        "non-empty",
        report.suggestion.len()
    );

    // Phase 4: Verify structured JSON output.
    test_section!("json-output");
    let json = report.to_json().expect("JSON serialization");
    tracing::info!(json_len = json.len(), "Structured JSON diagnostic output");
    tracing::debug!(json = %json, "Full JSON report");

    assert_with_log!(
        json.contains("\"category\""),
        "JSON has category",
        true,
        json.contains("\"category\"")
    );
    assert_with_log!(
        json.contains("\"divergence_index\""),
        "JSON has divergence_index",
        true,
        json.contains("\"divergence_index\"")
    );
    assert_with_log!(
        json.contains("\"explanation\""),
        "JSON has explanation",
        true,
        json.contains("\"explanation\"")
    );
    assert_with_log!(
        json.contains("\"affected\""),
        "JSON has affected entities",
        true,
        json.contains("\"affected\"")
    );

    // Phase 5: Verify text report rendering.
    test_section!("text-output");
    let text = report.to_text();
    tracing::info!(text_len = text.len(), "Text diagnostic output");
    assert_with_log!(
        text.contains("Divergence Report"),
        "text has header",
        true,
        text.contains("Divergence Report")
    );

    // Phase 6: Minimal divergent prefix.
    test_section!("minimal-prefix");
    let prefix = minimal_divergent_prefix(&trace, report.divergence_index);
    tracing::info!(
        prefix_len = prefix.len(),
        original_len = event_count,
        "Minimal divergent prefix extracted"
    );
    assert_with_log!(
        prefix.len() <= event_count,
        "prefix <= original",
        event_count,
        prefix.len()
    );
    assert_with_log!(
        prefix.len() > report.divergence_index,
        "prefix includes divergence point",
        report.divergence_index + 1,
        prefix.len()
    );
    assert_with_log!(
        prefix.metadata.seed == trace.metadata.seed,
        "prefix preserves seed",
        trace.metadata.seed,
        prefix.metadata.seed
    );

    test_complete!(
        "e2e_divergence_diagnostics_structured_report",
        divergence_index = report.divergence_index,
        category = format!("{:?}", report.category),
        trace_length = event_count,
        prefix_length = prefix.len(),
        json_bytes = json.len()
    );
}

/// E2E test: multiple divergence categories produce distinct reports.
#[test]
fn e2e_divergence_category_classification() {
    init_test("e2e_divergence_category_classification");
    let config = DiagnosticConfig::default();

    // Scenario 1: Scheduling order divergence (different tasks).
    test_section!("scheduling-order");
    let mut trace1 = ReplayTrace::new(TraceMetadata::new(100));
    trace1.push(ReplayEvent::TaskScheduled {
        task: CompactTaskId(1),
        at_tick: 0,
    });
    trace1.push(ReplayEvent::TaskScheduled {
        task: CompactTaskId(2),
        at_tick: 1,
    });

    let err1 = TraceReplayer::new(trace1.clone())
        .verify(&ReplayEvent::TaskScheduled {
            task: CompactTaskId(99),
            at_tick: 0,
        })
        .expect_err("scheduling divergence");
    let report1 = diagnose_divergence(&trace1, &err1, &config);
    tracing::info!(category = ?report1.category, "Scheduling divergence classified");
    assert_with_log!(
        matches!(report1.category, DivergenceCategory::SchedulingOrder),
        "classified as SchedulingOrder",
        "SchedulingOrder",
        format!("{:?}", report1.category)
    );

    // Scenario 2: Outcome mismatch (same task, different outcome).
    test_section!("outcome-mismatch");
    let mut trace2 = ReplayTrace::new(TraceMetadata::new(200));
    trace2.push(ReplayEvent::TaskCompleted {
        task: CompactTaskId(1),
        outcome: 0,
    });

    let err2 = TraceReplayer::new(trace2.clone())
        .verify(&ReplayEvent::TaskCompleted {
            task: CompactTaskId(1),
            outcome: 3,
        })
        .expect_err("outcome divergence");
    let report2 = diagnose_divergence(&trace2, &err2, &config);
    tracing::info!(category = ?report2.category, "Outcome mismatch classified");
    assert_with_log!(
        matches!(report2.category, DivergenceCategory::OutcomeMismatch),
        "classified as OutcomeMismatch",
        "OutcomeMismatch",
        format!("{:?}", report2.category)
    );

    // Scenario 3: Event type mismatch (completely different variants).
    test_section!("event-type-mismatch");
    let mut trace3 = ReplayTrace::new(TraceMetadata::new(300));
    trace3.push(ReplayEvent::RngSeed { seed: 42 });

    let err3 = TraceReplayer::new(trace3.clone())
        .verify(&ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        })
        .expect_err("type mismatch");
    let report3 = diagnose_divergence(&trace3, &err3, &config);
    tracing::info!(category = ?report3.category, "Event type mismatch classified");
    assert_with_log!(
        matches!(report3.category, DivergenceCategory::EventTypeMismatch),
        "classified as EventTypeMismatch",
        "EventTypeMismatch",
        format!("{:?}", report3.category)
    );

    // Verify all reports produce valid JSON.
    test_section!("verify-json");
    for (i, report) in [&report1, &report2, &report3].iter().enumerate() {
        let json = report.to_json().expect("JSON serialization");
        tracing::debug!(scenario = i + 1, json_len = json.len(), "JSON output");
        assert_with_log!(
            !json.is_empty(),
            &format!("scenario {}: non-empty JSON", i + 1),
            "non-empty",
            json.len()
        );
    }

    test_complete!("e2e_divergence_category_classification");
}
