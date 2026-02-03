#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::trace::{
    Breakpoint, CompactTaskId, ReplayError, ReplayEvent, ReplayMode, ReplayTrace, TraceMetadata,
    TraceReader, TraceReplayer, TraceWriter,
};
use asupersync::types::Budget;
use common::*;
use tempfile::NamedTempFile;

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

    runtime.scheduler.lock().unwrap().schedule(task_a, 0);
    runtime.scheduler.lock().unwrap().schedule(task_b, 0);

    runtime.run_until_quiescent();

    runtime.finish_replay_trace().expect("replay trace")
}

#[test]
fn trace_file_roundtrip_matches_recorded_events() {
    init_test("trace_file_roundtrip_matches_recorded_events");
    test_section!("record");
    let trace = record_simple_trace();

    test_section!("write");
    let temp = NamedTempFile::new().expect("tempfile");
    let path = temp.path();
    let mut writer = TraceWriter::create(path).expect("create writer");
    writer
        .write_metadata(&trace.metadata)
        .expect("write metadata");
    for event in &trace.events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish writer");

    test_section!("read");
    let reader = TraceReader::open(path).expect("open reader");
    let metadata = reader.metadata().clone();
    let event_count = reader.event_count();
    let events: Vec<_> = reader
        .events()
        .map(|event| event.expect("read event"))
        .collect();

    test_section!("verify");
    assert_with_log!(
        metadata.seed == trace.metadata.seed,
        "seed roundtrip",
        trace.metadata.seed,
        metadata.seed
    );
    assert_with_log!(
        event_count == trace.len() as u64,
        "event count",
        trace.len() as u64,
        event_count
    );
    assert_with_log!(
        events == trace.events,
        "events roundtrip",
        trace.events.len(),
        events.len()
    );
    test_complete!("trace_file_roundtrip_matches_recorded_events");
}

#[test]
fn replayer_verifies_full_trace_sequence() {
    init_test("replayer_verifies_full_trace_sequence");
    test_section!("record");
    let trace = record_simple_trace();

    test_section!("replay");
    let mut replayer = TraceReplayer::new(trace.clone());
    for event in &trace.events {
        replayer
            .verify_and_advance(event)
            .expect("verify and advance");
    }

    test_section!("verify");
    assert_with_log!(
        replayer.is_completed(),
        "replayer completed",
        true,
        replayer.is_completed()
    );
    test_complete!("replayer_verifies_full_trace_sequence");
}

#[test]
fn replayer_detects_divergence() {
    init_test("replayer_detects_divergence");
    test_section!("setup");
    let mut trace = ReplayTrace::new(TraceMetadata::new(7));
    trace.push(ReplayEvent::RngSeed { seed: 7 });
    trace.push(ReplayEvent::TaskScheduled {
        task: CompactTaskId(1),
        at_tick: 0,
    });

    test_section!("diverge");
    let mut replayer = TraceReplayer::new(trace);
    let bad_event = ReplayEvent::RngSeed { seed: 999 };
    let err = replayer
        .verify_and_advance(&bad_event)
        .expect_err("expected divergence");

    test_section!("verify");
    let is_divergence = matches!(err, ReplayError::Divergence(_));
    assert_with_log!(is_divergence, "divergence error", true, is_divergence);
    test_complete!("replayer_detects_divergence");
}

#[test]
fn replayer_run_to_breakpoint() {
    init_test("replayer_run_to_breakpoint");
    test_section!("setup");
    let mut trace = ReplayTrace::new(TraceMetadata::new(99));
    trace.push(ReplayEvent::RngSeed { seed: 99 });
    trace.push(ReplayEvent::TaskScheduled {
        task: CompactTaskId(1),
        at_tick: 0,
    });
    trace.push(ReplayEvent::TaskCompleted {
        task: CompactTaskId(1),
        outcome: 0,
    });

    test_section!("run");
    let mut replayer = TraceReplayer::new(trace);
    replayer.set_mode(ReplayMode::RunTo(Breakpoint::EventIndex(1)));
    let processed = replayer.run().expect("run");

    test_section!("verify");
    assert_with_log!(processed > 0, "processed", "> 0", processed);
    assert_with_log!(
        replayer.at_breakpoint(),
        "at breakpoint",
        true,
        replayer.at_breakpoint()
    );
    test_complete!("replayer_run_to_breakpoint");
}

#[test]
fn e2e_debugging_workflow_record_save_load_step() {
    init_test("e2e_debugging_workflow_record_save_load_step");

    // Phase 1: Record execution
    test_section!("record");
    let trace = record_simple_trace();
    let event_count = trace.len();
    tracing::info!(event_count, "Recorded trace");
    assert!(event_count > 0, "must record events");

    // Phase 2: Persist trace to file
    test_section!("persist");
    let temp = NamedTempFile::new().expect("tempfile");
    let path = temp.path();
    let mut writer = TraceWriter::create(path).expect("create writer");
    writer
        .write_metadata(&trace.metadata)
        .expect("write metadata");
    for event in &trace.events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish writer");
    tracing::info!(?path, "Trace persisted to file");

    // Phase 3: Load trace from file (simulating later debug session)
    test_section!("load");
    let reader = TraceReader::open(path).expect("open reader");
    let loaded_metadata = reader.metadata().clone();
    let loaded_events: Vec<_> = reader.events().map(|e| e.expect("read event")).collect();
    let loaded_trace = ReplayTrace {
        metadata: loaded_metadata,
        events: loaded_events,
        cursor: 0,
    };
    tracing::info!(events = loaded_trace.len(), "Loaded trace from file");

    // Phase 4: Step through events one by one (debugging workflow)
    test_section!("step-through");
    let mut replayer = TraceReplayer::new(loaded_trace);
    let mut stepped = 0;
    while let Ok(Some(_event)) = replayer.step() {
        stepped += 1;
        tracing::debug!(
            index = replayer.current_index(),
            remaining = replayer.remaining_events().len(),
            "Stepped event"
        );
    }
    assert_with_log!(
        stepped == event_count,
        "stepped all events",
        event_count,
        stepped
    );
    assert_with_log!(
        replayer.is_completed(),
        "replayer completed",
        true,
        replayer.is_completed()
    );

    // Phase 5: Seek back and set breakpoint (interactive debugging)
    test_section!("seek-and-breakpoint");
    replayer.reset();
    assert_with_log!(
        replayer.current_index() == 0,
        "reset to start",
        0usize,
        replayer.current_index()
    );

    let mid = event_count / 2;
    if mid > 0 {
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::EventIndex(mid)));
        let processed = replayer.run().expect("run to midpoint");
        tracing::info!(processed, mid, "Hit breakpoint at midpoint");
        assert_with_log!(
            replayer.at_breakpoint(),
            "at midpoint breakpoint",
            true,
            replayer.at_breakpoint()
        );
    }

    test_complete!("e2e_debugging_workflow_record_save_load_step");
}
