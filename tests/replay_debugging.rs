#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::test_logging::{load_repro_manifest, replay_context_from_manifest};
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

    runtime.scheduler.lock().schedule(task_a, 0);
    runtime.scheduler.lock().schedule(task_b, 0);

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

/// Verifies the artifact → seed → run pipeline: record a trace, persist it,
/// extract the seed from the artifact, and re-run with the same seed to get
/// an identical trace.
#[test]
fn artifact_seed_extraction_and_deterministic_rerun() {
    init_test("artifact_seed_extraction_and_deterministic_rerun");

    // Phase 1: Record with a specific seed
    test_section!("record-first");
    let seed = 0xBEEF_CAFE;
    let config = LabConfig::new(seed).with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task, 0);
    runtime.run_until_quiescent();
    let trace1 = runtime.finish_replay_trace().expect("first trace");

    // Phase 2: Persist to file
    test_section!("persist");
    let temp = NamedTempFile::new().expect("tempfile");
    let path = temp.path();
    let mut writer = TraceWriter::create(path).expect("create writer");
    writer
        .write_metadata(&trace1.metadata)
        .expect("write metadata");
    for event in &trace1.events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish");

    // Phase 3: Extract seed from artifact
    test_section!("extract-seed");
    let reader = TraceReader::open(path).expect("open reader");
    let extracted_seed = reader.metadata().seed;
    assert_with_log!(
        extracted_seed == seed,
        "seed extracted from artifact",
        seed,
        extracted_seed
    );

    // Phase 4: Re-run with extracted seed
    test_section!("rerun");
    let config2 = LabConfig::new(extracted_seed).with_default_replay_recording();
    let mut runtime2 = LabRuntime::new(config2);
    let region2 = runtime2.state.create_root_region(Budget::INFINITE);
    let (task2, _handle2) = runtime2
        .state
        .create_task(region2, Budget::INFINITE, async {})
        .expect("create task");
    runtime2.scheduler.lock().schedule(task2, 0);
    runtime2.run_until_quiescent();
    let trace2 = runtime2.finish_replay_trace().expect("second trace");

    // Phase 5: Verify traces are identical
    test_section!("verify-determinism");
    assert_with_log!(
        trace1.events.len() == trace2.events.len(),
        "event count matches",
        trace1.events.len(),
        trace2.events.len()
    );
    assert_with_log!(
        trace1.events == trace2.events,
        "events are identical",
        trace1.events.len(),
        trace2.events.len()
    );

    test_complete!("artifact_seed_extraction_and_deterministic_rerun");
}

/// Verifies that loading a trace from file and replaying it through the
/// verifier produces no divergence — confirming the trace is self-consistent.
#[test]
fn loaded_trace_verifies_against_itself() {
    init_test("loaded_trace_verifies_against_itself");

    test_section!("record-and-persist");
    let trace = record_simple_trace();
    let temp = NamedTempFile::new().expect("tempfile");
    let path = temp.path();
    let mut writer = TraceWriter::create(path).expect("create writer");
    writer
        .write_metadata(&trace.metadata)
        .expect("write metadata");
    for event in &trace.events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish");

    test_section!("load-and-verify");
    let reader = TraceReader::open(path).expect("open reader");
    let metadata = reader.metadata().clone();
    let loaded_events: Vec<_> = reader.events().map(|e| e.expect("read event")).collect();
    let loaded_trace = ReplayTrace {
        metadata,
        events: loaded_events.clone(),
        cursor: 0,
    };

    let mut replayer = TraceReplayer::new(loaded_trace);
    for event in &loaded_events {
        replayer
            .verify_and_advance(event)
            .expect("verify should not diverge on self-consistent trace");
    }

    test_section!("final-check");
    assert_with_log!(
        replayer.is_completed(),
        "replayer completed",
        true,
        replayer.is_completed()
    );

    test_complete!("loaded_trace_verifies_against_itself");
}

// =========================================================================
// Failure Triage Pipeline: capture → manifest → replay (bd-1ex7)
// =========================================================================

/// End-to-end test: record a trace, save a ReproManifest, reload it, and
/// verify the replay produces the same events.
#[test]
fn failure_triage_capture_manifest_replay_roundtrip() {
    init_test("failure_triage_capture_manifest_replay_roundtrip");

    // Phase 1: Record a trace with a known seed.
    test_section!("capture");
    let seed = 0xDEAD_BEEF_u64;
    let config = LabConfig::new(seed).with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let (task_a, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task a");
    let (task_b, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task b");

    runtime.scheduler.lock().schedule(task_a, 0);
    runtime.scheduler.lock().schedule(task_b, 0);
    runtime.run_until_quiescent();

    let trace = runtime.finish_replay_trace().expect("capture trace");
    let event_count = trace.events.len();
    assert_with_log!(event_count > 0, "captured events", true, event_count > 0);

    // Phase 2: Create and persist a ReproManifest.
    test_section!("manifest");
    let ctx = TestContext::new("cancel_drain_scenario", seed)
        .with_subsystem("scheduler")
        .with_invariant("quiescence");
    let mut manifest = ReproManifest::from_context(&ctx, false);
    manifest.trace_fingerprint = Some(format!("{event_count}_events"));

    let tmp = tempfile::tempdir().expect("tempdir");
    let manifest_path = manifest.write_to_dir(tmp.path()).expect("write manifest");

    // Phase 3: Load manifest and recreate context.
    test_section!("reload");
    let loaded = load_repro_manifest(&manifest_path).expect("load manifest");
    assert_with_log!(
        loaded.seed == seed,
        "manifest seed preserved",
        seed,
        loaded.seed
    );
    assert_with_log!(
        loaded.scenario_id == "cancel_drain_scenario",
        "scenario_id preserved",
        "cancel_drain_scenario",
        loaded.scenario_id
    );
    assert_with_log!(
        loaded.subsystem.as_deref() == Some("scheduler"),
        "subsystem preserved",
        Some("scheduler"),
        loaded.subsystem.as_deref()
    );

    let replay_ctx = replay_context_from_manifest(&loaded);
    assert_with_log!(
        replay_ctx.seed == seed,
        "replay context seed",
        seed,
        replay_ctx.seed
    );

    // Phase 4: Replay - re-run with same seed and verify events match.
    test_section!("replay");
    let replay_config = LabConfig::new(replay_ctx.seed).with_default_replay_recording();
    let mut replay_runtime = LabRuntime::new(replay_config);
    let replay_region = replay_runtime.state.create_root_region(Budget::INFINITE);

    let (replay_task_a, _) = replay_runtime
        .state
        .create_task(replay_region, Budget::INFINITE, async {})
        .expect("replay task a");
    let (replay_task_b, _) = replay_runtime
        .state
        .create_task(replay_region, Budget::INFINITE, async {})
        .expect("replay task b");

    replay_runtime.scheduler.lock().schedule(replay_task_a, 0);
    replay_runtime.scheduler.lock().schedule(replay_task_b, 0);
    replay_runtime.run_until_quiescent();

    let replay_trace = replay_runtime.finish_replay_trace().expect("replay trace");

    // Verify event counts match (deterministic replay).
    assert_with_log!(
        replay_trace.events.len() == event_count,
        "replay event count matches",
        event_count,
        replay_trace.events.len()
    );

    // Verify events can be replayed against original.
    let mut replayer = TraceReplayer::new(trace);
    for event in &replay_trace.events {
        replayer
            .verify_and_advance(event)
            .expect("events should match between runs with same seed");
    }
    assert_with_log!(
        replayer.is_completed(),
        "all events replayed",
        true,
        replayer.is_completed()
    );

    test_complete!("failure_triage_capture_manifest_replay_roundtrip");
}

/// Test that a ReproManifest roundtrips through write + load preserving all fields.
#[test]
fn manifest_write_load_preserves_all_fields() {
    init_test("manifest_write_load_preserves_all_fields");
    let mut manifest = ReproManifest::new(0xCAFE_BABE, "full_field_test", false);
    manifest.entropy_seed = Some(0x1234);
    manifest.config_hash = Some("cfg_abc".to_string());
    manifest.trace_fingerprint = Some("fp_42".to_string());
    manifest.input_digest = Some("sha256:deadbeef".to_string());
    manifest.oracle_violations = vec!["leak_detected".to_string(), "timeout".to_string()];
    manifest.subsystem = Some("obligation".to_string());
    manifest.invariant = Some("no_leaks".to_string());
    manifest.trace_file = Some("traces/run_42.bin".to_string());
    manifest.input_file = Some("inputs/scenario_1.json".to_string());

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = manifest.write_to_dir(tmp.path()).expect("write");

    let loaded = load_repro_manifest(&path).expect("load");
    assert_with_log!(
        loaded.schema_version == ARTIFACT_SCHEMA_VERSION,
        "schema version",
        ARTIFACT_SCHEMA_VERSION,
        loaded.schema_version
    );
    assert_with_log!(
        loaded.seed == 0xCAFE_BABE,
        "seed",
        0xCAFE_BABEu64,
        loaded.seed
    );
    assert_with_log!(
        loaded.entropy_seed == Some(0x1234),
        "entropy_seed",
        Some(0x1234u64),
        loaded.entropy_seed
    );
    assert_with_log!(
        loaded.config_hash.as_deref() == Some("cfg_abc"),
        "config_hash",
        Some("cfg_abc"),
        loaded.config_hash.as_deref()
    );
    assert_with_log!(
        loaded.oracle_violations.len() == 2,
        "oracle violations count",
        2,
        loaded.oracle_violations.len()
    );
    assert_with_log!(
        loaded.trace_file.as_deref() == Some("traces/run_42.bin"),
        "trace_file",
        Some("traces/run_42.bin"),
        loaded.trace_file.as_deref()
    );
    assert_with_log!(!loaded.passed, "failed status", false, loaded.passed);

    test_complete!("manifest_write_load_preserves_all_fields");
}

/// Test that replay_context_from_manifest produces a valid context for re-execution.
#[test]
fn replay_context_reproduces_with_same_seed() {
    init_test("replay_context_reproduces_with_same_seed");

    // Run a lab with a specific seed and capture the trace.
    let seed = 0x5EED_1234_u64;
    let config = LabConfig::new(seed).with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let (task, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task, 0);
    runtime.run_until_quiescent();
    let original_trace = runtime.finish_replay_trace().expect("trace");

    // Create manifest and context.
    let manifest = ReproManifest::new(seed, "repro_test", true);
    let ctx = replay_context_from_manifest(&manifest);

    // Verify derived seeds are deterministic.
    let comp_seed_a = ctx.component_seed("scheduler");
    let comp_seed_b = ctx.component_seed("scheduler");
    assert_with_log!(
        comp_seed_a == comp_seed_b,
        "component seed deterministic",
        comp_seed_a,
        comp_seed_b
    );

    // Re-run with the same seed from the manifest context.
    let replay_config = LabConfig::new(ctx.seed).with_default_replay_recording();
    let mut replay_rt = LabRuntime::new(replay_config);
    let replay_region = replay_rt.state.create_root_region(Budget::INFINITE);
    let (replay_task, _) = replay_rt
        .state
        .create_task(replay_region, Budget::INFINITE, async {})
        .expect("replay task");
    replay_rt.scheduler.lock().schedule(replay_task, 0);
    replay_rt.run_until_quiescent();
    let replay_trace = replay_rt.finish_replay_trace().expect("replay trace");

    // Event counts should be identical (determinism from seed).
    assert_with_log!(
        original_trace.events.len() == replay_trace.events.len(),
        "event count matches via seed replay",
        original_trace.events.len(),
        replay_trace.events.len()
    );

    test_complete!("replay_context_reproduces_with_same_seed");
}

/// Test the trace file persistence + replayer integration (write → read → verify).
#[test]
fn trace_file_persistence_and_replayer_verify() {
    init_test("trace_file_persistence_and_replayer_verify");

    test_section!("capture");
    let trace = record_simple_trace();
    let event_count = trace.events.len();

    test_section!("persist");
    let tmp = NamedTempFile::new().expect("tempfile");
    let path = tmp.path();
    let mut writer = TraceWriter::create(path).expect("create writer");
    writer
        .write_metadata(&trace.metadata)
        .expect("write metadata");
    for event in &trace.events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish");

    test_section!("load");
    let reader = TraceReader::open(path).expect("open reader");
    let loaded_meta = reader.metadata().clone();
    let loaded_events: Vec<ReplayEvent> = reader.events().map(|e| e.expect("read event")).collect();

    assert_with_log!(
        loaded_meta.seed == trace.metadata.seed,
        "metadata seed preserved through file",
        trace.metadata.seed,
        loaded_meta.seed
    );
    assert_with_log!(
        loaded_events.len() == event_count,
        "event count preserved through file",
        event_count,
        loaded_events.len()
    );

    test_section!("verify");
    let loaded_trace = ReplayTrace {
        metadata: loaded_meta,
        events: loaded_events.clone(),
        cursor: 0,
    };
    let mut replayer = TraceReplayer::new(loaded_trace);
    for event in &loaded_events {
        replayer
            .verify_and_advance(event)
            .expect("loaded events verify against themselves");
    }
    assert_with_log!(
        replayer.is_completed(),
        "replayer exhausted all events",
        true,
        replayer.is_completed()
    );

    test_complete!("trace_file_persistence_and_replayer_verify");
}
