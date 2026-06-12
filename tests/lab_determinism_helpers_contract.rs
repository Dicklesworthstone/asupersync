use asupersync::Budget;
use asupersync::lab::{
    DeterminismSourceHint, DeterminismViolation, LabRuntime, TraceEventSummary,
    assert_deterministic_for_seeds,
};
use asupersync::trace::TraceEventKind;
use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};

fn spawn_empty_task(runtime: &mut LabRuntime) {
    spawn_empty_tasks(runtime, 1);
}

fn spawn_empty_tasks(runtime: &mut LabRuntime, count: usize) {
    let root = runtime.state.create_root_region(Budget::INFINITE);
    for _ in 0..count {
        runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create deterministic task");
    }
    runtime.run_until_quiescent();
}

fn panic_payload_to_string(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    "<non-string panic>".to_string()
}

#[test]
fn seed_matrix_helper_accepts_stable_lab_program() {
    assert_deterministic_for_seeds([1, 2, 13, 55], spawn_empty_task);
}

#[test]
fn seed_matrix_helper_reports_seed_and_checklist_on_divergence() {
    let run_count = AtomicUsize::new(0);

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        assert_deterministic_for_seeds([99], |runtime| {
            let task_count = if run_count.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
                1
            } else {
                2
            };
            spawn_empty_tasks(runtime, task_count);
        });
    }));

    let panic = result.expect_err("same-seed divergence should panic");
    let message = panic_payload_to_string(panic);
    assert!(message.contains("seed 99"), "{message}");
    assert!(message.contains("[ASUP-E403]"), "{message}");
    assert!(message.contains("determinism.checklist."), "{message}");
}

#[test]
fn violation_display_includes_after_context_and_hint_metadata() {
    let violation = DeterminismViolation {
        divergence_index: 1,
        expected: Some(TraceEventSummary {
            seq: 1,
            time_nanos: 10,
            kind: TraceEventKind::TimeAdvance,
            data_summary: "old=0 new=10".to_string(),
        }),
        actual: Some(TraceEventSummary {
            seq: 1,
            time_nanos: 11,
            kind: TraceEventKind::TimerFired,
            data_summary: "timer=7".to_string(),
        }),
        context_before: vec![TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=start".to_string(),
        }],
        context_after_expected: vec![TraceEventSummary {
            seq: 2,
            time_nanos: 12,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=expected-after".to_string(),
        }],
        context_after_actual: vec![TraceEventSummary {
            seq: 2,
            time_nanos: 13,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=actual-after".to_string(),
        }],
        source_hint: DeterminismSourceHint::AmbientClock,
        trace1_len: 3,
        trace2_len: 3,
    };

    assert_eq!(
        DeterminismSourceHint::AmbientClock.checklist_item(),
        "determinism.checklist.ambient-clock"
    );

    let rendered = violation.to_string();
    assert!(rendered.contains("[ASUP-E403]"), "{rendered}");
    assert!(
        rendered.contains("determinism.checklist.ambient-clock"),
        "{rendered}"
    );
    assert!(
        rendered.contains("Expected context after divergence"),
        "{rendered}"
    );
    assert!(
        rendered.contains("Actual context after divergence"),
        "{rendered}"
    );
}
