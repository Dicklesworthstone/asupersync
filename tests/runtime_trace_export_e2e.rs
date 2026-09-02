//! Behavioral proof that a production runtime's trace can be exported and
//! fed to the lab analysis tools.
//!
//! The README promises "trace capture/replay: debug production issues
//! locally". Until `Runtime::trace_snapshot` there was no public way to get
//! a production trace out of the runtime. This test spawns real tasks on a
//! production runtime, exports the trace, and asserts:
//!
//! - every spawned task has a `Spawn` and a `Complete` event carrying its
//!   task id (the same canonical schema the lab records);
//! - the lab analysis entry points accept the production trace:
//!   `normalize_trace_default` returns a trace of the same length, and
//!   `HappensBeforeGraph::from_trace` / `RaceDetector::from_trace` run on it;
//! - `RuntimeHandle::trace_snapshot` returns the same view;
//! - planted negative: a runtime that spawned nothing exports no `Spawn`
//!   event.
//!
//! No-claim: this does not prove schedule re-execution (replay of a
//! production interleaving in the lab is a separate gap), nor completeness
//! of the ring buffer beyond its configured capacity.

use asupersync::Cx;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::trace::{
    HappensBeforeGraph, RaceDetector, TraceData, TraceEvent, TraceEventKind,
    normalize_trace_default,
};
use asupersync::types::TaskId;

fn task_events<'a>(
    events: &'a [TraceEvent],
    kind: TraceEventKind,
    task_id: TaskId,
) -> impl Iterator<Item = &'a TraceEvent> + 'a {
    events.iter().filter(move |event| {
        event.kind == kind && matches!(event.data, TraceData::Task { task, .. } if task == task_id)
    })
}

#[test]
fn production_trace_exports_spawn_and_complete_for_every_task() {
    // Default trace storage profile: a 4096-event ring buffer.
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    let task_ids: Vec<TaskId> = runtime.block_on(async {
        let cx = Cx::current().expect("root cx");
        let mut handles = Vec::new();
        for i in 0..3u32 {
            let handle = cx
                .spawn(move |_task_cx| async move {
                    for _ in 0..2 {
                        yield_now().await;
                    }
                    i * 10
                })
                .expect("spawn");
            handles.push(handle);
        }
        let mut ids = Vec::new();
        for (i, mut handle) in handles.into_iter().enumerate() {
            let value = handle.join(&cx).await.expect("join");
            assert_eq!(value, (i as u32) * 10);
            // Canonical id only after admission, so read it after the join.
            ids.push(handle.task_id());
        }
        ids
    });

    let events = runtime.trace_snapshot();
    assert!(
        !events.is_empty(),
        "the production runtime must record trace events"
    );
    for task_id in &task_ids {
        assert!(
            task_events(&events, TraceEventKind::Spawn, *task_id)
                .next()
                .is_some(),
            "missing Spawn event for {task_id:?}"
        );
        assert!(
            task_events(&events, TraceEventKind::Complete, *task_id)
                .next()
                .is_some(),
            "missing Complete event for {task_id:?}"
        );
    }
    // Sequence numbers are strictly increasing in the exported order.
    assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));

    // The lab analysis tools accept the production trace as-is.
    let (normalized, result) = normalize_trace_default(&events);
    assert_eq!(
        normalized.len(),
        events.len(),
        "normalization must not lose events"
    );
    let _ = result;
    let graph = HappensBeforeGraph::from_trace(&events);
    let _ = graph;
    let detector = RaceDetector::from_trace(&events);
    // Three independent tasks that touch no shared resource: the detector
    // must at least run to completion; its race count is reported but not
    // asserted (see the DPOR clock-mode gap bead).
    let _ = detector.race_count();

    let via_handle = runtime
        .handle()
        .trace_snapshot()
        .expect("strong handle can snapshot");
    assert!(via_handle.len() >= events.len());
}

#[test]
fn runtime_that_spawned_nothing_exports_no_spawn_events_planted_negative() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(async {});
    let events = runtime.trace_snapshot();
    assert!(
        events
            .iter()
            .all(|event| event.kind != TraceEventKind::Spawn),
        "no task was spawned, so no Spawn event may appear: {events:?}"
    );
}
