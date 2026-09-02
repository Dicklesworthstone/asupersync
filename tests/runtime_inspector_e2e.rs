//! Behavioral proof that `TaskInspector` and `Diagnostics` are reachable from
//! a production `Runtime` and report live task state.
//!
//! What green proves: on a current-thread production runtime, a task that has
//! started running and is parked on an mpsc receive is visible to
//! `Runtime::task_inspector` in a non-terminal state;
//! `Runtime::diagnostics().explain_task_blocked` classifies it as something
//! other than unknown; `RuntimeHandle` exposes the same views; after the task
//! is released, joined, and reaped its id is reported absent (the planted
//! negative); and a task cancelled with an explicit reason has that reason
//! reproduced by `explain_cancellation`.
//!
//! Two runtime facts shape the test: a current-thread runtime only makes
//! progress while `block_on` is driving it, so every probe runs inside the
//! driven future and yields between probes; and `TaskHandle::task_id()` is a
//! provisional mailbox id until admission has run, so it is re-read rather than
//! captured once. "Has been polled" is proven by a flag the task itself sets,
//! not by the record's `poll_count`, which stayed at 0 here for a task that
//! had provably run (the production dispatch path does not advance it).
//!
//! No-claim: this does not prove lock-metrics, spectral-health accuracy,
//! multi-worker race freedom, or the sharded state shape (the runtime here is
//! the default unified shape).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::observability::{BlockReason, TaskInspector, TaskInspectorConfig, TaskStateInfo};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::types::{CancelKind, CancelReason, TaskId};

/// Upper bound on cooperative yields while waiting for a condition; each
/// yield lets the single worker run other tasks once.
const MAX_YIELDS: usize = 20_000;

async fn yield_until(mut probe: impl FnMut() -> bool) -> bool {
    for _ in 0..MAX_YIELDS {
        if probe() {
            return true;
        }
        yield_now().await;
    }
    probe()
}

fn is_terminal(state: &TaskStateInfo) -> bool {
    matches!(state, TaskStateInfo::Completed { .. })
}

fn describe(inspector: &TaskInspector) -> Vec<(TaskId, TaskStateInfo, u64)> {
    inspector
        .list_tasks()
        .iter()
        .map(|task| (task.id, task.state.clone(), task.poll_count))
        .collect()
}

#[test]
fn production_runtime_inspector_reports_parked_task_then_absence_after_reap() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");
    let inspector = runtime.task_inspector(TaskInspectorConfig::default());
    let diagnostics = runtime.diagnostics();
    let handle_inspector = runtime
        .handle()
        .task_inspector(TaskInspectorConfig::default())
        .expect("a strong runtime handle can build an inspector");
    let handle_diagnostics = runtime
        .handle()
        .diagnostics()
        .expect("a strong runtime handle can build diagnostics");
    let (tx, mut rx) = mpsc::channel::<u8>(1);
    let started = Arc::new(AtomicBool::new(false));

    let received = runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a root Cx");
        let started_flag = Arc::clone(&started);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                started_flag.store(true, Ordering::SeqCst);
                rx.recv(&task_cx).await.ok()
            })
            .expect("spawn parked task");

        // The task proves it ran; the inspector must then see it live.
        let running = yield_until(|| {
            started.load(Ordering::SeqCst) && inspector.inspect_task(handle.task_id()).is_some()
        })
        .await;
        assert!(
            running,
            "the parked task must run and be visible to the inspector; started = {}, handle id = {:?}, visible = {:?}",
            started.load(Ordering::SeqCst),
            handle.task_id(),
            describe(&inspector)
        );
        let task_id = handle.task_id();

        let details = inspector
            .inspect_task(task_id)
            .expect("live task details for the parked task");
        assert_eq!(details.id, task_id);
        assert!(
            !is_terminal(&details.state),
            "a task parked on recv must not be terminal: {:?}",
            details.state
        );
        assert!(
            inspector.list_tasks().iter().any(|task| task.id == task_id),
            "list_tasks must include the parked task"
        );
        let blocked = diagnostics.explain_task_blocked(task_id);
        assert!(
            !matches!(blocked.block_reason, BlockReason::TaskNotFound),
            "the live parked task must not be reported as unknown: {:?}",
            blocked.block_reason
        );
        // The same views are reachable through a runtime handle.
        assert!(handle_inspector.inspect_task(task_id).is_some());
        assert!(!matches!(
            handle_diagnostics.explain_task_blocked(task_id).block_reason,
            BlockReason::TaskNotFound
        ));

        // Release the task and join it.
        let permit = tx.reserve(&cx).await.expect("reserve channel capacity");
        let _ = permit.send(7);
        let received = handle.join(&cx).await.expect("join released task");

        // Planted negative: once the completed task has been reaped, the id
        // that was live a moment ago must be reported absent by both engines.
        let absent = yield_until(|| inspector.inspect_task(task_id).is_none()).await;
        assert!(
            absent,
            "a completed and reaped task must disappear from the inspector; visible = {:?}",
            describe(&inspector)
        );
        assert!(matches!(
            diagnostics.explain_task_blocked(task_id).block_reason,
            BlockReason::TaskNotFound
        ));
        assert!(diagnostics.explain_cancellation(task_id).is_none());
        received
    });
    assert_eq!(received, Some(7));
}

#[test]
fn production_runtime_diagnostics_explains_a_cancelled_task() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");
    let inspector = runtime.task_inspector(TaskInspectorConfig::default());
    let diagnostics = runtime.diagnostics();
    let started = Arc::new(AtomicBool::new(false));
    let observed_cancel = Arc::new(AtomicBool::new(false));

    runtime.block_on(async {
        let cx = Cx::current().expect("root cx");
        let started_flag = Arc::clone(&started);
        let observed_flag = Arc::clone(&observed_cancel);
        let handle = cx
            .spawn(move |task_cx| async move {
                started_flag.store(true, Ordering::SeqCst);
                // Cooperate with cancellation, then stay parked so the record
                // (and its recorded cancel reason) remains observable.
                loop {
                    if task_cx.checkpoint().is_err() {
                        observed_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                    yield_now().await;
                }
                std::future::pending::<()>().await;
            })
            .expect("spawn cooperative task");

        let running = yield_until(|| {
            started.load(Ordering::SeqCst) && inspector.inspect_task(handle.task_id()).is_some()
        })
        .await;
        assert!(
            running,
            "cooperative task must run and be visible; handle id = {:?}, visible = {:?}",
            handle.task_id(),
            describe(&inspector)
        );
        let task_id = handle.task_id();
        assert!(
            diagnostics.explain_cancellation(task_id).is_none(),
            "no cancellation has been requested yet"
        );

        handle.abort_with_reason(CancelReason::user("inspector-e2e cancel"));

        let explained = yield_until(|| {
            observed_cancel.load(Ordering::SeqCst)
                && diagnostics.explain_cancellation(task_id).is_some()
        })
        .await;
        assert!(
            explained,
            "the task must observe cancellation and the recorded reason must become observable; \
             observed = {}, visible = {:?}",
            observed_cancel.load(Ordering::SeqCst),
            describe(&inspector)
        );
        let explanation = diagnostics
            .explain_cancellation(task_id)
            .expect("cancellation explanation");
        assert_eq!(explanation.kind, CancelKind::User);
        assert_eq!(
            explanation.message.as_deref(),
            Some("inspector-e2e cancel"),
            "the explanation must carry the exact reason message"
        );
        assert!(
            !explanation.propagation_path.is_empty(),
            "a directly cancelled task yields at least one propagation step"
        );
        // The task is left parked on purpose; runtime teardown aborts it.
    });
}
