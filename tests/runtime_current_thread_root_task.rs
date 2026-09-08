//! GH#58 (br-asupersync-94jh37): on a `RuntimeBuilder::current_thread()`
//! runtime the root future of `Runtime::block_on` is a real task driven on
//! the calling thread.
//!
//! The three reporter reproducers (A: task affinity, B: `spawn_local` from
//! the root, C: root liveness in quiescence accounting) are ported verbatim
//! in spirit, plus planted negatives (the multi-thread flavor still moves
//! spawned work off the caller) and controls (the runtime is quiescent once
//! `block_on` returns; root panics still propagate; `!Send` roots are
//! accepted; work spawned outside `block_on` still progresses).

use std::panic::AssertUnwindSafe;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use asupersync::Cx;
use asupersync::observability::TaskInspectorConfig;
use asupersync::runtime::{Runtime, RuntimeBuilder, yield_now};

/// Repro A: a task spawned from the root of a current-thread runtime runs
/// on the calling thread (Tokio `new_current_thread` semantics).
#[test]
fn current_thread_spawn_from_root_runs_on_calling_thread() {
    let caller = thread::current().id();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    let task = runtime.block_on(async {
        Runtime::current_handle()
            .expect("runtime handle is installed")
            .spawn(async { thread::current().id() })
            .await
    });

    assert_eq!(
        task, caller,
        "current_thread moved the task to another OS thread"
    );
}

/// Repro A, repeated: every `block_on` call re-borrows the worker for the
/// caller, including after the background thread resumed it in between.
#[test]
fn current_thread_repeated_block_on_keeps_spawned_work_on_caller() {
    let caller = thread::current().id();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    for round in 0..3 {
        let task = runtime.block_on(async {
            Runtime::current_handle()
                .expect("runtime handle is installed")
                .spawn(async { thread::current().id() })
                .await
        });
        assert_eq!(task, caller, "round {round}: task left the calling thread");
    }
}

/// Repro B: the root `Cx` of a current-thread runtime accepts a `!Send`
/// local task and joins it.
#[test]
fn current_thread_root_cx_accepts_spawn_local() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    let value = runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let state = Rc::new(41_u32);
        let mut task = cx
            .spawn_local(move |_| async move { *state + 1 })
            .expect("current_thread root must accept a local task");
        task.join(&cx).await.expect("local task completes")
    });

    assert_eq!(value, 42);
}

/// Repro B, thread affinity: the local task also runs on the calling thread.
#[test]
fn current_thread_spawn_local_from_root_runs_on_calling_thread() {
    let caller = thread::current().id();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    let task = runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let mut task = cx
            .spawn_local(|_| async { thread::current().id() })
            .expect("current_thread root must accept a local task");
        task.join(&cx).await.expect("local task completes")
    });

    assert_eq!(task, caller, "local task left the calling thread");
}

/// Repro C: the active root future is live work; the runtime is not
/// quiescent while it runs.
#[test]
fn current_thread_root_is_live_in_quiescence_accounting() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        assert!(
            !runtime.is_quiescent(),
            "active root task {:?} is absent from runtime liveness accounting",
            cx.task_id()
        );
    });
}

/// The root's `Cx::current()` names a task record that the inspector lists
/// in the root region while the root runs.
#[test]
fn current_thread_root_cx_is_a_registered_task() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let inspector = runtime.task_inspector(TaskInspectorConfig::default());
        let tasks = inspector.list_tasks();
        assert!(
            tasks.iter().any(|task| task.id == cx.task_id()),
            "root task {:?} has no task record; inspector lists {:?}",
            cx.task_id(),
            tasks.iter().map(|task| task.id).collect::<Vec<_>>()
        );
    });
}

/// Planted negative: the multi-thread flavor is unchanged — a task spawned
/// from the root runs on a scheduler worker, not on the calling thread.
#[test]
fn multi_thread_spawn_from_root_leaves_calling_thread() {
    let caller = thread::current().id();
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("build asupersync runtime");

    let task = runtime.block_on(async {
        Runtime::current_handle()
            .expect("runtime handle is installed")
            .spawn(async { thread::current().id() })
            .await
    });

    assert_ne!(
        task, caller,
        "multi_thread ran the spawned task on the calling thread"
    );
}

/// Control: once `block_on` returns, the root task has retired and the
/// runtime is quiescent (no leaked root record).
#[test]
fn current_thread_runtime_is_quiescent_after_block_on_returns() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    let value = runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let mut task = cx
            .spawn(|_| async { 40_u32 + 2 })
            .expect("root Cx has spawn authority");
        task.join(&cx).await.expect("task completes")
    });
    assert_eq!(value, 42);

    let tasks = runtime
        .task_inspector(TaskInspectorConfig::default())
        .list_tasks();
    assert!(
        runtime.is_quiescent(),
        "runtime not quiescent after block_on returned; inspector lists {:?}",
        tasks
            .iter()
            .map(|task| (task.id, task.state, task.poll_count))
            .collect::<Vec<_>>()
    );
}

/// Control: a panic in the root future still propagates out of `block_on`
/// with its original payload, and the runtime stays usable afterwards.
#[test]
fn current_thread_block_on_propagates_root_panic_and_stays_usable() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            yield_now().await;
            panic!("root boom");
        })
    }));
    let payload = outcome.expect_err("root panic must propagate out of block_on");
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("root boom"),
        "block_on must re-raise the root's own panic payload"
    );

    let value = runtime.block_on(async { 7_u8 });
    assert_eq!(value, 7, "runtime must stay usable after a root panic");
    assert!(
        runtime.is_quiescent(),
        "panicked root left the runtime non-quiescent"
    );
}

/// Control: the root future may be `!Send` and borrow the caller's stack.
#[test]
fn current_thread_block_on_accepts_non_send_root_future() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let local = String::from("borrowed");

    let value = runtime.block_on(async {
        let rc = Rc::new(20_u32);
        yield_now().await;
        let borrowed = &local;
        *rc * 2 + u32::try_from(borrowed.len()).expect("small length")
    });

    assert_eq!(value, 48);
}

/// Control: work spawned through a handle outside `block_on` still makes
/// progress (the background worker thread runs the worker between
/// `block_on` calls).
#[test]
fn current_thread_handle_spawn_outside_block_on_still_progresses() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let (tx, rx) = mpsc::channel();

    runtime.handle().spawn(async move {
        tx.send(thread::current().id()).expect("receiver alive");
    });

    let worker = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("task spawned outside block_on must run without block_on");
    assert_ne!(
        worker,
        thread::current().id(),
        "outside block_on the worker runs on the background thread"
    );
}
