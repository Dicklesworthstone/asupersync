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

use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::observability::TaskInspectorConfig;
use asupersync::runtime::{Runtime, RuntimeBuilder, yield_now};
use asupersync::sync::{LockError, Mutex, OwnedMutexGuard};

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
        "runtime not quiescent after block_on returned; inspector lists {tasks:?}"
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

/// Drain contract: tasks spawned from the root and never awaited are
/// polled to completion before `block_on` returns (runnable work is
/// drained; only work parked on external events stays parked).
#[test]
fn current_thread_block_on_drains_unawaited_spawns_before_returning() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let completed = Arc::new(AtomicUsize::new(0));

    runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        for _ in 0..4 {
            let completed = Arc::clone(&completed);
            // Dropping the handle detaches the task; nothing awaits it.
            let _detached = cx
                .spawn(move |_| async move {
                    for _ in 0..3 {
                        yield_now().await;
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .expect("root Cx has spawn authority");
        }
        let _detached = Runtime::current_handle()
            .expect("runtime handle is installed")
            .spawn({
                let completed = Arc::clone(&completed);
                async move {
                    yield_now().await;
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            });
    });

    assert_eq!(
        completed.load(Ordering::SeqCst),
        5,
        "unawaited root spawns must be polled to completion before block_on returns"
    );
    assert!(
        runtime.is_quiescent(),
        "drained runtime must be quiescent once block_on returned"
    );
}

/// Drain contract for `!Send` work: an unawaited `spawn_local` from the
/// root also completes before `block_on` returns, on the calling thread.
#[test]
fn current_thread_block_on_drains_unawaited_spawn_local_before_returning() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let completed = Rc::new(Cell::new(0_u32));

    runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let completed = Rc::clone(&completed);
        let _detached = cx
            .spawn_local(move |_| async move {
                for _ in 0..3 {
                    yield_now().await;
                }
                completed.set(completed.get() + 1);
            })
            .expect("current_thread root must accept a local task");
    });

    assert_eq!(
        completed.get(),
        1,
        "unawaited local root spawn must be polled to completion before block_on returns"
    );
    assert!(
        runtime.is_quiescent(),
        "drained runtime must be quiescent once block_on returned"
    );
}

/// Regression for the first caller-driven implementation (swept to main as
/// b07a58fd7, 2026-09-08): a `!Send` task spawned from the root, parked on
/// a cancel-aware mutex, aborted and joined — all inside one `block_on` —
/// must complete within a bound. In that implementation a local future
/// could end up in the thread-local store of a thread other than the one
/// executing the worker; the abort's cancel dispatch then found no future
/// and was dropped, so the join never resolved.
#[test]
fn current_thread_abort_of_parked_local_task_from_root_completes_within_bound() {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build asupersync runtime");
        let typed_cancellation = runtime.block_on(async {
            let cx = Cx::current().expect("root Cx is installed");
            let mutex = Arc::new(Mutex::new(()));
            let holder = mutex
                .try_lock_owned()
                .expect("seed mutex must be available");
            let waiter_mutex = Arc::clone(&mutex);
            let mut waiter = cx
                .spawn_local(move |waiter_cx| async move {
                    OwnedMutexGuard::lock(waiter_mutex, &waiter_cx)
                        .await
                        .map(drop)
                })
                .expect("current_thread root must accept a local task");

            for _ in 0..256 {
                if mutex.waiters() == 1 {
                    break;
                }
                yield_now().await;
            }
            assert_eq!(
                mutex.waiters(),
                1,
                "local waiter must be genuinely parked before abort"
            );

            waiter.abort();
            let result = waiter.join(&cx).await;
            assert_eq!(
                mutex.waiters(),
                0,
                "abort must unlink the parked local waiter before the holder unlocks"
            );
            drop(holder);
            matches!(result, Ok(Err(LockError::Cancelled)))
        });
        let _ = tx.send(typed_cancellation);
    });

    let typed_cancellation = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("abort + join of a parked local task from the root must complete within 10 s");
    assert!(
        typed_cancellation,
        "abort of a parked local task must join as the mutex's typed cancellation"
    );
}

/// Proves the background worker thread has resumed the worker: a task
/// spawned through a handle from outside `block_on` runs and reports back.
fn wait_for_background_dispatch(runtime: &Runtime, what: &str) {
    let (tx, rx) = mpsc::channel();
    runtime.handle().spawn(async move {
        tx.send(()).expect("receiver alive");
    });
    rx.recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("background worker did not dispatch: {what}"));
}

/// Joins every handle from inside a fresh `block_on`, polling with a bound;
/// returns how many completed with the expected value.
fn join_all_within(
    runtime: &Runtime,
    handles: Vec<asupersync::runtime::TaskHandle<u32>>,
    bound: Duration,
) -> usize {
    runtime.block_on(async move {
        let deadline = Instant::now() + bound;
        let mut pending = handles;
        let mut completed = 0;
        while !pending.is_empty() && Instant::now() < deadline {
            let mut still_pending = Vec::with_capacity(pending.len());
            for mut handle in pending {
                match handle.try_join() {
                    Ok(Some(value)) => {
                        assert_eq!(value, 42, "surviving local task returned a wrong value");
                        completed += 1;
                    }
                    Ok(None) => still_pending.push(handle),
                    Err(error) => panic!("surviving local task failed: {error}"),
                }
            }
            pending = still_pending;
            if !pending.is_empty() {
                yield_now().await;
            }
        }
        completed
    })
}

/// CopperOak survive probe (2026-09-08), ported: a `!Send` task admitted
/// inside `block_on` and still pending when it returns; the background
/// worker resumes; the task is made ready and woken from outside; `block_on`
/// is re-entered and the join must complete. On the swept state the wake
/// was consumed on the background thread, which does not hold the future,
/// and dropped ("ready local task lost progress after worker handover").
#[test]
fn current_thread_local_task_survives_worker_handover() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let started = Rc::new(Cell::new(false));
    let ready = Rc::new(Cell::new(false));
    let wake = Rc::new(RefCell::new(None::<Waker>));

    let handle = runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let task_started = Rc::clone(&started);
        let task_ready = Rc::clone(&ready);
        let task_wake = Rc::clone(&wake);
        let handle = cx
            .spawn_local(move |_| async move {
                poll_fn(|ctx| {
                    task_started.set(true);
                    if task_ready.get() {
                        Poll::Ready(42_u32)
                    } else {
                        *task_wake.borrow_mut() = Some(ctx.waker().clone());
                        Poll::Pending
                    }
                })
                .await
            })
            .expect("current_thread root must accept a local task");
        while !started.get() {
            yield_now().await;
        }
        handle
    });
    assert!(started.get());
    assert!(
        !handle.is_finished(),
        "pending local task must survive the first block_on"
    );

    wait_for_background_dispatch(&runtime, "after the first block_on returned");
    ready.set(true);
    wake.borrow_mut()
        .take()
        .expect("pending task registered a waker")
        .wake();
    wait_for_background_dispatch(&runtime, "after the local wake");

    let completed = join_all_within(&runtime, vec![handle], Duration::from_secs(2));
    assert_eq!(
        completed, 1,
        "ready local task lost progress after worker handover"
    );
}

/// Same shape with more pending local tasks than the first implementation's
/// stranded-wake cap (256): every wake consumed on the background thread
/// must be preserved and honoured on re-entry.
#[test]
fn current_thread_more_than_256_stranded_local_wakes_survive_handover() {
    const LOCAL_TASKS: usize = 300;
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let started = Rc::new(Cell::new(0_usize));
    let ready = Rc::new(Cell::new(false));
    let wakers = Rc::new(RefCell::new(Vec::<Waker>::with_capacity(LOCAL_TASKS)));

    let handles = runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let mut handles = Vec::with_capacity(LOCAL_TASKS);
        for _ in 0..LOCAL_TASKS {
            let task_started = Rc::clone(&started);
            let task_ready = Rc::clone(&ready);
            let task_wakers = Rc::clone(&wakers);
            let mut registered = false;
            let handle = cx
                .spawn_local(move |_| async move {
                    poll_fn(|ctx| {
                        if !registered {
                            registered = true;
                            task_started.set(task_started.get() + 1);
                        }
                        if task_ready.get() {
                            Poll::Ready(42_u32)
                        } else {
                            task_wakers.borrow_mut().push(ctx.waker().clone());
                            Poll::Pending
                        }
                    })
                    .await
                })
                .expect("current_thread root must accept a local task");
            handles.push(handle);
        }
        while started.get() < LOCAL_TASKS {
            yield_now().await;
        }
        handles
    });
    assert_eq!(started.get(), LOCAL_TASKS);
    assert!(handles.iter().all(|handle| !handle.is_finished()));

    wait_for_background_dispatch(&runtime, "after the first block_on returned");
    ready.set(true);
    let woken = wakers.borrow_mut().drain(..).collect::<Vec<_>>();
    assert!(
        woken.len() >= LOCAL_TASKS,
        "every pending local task must have registered a waker"
    );
    for waker in woken {
        waker.wake();
    }
    wait_for_background_dispatch(&runtime, "after the local wakes");

    let completed = join_all_within(&runtime, handles, Duration::from_secs(5));
    assert_eq!(
        completed, LOCAL_TASKS,
        "local wakes consumed while the background thread ran the worker must not be lost"
    );
}

/// CopperOak nested probe (2026-09-08), ported: two distinct current-thread
/// runtimes nested on one thread. Both roots are real tasks and both root
/// records retire; on the swept state the inner root's `!Send` stub
/// displaced the outer's in the shared thread-local store, so the outer
/// runtime never became quiescent.
#[test]
fn current_thread_nested_distinct_runtimes_both_roots_retire() {
    let outer = RuntimeBuilder::current_thread()
        .build()
        .expect("build outer runtime");
    let inner = RuntimeBuilder::current_thread()
        .build()
        .expect("build inner runtime");
    let caller = thread::current().id();

    let value = outer.block_on(async {
        let outer_cx = Cx::current().expect("outer root Cx is installed");
        let outer_id = outer_cx.task_id();
        let (inner_id, inner_spawn_thread) = inner.block_on(async {
            let inner_cx = Cx::current().expect("inner root Cx is installed");
            let inner_id = inner_cx.task_id();
            let spawn_thread = Runtime::current_handle()
                .expect("inner runtime handle is installed")
                .spawn(async { thread::current().id() })
                .await;
            assert!(
                !inner.is_quiescent(),
                "inner root {inner_id:?} must be live inside its block_on"
            );
            (inner_id, spawn_thread)
        });
        assert_eq!(
            inner_spawn_thread, caller,
            "the inner runtime's spawn must run on the nesting thread"
        );
        assert!(
            inner.is_quiescent(),
            "inner root task record did not retire after the nested block_on"
        );
        assert!(
            !outer.is_quiescent(),
            "outer root {outer_id:?} must still be live after the inner returned"
        );
        assert_eq!(
            Cx::current().expect("outer root Cx is restored").task_id(),
            outer_id,
            "the outer root Cx must be restored after the nested block_on"
        );
        (outer_id, inner_id)
    });

    assert!(
        inner.is_quiescent(),
        "inner root task record did not retire (ids {value:?})"
    );
    assert!(
        outer.is_quiescent(),
        "outer root task record did not retire after nested runtime (ids {value:?})"
    );
}

/// Bounded post-root drain: a cancellation-blind self-waking task spawned
/// from the root must not keep `block_on` from returning.
#[test]
fn current_thread_block_on_returns_despite_cancellation_blind_self_waker() {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build asupersync runtime");
        let polls = Arc::new(AtomicUsize::new(0));
        let value = runtime.block_on(async {
            let cx = Cx::current().expect("root Cx is installed");
            let polls = Arc::clone(&polls);
            let _detached = cx
                .spawn(move |_| async move {
                    loop {
                        polls.fetch_add(1, Ordering::Relaxed);
                        yield_now().await;
                    }
                })
                .expect("root Cx has spawn authority");
            42_u32
        });
        let _ = tx.send((value, polls.load(Ordering::Relaxed)));
        // Dropping the runtime signals shutdown; the self-waker yields
        // between polls, so the background worker exits at its next turn.
        drop(runtime);
    });

    let (value, polls) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("block_on must return within 10 s despite a self-waking task");
    assert_eq!(value, 42);
    assert!(
        polls > 0,
        "the self-waking task must have been polled at least once by the drain"
    );
}

/// Teardown: a `!Send` task admitted by this thread and still parked when
/// the runtime is dropped is dropped with it (abort-by-drop at teardown),
/// and the runtime's per-thread local store is retired, not leaked.
#[cfg(feature = "test-internals")]
#[test]
fn dropping_the_runtime_retires_the_caller_thread_local_store() {
    use asupersync::runtime::local::keyed_local_store_count;

    struct DropFlag(Rc<Cell<bool>>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    let stores_before = keyed_local_store_count();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let dropped = Rc::new(Cell::new(false));
    let started = Rc::new(Cell::new(false));

    runtime.block_on(async {
        let cx = Cx::current().expect("root Cx is installed");
        let flag = DropFlag(Rc::clone(&dropped));
        let task_started = Rc::clone(&started);
        let _parked = cx
            .spawn_local(move |_| async move {
                let _flag = flag;
                task_started.set(true);
                std::future::pending::<()>().await;
            })
            .expect("current_thread root must accept a local task");
        while !started.get() {
            yield_now().await;
        }
    });

    assert!(
        !dropped.get(),
        "a parked local task must stay alive after block_on returns"
    );
    assert_eq!(
        keyed_local_store_count(),
        stores_before + 1,
        "the runtime's local store must exist on the admitting thread"
    );

    drop(runtime);

    assert!(
        dropped.get(),
        "the parked local task must be dropped when the runtime is dropped"
    );
    assert_eq!(
        keyed_local_store_count(),
        stores_before,
        "the runtime's local store must be retired when the runtime is dropped"
    );
}
