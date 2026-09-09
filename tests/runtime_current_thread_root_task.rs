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

    let value = runtime.block_on(async {
        let cx = Cx::current().expect("recovered root Cx");
        let local = Rc::new(7_u8);
        let mut task = cx
            .spawn_local(move |_| async move { *local })
            .expect("recovered root retains local spawn authority");
        task.join(&cx).await.expect("recovered worker dispatches")
    });
    assert_eq!(value, 7, "runtime must stay usable after a root panic");
    assert!(
        runtime.is_quiescent(),
        "panicked root left the runtime non-quiescent"
    );
}

/// A startup hook can unwind before the worker enters its dispatch loop.
/// A subsequent caller must fall back to polling its root, rather than wait
/// forever for a handover from that dead worker. Shutdown releases the old
/// implementation's waiter before the assertion, so even RED leaves no hang.
#[test]
fn current_thread_start_hook_panic_does_not_strand_block_on() {
    let (unwinding, unwound) = mpsc::channel();
    let runtime = RuntimeBuilder::current_thread()
        .on_thread_start(move || {
            struct OnUnwind(mpsc::Sender<()>);
            impl Drop for OnUnwind {
                fn drop(&mut self) {
                    let _ = self.0.send(());
                }
            }
            let _notify = OnUnwind(unwinding.clone());
            panic!("startup hook boom");
        })
        .build()
        .expect("build runtime with panicking startup hook");
    unwound
        .recv_timeout(Duration::from_secs(5))
        .expect("startup hook must actually unwind");

    let caller_runtime = runtime.clone();
    let (sent, received) = mpsc::channel();
    let caller = thread::spawn(move || {
        let value = caller_runtime.block_on(async { 42_u32 });
        let _ = sent.send(value);
    });
    let result = received.recv_timeout(Duration::from_secs(2));
    runtime.shutdown_background();
    caller.join().expect("caller exits after shutdown cleanup");
    assert_eq!(
        result.expect("block_on waited for a worker whose startup hook panicked"),
        42
    );
}

/// The actual pinned root, including its destructor, belongs to the root
/// task. Drop may spawn local work, which must be drained before return.
#[test]
fn current_thread_root_destructor_runs_before_retirement_and_drain() {
    use std::future::Future;
    use std::marker::PhantomPinned;
    use std::pin::Pin;
    use std::task::Context;

    struct Root<'a> {
        runtime: &'a Runtime,
        root_id: Cell<Option<asupersync::types::TaskId>>,
        address: Cell<usize>,
        drop_live: &'a Cell<bool>,
        drop_context: &'a Cell<bool>,
        child_ran: Rc<Cell<bool>>,
        _pin: PhantomPinned,
    }
    impl Future for Root<'_> {
        type Output = u32;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u32> {
            self.root_id
                .set(Some(Cx::current().expect("root Cx").task_id()));
            self.address
                .set(std::ptr::from_ref(self.as_ref().get_ref()) as usize);
            Poll::Ready(42)
        }
    }
    impl Drop for Root<'_> {
        fn drop(&mut self) {
            assert_eq!(self.address.get(), std::ptr::from_ref(self) as usize);
            let cx = Cx::current().expect("root destructor Cx");
            self.drop_context
                .set(Some(cx.task_id()) == self.root_id.get());
            self.drop_live.set(
                !self.runtime.is_quiescent()
                    && self
                        .runtime
                        .task_inspector(TaskInspectorConfig::default())
                        .list_tasks()
                        .iter()
                        .any(|task| Some(task.id) == self.root_id.get()),
            );
            let ran = Rc::clone(&self.child_ran);
            let _child = cx
                .spawn_local(move |_| async move {
                    ran.set(true);
                })
                .expect("root destructor retains local spawn authority");
        }
    }

    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    let live = Cell::new(false);
    let context = Cell::new(false);
    let ran = Rc::new(Cell::new(false));
    assert_eq!(
        runtime.block_on(Root {
            runtime: &runtime,
            root_id: Cell::new(None),
            address: Cell::new(0),
            drop_live: &live,
            drop_context: &context,
            child_ran: Rc::clone(&ran),
            _pin: PhantomPinned,
        }),
        42
    );
    assert!(
        context.get(),
        "root destructor lost its admission-minted Cx"
    );
    assert!(
        live.get(),
        "root record retired before its future was dropped"
    );
    assert!(ran.get(), "root destructor's local child was not drained");
    assert!(
        runtime.is_quiescent(),
        "root and destructor child must retire"
    );
}

/// Keeps a destructor action in the actual root future until it is dropped.
struct RootDropAction<F: FnOnce()> {
    on_drop: Option<F>,
    panic_in_poll: bool,
}

impl<F: FnOnce()> std::future::Future for RootDropAction<F> {
    type Output = u8;

    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<u8> {
        assert!(!self.panic_in_poll, "root poll boom");
        Poll::Ready(7)
    }
}

impl<F: FnOnce()> Drop for RootDropAction<F> {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

#[test]
fn current_thread_root_destructor_can_reenter_and_join_local_work() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    let completed = Cell::new(0);
    runtime.block_on(RootDropAction {
        on_drop: Some(|| {
            let cx = Cx::current().expect("root destructor Cx");
            let local = Rc::new(42_u32);
            let task = cx
                .spawn_local(move |_| async move { *local })
                .expect("root destructor has local spawn authority");
            completed.set(join_all_within(
                &runtime,
                vec![task],
                Duration::from_secs(2),
            ));
            assert_eq!(
                Cx::current().expect("restored destructor Cx").task_id(),
                cx.task_id()
            );
        }),
        panic_in_poll: false,
    });
    assert_eq!(
        completed.get(),
        1,
        "root destructor could not drive its local child"
    );
    assert!(runtime.is_quiescent());
}

#[test]
fn current_thread_root_destructor_panic_still_drains_and_returns_worker() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    for panic_in_poll in [false, true] {
        let ran = Rc::new(Cell::new(false));
        let child_ran = Rc::clone(&ran);
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(RootDropAction {
                on_drop: Some(|| {
                    let cx = Cx::current().expect("root destructor Cx");
                    let _child = cx
                        .spawn_local(move |_| async move {
                            child_ran.set(true);
                        })
                        .expect("destructor local spawn");
                    panic!("root drop boom");
                }),
                panic_in_poll,
            })
        }));
        let payload = outcome.expect_err("root panic must propagate");
        let expected = if panic_in_poll {
            "root poll boom"
        } else {
            "root drop boom"
        };
        assert_eq!(payload.downcast_ref::<&str>().copied(), Some(expected));
        assert!(ran.get(), "destructor panic skipped runnable child drain");
        assert!(
            runtime.is_quiescent(),
            "panicking destructor leaked root accounting"
        );
        let caller = thread::current().id();
        assert_eq!(
            runtime.block_on(async {
                runtime
                    .handle()
                    .spawn(async { thread::current().id() })
                    .await
            }),
            caller,
            "worker must remain usable on caller after destructor panic"
        );
    }
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

/// Re-entrancy: a root may call `block_on` on its own runtime again, to any
/// depth, and every level's spawns run on the calling thread and can be
/// awaited (the outer drive parks the worker for the nested call while it
/// polls its root). Also the compile-time regression for the `Send`-proof
/// depth of futures that capture a `RuntimeHandle`: this file compiles
/// under `-D warnings`, where `recursion_depth_exceeding_limit` is an error.
#[test]
fn current_thread_three_deep_nested_block_on_spawns_at_every_level() {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let caller = thread::current().id();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build asupersync runtime");
        let value = runtime.block_on(async {
            let level1 = Runtime::current_handle()
                .expect("runtime handle is installed")
                .spawn(async { thread::current().id() })
                .await;
            assert_eq!(level1, caller, "level 1 spawn left the calling thread");
            let inner = runtime.block_on(async {
                let level2 = Runtime::current_handle()
                    .expect("runtime handle is installed")
                    .spawn(async { thread::current().id() })
                    .await;
                assert_eq!(level2, caller, "level 2 spawn left the calling thread");
                let innermost = runtime.block_on(async {
                    let cx = Cx::current().expect("level 3 root Cx is installed");
                    let mut level3 = cx
                        .spawn(|_| async { thread::current().id() })
                        .expect("level 3 root Cx has spawn authority");
                    let level3 = level3.join(&cx).await.expect("level 3 task completes");
                    assert_eq!(level3, caller, "level 3 spawn left the calling thread");
                    40_u32
                });
                innermost + 1
            });
            assert!(
                !runtime.is_quiescent(),
                "the outer root must still be live after the nested calls returned"
            );
            inner + 1
        });
        let quiescent = runtime.is_quiescent();
        let _ = tx.send((value, quiescent));
    });

    let (value, quiescent) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("three-deep nested block_on must complete within 10 s");
    assert_eq!(value, 42);
    assert!(
        quiescent,
        "every nested root record must retire once the outermost block_on returned"
    );
}

/// A same-runtime nested drive must admit local requests queued by its
/// outer root: the inner root may be waiting for exactly that child.
#[test]
fn current_thread_nested_block_on_joins_outer_pending_local_spawn() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");
    let caller = thread::current().id();
    let ran = Rc::new(Cell::new(false));

    runtime.block_on(async {
        let cx = Cx::current().expect("outer root Cx is installed");
        let task_ran = Rc::clone(&ran);
        let handle = cx
            .spawn_local(move |_| async move {
                assert_eq!(thread::current().id(), caller);
                task_ran.set(true);
                42_u32
            })
            .expect("outer root accepts a local task");
        assert!(!ran.get(), "the child must still be awaiting admission");

        // Self-waking bounded joins make the old hidden-request deadlock
        // fail with a count of zero instead of hanging the test process.
        let completed = join_all_within(&runtime, vec![handle], Duration::from_secs(2));
        assert_eq!(completed, 1, "nested drive hid the outer local request");
        assert_eq!(
            Cx::current().expect("outer Cx restored").task_id(),
            cx.task_id()
        );
        assert!(!runtime.is_quiescent(), "the outer root must remain live");
    });

    assert!(ran.get());
    assert!(runtime.is_quiescent(), "both root records must retire");
}

/// A caught nested panic returns the worker and restores the outer root's
/// context, including its authority to admit subsequent local work.
#[test]
fn current_thread_caught_nested_panic_restores_local_spawn_and_reentry() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync runtime");

    runtime.block_on(async {
        let cx = Cx::current().expect("outer root Cx is installed");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(async {
                yield_now().await;
                panic!("nested root boom");
            })
        }));
        let payload = outcome.expect_err("nested root panic must propagate");
        assert_eq!(
            payload.downcast_ref::<&str>().copied(),
            Some("nested root boom")
        );
        assert_eq!(
            Cx::current().expect("outer Cx restored").task_id(),
            cx.task_id()
        );

        let local = Rc::new(42_u32);
        let handle = cx
            .spawn_local(move |_| async move { *local })
            .expect("outer root retains local spawn authority after nested panic");
        assert_eq!(
            join_all_within(&runtime, vec![handle], Duration::from_secs(2)),
            1
        );
        assert_eq!(runtime.block_on(async { 7_u8 }), 7);
        assert!(
            !runtime.is_quiescent(),
            "outer root remains live after recovery"
        );
    });

    assert_eq!(runtime.block_on(async { 9_u8 }), 9);
    assert!(runtime.is_quiescent(), "panicked nested root must retire");
}

/// Distinct runtimes share the thread's local-spawn lane, but must never
/// admit each other's pending local requests into the wrong task store.
#[test]
fn current_thread_nested_distinct_runtimes_preserve_pending_outer_local_spawn() {
    let outer = RuntimeBuilder::current_thread()
        .build()
        .expect("outer runtime");
    let inner = RuntimeBuilder::current_thread()
        .build()
        .expect("inner runtime");
    let ran = Rc::new(Cell::new(false));

    outer.block_on(async {
        let cx = Cx::current().expect("outer root Cx is installed");
        let task_ran = Rc::clone(&ran);
        let handle = cx
            .spawn_local(move |_| async move {
                task_ran.set(true);
                42_u32
            })
            .expect("outer root accepts a local task");
        inner.block_on(async {
            let inner_cx = Cx::current().expect("inner root Cx is installed");
            let local = Rc::new(42_u32);
            let mut task = inner_cx
                .spawn_local(move |_| async move { *local })
                .expect("inner root accepts its own local task");
            assert_eq!(
                task.join(&inner_cx).await.expect("inner child completes"),
                42
            );
            assert!(!ran.get(), "inner runtime must not admit the outer request");
        });
        assert!(
            !ran.get(),
            "outer request stays pending until the outer drive resumes"
        );
        assert_eq!(
            join_all_within(&outer, vec![handle], Duration::from_secs(2)),
            1
        );
    });

    assert!(ran.get());
    assert!(outer.is_quiescent());
    assert!(inner.is_quiescent());
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
