//! Behavioral proof that the root region is drained when the entry future
//! returns, and that `Runtime::drain_root_region` is bounded.
//!
//! Before this change nothing closed the root region: `block_on` returned as
//! soon as its future completed and teardown joined the workers and dropped
//! state, so a root-region task that outlived `main` was abort-by-dropped
//! and its cleanup never ran. Now the entry macros request cancellation of
//! the root region and wait (default 2 s) for quiescence.
//!
//! What green proves:
//! - a cooperative task spawned from `main` that outlives it observes the
//!   shutdown cancellation and runs its cleanup before `main()` returns (the
//!   cleanup counter is read after the macro-expanded function returns);
//! - `drain_ms = 0` restores the old behaviour: the same task's cleanup has
//!   not run when the function returns (planted negative);
//! - `Runtime::drain_root_region` reports `Quiescent` for completed root
//!   close and `TimedOut` within the bound for non-cooperative work;
//! - an unwinding entry panic still drains its genuinely parked child, emits
//!   the opt-in terminal report, and resumes the original panic in a subprocess.
//!
//! No-claim: non-cooperative code is not bounded beyond the wait; LabRuntime
//! semantics are unchanged.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::observability::TaskInspectorConfig;
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder, yield_now};

async fn panic_after_child_parks(cx: &Cx) {
    let parked = Arc::new(asupersync::sync::Notify::new());
    let pending = Arc::new(AtomicBool::new(false));
    let child_parked = Arc::clone(&parked);
    let child_pending = Arc::clone(&pending);
    let _child = cx
        .spawn(move |child| async move {
            let mut cancelled = std::pin::pin!(child.cancelled());
            std::future::poll_fn(|task| {
                let result = cancelled.as_mut().poll(task);
                if result.is_pending() {
                    child_pending.store(true, Ordering::Release);
                    child_parked.notify_one();
                }
                result
            })
            .await;
            child
                .checkpoint()
                .expect_err("entry panic must run the shutdown drain");
            let reason = child
                .cancel_reason()
                .expect("the shutdown drain records its cancel reason");
            assert_eq!(reason.kind, asupersync::types::CancelKind::Shutdown);
            eprintln!("ENTRY_PANIC_CHILD_CLEANED kind=Shutdown");
        })
        .expect("spawn child that outlives the panicking entry");
    parked.wait_until(|| pending.load(Ordering::Acquire)).await;
    eprintln!("ENTRY_PANIC_CHILD_PARKED");
    panic!("ORIGINAL_ENTRY_PANIC_MUST_SURVIVE");
}

mod panicking_current_thread {
    use super::*;

    #[asupersync::main(flavor = "current_thread", drain_ms = 1000, drain_report = true)]
    pub(super) async fn main(cx: &Cx) {
        panic_after_child_parks(cx).await;
    }
}

mod panicking_multi_thread {
    use super::*;

    #[asupersync::main(workers = 2, drain_ms = 1000, drain_report = true)]
    pub(super) async fn main(cx: &Cx) {
        panic_after_child_parks(cx).await;
    }
}

#[test]
fn panicking_entry_drains_children_and_reports_before_resuming_panic() {
    const CHILD_CASE: &str = "ASUPERSYNC_ENTRY_PANIC_DRAIN_CASE";
    if let Ok(case) = std::env::var(CHILD_CASE) {
        let result = std::panic::catch_unwind(|| match case.as_str() {
            "current" => panicking_current_thread::main(),
            "multi" => panicking_multi_thread::main(),
            _ => panic!("unknown entry panic case"),
        });
        let panic = result.expect_err("panicking entry unexpectedly returned");
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("ORIGINAL_ENTRY_PANIC_MUST_SURVIVE"));
        eprintln!("ENTRY_PANIC_ORIGINAL_PAYLOAD_OBSERVED_AFTER_DRAIN");
        std::panic::resume_unwind(panic);
    }
    for case in ["current", "multi"] {
        let started = Instant::now();
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "panicking_entry_drains_children_and_reports_before_resuming_panic",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_CASE, case)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn entry panic subprocess");
        loop {
            if child.try_wait().expect("entry subprocess status").is_some() {
                break;
            }
            if started.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("entry panic drain exceeded process watchdog: {case}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child
            .wait_with_output()
            .expect("collect entry panic output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !output.status.success(),
            "the original panic must remain a failure"
        );
        assert!(
            stderr.contains("ENTRY_PANIC_CHILD_PARKED"),
            "child never parked: {stdout}\n{stderr}"
        );
        assert!(
            stderr.contains("ENTRY_PANIC_CHILD_CLEANED kind=Shutdown"),
            "panic skipped cooperative cleanup: {stdout}\n{stderr}"
        );
        assert!(
            stderr.contains("ORIGINAL_ENTRY_PANIC_MUST_SURVIVE"),
            "original panic payload lost: {stdout}\n{stderr}"
        );
        let cleanup = stderr.find("ENTRY_PANIC_CHILD_CLEANED").unwrap();
        let report = stderr
            .find("asupersync root drain: Quiescent")
            .expect("observable successful drain report");
        assert!(cleanup < report, "drain reported before cleanup");
        let payload = stderr
            .find("ENTRY_PANIC_ORIGINAL_PAYLOAD_OBSERVED_AFTER_DRAIN")
            .expect("subprocess must inspect the resumed payload, not only its panic hook");
        assert!(
            report < payload,
            "the report precedes resuming the entry panic"
        );
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.92\",\"scenario\":\"panic-entry\",\"runtime\":\"{case}\",\"elapsed_ms\":{},\"cleanup_observed\":true,\"original_panic_preserved\":true}}",
            started.elapsed().as_millis()
        );
    }
}

/// Spawns a task that keeps checkpointing until cancelled, then bumps
/// `cleanup` once. The handle is deliberately dropped: the task outlives the
/// caller and only the root-region drain can make its cleanup run.
///
/// Returns a flag the task sets on its first poll. Spawns are admitted
/// asynchronously through the mailbox, so a caller that wants "a task that is
/// running when the entry future returns" must wait for this flag; otherwise
/// the drain may cancel a still-pending spawn, which then never runs at all.
fn spawn_outliving_worker(cx: &Cx, cleanup: Arc<AtomicUsize>) -> Arc<AtomicBool> {
    let started = Arc::new(AtomicBool::new(false));
    let started_for_task = Arc::clone(&started);
    let _ = cx
        .spawn(move |task_cx| async move {
            started_for_task.store(true, Ordering::SeqCst);
            loop {
                if task_cx.checkpoint().is_err() {
                    break;
                }
                yield_now().await;
            }
            cleanup.fetch_add(1, Ordering::SeqCst);
        })
        .expect("spawn outliving worker");
    started
}

/// Yields until `started` is set (bounded so a broken spawn path fails
/// instead of hanging).
async fn wait_started(started: &AtomicBool) {
    for _ in 0..100_000 {
        if started.load(Ordering::SeqCst) {
            return;
        }
        yield_now().await;
    }
    panic!("spawned task never started");
}

mod drained {
    use super::*;

    thread_local! {
        static SHARED: std::cell::RefCell<Option<Arc<AtomicUsize>>> = const { std::cell::RefCell::new(None) };
    }

    #[asupersync::main]
    async fn main(cx: &Cx) {
        let cleanup = Arc::new(AtomicUsize::new(0));
        let started = spawn_outliving_worker(cx, Arc::clone(&cleanup));
        // Wait until the worker is really running, then leave it running.
        wait_started(&started).await;
        // Publish the shared counter so the test can read it after return
        // (block_on drives this future on the test thread).
        SHARED.with(|slot| *slot.borrow_mut() = Some(cleanup));
    }

    #[test]
    fn main_drains_outliving_task_before_returning() {
        main();
        let cleanup = SHARED
            .with(|slot| slot.borrow().clone())
            .expect("main published counter");
        assert_eq!(
            cleanup.load(Ordering::SeqCst),
            1,
            "the outliving task's cleanup must have run before #[asupersync::main] returned"
        );
    }
}

mod undrained_planted_negative {
    use super::*;

    thread_local! {
        static SHARED: std::cell::RefCell<Option<Arc<AtomicUsize>>> = const { std::cell::RefCell::new(None) };
    }

    #[asupersync::main(drain_ms = 0)]
    async fn main(cx: &Cx) {
        let cleanup = Arc::new(AtomicUsize::new(0));
        let started = spawn_outliving_worker(cx, Arc::clone(&cleanup));
        wait_started(&started).await;
        SHARED.with(|slot| *slot.borrow_mut() = Some(cleanup));
    }

    #[test]
    fn drain_zero_leaves_the_outliving_task_undrained() {
        main();
        let cleanup = SHARED
            .with(|slot| slot.borrow().clone())
            .expect("main published counter");
        assert_eq!(
            cleanup.load(Ordering::SeqCst),
            0,
            "with drain_ms = 0 the task is dropped at teardown and its cleanup never runs"
        );
    }
}

fn drain_reports_quiescent_for_cooperative_work(runtime: asupersync::runtime::Runtime) {
    let cleanup = Arc::new(AtomicUsize::new(0));
    let cleanup_for_task = Arc::clone(&cleanup);
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let started = spawn_outliving_worker(&cx, cleanup_for_task);
        wait_started(&started).await;
    });
    assert_eq!(
        cleanup.load(Ordering::SeqCst),
        0,
        "still running when block_on returns"
    );
    let outcome = runtime.drain_root_region(Duration::from_secs(5));
    if outcome != RootDrainOutcome::Quiescent {
        // Diagnostics for a red run: what does the runtime think the task is
        // doing? (state, phase, poll count, time since last poll)
        let inspector = runtime.task_inspector(TaskInspectorConfig::default());
        eprintln!(
            "drain timed out; inspector snapshot:\n{}",
            inspector
                .wire_snapshot_pretty_json()
                .unwrap_or_else(|e| format!("<snapshot failed: {e}>"))
        );
        for task in inspector.list_tasks() {
            eprintln!(
                "task {:?} region {:?} state {:?} phase {:?} polls {} since_last_poll {:?} wake_pending {}",
                task.id,
                task.region_id,
                task.state,
                task.phase,
                task.poll_count,
                task.time_since_last_poll,
                task.wake_pending
            );
        }
    }
    assert_eq!(outcome, RootDrainOutcome::Quiescent);
    assert_eq!(cleanup.load(Ordering::SeqCst), 1);
    // Full runtime quiescence additionally requires no I/O registrations;
    // root lifecycle completion is now part of the drain's own contract.
    eprintln!(
        "runtime.is_quiescent() after drain = {}",
        runtime.is_quiescent()
    );
}

#[test]
fn drain_root_region_reports_quiescent_for_cooperative_work() {
    drain_reports_quiescent_for_cooperative_work(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
    );
}

#[test]
fn drain_root_region_reports_quiescent_for_cooperative_work_current_thread() {
    drain_reports_quiescent_for_cooperative_work(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
    );
}

#[test]
fn drain_root_region_times_out_within_bound_for_non_cooperative_work() {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let started = Arc::new(AtomicBool::new(false));
        let started_for_task = Arc::clone(&started);
        let _ = cx
            .spawn(move |_task_cx| async move {
                started_for_task.store(true, Ordering::SeqCst);
                // Never checkpoints: cannot be drained cooperatively.
                std::thread::sleep(Duration::from_millis(1500));
            })
            .expect("spawn non-cooperative task");
        wait_started(&started).await;
    });
    let started = Instant::now();
    let outcome = runtime.drain_root_region(Duration::from_millis(200));
    let waited = started.elapsed();
    assert_eq!(outcome, RootDrainOutcome::TimedOut);
    assert!(
        waited < Duration::from_millis(1200),
        "the drain must give up at its bound, not wait for the blocking task; waited {waited:?}"
    );
}

/// A task inside a child region that spawns through the runtime handle
/// spawns into the ROOT region: the child region's close neither waits for
/// nor cancels that task, and only the root drain cancels and drains it
/// (br-asupersync-issue65-criticisms-kpmoy5.2.3).
fn handle_spawn_escapes_the_callers_child_region(runtime: asupersync::runtime::Runtime) {
    let started = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let cancel_kind = Arc::new(std::sync::Mutex::new(None));
    let started_for_task = Arc::clone(&started);
    let polls_for_task = Arc::clone(&polls);
    let kind_for_task = Arc::clone(&cancel_kind);
    let kind_for_check = Arc::clone(&cancel_kind);
    let kind_after_child_close = runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let child = cx
            .open_child_region(asupersync::cx::ChildRegionSpec::inherit())
            .await
            .expect("child region");
        let mut spawner = child
            .cx()
            .spawn(move |_inner| async move {
                let handle = asupersync::runtime::Runtime::current_handle()
                    .expect("a runtime task can reach its runtime handle");
                handle.spawn_with_cx(move |escaped| async move {
                    started_for_task.store(true, Ordering::SeqCst);
                    while escaped.checkpoint().is_ok() {
                        polls_for_task.fetch_add(1, Ordering::SeqCst);
                        yield_now().await;
                    }
                    *kind_for_task.lock().unwrap() = escaped.cancel_reason().map(|r| r.kind);
                });
            })
            .expect("spawn in the child region");
        spawner
            .join(child.cx())
            .await
            .expect("the spawning task finishes");
        wait_started(&started).await;
        child
            .close()
            .await
            .expect("the child region closes without waiting for the escaped task");
        let kind = *kind_for_check.lock().unwrap();
        // Still running after the close: it keeps passing checkpoints.
        let polls_at_close = polls.load(Ordering::SeqCst);
        for _ in 0..100_000 {
            if polls.load(Ordering::SeqCst) > polls_at_close {
                return kind;
            }
            yield_now().await;
        }
        panic!("the escaped task stopped running when its spawner's region closed");
    });
    assert_eq!(
        kind_after_child_close, None,
        "closing the child region must not cancel a root-region task"
    );
    assert_eq!(
        runtime.drain_root_region(Duration::from_secs(5)),
        RootDrainOutcome::Quiescent
    );
    assert_eq!(
        *cancel_kind.lock().unwrap(),
        Some(asupersync::CancelKind::Shutdown),
        "the root drain cancels the escaped task"
    );
}

#[test]
fn handle_spawn_escapes_the_callers_child_region_until_root_drain() {
    handle_spawn_escapes_the_callers_child_region(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
    );
}

#[test]
fn handle_spawn_escapes_the_callers_child_region_until_root_drain_current_thread() {
    handle_spawn_escapes_the_callers_child_region(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
    );
}

/// Parks until released and ignores cancellation: a task that never reaches
/// a checkpoint or a cancel-aware await.
type Gate = Arc<(AtomicBool, std::sync::Mutex<Option<std::task::Waker>>)>;

struct Released(Gate);

impl Future for Released {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let (released, waker) = &*self.0;
        *waker.lock().unwrap() = Some(cx.waker().clone());
        if released.load(Ordering::SeqCst) {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }
}

fn release(gate: &Gate) {
    gate.0.store(true, Ordering::SeqCst);
    if let Some(waker) = gate.1.lock().unwrap().take() {
        waker.wake();
    }
}

/// `ChildRegion::close_within` gives up at its bound and names the task that
/// ignores cancellation. The region keeps owning that task: the cooperative
/// sibling is drained, and once the straggler is released the runtime reaches
/// quiescence (br-asupersync-issue65-criticisms-kpmoy5.2.4).
fn close_within_names_the_straggler_and_keeps_owning_it(runtime: asupersync::runtime::Runtime) {
    use asupersync::cx::{ChildRegionCloseOutcome, ChildRegionSpec};

    let bound = Duration::from_millis(50);
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("child region");
        let cooperative_started = Arc::new(AtomicBool::new(false));
        let cooperative_flag = Arc::clone(&cooperative_started);
        let cooperative_done = Arc::new(AtomicBool::new(false));
        let done_flag = Arc::clone(&cooperative_done);
        let mut cooperative = child
            .cx()
            .spawn(move |task_cx| async move {
                cooperative_flag.store(true, Ordering::SeqCst);
                while task_cx.checkpoint().is_ok() {
                    yield_now().await;
                }
                done_flag.store(true, Ordering::SeqCst);
            })
            .expect("spawn the cooperative task");
        let gate: Gate = Arc::new((AtomicBool::new(false), std::sync::Mutex::new(None)));
        let gate_for_task = Arc::clone(&gate);
        let straggler_started = Arc::new(AtomicBool::new(false));
        let straggler_flag = Arc::clone(&straggler_started);
        let straggler_id = Arc::new(std::sync::Mutex::new(None));
        let id_slot = Arc::clone(&straggler_id);
        let mut straggler = child
            .cx()
            .spawn(move |task_cx| async move {
                *id_slot.lock().unwrap() = Some(task_cx.task_id());
                straggler_flag.store(true, Ordering::SeqCst);
                Released(gate_for_task).await;
            })
            .expect("spawn the straggler");
        wait_started(&cooperative_started).await;
        wait_started(&straggler_started).await;

        let report = child.close_within(bound).await.expect("close report");
        assert_eq!(report.outcome, ChildRegionCloseOutcome::TimedOut);
        let expected = (*straggler_id.lock().unwrap()).expect("the straggler ran");
        assert_eq!(report.stragglers, vec![expected]);
        assert!(
            report.elapsed >= bound && report.elapsed < Duration::from_secs(5),
            "the report comes at the bound, not before and not much later: {:?}",
            report.elapsed
        );
        let _ = cooperative.join(&cx).await;
        assert!(
            cooperative_done.load(Ordering::SeqCst),
            "the cooperative task observed the close and finished"
        );
        release(&gate);
        let _ = straggler.join(&cx).await;
    });
    assert_eq!(
        runtime.drain_root_region(Duration::from_secs(5)),
        RootDrainOutcome::Quiescent
    );
}

#[test]
fn close_within_names_the_straggler_and_keeps_owning_it_multi_thread() {
    close_within_names_the_straggler_and_keeps_owning_it(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
    );
}

#[test]
fn close_within_names_the_straggler_and_keeps_owning_it_current_thread() {
    close_within_names_the_straggler_and_keeps_owning_it(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
    );
}

/// Without a straggler, `close_within` reports quiescence well inside its
/// bound, with no straggler list.
#[test]
fn close_within_reports_quiescence_when_every_task_cooperates() {
    use asupersync::cx::{ChildRegionCloseOutcome, ChildRegionSpec};

    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("child region");
        let started = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&started);
        let _task = child
            .cx()
            .spawn(move |task_cx| async move {
                flag.store(true, Ordering::SeqCst);
                while task_cx.checkpoint().is_ok() {
                    yield_now().await;
                }
            })
            .expect("spawn");
        wait_started(&started).await;
        let report = child
            .close_within(Duration::from_secs(30))
            .await
            .expect("close report");
        assert_eq!(report.outcome, ChildRegionCloseOutcome::Quiescent);
        assert!(report.stragglers.is_empty());
        assert!(report.elapsed < Duration::from_secs(30));
    });
}
