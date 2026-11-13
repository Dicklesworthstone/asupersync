#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::oneshot;
use crate::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use crate::cx::io_gate::require_ambient_io;
use crate::lab::run_async_under_lab;
use crate::runtime::spawn_mailbox::{RegionCommand, RegisterRegionFinalizer};
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::sync::Notify;
use crate::types::{CancelKind, TaskId};
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

fn capacity(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

fn config(window: usize) -> PipelineExecutionConfig {
    PipelineExecutionConfig::new(capacity(1), capacity(window))
}

#[derive(Default)]
struct Progress {
    parked: AtomicBool,
    cleaning: AtomicBool,
    finished: AtomicBool,
    retired: AtomicBool,
    changed: Notify,
}

impl Progress {
    fn note(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait(&self, ready: impl Fn(&Self) -> bool) {
        self.changed.wait_until(|| ready(self)).await;
    }
}

struct Retire(Arc<Progress>);

impl Drop for Retire {
    fn drop(&mut self) {
        self.0.note(&self.0.retired);
    }
}

async fn held_descendant(
    cx: Cx,
    sender: mpsc::Sender<()>,
    seen: Arc<Progress>,
    mut release: oneshot::Receiver<()>,
    panic_after_cleanup: bool,
) -> CancelReason {
    let _retire = Retire(Arc::clone(&seen));
    let permit = sender.reserve_checked(&cx).await.unwrap();
    {
        let mut cancelled = std::pin::pin!(cx.cancelled());
        poll_fn(|task| {
            let progress = cancelled.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.load(Ordering::Acquire) {
                seen.note(&seen.parked);
            }
            progress
        })
        .await;
    }
    assert!(cx.checkpoint().is_err());
    let reason = cx.cancel_reason().expect("attributed subtree cancellation");
    {
        let mut cleanup = std::pin::pin!(release.recv_uninterruptible());
        poll_fn(|task| {
            let progress = cx.masked(|| cleanup.as_mut().poll(task));
            if progress.is_pending() && !seen.cleaning.load(Ordering::Acquire) {
                seen.note(&seen.cleaning);
            }
            progress
        })
        .await
        .expect("controller releases cleanup after Pending");
    }
    drop(permit);
    seen.note(&seen.finished);
    assert!(
        !panic_after_cleanup,
        "scoped pipeline descendant cleanup panic"
    );
    reason
}

#[cfg(not(target_arch = "wasm32"))]
fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("scoped-pipeline-native".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for workers in [1, 2] {
                    for sharded in [false, true] {
                        let builder = if workers == 1 {
                            RuntimeBuilder::current_thread()
                        } else {
                            RuntimeBuilder::new().worker_threads(workers)
                        };
                        let runtime = builder.with_sharded_state(sharded).build().unwrap();
                        runtime.block_on(async {
                            let root = Cx::current().expect("native root context");
                            let mut owner = root.spawn(scenario).unwrap();
                            owner
                                .join(&root)
                                .await
                                .expect("native scoped pipeline scenario");
                        });
                        let drain = runtime.shutdown_drained(Duration::from_secs(5));
                        assert_eq!(
                            drain.outcome,
                            RootDrainOutcome::Quiescent,
                            "workers={workers}, sharded={sharded}: {drain:?}"
                        );
                        assert_eq!(drain.live_tasks, 0);
                        assert_eq!(drain.live_regions, 0);
                        assert_eq!(drain.pending_spawns, 0);
                        assert_eq!(drain.pending_obligations, 0);
                        assert_eq!(drain.queued_finalizers, 0);
                        assert!(!drain.has_pending_obligation_posts);
                        assert!(runtime.is_quiescent());
                    }
                }
            }));
            let _ = send.send(result);
        })
        .unwrap();
    // A watchdog bounds failure only. Positive assertions use actual Pending
    // polls, checked permits, terminal joins and independent close receipts.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("scoped pipeline must drain its operation subtree");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Finish {
    Error,
    Success,
    DescendantPanic,
    CancelDuringClose,
}

async fn subtree_journey(cx: Cx, finish: Finish) {
    let seen = Arc::new(Progress::default());
    let retained_regions = Arc::new(parking_lot::Mutex::new(Vec::<ChildRegion>::new()));
    let retained_handles = Arc::new(parking_lot::Mutex::new(
        Vec::<TaskHandle<CancelReason>>::new(),
    ));
    let outputs = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let (sender, mut receiver) = mpsc::channel(1);
    let (release, cleanup) = oneshot::channel();
    let unrelated_seen = Arc::new(Progress::default());
    let unrelated_observer = Arc::clone(&unrelated_seen);
    let mut unrelated = cx
        .spawn(move |child| async move {
            let mut cancellation = std::pin::pin!(child.cancelled());
            poll_fn(|task| {
                let progress = cancellation.as_mut().poll(task);
                if progress.is_pending() {
                    unrelated_observer.note(&unrelated_observer.parked);
                }
                progress
            })
            .await;
            assert!(child.checkpoint().is_err());
            unrelated_observer.note(&unrelated_observer.finished);
        })
        .unwrap();
    unrelated_seen
        .wait(|state| state.parked.load(Ordering::Acquire))
        .await;

    let observe = Arc::clone(&seen);
    let regions = Arc::clone(&retained_regions);
    let handles = Arc::clone(&retained_handles);
    let published = Arc::clone(&outputs);
    let send = sender.clone();
    let mut operation = cx
        .spawn(move |owner| async move {
            let owner_region = owner.region_id();
            let first_seen = Arc::clone(&observe);
            let mut cleanup = Some(cleanup);
            let report = ScopedPipelineExecution::new(&owner, 0..2, config(2))
                .then(capacity(1), move |stage, index| {
                    let seen = Arc::clone(&first_seen);
                    let regions = Arc::clone(&regions);
                    let handles = Arc::clone(&handles);
                    let sender = send.clone();
                    let cleanup = if index == 1 { cleanup.take() } else { None };
                    async move {
                        assert_ne!(stage.region_id(), owner_region);
                        if index == 1 {
                            let nested = stage
                                .open_child_region(ChildRegionSpec::inherit())
                                .await
                                .unwrap();
                            let child_seen = Arc::clone(&seen);
                            let mut descendant = nested
                                .cx()
                                .spawn(move |child| {
                                    held_descendant(
                                        child,
                                        sender,
                                        child_seen,
                                        cleanup.unwrap(),
                                        finish == Finish::DescendantPanic,
                                    )
                                })
                                .unwrap();
                            seen.wait(|state| state.parked.load(Ordering::Acquire))
                                .await;
                            if finish == Finish::Error {
                                // The downstream stage fails on input zero while
                                // this upstream worker ordinary-joins a descendant.
                                // A direct-task-only abort cannot release this join.
                                let reason = descendant.join(&stage).await.unwrap();
                                assert_eq!(reason.kind, CancelKind::ParentCancelled);
                                drop(nested);
                                return Outcome::Cancelled(reason);
                            }
                            // Keep both owners outside the worker: its retirement
                            // cannot accidentally cause the successful close.
                            handles.lock().push(descendant);
                            regions.lock().push(nested);
                        }
                        Outcome::Ok(index + 10)
                    }
                })
                .then(capacity(1), move |_stage, value| {
                    let seen = Arc::clone(&observe);
                    async move {
                        if finish == Finish::Error {
                            seen.wait(|state| state.parked.load(Ordering::Acquire))
                                .await;
                            Outcome::Err("initiating downstream failure")
                        } else {
                            Outcome::Ok(format!("value:{value}"))
                        }
                    }
                })
                .run(move |sink, value| {
                    let outputs = Arc::clone(&published);
                    async move {
                        assert_ne!(sink.region_id(), owner_region);
                        outputs.lock().push(value);
                        Outcome::Ok(())
                    }
                })
                .await
                .unwrap();
            if owner.is_cancel_requested() {
                assert!(owner.checkpoint().is_err());
            }
            report
        })
        .unwrap();

    seen.wait(|state| state.cleaning.load(Ordering::Acquire))
        .await;
    assert!(
        matches!(operation.try_join(), Ok(None)),
        "held cleanup gates publication"
    );
    assert!(!seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x32_40)
            .reserved_uncommitted_obligations,
        1
    );
    assert!(!unrelated_seen.finished.load(Ordering::Acquire));
    let late_reason =
        CancelReason::shutdown().with_message("owner cancelled during pipeline close");
    if finish == Finish::CancelDuringClose {
        operation.abort_with_reason(late_reason.clone());
    }
    release.send_blocking(()).unwrap();
    let report = operation
        .join(&cx)
        .await
        .expect("typed pipeline report after acknowledgement");
    assert_ne!(report.region_id, cx.region_id());
    assert_eq!(report.execution.summary.stages, 2);
    assert_eq!(report.execution.summary.admitted, 2);
    assert!(report.execution.summary.max_in_flight <= 2);
    assert!(seen.finished.load(Ordering::Acquire) && seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x32_40)
            .reserved_uncommitted_obligations,
        0
    );
    assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
    let close = report.close.expect("actual operation close receipt");
    assert!(close.cleanup_outcome.is_none());
    if finish == Finish::Error {
        assert!(matches!(report.execution.outcome, Outcome::Cancelled(_)));
        assert!(matches!(
            report.execution.error(),
            Some(PipelineExecutionError::Stage {
                stage: 1,
                input: 0,
                error: "initiating downstream failure",
            })
        ));
        assert_eq!(report.execution.summary.consumed, 0);
        assert!(outputs.lock().is_empty());
        assert!(close.descendant_panic.is_none());
    } else {
        assert!(matches!(report.execution.outcome, Outcome::Ok(_)));
        assert_eq!(report.execution.summary.consumed, 2);
        assert_eq!(&*outputs.lock(), &["value:10", "value:11"]);
        if finish == Finish::DescendantPanic {
            assert!(matches!(close.descendant_panic, Some(ref panic)
                if format!("{panic:?}").contains("scoped pipeline descendant cleanup panic")));
        } else {
            assert!(close.descendant_panic.is_none());
        }
    }
    if finish == Finish::CancelDuringClose {
        assert_eq!(report.owner_cancellation, Some(late_reason));
    } else {
        assert!(report.owner_cancellation.is_none());
    }
    for handle in retained_handles.lock().iter_mut() {
        assert!(
            !matches!(handle.try_join(), Ok(None)),
            "retained descendant is terminal before parent close"
        );
    }
    assert!(!unrelated_seen.finished.load(Ordering::Acquire));
    assert!(!cx.is_cancel_requested());
    unrelated.abort();
    unrelated.join(&cx).await.unwrap();
    assert!(unrelated_seen.finished.load(Ordering::Acquire));
    drop(retained_regions);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn scoped_pipeline_native_failure_cancels_descendants_before_worker_joins() {
    native(|cx| subtree_journey(cx, Finish::Error));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn scoped_pipeline_native_success_waits_for_leftovers_and_independent_close_outcomes() {
    native(|cx| subtree_journey(cx, Finish::Success));
    native(|cx| subtree_journey(cx, Finish::DescendantPanic));
    native(|cx| subtree_journey(cx, Finish::CancelDuringClose));
}

#[test]
fn scoped_pipeline_lab_owns_success_and_failure_subtrees() {
    for finish in [Finish::Error, Finish::Success] {
        let ((), report) = run_async_under_lab(0x32_4001, move |cx| subtree_journey(cx, finish));
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn cancellation_or_drop_journey(cx: Cx, abandon: bool) {
    let seen = Arc::new(Progress::default());
    let observe = Arc::clone(&seen);
    let (sender, _receiver) = mpsc::channel(1);
    let send = sender.clone();
    let (release, cleanup) = oneshot::channel();
    let sink_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&sink_calls);
    let mut operation = cx
        .spawn(move |owner| async move {
            let signal = Arc::clone(&observe);
            let mut cleanup = Some(cleanup);
            let mut work = Box::pin(
                ScopedPipelineExecution::new(&owner, [()], config(1))
                    .then(capacity(1), move |stage, ()| {
                        let seen = Arc::clone(&observe);
                        let sender = send.clone();
                        let cleanup = cleanup.take().unwrap();
                        async move {
                            let nested = stage
                                .open_child_region(ChildRegionSpec::inherit())
                                .await
                                .unwrap();
                            let mut child = nested
                                .cx()
                                .spawn(move |child| {
                                    held_descendant(child, sender, seen, cleanup, false)
                                })
                                .unwrap();
                            let reason = child.join(&stage).await.unwrap();
                            drop(nested);
                            Outcome::<usize, ()>::Cancelled(reason)
                        }
                    })
                    .run(move |_sink, _value| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async { Outcome::Ok(()) }
                    }),
            );
            if abandon {
                let mut parked =
                    std::pin::pin!(signal.wait(|state| state.parked.load(Ordering::Acquire)));
                poll_fn(|task| {
                    assert!(work.as_mut().poll(task).is_pending());
                    parked.as_mut().poll(task)
                })
                .await;
                drop(work);
                None
            } else {
                let report = work.await.unwrap();
                assert!(owner.checkpoint().is_err());
                Some(report)
            }
        })
        .unwrap();
    seen.wait(|state| state.parked.load(Ordering::Acquire))
        .await;
    let reason = CancelReason::shutdown().with_cause(CancelReason::user("stop pipeline operation"));
    if !abandon {
        operation.abort_with_reason(reason.clone());
    }
    seen.wait(|state| state.cleaning.load(Ordering::Acquire))
        .await;
    assert!(!seen.retired.load(Ordering::Acquire));
    if !abandon {
        assert!(matches!(operation.try_join(), Ok(None)));
    }
    release.send_blocking(()).unwrap();
    let report = operation.join(&cx).await.unwrap();
    if abandon {
        assert!(report.is_none(), "Drop does not fabricate a close receipt");
    } else {
        let report = report.unwrap();
        assert!(matches!(report.execution.outcome, Outcome::Cancelled(_)));
        assert_eq!(report.owner_cancellation, Some(reason));
        assert_eq!(report.execution.summary.consumed, 0);
        let close = report.close.unwrap();
        assert!(close.cleanup_outcome.is_none() && close.descendant_panic.is_none());
    }
    seen.wait(|state| state.retired.load(Ordering::Acquire))
        .await;
    assert!(seen.finished.load(Ordering::Acquire));
    assert_eq!(sink_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        sender
            .telemetry_snapshot(0x32_41)
            .reserved_uncommitted_obligations,
        0
    );
    assert!(!cx.is_cancel_requested());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn scoped_pipeline_native_owner_cancel_and_drop_drain_the_entire_operation() {
    native(|cx| cancellation_or_drop_journey(cx, false));
    native(|cx| cancellation_or_drop_journey(cx, true));
}

#[derive(Default)]
struct FlowCounts {
    pulled: usize,
    consumed: usize,
    high_water: usize,
    sink_pending: bool,
}

#[derive(Default)]
struct Flow {
    counts: parking_lot::Mutex<FlowCounts>,
    changed: Notify,
}

struct FlowInputs {
    next: std::ops::Range<usize>,
    flow: Arc<Flow>,
}

impl Iterator for FlowInputs {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.next.next()?;
        {
            let mut counts = self.flow.counts.lock();
            counts.pulled += 1;
            counts.high_water = counts.high_water.max(counts.pulled - counts.consumed);
        }
        self.flow.changed.notify_waiters();
        Some(value)
    }
}

#[test]
fn scoped_pipeline_typed_edges_and_slow_sink_keep_the_whole_work_window_bounded() {
    let ((), lab) = run_async_under_lab(0x32_4002, |cx| async move {
        let flow = Arc::new(Flow::default());
        let observe = Arc::clone(&flow);
        let outputs = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let published = Arc::clone(&outputs);
        let (release, first_sink) = oneshot::channel();
        let mut operation = cx
            .spawn(move |owner| async move {
                let source = FlowInputs {
                    next: 0..9,
                    flow: Arc::clone(&observe),
                };
                let mut first_sink = Some(first_sink);
                ScopedPipelineExecution::new(&owner, source, config(3))
                    .then(capacity(1), |_stage, value| async move {
                        Outcome::<_, ()>::Ok(format!("item:{value}"))
                    })
                    .then(capacity(2), |_stage, text: String| async move {
                        Outcome::Ok(text.into_bytes())
                    })
                    .run(move |sink, bytes| {
                        let pause = first_sink.take();
                        let flow = Arc::clone(&observe);
                        let outputs = Arc::clone(&published);
                        async move {
                            if let Some(mut pause) = pause {
                                let mut waiting = std::pin::pin!(pause.recv(&sink));
                                poll_fn(|task| {
                                    let progress = waiting.as_mut().poll(task);
                                    if progress.is_pending() {
                                        flow.counts.lock().sink_pending = true;
                                        flow.changed.notify_waiters();
                                    }
                                    progress
                                })
                                .await
                                .unwrap();
                            }
                            outputs.lock().push(bytes);
                            flow.counts.lock().consumed += 1;
                            flow.changed.notify_waiters();
                            Outcome::Ok(())
                        }
                    })
                    .await
                    .unwrap()
            })
            .unwrap();
        flow.changed
            .wait_until(|| {
                let counts = flow.counts.lock();
                counts.sink_pending && counts.pulled == 3
            })
            .await;
        assert_eq!(flow.counts.lock().consumed, 0);
        assert!(matches!(operation.try_join(), Ok(None)));
        release.send_blocking(()).unwrap();
        let report = operation.join(&cx).await.unwrap();
        assert!(matches!(report.execution.outcome, Outcome::Ok(_)));
        assert_eq!(report.execution.summary.admitted, 9);
        assert_eq!(report.execution.summary.consumed, 9);
        assert_eq!(report.execution.summary.max_in_flight, 3);
        assert_eq!(report.execution.summary.stages, 2);
        assert_eq!(flow.counts.lock().high_water, 3);
        let expected: Vec<Vec<u8>> = (0..9)
            .map(|index| format!("item:{index}").into_bytes())
            .collect();
        assert_eq!(*outputs.lock(), expected);
        let close = report.close.unwrap();
        assert!(close.cleanup_outcome.is_none() && close.descendant_panic.is_none());
        assert!(report.owner_cancellation.is_none());
    });
    assert!(lab.quiescent && lab.invariant_violations.is_empty());
}

#[test]
fn scoped_pipeline_empty_and_identity_runs_close_without_losing_sink_acknowledgements() {
    for count in [0, 1, 5] {
        let ((), lab) = run_async_under_lab(0x32_4003, move |cx| async move {
            let outputs = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let published = Arc::clone(&outputs);
            let report = ScopedPipelineExecution::new(&cx, 0..count, config(2))
                .run(move |_sink, value| {
                    let outputs = Arc::clone(&published);
                    async move {
                        outputs.lock().push(value);
                        Outcome::<(), ()>::Ok(())
                    }
                })
                .await
                .unwrap();
            assert!(matches!(report.execution.outcome, Outcome::Ok(_)));
            assert_eq!(report.execution.summary.admitted, count);
            assert_eq!(report.execution.summary.consumed, count);
            assert_eq!(report.execution.summary.stages, 0);
            assert!(report.execution.summary.max_in_flight <= 2);
            assert_eq!(*outputs.lock(), (0..count).collect::<Vec<_>>());
            let close = report.close.unwrap();
            assert!(close.cleanup_outcome.is_none() && close.descendant_panic.is_none());
        });
        assert!(lab.quiescent && lab.invariant_violations.is_empty());
    }
}

#[test]
fn scoped_pipeline_finalizer_failure_retains_the_original_execution_report() {
    for fail_stage in [false, true] {
        let ((), lab) = run_async_under_lab(0x32_4004, move |cx| async move {
            let finalized = Arc::new(AtomicUsize::new(0));
            let observe = Arc::clone(&finalized);
            let report = ScopedPipelineExecution::new(&cx, [()], config(1))
                .then(capacity(1), move |stage, ()| {
                    let finalized = Arc::clone(&observe);
                    async move {
                        let (ack, mut acknowledged) = oneshot::channel();
                        let request = RegisterRegionFinalizer::new(
                            stage.region_id(),
                            move || {
                                finalized.fetch_add(1, Ordering::SeqCst);
                                panic!("scoped pipeline finalizer panic");
                            },
                            ack,
                        );
                        stage
                            .spawn_gateway_handle()
                            .unwrap()
                            .enqueue_region_command(RegionCommand::RegisterFinalizer(request))
                            .unwrap();
                        acknowledged.recv_uninterruptible().await.unwrap().unwrap();
                        if fail_stage {
                            Outcome::Err("stage cause")
                        } else {
                            Outcome::Ok(42)
                        }
                    }
                })
                .run(|_sink, value| async move {
                    assert_eq!(value, 42);
                    Outcome::Ok(())
                })
                .await
                .unwrap();
            assert_eq!(
                finalized.load(Ordering::SeqCst),
                1,
                "finalizer completed before report"
            );
            if fail_stage {
                assert!(matches!(
                    report.execution.error(),
                    Some(PipelineExecutionError::Stage {
                        stage: 0,
                        input: 0,
                        error: "stage cause",
                    })
                ));
                assert_eq!(report.execution.summary.consumed, 0);
            } else {
                assert!(matches!(report.execution.outcome, Outcome::Ok(_)));
                assert_eq!(report.execution.summary.consumed, 1);
            }
            let close = report.close.unwrap();
            assert!(
                matches!(close.cleanup_outcome, Some(Outcome::Panicked(ref panic))
                if format!("{panic:?}").contains("scoped pipeline finalizer panic"))
            );
        });
        assert!(lab.quiescent && lab.invariant_violations.is_empty());
    }
}

struct UnenteredSource(Arc<AtomicUsize>);

impl IntoIterator for UnenteredSource {
    type Item = usize;
    type IntoIter = std::array::IntoIter<usize, 1>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.fetch_add(1, Ordering::SeqCst);
        [1].into_iter()
    }
}

#[test]
fn scoped_pipeline_pre_admission_refusals_do_not_enter_source_or_callbacks() {
    for cancelled in [false, true] {
        let owner = Cx::for_testing();
        let reason = CancelReason::user("pipeline already stopped");
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let entered = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let transform_calls = Arc::clone(&calls);
        let sink_calls = Arc::clone(&calls);
        let result = futures_lite::future::block_on(
            ScopedPipelineExecution::new(&owner, UnenteredSource(Arc::clone(&entered)), config(1))
                .then(capacity(1), move |_stage, value| {
                    transform_calls.fetch_add(1, Ordering::SeqCst);
                    async move { Outcome::<_, ()>::Ok(value) }
                })
                .run(move |_sink, _value| {
                    sink_calls.fetch_add(1, Ordering::SeqCst);
                    async { Outcome::Ok(()) }
                }),
        );
        if cancelled {
            assert!(
                matches!(result, Err(ScopedPipelineExecutionError::Cancelled(actual)) if actual == reason)
            );
        } else {
            assert!(matches!(
                result,
                Err(ScopedPipelineExecutionError::Region(
                    ChildRegionError::NoRuntimeGateway
                ))
            ));
        }
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    let ((), lab) = run_async_under_lab(0x32_4005, |cx| async move {
        let mut denied = cx.clone();
        denied.runtime_mask = CapMask::none();
        let entered = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let sink_calls = Arc::clone(&calls);
        let result =
            ScopedPipelineExecution::new(&denied, UnenteredSource(Arc::clone(&entered)), config(1))
                .run(move |_sink, _value| {
                    sink_calls.fetch_add(1, Ordering::SeqCst);
                    async { Outcome::<(), ()>::Ok(()) }
                })
                .await;
        assert!(matches!(
            result,
            Err(ScopedPipelineExecutionError::Region(
                ChildRegionError::RuntimeUnavailable
            ))
        ));
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let mint_entered = Arc::clone(&entered);
        let mut task = cx
            .spawn(move |owner| async move {
                let mut work = Box::pin(
                    ScopedPipelineExecution::new(&owner, UnenteredSource(mint_entered), config(1))
                        .run(|_sink, _value| async { Outcome::<(), ()>::Ok(()) }),
                );
                // Lab dispatch cannot publish the queued mint until this turn
                // yields. Cancellation during that actual Pending must still
                // close the admitted region without constructing the iterator.
                poll_fn(|task| {
                    assert!(work.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                owner.cancel_with_reason(CancelReason::user(
                    "cancel while pipeline mint is pending",
                ));
                let report = work.await.unwrap();
                assert!(owner.checkpoint().is_err());
                report
            })
            .unwrap();
        let report = task.join(&cx).await.unwrap();
        assert!(matches!(report.execution.outcome, Outcome::Cancelled(_)));
        assert_eq!(report.execution.summary.admitted, 0);
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert!(report.close.is_ok());
        assert!(report.owner_cancellation.is_some());
    });
    assert!(lab.quiescent && lab.invariant_violations.is_empty());
}

struct AuthoritySource {
    owner: TaskId,
    observations: Arc<[AtomicUsize; 3]>,
}

struct AuthorityIter {
    source: AuthoritySource,
    next: std::ops::Range<usize>,
}

fn assert_owner_authority(owner: TaskId) {
    assert_eq!(Cx::current().unwrap().task_id(), owner);
    assert!(require_ambient_io("scoped pipeline source callback").is_err());
}

impl IntoIterator for AuthoritySource {
    type Item = usize;
    type IntoIter = AuthorityIter;

    fn into_iter(self) -> Self::IntoIter {
        assert_owner_authority(self.owner);
        self.observations[0].fetch_add(1, Ordering::SeqCst);
        AuthorityIter {
            source: self,
            next: 0..3,
        }
    }
}

impl Iterator for AuthorityIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        assert_owner_authority(self.source.owner);
        self.source.observations[1].fetch_add(1, Ordering::SeqCst);
        self.next.next()
    }
}

impl Drop for AuthorityIter {
    fn drop(&mut self) {
        assert_owner_authority(self.source.owner);
        self.source.observations[2].fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn scoped_pipeline_foreign_polling_keeps_source_authority_and_checked_credits_on_owner() {
    let ((), lab) = run_async_under_lab(0x32_4006, |cx| async move {
        let mut owner = cx.clone();
        owner.runtime_mask = <CapSet<true, false, false, false, false> as CapSetRuntimeMask>::MASK;
        let owner_region = owner.region_id();
        let observations = Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
        let output = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let published = Arc::clone(&output);
        let mut work = std::pin::pin!(
            ScopedPipelineExecution::new(
                &owner,
                AuthoritySource {
                    owner: owner.task_id(),
                    observations: Arc::clone(&observations)
                },
                config(2)
            )
            .then(capacity(1), move |stage, value| async move {
                assert_eq!(Cx::current().unwrap().task_id(), stage.task_id());
                assert_ne!(stage.region_id(), owner_region);
                assert!(require_ambient_io("scoped pipeline transform").is_err());
                Outcome::<_, ()>::Ok(value * 10)
            })
            .run(move |sink, value| {
                let output = Arc::clone(&published);
                async move {
                    assert_eq!(Cx::current().unwrap().task_id(), sink.task_id());
                    assert_ne!(sink.region_id(), owner_region);
                    assert!(require_ambient_io("scoped pipeline sink").is_err());
                    output.lock().push(value);
                    Outcome::Ok(())
                }
            })
        );
        let foreign = Cx::new(
            RegionId::new_for_test(91, 4),
            TaskId::new_for_test(92, 5),
            crate::types::Budget::INFINITE,
        );
        let report = poll_fn(|task| {
            let _foreign = Cx::set_current(Some(foreign.clone()));
            assert!(require_ambient_io("foreign before pipeline poll").is_ok());
            let progress = work.as_mut().poll(task);
            assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
            assert!(require_ambient_io("foreign after pipeline poll").is_ok());
            progress
        })
        .await
        .unwrap();
        assert!(matches!(report.execution.outcome, Outcome::Ok(_)));
        assert_eq!(report.execution.summary.consumed, 3);
        assert_eq!(*output.lock(), [0, 10, 20]);
        assert_eq!(
            observations
                .each_ref()
                .map(|value| value.load(Ordering::SeqCst)),
            [1, 4, 1]
        );
        assert!(report.close.is_ok());
        assert!(require_ambient_io("scenario after foreign polling").is_ok());
    });
    assert!(lab.quiescent && lab.invariant_violations.is_empty());
}

#[test]
fn scoped_pipeline_unrun_builder_and_unpolled_future_drop_borrowed_non_send_captures_under_owner() {
    use std::cell::Cell;
    use std::rc::Rc;

    struct Source<'a> {
        drops: &'a Cell<usize>,
        entered: &'a Cell<usize>,
        marker: Rc<()>,
        panic: bool,
    }
    impl IntoIterator for Source<'_> {
        type Item = usize;
        type IntoIter = std::iter::Empty<usize>;
        fn into_iter(self) -> Self::IntoIter {
            self.entered.set(self.entered.get() + 1);
            panic!("an unpolled scoped pipeline must not construct its iterator");
        }
    }
    impl Drop for Source<'_> {
        fn drop(&mut self) {
            assert!(require_ambient_io("scoped pipeline source drop").is_err());
            assert_eq!(Rc::strong_count(&self.marker), 1);
            self.drops.set(self.drops.get() + 1);
            assert!(!self.panic, "first scoped pipeline capture panic");
        }
    }
    struct Capture {
        index: usize,
        drops: Arc<[AtomicUsize; 3]>,
        calls: Arc<AtomicUsize>,
        panic: bool,
    }
    impl Capture {
        fn touch(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Drop for Capture {
        fn drop(&mut self) {
            assert!(require_ambient_io("scoped pipeline stage or sink capture drop").is_err());
            self.drops[self.index].fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic, "secondary scoped pipeline capture panic");
        }
    }

    for unpolled_run in [false, true] {
        for panic_source in [false, true] {
            let foreign = Cx::new(
                RegionId::new_for_test(93, 1),
                TaskId::new_for_test(94, 1),
                crate::types::Budget::INFINITE,
            );
            let _foreign = Cx::set_current(Some(foreign));
            let mut owner = Cx::for_testing();
            owner.runtime_mask = CapMask::none();
            let source_drops = Cell::new(0);
            let entered = Cell::new(0);
            let drops = Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
            let calls = Arc::new(AtomicUsize::new(0));
            let first = Capture {
                index: 0,
                drops: Arc::clone(&drops),
                calls: Arc::clone(&calls),
                panic: panic_source,
            };
            let second = Capture {
                index: 1,
                drops: Arc::clone(&drops),
                calls: Arc::clone(&calls),
                panic: false,
            };
            let builder = ScopedPipelineExecution::new(
                &owner,
                Source {
                    drops: &source_drops,
                    entered: &entered,
                    marker: Rc::new(()),
                    panic: panic_source,
                },
                config(1),
            )
            .then(capacity(1), move |_stage, value| {
                first.touch();
                async move { Outcome::<_, ()>::Ok(value) }
            })
            .then(capacity(1), move |_stage, value| {
                second.touch();
                async move { Outcome::Ok(value) }
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if unpolled_run {
                    let sink = Capture {
                        index: 2,
                        drops: Arc::clone(&drops),
                        calls: Arc::clone(&calls),
                        panic: false,
                    };
                    drop(builder.run(move |_sink, _value| {
                        sink.touch();
                        async { Outcome::Ok(()) }
                    }));
                } else {
                    drop(builder);
                }
            }));
            assert_eq!(result.is_err(), panic_source);
            assert_eq!(entered.get(), 0);
            assert_eq!(source_drops.get(), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                drops.each_ref().map(|value| value.load(Ordering::SeqCst)),
                [1, 1, usize::from(unpolled_run)]
            );
            assert!(require_ambient_io("foreign after scoped pipeline drop").is_ok());
        }
    }
}
