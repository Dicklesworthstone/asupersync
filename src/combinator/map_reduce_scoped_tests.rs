#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::{mpsc, oneshot};
use crate::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use crate::cx::io_gate::require_ambient_io;
use crate::lab::run_async_under_lab;
use crate::runtime::spawn_mailbox::{RegionCommand, RegisterRegionFinalizer};
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::sync::Notify;
use crate::types::{TaskId, Time};
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

fn limits(concurrency: usize, retained: usize) -> MapReduceLimits {
    MapReduceLimits::new(
        NonZeroUsize::new(concurrency).unwrap(),
        NonZeroUsize::new(retained).unwrap(),
    )
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
        let mut cancellation = std::pin::pin!(cx.cancelled());
        poll_fn(|task| {
            let progress = cancellation.as_mut().poll(task);
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
        .expect("controller releases cleanup after observing Pending");
    }
    drop(permit);
    seen.note(&seen.finished);
    assert!(!panic_after_cleanup, "scoped map descendant cleanup panic");
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
        .name("scoped-map-reduce-native".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
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
                            owner.join(&root).await.expect("native scoped map scenario");
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
    // This watchdog only bounds failure. Positive evidence comes from actual
    // Pending polls, checked obligations, terminal joins and close receipts.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("scoped map-reduce must drain its operation subtree");
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
    let send = sender.clone();
    let mut operation = cx
        .spawn(move |owner| async move {
            let owner_region = owner.region_id();
            let mut inputs = vec![(0, Some(cleanup))];
            if finish == Finish::Error {
                inputs.push((1, None));
            }
            let report = execute_map_reduce_scoped(
                &owner,
                limits(2, 2),
                inputs,
                move |mapper, (index, cleanup)| {
                    let seen = Arc::clone(&observe);
                    let regions = Arc::clone(&regions);
                    let handles = Arc::clone(&handles);
                    let sender = send.clone();
                    async move {
                        assert_ne!(mapper.region_id(), owner_region);
                        if index == 1 {
                            seen.wait(|state| state.parked.load(Ordering::Acquire))
                                .await;
                            return Outcome::Err("initiating mapper failure");
                        }
                        let nested = mapper
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
                            // This ordinary join ignores mapper cancellation. Only
                            // cancelling the owned subtree can release the child.
                            let reason = descendant
                                .join(&mapper)
                                .await
                                .expect("acknowledged descendant result");
                            assert_eq!(reason.kind, CancelKind::ParentCancelled);
                            drop(nested);
                            Outcome::Cancelled(reason)
                        } else {
                            // External retention rules out handle Drop as the cause
                            // of successful operation cleanup.
                            handles.lock().push(descendant);
                            regions.lock().push(nested);
                            Outcome::Ok(String::from("mapped value"))
                        }
                    }
                },
                |left, right| format!("{left}>{right}"),
            )
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
        "cleanup gates report publication"
    );
    assert!(!seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x32_30)
            .reserved_uncommitted_obligations,
        1
    );
    assert!(!unrelated_seen.finished.load(Ordering::Acquire));
    let late_reason = CancelReason::shutdown().with_message("owner cancelled during map close");
    if finish == Finish::CancelDuringClose {
        operation.abort_with_reason(late_reason.clone());
    }
    release.send_blocking(()).unwrap();
    let report = operation
        .join(&cx)
        .await
        .expect("owner publishes typed execution report");
    assert_ne!(report.region_id, cx.region_id());
    assert_eq!(report.execution.admitted, report.execution.completed);
    assert!(seen.finished.load(Ordering::Acquire));
    assert!(seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x32_30)
            .reserved_uncommitted_obligations,
        0
    );
    assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
    let close = report.close.expect("actual operation subtree quiesced");
    assert!(close.cleanup_outcome.is_none());
    if finish == Finish::Error {
        assert!(matches!(
            report.execution.outcome,
            Outcome::Err(MapReduceExecutionError::Map("initiating mapper failure"))
        ));
        assert_eq!(report.execution.failure_index, Some(1));
        assert_eq!(
            report.execution.stopped_by,
            Some((1, MapReduceStopCause::Error))
        );
        assert!(report.execution.errors.is_empty());
        assert!(close.descendant_panic.is_none());
    } else {
        assert!(
            matches!(report.execution.outcome, Outcome::Ok(Some(ref value)) if value == "mapped value")
        );
        assert!(report.execution.stopped_by.is_none());
        if finish == Finish::DescendantPanic {
            assert!(
                matches!(close.descendant_panic, Some(ref panic) if format!("{panic:?}").contains("scoped map descendant cleanup panic"))
            );
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
            "retained descendant retired before parent close"
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
fn scoped_map_native_failure_cancels_descendants_before_mapper_joins() {
    native(|cx| subtree_journey(cx, Finish::Error));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn scoped_map_native_success_closes_leftovers_and_preserves_independent_cleanup_outcomes() {
    for finish in [
        Finish::Success,
        Finish::DescendantPanic,
        Finish::CancelDuringClose,
    ] {
        match finish {
            Finish::Success => native(|cx| subtree_journey(cx, Finish::Success)),
            Finish::DescendantPanic => native(|cx| subtree_journey(cx, Finish::DescendantPanic)),
            Finish::CancelDuringClose => {
                native(|cx| subtree_journey(cx, Finish::CancelDuringClose))
            }
            Finish::Error => unreachable!(),
        }
    }
}

#[test]
fn scoped_map_lab_owns_nested_failure_and_success_boundaries() {
    for finish in [Finish::Error, Finish::Success] {
        let ((), report) = run_async_under_lab(0x32_3001, move |cx| subtree_journey(cx, finish));
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
    let mut operation = cx
        .spawn(move |owner| async move {
            let signal = Arc::clone(&observe);
            let mut work = Box::pin(execute_map_reduce_scoped(
                &owner,
                limits(1, 1),
                [cleanup],
                move |mapper, cleanup| {
                    let seen = Arc::clone(&observe);
                    let sender = send.clone();
                    async move {
                        let nested = mapper
                            .open_child_region(ChildRegionSpec::inherit())
                            .await
                            .unwrap();
                        let mut child = nested
                            .cx()
                            .spawn(move |child| {
                                held_descendant(child, sender, seen, cleanup, false)
                            })
                            .unwrap();
                        let reason = child.join(&mapper).await.unwrap();
                        drop(nested);
                        Outcome::<usize, ()>::Cancelled(reason)
                    }
                },
                |left, right| left + right,
            ));
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
    let reason = CancelReason::shutdown().with_cause(CancelReason::user("stop map operation"));
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
        assert!(
            report.is_none(),
            "Drop requests cleanup without claiming to await it"
        );
    } else {
        let report = report.unwrap();
        assert!(matches!(report.execution.outcome, Outcome::Cancelled(_)));
        assert_eq!(report.owner_cancellation, Some(reason));
        assert_eq!(report.execution.admitted, report.execution.completed);
        let close = report.close.unwrap();
        assert!(close.cleanup_outcome.is_none() && close.descendant_panic.is_none());
    }
    seen.wait(|state| state.retired.load(Ordering::Acquire))
        .await;
    assert!(seen.finished.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x32_31)
            .reserved_uncommitted_obligations,
        0
    );
    assert!(!cx.is_cancel_requested());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn scoped_map_native_owner_cancel_and_abandonment_request_entire_subtree_cleanup() {
    native(|cx| cancellation_or_drop_journey(cx, false));
    native(|cx| cancellation_or_drop_journey(cx, true));
}

#[test]
fn scoped_map_bounds_and_noncommutative_fold_survive_operation_ownership() {
    struct MoveOnly(String);
    for count in [0, 1, 9] {
        for (concurrency, retained) in [(1, 1), (4, 2), (2, 5)] {
            let ((), lab) = run_async_under_lab(0x32_3002, move |cx| async move {
                let report =
                    execute_map_reduce_scoped(
                        &cx,
                        limits(concurrency, retained),
                        0..count,
                        |_mapper, index| async move {
                            Outcome::<_, ()>::Ok(MoveOnly(index.to_string()))
                        },
                        |left, right| MoveOnly(format!("{}>{}", left.0, right.0)),
                    )
                    .await
                    .unwrap();
                assert_eq!(report.execution.admitted, count);
                assert_eq!(report.execution.completed, count);
                assert_eq!(report.execution.reduced, count);
                assert!(report.execution.max_in_flight <= concurrency);
                assert!(report.execution.max_retained <= retained);
                let Outcome::Ok(value) = report.execution.outcome else {
                    panic!("successful fold")
                };
                assert_eq!(
                    value.map(|value| value.0),
                    (count > 0).then(|| (0..count)
                        .map(|index| index.to_string())
                        .collect::<Vec<_>>()
                        .join(">")),
                );
                let close = report.close.unwrap();
                assert!(close.cleanup_outcome.is_none() && close.descendant_panic.is_none());
                assert!(report.owner_cancellation.is_none());
            });
            assert!(lab.quiescent && lab.invariant_violations.is_empty());
        }
    }
}

#[test]
fn scoped_map_finalizer_panic_is_independent_of_success_or_initiating_mapper_error() {
    for fail_mapper in [false, true] {
        let ((), lab) = run_async_under_lab(0x32_3003, move |cx| async move {
            let finalized = Arc::new(AtomicUsize::new(0));
            let observe = Arc::clone(&finalized);
            let report = execute_map_reduce_scoped(
                &cx,
                limits(1, 1),
                [()],
                move |mapper, ()| {
                    let finalized = Arc::clone(&observe);
                    async move {
                        let (ack, mut acknowledged) = oneshot::channel();
                        let request = RegisterRegionFinalizer::new(
                            mapper.region_id(),
                            move || {
                                finalized.fetch_add(1, Ordering::SeqCst);
                                panic!("scoped map finalizer panic");
                            },
                            ack,
                        );
                        mapper
                            .spawn_gateway_handle()
                            .unwrap()
                            .enqueue_region_command(RegionCommand::RegisterFinalizer(request))
                            .unwrap();
                        acknowledged.recv_uninterruptible().await.unwrap().unwrap();
                        if fail_mapper {
                            Outcome::Err("mapper cause")
                        } else {
                            Outcome::Ok(42)
                        }
                    }
                },
                |left, right| left + right,
            )
            .await
            .unwrap();
            assert_eq!(
                finalized.load(Ordering::SeqCst),
                1,
                "finalizer finished before report"
            );
            if fail_mapper {
                assert!(matches!(
                    report.execution.outcome,
                    Outcome::Err(MapReduceExecutionError::Map("mapper cause"))
                ));
                assert_eq!(
                    report.execution.stopped_by,
                    Some((0, MapReduceStopCause::Error))
                );
            } else {
                assert!(matches!(report.execution.outcome, Outcome::Ok(Some(42))));
            }
            let close = report.close.unwrap();
            assert!(
                matches!(close.cleanup_outcome, Some(Outcome::Panicked(ref panic)) if format!("{panic:?}").contains("scoped map finalizer panic"))
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
fn scoped_map_refusals_do_not_enter_sources_or_construct_mappers() {
    for cancelled in [false, true] {
        let owner = Cx::for_testing();
        let reason = CancelReason::user("already stopped");
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let entered = Arc::new(AtomicUsize::new(0));
        let factories = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&factories);
        let result = futures_lite::future::block_on(execute_map_reduce_scoped(
            &owner,
            limits(1, 1),
            UnenteredSource(Arc::clone(&entered)),
            move |_mapper, value| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move { Outcome::<_, ()>::Ok(value) }
            },
            |left, right| left + right,
        ));
        if cancelled {
            assert!(
                matches!(result, Err(ScopedMapReduceError::Cancelled(actual)) if actual == reason)
            );
        } else {
            assert!(matches!(
                result,
                Err(ScopedMapReduceError::Region(
                    ChildRegionError::NoRuntimeGateway
                ))
            ));
        }
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(factories.load(Ordering::SeqCst), 0);
    }
    let ((), lab) = run_async_under_lab(0x32_3004, |cx| async move {
        let mut denied = cx.clone();
        denied.runtime_mask = CapMask::none();
        let entered = Arc::new(AtomicUsize::new(0));
        let factories = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&factories);
        let result = execute_map_reduce_scoped(
            &denied,
            limits(1, 1),
            UnenteredSource(Arc::clone(&entered)),
            move |_mapper, value| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move { Outcome::<_, ()>::Ok(value) }
            },
            |left, right| left + right,
        )
        .await;
        assert!(matches!(
            result,
            Err(ScopedMapReduceError::Region(
                ChildRegionError::RuntimeUnavailable
            ))
        ));
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(factories.load(Ordering::SeqCst), 0);
        assert!(!cx.is_cancel_requested());
    });
    assert!(lab.quiescent && lab.invariant_violations.is_empty());
}

#[test]
fn scoped_map_cleanup_provenance_requires_the_exact_operation_cause_chain() {
    let operation = RegionId::new_for_test(31, 2);
    let owner = TaskId::new_for_test(32, 3);
    let marker = CancelReason::race_loser()
        .with_region(operation)
        .with_task(owner)
        .with_timestamp(Time::from_nanos(37))
        .with_message("map-reduce sibling drain");
    let forwarded = CancelReason::parent_cancelled()
        .with_region(operation)
        .with_cause(
            CancelReason::parent_cancelled()
                .with_region(operation)
                .with_cause(marker.clone()),
        );
    assert!(executing_map_induced_cancel(&marker, Some(&marker), false));
    assert!(executing_map_induced_cancel(
        &forwarded,
        Some(&marker),
        true
    ));
    assert!(!executing_map_induced_cancel(
        &forwarded,
        Some(&marker),
        false
    ));
    assert!(!executing_map_induced_cancel(&forwarded, None, true));
    let other_operation = marker.clone().with_region(RegionId::new_for_test(33, 2));
    assert!(!executing_map_induced_cancel(
        &CancelReason::parent_cancelled().with_cause(other_operation),
        Some(&marker),
        true,
    ));
    let independent = CancelReason::shutdown().with_cause(marker.clone());
    assert!(!executing_map_induced_cancel(
        &independent,
        Some(&marker),
        true
    ));
    assert!(!executing_map_induced_cancel(
        &CancelReason::parent_cancelled().with_cause(independent),
        Some(&marker),
        true,
    ));
    assert!(!executing_map_induced_cancel(
        &CancelReason::parent_cancelled(),
        Some(&marker),
        true
    ));
}

fn assert_owner_authority(owner: TaskId) {
    assert_eq!(Cx::current().unwrap().task_id(), owner);
    assert!(require_ambient_io("scoped map callback").is_err());
}

struct AuthoritySource {
    owner: TaskId,
    observations: Arc<[AtomicUsize; 5]>,
}

struct AuthorityIter {
    source: AuthoritySource,
    next: std::ops::Range<usize>,
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
        self.source.observations[3].fetch_add(1, Ordering::SeqCst);
    }
}

struct AuthorityReducer {
    owner: TaskId,
    observations: Arc<[AtomicUsize; 5]>,
}

impl AuthorityReducer {
    fn reduce(&self, left: usize, right: usize) -> usize {
        assert_owner_authority(self.owner);
        self.observations[2].fetch_add(1, Ordering::SeqCst);
        left * 10 + right
    }
}

impl Drop for AuthorityReducer {
    fn drop(&mut self) {
        assert_owner_authority(self.owner);
        self.observations[4].fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn scoped_map_callbacks_and_capture_cleanup_use_explicit_owner_under_foreign_polling() {
    let ((), lab) = run_async_under_lab(0x32_3005, |cx| async move {
        let mut owner = cx.clone();
        owner.runtime_mask = <CapSet<true, false, false, false, false> as CapSetRuntimeMask>::MASK;
        let observations = Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
        let reducer = AuthorityReducer {
            owner: owner.task_id(),
            observations: Arc::clone(&observations),
        };
        let mut work = std::pin::pin!(execute_map_reduce_scoped(
            &owner,
            limits(2, 2),
            AuthoritySource {
                owner: owner.task_id(),
                observations: Arc::clone(&observations)
            },
            |mapper, value| async move {
                assert_eq!(Cx::current().unwrap().task_id(), mapper.task_id());
                assert!(require_ambient_io("scoped map child").is_err());
                Outcome::<_, ()>::Ok(value)
            },
            move |left, right| reducer.reduce(left, right),
        ));
        let foreign = Cx::for_testing();
        let report = poll_fn(|task| {
            let _foreign = Cx::set_current(Some(foreign.clone()));
            assert!(require_ambient_io("foreign before map poll").is_ok());
            let progress = work.as_mut().poll(task);
            assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
            assert!(require_ambient_io("foreign after map poll").is_ok());
            progress
        })
        .await
        .unwrap();
        assert!(matches!(report.execution.outcome, Outcome::Ok(Some(12))));
        assert!(report.close.is_ok());
        let actual = observations
            .each_ref()
            .map(|value| value.load(Ordering::SeqCst));
        assert_eq!(actual, [1, 4, 2, 1, 1]);
        assert!(require_ambient_io("scenario after foreign poll").is_ok());
    });
    assert!(lab.quiescent && lab.invariant_violations.is_empty());
}

#[test]
fn scoped_map_unpolled_drop_supports_borrowed_non_send_state_and_owner_authority() {
    use std::cell::Cell;

    struct BorrowedDrop<'a>(&'a Cell<usize>);
    impl Drop for BorrowedDrop<'_> {
        fn drop(&mut self) {
            assert!(require_ambient_io("scoped map unpolled capture drop").is_err());
            self.0.set(self.0.get() + 1);
        }
    }
    impl IntoIterator for BorrowedDrop<'_> {
        type Item = usize;
        type IntoIter = std::iter::Empty<usize>;
        fn into_iter(self) -> Self::IntoIter {
            panic!("an unpolled operation must not enter its source");
        }
    }
    impl BorrowedDrop<'_> {
        fn touch(&self) {
            assert_eq!(self.0.get(), 0);
        }
    }

    let foreign = Cx::for_testing();
    let _foreign = Cx::set_current(Some(foreign));
    let mut owner = Cx::for_testing();
    owner.runtime_mask = CapMask::none();
    let source_drops = Cell::new(0);
    let reducer_drops = Cell::new(0);
    let reducer = BorrowedDrop(&reducer_drops);
    let work = execute_map_reduce_scoped(
        &owner,
        limits(1, 1),
        BorrowedDrop(&source_drops),
        |_mapper, value| async move { Outcome::<_, ()>::Ok(value) },
        move |left, right| {
            reducer.touch();
            left + right
        },
    );
    drop(work);
    assert_eq!(source_drops.get(), 1);
    assert_eq!(reducer_drops.get(), 1);
    assert!(require_ambient_io("foreign after unpolled drop").is_ok());
}
