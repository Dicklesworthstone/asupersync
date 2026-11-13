//! Native slot-reuse and subtree-drain boundaries for the lazy all-settled join.

use super::{ScopedJoinAttempt, ScopedJoinBoundedStop, ScopedJoinTask};
use crate::Cx;
use crate::channel::{mpsc, oneshot};
use crate::cx::{ChildRegionSpec, RaceFactory};
use crate::runtime::spawn_mailbox::{RegionCommand, RegisterRegionFinalizer};
use crate::runtime::{RootDrainOutcome, RuntimeBuilder, TaskHandle};
use crate::sync::Notify;
use crate::types::{CancelKind, CancelReason, RegionId};
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cleaning: AtomicBool,
    finished: AtomicBool,
    retired: AtomicBool,
    changed: Notify,
}

impl Witness {
    fn note(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait(&self, ready: impl Fn(&Self) -> bool) {
        self.changed.wait_until(|| ready(self)).await;
    }
}

struct Retire(Arc<Witness>);

impl Drop for Retire {
    fn drop(&mut self) {
        self.0.note(&self.0.retired);
    }
}

async fn held_descendant(
    cx: Cx,
    sender: mpsc::Sender<()>,
    seen: Arc<Witness>,
    mut release: oneshot::Receiver<()>,
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
    let reason = cx
        .cancel_reason()
        .expect("descendant cancellation attribution");
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
        .expect("controller releases actual pending cleanup");
    }
    drop(permit);
    seen.note(&seen.finished);
    reason
}

async fn register_finalizer(cx: &Cx, finalizer: impl FnOnce() + Send + 'static) {
    let (send, mut receive) = oneshot::channel();
    let request = RegisterRegionFinalizer::new(cx.region_id(), finalizer, send);
    cx.spawn_gateway_handle()
        .unwrap()
        .enqueue_region_command(RegionCommand::RegisterFinalizer(request))
        .unwrap();
    receive.recv_uninterruptible().await.unwrap().unwrap();
}

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("bounded-scoped-join-native".to_owned())
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
                                .expect("bounded join native scenario");
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
    // The watchdog bounds failure. Positive assertions below use actual
    // Pending polls, checked obligations, finalizers, and close receipts.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("bounded join must retire its admitted subtrees");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn assert_closed<T>(attempt: &ScopedJoinAttempt<T>, index: usize, parent: RegionId) -> RegionId {
    assert_eq!(attempt.index, index);
    let region = attempt.region_id.expect("private branch region admitted");
    assert_ne!(region, parent);
    let close = attempt
        .close
        .as_ref()
        .expect("admitted branch retains its close receipt")
        .as_ref()
        .expect("actual subtree quiescence");
    assert!(close.cleanup_outcome.is_none());
    assert!(close.descendant_panic.is_none());
    region
}

async fn slot_lasts_through_descendant_and_finalizer(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let pulled = Arc::new(AtomicUsize::new(0));
    let finalized = Arc::new(AtomicUsize::new(0));
    let retained = Arc::new(parking_lot::Mutex::new(
        Vec::<TaskHandle<CancelReason>>::new(),
    ));
    let (sender, mut receiver) = mpsc::channel(1);
    let (release, cleanup) = oneshot::channel();
    let source_seen = Arc::clone(&seen);
    let source_pulled = Arc::clone(&pulled);
    let source_finalized = Arc::clone(&finalized);
    let source_retained = Arc::clone(&retained);
    let source_sender = sender.clone();
    let mut cleanup = Some(cleanup);
    let factories = (0..2).map(move |index| {
        source_pulled.fetch_add(1, Ordering::SeqCst);
        if index == 1 {
            // This assertion is in Iterator::next, before the second factory
            // can be submitted. A joined body cannot release this slot early.
            assert_eq!(source_finalized.load(Ordering::Acquire), 1);
            assert!(source_seen.retired.load(Ordering::Acquire));
        }
        let seen = Arc::clone(&source_seen);
        let finalized = Arc::clone(&source_finalized);
        let retained = Arc::clone(&source_retained);
        let sender = source_sender.clone();
        let cleanup = if index == 0 { cleanup.take() } else { None };
        move |branch: Cx| async move {
            if index == 0 {
                let finalizer_seen = Arc::clone(&seen);
                let finalizer_sender = sender.clone();
                register_finalizer(&branch, move || {
                    assert!(finalizer_seen.finished.load(Ordering::Acquire));
                    assert!(finalizer_seen.retired.load(Ordering::Acquire));
                    assert_eq!(
                        finalizer_sender
                            .telemetry_snapshot(0x6a_01)
                            .reserved_uncommitted_obligations,
                        0
                    );
                    finalized.fetch_add(1, Ordering::Release);
                })
                .await;
                let child_seen = Arc::clone(&seen);
                let child = branch
                    .spawn(move |child| {
                        held_descendant(child, sender, child_seen, cleanup.unwrap())
                    })
                    .unwrap();
                seen.wait(|state| state.parked.load(Ordering::Acquire))
                    .await;
                // Retain the handle outside the body: body capture retirement
                // must not be the operation that releases the descendant.
                retained.lock().push(child);
                Err::<u64, _>("first branch domain failure")
            } else {
                Ok(42)
            }
        }
    });
    let mut joining =
        std::pin::pin!(owner.join_all_scoped_bounded(NonZeroUsize::new(1).unwrap(), factories,));
    let mut cleaning = std::pin::pin!(seen.wait(|state| state.cleaning.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(joining.as_mut().poll(task).is_pending());
        cleaning.as_mut().poll(task)
    })
    .await;
    assert_eq!(pulled.load(Ordering::Acquire), 1);
    assert_eq!(finalized.load(Ordering::Acquire), 0);
    assert!(!seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x6a_01)
            .reserved_uncommitted_obligations,
        1
    );
    release.send_blocking(()).unwrap();
    let report = joining.await.unwrap();
    assert!(matches!(report.stop, ScopedJoinBoundedStop::Completed));
    assert!(report.input_exhausted);
    assert!(report.input_panic.is_none());
    assert!(report.owner_cancellation.is_none());
    assert_eq!(report.max_active, 1);
    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        &report.attempts[0].task,
        ScopedJoinTask::Joined(Ok(Err("first branch domain failure")))
    ));
    assert!(matches!(
        &report.attempts[1].task,
        ScopedJoinTask::Joined(Ok(Ok(42)))
    ));
    let first = assert_closed(&report.attempts[0], 0, owner.region_id());
    let second = assert_closed(&report.attempts[1], 1, owner.region_id());
    assert_ne!(first, second);
    assert_eq!(pulled.load(Ordering::Acquire), 2);
    assert_eq!(finalized.load(Ordering::Acquire), 1);
    assert!(seen.finished.load(Ordering::Acquire) && seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x6a_01)
            .reserved_uncommitted_obligations,
        0
    );
    assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
    let mut handles = retained.lock();
    assert_eq!(handles.len(), 1);
    assert!(matches!(handles[0].try_join(), Ok(Some(_))));
    assert!(!owner.is_cancel_requested());
}

#[test]
fn bounded_join_native_reuses_slot_only_after_descendant_obligation_and_finalizer_close() {
    native(slot_lasts_through_descendant_and_finalizer);
}

async fn source_panic_closes_subtree_before_ordinary_descendant_join(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let first_finalized = Arc::new(AtomicUsize::new(0));
    let source_polls = Arc::new(AtomicUsize::new(0));
    let (sender, mut receiver) = mpsc::channel(1);
    let (release, cleanup) = oneshot::channel();
    let first_seen = Arc::clone(&seen);
    let finalized = Arc::clone(&first_finalized);
    let second_seen = Arc::clone(&seen);
    let child_sender = sender.clone();
    let factories: Vec<RaceFactory<u64>> = vec![
        Box::new(move |branch| {
            Box::pin(async move {
                register_finalizer(&branch, move || {
                    finalized.fetch_add(1, Ordering::Release);
                })
                .await;
                first_seen
                    .wait(|state| state.parked.load(Ordering::Acquire))
                    .await;
                11
            })
        }),
        Box::new(move |branch| {
            Box::pin(async move {
                let nested = branch
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let child_seen = Arc::clone(&second_seen);
                let mut child = nested
                    .cx()
                    .spawn(move |child| held_descendant(child, child_sender, child_seen, cleanup))
                    .unwrap();
                // Cancellation of only this direct task cannot release the
                // ordinary join; its entire private subtree must be cancelled.
                let reason = child.join(&branch).await.unwrap();
                assert_eq!(reason.kind, CancelKind::ParentCancelled);
                assert!(branch.checkpoint().is_err());
                drop(nested);
                22
            })
        }),
    ];
    let mut prefix = factories.into_iter();
    let polled = Arc::clone(&source_polls);
    let source_finalized = Arc::clone(&first_finalized);
    let source = std::iter::from_fn(move || {
        polled.fetch_add(1, Ordering::SeqCst);
        if let Some(factory) = prefix.next() {
            return Some(factory);
        }
        assert_eq!(
            source_finalized.load(Ordering::Acquire),
            1,
            "the completed first branch must close before another source pull"
        );
        panic!("bounded join source failed after its closed prefix");
    });
    let mut joining =
        std::pin::pin!(owner.join_all_scoped_bounded(NonZeroUsize::new(2).unwrap(), source,));
    let mut cleaning = std::pin::pin!(seen.wait(|state| state.cleaning.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(joining.as_mut().poll(task).is_pending());
        cleaning.as_mut().poll(task)
    })
    .await;
    assert_eq!(source_polls.load(Ordering::Acquire), 3);
    assert_eq!(first_finalized.load(Ordering::Acquire), 1);
    assert!(!seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x6a_02)
            .reserved_uncommitted_obligations,
        1
    );
    release.send_blocking(()).unwrap();
    let report = joining.await.unwrap();
    assert!(matches!(
        report.stop,
        ScopedJoinBoundedStop::InputPanicked { next_index: 2 }
    ));
    assert!(!report.input_exhausted, "a panicking tail is not EOF");
    assert!(matches!(report.input_panic, Some(ref panic)
        if format!("{panic:?}").contains("bounded join source failed after its closed prefix")));
    assert!(report.owner_cancellation.is_none());
    assert_eq!(report.max_active, 2);
    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        &report.attempts[0].task,
        ScopedJoinTask::Joined(Ok(11))
    ));
    assert!(matches!(
        &report.attempts[1].task,
        ScopedJoinTask::Joined(Ok(22))
    ));
    assert_closed(&report.attempts[0], 0, owner.region_id());
    assert_closed(&report.attempts[1], 1, owner.region_id());
    assert_eq!(
        source_polls.load(Ordering::Acquire),
        3,
        "stopped source is never polled again"
    );
    assert!(seen.finished.load(Ordering::Acquire) && seen.retired.load(Ordering::Acquire));
    assert_eq!(
        sender
            .telemetry_snapshot(0x6a_02)
            .reserved_uncommitted_obligations,
        0
    );
    assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
    assert!(!owner.is_cancel_requested());
}

#[test]
fn bounded_join_native_source_panic_cancels_descendants_before_joining_held_body() {
    native(source_panic_closes_subtree_before_ordinary_descendant_join);
}
