//! Native contracts for typed policy regions (br-asupersync-mfqmcs).
//!
//! Each journey runs on current-thread and two-worker runtimes, with both
//! unified and sharded state. Readiness comes from a real Pending poll, and
//! monitor notifications witness retirement before negative assertions.
//! Replay: rch exec -- env CARGO_TARGET_DIR=target/rch-policy-region cargo test
//! --test native_policy_region -- --test-threads=1

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx, PolicyRegionReport};
use asupersync::error::Error;
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
use asupersync::types::policy::{AggregateDecision, CollectAll, FailFast, Policy, PolicyAction};
use asupersync::types::{CancelKind, CancelReason, Outcome};
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::Duration;

// A test-only wall-clock watchdog bounds a broken cancellation journey; it
// is never used to decide whether a task is ready or a policy has executed.
#[cfg(test)]
fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("policy region must drain every participant");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    bounded(move || {
        for workers in [1, 2] {
            for sharded in [false, true] {
                let builder = if workers == 1 {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::new().worker_threads(workers)
                };
                let runtime = builder.with_sharded_state(sharded).build().unwrap();
                runtime.block_on(async {
                    let root = Cx::current().unwrap();
                    // A real admitted owner is required for monitor identity
                    // on both runtime shapes, including multi-worker block_on.
                    let mut owner = root.spawn(scenario).unwrap();
                    owner.join(&root).await.unwrap();
                });
                drained(&runtime);
            }
        }
    });
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

fn closed<T, E>(report: &PolicyRegionReport<T, E>) {
    assert!(report.close.is_ok(), "{:?}", report.close);
    assert!(!report.cancellation_dispatch_failed);
}

struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Publish the actual admitted Cx only after its cancellation waiter parks.
async fn parked_until_cancelled(cx: &Cx, ready: oneshot::Sender<Cx>) -> CancelReason {
    let mut ready = Some(ready);
    let mut cancelled = pin!(cx.cancelled());
    poll_fn(|task| match cancelled.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                ready.send_blocking(cx.clone()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
    assert!(cx.checkpoint().is_err(), "acknowledge before async cleanup");
    cx.cancel_reason().unwrap()
}

async fn parked_until_released(
    cx: &Cx,
    ready: oneshot::Sender<Cx>,
    mut release: oneshot::Receiver<()>,
) {
    let mut ready = Some(ready);
    let mut receive = pin!(release.recv(cx));
    poll_fn(|task| match receive.as_mut().poll(task) {
        Poll::Ready(result) => Poll::Ready(result.unwrap()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                ready.send_blocking(cx.clone()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
}

async fn fail_fast_before_join(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let (ready, mut parked) = oneshot::channel();
    let (cleaned, mut cleanup) = oneshot::channel();
    let (failure_id, mut failed) = oneshot::channel();
    let mut region = cx
        .open_policy_region::<u32, _>(
            ChildRegionSpec::inherit(),
            FailFast,
            NonZeroUsize::new(2).unwrap(),
        )
        .await
        .unwrap();
    let child_drops = Arc::clone(&drops);
    assert_eq!(
        region
            .spawn(move |child| async move {
                let _drop = Dropped(child_drops);
                let reason = parked_until_cancelled(&child, ready).await;
                // Acknowledged cleanup must survive another Pending poll.
                yield_now().await;
                cleaned.send_blocking(reason).unwrap();
                Outcome::Ok(11)
            })
            .unwrap(),
        0
    );
    let sibling = parked.recv(&cx).await.unwrap();
    assert_eq!(
        region
            .spawn(move |child| async move {
                failure_id.send_blocking(child.task_id()).unwrap();
                Outcome::Err(Error::internal("typed failure"))
            })
            .unwrap(),
        1
    );

    // No join future has been constructed. Policy must already wake the
    // parked sibling while its owner is waiting on unrelated work.
    let reason = cleanup.recv(&cx).await.unwrap();
    assert_eq!(reason.kind, CancelKind::FailFast);
    let failing_task = failed.recv(&cx).await.unwrap();
    assert!(sibling.is_cancel_requested());
    assert!(!cx.is_cancel_requested());

    let report = region.join().await;
    closed(&report);
    assert_eq!(report.outcomes.len(), 2);
    assert!(matches!(&report.outcomes[0], Outcome::Ok(11)));
    assert!(matches!(&report.outcomes[1], Outcome::Err(error)
        if error.message() == Some("typed failure")));
    assert!(matches!(&report.decision, Ok(AggregateDecision::FirstError(error))
        if error.message() == Some("typed failure")));
    assert!(matches!(&report.first_action, Some((task, PolicyAction::CancelSiblings(_)))
        if *task == failing_task));
    assert!(!report.escalated);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn fail_fast_cancels_parked_siblings_before_join_and_preserves_typed_error() {
    native(fail_fast_before_join);
}

async fn collect_all_after_retirement(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let (ready, mut parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (failure_id, mut failing) = oneshot::channel();
    let (fail, mut allowed_to_fail) = oneshot::channel();
    let mut region = cx
        .open_policy_region::<u32, _>(
            ChildRegionSpec::inherit(),
            CollectAll,
            NonZeroUsize::new(2).unwrap(),
        )
        .await
        .unwrap();
    let child_drops = Arc::clone(&drops);
    region
        .spawn(move |child| async move {
            let _drop = Dropped(child_drops);
            parked_until_released(&child, ready, released).await;
            Outcome::Ok(21)
        })
        .unwrap();
    let sibling = parked.recv(&cx).await.unwrap();
    region
        .spawn(move |child| async move {
            failure_id.send_blocking(child.task_id()).unwrap();
            allowed_to_fail.recv(&child).await.unwrap();
            Outcome::Err(Error::internal("collected failure"))
        })
        .unwrap();

    let failing_task = failing.recv(&cx).await.unwrap();
    let monitor = cx.monitor(failing_task).await.unwrap();
    fail.send_blocking(()).unwrap();
    let down = monitor.down(&cx).await.unwrap();
    assert_eq!(down.monitored, failing_task);

    // The failing child has retired, so this cannot pass merely because the
    // scheduler has not reached its terminal policy callback yet.
    assert!(!sibling.is_cancel_requested());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    release.send_blocking(()).unwrap();

    let report = region.join().await;
    closed(&report);
    assert!(matches!(&report.outcomes[0], Outcome::Ok(21)));
    assert!(matches!(&report.outcomes[1], Outcome::Err(error)
        if error.message() == Some("collected failure")));
    assert!(matches!(&report.decision, Ok(AggregateDecision::FirstError(error))
        if error.message() == Some("collected failure")));
    assert!(report.first_action.is_none());
    assert!(!report.escalated);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn collect_all_leaves_parked_sibling_live_after_failed_member_retires() {
    native(collect_all_after_retirement);
}

async fn panic_before_join(cx: Cx) {
    for in_factory in [true, false] {
        let drops = Arc::new(AtomicUsize::new(0));
        let (ready, mut parked) = oneshot::channel();
        let (cleaned, mut cleanup) = oneshot::channel();
        let (panic_id, mut panicking) = oneshot::channel();
        let mut region = cx
            .open_policy_region::<u32, _>(
                ChildRegionSpec::inherit(),
                FailFast,
                NonZeroUsize::new(2).unwrap(),
            )
            .await
            .unwrap();
        let child_drops = Arc::clone(&drops);
        region
            .spawn(move |child| async move {
                let _drop = Dropped(child_drops);
                let reason = parked_until_cancelled(&child, ready).await;
                yield_now().await;
                cleaned.send_blocking(reason).unwrap();
                Outcome::Ok(31)
            })
            .unwrap();
        parked.recv(&cx).await.unwrap();
        if in_factory {
            region
                .spawn(move |child| -> std::future::Ready<Outcome<u32, Error>> {
                    panic_id.send_blocking(child.task_id()).unwrap();
                    panic!("typed factory panic")
                })
                .unwrap();
        } else {
            region
                .spawn(move |child| async move {
                    panic_id.send_blocking(child.task_id()).unwrap();
                    panic!("typed future panic")
                })
                .unwrap();
        }
        let reason = cleanup.recv(&cx).await.unwrap();
        assert_eq!(reason.kind, CancelKind::FailFast);
        let panicking_task = panicking.recv(&cx).await.unwrap();

        let report = region.join().await;
        closed(&report);
        let message = if in_factory {
            "typed factory panic"
        } else {
            "typed future panic"
        };
        assert!(matches!(&report.outcomes[0], Outcome::Ok(31)));
        assert!(matches!(&report.outcomes[1], Outcome::Panicked(payload)
            if payload.message() == message));
        assert!(matches!(&report.decision, Ok(AggregateDecision::Panicked {
            payload,
            first_panic_index: 1,
        }) if payload.message() == message));
        assert!(matches!(&report.first_action, Some((task, PolicyAction::CancelSiblings(_)))
            if *task == panicking_task));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!cx.is_cancel_requested());
    }
}

#[test]
fn factory_and_future_panics_trigger_fail_fast_before_join() {
    native(panic_before_join);
}

async fn owner_cancel_with_dependent_cleanup(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let first_drops = Arc::clone(&drops);
    let second_drops = Arc::clone(&drops);
    let (ready_a, mut parked_a) = oneshot::channel();
    let (ready_b, mut parked_b) = oneshot::channel();
    let (peer_done, mut peer_wait) = oneshot::channel();
    // Cleanup coordination uses the still-live enclosing context, never the
    // already-cancelled member's cancel-aware receiver.
    let cleanup_cx = cx.clone();
    let mut owner = cx
        .spawn(move |owner| async move {
            let mut region = owner
                .open_policy_region::<(u32, CancelKind), _>(
                    ChildRegionSpec::inherit(),
                    CollectAll,
                    NonZeroUsize::new(2).unwrap(),
                )
                .await
                .unwrap();
            region
                .spawn(move |child| async move {
                    let _drop = Dropped(first_drops);
                    let reason = parked_until_cancelled(&child, ready_a).await;
                    peer_wait.recv(&cleanup_cx).await.unwrap();
                    yield_now().await;
                    Outcome::Ok((41, reason.kind))
                })
                .unwrap();
            region
                .spawn(move |child| async move {
                    let _drop = Dropped(second_drops);
                    let reason = parked_until_cancelled(&child, ready_b).await;
                    yield_now().await;
                    peer_done.send_blocking(()).unwrap();
                    Outcome::Ok((42, reason.kind))
                })
                .unwrap();
            region.join().await
        })
        .unwrap();
    let child_a = parked_a.recv(&cx).await.unwrap();
    let child_b = parked_b.recv(&cx).await.unwrap();
    owner.abort_with_reason(CancelReason::race_loser());

    let report = owner.join(&cx).await.unwrap();
    closed(&report);
    assert!(matches!(&report.outcomes[0], Outcome::Ok((41, CancelKind::RaceLost))));
    assert!(matches!(&report.outcomes[1], Outcome::Ok((42, CancelKind::RaceLost))));
    assert!(matches!(&report.decision, Ok(AggregateDecision::AllOk)));
    assert!(report.first_action.is_none());
    assert!(child_a.is_cancel_requested());
    assert!(child_b.is_cancel_requested());
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn owner_cancellation_reaches_all_members_before_dependent_async_cleanup() {
    native(owner_cancel_with_dependent_cleanup);
}

async fn descendant_drain(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let child_drops = Arc::clone(&drops);
    let (descendant_done, mut done) = oneshot::channel();
    let mut region = cx
        .open_policy_region::<u32, _>(
            ChildRegionSpec::inherit(),
            CollectAll,
            NonZeroUsize::new(1).unwrap(),
        )
        .await
        .unwrap();
    region
        .spawn(move |member| async move {
            let (ready, mut parked) = oneshot::channel();
            let _descendant = member
                .spawn(move |descendant| async move {
                    let _drop = Dropped(child_drops);
                    parked_until_cancelled(&descendant, ready).await;
                    yield_now().await;
                    descendant_done.send_blocking(()).unwrap();
                })
                .unwrap();
            parked.recv(&member).await.unwrap();
            Outcome::Ok(51)
        })
        .unwrap();

    let report = region.join().await;
    closed(&report);
    assert!(matches!(&report.outcomes[..], [Outcome::Ok(51)]));
    assert!(matches!(&report.decision, Ok(AggregateDecision::AllOk)));
    assert!(report.first_action.is_none());
    // The untyped descendant is absent from aggregation but must already
    // have completed and dropped before the close receipt is returned.
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    done.recv(&cx).await.unwrap();
    assert!(!cx.is_cancel_requested());
}

#[test]
fn join_waits_for_member_descendants_after_typed_member_retirement() {
    native(descendant_drain);
}

async fn abandoned_join(cx: Cx) {
    for poll_first in [false, true] {
        let outer = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let child_drops = Arc::clone(&drops);
        let (ready, mut parked) = oneshot::channel();
        let (cleaned, mut cleanup) = oneshot::channel();
        let mut region = outer
            .cx()
            .open_policy_region::<u32, _>(
                ChildRegionSpec::inherit(),
                CollectAll,
                NonZeroUsize::new(1).unwrap(),
            )
            .await
            .unwrap();
        region
            .spawn(move |child| async move {
                let _drop = Dropped(child_drops);
                parked_until_cancelled(&child, ready).await;
                yield_now().await;
                cleaned.send_blocking(()).unwrap();
                Outcome::Ok(61)
            })
            .unwrap();
        parked.recv(&cx).await.unwrap();
        let mut joining = Box::pin(region.join());
        if poll_first {
            poll_fn(|task| {
                assert!(joining.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(joining);
        // Observe cleanup before closing the outer region: otherwise outer
        // close could hide a missing cancellation request in join Drop.
        cleanup.recv(&cx).await.unwrap();
        outer.close().await.unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!cx.is_cancel_requested());
    }
}

#[test]
fn dropping_unpolled_or_pending_join_keeps_child_cleanup_owned() {
    native(abandoned_join);
}

#[derive(Clone, Copy)]
struct PanickingCallback;

impl Policy for PanickingCallback {
    type Error = Error;

    fn on_child_outcome<T>(
        &self,
        _child: asupersync::types::TaskId,
        outcome: &Outcome<T, Error>,
    ) -> PolicyAction {
        if matches!(outcome, Outcome::Err(_)) {
            panic!("policy callback panic");
        }
        PolicyAction::Continue
    }

    fn aggregate_outcomes<T>(&self, outcomes: &[Outcome<T, Error>]) -> AggregateDecision<Error> {
        CollectAll.aggregate_outcomes(outcomes)
    }
}

async fn callback_panic_drains(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let child_drops = Arc::clone(&drops);
    let (ready, mut parked) = oneshot::channel();
    let (cleaned, mut cleanup) = oneshot::channel();
    let (failure_id, mut failed) = oneshot::channel();
    let mut region = cx
        .open_policy_region::<u32, _>(
            ChildRegionSpec::inherit(),
            PanickingCallback,
            NonZeroUsize::new(2).unwrap(),
        )
        .await
        .unwrap();
    region
        .spawn(move |child| async move {
            let _drop = Dropped(child_drops);
            parked_until_cancelled(&child, ready).await;
            yield_now().await;
            cleaned.send_blocking(()).unwrap();
            Outcome::Ok(71)
        })
        .unwrap();
    parked.recv(&cx).await.unwrap();
    region
        .spawn(move |child| async move {
            failure_id.send_blocking(child.task_id()).unwrap();
            Outcome::Err(Error::internal("preserved despite policy panic"))
        })
        .unwrap();

    // A panic in user supervision must request cleanup immediately, before
    // this owner constructs a join future, and leave terminal publication live.
    cleanup.recv(&cx).await.unwrap();
    let failing_task = failed.recv(&cx).await.unwrap();
    let report = region.join().await;
    closed(&report);
    assert!(matches!(&report.outcomes[0], Outcome::Ok(71)));
    assert!(matches!(&report.outcomes[1], Outcome::Err(error)
        if error.message() == Some("preserved despite policy panic")));
    assert_eq!(report.decision.as_ref().unwrap_err().message(), "policy callback panic");
    assert!(matches!(&report.first_action, Some((task, PolicyAction::CancelSiblings(_)))
        if *task == failing_task));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn panicking_policy_callback_preserves_child_error_and_still_drains() {
    native(callback_panic_drains);
}

#[derive(Clone)]
struct PanickingAggregate(Arc<AtomicUsize>);

impl Policy for PanickingAggregate {
    type Error = Error;

    fn on_child_outcome<T>(
        &self,
        _child: asupersync::types::TaskId,
        _outcome: &Outcome<T, Error>,
    ) -> PolicyAction {
        PolicyAction::Continue
    }

    fn aggregate_outcomes<T>(&self, _outcomes: &[Outcome<T, Error>]) -> AggregateDecision<Error> {
        assert_eq!(
            self.0.load(Ordering::SeqCst),
            1,
            "aggregation must wait for actual descendant cleanup"
        );
        panic!("policy aggregation panic");
    }
}

async fn aggregation_panic_after_close(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let child_drops = Arc::clone(&drops);
    let mut region = cx
        .open_policy_region::<u32, _>(
            ChildRegionSpec::inherit(),
            PanickingAggregate(Arc::clone(&drops)),
            NonZeroUsize::new(1).unwrap(),
        )
        .await
        .unwrap();
    region
        .spawn(move |member| async move {
            let (ready, mut parked) = oneshot::channel();
            let _descendant = member
                .spawn(move |descendant| async move {
                    let _drop = Dropped(child_drops);
                    parked_until_cancelled(&descendant, ready).await;
                    yield_now().await;
                })
                .unwrap();
            parked.recv(&member).await.unwrap();
            Outcome::Ok(81)
        })
        .unwrap();

    let report = region.join().await;
    closed(&report);
    assert!(matches!(&report.outcomes[..], [Outcome::Ok(81)]));
    assert_eq!(report.decision.as_ref().unwrap_err().message(), "policy aggregation panic");
    assert!(report.first_action.is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn panicking_aggregation_keeps_results_and_waits_for_descendant_cleanup() {
    native(aggregation_panic_after_close);
}

#[derive(Clone, Copy)]
struct EscalatingPolicy;

impl Policy for EscalatingPolicy {
    type Error = Error;

    fn on_child_outcome<T>(
        &self,
        _child: asupersync::types::TaskId,
        outcome: &Outcome<T, Error>,
    ) -> PolicyAction {
        match outcome {
            Outcome::Err(_) | Outcome::Panicked(_) => PolicyAction::Escalate,
            Outcome::Ok(_) | Outcome::Cancelled(_) => PolicyAction::Continue,
        }
    }

    fn aggregate_outcomes<T>(&self, outcomes: &[Outcome<T, Error>]) -> AggregateDecision<Error> {
        CollectAll.aggregate_outcomes(outcomes)
    }
}

async fn escalation_cancels_parent(cx: Cx) {
    let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    let parent_id = parent.region_id();
    let drops = Arc::new(AtomicUsize::new(0));
    let peer_drops = Arc::clone(&drops);
    let member_drops = Arc::clone(&drops);
    let (peer_ready, mut peer_parked) = oneshot::channel();
    let mut parent_peer = parent
        .cx()
        .spawn(move |peer| async move {
            let _drop = Dropped(peer_drops);
            let reason = parked_until_cancelled(&peer, peer_ready).await;
            yield_now().await;
            reason
        })
        .unwrap();
    peer_parked.recv(&cx).await.unwrap();
    let (failure_id, mut failed) = oneshot::channel();

    let mut owner = parent
        .cx()
        .spawn(move |owner| async move {
            let mut region = owner
                .open_policy_region::<u32, _>(
                    ChildRegionSpec::inherit(),
                    EscalatingPolicy,
                    NonZeroUsize::new(2).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(region.parent_region_id(), parent_id);
            let (ready, mut parked) = oneshot::channel();
            region
                .spawn(move |member| async move {
                    let _drop = Dropped(member_drops);
                    parked_until_cancelled(&member, ready).await;
                    yield_now().await;
                    Outcome::Ok(91)
                })
                .unwrap();
            parked.recv(&owner).await.unwrap();
            region
                .spawn(move |child| async move {
                    failure_id.send_blocking(child.task_id()).unwrap();
                    Outcome::Err(Error::internal("escalate to owning parent"))
                })
                .unwrap();
            let report = region.join().await;
            assert!(owner.is_cancel_requested(), "escalation reaches the actual opener");
            report
        })
        .unwrap();

    // Neither explicit parent close nor root shutdown has requested
    // cancellation here. Only Escalate can release the outside peer.
    let report = owner.join(&cx).await.unwrap();
    let peer_reason = parent_peer.join(&cx).await.unwrap();
    assert_eq!(peer_reason.kind, CancelKind::FailFast);
    let failing_task = failed.recv(&cx).await.unwrap();
    closed(&report);
    assert!(report.escalated);
    assert!(matches!(&report.first_action, Some((task, PolicyAction::Escalate))
        if *task == failing_task));
    assert!(matches!(&report.outcomes[0], Outcome::Ok(91)));
    assert!(matches!(&report.outcomes[1], Outcome::Err(error)
        if error.message() == Some("escalate to owning parent")));
    assert!(matches!(&report.decision, Ok(AggregateDecision::FirstError(error))
        if error.message() == Some("escalate to owning parent")));
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(!cx.is_cancel_requested(), "the enclosing root is outside the targeted parent");
    parent.close().await.unwrap();
}

#[test]
fn escalation_cancels_the_admitted_parent_and_preserves_owner_report() {
    native(escalation_cancels_parent);
}
