//! Native ownership boundaries for factory-based all-settled joins.

use super::{ScopedJoinAttempt, ScopedJoinStop, ScopedJoinTask};
use crate::Cx;
use crate::channel::oneshot;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::sync::Notify;
use crate::types::{CancelReason, RegionId};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
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

async fn held_cleanup(cx: Cx, seen: Arc<Witness>, mut release: oneshot::Receiver<()>) {
    let _retire = Retire(Arc::clone(&seen));
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
    assert!(cx.checkpoint().is_err(), "owned task acknowledges cancellation");
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
    seen.note(&seen.finished);
}

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("scoped-join-native".to_owned())
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
                            let mut owner = root.spawn(scenario).expect("native scenario owner");
                            owner.join(&root).await.expect("native scoped join scenario");
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
    // A timeout only bounds failure; every positive readiness assertion below
    // comes from an actual Pending poll, a cleanup receipt, or task retirement.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("scoped join must retire every owned branch");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn assert_closed<T>(attempt: &ScopedJoinAttempt<T>, index: usize, parent: RegionId) -> RegionId {
    assert_eq!(attempt.index, index);
    let region = attempt.region_id.expect("admitted branch has a private region");
    assert_ne!(region, parent);
    let close = attempt
        .close
        .as_ref()
        .expect("admitted branch has a close receipt")
        .as_ref()
        .expect("branch region actually quiesced");
    assert!(close.descendant_panic.is_none());
    assert!(close.cleanup_outcome.is_none());
    region
}

async fn completed_branch_drains_while_sibling_is_pending(owner: Cx) {
    let left_seen = Arc::new(Witness::default());
    let right_seen = Arc::new(Witness::default());
    let left_factory_seen = Arc::clone(&left_seen);
    let right_factory_seen = Arc::clone(&right_seen);
    let (release_left, left_cleanup) = oneshot::channel();
    let (release_right, mut right_body) = oneshot::channel();
    let mut joining = std::pin::pin!(owner.join_scoped(
        move |branch| async move {
            let child_seen = Arc::clone(&left_factory_seen);
            branch
                .spawn(move |child| held_cleanup(child, child_seen, left_cleanup))
                .unwrap();
            left_factory_seen
                .wait(|state| state.parked.load(Ordering::Acquire))
                .await;
            Err::<u64, _>("left domain failure")
        },
        move |branch| async move {
            {
                let mut body = std::pin::pin!(right_body.recv(&branch));
                poll_fn(|task| {
                    let progress = body.as_mut().poll(task);
                    if progress.is_pending() && !right_factory_seen.parked.load(Ordering::Acquire) {
                        right_factory_seen.note(&right_factory_seen.parked);
                    }
                    progress
                })
                .await
                .expect("left failure must not cancel its sibling");
            }
            right_factory_seen.note(&right_factory_seen.finished);
            String::from("right success")
        },
    ));
    let mut boundaries = std::pin::pin!(async {
        left_seen
            .wait(|state| state.cleaning.load(Ordering::Acquire))
            .await;
        right_seen
            .wait(|state| state.parked.load(Ordering::Acquire))
            .await;
    });
    poll_fn(|task| {
        assert!(joining.as_mut().poll(task).is_pending());
        boundaries.as_mut().poll(task)
    })
    .await;
    assert!(!left_seen.retired.load(Ordering::Acquire));
    assert!(!right_seen.finished.load(Ordering::Acquire));
    release_left.send_blocking(()).unwrap();
    let mut retired = std::pin::pin!(left_seen.wait(|state| state.retired.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(joining.as_mut().poll(task).is_pending());
        retired.as_mut().poll(task)
    })
    .await;
    assert!(!right_seen.finished.load(Ordering::Acquire));
    release_right.send_blocking(()).unwrap();
    let report = joining.await.expect("heterogeneous pair report");
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert!(matches!(
        report.left.task,
        ScopedJoinTask::Joined(Ok(Err("left domain failure")))
    ));
    assert!(matches!(
        &report.right.task,
        ScopedJoinTask::Joined(Ok(value)) if value == "right success"
    ));
    let left_region = assert_closed(&report.left, 0, owner.region_id());
    let right_region = assert_closed(&report.right, 1, owner.region_id());
    assert_ne!(left_region, right_region);
    assert!(report.owner_cancellation.is_none());
    assert!(left_seen.finished.load(Ordering::Acquire));
    assert!(right_seen.finished.load(Ordering::Acquire));
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_join_native_pair_preserves_types_and_drains_completed_branch_early() {
    native(completed_branch_drains_while_sibling_is_pending);
}

async fn cancellation_fans_out_before_held_cleanup(owner: Cx) {
    let witnesses: Vec<_> = (0..3).map(|_| Arc::new(Witness::default())).collect();
    let mut releases = Vec::new();
    let factories: Vec<_> = witnesses
        .iter()
        .enumerate()
        .map(|(index, seen)| {
            let seen = Arc::clone(seen);
            let (release, cleanup) = oneshot::channel();
            releases.push(release);
            move |branch| async move {
                held_cleanup(branch, seen, cleanup).await;
                100_u64 + index as u64
            }
        })
        .collect();
    let mut task = owner
        .spawn(move |join_owner| async move {
            let report = join_owner.join_all_scoped(factories).await.unwrap();
            assert!(join_owner.checkpoint().is_err());
            report
        })
        .unwrap();
    for seen in &witnesses {
        seen.wait(|state| state.parked.load(Ordering::Acquire)).await;
    }
    let reason = CancelReason::shutdown().with_cause(CancelReason::user("stop all joined branches"));
    task.abort_with_reason(reason.clone());
    for seen in &witnesses {
        seen.wait(|state| state.cleaning.load(Ordering::Acquire)).await;
        assert!(!seen.retired.load(Ordering::Acquire));
    }
    poll_fn(|context| {
        assert!(
            task.poll_join(context).is_pending(),
            "owner cannot publish its report while any branch cleanup is held"
        );
        Poll::Ready(())
    })
    .await;
    for release in releases.into_iter().rev() {
        release.send_blocking(()).unwrap();
    }
    let report = task.join(&owner).await.expect("acknowledged late values");
    assert!(matches!(&report.stop, ScopedJoinStop::Cancelled(actual) if actual == &reason));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert_eq!(report.attempts.len(), witnesses.len());
    let mut regions = Vec::new();
    for (index, attempt) in report.attempts.iter().enumerate() {
        assert!(matches!(
            &attempt.task,
            ScopedJoinTask::Joined(Ok(value)) if *value == 100_u64 + index as u64
        ));
        let region = assert_closed(attempt, index, owner.region_id());
        assert!(!regions.contains(&region));
        regions.push(region);
        assert!(witnesses[index].finished.load(Ordering::Acquire));
        assert!(witnesses[index].retired.load(Ordering::Acquire));
    }
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_join_native_owner_cancel_fans_out_and_preserves_late_values() {
    native(cancellation_fans_out_before_held_cleanup);
}

async fn dropped_collector_closes_every_subtree(owner: Cx) {
    let witnesses: Vec<_> = (0..3).map(|_| Arc::new(Witness::default())).collect();
    let mut releases = Vec::new();
    let factories: Vec<_> = witnesses
        .iter()
        .map(|seen| {
            let seen = Arc::clone(seen);
            let (release, cleanup) = oneshot::channel();
            releases.push(release);
            move |branch: Cx| async move {
                let child_seen = Arc::clone(&seen);
                branch
                    .spawn(move |child| held_cleanup(child, child_seen, cleanup))
                    .unwrap();
                seen.wait(|state| state.parked.load(Ordering::Acquire)).await;
                branch.cancelled().await;
                assert!(branch.checkpoint().is_err());
            }
        })
        .collect();
    let mut joining = Box::pin(owner.join_all_scoped(factories));
    let mut parked = std::pin::pin!(async {
        for seen in &witnesses {
            seen.wait(|state| state.parked.load(Ordering::Acquire)).await;
        }
    });
    poll_fn(|task| {
        assert!(joining.as_mut().poll(task).is_pending());
        parked.as_mut().poll(task)
    })
    .await;
    drop(joining);
    for seen in &witnesses {
        seen.wait(|state| state.cleaning.load(Ordering::Acquire)).await;
        assert!(!seen.retired.load(Ordering::Acquire));
    }
    for release in releases {
        release.send_blocking(()).unwrap();
    }
    for seen in &witnesses {
        seen.wait(|state| state.retired.load(Ordering::Acquire)).await;
        assert!(seen.finished.load(Ordering::Acquire));
    }
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_join_native_dropped_collector_retires_all_descendants() {
    native(dropped_collector_closes_every_subtree);
}
