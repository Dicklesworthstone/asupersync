//! Native parked-task and subtree cleanup boundaries for the scoped hedge.

use super::{
    ScopedHedgeBranch, ScopedHedgeBranchReport, ScopedHedgeReport, ScopedHedgeStop, ScopedHedgeTask,
};
use crate::Cx;
use crate::channel::oneshot;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::sync::Notify;
use crate::types::{CancelKind, CancelReason, RegionId};
use std::future::{Future, poll_fn};
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

async fn child_cleanup(
    cx: Cx,
    seen: Arc<Witness>,
    mut release: oneshot::Receiver<()>,
    expected_kind: CancelKind,
) {
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
    assert!(cx.checkpoint().is_err());
    assert_eq!(cx.cancel_reason().unwrap().kind, expected_kind);
    {
        let mut cleanup = std::pin::pin!(release.recv_uninterruptible());
        poll_fn(|task| {
            let progress = cleanup.as_mut().poll(task);
            if progress.is_pending() && !seen.cleaning.load(Ordering::Acquire) {
                seen.note(&seen.cleaning);
            }
            progress
        })
        .await
        .expect("controller releases witnessed asynchronous cleanup");
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
        .name("scoped-hedge-native".to_owned())
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
                            let mut owner = root.spawn(scenario).expect("native hedge owner");
                            owner.join(&root).await.expect("native hedge scenario");
                        });
                        let drain = runtime.shutdown_drained(Duration::from_secs(5));
                        assert_eq!(
                            drain.outcome,
                            RootDrainOutcome::Quiescent,
                            "workers={workers}, sharded={sharded}: {drain:?}"
                        );
                        assert_eq!(drain.live_tasks, 0, "{drain:?}");
                        assert_eq!(drain.live_regions, 0, "{drain:?}");
                        assert_eq!(drain.pending_spawns, 0, "{drain:?}");
                        assert_eq!(drain.pending_obligations, 0, "{drain:?}");
                        assert_eq!(drain.queued_finalizers, 0, "{drain:?}");
                        assert!(!drain.has_pending_obligation_posts, "{drain:?}");
                        assert!(runtime.is_quiescent());
                        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                    }
                }
            }));
            let _ = send.send(result);
        })
        .unwrap();
    // This watchdog only bounds a broken test. Readiness is established by
    // polling the actual cancellation and cleanup futures through Pending.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("scoped hedge must retire every owned branch");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn assert_closed<T>(branch: &ScopedHedgeBranchReport<T>, owner_region: RegionId) {
    assert_ne!(branch.region_id, Some(owner_region));
    assert!(branch.region_id.is_some());
    assert!(branch.submission_error.is_none());
    let close = branch.close.as_ref().unwrap().as_ref().unwrap();
    assert!(close.descendant_panic.is_none());
    assert!(
        close
            .cleanup_outcome
            .as_ref()
            .is_none_or(|outcome| outcome.is_ok())
    );
}

fn assert_both_closed<P, B>(report: &ScopedHedgeReport<P, B>, owner_region: RegionId) {
    assert_closed(&report.primary, owner_region);
    assert_closed(&report.backup, owner_region);
    assert_ne!(report.primary.region_id, report.backup.region_id);
}

async fn backup_drains_a_primary_joining_its_child(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let primary_seen = Arc::clone(&seen);
    let backup_seen = Arc::clone(&seen);
    let backups = Arc::new(AtomicUsize::new(0));
    let backup_calls = Arc::clone(&backups);
    let (release, cleanup) = oneshot::channel();
    let mut hedge = std::pin::pin!(owner.hedge_scoped(
        Duration::from_millis(1),
        move |body| async move {
            let mut child = body
                .spawn(move |child| {
                    child_cleanup(child, primary_seen, cleanup, CancelKind::RaceLost)
                })
                .unwrap();
            // A plain join does not release merely because its caller is
            // cancelled. The hedge must cancel the entire branch subtree.
            child.join(&body).await.unwrap();
            assert!(body.checkpoint().is_err());
            29_u8
        },
        move |_| {
            backup_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                backup_seen
                    .wait(|state| state.parked.load(Ordering::Acquire))
                    .await;
                String::from("backup result")
            }
        },
    ));
    let mut cleaning = std::pin::pin!(seen.wait(|state| state.cleaning.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(
            hedge.as_mut().poll(task).is_pending(),
            "the selected backup cannot outrun primary descendant cleanup"
        );
        cleaning.as_mut().poll(task)
    })
    .await;
    assert_eq!(backups.load(Ordering::SeqCst), 1);
    assert!(!seen.finished.load(Ordering::Acquire));
    assert!(!seen.retired.load(Ordering::Acquire));
    release.send_blocking(()).unwrap();
    let report = hedge.await.expect("drained hedge report");
    assert!(matches!(
        report.stop,
        ScopedHedgeStop::Winner(ScopedHedgeBranch::Backup)
    ));
    assert!(report.backup_started);
    assert!(
        matches!(&report.backup.task, ScopedHedgeTask::Joined(Ok(value)) if value == "backup result")
    );
    assert!(matches!(
        report.primary.task,
        ScopedHedgeTask::Joined(Ok(29))
    ));
    assert!(seen.finished.load(Ordering::Acquire));
    assert!(seen.retired.load(Ordering::Acquire));
    assert_both_closed(&report, owner.region_id());
    assert!(report.owner_cancellation.is_none());
    assert!(owner.timer_driver().unwrap().is_empty());
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_hedge_native_backup_waits_for_primary_child_join_and_async_cleanup() {
    native(backup_drains_a_primary_joining_its_child);
}

async fn selected_primary_survives_owner_abort_during_cleanup(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let primary_seen = Arc::clone(&seen);
    let backups = Arc::new(AtomicUsize::new(0));
    let backup_calls = Arc::clone(&backups);
    let (release, cleanup) = oneshot::channel();
    let mut hedging = owner
        .spawn(move |hedge_owner| async move {
            let report = hedge_owner
                .hedge_scoped(
                    Duration::from_secs(60),
                    move |body| async move {
                        let child_seen = Arc::clone(&primary_seen);
                        body.spawn(move |child| {
                            child_cleanup(child, child_seen, cleanup, CancelKind::User)
                        })
                        .unwrap();
                        primary_seen
                            .wait(|state| state.parked.load(Ordering::Acquire))
                            .await;
                        73_u64
                    },
                    move |_| {
                        backup_calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready("unused backup")
                    },
                )
                .await
                .expect("selected primary report");
            assert!(hedge_owner.checkpoint().is_err());
            report
        })
        .unwrap();
    seen.wait(|state| state.cleaning.load(Ordering::Acquire))
        .await;
    // Cleanup has crossed Pending, so primary selection is already committed.
    // The actual owning task is then aborted through its native TaskHandle.
    let reason =
        CancelReason::shutdown().with_cause(CancelReason::user("abort selected hedge cleanup"));
    hedging.abort_with_reason(reason.clone());
    assert!(!seen.finished.load(Ordering::Acquire));
    release.send_blocking(()).unwrap();
    let report = hedging
        .join(&owner)
        .await
        .expect("acknowledged selected-primary receipt");
    assert!(matches!(
        report.stop,
        ScopedHedgeStop::Winner(ScopedHedgeBranch::Primary)
    ));
    assert!(matches!(
        report.primary.task,
        ScopedHedgeTask::Joined(Ok(73))
    ));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert!(!report.backup_started);
    assert_eq!(backups.load(Ordering::SeqCst), 0);
    assert!(!matches!(
        report.backup.task,
        ScopedHedgeTask::Joined(Ok(_))
    ));
    assert!(seen.finished.load(Ordering::Acquire));
    assert!(seen.retired.load(Ordering::Acquire));
    assert_both_closed(&report, owner.region_id());
    assert!(owner.timer_driver().unwrap().is_empty());
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_hedge_native_selected_primary_survives_owner_abort_during_cleanup() {
    native(selected_primary_survives_owner_abort_during_cleanup);
}

async fn owner_abort_during_delay_never_selects_a_skipped_backup(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let primary_seen = Arc::clone(&seen);
    let backups = Arc::new(AtomicUsize::new(0));
    let backup_calls = Arc::clone(&backups);
    let (release, cleanup) = oneshot::channel();
    let timer = owner.timer_driver().unwrap();
    let mut hedging = owner
        .spawn(move |hedge_owner| async move {
            let report = hedge_owner
                .hedge_scoped(
                    Duration::from_secs(60),
                    move |body| async move {
                        let mut child = body
                            .spawn(move |child| {
                                child_cleanup(child, primary_seen, cleanup, CancelKind::Shutdown)
                            })
                            .unwrap();
                        child.join(&body).await.unwrap();
                        assert!(body.checkpoint().is_err());
                        19_u8
                    },
                    move |_| {
                        backup_calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready("a skipped wrapper is not a winner")
                    },
                )
                .await
                .expect("cancelled hedge report");
            assert!(hedge_owner.checkpoint().is_err());
            report
        })
        .unwrap();
    seen.wait(|state| state.parked.load(Ordering::Acquire))
        .await;
    // Wait for the actual registered timer, not a scheduling guess or sleep.
    // This isolated runtime has no timer other than the hedge's delay.
    while timer.is_empty() {
        crate::runtime::yield_now().await;
    }
    assert_eq!(backups.load(Ordering::SeqCst), 0);
    let reason = CancelReason::shutdown().with_message("abort hedge during delay");
    hedging.abort_with_reason(reason.clone());
    seen.wait(|state| state.cleaning.load(Ordering::Acquire))
        .await;
    assert!(!seen.finished.load(Ordering::Acquire));
    release.send_blocking(()).unwrap();
    let report = hedging
        .join(&owner)
        .await
        .expect("acknowledged cancellation receipt");
    assert!(matches!(&report.stop, ScopedHedgeStop::Cancelled(actual) if actual == &reason));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert!(!report.backup_started);
    assert_eq!(backups.load(Ordering::SeqCst), 0);
    assert!(!matches!(
        report.backup.task,
        ScopedHedgeTask::Joined(Ok(_))
    ));
    assert!(seen.finished.load(Ordering::Acquire));
    assert!(seen.retired.load(Ordering::Acquire));
    assert_both_closed(&report, owner.region_id());
    assert!(
        timer.is_empty(),
        "cancelled hedge retires its registered delay"
    );
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_hedge_native_abort_during_delay_drains_without_fake_backup_winner() {
    native(owner_abort_during_delay_never_selects_a_skipped_backup);
}
