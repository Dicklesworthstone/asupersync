//! Ready region cleanup must make progress while unrelated work stays runnable.

use crate::channel::oneshot;
use crate::cx::{ChildRegionSpec, Cx};
use crate::runtime::RuntimeBuilder;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::types::{Budget, CancelReason};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

#[derive(Clone, Copy, Debug)]
enum CloseCommand {
    Close,
    Cancel,
    CancelWithBudget,
}

struct Finalized(Arc<AtomicUsize>);

impl Drop for Finalized {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn queued_close_admits_finalizers_before_unrelated_work_becomes_idle() {
    for sharded in [false, true] {
        for command in [
            CloseCommand::Close,
            CloseCommand::Cancel,
            CloseCommand::CancelWithBudget,
        ] {
            let runtime = RuntimeBuilder::current_thread()
                .with_sharded_state(sharded)
                .build()
                .unwrap();
            let finalized = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            runtime.block_on(async {
                let owner = Cx::current().expect("native root context");
                let (entered, mut spinner_entered) = oneshot::channel();
                let spinner_stop = Arc::clone(&stop);
                let mut spinner = owner
                    .spawn(move |child| async move {
                        let mut entered = Some(entered);
                        poll_fn(|task| {
                            if spinner_stop.load(Ordering::SeqCst)
                                || child.checkpoint().is_err()
                            {
                                return Poll::Ready(());
                            }
                            // Every Pending poll leaves real runnable work behind.
                            // Cancellation keeps a failed assertion from stranding it.
                            task.waker().wake_by_ref();
                            if let Some(entered) = entered.take() {
                                entered.send_blocking(()).unwrap();
                            }
                            Poll::Pending
                        })
                        .await;
                    })
                    .unwrap();
                spinner_entered.recv(&owner).await.unwrap();

                let region = owner
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                region
                    .retain_until_finalized(Finalized(Arc::clone(&finalized)))
                    .await
                    .unwrap();
                let mut body = region.cx().spawn(|_| async { 17_u32 }).unwrap();
                assert_eq!(body.join(&owner).await.unwrap(), 17);
                assert_eq!(finalized.load(Ordering::SeqCst), 0);
                assert!(!spinner.is_finished());

                // No body can complete after this point and incidentally admit
                // cleanup. Only the queued lifecycle command makes it ready.
                match command {
                    CloseCommand::Close => {}
                    CloseCommand::Cancel => {
                        region
                            .cancel(CancelReason::user("finalizer fairness"))
                            .unwrap();
                    }
                    CloseCommand::CancelWithBudget => {
                        region
                            .cancel_with_budget(
                                CancelReason::user("finalizer fairness"),
                                Budget::INFINITE,
                            )
                            .unwrap();
                    }
                }
                let mut close = std::pin::pin!(region.close());
                let mut turns = 0;
                poll_fn(|task| {
                    // For cancellation cases, do not enqueue Close as a hidden
                    // second trigger: the first command must start finalization.
                    if (matches!(command, CloseCommand::Close)
                        || finalized.load(Ordering::SeqCst) != 0)
                        && let Poll::Ready(result) = close.as_mut().poll(task)
                    {
                        return Poll::Ready(result);
                    }
                    turns += 1;
                    assert!(
                        turns <= 128,
                        "queued {command:?} stranded ready cleanup behind unrelated work \
                         (sharded={sharded})",
                    );
                    // The current-thread root lends one native scheduler turn
                    // between polls, so this is a deterministic dispatch bound.
                    task.waker().wake_by_ref();
                    Poll::Pending
                })
                .await
                .unwrap();

                assert_eq!(finalized.load(Ordering::SeqCst), 1);
                assert!(
                    !spinner.is_finished(),
                    "cleanup completed while work remained runnable",
                );
                stop.store(true, Ordering::SeqCst);
                spinner.join(&owner).await.unwrap();
            });
            assert_eq!(finalized.load(Ordering::SeqCst), 1);
            assert!(runtime.is_quiescent());
        }
    }
}
