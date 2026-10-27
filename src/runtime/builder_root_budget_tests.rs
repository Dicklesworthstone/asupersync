//! Native root-budget journeys for asupersync-0fvvq9. These use the actual
//! worker/caller drivers, including private framework-adapter entry points.

use super::{Runtime, RuntimeBuilder};
use crate::cx::Cx;
use crate::observability::TaskInspectorConfig;
use crate::record::RegionLimits;
use crate::types::{Budget, CancelKind};
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak, mpsc};
use std::task::{Poll, Wake, Waker};
use std::time::Duration;

const MODES: [(bool, bool); 4] = [(true, false), (true, true), (false, false), (false, true)];

fn builder(current_thread: bool, sharded: bool) -> RuntimeBuilder {
    let builder = if current_thread {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(2)
    };
    builder.with_sharded_state(sharded)
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Root,
    Request,
    CurrentRequest,
}

fn drive<F: Future>(runtime: &Runtime, entry: Entry, budget: Budget, future: F) -> F::Output {
    match entry {
        Entry::Root => runtime.block_on_with_budget(budget, future),
        Entry::Request => runtime.block_on_with_cx(runtime.request_cx_with_budget(budget), future),
        Entry::CurrentRequest => runtime.block_on(async {
            let outer = Cx::current().expect("outer root context");
            let output =
                Runtime::block_on_current_with_cx(runtime.request_cx_with_budget(budget), future)
                    .expect("current runtime installed");
            assert_eq!(Cx::current().unwrap().task_id(), outer.task_id());
            assert!(
                !outer.is_cancel_requested(),
                "request cancellation stays scoped"
            );
            output
        }),
    }
}

#[test]
fn root_quotas_charge_actual_polls_including_zero_quota_admission() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        for quota in [0_u32, 1, 4] {
            // Borrowed !Send state also pins the new public entry's bounds.
            let polls = Rc::new(Cell::new(0_u32));
            let root = runtime.block_on_with_budget(
                Budget::INFINITE.with_poll_quota(quota),
                poll_fn(|ctx| {
                    let cx = Cx::current().expect("root context");
                    let poll = polls.get() + 1;
                    polls.set(poll);
                    assert!(poll <= quota + 1, "root quota never cancelled");
                    assert_eq!(cx.budget().poll_quota, quota.saturating_sub(poll));
                    if poll == 1 {
                        assert!(
                            runtime
                                .task_inspector(TaskInspectorConfig::default())
                                .list_tasks()
                                .iter()
                                .any(|task| task.id == cx.task_id()),
                            "zero quota must still admit the root's ownership record"
                        );
                    }
                    if poll <= quota {
                        assert!(!cx.is_cancel_requested());
                        ctx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                        assert!(cx.checkpoint().is_err());
                        Poll::Ready(cx)
                    }
                }),
            );
            assert_eq!(polls.get(), quota + 1);
            assert_eq!(root.cancel_reason().unwrap().kind, CancelKind::PollQuota);
            assert!(runtime.is_quiescent(), "root accounting must retire");
            assert!(Cx::current().is_none());
        }
    }
}

#[test]
fn both_explicit_context_drivers_charge_the_supplied_request() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        for entry in [Entry::Request, Entry::CurrentRequest] {
            for quota in [0_u32, 4] {
                let mut polls = 0;
                let cx = drive(
                    &runtime,
                    entry,
                    Budget::INFINITE.with_poll_quota(quota),
                    poll_fn(|ctx| {
                        polls += 1;
                        assert!(polls <= quota + 1, "{entry:?} did not charge the request");
                        let cx = Cx::current().unwrap();
                        assert_eq!(cx.budget().poll_quota, quota.saturating_sub(polls));
                        if cx.is_cancel_requested() {
                            assert_eq!(polls, quota + 1);
                            assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                            Poll::Ready(cx)
                        } else {
                            ctx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }),
                );
                assert_eq!(polls, quota + 1);
                assert_eq!(cx.budget().poll_quota, 0);
                assert!(runtime.is_quiescent());
                assert!(Cx::current().is_none());
            }
        }
    }
}

#[test]
fn unlimited_roots_and_early_completion_keep_their_remaining_budget() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        let mut polls = 0;
        runtime.block_on(poll_fn(|ctx| {
            polls += 1;
            let cx = Cx::current().unwrap();
            assert_eq!(cx.budget().poll_quota, u32::MAX);
            assert!(cx.checkpoint().is_ok());
            if polls == 8 {
                Poll::Ready(())
            } else {
                ctx.waker().wake_by_ref();
                Poll::Pending
            }
        }));
        for entry in [Entry::Root, Entry::Request, Entry::CurrentRequest] {
            for quota in [7, u32::MAX] {
                let mut polls = 0;
                let cx = drive(
                    &runtime,
                    entry,
                    Budget::INFINITE.with_poll_quota(quota),
                    poll_fn(|ctx| {
                        polls += 1;
                        let cx = Cx::current().unwrap();
                        assert!(cx.checkpoint().is_ok());
                        if polls == 3 {
                            Poll::Ready(cx)
                        } else {
                            ctx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }),
                );
                assert_eq!(
                    cx.budget().poll_quota,
                    if quota == u32::MAX { quota } else { 4 }
                );
                assert!(!cx.is_cancel_requested());
            }
        }
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn root_children_inherit_remaining_quota_and_are_charged_by_the_worker() {
    for sharded in [false, true] {
        let runtime = builder(true, sharded).build().unwrap();
        let caller = std::thread::current().id();
        let touched = Rc::new(Cell::new(false));
        let child_touched = Rc::clone(&touched);
        runtime.block_on_with_budget(Budget::INFINITE.with_poll_quota(8), async {
            let cx = Cx::current().unwrap();
            assert_eq!(cx.budget().poll_quota, 7);
            let mut task = cx
                .spawn_local(move |child| async move {
                    assert_eq!(std::thread::current().id(), caller);
                    child_touched.set(true);
                    let mut polls = 0_u32;
                    poll_fn(|ctx| {
                        polls += 1;
                        assert!(
                            polls <= 8,
                            "child inherited the root's accounting exemption"
                        );
                        assert_eq!(child.budget().poll_quota, 7_u32.saturating_sub(polls));
                        if child.is_cancel_requested() {
                            assert_eq!(polls, 8);
                            assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                            assert!(child.checkpoint().is_err());
                            Poll::Ready(polls)
                        } else {
                            ctx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await
                })
                .unwrap();
            assert_eq!(task.join(&cx).await.unwrap(), 8);
            assert!(cx.budget().poll_quota > 0);
            assert!(
                !cx.is_cancel_requested(),
                "child exhaustion cannot cancel its root"
            );
        });
        assert!(touched.get());
        assert!(runtime.is_quiescent());
    }
}

/// The first Pending carries the actual driver waker. A broken implementation
/// is rescued only after the bounded completion check, so it fails instead of
/// stranding a helper thread. No timer or primitive wakes the healthy root.
fn checkpoint_cleanup_journey(current_thread: bool, sharded: bool, entry: Entry, shutdown: bool) {
    let runtime = builder(current_thread, sharded).build().unwrap();
    let caller_runtime = runtime.clone();
    let (parked, parked_rx) = mpsc::channel();
    let (finished, finished_rx) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        let mut polls = 0;
        let result = drive(
            &caller_runtime,
            entry,
            Budget::INFINITE.with_poll_quota(if shutdown { 2 } else { 1 }),
            poll_fn(|ctx| {
                polls += 1;
                let cx = Cx::current().unwrap();
                if shutdown && polls == 1 {
                    assert_eq!(cx.budget().poll_quota, 1);
                    caller_runtime.inner.scheduler.shutdown();
                    ctx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                assert!(cx.checkpoint().is_err());
                assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                if polls == if shutdown { 2 } else { 1 } {
                    parked.send(ctx.waker().clone()).unwrap();
                    Poll::Pending
                } else {
                    Poll::Ready(polls)
                }
            }),
        );
        finished.send(result).unwrap();
    });
    let rescue = parked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("checkpoint Pending witness");
    let first = finished_rx.recv_timeout(Duration::from_secs(2));
    let completed_without_rescue = first.is_ok();
    let polls = first.unwrap_or_else(|_| {
        rescue.wake_by_ref();
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("rescue wakes the root")
    });
    caller.join().unwrap();
    assert_eq!(polls, if shutdown { 3 } else { 2 });
    assert!(
        completed_without_rescue,
        "{entry:?}: deferred cancellation wake was lost"
    );
    assert!(runtime.is_quiescent());
}

#[test]
fn checkpoint_exhaustion_wakes_pending_root_cleanup_on_every_entry() {
    for (current_thread, sharded) in MODES {
        for entry in [Entry::Root, Entry::Request, Entry::CurrentRequest] {
            checkpoint_cleanup_journey(current_thread, sharded, entry, false);
        }
    }
}

#[test]
fn shutdown_root_loop_keeps_charging_and_flushing_checkpoint_wakes() {
    for sharded in [false, true] {
        checkpoint_cleanup_journey(true, sharded, Entry::Root, true);
    }
}

#[test]
fn ready_checkpoint_delivers_auxiliary_cancel_wakes_outside_the_context_lock() {
    struct Observer {
        inner: Weak<parking_lot::RwLock<crate::types::CxInner>>,
        wakes: Arc<AtomicUsize>,
        unlocked: Arc<AtomicUsize>,
    }

    impl Wake for Observer {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            if self
                .inner
                .upgrade()
                .is_some_and(|inner| inner.try_write().is_some())
            {
                self.unlocked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        for entry in [Entry::Root, Entry::Request, Entry::CurrentRequest] {
            let wakes = Arc::new(AtomicUsize::new(0));
            let unlocked = Arc::new(AtomicUsize::new(0));
            let (cx, token) = drive(
                &runtime,
                entry,
                Budget::INFINITE.with_poll_quota(1),
                async {
                    let cx = Cx::current().unwrap();
                    let observer = Waker::from(Arc::new(Observer {
                        inner: Arc::downgrade(&cx.inner),
                        wakes: Arc::clone(&wakes),
                        unlocked: Arc::clone(&unlocked),
                    }));
                    let token = cx.refresh_cancel_waker(None, &observer);
                    assert!(cx.checkpoint().is_err());
                    assert_eq!(
                        wakes.load(Ordering::SeqCst),
                        0,
                        "checkpoint defers callbacks"
                    );
                    (cx, token)
                },
            );
            cx.clear_cancel_waker(token);
            assert_eq!(
                wakes.load(Ordering::SeqCst),
                1,
                "{entry:?}: terminal wake debt"
            );
            assert_eq!(
                unlocked.load(Ordering::SeqCst),
                1,
                "callback can reenter its context"
            );
        }
    }
}

#[test]
fn cancellation_cleanup_does_not_spend_or_replace_a_positive_remaining_quota() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        for entry in [Entry::Root, Entry::Request, Entry::CurrentRequest] {
            let mut polls = 0;
            let mut cleanup_quota = None;
            let cx = drive(
                &runtime,
                entry,
                Budget::INFINITE.with_poll_quota(3),
                poll_fn(|ctx| {
                    polls += 1;
                    let cx = Cx::current().unwrap();
                    if polls == 1 {
                        assert_eq!(cx.budget().poll_quota, 2);
                        cx.cancel_with(CancelKind::User, Some("root cleanup test"));
                    }
                    assert!(cx.checkpoint().is_err());
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
                    assert!(cx.budget().poll_quota > 0);
                    if polls > 1 {
                        let remaining = cx.budget().poll_quota;
                        if let Some(expected) = cleanup_quota {
                            assert_eq!(remaining, expected, "cleanup polls are advisory");
                        } else {
                            // The current-thread accounting task reconciles
                            // the first acknowledgement between root polls.
                            cleanup_quota = Some(remaining);
                        }
                    }
                    if polls == 130 {
                        Poll::Ready(cx)
                    } else {
                        ctx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }),
            );
            assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
        }
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn explicit_checkpoint_retains_its_existing_exhaustion_strengthening() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        for entry in [Entry::Root, Entry::Request, Entry::CurrentRequest] {
            drive(
                &runtime,
                entry,
                Budget::INFINITE.with_poll_quota(1),
                async {
                    let cx = Cx::current().unwrap();
                    assert_eq!(cx.budget().poll_quota, 0);
                    cx.cancel_with(CancelKind::User, Some("cancel after the last charged unit"));
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
                    assert!(cx.checkpoint().is_err());
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                },
            );
        }
    }
}

#[test]
fn admission_refusal_keeps_enforcing_the_fallback_root_budget() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded)
            .root_region_limits(RegionLimits {
                max_tasks: Some(0),
                ..RegionLimits::UNLIMITED
            })
            .build()
            .unwrap();
        let mut polls = 0;
        runtime.block_on_with_budget(
            Budget::INFINITE.with_poll_quota(2),
            poll_fn(|ctx| {
                polls += 1;
                assert!(polls <= 3, "fallback root escaped its budget");
                let cx = Cx::current().unwrap();
                if cx.is_cancel_requested() {
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                    Poll::Ready(())
                } else {
                    ctx.waker().wake_by_ref();
                    Poll::Pending
                }
            }),
        );
        assert_eq!(polls, 3);
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn nested_budgeted_roots_restore_the_outer_finite_budget() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded).build().unwrap();
        runtime.block_on_with_budget(Budget::INFINITE.with_poll_quota(5), async {
            let outer = Cx::current().unwrap();
            assert_eq!(outer.budget().poll_quota, 4);
            let mut polls = 0;
            runtime.block_on_with_budget(
                Budget::INFINITE.with_poll_quota(2),
                poll_fn(|ctx| {
                    polls += 1;
                    assert!(polls <= 3);
                    let inner = Cx::current().unwrap();
                    assert_ne!(inner.task_id(), outer.task_id());
                    if inner.is_cancel_requested() {
                        assert_eq!(inner.cancel_reason().unwrap().kind, CancelKind::PollQuota);
                        Poll::Ready(())
                    } else {
                        ctx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }),
            );
            assert_eq!(polls, 3);
            assert_eq!(Cx::current().unwrap().task_id(), outer.task_id());
            assert_eq!(outer.budget().poll_quota, 4);
            assert!(!outer.is_cancel_requested());
        });
        assert!(runtime.is_quiescent());
    }
}
