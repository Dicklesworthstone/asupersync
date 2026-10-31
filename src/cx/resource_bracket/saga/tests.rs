//! Bead: asupersync-tmh.2.3 (async slice); fixed Lab seed 0x5a6a_2026.
//! Native fixtures use observed Pending gates, not timing to select cancellation.
#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::lab::{LabConfig, LabRuntime};
use crate::types::{Budget, CancelKind, CancelReason};
use std::cell::Cell;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn run_case<F, Fut>(factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0x5a6a_2026).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            factory(Cx::current().expect("registered saga test owner")).await;
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join()
        .unwrap()
        .expect("saga completed within the lab step bound");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab
            .state
            .cancel_request(root, &CancelReason::shutdown(), None)
            .into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
}

async fn no_compensation(_: Cx, _: u8) -> Outcome<(), &'static str> {
    panic!("unsuccessful or committed step must not be compensated");
}

#[test]
fn successful_heterogeneous_steps_commit_without_compensation() {
    run_case(|cx| async move {
        let mut handle = cx
            .spawn_saga::<String, &'static str, &'static str, _>(
                BracketConfig::new(4),
                2,
                |_, mut saga| {
                    Box::pin(async move {
                        let first = saga
                            .step(
                                "reserve counter",
                                |_| async { Outcome::<_, &'static str>::Ok(Cell::new(4_u8)) },
                                |_, _: Cell<u8>| async {
                                    panic!("committed counter undo");
                                },
                            )
                            .await
                            .unwrap();
                        assert!(first.is_success());
                        let Outcome::Ok(first) = first.outcome else {
                            panic!("first step");
                        };
                        saga.get(&first).unwrap().set(7);
                        let second = saga
                            .step(
                                "reserve name",
                                |_| async { Outcome::<_, &'static str>::Ok(String::from("ready")) },
                                |_, _: String| async {
                                    panic!("committed name undo");
                                },
                            )
                            .await
                            .unwrap();
                        let Outcome::Ok(second) = second.outcome else {
                            panic!("second step");
                        };
                        saga.get_mut(&second).unwrap().push('!');
                        assert_eq!(saga.get(&first).unwrap().get(), 7);
                        Outcome::Ok(saga.get(&second).unwrap().clone())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(report.is_success(), "{report:?}");
        assert!(matches!(&report.lifecycle.usage.as_ref().unwrap().outcome,
            Outcome::Ok(value) if value == "ready!"));
        let resolution = report.resolution.unwrap();
        assert_eq!(resolution.decision, AsyncSagaDecision::Commit);
        assert!(resolution.abort.is_none());
        assert!(resolution.compensations.is_none());
        assert_eq!(
            resolution
                .disposals
                .iter()
                .map(|entry| entry.step)
                .collect::<Vec<_>>(),
            [1, 0]
        );
    });
}

#[test]
fn caught_forward_error_is_sticky_and_all_lifo_errors_survive() {
    run_case(|cx| async move {
        let log = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&log);
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(4),
                5,
                move |_, mut saga| {
                    Box::pin(async move {
                        for index in 0_u8..3 {
                            let log = Arc::clone(&observed);
                            let phase = saga
                                .step(
                                    format!("step {index}"),
                                    move |_| async move { Outcome::<_, &'static str>::Ok(index) },
                                    move |_, undo| async move {
                                        log.lock().push(undo);
                                        match undo {
                                            2 => panic!("newest compensation panic"),
                                            1 => Outcome::Err("middle compensation failure"),
                                            _ => Outcome::Ok(()),
                                        }
                                    },
                                )
                                .await
                                .unwrap();
                            assert!(phase.is_success());
                        }
                        let failed = saga
                            .step(
                                "rejected forward",
                                |_| async { Outcome::<u8, _>::Err("forward error") },
                                no_compensation,
                            )
                            .await
                            .unwrap();
                        assert!(matches!(failed.outcome, Outcome::Err("forward error")));
                        assert_eq!(saga.abort_reason().unwrap().step, 3);
                        let refused = saga
                            .step(
                                "must not start",
                                |_| -> std::future::Ready<Outcome<u8, &'static str>> {
                                    panic!("late forward ran");
                                },
                                no_compensation,
                            )
                            .await;
                        assert_eq!(refused.unwrap_err(), ResourceStackError::Closed);
                        // Catching the error cannot turn the earlier effects into a commit.
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.is_success());
        assert!(!report.committed());
        assert!(report.lifecycle.usage.as_ref().unwrap().is_success());
        assert!(matches!(
            report.lifecycle.release.as_ref().unwrap().outcome,
            Outcome::Err(())
        ));
        let resolution = report.resolution.unwrap();
        assert_eq!(resolution.decision, AsyncSagaDecision::Rollback);
        assert_eq!(
            resolution.abort.unwrap().reason,
            AsyncSagaAbortReason::FailedStep
        );
        let cleanup = resolution.compensations.unwrap();
        assert!(cleanup.complete);
        assert_eq!(
            cleanup
                .entries
                .iter()
                .map(|entry| entry.index)
                .collect::<Vec<_>>(),
            [2, 1, 0]
        );
        assert!(matches!(&cleanup.entries[0].phase.outcome,
            Outcome::Panicked(panic) if panic.message() == "newest compensation panic"));
        assert!(matches!(
            cleanup.entries[1].phase.outcome,
            Outcome::Err("middle compensation failure")
        ));
        assert!(cleanup.entries[2].phase.is_success());
        assert_eq!(*log.lock(), [2, 1, 0]);
    });
}

struct ReturnedUndoThenPanicked {
    cx: Option<Cx>,
}
impl Future for ReturnedUndoThenPanicked {
    type Output = Outcome<u8, &'static str>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(cx) = self.cx.take() {
            cx.cancel_fast(CancelKind::User);
        }
        Poll::Ready(Outcome::Ok(19))
    }
}
impl Drop for ReturnedUndoThenPanicked {
    fn drop(&mut self) {
        panic!("forward retirement panic");
    }
}

#[test]
fn successful_undo_is_owned_despite_cancellation_and_future_drop_panic() {
    run_case(|cx| async move {
        let returned = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&returned);
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(4),
                1,
                move |_, mut saga| {
                    Box::pin(async move {
                        let phase = saga
                            .step(
                                "cancellation at return",
                                |cx| ReturnedUndoThenPanicked { cx: Some(cx) },
                                move |_, undo| async move {
                                    observed.store(usize::from(undo), Ordering::SeqCst);
                                    Outcome::Ok(())
                                },
                            )
                            .await
                            .unwrap();
                        assert!(phase.outcome.is_ok());
                        assert_eq!(
                            phase.retirement_panic.as_ref().unwrap().message(),
                            "forward retirement panic"
                        );
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        let resolution = report.resolution.unwrap();
        assert_eq!(resolution.steps[0].state, AsyncSagaStepState::Failed);
        assert_eq!(resolution.compensations.unwrap().entries.len(), 1);
        assert_eq!(returned.load(Ordering::SeqCst), 19);
    });
}

#[test]
fn capacity_refusal_happens_before_forward_effect_and_forces_rollback() {
    run_case(|cx| async move {
        let undos = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&undos);
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(1),
                1,
                move |_, mut saga| {
                    Box::pin(async move {
                        saga.step(
                            "first",
                            |_| async { Outcome::<_, &'static str>::Ok(1_u8) },
                            move |_, _| async move {
                                observed.fetch_add(1, Ordering::SeqCst);
                                Outcome::Ok(())
                            },
                        )
                        .await
                        .unwrap();
                        let refused = saga
                            .step(
                                "over limit",
                                |_| -> std::future::Ready<Outcome<u8, &'static str>> {
                                    panic!("capacity checked too late");
                                },
                                no_compensation,
                            )
                            .await;
                        assert_eq!(
                            refused.unwrap_err(),
                            ResourceStackError::Capacity { limit: 1 }
                        );
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        let resolution = report.resolution.unwrap();
        assert_eq!(
            resolution.abort.unwrap().reason,
            AsyncSagaAbortReason::Registration(ResourceStackError::Capacity { limit: 1 })
        );
        assert!(resolution.compensations.unwrap().is_success());
        assert_eq!(undos.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn abandoned_pending_step_blocks_later_steps_and_commit() {
    run_case(|cx| async move {
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(1),
                2,
                |_, mut saga| {
                    Box::pin(async move {
                        {
                            let mut step = Box::pin(saga.step(
                                "abandoned",
                                |_| std::future::pending::<Outcome<u8, &'static str>>(),
                                no_compensation,
                            ));
                            assert!(
                                step.as_mut()
                                    .poll(&mut Context::from_waker(Waker::noop()))
                                    .is_pending()
                            );
                        }
                        assert_eq!(
                            saga.abort_reason().unwrap().reason,
                            AsyncSagaAbortReason::IncompleteStep
                        );
                        let refused = saga
                            .step(
                                "late",
                                |_| async { Outcome::<_, &'static str>::Ok(0_u8) },
                                no_compensation,
                            )
                            .await;
                        assert_eq!(refused.unwrap_err(), ResourceStackError::Closed);
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        let resolution = report.resolution.unwrap();
        assert_eq!(resolution.steps[0].state, AsyncSagaStepState::Pending);
        assert!(resolution.compensations.unwrap().is_success());
    });
}

#[test]
fn body_panic_rolls_back_the_owned_steps() {
    run_case(|cx| async move {
        let undos = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&undos);
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(1),
                1,
                move |_, mut saga| {
                    Box::pin(async move {
                        saga.step(
                            "before panic",
                            |_| async { Outcome::<_, &'static str>::Ok(5_u8) },
                            move |_, value| async move {
                                observed.store(usize::from(value), Ordering::SeqCst);
                                Outcome::Ok(())
                            },
                        )
                        .await
                        .unwrap();
                        panic!("body panic");
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        assert!(matches!(&report.lifecycle.usage.as_ref().unwrap().outcome,
            Outcome::Panicked(panic) if panic.message() == "body panic"));
        assert!(report.resolution.unwrap().cleanup_succeeded());
        assert_eq!(undos.load(Ordering::SeqCst), 5);
    });
}

#[test]
fn missing_runtime_refuses_before_the_body_factory() {
    let refused =
        Cx::for_testing().spawn_saga::<(), (), (), _>(BracketConfig::new(0), 0, |_, _| {
            panic!("unadmitted body ran");
        });
    assert!(matches!(refused, Err(SpawnError::RuntimeUnavailable)));
}

#[test]
fn caught_descendant_panic_still_forces_rollback_after_body_success() {
    run_case(|cx| async move {
        let undos = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&undos);
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(2),
                1,
                move |work_cx, mut saga| {
                    Box::pin(async move {
                        saga.step(
                            "before descendant failure",
                            |_| async { Outcome::<_, &'static str>::Ok(1_u8) },
                            move |_, _| async move {
                                observed.fetch_add(1, Ordering::SeqCst);
                                Outcome::Ok(())
                            },
                        )
                        .await
                        .unwrap();
                        let nested = work_cx
                            .open_child_region(ChildRegionSpec::inherit())
                            .await
                            .unwrap();
                        let mut descendant = nested
                            .cx()
                            .spawn(|_| async {
                                panic!("descendant failure");
                            })
                            .unwrap();
                        assert!(descendant.join(&work_cx).await.is_err());
                        nested.close().await.unwrap();
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        assert!(report.lifecycle.usage.as_ref().unwrap().is_success());
        let resolution = report.resolution.unwrap();
        assert_eq!(
            resolution.descendant_panic.as_ref().unwrap().message(),
            "descendant failure"
        );
        assert!(resolution.cleanup_succeeded());
        assert_eq!(undos.load(Ordering::SeqCst), 1);
    });
}

struct DropPanic(&'static str);
impl Drop for DropPanic {
    fn drop(&mut self) {
        panic!("{}", self.0);
    }
}
struct DropCount(Arc<AtomicUsize>);
impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn commit_disposal_isolates_both_owners_and_continues_older_entries() {
    run_case(|cx| async move {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let mut handle = cx.spawn_saga::<(), &'static str, &'static str, _>(
            BracketConfig::new(2), 2, move |_, mut saga| Box::pin(async move {
                saga.step("oldest", move |_| async move { Outcome::<_, &'static str>::Ok(DropCount(observed)) },
                    |_, _: DropCount| async { panic!("commit must not run undo"); },
                ).await.unwrap();
                let captured = DropPanic("compensation capture panic");
                saga.step("two panicking owners", |_| async { Outcome::<_, &'static str>::Ok(DropPanic("undo drop panic")) },
                    move |_, undo| async move {
                        drop(captured);
                        drop(undo);
                        Outcome::Ok(())
                    },
                ).await.unwrap();
                Outcome::Ok(())
            }),
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(
            report.committed(),
            "disposal failure cannot retroactively uncommit"
        );
        assert!(!report.is_success());
        let resolution = report.resolution.unwrap();
        assert!(resolution.compensations.is_none());
        assert_eq!(resolution.disposals.len(), 2);
        assert_eq!(resolution.disposals[0].step, 1);
        assert_eq!(
            resolution.disposals[0]
                .undo_panic
                .as_ref()
                .unwrap()
                .message(),
            "undo drop panic"
        );
        assert_eq!(
            resolution.disposals[0]
                .compensation_panic
                .as_ref()
                .unwrap()
                .message(),
            "compensation capture panic"
        );
        assert_eq!(resolution.disposals[1].step, 0);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    });
}

struct CancelAtCommit;
impl Drop for CancelAtCommit {
    fn drop(&mut self) {
        Cx::current().unwrap().cancel_fast(CancelKind::User);
    }
}

#[test]
fn cancellation_after_commit_decision_remains_independent_evidence() {
    run_case(|cx| async move {
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(2),
                1,
                |_, mut saga| {
                    Box::pin(async move {
                        saga.step(
                            "cancel while retiring commit",
                            |_| async { Outcome::<_, &'static str>::Ok(CancelAtCommit) },
                            |_, _: CancelAtCommit| async {
                                panic!("committed effect cannot be rolled back late");
                            },
                        )
                        .await
                        .unwrap();
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(report.committed());
        assert!(!report.is_success());
        assert!(report.lifecycle.cancellation.is_some());
        assert!(report.resolution.unwrap().cleanup_succeeded());
    });
}

#[test]
fn finalizer_completion_and_failure_precede_the_commit_decision() {
    for fail_cleanup in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(0x5a6a_2027).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let handle_slot = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&handle_slot);
        let nested_slot = Arc::new(Mutex::new(None));
        let nested_publication = Arc::clone(&nested_slot);
        let (finish_work, mut work_gate) = oneshot::channel();
        let (finish_finalizer, mut finalizer_gate) = oneshot::channel();
        let finalizer_state = Arc::new(AtomicUsize::new(0));
        let state = Arc::clone(&finalizer_state);
        let undos = Arc::new(AtomicUsize::new(0));
        let undone = Arc::clone(&undos);
        let finalizer_observed = Arc::clone(&finalizer_state);
        let (parent, mut parent_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let handle = cx
                    .spawn_saga::<(), &'static str, &'static str, _>(
                        BracketConfig::new(4),
                        1,
                        move |work_cx, mut saga| {
                            Box::pin(async move {
                                saga.step(
                                    "forward success",
                                    |_| async { Outcome::<_, &'static str>::Ok(9_u8) },
                                    move |_, undo| async move {
                                        assert_eq!(finalizer_observed.load(Ordering::SeqCst), 2);
                                        undone.store(usize::from(undo), Ordering::SeqCst);
                                        Outcome::Ok(())
                                    },
                                )
                                .await
                                .unwrap();
                                let nested = work_cx
                                    .open_child_region(ChildRegionSpec::inherit())
                                    .await
                                    .unwrap();
                                *nested_publication.lock() = Some(nested.region_id());
                                work_gate.recv_uninterruptible().await.unwrap();
                                drop(nested);
                                Outcome::Ok(())
                            })
                        },
                    )
                    .unwrap();
                *publication.lock() = Some(handle);
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(parent_join.try_join().unwrap().is_some());
        let nested = nested_slot.lock().expect("work reached nested region");
        assert!(lab.state.register_async_finalizer(nested, async move {
            poll_fn(|cx| match finalizer_gate.poll_recv_uninterruptible(cx) {
                Poll::Pending => {
                    state.store(1, Ordering::SeqCst);
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result.unwrap()),
            })
            .await;
            state.store(2, Ordering::SeqCst);
            assert!(!fail_cleanup, "nested finalizer failure");
        }));
        let mut handle = handle_slot.lock().take().unwrap();
        finish_work.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_eq!(finalizer_state.load(Ordering::SeqCst), 1);
        assert_eq!(undos.load(Ordering::SeqCst), 0);
        {
            let mut join = std::pin::pin!(handle.join());
            assert!(
                join.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        finish_finalizer.send_blocking(()).unwrap();
        lab.run_until_idle();
        let report = {
            let mut join = std::pin::pin!(handle.join());
            match join.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(result) => result.unwrap(),
                Poll::Pending => panic!("finalized saga must have a terminal report"),
            }
        };
        assert_eq!(report.committed(), !fail_cleanup);
        assert_eq!(report.is_success(), !fail_cleanup);
        assert_eq!(
            undos.load(Ordering::SeqCst),
            if fail_cleanup { 9 } else { 0 }
        );
        assert!(lab.state.region(nested).is_none());
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        let (tasks, wakes) = lab
            .state
            .cancel_request(root, &CancelReason::shutdown(), None)
            .into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
        assert!(lab.state.region(root).is_none());
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use std::time::Duration;

    async fn witness_pending<F: Future>(future: F, witness: oneshot::Sender<()>) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut witness = Some(witness);
        poll_fn(|task| {
            let result = future.as_mut().poll(task);
            if result.is_pending() {
                if let Some(witness) = witness.take() {
                    witness.send_blocking(()).unwrap();
                }
            }
            result
        })
        .await
    }

    // Bounds a failed test's wait, not the saga's cleanup contract.
    fn bounded(test: impl FnOnce() + Send + 'static) {
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
            let _ = send.send(result);
        });
        let result = receive
            .recv_timeout(Duration::from_secs(30))
            .expect("native saga must finish after the witnessed external wake");
        thread.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn cancellation(multithread: bool, drop_handle: bool) {
        let runtime = if multithread {
            RuntimeBuilder::new().worker_threads(2).build().unwrap()
        } else {
            RuntimeBuilder::current_thread().build().unwrap()
        };
        let (external_finish, mut external_gate) = oneshot::channel();
        let (permit_wake, await_permission) = std::sync::mpsc::channel();
        let external = std::thread::spawn(move || {
            await_permission
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            external_finish.send_blocking(()).unwrap();
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed_events = Arc::clone(&events);
        let history = Arc::new(Mutex::new(Vec::new()));
        let observed_history = Arc::clone(&history);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        runtime.block_on_with_cx(owner.clone(), async move {
            let boundary = owner
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let (body_parked, mut wait_body) = oneshot::channel();
            let (undo_parked, mut wait_undo) = oneshot::channel();
            let mut handle = Some(
                boundary
                    .cx()
                    .spawn_saga::<(), &'static str, &'static str, _>(
                        BracketConfig::new(1),
                        2,
                        move |work_cx, mut saga| {
                            Box::pin(async move {
                                let old_events = Arc::clone(&observed_events);
                                let old_history = Arc::clone(&observed_history);
                                saga.step(
                                    "oldest",
                                    |_| async { Outcome::<_, &'static str>::Ok(0_u8) },
                                    move |cx, undo| async move {
                                        let masked = cx.checkpoint().is_ok();
                                        old_history.lock().push((undo, masked));
                                        old_events.lock().push(undo);
                                        Outcome::Ok(())
                                    },
                                )
                                .await
                                .unwrap();
                                saga.step(
                                    "externally woken undo",
                                    |_| async { Outcome::<_, &'static str>::Ok(1_u8) },
                                    move |cx, undo| async move {
                                        let mut witness = Some(undo_parked);
                                        poll_fn(|task| {
                                            let masked = cx.checkpoint().is_ok();
                                            observed_history.lock().push((undo, masked));
                                            let result =
                                                external_gate.poll_recv_uninterruptible(task);
                                            if result.is_pending() {
                                                if let Some(witness) = witness.take() {
                                                    witness.send_blocking(()).unwrap();
                                                }
                                            }
                                            result
                                        })
                                        .await
                                        .unwrap();
                                        observed_events.lock().push(undo);
                                        Outcome::Err("remote undo refused")
                                    },
                                )
                                .await
                                .unwrap();
                                witness_pending(work_cx.cancelled(), body_parked).await;
                                assert!(work_cx.checkpoint().is_err());
                                Outcome::Cancelled(work_cx.cancel_reason().unwrap())
                            })
                        },
                    )
                    .unwrap(),
            );
            wait_body
                .recv(&owner)
                .await
                .expect("body actually parked before cancellation");
            if drop_handle {
                drop(handle.take());
            } else {
                handle.as_ref().unwrap().abort();
            }
            wait_undo
                .recv(&owner)
                .await
                .expect("compensation actually parked after cancellation");
            assert!(events.lock().is_empty());
            if let Some(handle) = &mut handle {
                for _ in 0..3 {
                    let mut join = std::pin::pin!(handle.join());
                    assert!(
                        join.as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_pending()
                    );
                }
            }
            permit_wake.send(()).unwrap();
            if let Some(handle) = &mut handle {
                let report = handle.join().await.unwrap();
                assert!(!report.committed());
                assert!(report.lifecycle.cancellation.is_some());
                assert!(
                    report
                        .lifecycle
                        .usage
                        .as_ref()
                        .unwrap()
                        .outcome
                        .is_cancelled()
                );
                assert!(report.lifecycle.controller_task.is_ok());
                assert!(report.lifecycle.unreleased.is_none());
                let cleanup = report.resolution.unwrap().compensations.unwrap();
                assert!(cleanup.complete);
                assert_eq!(
                    cleanup
                        .entries
                        .iter()
                        .map(|entry| entry.index)
                        .collect::<Vec<_>>(),
                    [1, 0]
                );
                assert!(matches!(
                    cleanup.entries[0].phase.outcome,
                    Outcome::Err("remote undo refused")
                ));
                assert!(cleanup.entries[1].phase.is_success());
            }
            // Authoritative controller drain barrier even when its handle was dropped.
            boundary.close().await.unwrap();
            assert_eq!(*events.lock(), [1, 0]);
            let history = history.lock();
            assert_eq!(history[0], (1, true));
            assert!(
                history[1..].iter().all(|(_, masked)| !masked),
                "mask allowance reset per step"
            );
            assert_eq!(history.last(), Some(&(0, false)));
        });
        external.join().unwrap();
    }

    #[test]
    fn cancelled_saga_retains_external_undo_current_thread() {
        bounded(|| cancellation(false, false));
    }
    #[test]
    fn cancelled_saga_retains_external_undo_two_workers() {
        bounded(|| cancellation(true, false));
    }
    #[test]
    fn dropped_handle_retains_external_undo_current_thread() {
        bounded(|| cancellation(false, true));
    }
    #[test]
    fn dropped_handle_retains_external_undo_two_workers() {
        bounded(|| cancellation(true, true));
    }

    #[test]
    fn closing_ancestor_refuses_new_cleanup_admission_without_skipping_older_undo() {
        bounded(|| {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            runtime.block_on_with_cx(owner.clone(), async move {
                let boundary = owner
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let (body_parked, mut wait_body) = oneshot::channel();
                let undos = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&undos);
                let factories = Arc::new(AtomicUsize::new(0));
                let admitted_factories = Arc::clone(&factories);
                let mut handle = boundary
                    .cx()
                    .spawn_saga::<(), &'static str, JoinError, _>(
                        BracketConfig::new(8),
                        2,
                        move |work_cx, mut saga| {
                            Box::pin(async move {
                                saga.step(
                                    "oldest",
                                    |_| async { Outcome::<_, &'static str>::Ok(0_u8) },
                                    move |_, _| async move {
                                        observed.fetch_add(1, Ordering::SeqCst);
                                        Outcome::Ok(())
                                    },
                                )
                                .await
                                .unwrap();
                                saga.step(
                                    "new task needed for undo",
                                    |_| async { Outcome::<_, &'static str>::Ok(1_u8) },
                                    move |cx, _| async move {
                                        assert!(
                                            cx.checkpoint().is_ok(),
                                            "cleanup is currently masked"
                                        );
                                        // Cx::spawn reserves a provisional handle;
                                        // the region owner decides admission later.
                                        let mut task = cx.spawn(move |_| {
                                            admitted_factories.fetch_add(1, Ordering::SeqCst);
                                            async {}
                                        }).unwrap();
                                        match poll_fn(|task_cx| task.poll_join(task_cx)).await {
                                            Err(error) => Outcome::Err(error),
                                            Ok(()) => panic!("masking must not grant new task admission"),
                                        }
                                    },
                                )
                                .await
                                .unwrap();
                                witness_pending(work_cx.cancelled(), body_parked).await;
                                assert!(work_cx.checkpoint().is_err());
                                Outcome::Cancelled(work_cx.cancel_reason().unwrap())
                            })
                        },
                    )
                    .unwrap();
                wait_body.recv(&owner).await.unwrap();
                // This is ancestor shutdown, not merely aborting a handle in an
                // otherwise Open parent. It must not be bypassed by the mask.
                boundary.close().await.unwrap();
                let report = handle.join().await.unwrap();
                assert!(!report.committed());
                let cleanup = report.resolution.unwrap().compensations.unwrap();
                assert_eq!(
                    cleanup
                        .entries
                        .iter()
                        .map(|entry| entry.index)
                        .collect::<Vec<_>>(),
                    [1, 0]
                );
                // Native and Lab admission resolve a RegionClosed denial as a
                // bare ParentCancelled reason (three_lane.rs drain paths, since
                // 31516236f), with no SpawnError message; factories == 0 below
                // proves the undo's task was refused rather than admitted.
                assert!(matches!(&cleanup.entries[0].phase.outcome,
                    Outcome::Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::ParentCancelled));
                assert!(cleanup.entries[1].phase.is_success());
                assert_eq!(undos.load(Ordering::SeqCst), 1);
                assert_eq!(factories.load(Ordering::SeqCst), 0);
            });
        });
    }
}
