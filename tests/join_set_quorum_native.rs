//! Native task-group success selection; no self-waking stand-ins for parked work.
//! Run with the repository-authorized RCH lane and default features.
#![cfg(not(target_arch = "wasm32"))]
use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::combinator::{JoinSet, QuorumError, TaskQuorumDecision, TaskQuorumPhase};
use asupersync::observability::diagnostics::BlockReason;
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{CancelKind, CancelReason, Outcome, TaskId};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::Duration;

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("native task quorum scenario exceeded watchdog");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn run<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    let runtime = builder.build().unwrap();
    runtime.block_on(runtime.handle().spawn(async move {
        test(Cx::current().expect("native task context")).await;
    }));
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
    eprintln!("task-quorum: workers={workers}, root quiescent, tasks=0 spawns=0 obligations=0");
}

async fn parked(child: &Cx, ready: oneshot::Sender<()>) {
    let mut ready = Some(ready);
    let mut cancellation = pin!(child.cancelled());
    poll_fn(|task| match cancellation.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                // Witness is emitted AFTER a real cancellation waker is installed.
                ready.send_blocking(()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
    assert!(child.is_cancel_requested());
    let _ = child.checkpoint();
}

#[test]
fn first_success_tolerates_error_and_retires_parked_sibling() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(99)
                })
                .unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("one backend failed") })
                    .unwrap();
                set.spawn(&cx, |_| async { Ok(7) }).unwrap();
                assert_eq!(set.join_first_ok(&cx).await.unwrap(), 7);
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn quorum_retires_parked_prefix_and_returns_exact_number_of_values() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                for _ in 0..3 {
                    let (ready, mut witness) = oneshot::channel();
                    let count = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(99)
                    })
                    .unwrap();
                    witness.recv(&cx).await.unwrap();
                }
                set.spawn(&cx, |_| async { Ok(3) }).unwrap();
                set.spawn(&cx, |_| async { Ok(8) }).unwrap();
                let mut values = set.join_quorum(&cx, 2).await.unwrap();
                values.sort_unstable();
                assert_eq!(values, [3, 8]);
                assert_eq!(cleaned.load(Ordering::SeqCst), 3);
            });
        }
    });
}

#[test]
fn impossible_quorum_preserves_errors_instead_of_cleanup_cancellation() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(9)
                })
                .unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("unavailable") }).unwrap();
                let result = set.join_quorum(&cx, 2).await;
                assert!(matches!(result,
                    Err(QuorumError::InsufficientSuccesses {
                        required: 2, total: 2, achieved: 0, errors
                    }) if errors == ["unavailable"]));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn invalid_quorums_drain_already_admitted_work() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                for required in [0, 2, usize::MAX] {
                    let cleaned = Arc::new(AtomicUsize::new(0));
                    let count = Arc::clone(&cleaned);
                    let (ready, mut witness) = oneshot::channel();
                    let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(9)
                    })
                    .unwrap();
                    witness.recv(&cx).await.unwrap();
                    assert!(matches!(set.join_quorum(&cx, required).await,
                        Err(QuorumError::InvalidQuorum { required: actual, total: 1 })
                        if actual == required));
                    assert_eq!(cleaned.load(Ordering::SeqCst), 1);
                }
                let empty = JoinSet::<u8, (), _>::in_cx(&cx);
                assert!(matches!(
                    empty.join_first_ok(&cx).await,
                    Err(QuorumError::InvalidQuorum {
                        required: 1,
                        total: 0
                    })
                ));
            });
        }
    });
}

#[test]
fn previously_collected_members_do_not_vote_in_a_later_quorum() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                set.spawn(&cx, |_| async { Ok(10) }).unwrap();
                assert_eq!(set.join_next(&cx).await.unwrap().expect("first member"), 10);
                set.spawn(&cx, |_| async { Ok(20) }).unwrap();
                assert_eq!(set.join_first_ok(&cx).await.unwrap(), 20);
            });
        }
    });
}

#[test]
fn owner_abort_reaches_every_parked_member() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let mut owner = cx
                    .spawn(move |owner| async move {
                        let mut set = JoinSet::<u8, (), _>::in_cx(&owner);
                        set.spawn(&owner, move |child| async move {
                            parked(&child, ready).await;
                            assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::Shutdown);
                            count.fetch_add(1, Ordering::SeqCst);
                            Ok(9)
                        })
                        .unwrap();
                        set.join_first_ok(&owner).await
                    })
                    .unwrap();
                witness.recv(&cx).await.unwrap();
                owner.abort_with_reason(CancelReason::shutdown());
                assert!(matches!(owner.join(&cx).await.unwrap(),
                    Err(QuorumError::Cancelled(reason)) if reason.kind == CancelKind::Shutdown));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn cleanup_panic_defeats_an_already_selected_success() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    panic!("intentional quorum loser cleanup panic");
                })
                .unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Ok(1) }).unwrap();
                assert!(matches!(
                    set.join_first_ok(&cx).await,
                    Err(QuorumError::Panicked(_))
                ));
            });
        }
    });
}

#[derive(Debug)]
struct DropAfterCleanup {
    cleaned: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl Drop for DropAfterCleanup {
    fn drop(&mut self) {
        assert_eq!(
            self.cleaned.load(Ordering::SeqCst),
            1,
            "selected value destroyed before sibling cleanup"
        );
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancellation_during_slow_drain_keeps_selected_value_until_cleanup() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let dropped = Arc::new(AtomicUsize::new(0));
                let (parked_send, mut parked_receive) = oneshot::channel();
                let (draining_send, mut draining_receive) = oneshot::channel();
                let (release, mut wait_release) = oneshot::channel();
                let (release_winner, mut wait_winner) = oneshot::channel();
                let count = Arc::clone(&cleaned);
                let winning = DropAfterCleanup {
                    cleaned: Arc::clone(&cleaned),
                    dropped: Arc::clone(&dropped),
                };
                let cleanup_cx = cx.clone();
                let mut owner = cx
                    .spawn(move |owner| async move {
                        let mut set = JoinSet::<DropAfterCleanup, &'static str, _>::in_cx(&owner);
                        set.spawn(&owner, move |child| async move {
                            parked(&child, parked_send).await;
                            draining_send.send_blocking(()).unwrap();
                            wait_release.recv(&cleanup_cx).await.unwrap();
                            count.fetch_add(1, Ordering::SeqCst);
                            Err("cleanup finished")
                        })
                        .unwrap();
                        set.spawn(&owner, move |child| async move {
                            wait_winner.recv(&child).await.unwrap();
                            Ok(winning)
                        })
                        .unwrap();
                        set.join_first_ok(&owner).await
                    })
                    .unwrap();
                parked_receive.recv(&cx).await.unwrap();
                // The winner cannot trigger loser cancellation until the
                // parent has observed the loser's real parked-state witness.
                release_winner.send_blocking(()).unwrap();
                draining_receive.recv(&cx).await.unwrap();
                assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                assert!(
                    matches!(owner.try_join(), Ok(None)),
                    "winner escaped before drain"
                );
                owner.abort_with_reason(CancelReason::shutdown());
                assert!(
                    matches!(owner.try_join(), Ok(None)),
                    "abort abandoned cleanup"
                );
                release.send_blocking(()).unwrap();
                assert!(matches!(owner.join(&cx).await.unwrap(),
                    Err(QuorumError::Cancelled(reason)) if reason.kind == CancelKind::Shutdown));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn dropping_an_unpolled_quorum_requests_cancellation_and_region_drains() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let (ready, mut witness) = oneshot::channel();
                let (cleaned, mut cleanup) = oneshot::channel();
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    cleaned.send_blocking(()).unwrap();
                    Ok(1)
                })
                .unwrap();
                witness.recv(&cx).await.unwrap();
                // Do not poll the consuming future at all: its captured set
                // must already own the abort-on-drop obligation.
                drop(set.join_quorum(&cx, 1));
                cleanup.recv(&cx).await.unwrap();
            });
        }
    });
}

#[test]
fn dropping_a_pending_quorum_does_not_abandon_its_parked_members() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                let mut cleanups = Vec::new();
                for _ in 0..3 {
                    let (ready, mut witness) = oneshot::channel();
                    let (cleaned, cleanup) = oneshot::channel();
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        cleaned.send_blocking(()).unwrap();
                        Ok(1)
                    })
                    .unwrap();
                    witness.recv(&cx).await.unwrap();
                    cleanups.push(cleanup);
                }
                let mut selection = Box::pin(set.join_quorum(&cx, 2));
                poll_fn(|task| {
                    assert!(selection.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(selection);
                for cleanup in &mut cleanups {
                    cleanup.recv(&cx).await.unwrap();
                }
            });
        }
    });
}

#[test]
fn a_large_quorum_crosses_collection_quanta_without_cloning_results() {
    #[derive(Debug)]
    struct Value(usize);
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let mut set = JoinSet::<Value, (), _>::in_cx(&cx);
                for index in 0..193 {
                    set.spawn(&cx, move |_| async move { Ok(Value(index)) })
                        .unwrap();
                }
                let values = set.join_quorum(&cx, 193).await.unwrap();
                let mut indices: Vec<_> = values.into_iter().map(|value| value.0).collect();
                indices.sort_unstable();
                assert_eq!(indices, (0..193).collect::<Vec<_>>());
            });
        }
    });
}

#[test]
fn worker_pinned_non_send_futures_participate_in_a_success_quorum() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let mut set = JoinSet::<usize, (), _>::in_cx(&cx);
                for index in 0..3 {
                    set.spawn_local(&cx, move |_| async move {
                        let local = std::rc::Rc::new(index);
                        asupersync::runtime::yield_now().await;
                        Ok(*local)
                    })
                    .unwrap();
                }
                let mut values = set.join_quorum(&cx, 3).await.unwrap();
                values.sort_unstable();
                assert_eq!(values, [0, 1, 2]);
            });
        }
    });
}

#[test]
fn quorum_report_preserves_selected_values_and_records_owner_cancel_during_cleanup() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let dropped = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let (draining, mut drain_witness) = oneshot::channel();
                let (release_cleanup, mut cleanup_gate) = oneshot::channel();
                let cleanup_cx = cx.clone();
                let mut releases = Vec::new();
                let mut winners = Vec::new();
                for _ in 0..2 {
                    let (release, gate) = oneshot::channel();
                    releases.push(release);
                    winners.push((
                        gate,
                        DropAfterCleanup {
                            cleaned: Arc::clone(&cleaned),
                            dropped: Arc::clone(&dropped),
                        },
                    ));
                }
                let mut owner = cx
                    .spawn(move |owner| async move {
                        let mut set =
                            JoinSet::<(TaskId, DropAfterCleanup), &'static str, _>::in_cx(&owner);
                        set.spawn(&owner, move |child| async move {
                            parked(&child, ready).await;
                            assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::RaceLost);
                            let mut draining = Some(draining);
                            let mut cleanup = pin!(cleanup_gate.recv(&cleanup_cx));
                            poll_fn(|task| match cleanup.as_mut().poll(task) {
                                Poll::Ready(result) => Poll::Ready(result),
                                Poll::Pending => {
                                    if let Some(draining) = draining.take() {
                                        // Witness the actual parked cleanup future, not
                                        // merely the start of the loser's cleanup body.
                                        draining.send_blocking(child.task_id()).unwrap();
                                    }
                                    Poll::Pending
                                }
                            })
                            .await
                            .unwrap();
                            count.fetch_add(1, Ordering::SeqCst);
                            Err("cleanup finished")
                        })
                        .unwrap();
                        for (mut gate, value) in winners {
                            set.spawn(&owner, move |child| async move {
                                gate.recv(&child).await.unwrap();
                                Ok((child.task_id(), value))
                            })
                            .unwrap();
                        }
                        set.join_quorum_report(&owner, 2).await
                    })
                    .unwrap();
                witness.recv(&cx).await.unwrap();
                for release in releases {
                    release.send_blocking(()).unwrap();
                }
                let loser_id = drain_witness.recv(&cx).await.unwrap();
                assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                assert!(matches!(owner.try_join(), Ok(None)));
                owner.abort_with_reason(CancelReason::shutdown());
                assert!(matches!(owner.try_join(), Ok(None)));
                release_cleanup.send_blocking(()).unwrap();

                let report = owner.join(&cx).await.unwrap();
                assert!(matches!(&report.decision, TaskQuorumDecision::Satisfied));
                assert_eq!(report.required, 2);
                assert_eq!(report.total, 3);
                assert_eq!(report.selected.len(), 2);
                assert_eq!(report.members.len(), 3);
                assert_eq!(
                    report.owner_cancellation.as_ref().unwrap().kind,
                    CancelKind::Shutdown
                );
                for member in &report.members[..2] {
                    assert!(matches!(member.index, 1 | 2));
                    assert_eq!(member.phase, TaskQuorumPhase::Selection);
                    assert!(report.selected.contains(&member.task_id));
                    match &member.outcome {
                        Outcome::Ok((id, _)) => assert_eq!(member.task_id, *id),
                        other => panic!("selected value was erased: {other:?}"),
                    }
                }
                let loser = &report.members[2];
                assert_eq!(loser.index, 0);
                assert_eq!(loser.task_id, loser_id);
                assert_eq!(loser.phase, TaskQuorumPhase::Cleanup);
                assert!(matches!(&loser.outcome,
                    Outcome::Cancelled(reason) if reason.kind == CancelKind::RaceLost));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                drop(report);
                assert_eq!(dropped.load(Ordering::SeqCst), 2);
            });
        }
    });
}

#[test]
fn quorum_report_retains_published_extra_successes_and_original_member_indices() {
    #[derive(Debug)]
    struct Value {
        task_id: TaskId,
        number: u8,
    }

    bounded(|| {
        for workers in [1, 2] {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::new().worker_threads(workers)
            };
            let runtime = builder.build().unwrap();
            let diagnostics = runtime.diagnostics();
            runtime.block_on(async {
                let cx = Cx::current().expect("native root context");
                let mut set = JoinSet::<Value, (), _>::in_cx(&cx);
                set.spawn(&cx, |child| async move {
                    Ok(Value {
                        task_id: child.task_id(),
                        number: 0,
                    })
                })
                .unwrap();
                let previous = set.join_next(&cx).await.unwrap().expect("earlier member");
                let mut ids = Vec::new();
                for number in 1..=3 {
                    let (admitted, mut receive_id) = oneshot::channel();
                    set.spawn(&cx, move |child| async move {
                        let task_id = child.task_id();
                        admitted.send_blocking(task_id).unwrap();
                        Ok(Value { task_id, number })
                    })
                    .unwrap();
                    ids.push(receive_id.recv(&cx).await.unwrap());
                }
                // Every terminal must already be published before the quorum
                // cancels siblings. Body-return signals alone would race the
                // cancellation-dominant task wrapper and could erase values.
                while ids.iter().any(|id| {
                    !matches!(
                        diagnostics.explain_task_blocked(*id).block_reason,
                        BlockReason::TaskNotFound
                    )
                }) {
                    asupersync::runtime::yield_now().await;
                }
                let report = set.join_first_ok_report(&cx).await;
                assert!(matches!(&report.decision, TaskQuorumDecision::Satisfied));
                assert_eq!(report.required, 1);
                assert_eq!(report.total, 3);
                assert_eq!(report.selected, [ids[0]]);
                assert!(!report.selected.contains(&previous.task_id));
                assert!(report.owner_cancellation.is_none());
                assert_eq!(report.members.len(), 3);
                for (offset, member) in report.members.iter().enumerate() {
                    assert_eq!(member.index, (offset + 1) as u64);
                    assert_eq!(member.task_id, ids[offset]);
                    assert_eq!(
                        member.phase,
                        if offset == 0 {
                            TaskQuorumPhase::Selection
                        } else {
                            TaskQuorumPhase::Cleanup
                        }
                    );
                    match &member.outcome {
                        Outcome::Ok(value) => {
                            assert_eq!(value.task_id, member.task_id);
                            assert_eq!(usize::from(value.number), offset + 1);
                        }
                        other => panic!("published success was lost: {other:?}"),
                    }
                }
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }
    });
}

#[test]
fn quorum_report_keeps_cleanup_panic_separate_from_the_selected_success() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    panic!("intentional quorum report cleanup panic");
                })
                .unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Ok(7) }).unwrap();
                let report = set.join_first_ok_report(&cx).await;
                assert!(matches!(&report.decision, TaskQuorumDecision::Satisfied));
                assert_eq!(report.total, 2);
                assert_eq!(report.selected, [report.members[0].task_id]);
                assert_eq!(report.members[0].index, 1);
                assert_eq!(report.members[0].phase, TaskQuorumPhase::Selection);
                assert!(matches!(&report.members[0].outcome, Outcome::Ok(7)));
                assert_eq!(report.members[1].index, 0);
                assert_eq!(report.members[1].phase, TaskQuorumPhase::Cleanup);
                assert!(matches!(&report.members[1].outcome, Outcome::Panicked(_)));
                assert!(report.owner_cancellation.is_none());
            });
        }
    });
}

#[test]
fn quorum_report_owner_cancel_before_selection_drains_every_member() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let (ready, mut witness) = oneshot::channel();
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let mut owner = cx
                    .spawn(move |owner| async move {
                        let mut set = JoinSet::<u8, (), _>::in_cx(&owner);
                        set.spawn(&owner, move |child| async move {
                            parked(&child, ready).await;
                            count.fetch_add(1, Ordering::SeqCst);
                            Ok(9)
                        })
                        .unwrap();
                        set.join_first_ok_report(&owner).await
                    })
                    .unwrap();
                witness.recv(&cx).await.unwrap();
                owner.abort_with_reason(CancelReason::shutdown());
                let report = owner.join(&cx).await.unwrap();
                assert!(matches!(&report.decision,
                    TaskQuorumDecision::OwnerCancelled(reason)
                        if reason.kind == CancelKind::Shutdown));
                assert!(report.selected.is_empty());
                assert_eq!(report.total, 1);
                assert_eq!(report.members.len(), 1);
                assert_eq!(report.members[0].phase, TaskQuorumPhase::Cleanup);
                assert!(matches!(&report.members[0].outcome,
                    Outcome::Cancelled(reason) if reason.kind == CancelKind::Shutdown));
                assert_eq!(
                    report.owner_cancellation.as_ref().unwrap().kind,
                    CancelKind::Shutdown
                );
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn quorum_reports_preserve_impossibility_errors_and_drain_invalid_requests() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    Ok(99)
                })
                .unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("backend unavailable") })
                    .unwrap();
                let report = set.join_quorum_report(&cx, 2).await;
                assert!(matches!(&report.decision, TaskQuorumDecision::Impossible));
                assert!(report.selected.is_empty());
                assert_eq!(report.members.len(), 2);
                assert_eq!(report.members[0].index, 1);
                assert_eq!(report.members[0].phase, TaskQuorumPhase::Selection);
                assert!(matches!(
                    &report.members[0].outcome,
                    Outcome::Err("backend unavailable")
                ));
                assert_eq!(report.members[1].phase, TaskQuorumPhase::Cleanup);
                assert!(matches!(&report.members[1].outcome, Outcome::Cancelled(_)));

                for required in [0, 2, usize::MAX] {
                    let (ready, mut witness) = oneshot::channel();
                    let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        Ok(99)
                    })
                    .unwrap();
                    witness.recv(&cx).await.unwrap();
                    let report = set.join_quorum_report(&cx, required).await;
                    assert!(matches!(&report.decision, TaskQuorumDecision::Invalid));
                    assert_eq!(report.required, required);
                    assert_eq!(report.total, 1);
                    assert!(report.selected.is_empty());
                    assert_eq!(report.members.len(), 1);
                    assert_eq!(report.members[0].phase, TaskQuorumPhase::Cleanup);
                    assert!(matches!(&report.members[0].outcome, Outcome::Cancelled(_)));
                }
                let report = JoinSet::<u8, (), _>::in_cx(&cx)
                    .join_first_ok_report(&cx)
                    .await;
                assert!(matches!(&report.decision, TaskQuorumDecision::Invalid));
                assert_eq!(report.total, 0);
                assert!(report.members.is_empty());
                assert!(report.selected.is_empty());
            });
        }
    });
}

#[test]
fn dropping_a_quorum_report_future_cancels_owned_members_before_region_close() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                for poll_once in [false, true] {
                    let (ready, mut witness) = oneshot::channel();
                    let (cleaned, mut cleanup) = oneshot::channel();
                    let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        cleaned.send_blocking(()).unwrap();
                        Ok(1)
                    })
                    .unwrap();
                    witness.recv(&cx).await.unwrap();
                    let mut report = Box::pin(set.join_first_ok_report(&cx));
                    if poll_once {
                        poll_fn(|task| {
                            assert!(report.as_mut().poll(task).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                    }
                    drop(report);
                    cleanup.recv(&cx).await.unwrap();
                }
            });
        }
    });
}
