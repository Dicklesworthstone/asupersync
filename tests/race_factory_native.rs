//! Native child-context race cancellation and drain, not a source-text proxy.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::cx::{RaceFactory, cap};
use asupersync::runtime::{JoinError, RuntimeBuilder, TaskHandle};
use asupersync::sync::Notify;
use asupersync::types::{CancelKind, CancelReason, TaskId};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    released: AtomicBool,
    retired: AtomicBool,
    task: Mutex<Option<TaskId>>,
    reason: Mutex<Option<CancelReason>>,
    context: Mutex<Option<Cx>>,
    changed: Notify,
}
impl Witness {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

fn boxed<T, F, Fut>(factory: F) -> RaceFactory<T>
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    Box::new(move |child| Box::pin(factory(child)))
}

fn native<F, Fut>(workers: usize, body: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new().worker_threads(workers).build().unwrap()
    };
    // `JoinHandle<()>` resolves to `()`: a panicked owner is resumed here and a
    // dropped or cancelled one panics, so any owner failure fails the test.
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("real admitted native task");
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), body(cx.clone()))
            .await.expect("native race/drain watchdog");
    }));
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

async fn loser(child: Cx, mut receiver: mpsc::Receiver<()>, seen: Arc<Witness>) -> u8 {
    let _retire = Retire(Arc::clone(&seen));
    *seen.task.lock().unwrap() = Some(child.task_id());
    let result = {
        let mut receive = std::pin::pin!(receiver.recv(&child));
        poll_fn(|task| {
            let progress = receive.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) {
                seen.changed.notify_waiters();
            }
            progress
        }).await
    };
    // The sender is still retained by the owner and never sends. Only the
    // branch's actual cancellation can release this witnessed pending receive.
    assert!(result.is_err());
    assert!(child.is_cancel_requested());
    assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::RaceLost);
    assert!(child.checkpoint().is_err());
    seen.cancelled.store(true, Ordering::Release);
    seen.changed.notify_waiters();
    // Deliberately asynchronous cleanup, withheld until the owner verifies
    // that neither ordinary selection nor timeout published an early result.
    seen.changed.wait_until(|| seen.released.load(Ordering::Acquire)).await;
    0
}

async fn winner(seen: Arc<Witness>) -> u8 {
    seen.changed.wait_until(|| seen.parked.load(Ordering::Acquire)).await;
    7
}

async fn wait_cancel<T>(future: &mut Pin<Box<impl Future<Output = T>>>, seen: &Witness) {
    let mut cancelled = std::pin::pin!(seen.changed.wait_until(|| seen.cancelled.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending(), "race returned before withheld cleanup");
        cancelled.as_mut().poll(task)
    }).await;
    assert!(!seen.retired.load(Ordering::Acquire));
}

// This branch witnesses an actual Pending receive, then withholds asynchronous
// cleanup. Closing its sender provides an independent no-cancellation control
// and also lets a watchdog failure tear down the test without stranded tasks.
async fn owner_cancel_branch(
    child: Cx,
    mut receiver: mpsc::Receiver<()>,
    seen: Arc<Witness>,
    panic_during_cleanup: bool,
) -> u8 {
    let _retire = Retire(Arc::clone(&seen));
    *seen.task.lock().unwrap() = Some(child.task_id());
    *seen.context.lock().unwrap() = Some(child.clone());
    let result = {
        let mut receive = std::pin::pin!(receiver.recv(&child));
        poll_fn(|task| {
            let progress = receive.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) {
                seen.changed.notify_waiters();
            }
            progress
        })
        .await
    };
    if !child.is_cancel_requested() {
        return 7;
    }
    assert!(result.is_err());
    assert!(child.checkpoint().is_err());
    *seen.reason.lock().unwrap() = child.cancel_reason();
    seen.cancelled.store(true, Ordering::Release);
    seen.changed.notify_waiters();
    seen.changed
        .wait_until(|| seen.released.load(Ordering::Acquire))
        .await;
    assert!(
        !panic_during_cleanup,
        "owner-cancelled branch cleanup sentinel"
    );
    0
}

#[derive(Clone, Copy, Debug)]
enum OwnerRaceForm {
    Factories,
    AllHandles,
    TwoHandles,
    Legacy,
    TimedFactories,
    #[cfg(feature = "proc-macros")]
    FactoryMacro,
    #[cfg(feature = "proc-macros")]
    LegacyMacro,
    #[cfg(feature = "proc-macros")]
    SelectMacro,
    #[cfg(feature = "proc-macros")]
    BiasedSelectMacro,
}

async fn owner_race(
    form: OwnerRaceForm,
    owner: Cx,
    receivers: [mpsc::Receiver<()>; 2],
    witnesses: [Arc<Witness>; 2],
    panic_first: bool,
) -> Result<u8, JoinError> {
    let [ra, rb] = receivers;
    let [a, b] = witnesses;
    match form {
        OwnerRaceForm::Factories => {
            owner
                .race_drained_with(vec![
                    boxed(move |child| owner_cancel_branch(child, ra, a, panic_first)),
                    boxed(move |child| owner_cancel_branch(child, rb, b, false)),
                ])
                .await
        }
        OwnerRaceForm::TimedFactories => {
            owner
                .race_drained_with_timeout(
                    Duration::from_secs(3600),
                    vec![
                        boxed(move |child| owner_cancel_branch(child, ra, a, panic_first)),
                        boxed(move |child| owner_cancel_branch(child, rb, b, false)),
                    ],
                )
                .await
        }
        OwnerRaceForm::AllHandles | OwnerRaceForm::TwoHandles => {
            let scope = owner.scope();
            let ha = owner
                .spawn_in(&scope, move |child| {
                    owner_cancel_branch(child, ra, a, panic_first)
                })
                .unwrap();
            let hb = owner
                .spawn_in(&scope, move |child| {
                    owner_cancel_branch(child, rb, b, false)
                })
                .unwrap();
            if matches!(form, OwnerRaceForm::TwoHandles) {
                scope.race(&owner, ha, hb).await
            } else {
                scope
                    .race_all(&owner, vec![ha, hb])
                    .await
                    .map(|(value, _)| value)
            }
        }
        OwnerRaceForm::Legacy => {
            owner
                .race_drained(vec![
                    Box::pin(async move {
                        owner_cancel_branch(Cx::current().unwrap(), ra, a, panic_first).await
                    }),
                    Box::pin(async move {
                        owner_cancel_branch(Cx::current().unwrap(), rb, b, false).await
                    }),
                ])
                .await
        }
        #[cfg(feature = "proc-macros")]
        OwnerRaceForm::FactoryMacro => asupersync::race!(owner, {
            move |child| owner_cancel_branch(child, ra, a, panic_first),
            move |child| owner_cancel_branch(child, rb, b, false),
        }),
        #[cfg(feature = "proc-macros")]
        OwnerRaceForm::LegacyMacro => asupersync::race!(owner, {
            async move {
                owner_cancel_branch(Cx::current().unwrap(), ra, a, panic_first).await
            },
            async move {
                owner_cancel_branch(Cx::current().unwrap(), rb, b, false).await
            },
        }),
        #[cfg(feature = "proc-macros")]
        OwnerRaceForm::SelectMacro => asupersync::select!(owner, {
            value = move |child| owner_cancel_branch(child, ra, a, panic_first) => value,
            value = move |child| owner_cancel_branch(child, rb, b, false) => value,
        }),
        #[cfg(feature = "proc-macros")]
        OwnerRaceForm::BiasedSelectMacro => asupersync::select!(owner, biased, {
            value = move |child| owner_cancel_branch(child, ra, a, panic_first) => value,
            value = move |child| owner_cancel_branch(child, rb, b, false) => value,
        }),
    }
}

async fn cancel_parked_owner(
    cx: &Cx,
    owner: TaskHandle<Result<u8, JoinError>>,
    witnesses: &[Arc<Witness>],
    panic_first: bool,
) {
    for seen in witnesses {
        seen.changed
            .wait_until(|| seen.parked.load(Ordering::Acquire))
            .await;
        let branch = seen.task.lock().unwrap().unwrap();
        assert_ne!(branch, owner.task_id());
        assert_ne!(branch, cx.task_id());
    }
    // User is deliberately less severe than RaceLost: dropping armed joins
    // before propagation would silently replace this exact attribution.
    let reason = CancelReason::user("stop parked race owner").with_task(owner.task_id());
    owner.abort_with_reason(reason.clone());
    finish_cancelled_owner(cx, owner, witnesses, reason, panic_first).await;
}

async fn finish_cancelled_owner(
    cx: &Cx,
    mut owner: TaskHandle<Result<u8, JoinError>>,
    witnesses: &[Arc<Witness>],
    reason: CancelReason,
    panic_first: bool,
) {
    let mut joined = Box::pin(owner.join(cx));
    for seen in witnesses {
        wait_cancel(&mut joined, seen).await;
        assert_eq!(*seen.reason.lock().unwrap(), Some(reason.clone()));
    }
    assert!(
        !cx.is_cancel_requested(),
        "cancellation escaped to the observer"
    );
    for seen in witnesses {
        seen.release();
    }
    // The race acknowledges owner cancellation; ordinary spawn preserves the
    // owner's typed result, including a panic reported by a draining branch.
    let result = joined
        .await
        .expect("owner must preserve its acknowledged result");
    if panic_first {
        match result {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "owner-cancelled branch cleanup sentinel");
            }
            other => panic!("cleanup panic must outrank owner cancellation: {other:?}"),
        }
    } else {
        assert!(matches!(result, Err(JoinError::Cancelled(actual)) if actual == reason));
    }
    assert!(
        witnesses
            .iter()
            .all(|seen| seen.retired.load(Ordering::Acquire))
    );
}

async fn owner_cancellation_scenario(cx: Cx, form: OwnerRaceForm, panic_first: bool) {
    let seen = [Arc::new(Witness::default()), Arc::new(Witness::default())];
    let branches = seen.clone();
    let (sa, ra) = mpsc::channel(1);
    let (sb, rb) = mpsc::channel(1);
    let owner = cx
        .spawn(move |owner| owner_race(form, owner, [ra, rb], branches, panic_first))
        .unwrap();
    cancel_parked_owner(&cx, owner, &seen, panic_first).await;
    for sender in [sa, sb] {
        let telemetry = sender.telemetry_snapshot(0);
        assert_eq!(telemetry.recv_waiter_count, 0);
        assert_eq!(telemetry.reserved_uncommitted_obligations, 0);
        assert_eq!(telemetry.queued_messages, 0);
    }
}

#[test]
fn owner_cancellation_wakes_and_drains_parked_races_on_both_native_runtimes() {
    for workers in [1, 2] {
        for form in [
            OwnerRaceForm::Factories,
            OwnerRaceForm::AllHandles,
            OwnerRaceForm::TwoHandles,
            OwnerRaceForm::Legacy,
            OwnerRaceForm::TimedFactories,
        ] {
            native(workers, move |cx| {
                owner_cancellation_scenario(cx, form, false)
            });
        }
    }
}

#[cfg(feature = "proc-macros")]
#[test]
fn owner_cancellation_reaches_race_and_blocking_select_macro_branches() {
    for workers in [1, 2] {
        for form in [
            OwnerRaceForm::FactoryMacro,
            OwnerRaceForm::LegacyMacro,
            OwnerRaceForm::SelectMacro,
            OwnerRaceForm::BiasedSelectMacro,
        ] {
            native(workers, move |cx| {
                owner_cancellation_scenario(cx, form, false)
            });
        }
    }
}

#[test]
fn cleanup_panic_outranks_owner_cancellation_after_every_branch_drains() {
    for workers in [1, 2] {
        for form in [OwnerRaceForm::Factories, OwnerRaceForm::TwoHandles] {
            native(workers, move |cx| {
                owner_cancellation_scenario(cx, form, true)
            });
        }
    }
}

#[test]
fn parked_race_control_completes_when_one_channel_closes_without_owner_abort() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = [Arc::new(Witness::default()), Arc::new(Witness::default())];
            let branches = seen.clone();
            let (sa, ra) = mpsc::channel(1);
            let (_sb, rb) = mpsc::channel(1);
            let mut owner = cx
                .spawn(move |owner| {
                    owner_race(OwnerRaceForm::Factories, owner, [ra, rb], branches, false)
                })
                .unwrap();
            for branch in &seen {
                branch
                    .changed
                    .wait_until(|| branch.parked.load(Ordering::Acquire))
                    .await;
            }
            drop(sa);
            let mut joined = Box::pin(owner.join(&cx));
            wait_cancel(&mut joined, &seen[1]).await;
            assert_eq!(
                seen[1].reason.lock().unwrap().as_ref().unwrap().kind,
                CancelKind::RaceLost
            );
            seen[1].release();
            assert_eq!(joined.await.unwrap().unwrap(), 7);
            assert!(
                seen.iter()
                    .all(|branch| branch.retired.load(Ordering::Acquire))
            );
            assert!(!seen[0].cancelled.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn owner_cancellation_drains_nested_races_before_returning() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = [
                Arc::new(Witness::default()),
                Arc::new(Witness::default()),
                Arc::new(Witness::default()),
            ];
            let [a, b, c] = seen.clone();
            let (_sa, ra) = mpsc::channel(1);
            let (_sb, rb) = mpsc::channel(1);
            let (_sc, rc) = mpsc::channel(1);
            let owner = cx
                .spawn(move |owner| async move {
                    owner
                        .race_drained_with(vec![
                            boxed(move |inner| async move {
                                let result = inner
                                    .race_drained_with(vec![
                                        boxed(move |child| {
                                            owner_cancel_branch(child, ra, a, false)
                                        }),
                                        boxed(move |child| {
                                            owner_cancel_branch(child, rb, b, false)
                                        }),
                                    ])
                                    .await;
                                assert!(matches!(result, Err(JoinError::Cancelled(_))));
                                0
                            }),
                            boxed(move |child| owner_cancel_branch(child, rc, c, false)),
                        ])
                        .await
                })
                .unwrap();
            cancel_parked_owner(&cx, owner, &seen, false).await;
        });
    }
}

#[test]
fn masked_owner_poll_defers_branch_cancellation_until_an_unmasked_poll() {
    for workers in [1, 2] {
        for form in [OwnerRaceForm::Factories, OwnerRaceForm::TwoHandles] {
            native(workers, move |cx| async move {
                let seen = [Arc::new(Witness::default()), Arc::new(Witness::default())];
                let branches = seen.clone();
                let checked = seen.clone();
                let mask = Arc::new(Witness::default());
                let owner_mask = Arc::clone(&mask);
                let (_sa, ra) = mpsc::channel(1);
                let (_sb, rb) = mpsc::channel(1);
                let owner = cx
                    .spawn(move |owner| async move {
                        let mut race =
                            Box::pin(owner_race(form, owner.clone(), [ra, rb], branches, false));
                        poll_fn(|task| {
                            if owner.is_cancel_requested() {
                                assert!(owner.masked(|| race.as_mut().poll(task)).is_pending());
                                for branch in &checked {
                                    assert!(
                                        !branch
                                            .context
                                            .lock()
                                            .unwrap()
                                            .as_ref()
                                            .unwrap()
                                            .is_cancel_requested()
                                    );
                                }
                                owner_mask.parked.store(true, Ordering::Release);
                                owner_mask.changed.notify_waiters();
                                Poll::Ready(())
                            } else {
                                assert!(race.as_mut().poll(task).is_pending());
                                Poll::Pending
                            }
                        })
                        .await;
                        // Keep the owner paused outside the masked poll so the
                        // observer can inspect both real branch contexts.
                        owner_mask
                            .changed
                            .wait_until(|| owner_mask.released.load(Ordering::Acquire))
                            .await;
                        race.await
                    })
                    .unwrap();
                for branch in &seen {
                    branch
                        .changed
                        .wait_until(|| branch.parked.load(Ordering::Acquire))
                        .await;
                }
                let reason = CancelReason::user("masked race owner").with_task(owner.task_id());
                owner.abort_with_reason(reason.clone());
                mask.changed
                    .wait_until(|| mask.parked.load(Ordering::Acquire))
                    .await;
                for branch in &seen {
                    assert!(
                        !branch
                            .context
                            .lock()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .is_cancel_requested()
                    );
                    assert!(!branch.cancelled.load(Ordering::Acquire));
                }
                mask.release();
                finish_cancelled_owner(&cx, owner, &seen, reason, false).await;
            });
        }
    }
}

#[test]
fn lab_owner_cancellation_retires_all_tasks_and_completes_drain_history() {
    use asupersync::{Budget, LabConfig, LabRuntime};

    for seed in [17, 41, 93] {
        for form in [OwnerRaceForm::Factories, OwnerRaceForm::TwoHandles] {
            let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let (task, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    owner_cancellation_scenario(Cx::current().unwrap(), form, false).await;
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            let report = lab.run_until_quiescent_with_report();
            assert!(
                matches!(joined.try_join(), Ok(Some(()))),
                "owner scenario did not finish: {report:?}"
            );
            assert!(lab.state.tasks_is_empty(), "race left live task records");
            assert!(
                lab.state
                    .obligations_iter()
                    .all(|(_, obligation)| !obligation.is_pending()),
                "race left unsettled obligations"
            );
            assert_eq!(lab.oracles.loser_drain.active_race_count(), 0);
            assert_eq!(lab.oracles.loser_drain.completed_race_count(), 1);
            assert!(
                report.lab_test_passed(),
                "owner-cancelled race oracle failure: {report:?}"
            );
        }
    }
}

#[test]
fn cancellation_after_selection_keeps_the_winner_while_finishing_loser_cleanup() {
    for workers in [1, 2] {
        for two_handles in [false, true] {
            native(workers, move |cx| async move {
                let seen = Arc::new(Witness::default());
                let a = Arc::clone(&seen);
                let b = Arc::clone(&seen);
                let (_sender, receiver) = mpsc::channel(1);
                let mut owner = cx
                    .spawn(move |owner| async move {
                        let result = if two_handles {
                            let scope = owner.scope();
                            let a = owner
                                .spawn_in(&scope, move |child| loser(child, receiver, a))
                                .unwrap();
                            let b = owner.spawn_in(&scope, move |_child| winner(b)).unwrap();
                            scope.race(&owner, a, b).await
                        } else {
                            owner
                                .race_drained_with(vec![
                                    boxed(move |child| loser(child, receiver, a)),
                                    boxed(move |_child| winner(b)),
                                ])
                                .await
                        };
                        assert!(
                            matches!(result, Ok(7)),
                            "late cancellation replaced a selected winner: {result:?}"
                        );
                        // Observe the owner's independent request only after the
                        // race has published its selected result.
                        assert!(owner.checkpoint().is_err());
                        result
                    })
                    .unwrap();
                seen.changed
                    .wait_until(|| seen.cancelled.load(Ordering::Acquire))
                    .await;
                owner
                    .abort_with_reason(CancelReason::user("cancel during selected winner cleanup"));
                let mut joined = Box::pin(owner.join(&cx));
                wait_cancel(&mut joined, &seen).await;
                seen.release();
                assert_eq!(joined.await.unwrap().unwrap(), 7);
                assert!(seen.retired.load(Ordering::Acquire));
                assert!(!cx.is_cancel_requested());
            });
        }
    }
}

#[test]
fn factories_cancel_the_real_child_and_await_its_cleanup_on_both_native_runtimes() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let start = Instant::now();
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let a = Arc::clone(&seen);
            let b = Arc::clone(&seen);
            let mut race = Box::pin(cx.race_drained_with(vec![
                boxed(move |child| loser(child, receiver, a)),
                boxed(move |_child| winner(b)),
            ]));
            wait_cancel(&mut race, &seen).await;
            assert_ne!(seen.task.lock().unwrap().unwrap(), cx.task_id());
            assert!(!cx.is_cancel_requested());
            seen.release();
            assert_eq!(race.await.unwrap(), 7);
            assert!(seen.retired.load(Ordering::Acquire));
            eprintln!("scenario=factory-recv workers={workers} parent={:?} child={:?} parked=true cancelled=true retired=true elapsed={:?}", cx.task_id(), *seen.task.lock().unwrap(), start.elapsed());
        });
    }
}

#[test]
fn timeout_waits_for_both_parked_losers_to_finish_cleanup() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let start = Instant::now();
            let a = Arc::new(Witness::default());
            let b = Arc::new(Witness::default());
            let (_sa, ra) = mpsc::channel(1);
            let (_sb, rb) = mpsc::channel(1);
            let fa = Arc::clone(&a);
            let fb = Arc::clone(&b);
            let mut race = Box::pin(cx.race_drained_with_timeout(Duration::from_millis(500), vec![
                boxed(move |child| loser(child, ra, fa)),
                boxed(move |child| loser(child, rb, fb)),
            ]));
            wait_cancel(&mut race, &a).await;
            wait_cancel(&mut race, &b).await;
            assert!(a.parked.load(Ordering::Acquire) && b.parked.load(Ordering::Acquire));
            a.release();
            b.release();
            assert!(matches!(race.await, Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout));
            assert!(a.retired.load(Ordering::Acquire) && b.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
            eprintln!("scenario=factory-timeout workers={workers} cancelled=2 retired=2 elapsed={:?}", start.elapsed());
        });
    }
}

#[test]
fn loser_cleanup_panic_is_not_hidden_by_a_successful_winner() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let a = Arc::clone(&seen);
            let b = Arc::clone(&seen);
            let mut race = Box::pin(cx.race_drained_with(vec![
                boxed(move |child| async move {
                    loser(child, receiver, a).await;
                    panic!("factory loser cleanup sentinel");
                }),
                boxed(move |_child| winner(b)),
            ]));
            wait_cancel(&mut race, &seen).await;
            seen.release();
            assert!(matches!(race.await, Err(JoinError::Panicked(_))));
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}

#[test]
fn cancelled_and_masked_owners_never_invoke_a_factory() {
    native(1, |cx| async move {
        let denied = {
            let _guard = cx.clone().restrict::<cap::CapSet<false, true, true, true, true>>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = denied.race_drained_with(vec![boxed(move |_child| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { 1 }
        })]).await;
        assert!(matches!(result, Err(JoinError::Cancelled(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    });
    // `race_drained_with` needs spawn authority (`Cx<cap::All>`), which a
    // detached `Cx<cap::None>` cannot carry, so the cancelled owner is a real
    // admitted native task that cancels its own context before racing.
    native(1, |cx| async move {
        cx.cancel_fast(CancelKind::User);
        let mut future = Box::pin(cx.race_drained_with(vec![boxed::<(), _, _>(|_child| async {
            panic!("cancelled owner must not invoke its factory");
        })]));
        assert!(matches!(future.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())),
            Poll::Ready(Err(JoinError::Cancelled(reason))) if reason.kind == CancelKind::User));
    });
}

#[cfg(feature = "proc-macros")]
#[test]
fn race_macro_factory_forms_share_native_cancel_and_drain_semantics() {
    for workers in [1, 2] {
        for form in 0..4 {
            native(workers, move |cx| async move {
                let seen = Arc::new(Witness::default());
                let (_sender, receiver) = mpsc::channel(1);
                let a = Arc::clone(&seen);
                let b = Arc::clone(&seen);
                let run = async {
                    match form {
                        0 => asupersync::race!(cx, {
                            move |child| loser(child, receiver, a),
                            move |_child| winner(b),
                        }),
                        1 => asupersync::race!(cx, {
                            "parked" => move |child| loser(child, receiver, a),
                            "winner" => move |_child| winner(b),
                        }),
                        2 => asupersync::race!(cx, timeout: Duration::from_secs(5), {
                            move |child| loser(child, receiver, a),
                            move |_child| winner(b),
                        }),
                        _ => asupersync::race!(cx, timeout: Duration::from_secs(5), {
                            "parked" => move |child| loser(child, receiver, a),
                            "winner" => move |_child| winner(b),
                        }),
                    }
                };
                let mut race = Box::pin(run);
                wait_cancel(&mut race, &seen).await;
                seen.release();
                assert_eq!(race.await.unwrap(), 7);
                assert!(seen.retired.load(Ordering::Acquire));
                assert!(!cx.is_cancel_requested());
                eprintln!("scenario=macro-factory workers={workers} form={form} parked=true cancelled=true retired=true");
            });
        }
    }
}

#[cfg(feature = "proc-macros")]
#[test]
fn select_factory_heterogeneous_outputs_drain_before_returning() {
    for workers in [1, 2] {
        for biased in [false, true] {
            native(workers, move |cx| async move {
                let seen = Arc::new(Witness::default());
                let (_sender, receiver) = mpsc::channel(1);
                let a = Arc::clone(&seen);
                let b = Arc::clone(&seen);
                let run = async {
                    if biased {
                        asupersync::select!(cx, biased, {
                            value = move |child| loser(child, receiver, a) => value,
                            (value, label) = move |_child| async move {
                                (winner(b).await, String::from("selected"))
                            } => { assert_eq!(label, "selected"); value },
                        })
                    } else {
                        asupersync::select!(cx, {
                            value = move |child| loser(child, receiver, a) => value,
                            (value, label) = move |_child| async move {
                                (winner(b).await, String::from("selected"))
                            } => { assert_eq!(label, "selected"); value },
                        })
                    }
                };
                let mut race = Box::pin(run);
                wait_cancel(&mut race, &seen).await;
                assert_ne!(seen.task.lock().unwrap().unwrap(), cx.task_id());
                seen.release();
                assert_eq!(race.await.unwrap(), 7);
                assert!(seen.retired.load(Ordering::Acquire));
                assert!(!cx.is_cancel_requested());
                eprintln!("scenario=select-factory workers={workers} biased={biased} parked=true cancelled=true retired=true");
            });
        }
    }
}

#[cfg(feature = "proc-macros")]
#[test]
fn select_default_still_needs_no_spawn_and_accepts_non_send_borrows() {
    use std::cell::Cell;
    use std::rc::Rc;
    let cx = Cx::detached_cancel_context();
    let calls = Rc::new(Cell::new(0));
    let retained = Rc::clone(&calls);
    let mut future = std::pin::pin!(async {
        asupersync::select!(cx, {
            () = async {
                retained.set(retained.get() + 1);
                std::future::pending::<()>().await;
            } => 0,
            else => 41,
        })
    });
    assert!(matches!(future.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())), Poll::Ready(41)));
    assert_eq!(calls.get(), 1);
}

#[test]
fn factory_sleep_loser_is_cancelled_without_waiting_for_its_deadline() {
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let seen = Arc::new(Witness::default());
            let a = Arc::clone(&seen);
            let b = Arc::clone(&seen);
            let mut race = Box::pin(cx.race_drained_with(vec![
                boxed(move |child| async move {
                    let _retire = Retire(Arc::clone(&a));
                    *a.task.lock().unwrap() = Some(child.task_id());
                    let mut sleep = std::pin::pin!(asupersync::time::sleep(child.now(), Duration::from_secs(3600)));
                    poll_fn(|task| {
                        let result = sleep.as_mut().poll(task);
                        if result.is_pending() && !a.parked.swap(true, Ordering::AcqRel) {
                            a.changed.notify_waiters();
                        }
                        result
                    }).await;
                    assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::RaceLost);
                    assert!(child.checkpoint().is_err());
                    a.cancelled.store(true, Ordering::Release);
                    a.changed.notify_waiters();
                    a.changed.wait_until(|| a.released.load(Ordering::Acquire)).await;
                    0
                }),
                boxed(move |_child| winner(b)),
            ]));
            wait_cancel(&mut race, &seen).await;
            seen.release();
            assert_eq!(race.await.unwrap(), 7);
            assert!(seen.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
            eprintln!("scenario=factory-sleep workers={workers} deadline=3600s parked=true cancelled=true retired=true");
        });
    }
}

/// A loser parked on a receive whose sender stays alive. It records the cause
/// it observes once cancellation releases it.
async fn parked_until_cancelled(
    child: Cx,
    mut receiver: mpsc::Receiver<()>,
    parked: Arc<AtomicUsize>,
    kinds: Arc<Mutex<Vec<CancelKind>>>,
) -> u8 {
    let mut marked = false;
    let result = {
        let mut receive = std::pin::pin!(receiver.recv(&child));
        poll_fn(|task| {
            let progress = receive.as_mut().poll(task);
            if progress.is_pending() && !marked {
                marked = true;
                parked.fetch_add(1, Ordering::SeqCst);
            }
            progress
        })
        .await
    };
    if let Some(reason) = child.cancel_reason() {
        kinds.lock().unwrap().push(reason.kind);
    }
    assert!(result.is_err(), "the retained sender never sends");
    0
}

/// Races a parked loser against a winner that panics once the loser is
/// parked. Returns whether the race ended Panicked and the causes the loser
/// observed before the race returned.
async fn panicking_winner_race(cx: Cx) -> (bool, Vec<CancelKind>) {
    let parked = Arc::new(AtomicUsize::new(0));
    let kinds = Arc::new(Mutex::new(Vec::new()));
    let (_sender, receiver) = mpsc::channel::<()>(1);
    let (loser_parked, loser_kinds) = (Arc::clone(&parked), Arc::clone(&kinds));
    let winner_waits = Arc::clone(&parked);
    let result = cx
        .race_drained_with(vec![
            boxed(move |child| parked_until_cancelled(child, receiver, loser_parked, loser_kinds)),
            boxed(move |_child| async move {
                while winner_waits.load(Ordering::SeqCst) == 0 {
                    asupersync::runtime::yield_now().await;
                }
                panic!("winner panics after the loser parked");
            }),
        ])
        .await;
    let observed = kinds.lock().unwrap().clone();
    (matches!(result, Err(JoinError::Panicked(_))), observed)
}

/// asupersync-bi2462.101: under the deterministic lab a panicking winner used
/// to return after one noop-waker poll of the loser's join, while the lab
/// recorded a drain that never happened. The lab now drains the parked loser
/// before returning, exactly as both native runtimes do.
#[test]
fn lab_and_native_drain_a_parked_loser_before_a_panicking_winner_returns() {
    use asupersync::{Budget, LabConfig, LabRuntime};

    for seed in [17, 41, 93] {
        let observed = Arc::new(Mutex::new(None));
        let publish = Arc::clone(&observed);
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut joined) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let outcome = panicking_winner_race(Cx::current().unwrap()).await;
                *publish.lock().unwrap() = Some(outcome);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        let report = lab.run_until_quiescent_with_report();
        assert!(
            matches!(joined.try_join(), Ok(Some(()))),
            "seed {seed}: owner did not finish: {report:?}"
        );
        assert_eq!(
            *observed.lock().unwrap(),
            Some((true, vec![CancelKind::RaceLost])),
            "seed {seed}: the lab drains the loser before the race returns"
        );
        assert_eq!(
            lab.oracles.loser_drain.completed_race_count(),
            1,
            "seed {seed}: the recorded drain happened"
        );
    }
    for workers in [1, 2] {
        native(workers, move |cx| async move {
            let outcome = panicking_winner_race(cx).await;
            assert_eq!(
                outcome,
                (true, vec![CancelKind::RaceLost]),
                "native workers={workers} drains the loser first"
            );
        });
    }
    eprintln!(
        "scenario=panicking-winner-drain seeds=17,41,93 lab=drained native=drained loser_kind=RaceLost"
    );
}
