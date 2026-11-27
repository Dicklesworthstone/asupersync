//! Native lifecycle witnesses for deferred activation in the running controller.
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::{mpsc, oneshot};
use crate::cx::{ChildRegionSpec, Cx};
use crate::runtime::{RuntimeBuilder, RuntimeHandle};
use crate::types::CancelKind;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

fn legacy_must_not_run(
    _: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
    _: &mut RuntimeState,
    _: &Cx,
) -> Result<TaskId, SpawnError> {
    panic!("managed activation must use its retained factory")
}

fn deferred(name: &str) -> ChildSpec {
    ChildSpec::new(name, legacy_must_not_run).with_start_immediately(false)
}

fn config(policy: RestartPolicy, restarts: u32) -> SupervisionConfig {
    SupervisionConfig::new(restarts, Duration::from_secs(60))
        .with_restart_policy(policy)
        .with_backoff(BackoffStrategy::None)
}

fn native_case<F, Fut>(sharded: bool, case: F)
where
    F: FnOnce(Cx, RuntimeHandle) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .with_sharded_state(sharded)
        .build()
        .expect("native controlled supervisor runtime");
    assert_eq!(runtime.config().worker_threads, 2);
    let native = runtime.handle();
    let (finished, finish) = std::sync::mpsc::sync_channel(1);
    let owner = runtime.handle().spawn(async move {
        case(Cx::current().expect("native owner"), native).await;
        finished.send(()).unwrap();
    });
    finish
        .recv_timeout(Duration::from_secs(15))
        .expect("native activation case must finish without a synthetic wake");
    runtime.block_on(owner);
}

async fn until_cancelled(cx: &Cx) -> Outcome<(), &'static str> {
    let (_sender, mut receiver) = mpsc::channel::<()>(1);
    assert!(matches!(
        receiver.recv(cx).await,
        Err(mpsc::RecvError::Cancelled)
    ));
    Outcome::Cancelled(cx.cancel_reason().expect("cancellation delivered"))
}

struct TrackedFactory {
    starts: Arc<AtomicUsize>,
    retired: Arc<AtomicUsize>,
}

impl ManagedChildFactory<&'static str> for TrackedFactory {
    fn start(&self, cx: Cx, _: ManagedGeneration) -> ManagedChildFuture<&'static str> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { until_cancelled(&cx).await })
    }

    fn retired(&self) {
        self.retired.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn native_activation_checks_dependencies_and_duplicates_then_abort_drains() {
    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let finalized = Arc::new(AtomicUsize::new(0));
            let managed = SupervisorBuilder::new("controlled-dependencies")
                .child(deferred("base"))
                .child(deferred("dependent").depends_on("base"))
                .child(deferred("dormant"))
                .compile()
                .unwrap()
                .bind_managed(
                    ["base", "dependent", "dormant"]
                        .into_iter()
                        .map(|name| {
                            ManagedChildBinding::new(
                                name,
                                ManagedRestartMode::Temporary,
                                TrackedFactory {
                                    starts: Arc::clone(&starts),
                                    retired: Arc::clone(&retired),
                                },
                            )
                        })
                        .collect(),
                    config(RestartPolicy::OneForOne, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                .unwrap();
            assert!(matches!(
                control.activate(&cx, "missing").await,
                Err(ManagedActivationError::UnknownChild { .. })
            ));
            assert!(matches!(control.activate(&cx, "dependent").await,
                Err(ManagedActivationError::DependencyUnavailable { child, dependency })
                    if child == "dependent" && dependency == "base"));
            assert_eq!(starts.load(Ordering::SeqCst), 0);
            assert_eq!(
                retired.load(Ordering::SeqCst),
                0,
                "dormant factories remain available"
            );
            let base = control.activate(&cx, "base").await.unwrap();
            let dependent = control.activate(&cx, "dependent").await.unwrap();
            assert_eq!((base.number, dependent.number), (1, 1));
            assert_ne!(base.region, dependent.region);
            assert_ne!(base.task, dependent.task);
            for generation in [base, dependent] {
                let finalized = Arc::clone(&finalized);
                assert!(
                    native.register_sync_finalizer_for_testing(generation.region, move || {
                        finalized.fetch_add(1, Ordering::SeqCst);
                    })
                );
            }
            assert!(matches!(
                control.activate(&cx, "base").await,
                Err(ManagedActivationError::AlreadyActivated { .. })
            ));
            assert_eq!(starts.load(Ordering::SeqCst), 2);
            supervisor.abort();
            let report = supervisor.join().await.unwrap();
            assert!(
                matches!(report.outcome, Outcome::Cancelled(_)),
                "{report:?}"
            );
            assert_eq!(
                (report.started, report.joined, report.children.len()),
                (2, 2, 2)
            );
            assert!(report.region_outcome.is_some());
            assert!(
                report
                    .children
                    .iter()
                    .all(|child| child.region_outcome.is_some())
            );
            assert_eq!(
                finalized.load(Ordering::SeqCst),
                2,
                "join includes real region finalizers"
            );
            assert_eq!(
                retired.load(Ordering::SeqCst),
                3,
                "shutdown retires the unused binding too"
            );
            assert!(matches!(
                control.activate(&cx, "dormant").await,
                Err(ManagedActivationError::Closed)
            ));
            assert!(
                cx.checkpoint().is_ok(),
                "abort is confined to the managed tree"
            );
        });
    }
}

#[test]
fn native_last_control_drop_preserves_live_children_and_legacy_deferred_retirement() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let (release, released) = oneshot::channel();
            let released = Arc::new(Mutex::new(Some(released)));
            let managed = SupervisorBuilder::new("controlled-last-client")
                .child(deferred("child"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "child",
                        ManagedRestartMode::Temporary,
                        move |cx: Cx, _: ManagedGeneration| {
                            let mut released = released.lock().take().unwrap();
                            async move {
                                released
                                    .recv(&cx)
                                    .await
                                    .expect("last control drop must not cancel child");
                                Outcome::<(), &'static str>::Ok(())
                            }
                        },
                    )],
                    config(RestartPolicy::OneForOne, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            control.activate(&cx, "child").await.unwrap();
            let clone = control.clone();
            drop(control);
            drop(clone);
            let mut joined = Box::pin(supervisor.join());
            poll_fn(|task| {
                assert!(
                    joined.as_mut().poll(task).is_pending(),
                    "live child still owns the tree"
                );
                Poll::Ready(())
            })
            .await;
            release.send_blocking(()).unwrap();
            let report = joined.await.unwrap();
            assert!(report.outcome.is_ok(), "{report:?}");
            assert_eq!((report.started, report.joined), (1, 1));

            for controlled in [false, true] {
                let starts = Arc::new(AtomicUsize::new(0));
                let retired = Arc::new(AtomicUsize::new(0));
                let managed = SupervisorBuilder::new("unused-deferred")
                    .child(deferred("unused"))
                    .compile()
                    .unwrap()
                    .bind_managed(
                        vec![ManagedChildBinding::new(
                            "unused",
                            ManagedRestartMode::Temporary,
                            TrackedFactory {
                                starts: Arc::clone(&starts),
                                retired: Arc::clone(&retired),
                            },
                        )],
                        config(RestartPolicy::OneForOne, 0),
                    )
                    .unwrap();
                let mut supervisor = if controlled {
                    let (handle, control) = managed
                        .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                        .unwrap();
                    // A completed request proves the native controller is idle
                    // before its last client disappears.
                    assert!(matches!(
                        control.activate(&cx, "missing").await,
                        Err(ManagedActivationError::UnknownChild { .. })
                    ));
                    assert_eq!(retired.load(Ordering::SeqCst), 0);
                    drop(control);
                    handle
                } else {
                    managed.spawn(&cx).unwrap()
                };
                let report = supervisor.join().await.unwrap();
                assert!(report.outcome.is_ok());
                assert_eq!((report.started, report.joined), (0, 0));
                assert_eq!(starts.load(Ordering::SeqCst), 0);
                assert_eq!(retired.load(Ordering::SeqCst), 1);
            }
        });
    }
}

#[test]
fn native_blocked_boot_bounds_mailbox_and_withdraws_unpolled_cancelled_requests() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let (entered, mut entry) = oneshot::channel();
            let entered = Arc::new(Mutex::new(Some(entered)));
            let (release, released) = std::sync::mpsc::sync_channel(1);
            let released = Arc::new(Mutex::new(released));
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let managed = SupervisorBuilder::new("controlled-bounded")
                .child(ChildSpec::new("boot", legacy_must_not_run))
                .child(deferred("lazy"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![
                        ManagedChildBinding::new(
                            "boot",
                            ManagedRestartMode::Temporary,
                            move |_: Cx, _: ManagedGeneration| {
                                // Hold actual first factory entry on one native
                                // worker; the other runs the caller and controller.
                                entered.lock().take().unwrap().send_blocking(()).unwrap();
                                released
                                    .lock()
                                    .recv_timeout(Duration::from_secs(10))
                                    .unwrap();
                                async { Outcome::<(), &'static str>::Ok(()) }
                            },
                        ),
                        ManagedChildBinding::new(
                            "lazy",
                            ManagedRestartMode::Temporary,
                            move |_: Cx, _: ManagedGeneration| {
                                observed.fetch_add(1, Ordering::SeqCst);
                                async { Outcome::<(), &'static str>::Ok(()) }
                            },
                        ),
                    ],
                    config(RestartPolicy::OneForOne, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                .unwrap();
            entry.recv(&cx).await.unwrap();
            let request_cx = cx.derive_cancel_scope();
            let mut dropped = Box::pin(control.activate(&cx, "lazy"));
            let mut cancelled = Box::pin(control.activate(&request_cx, "lazy"));
            poll_fn(|task| {
                assert!(dropped.as_mut().poll(task).is_pending());
                assert!(cancelled.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(matches!(
                control.activate(&cx, "lazy").await,
                Err(ManagedActivationError::Full)
            ));
            drop(dropped);
            request_cx.cancel_with(CancelKind::User, Some("withdraw queued activation"));
            // Do NOT repoll cancelled yet: only the controller can observe
            // this cancellation while the response future is suspended.
            release.send(()).unwrap();
            loop {
                match control.activate(&cx, "missing").await {
                    Err(ManagedActivationError::Full) => crate::runtime::yield_now().await,
                    Err(ManagedActivationError::UnknownChild { .. }) => break,
                    other => panic!("unexpected control barrier result: {other:?}"),
                }
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "neither withdrawn request entered its factory"
            );
            assert!(matches!(
                cancelled.await,
                Err(ManagedActivationError::Cancelled {
                    may_have_started: false,
                    ..
                })
            ));
            assert!(matches!(
                control.activate(&cx, "boot").await,
                Err(ManagedActivationError::NotDeferred { .. })
            ));
            assert_eq!(control.activate(&cx, "lazy").await.unwrap().number, 1);
            drop(control);
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_ok(), "{report:?}");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!((report.started, report.joined), (2, 2));
        });
    }
}

#[test]
fn native_claimed_activation_survives_caller_cancel_and_parent_drain_waits_for_cleanup() {
    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let parent = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let (entered, mut entry) = oneshot::channel();
            let (cleaning, mut cleanup) = oneshot::channel();
            let (finish_cleanup, cleanup_gate) = oneshot::channel();
            let (release_factory, factory_gate) = std::sync::mpsc::sync_channel(1);
            let factory_gate = Arc::new(Mutex::new(factory_gate));
            let setup = Arc::new(Mutex::new(Some((entered, cleaning, cleanup_gate))));
            let finalized = Arc::new(AtomicUsize::new(0));
            let managed = SupervisorBuilder::new("controlled-claimed")
                .child(deferred("lazy"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "lazy",
                        ManagedRestartMode::Temporary,
                        move |cx: Cx, generation: ManagedGeneration| {
                            let (entered, cleaning, mut cleanup_gate) =
                                setup.lock().take().unwrap();
                            entered.send_blocking(generation).unwrap();
                            factory_gate
                                .lock()
                                .recv_timeout(Duration::from_secs(10))
                                .unwrap();
                            async move {
                                let outcome = until_cancelled(&cx).await;
                                cleaning.send_blocking(()).unwrap();
                                cleanup_gate.recv_uninterruptible().await.unwrap();
                                outcome
                            }
                        },
                    )],
                    config(RestartPolicy::OneForOne, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(parent.cx(), NonZeroUsize::new(1).unwrap())
                .unwrap();
            let request_cx = cx.derive_cancel_scope();
            let mut activation = Box::pin(control.activate(&request_cx, "lazy"));
            poll_fn(|task| {
                assert!(activation.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            let generation = entry.recv(&cx).await.unwrap();
            let finalizer = Arc::clone(&finalized);
            assert!(
                native.register_sync_finalizer_for_testing(generation.region, move || {
                    finalizer.fetch_add(1, Ordering::SeqCst);
                })
            );
            request_cx.cancel_with(CancelKind::User, Some("stop observing claimed activation"));
            assert!(matches!(
                activation.await,
                Err(ManagedActivationError::Cancelled {
                    may_have_started: true,
                    ..
                })
            ));
            parent
                .cancel(CancelReason::user("parent shutdown"))
                .unwrap();
            release_factory.send(()).unwrap();
            cleanup.recv(&cx).await.unwrap();
            let mut joined = Box::pin(supervisor.join());
            poll_fn(|task| {
                assert!(
                    joined.as_mut().poll(task).is_pending(),
                    "cleanup is still held"
                );
                Poll::Ready(())
            })
            .await;
            assert_eq!(finalized.load(Ordering::SeqCst), 0);
            finish_cleanup.send_blocking(()).unwrap();
            let report = joined.await.unwrap();
            assert!(
                matches!(report.outcome, Outcome::Cancelled(_)),
                "{report:?}"
            );
            assert_eq!((report.started, report.joined), (1, 1));
            assert_eq!(report.children[0].generation, generation);
            assert_eq!(finalized.load(Ordering::SeqCst), 1);
            assert!(matches!(
                control.activate(&cx, "lazy").await,
                Err(ManagedActivationError::Closed)
            ));
            parent.close().await.unwrap();
            assert!(
                cx.checkpoint().is_ok(),
                "parent subtree cancellation stays scoped"
            );
        });
    }
}

#[test]
fn native_activated_children_share_restart_policy_and_intensity_while_dormant_stay_out() {
    for sharded in [false, true] {
        for policy in [
            RestartPolicy::OneForOne,
            RestartPolicy::OneForAll,
            RestartPolicy::RestForOne,
        ] {
            native_case(sharded, move |cx, native| async move {
                let parent = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let (first_failure, first_gate) = oneshot::channel();
                let (second_failure, second_gate) = oneshot::channel();
                let gates = Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate])));
                let (started, mut starts) = mpsc::channel(8);
                let trigger_starts = started.clone();
                let active_starts = started.clone();
                let trigger_finalized = Arc::new(AtomicUsize::new(0));
                let active_finalized = Arc::new(AtomicUsize::new(0));
                let observed_trigger = Arc::clone(&trigger_finalized);
                let observed_active = Arc::clone(&active_finalized);
                let dormant = Arc::new(AtomicUsize::new(0));
                let dormant_calls = Arc::clone(&dormant);
                let managed = SupervisorBuilder::new("controlled-restarts")
                    .with_restart_policy(policy)
                    .child(ChildSpec::new("trigger", legacy_must_not_run))
                    .child(deferred("active").depends_on("trigger"))
                    .child(deferred("dormant"))
                    .compile()
                    .unwrap()
                    .bind_managed(
                        vec![
                            ManagedChildBinding::new(
                                "trigger",
                                ManagedRestartMode::Transient,
                                move |cx: Cx, generation: ManagedGeneration| {
                                    if generation.number > 1 {
                                        assert_eq!(observed_trigger.load(Ordering::SeqCst), 1);
                                    }
                                    let mut gate = gates
                                        .lock()
                                        .pop_front()
                                        .expect("restart intensity bounds generations");
                                    trigger_starts.try_send(("trigger", generation)).unwrap();
                                    async move {
                                        gate.recv(&cx).await.unwrap();
                                        Outcome::Err("restart trigger")
                                    }
                                },
                            ),
                            ManagedChildBinding::new(
                                "active",
                                ManagedRestartMode::Transient,
                                move |cx: Cx, generation: ManagedGeneration| {
                                    if generation.number > 1 {
                                        assert_eq!(
                                            observed_active.load(Ordering::SeqCst),
                                            1,
                                            "old activated generation finalized before replacement"
                                        );
                                    }
                                    active_starts.try_send(("active", generation)).unwrap();
                                    async move { until_cancelled(&cx).await }
                                },
                            ),
                            ManagedChildBinding::new(
                                "dormant",
                                ManagedRestartMode::Permanent,
                                move |_: Cx, _: ManagedGeneration| {
                                    dormant_calls.fetch_add(1, Ordering::SeqCst);
                                    async { Outcome::<(), &'static str>::Ok(()) }
                                },
                            ),
                        ],
                        config(policy, 1).with_escalation(EscalationPolicy::Escalate),
                    )
                    .unwrap();
                let (mut supervisor, control) = managed
                    .spawn_controlled(parent.cx(), NonZeroUsize::new(2).unwrap())
                    .unwrap();
                let active = control.activate(&cx, "active").await.unwrap();
                let mut trigger = None;
                for _ in 0..2 {
                    let (name, generation) = starts.recv(&cx).await.unwrap();
                    if name == "trigger" {
                        trigger = Some(generation);
                    }
                }
                for (generation, finalized) in [
                    (trigger.unwrap(), Arc::clone(&trigger_finalized)),
                    (active, Arc::clone(&active_finalized)),
                ] {
                    assert!(native.register_sync_finalizer_for_testing(
                        generation.region,
                        move || {
                            finalized.fetch_add(1, Ordering::SeqCst);
                        }
                    ));
                }
                first_failure.send_blocking(()).unwrap();
                let replacement_count = if policy == RestartPolicy::OneForOne {
                    1
                } else {
                    2
                };
                for _ in 0..replacement_count {
                    let (name, generation) = starts.recv(&cx).await.unwrap();
                    assert_eq!(generation.number, 2);
                    assert!(name == "trigger" || name == "active");
                    if policy == RestartPolicy::OneForOne {
                        assert_eq!(name, "trigger");
                    }
                }
                assert_eq!(
                    dormant.load(Ordering::SeqCst),
                    0,
                    "sibling restart does not activate a dormant binding"
                );
                second_failure.send_blocking(()).unwrap();
                let report = supervisor.join().await.unwrap();
                assert!(
                    matches!(
                        report.outcome,
                        Outcome::Err(ManagedSupervisorError::RestartLimit { .. })
                    ),
                    "{report:?}"
                );
                assert_eq!(report.restart_batches, 1);
                assert_eq!(report.escalations, 1);
                assert_eq!(report.started, 2 + replacement_count);
                assert_eq!(report.started, report.joined);
                assert_eq!(report.children.len(), 2);
                assert_eq!(active_finalized.load(Ordering::SeqCst), 1);
                assert_eq!(dormant.load(Ordering::SeqCst), 0);
                parent.close().await.unwrap();
                assert!(
                    cx.checkpoint().is_ok(),
                    "restart escalation targets the supervisor's parent region"
                );
            });
        }
    }
}

#[test]
fn native_idle_controlled_supervisor_observes_its_region_deadline() {
    native_case(false, |cx, _| async move {
        let deadline = cx.now().saturating_add_nanos(50_000_000);
        let managed = SupervisorBuilder::new("controlled-idle-deadline")
            .with_budget(Budget::INFINITE.with_deadline(deadline))
            .child(deferred("unused"))
            .compile()
            .unwrap()
            .bind_managed(
                vec![ManagedChildBinding::new(
                    "unused",
                    ManagedRestartMode::Temporary,
                    |_: Cx, _: ManagedGeneration| async {
                        panic!("deadline must not activate deferred work");
                        #[allow(unreachable_code)]
                        Outcome::<(), &'static str>::Ok(())
                    },
                )],
                config(RestartPolicy::OneForOne, 0),
            )
            .unwrap();
        let (mut supervisor, control) = managed
            .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
            .unwrap();
        let report = supervisor.join().await.unwrap();
        assert!(
            matches!(report.outcome, Outcome::Cancelled(ref reason) if reason.kind == CancelKind::Deadline),
            "{report:?}"
        );
        assert_eq!((report.started, report.joined), (0, 0));
        assert!(matches!(
            control.activate(&cx, "unused").await,
            Err(ManagedActivationError::Closed)
        ));
    });
}

#[test]
fn native_stop_child_fences_identity_dependencies_and_permanent_retirement() {
    for sharded in [false, true] {
        for policy in [
            RestartPolicy::OneForOne,
            RestartPolicy::OneForAll,
            RestartPolicy::RestForOne,
        ] {
            native_case(sharded, move |cx, native| async move {
                let starts = Arc::new(AtomicUsize::new(0));
                let retired = Arc::new(AtomicUsize::new(0));
                let finalized = Arc::new(AtomicUsize::new(0));
                let managed = SupervisorBuilder::new("controlled-stop")
                    .with_restart_policy(policy)
                    .child(deferred("base"))
                    .child(deferred("dependent").depends_on("base"))
                    .child(deferred("peer"))
                    .child(deferred("dormant"))
                    .compile()
                    .unwrap()
                    .bind_managed(
                        ["base", "dependent", "peer", "dormant"]
                            .into_iter()
                            .map(|name| {
                                ManagedChildBinding::new(
                                    name,
                                    ManagedRestartMode::Permanent,
                                    TrackedFactory {
                                        starts: Arc::clone(&starts),
                                        retired: Arc::clone(&retired),
                                    },
                                )
                            })
                            .collect(),
                        config(policy, 0),
                    )
                    .unwrap();
                let (mut supervisor, control) = managed
                    .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                    .unwrap();
                let base = control.activate(&cx, "base").await.unwrap();
                let dependent = control.activate(&cx, "dependent").await.unwrap();
                let peer = control.activate(&cx, "peer").await.unwrap();
                for generation in [base, dependent, peer] {
                    let finalized = Arc::clone(&finalized);
                    assert!(
                        native.register_sync_finalizer_for_testing(generation.region, move || {
                            finalized.fetch_add(1, Ordering::SeqCst);
                        })
                    );
                }
                assert!(matches!(
                    control.stop_child(&cx, "missing", base).await,
                    Err(ManagedChildControlError::UnknownChild { .. })
                ));
                assert!(matches!(
                    control.stop_child(&cx, "dormant", base).await,
                    Err(ManagedChildControlError::NotRunning { .. })
                ));
                assert!(matches!(
                    control.stop_child(&cx, "peer", base).await,
                    Err(ManagedChildControlError::StaleGeneration { expected, actual, .. })
                        if expected == base && actual == peer
                ));
                assert!(matches!(
                    control.stop_child(&cx, "base", base).await,
                    Err(ManagedChildControlError::DependencyInUse { child, dependent })
                        if child == "base" && dependent == "dependent"
                ));
                assert_eq!(retired.load(Ordering::SeqCst), 0);
                assert_eq!(finalized.load(Ordering::SeqCst), 0);
                assert_eq!(
                    control.stop_child(&cx, "dependent", dependent).await.unwrap(),
                    dependent
                );
                assert_eq!(retired.load(Ordering::SeqCst), 1);
                assert_eq!(finalized.load(Ordering::SeqCst), 1);
                assert!(matches!(
                    control.stop_child(&cx, "dependent", dependent).await,
                    Err(ManagedChildControlError::NotRunning { .. })
                ));
                assert!(matches!(
                    control.activate(&cx, "dependent").await,
                    Err(ManagedActivationError::AlreadyActivated { .. })
                ));
                assert_eq!(control.stop_child(&cx, "base", base).await.unwrap(), base);
                assert_eq!(control.stop_child(&cx, "peer", peer).await.unwrap(), peer);
                assert_eq!(finalized.load(Ordering::SeqCst), 3);
                assert_eq!(starts.load(Ordering::SeqCst), 3);
                assert_eq!(retired.load(Ordering::SeqCst), 3);
                supervisor.abort();
                let report = supervisor.join().await.unwrap();
                assert_eq!((report.started, report.joined, report.restart_batches), (3, 3, 0));
                assert_eq!(report.escalations, 0);
                assert_eq!(retired.load(Ordering::SeqCst), 4, "retired exactly once");
                assert!(report.children.iter().all(|child| child.region_outcome.is_some()));
                assert!(matches!(
                    control.stop_child(&cx, "peer", peer).await,
                    Err(ManagedChildControlError::Closed)
                ));
                assert!(cx.checkpoint().is_ok(), "individual stops do not escalate");
            });
        }
    }
}

#[test]
fn native_queued_stop_shares_capacity_and_can_be_withdrawn_without_repolling() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let (entered, mut entry) = oneshot::channel();
            let entered = Arc::new(Mutex::new(Some(entered)));
            let (release, released) = std::sync::mpsc::sync_channel(1);
            let released = Arc::new(Mutex::new(released));
            let managed = SupervisorBuilder::new("controlled-stop-queued")
                .with_restart_policy(RestartPolicy::OneForAll)
                .child(deferred("target"))
                .child(deferred("blocker"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![
                        ManagedChildBinding::new(
                            "target",
                            ManagedRestartMode::Permanent,
                            TrackedFactory {
                                starts: Arc::clone(&starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                        ManagedChildBinding::new(
                            "blocker",
                            ManagedRestartMode::Temporary,
                            move |child: Cx, _: ManagedGeneration| {
                                entered.lock().take().unwrap().send_blocking(()).unwrap();
                                released.lock().recv_timeout(Duration::from_secs(10)).unwrap();
                                async move { until_cancelled(&child).await }
                            },
                        ),
                    ],
                    config(RestartPolicy::OneForAll, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                .unwrap();
            let generation = control.activate(&cx, "target").await.unwrap();
            let mut activation = Box::pin(control.activate(&cx, "blocker"));
            poll_fn(|task| {
                assert!(activation.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            entry.recv(&cx).await.unwrap();
            let request_cx = cx.derive_cancel_scope();
            let mut dropped = Box::pin(control.stop_child(&cx, "target", generation));
            let mut cancelled = Box::pin(control.stop_child(&request_cx, "target", generation));
            poll_fn(|task| {
                assert!(dropped.as_mut().poll(task).is_pending());
                assert!(cancelled.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(matches!(
                control.stop_child(&cx, "target", generation).await,
                Err(ManagedChildControlError::Full)
            ));
            assert!(matches!(
                control.activate(&cx, "missing").await,
                Err(ManagedActivationError::Full)
            ));
            drop(dropped);
            request_cx.cancel_with(CancelKind::User, Some("withdraw queued stop"));
            release.send(()).unwrap();
            activation.await.unwrap();
            loop {
                match control.activate(&cx, "missing").await {
                    Err(ManagedActivationError::Full) => crate::runtime::yield_now().await,
                    Err(ManagedActivationError::UnknownChild { .. }) => break,
                    other => panic!("unexpected control barrier: {other:?}"),
                }
            }
            assert_eq!(retired.load(Ordering::SeqCst), 0, "neither request stopped target");
            assert!(matches!(
                cancelled.await,
                Err(ManagedChildControlError::Cancelled { may_have_applied: false, .. })
            ));
            assert_eq!(
                control.stop_child(&cx, "target", generation).await.unwrap(),
                generation
            );
            assert_eq!(starts.load(Ordering::SeqCst), 1);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            supervisor.abort();
            let report = supervisor.join().await.unwrap();
            assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 0));
        });
    }
}

#[test]
fn native_claimed_stop_retains_name_until_descendants_and_finalizers_drain() {
    for sharded in [false, true] {
        for cancel_request in [false, true] {
            native_case(sharded, move |cx, native| async move {
                let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let registry = Arc::new(Mutex::new(crate::cx::registry::NameRegistry::new()));
                let (ready, mut started) = oneshot::channel();
                let (cleaning, mut cleanup) = oneshot::channel();
                let (finish_cleanup, cleanup_gate) = oneshot::channel();
                let setup = Arc::new(Mutex::new(Some((ready, cleaning, cleanup_gate))));
                let finalized = Arc::new(AtomicUsize::new(0));
                let managed = SupervisorBuilder::new("controlled-stop-cleanup")
                    .child(deferred("worker").with_registration(NameRegistrationPolicy::Register {
                        name: "stopping-service".into(),
                        collision: NameCollisionPolicy::Fail,
                    }))
                    .compile()
                    .unwrap()
                    .bind_managed_with_registry(
                        vec![ManagedChildBinding::new(
                            "worker",
                            ManagedRestartMode::Permanent,
                            move |child: Cx, _: ManagedGeneration| {
                                let (ready, cleaning, mut cleanup_gate) = setup.lock().take().unwrap();
                                async move {
                                    let (parked, mut parked_child) = oneshot::channel();
                                    let descendant = child.spawn(move |descendant| async move {
                                        let (_sender, mut receiver) = mpsc::channel::<()>(1);
                                        let mut receive = Box::pin(receiver.recv(&descendant));
                                        let mut parked = Some(parked);
                                        assert!(matches!(
                                            poll_fn(|task| {
                                                let result = receive.as_mut().poll(task);
                                                if result.is_pending() {
                                                    if let Some(parked) = parked.take() {
                                                        parked.send_blocking(()).unwrap();
                                                    }
                                                }
                                                result
                                            }).await,
                                            Err(mpsc::RecvError::Cancelled)
                                        ));
                                        cleaning.send_blocking(()).unwrap();
                                        cleanup_gate.recv_uninterruptible().await.unwrap();
                                    }).unwrap();
                                    parked_child.recv(&child).await.unwrap();
                                    ready.send_blocking(()).unwrap();
                                    let outcome = until_cancelled(&child).await;
                                    drop(descendant);
                                    outcome
                                }
                            },
                        )],
                        config(RestartPolicy::OneForOne, 0),
                        Arc::clone(&registry),
                    )
                    .unwrap();
                let (mut supervisor, control) = managed
                    .spawn_controlled(parent.cx(), NonZeroUsize::new(1).unwrap())
                    .unwrap();
                let generation = control.activate(&cx, "worker").await.unwrap();
                started.recv(&cx).await.unwrap();
                let finalizer = Arc::clone(&finalized);
                assert!(
                    native.register_sync_finalizer_for_testing(generation.region, move || {
                        finalizer.fetch_add(1, Ordering::SeqCst);
                    })
                );
                let request_cx = cx.derive_cancel_scope();
                let mut stopped = Box::pin(control.stop_child(&request_cx, "worker", generation));
                poll_fn(|task| {
                    assert!(stopped.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                cleanup.recv(&cx).await.unwrap();
                poll_fn(|task| {
                    assert!(stopped.as_mut().poll(task).is_pending(), "descendant still owns cleanup");
                    Poll::Ready(())
                })
                .await;
                assert_eq!(registry.lock().whereis("stopping-service"), Some(generation.task));
                assert_eq!(finalized.load(Ordering::SeqCst), 0);
                let report = if cancel_request {
                    request_cx.cancel_with(CancelKind::User, Some("stop observing claimed stop"));
                    assert!(matches!(
                        stopped.await,
                        Err(ManagedChildControlError::Cancelled { may_have_applied: true, .. })
                    ));
                    parent.cancel(CancelReason::user("shutdown while individual stop drains")).unwrap();
                    let mut joined = Box::pin(supervisor.join());
                    poll_fn(|task| {
                        assert!(joined.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(registry.lock().whereis("stopping-service"), Some(generation.task));
                    finish_cleanup.send_blocking(()).unwrap();
                    joined.await.unwrap()
                } else {
                    let mut retry = Box::pin(control.stop_child(&cx, "worker", generation));
                    poll_fn(|task| {
                        assert!(retry.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    finish_cleanup.send_blocking(()).unwrap();
                    assert_eq!(stopped.await.unwrap(), generation);
                    assert!(matches!(
                        retry.await,
                        Err(ManagedChildControlError::NotRunning { .. })
                    ));
                    assert!(registry.lock().is_empty(), "receipt includes name release");
                    assert_eq!(finalized.load(Ordering::SeqCst), 1);
                    supervisor.abort();
                    supervisor.join().await.unwrap()
                };
                assert!(matches!(report.outcome, Outcome::Cancelled(_)), "{report:?}");
                assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
                assert_eq!(report.children[0].generation, generation);
                assert!(report.children[0].region_outcome.is_some());
                assert!(registry.lock().is_empty());
                assert_eq!(finalized.load(Ordering::SeqCst), 1);
                parent.close().await.unwrap();
                assert!(cx.checkpoint().is_ok());
            });
        }
    }
}

#[test]
fn native_stop_checks_transitive_dependents_after_intermediate_retirement() {
    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let (release_middle, middle_gate) = oneshot::channel();
            let middle_gate = Arc::new(Mutex::new(Some(middle_gate)));
            let managed = SupervisorBuilder::new("controlled-transitive-stop")
                .child(deferred("base"))
                .child(deferred("middle").depends_on("base"))
                .child(deferred("leaf").depends_on("middle"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![
                        ManagedChildBinding::new(
                            "base",
                            ManagedRestartMode::Permanent,
                            TrackedFactory {
                                starts: Arc::clone(&starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                        ManagedChildBinding::new(
                            "middle",
                            ManagedRestartMode::Temporary,
                            move |child: Cx, _: ManagedGeneration| {
                                let mut gate = middle_gate.lock().take().unwrap();
                                async move {
                                    gate.recv(&child).await.unwrap();
                                    Outcome::<(), &'static str>::Ok(())
                                }
                            },
                        ),
                        ManagedChildBinding::new(
                            "leaf",
                            ManagedRestartMode::Permanent,
                            TrackedFactory {
                                starts: Arc::clone(&starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                    ],
                    config(RestartPolicy::OneForOne, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            let base = control.activate(&cx, "base").await.unwrap();
            let middle = control.activate(&cx, "middle").await.unwrap();
            let leaf = control.activate(&cx, "leaf").await.unwrap();
            let (finalized, mut middle_closed) = oneshot::channel();
            assert!(
                native.register_sync_finalizer_for_testing(middle.region, move || {
                    finalized.send_blocking(()).unwrap();
                })
            );
            release_middle.send_blocking(()).unwrap();
            middle_closed.recv(&cx).await.unwrap();
            assert!(matches!(
                control.stop_child(&cx, "middle", middle).await,
                Err(ManagedChildControlError::NotRunning { .. })
            ));
            assert!(matches!(
                control.stop_child(&cx, "base", base).await,
                Err(ManagedChildControlError::DependencyInUse { dependent, .. })
                    if dependent == "leaf"
            ));
            assert_eq!(control.stop_child(&cx, "leaf", leaf).await.unwrap(), leaf);
            assert_eq!(control.stop_child(&cx, "base", base).await.unwrap(), base);
            drop(control);
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_ok(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (3, 3, 0));
            assert_eq!(retired.load(Ordering::SeqCst), 2);
        });
    }
}

#[test]
fn native_failed_stop_preserves_cleanup_failure_and_retires_factory_once() {
    struct RetirementFailure {
        retired: Arc<AtomicUsize>,
        panic_on_retirement: bool,
    }

    impl ManagedChildFactory<&'static str> for RetirementFailure {
        fn start(&self, cx: Cx, _: ManagedGeneration) -> ManagedChildFuture<&'static str> {
            Box::pin(async move { until_cancelled(&cx).await })
        }

        fn retired(&self) {
            assert_eq!(self.retired.fetch_add(1, Ordering::SeqCst), 0);
            assert!(!self.panic_on_retirement, "individual stop retirement panic");
        }
    }

    for sharded in [false, true] {
        for fail_cleanup in [false, true] {
            native_case(sharded, move |cx, native| async move {
                let parent = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let retired = Arc::new(AtomicUsize::new(0));
                let finalized = Arc::new(AtomicUsize::new(0));
                let managed = SupervisorBuilder::new("controlled-stop-failure")
                    .with_restart_policy(RestartPolicy::OneForAll)
                    .child(deferred("worker"))
                    .compile()
                    .unwrap()
                    .bind_managed(
                        vec![ManagedChildBinding::new(
                            "worker",
                            ManagedRestartMode::Permanent,
                            RetirementFailure {
                                retired: Arc::clone(&retired),
                                panic_on_retirement: !fail_cleanup,
                            },
                        )],
                        config(RestartPolicy::OneForAll, 8),
                    )
                    .unwrap();
                let (mut supervisor, control) = managed
                    .spawn_controlled(parent.cx(), NonZeroUsize::new(1).unwrap())
                    .unwrap();
                let generation = control.activate(&cx, "worker").await.unwrap();
                let finalizer = Arc::clone(&finalized);
                assert!(
                    native.register_sync_finalizer_for_testing(generation.region, move || {
                        finalizer.fetch_add(1, Ordering::SeqCst);
                        assert!(!fail_cleanup, "individual stop finalizer panic");
                    })
                );
                assert!(matches!(
                    control.stop_child(&cx, "worker", generation).await,
                    Err(ManagedChildControlError::StopFailed { .. })
                ));
                let report = supervisor.join().await.unwrap();
                assert!(report.outcome.is_panicked(), "{report:?}");
                assert_eq!(
                    (report.started, report.joined, report.restart_batches),
                    (1, 1, 0)
                );
                assert_eq!(report.escalations, u8::from(fail_cleanup));
                assert_eq!(report.children[0].generation, generation);
                assert!(report.children[0].region_outcome.is_some());
                assert_eq!(
                    report.children[0]
                        .cleanup_outcome
                        .as_ref()
                        .is_some_and(Outcome::is_panicked),
                    fail_cleanup
                );
                assert_eq!(finalized.load(Ordering::SeqCst), 1);
                assert_eq!(retired.load(Ordering::SeqCst), 1);
                assert!(matches!(
                    control.activate(&cx, "worker").await,
                    Err(ManagedActivationError::Closed)
                ));
                parent.close().await.unwrap();
                assert!(cx.checkpoint().is_ok(), "failure stays in the owned subtree");
            });
        }
    }
}

#[test]
fn native_requested_restart_reuses_policy_order_names_and_generation_fences() {
    for sharded in [false, true] {
        for policy in [
            RestartPolicy::OneForOne,
            RestartPolicy::OneForAll,
            RestartPolicy::RestForOne,
        ] {
            native_case(sharded, move |cx, native| async move {
                let registry = Arc::new(Mutex::new(crate::cx::registry::NameRegistry::new()));
                let log = Arc::new(Mutex::new(Vec::<(&'static str, ManagedGeneration)>::new()));
                let finalized = Arc::new(AtomicUsize::new(0));
                let expected_drained = match policy {
                    RestartPolicy::OneForOne => 1,
                    RestartPolicy::OneForAll => 4,
                    RestartPolicy::RestForOne => 3,
                };
                let (peer_finalized, peer_gate) = oneshot::channel::<()>();
                let peer_gate = Arc::new(Mutex::new(Some(peer_gate)));
                let (ready, mut readiness) = mpsc::channel::<(&'static str, u64)>(16);
                let mut builder = SupervisorBuilder::new("controlled-requested-restart")
                    .with_restart_policy(policy);
                let mut bindings = Vec::new();
                for name in ["first", "middle", "last", "temporary", "dormant"] {
                    let registration = format!("restart-{name}");
                    let mut spec = deferred(name).with_registration(NameRegistrationPolicy::Register {
                        name: registration.clone(),
                        collision: NameCollisionPolicy::Fail,
                    });
                    if name == "middle" {
                        spec = spec.depends_on("first");
                    } else if name == "last" {
                        spec = spec.depends_on("middle");
                    }
                    builder = builder.child(spec);
                    let mode = match name {
                        "middle" => ManagedRestartMode::Transient,
                        "temporary" => ManagedRestartMode::Temporary,
                        _ => ManagedRestartMode::Permanent,
                    };
                    let log = Arc::clone(&log);
                    let registry = Arc::clone(&registry);
                    let finalized = Arc::clone(&finalized);
                    let peer_gate = Arc::clone(&peer_gate);
                    let ready = ready.clone();
                    bindings.push(ManagedChildBinding::new(
                        name,
                        mode,
                        move |child: Cx, generation: ManagedGeneration| {
                            assert_eq!(registry.lock().whereis(&registration), Some(generation.task));
                            if generation.number > 1 {
                                assert_eq!(
                                    finalized.load(Ordering::SeqCst),
                                    expected_drained,
                                    "all selected old regions close before any factory restarts"
                                );
                            }
                            log.lock().push((name, generation));
                            let gate = if name == "middle"
                                && generation.number == 1
                                && policy != RestartPolicy::OneForOne
                            {
                                Some(peer_gate.lock().take().unwrap())
                            } else {
                                None
                            };
                            let ready = ready.clone();
                            async move {
                                let mut cancelled = Box::pin(until_cancelled(&child));
                                let mut witnessed = false;
                                let outcome = poll_fn(|task| {
                                    let result = cancelled.as_mut().poll(task);
                                    if result.is_pending() && !witnessed {
                                        witnessed = true;
                                        ready.try_send((name, generation.number)).unwrap();
                                    }
                                    result
                                })
                                .await;
                                if let Some(mut gate) = gate {
                                    // This is a real sibling REGION finalizer receipt.
                                    // Joining only the source before reverse drain deadlocks.
                                    gate.recv_uninterruptible().await.unwrap();
                                }
                                outcome
                            }
                        },
                    ));
                }
                let managed = builder
                    .compile()
                    .unwrap()
                    .bind_managed_with_registry(bindings, config(policy, 1), Arc::clone(&registry))
                    .unwrap();
                let (mut supervisor, control) = managed
                    .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                    .unwrap();
                let mut generations = Vec::new();
                let mut peer_finalized = Some(peer_finalized);
                for name in ["first", "middle", "last", "temporary"] {
                    let generation = control.activate(&cx, name).await.unwrap();
                    generations.push((name, generation));
                    let counter = Arc::clone(&finalized);
                    let peer = (name == "last").then(|| peer_finalized.take().unwrap());
                    assert!(
                        native.register_sync_finalizer_for_testing(generation.region, move || {
                            counter.fetch_add(1, Ordering::SeqCst);
                            if let Some(peer) = peer {
                                let _ = peer.send_blocking(());
                            }
                        })
                    );
                }
                let mut parked = Vec::new();
                for _ in 0..4 {
                    let (name, number) = readiness.recv(&cx).await.unwrap();
                    assert_eq!(number, 1);
                    parked.push(name);
                }
                parked.sort_unstable();
                assert_eq!(parked, vec!["first", "last", "middle", "temporary"]);
                let original = generations[1].1;
                assert!(matches!(
                    control.restart_child(&cx, "missing", original).await,
                    Err(ManagedChildControlError::UnknownChild { .. })
                ));
                assert!(matches!(
                    control.restart_child(&cx, "dormant", original).await,
                    Err(ManagedChildControlError::NotRunning { .. })
                ));
                assert!(matches!(
                    control.restart_child(&cx, "temporary", generations[3].1).await,
                    Err(ManagedChildControlError::RestartDisabled { .. })
                ));
                assert!(matches!(
                    control.restart_child(&cx, "middle", generations[0].1).await,
                    Err(ManagedChildControlError::StaleGeneration { .. })
                ));
                assert_eq!(finalized.load(Ordering::SeqCst), 0);
                let withdrawn = cx.derive_cancel_scope();
                withdrawn.cancel_with(CancelKind::User, Some("withdraw restart before admission"));
                assert!(matches!(
                    control.restart_child(&withdrawn, "middle", original).await,
                    Err(ManagedChildControlError::Cancelled { may_have_applied: false, .. })
                ));
                let replacement = control.restart_child(&cx, "middle", original).await.unwrap();
                assert_eq!(replacement.number, 2);
                assert_ne!(replacement.region, original.region);
                assert_ne!(replacement.task, original.task);
                assert_eq!(registry.lock().whereis("restart-middle"), Some(replacement.task));
                let expected = match policy {
                    RestartPolicy::OneForOne => vec!["middle"],
                    RestartPolicy::OneForAll => vec!["first", "middle", "last"],
                    RestartPolicy::RestForOne => vec!["middle", "last"],
                };
                let actual: Vec<_> = log
                    .lock()
                    .iter()
                    .filter(|(_, generation)| generation.number == 2)
                    .map(|(name, _)| *name)
                    .collect();
                assert_eq!(actual, expected);
                assert_eq!(finalized.load(Ordering::SeqCst), expected_drained);
                assert!(matches!(
                    control.restart_child(&cx, "middle", original).await,
                    Err(ManagedChildControlError::StaleGeneration { actual, .. })
                        if actual == replacement
                ));
                assert_eq!(log.lock().len(), 4 + expected.len(), "retry cannot replace successor");
                supervisor.abort();
                let report = supervisor.join().await.unwrap();
                assert_eq!(report.started, (4 + expected.len()) as u64);
                assert_eq!(report.joined, report.started);
                assert_eq!(report.restart_batches, 1);
                assert_eq!(report.escalations, 0);
                assert!(registry.lock().is_empty());
                assert!(matches!(
                    control.restart_child(&cx, "middle", replacement).await,
                    Err(ManagedChildControlError::Closed)
                ));
                assert!(cx.checkpoint().is_ok());
            });
        }
    }
}

#[test]
fn native_requested_restart_stop_refusal_drains_and_retires_selected_group() {
    for sharded in [false, true] {
        for policy in [
            RestartPolicy::OneForOne,
            RestartPolicy::OneForAll,
            RestartPolicy::RestForOne,
        ] {
            native_case(sharded, move |cx, native| async move {
                let starts = Arc::new(AtomicUsize::new(0));
                let retired = Arc::new(AtomicUsize::new(0));
                let finalized = Arc::new(AtomicUsize::new(0));
                let managed = SupervisorBuilder::new("controlled-restart-stop-refusal")
                    .with_restart_policy(policy)
                    .child(deferred("first"))
                    .child(deferred("middle"))
                    .child(deferred("last"))
                    .child(deferred("dormant"))
                    .compile()
                    .unwrap()
                    .bind_managed(
                        ["first", "middle", "last", "dormant"]
                            .into_iter()
                            .map(|name| {
                                ManagedChildBinding::new(
                                    name,
                                    ManagedRestartMode::Permanent,
                                    TrackedFactory {
                                        starts: Arc::clone(&starts),
                                        retired: Arc::clone(&retired),
                                    },
                                )
                            })
                            .collect(),
                        config(policy, 0).with_escalation(EscalationPolicy::Stop),
                    )
                    .unwrap();
                let (mut supervisor, control) = managed
                    .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                    .unwrap();
                let mut source = None;
                for name in ["first", "middle", "last"] {
                    let generation = control.activate(&cx, name).await.unwrap();
                    if name == "middle" {
                        source = Some(generation);
                    }
                    let finalized = Arc::clone(&finalized);
                    assert!(
                        native.register_sync_finalizer_for_testing(generation.region, move || {
                            finalized.fetch_add(1, Ordering::SeqCst);
                        })
                    );
                }
                let source = source.unwrap();
                assert!(matches!(
                    control.restart_child(&cx, "middle", source).await,
                    Err(ManagedChildControlError::RestartRefused {
                        refusal: BudgetRefusal::WindowExhausted { max_restarts: 0, .. },
                        ..
                    })
                ));
                let selected = match policy {
                    RestartPolicy::OneForOne => 1,
                    RestartPolicy::OneForAll => 3,
                    RestartPolicy::RestForOne => 2,
                };
                assert_eq!(finalized.load(Ordering::SeqCst), selected);
                assert_eq!(retired.load(Ordering::SeqCst), selected);
                assert!(matches!(
                    control.restart_child(&cx, "middle", source).await,
                    Err(ManagedChildControlError::NotRunning { .. })
                ));
                assert!(matches!(
                    control.activate(&cx, "missing").await,
                    Err(ManagedActivationError::UnknownChild { .. })
                ));
                assert_eq!(starts.load(Ordering::SeqCst), 3, "refused siblings cannot resurrect");
                control.activate(&cx, "dormant").await.unwrap();
                supervisor.abort();
                let report = supervisor.join().await.unwrap();
                assert_eq!((report.started, report.joined, report.restart_batches), (4, 4, 0));
                assert_eq!(report.escalations, 0);
                assert_eq!(retired.load(Ordering::SeqCst), 4);
                assert_eq!(finalized.load(Ordering::SeqCst), 3);
                assert!(cx.checkpoint().is_ok(), "Stop keeps parent authority live");
            });
        }
    }
}

#[test]
fn native_requested_restart_backoff_cancellation_keeps_cleanup_owned() {
    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let finalized = Arc::new(AtomicUsize::new(0));
            let managed = SupervisorBuilder::new("controlled-restart-backoff")
                .child(deferred("worker"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "worker",
                        ManagedRestartMode::Transient,
                        TrackedFactory {
                            starts: Arc::clone(&starts),
                            retired: Arc::clone(&retired),
                        },
                    )],
                    config(RestartPolicy::OneForOne, 8)
                        .with_backoff(BackoffStrategy::Fixed(Duration::from_secs(60))),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(parent.cx(), NonZeroUsize::new(1).unwrap())
                .unwrap();
            let generation = control.activate(&cx, "worker").await.unwrap();
            let finalizer = Arc::clone(&finalized);
            assert!(
                native.register_sync_finalizer_for_testing(generation.region, move || {
                    finalizer.fetch_add(1, Ordering::SeqCst);
                })
            );
            let timer = cx.timer_driver().expect("native runtime timer");
            let before = timer.pending_count();
            let request_cx = cx.derive_cancel_scope();
            let mut restart = Box::pin(control.restart_child(&request_cx, "worker", generation));
            poll_fn(|task| {
                assert!(restart.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            let witness_deadline = cx.now() + Duration::from_secs(5);
            while timer.pending_count() == before {
                assert!(cx.now() < witness_deadline, "backoff timer was not registered");
                crate::runtime::yield_now().await;
            }
            assert!(
                timer.next_deadline().unwrap() > cx.now() + Duration::from_secs(30),
                "the controller is parked on its actual 60-second backoff"
            );
            assert_eq!(finalized.load(Ordering::SeqCst), 1);
            assert_eq!(starts.load(Ordering::SeqCst), 1);
            request_cx.cancel_with(CancelKind::User, Some("stop observing owned restart backoff"));
            assert!(matches!(
                restart.await,
                Err(ManagedChildControlError::Cancelled { may_have_applied: true, .. })
            ));
            assert_eq!(retired.load(Ordering::SeqCst), 0, "caller cancellation does not retire controller work");
            parent.cancel(CancelReason::user("cancel actual restart backoff")).unwrap();
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_cancelled(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
            assert_eq!(starts.load(Ordering::SeqCst), 1, "parent cancellation forbids resurrection");
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), before, "backoff registration is withdrawn");
            parent.close().await.unwrap();
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn native_requested_restarts_consume_intensity_and_escalate_once() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let managed = SupervisorBuilder::new("controlled-restart-intensity")
                .child(deferred("worker"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "worker",
                        ManagedRestartMode::Transient,
                        TrackedFactory {
                            starts: Arc::clone(&starts),
                            retired: Arc::clone(&retired),
                        },
                    )],
                    config(RestartPolicy::OneForOne, 1)
                        .with_escalation(EscalationPolicy::Escalate),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(parent.cx(), NonZeroUsize::new(1).unwrap())
                .unwrap();
            let first = control.activate(&cx, "worker").await.unwrap();
            let second = control.restart_child(&cx, "worker", first).await.unwrap();
            assert!(matches!(
                control.restart_child(&cx, "worker", second).await,
                Err(ManagedChildControlError::RestartRefused {
                    refusal: BudgetRefusal::WindowExhausted { max_restarts: 1, .. },
                    ..
                })
            ));
            let report = supervisor.join().await.unwrap();
            assert!(matches!(
                report.outcome,
                Outcome::Err(ManagedSupervisorError::RestartLimit { .. })
            ));
            assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 1));
            assert_eq!(report.escalations, 1);
            assert_eq!(starts.load(Ordering::SeqCst), 2);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            parent.close().await.unwrap();
            assert!(cx.checkpoint().is_ok(), "escalation stays in the controller parent");
        });
    }
}

#[test]
fn native_requested_restart_uses_shared_allowance_and_refusal_fence() {
    use crate::cx::dynamic_supervisor::{SharedRestartConfig, SharedRestartDomain};

    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let domain = Arc::new(SharedRestartDomain::new(
                SharedRestartConfig::new(1, Duration::from_secs(60))
                    .with_backoff(BackoffStrategy::None),
            ));
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let mut managed = SupervisorBuilder::new("controlled-restart-shared")
                .child(deferred("worker"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "worker",
                        ManagedRestartMode::Transient,
                        TrackedFactory {
                            starts: Arc::clone(&starts),
                            retired: Arc::clone(&retired),
                        },
                    )],
                    config(RestartPolicy::OneForOne, 8),
                )
                .unwrap();
            managed.set_shared_restarts(Arc::clone(&domain));
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            let first = control.activate(&cx, "worker").await.unwrap();
            let second = control.restart_child(&cx, "worker", first).await.unwrap();
            assert_eq!(domain.status().admitted, 1);
            assert!(matches!(domain.admit(), RestartVerdict::Denied { .. }));
            assert!(matches!(
                control.restart_child(&cx, "worker", second).await,
                Err(ManagedChildControlError::Closed)
            ));
            let report = supervisor.join().await.unwrap();
            assert!(matches!(
                report.outcome,
                Outcome::Err(ManagedSupervisorError::SharedRestartLimit { .. })
            ));
            assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 1));
            assert_eq!(domain.status().admitted, 1, "no private manual-restart allowance");
            assert_eq!(starts.load(Ordering::SeqCst), 2);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn native_requested_restart_optional_dependency_skip_settles_without_replacement() {
    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let (release_base, base_gate) = oneshot::channel();
            let base_gate = Arc::new(Mutex::new(Some(base_gate)));
            let managed = SupervisorBuilder::new("controlled-restart-optional")
                .child(deferred("base"))
                .child(deferred("worker").depends_on("base").with_required(false))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![
                        ManagedChildBinding::new(
                            "base",
                            ManagedRestartMode::Temporary,
                            move |child: Cx, _: ManagedGeneration| {
                                let mut gate = base_gate.lock().take().unwrap();
                                async move {
                                    gate.recv(&child).await.unwrap();
                                    Outcome::<(), &'static str>::Ok(())
                                }
                            },
                        ),
                        ManagedChildBinding::new(
                            "worker",
                            ManagedRestartMode::Transient,
                            TrackedFactory {
                                starts: Arc::clone(&starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                    ],
                    config(RestartPolicy::OneForOne, 8),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            let base = control.activate(&cx, "base").await.unwrap();
            let worker = control.activate(&cx, "worker").await.unwrap();
            let (closed, mut base_closed) = oneshot::channel();
            assert!(
                native.register_sync_finalizer_for_testing(base.region, move || {
                    closed.send_blocking(()).unwrap();
                })
            );
            release_base.send_blocking(()).unwrap();
            base_closed.recv(&cx).await.unwrap();
            assert!(matches!(
                control.restart_child(&cx, "worker", worker).await,
                Err(ManagedChildControlError::RestartFailed { .. })
            ));
            assert_eq!(starts.load(Ordering::SeqCst), 1);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert!(matches!(
                control.activate(&cx, "missing").await,
                Err(ManagedActivationError::UnknownChild { .. })
            ));
            drop(control);
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_ok(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 0));
        });
    }
}

#[test]
fn native_requested_restart_cleanup_failure_settles_after_shutdown() {
    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let finalized = Arc::new(AtomicUsize::new(0));
            let managed = SupervisorBuilder::new("controlled-restart-cleanup-failure")
                .child(deferred("worker"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "worker",
                        ManagedRestartMode::Transient,
                        TrackedFactory {
                            starts: Arc::clone(&starts),
                            retired: Arc::clone(&retired),
                        },
                    )],
                    config(RestartPolicy::OneForOne, 8),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(parent.cx(), NonZeroUsize::new(1).unwrap())
                .unwrap();
            let worker = control.activate(&cx, "worker").await.unwrap();
            let finalizer = Arc::clone(&finalized);
            assert!(
                native.register_sync_finalizer_for_testing(worker.region, move || {
                    finalizer.fetch_add(1, Ordering::SeqCst);
                    panic!("requested restart cleanup failure");
                })
            );
            assert!(matches!(
                control.restart_child(&cx, "worker", worker).await,
                Err(ManagedChildControlError::RestartFailed { .. })
            ));
            assert_eq!(finalized.load(Ordering::SeqCst), 1);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_panicked(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
            assert_eq!(report.escalations, 1);
            assert!(matches!(report.children[0].cleanup_outcome, Some(Outcome::Panicked(_))));
            assert_eq!(starts.load(Ordering::SeqCst), 1);
            parent.close().await.unwrap();
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn native_requested_restart_retirement_panic_dominates_allowance_refusal() {
    struct RefusedRetirement {
        finalized: Arc<AtomicUsize>,
        retired: Arc<AtomicUsize>,
    }

    impl ManagedChildFactory<&'static str> for RefusedRetirement {
        fn start(&self, child: Cx, _: ManagedGeneration) -> ManagedChildFuture<&'static str> {
            Box::pin(async move { until_cancelled(&child).await })
        }

        fn retired(&self) {
            assert_eq!(self.finalized.load(Ordering::SeqCst), 1);
            assert_eq!(self.retired.fetch_add(1, Ordering::SeqCst), 0);
            panic!("retirement failed after requested restart refusal");
        }
    }

    for sharded in [false, true] {
        native_case(sharded, |cx, native| async move {
            let finalized = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let managed = SupervisorBuilder::new("controlled-restart-refused-retirement")
                .child(deferred("worker"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "worker",
                        ManagedRestartMode::Transient,
                        RefusedRetirement {
                            finalized: Arc::clone(&finalized),
                            retired: Arc::clone(&retired),
                        },
                    )],
                    config(RestartPolicy::OneForOne, 0)
                        .with_escalation(EscalationPolicy::Stop),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            let worker = control.activate(&cx, "worker").await.unwrap();
            let finalizer = Arc::clone(&finalized);
            assert!(
                native.register_sync_finalizer_for_testing(worker.region, move || {
                    finalizer.fetch_add(1, Ordering::SeqCst);
                })
            );
            assert!(matches!(
                control.restart_child(&cx, "worker", worker).await,
                Err(ManagedChildControlError::RestartFailed { .. })
            ));
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_panicked(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
            assert_eq!(report.escalations, 0);
            assert!(
                report.children[0].cleanup_outcome.as_ref().is_none_or(Outcome::is_ok),
                "the generation drained successfully before retirement failed"
            );
            assert_eq!(finalized.load(Ordering::SeqCst), 1);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert!(cx.checkpoint().is_ok());
        });
    }
}

fn owned_generation(children: &[ManagedChildInfo], name: &str) -> ManagedGeneration {
    let child = children.iter().find(|child| child.name == name).unwrap();
    match child.state {
        ManagedChildState::Active { generation } => generation,
        state => panic!("expected controller-owned generation for {name}: {state:?}"),
    }
}

#[test]
fn native_child_snapshot_tracks_initial_activated_replaced_and_retired_generations() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let (fail, failed) = oneshot::channel::<()>();
            let failed = Arc::new(Mutex::new(Some(failed)));
            let (restarted, mut replacement_started) = oneshot::channel::<()>();
            let restarted = Arc::new(Mutex::new(Some(restarted)));
            let managed = SupervisorBuilder::new("controlled-snapshot-lifecycle")
                .with_tie_break(StartTieBreak::NameLex)
                .child(ChildSpec::new("zeta", legacy_must_not_run).depends_on("base"))
                .child(ChildSpec::new("base", legacy_must_not_run))
                .child(deferred("alpha"))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![
                        ManagedChildBinding::new(
                            "zeta",
                            ManagedRestartMode::Transient,
                            move |child: Cx, generation: ManagedGeneration| {
                                let failure = if generation.number == 1 {
                                    Some(failed.lock().take().unwrap())
                                } else {
                                    restarted.lock().take().unwrap().send_blocking(()).unwrap();
                                    None
                                };
                                async move {
                                    if let Some(mut failure) = failure {
                                        failure.recv(&child).await.unwrap();
                                        Outcome::Err("replace zeta")
                                    } else {
                                        until_cancelled(&child).await
                                    }
                                }
                            },
                        ),
                        ManagedChildBinding::new(
                            "base",
                            ManagedRestartMode::Temporary,
                            |child: Cx, _: ManagedGeneration| async move {
                                until_cancelled(&child).await
                            },
                        ),
                        ManagedChildBinding::new(
                            "alpha",
                            ManagedRestartMode::Temporary,
                            |child: Cx, _: ManagedGeneration| async move {
                                until_cancelled(&child).await
                            },
                        ),
                    ],
                    config(RestartPolicy::OneForOne, 1),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(2).unwrap())
                .unwrap();
            // No factory publishes an identity: the control is sufficient to
            // discover initially eager children and later automatic replacements.
            let initial = control.which_children(&cx).await.unwrap();
            assert_eq!(
                initial.iter().map(|child| child.name.as_str()).collect::<Vec<_>>(),
                vec!["alpha", "base", "zeta"]
            );
            assert_eq!(initial[0].state, ManagedChildState::Dormant);
            assert_eq!(initial[2].restart_mode, ManagedRestartMode::Transient);
            let base = owned_generation(&initial, "base");
            let first = owned_generation(&initial, "zeta");
            assert_eq!((base.number, first.number), (1, 1));
            assert_eq!(control.which_children(&cx).await.unwrap(), initial);

            let alpha = control.activate(&cx, "alpha").await.unwrap();
            let activated = control.which_children(&cx).await.unwrap();
            assert_eq!(owned_generation(&activated, "alpha"), alpha);
            assert_eq!(owned_generation(&activated, "base"), base);
            assert_eq!(owned_generation(&activated, "zeta"), first);
            control.stop_child(&cx, "alpha", alpha).await.unwrap();
            let stopped = control.which_children(&cx).await.unwrap();
            assert_eq!(
                stopped[0].state,
                ManagedChildState::Retired { last_generation: Some(alpha) }
            );

            fail.send_blocking(()).unwrap();
            replacement_started.recv(&cx).await.unwrap();
            let replaced = control.which_children(&cx).await.unwrap();
            let second = owned_generation(&replaced, "zeta");
            assert_eq!(second.number, 2);
            assert_ne!(second.region, first.region);
            assert_ne!(second.task, first.task);
            assert_eq!(owned_generation(&replaced, "base"), base);
            assert!(matches!(
                control.stop_child(&cx, "zeta", first).await,
                Err(ManagedChildControlError::StaleGeneration { actual, .. })
                    if actual == second
            ));
            control.stop_child(&cx, "zeta", second).await.unwrap();
            control.stop_child(&cx, "base", base).await.unwrap();
            let retired = control.which_children(&cx).await.unwrap();
            for (child, generation) in retired.iter().zip([alpha, base, second]) {
                assert_eq!(
                    child.state,
                    ManagedChildState::Retired { last_generation: Some(generation) }
                );
            }
            supervisor.abort();
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_cancelled(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (4, 4, 1));
            assert!(matches!(control.which_children(&cx).await, Err(ManagedSnapshotError::Closed)));
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn native_child_snapshot_shares_bounded_queue_and_waits_for_claimed_restart() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let (cleaning, mut cleanup_parked) = oneshot::channel::<()>();
            let (release, cleanup) = oneshot::channel::<()>();
            let setup = Arc::new(Mutex::new(Some((cleaning, cleanup))));
            let managed = SupervisorBuilder::new("controlled-snapshot-queue")
                .child(ChildSpec::new("worker", legacy_must_not_run))
                .compile()
                .unwrap()
                .bind_managed(
                    vec![ManagedChildBinding::new(
                        "worker",
                        ManagedRestartMode::Transient,
                        move |child: Cx, generation: ManagedGeneration| {
                            let cleanup = if generation.number == 1 {
                                Some(setup.lock().take().unwrap())
                            } else {
                                None
                            };
                            async move {
                                let outcome = until_cancelled(&child).await;
                                if let Some((cleaning, mut cleanup)) = cleanup {
                                    let mut witness = Some(cleaning);
                                    let mut wait = std::pin::pin!(cleanup.recv_uninterruptible());
                                    poll_fn(|task| {
                                        let result = wait.as_mut().poll(task);
                                        if result.is_pending() {
                                            if let Some(witness) = witness.take() {
                                                witness.send_blocking(()).unwrap();
                                            }
                                        }
                                        result
                                    })
                                    .await
                                    .unwrap();
                                }
                                outcome
                            }
                        },
                    )],
                    config(RestartPolicy::OneForOne, 1),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(3).unwrap())
                .unwrap();
            let initial = control.which_children(&cx).await.unwrap();
            let first = owned_generation(&initial, "worker");
            let mut restart = Box::pin(control.restart_child(&cx, "worker", first));
            poll_fn(|task| {
                assert!(restart.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            cleanup_parked.recv(&cx).await.unwrap();

            let cancelled_cx = cx.derive_cancel_scope();
            let late_cx = cx.derive_cancel_scope();
            let mut dropped = Box::pin(control.which_children(&cx));
            let mut cancelled = Box::pin(control.which_children(&cancelled_cx));
            let mut committed = Box::pin(control.which_children(&late_cx));
            poll_fn(|task| {
                assert!(dropped.as_mut().poll(task).is_pending());
                assert!(cancelled.as_mut().poll(task).is_pending());
                assert!(committed.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(matches!(control.which_children(&cx).await, Err(ManagedSnapshotError::Full)));
            assert!(matches!(
                control.stop_child(&cx, "worker", first).await,
                Err(ManagedChildControlError::Full)
            ));
            drop(dropped);
            cancelled_cx.cancel_with(CancelKind::User, Some("withdraw queued snapshot"));
            // Withdrawals do not create a second unbounded queue. The controller
            // must dequeue their tombstones before capacity becomes available.
            assert!(matches!(control.which_children(&cx).await, Err(ManagedSnapshotError::Full)));
            release.send_blocking(()).unwrap();
            let second = restart.await.unwrap();
            assert_eq!(second.number, 2);

            // This FIFO barrier proves the last snapshot was committed without
            // repolling either caller future, after the replacement was admitted.
            loop {
                match control.activate(&cx, "missing").await {
                    Err(ManagedActivationError::Full) => crate::runtime::yield_now().await,
                    Err(ManagedActivationError::UnknownChild { .. }) => break,
                    other => panic!("unexpected snapshot barrier result: {other:?}"),
                }
            }
            late_cx.cancel_with(CancelKind::User, Some("cancel after snapshot commit"));
            let children = committed.await.unwrap();
            assert_eq!(children.len(), 1);
            assert_eq!(owned_generation(&children, "worker"), second);
            assert!(matches!(cancelled.await, Err(ManagedSnapshotError::Cancelled { .. })));
            assert_eq!(control.which_children(&cx).await.unwrap(), children);

            supervisor.abort();
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_cancelled(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 1));
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn native_child_snapshot_distinguishes_retirement_without_admission_from_dormancy() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let registry = Arc::new(Mutex::new(crate::cx::registry::NameRegistry::new()));
            let unavailable_starts = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let registration = NameRegistrationPolicy::Register {
                name: "snapshot-owned-name".to_owned(),
                collision: NameCollisionPolicy::Fail,
            };
            let managed = SupervisorBuilder::new("controlled-snapshot-unstarted")
                .child(
                    ChildSpec::new("base", legacy_must_not_run)
                        .with_registration(registration.clone()),
                )
                .child(
                    ChildSpec::new("blocked", legacy_must_not_run)
                        .depends_on("base")
                        .with_registration(registration)
                        .with_required(false),
                )
                .child(
                    ChildSpec::new("skipped", legacy_must_not_run)
                        .depends_on("blocked")
                        .with_required(false),
                )
                .child(deferred("dormant"))
                .compile()
                .unwrap()
                .bind_managed_with_registry(
                    vec![
                        ManagedChildBinding::new(
                            "base",
                            ManagedRestartMode::Temporary,
                            |child: Cx, _: ManagedGeneration| async move {
                                until_cancelled(&child).await
                            },
                        ),
                        ManagedChildBinding::new(
                            "blocked",
                            ManagedRestartMode::Temporary,
                            TrackedFactory {
                                starts: Arc::clone(&unavailable_starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                        ManagedChildBinding::new(
                            "skipped",
                            ManagedRestartMode::Temporary,
                            TrackedFactory {
                                starts: Arc::clone(&unavailable_starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                        ManagedChildBinding::new(
                            "dormant",
                            ManagedRestartMode::Temporary,
                            TrackedFactory {
                                starts: Arc::clone(&unavailable_starts),
                                retired: Arc::clone(&retired),
                            },
                        ),
                    ],
                    config(RestartPolicy::OneForOne, 0),
                    Arc::clone(&registry),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            let children = control.which_children(&cx).await.unwrap();
            assert_eq!(
                children.iter().map(|child| child.name.as_str()).collect::<Vec<_>>(),
                vec!["base", "blocked", "skipped", "dormant"]
            );
            let base = owned_generation(&children, "base");
            assert_eq!(registry.lock().whereis("snapshot-owned-name"), Some(base.task));
            assert!(matches!(
                children[1].state,
                ManagedChildState::Retired { last_generation: Some(generation) }
                    if generation.number == 1 && generation != base
            ));
            assert_eq!(
                children[2].state,
                ManagedChildState::Retired { last_generation: None }
            );
            assert_eq!(children[3].state, ManagedChildState::Dormant);
            assert_eq!(unavailable_starts.load(Ordering::SeqCst), 0);
            assert_eq!(retired.load(Ordering::SeqCst), 2);
            supervisor.abort();
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_cancelled(), "{report:?}");
            assert_eq!(report.restart_batches, 0);
            assert_eq!(unavailable_starts.load(Ordering::SeqCst), 0);
            assert_eq!(retired.load(Ordering::SeqCst), 3);
            assert!(registry.lock().is_empty());
        });
    }
}

#[test]
fn native_child_snapshot_empty_controller_preserves_cancel_and_closed_results() {
    for sharded in [false, true] {
        native_case(sharded, |cx, _| async move {
            let managed = SupervisorBuilder::new("controlled-snapshot-empty")
                .compile()
                .unwrap()
                .bind_managed(
                    Vec::<ManagedChildBinding<&'static str>>::new(),
                    config(RestartPolicy::OneForOne, 0),
                )
                .unwrap();
            let (mut supervisor, control) = managed
                .spawn_controlled(&cx, NonZeroUsize::new(1).unwrap())
                .unwrap();
            assert!(control.which_children(&cx).await.unwrap().is_empty());
            let cancelled = cx.derive_cancel_scope();
            cancelled.cancel_with(CancelKind::User, Some("cancel snapshot before queue"));
            assert!(matches!(
                control.which_children(&cancelled).await,
                Err(ManagedSnapshotError::Cancelled { .. })
            ));
            assert!(control.which_children(&cx).await.unwrap().is_empty());
            supervisor.abort();
            let report = supervisor.join().await.unwrap();
            assert!(report.outcome.is_cancelled(), "{report:?}");
            assert_eq!((report.started, report.joined, report.restart_batches), (0, 0, 0));
            assert!(matches!(control.which_children(&cx).await, Err(ManagedSnapshotError::Closed)));
            assert!(cx.checkpoint().is_ok());
        });
    }
}
