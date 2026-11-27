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
