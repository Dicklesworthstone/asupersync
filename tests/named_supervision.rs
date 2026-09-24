//! Executing named-supervisor journeys in the Lab and native runtimes.
//! Every observed identity belongs to a spawned task. Pending witnesses come
//! from channel receives that have registered their wakers, not self-wakes.

use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::registry::{NameLeaseError, NameRegistry};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::{RuntimeState, SpawnError};
use asupersync::supervision::{
    BackoffStrategy, ChildSpec, ManagedChildBinding, ManagedGeneration, ManagedRestartMode,
    ManagedSupervisor, ManagedSupervisorError, NameCollisionPolicy, NameRegistrationPolicy,
    SupervisionConfig, SupervisorBuilder,
};
use asupersync::types::{Budget, CancelReason, Outcome, TaskId, policy::FailFast};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

type Registry = Arc<Mutex<NameRegistry>>;

fn legacy(
    _: &Scope<'static, FailFast>,
    _: &mut RuntimeState,
    _: &Cx,
) -> Result<TaskId, SpawnError> {
    panic!("named managed children never invoke legacy start factories")
}

fn bind(
    registry: &Registry,
    collision: NameCollisionPolicy,
    binding: ManagedChildBinding<&'static str>,
) -> ManagedSupervisor<&'static str> {
    SupervisorBuilder::new("named-owner")
        .child(ChildSpec::new("worker", legacy).with_registration(
            NameRegistrationPolicy::Register {
                name: "service".into(),
                collision,
            },
        ))
        .compile()
        .unwrap()
        .bind_managed_with_registry(
            vec![binding],
            SupervisionConfig::new(1, Duration::from_secs(60)).with_backoff(BackoffStrategy::None),
            Arc::clone(registry),
        )
        .unwrap()
}

async fn witnessed<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
    let mut future = pin!(future);
    let mut signal = Some(signal);
    poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Pending => {
            if let Some(signal) = signal.take() {
                signal.send_blocking(()).unwrap();
            }
            Poll::Pending
        }
        ready => ready,
    })
    .await
}

async fn wait_for_waiters(cx: &Cx, registry: &Registry, count: usize) {
    let end = cx.now().as_nanos().saturating_add(2_000_000_000);
    while registry.lock().waiter_count() != count {
        assert!(
            cx.now().as_nanos() < end,
            "FIFO waiter count did not reach {count}"
        );
        asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
    }
}

async fn restart_and_close(cx: Cx) {
    let registry = Arc::new(Mutex::new(NameRegistry::new()));
    let (ready, mut generations) = mpsc::channel::<(ManagedGeneration, oneshot::Sender<()>)>(2);
    let (cleanup_release, cleanup_gate) = oneshot::channel();
    let cleanup_gate = Arc::new(Mutex::new(Some(cleanup_gate)));
    let (cleanup_pending, mut cleanup_witness) = oneshot::channel();
    let cleanup_pending = Arc::new(Mutex::new(Some(cleanup_pending)));
    let cleaned = Arc::new(AtomicBool::new(false));
    let retired_context = Arc::new(Mutex::new(None));
    let saved_context = Arc::clone(&retired_context);
    let child_registry = Arc::clone(&registry);
    let child_cleaned = Arc::clone(&cleaned);
    let binding = ManagedChildBinding::new(
        "worker",
        ManagedRestartMode::Transient,
        move |child: Cx, generation: ManagedGeneration| {
            assert!(child.has_registry());
            *saved_context.lock() = Some(child.clone());
            assert_eq!(
                child_registry.lock().whereis("service"),
                Some(generation.task)
            );
            if generation.number == 2 {
                assert!(
                    child_cleaned.load(Ordering::Acquire),
                    "old descendant must drain before replacement"
                );
            }
            let registry = Arc::clone(&child_registry);
            let ready = ready.clone();
            let cleaned = Arc::clone(&child_cleaned);
            let cleanup_gate = Arc::clone(&cleanup_gate);
            let cleanup_pending = Arc::clone(&cleanup_pending);
            async move {
                let mut descendant = if generation.number == 1 {
                    let mut gate = cleanup_gate.lock().take().unwrap();
                    let pending = cleanup_pending.lock().take().unwrap();
                    let (parked, mut witness) = oneshot::channel();
                    let task = child
                        .spawn(move |descendant| async move {
                            let (_keep_sender, mut cancelled) = mpsc::channel::<()>(1);
                            assert!(
                                witnessed(cancelled.recv(&descendant), parked)
                                    .await
                                    .is_err()
                            );
                            let mut cleanup = pin!(gate.recv(&descendant));
                            witnessed(
                                poll_fn(|task| descendant.masked(|| cleanup.as_mut().poll(task))),
                                pending,
                            )
                            .await
                            .unwrap();
                            cleaned.store(true, Ordering::Release);
                        })
                        .unwrap();
                    witness.recv(&child).await.unwrap();
                    Some(task)
                } else {
                    None
                };
                let (release, mut gate) = oneshot::channel();
                let (parked, mut witness) = oneshot::channel();
                // A separately owned notifier publishes readiness only after
                // the worker's controlling receive has actually parked.
                let notify = child
                    .spawn(move |notifier| async move {
                        witness.recv(&notifier).await.unwrap();
                        ready.send(&notifier, (generation, release)).await.unwrap();
                    })
                    .unwrap();
                let result = witnessed(gate.recv(&child), parked).await;
                drop(notify);
                assert_eq!(registry.lock().whereis("service"), Some(generation.task));
                // Dropping the descendant handle requests cancellation; the
                // controller must still drain its region before re-registering.
                drop(descendant.take());
                if generation.number == 1 {
                    result.unwrap();
                    Outcome::Err("restart this generation")
                } else {
                    assert!(result.is_err());
                    Outcome::Cancelled(child.cancel_reason().unwrap())
                }
            }
        },
    );
    let mut supervisor = bind(&registry, NameCollisionPolicy::Fail, binding)
        .spawn(&cx)
        .unwrap();
    let (first, release) = generations.recv(&cx).await.unwrap();
    assert_eq!(first.number, 1);
    release.send_blocking(()).unwrap();
    cleanup_witness.recv(&cx).await.unwrap();
    assert_eq!(registry.lock().whereis("service"), Some(first.task));
    assert!(
        generations.try_recv().is_err(),
        "replacement cannot overlap parked cleanup"
    );
    cleanup_release.send_blocking(()).unwrap();
    let (second, _keep_parked) = generations.recv(&cx).await.unwrap();
    assert_eq!(second.number, 2);
    assert_ne!(first.task, second.task);
    assert_ne!(first.region, second.region);
    assert!(matches!(
        registry.lock().unregister("service", first.task),
        Err(NameLeaseError::PermissionDenied { .. })
    ));
    assert_eq!(registry.lock().whereis("service"), Some(second.task));
    supervisor.abort();
    let report = supervisor.join().await.unwrap();
    assert!(report.outcome.is_cancelled(), "{report:?}");
    assert_eq!(
        (report.started, report.joined, report.restart_batches),
        (2, 2, 1)
    );
    assert!(report.region_outcome.is_some());
    assert!(registry.lock().is_empty());
    assert_eq!(registry.lock().waiter_count(), 0);
    let stale_cx = retired_context.lock().take().unwrap();
    let refused = bind(
        &registry,
        NameCollisionPolicy::Fail,
        ManagedChildBinding::new(
            "worker",
            ManagedRestartMode::Temporary,
            |_: Cx, _: ManagedGeneration| async {
                panic!("a closed generation cannot admit a named supervisor")
            },
        ),
    )
    .run(&stale_cx)
    .await;
    assert!(!refused.outcome.is_ok());
    assert_eq!((refused.started, refused.joined), (0, 0));
    assert!(
        registry.lock().is_empty(),
        "closed admission must not leave a reserved name"
    );
    eprintln!(
        "NAMED_SUPERVISOR scenario=restart_close first={first:?} second={second:?} started={} joined={} registry=empty",
        report.started, report.joined
    );
}

async fn collision_and_wait_cancel(cx: Cx) {
    let registry = Arc::new(Mutex::new(NameRegistry::new()));
    let mut held = registry
        .lock()
        .register("service", cx.task_id(), cx.region_id(), cx.now())
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let make_binding = || {
        let calls = Arc::clone(&calls);
        let registry = Arc::clone(&registry);
        ManagedChildBinding::new(
            "worker",
            ManagedRestartMode::Temporary,
            move |_: Cx, generation: ManagedGeneration| {
                assert_eq!(registry.lock().whereis("service"), Some(generation.task));
                calls.fetch_add(1, Ordering::SeqCst);
                async { Outcome::Ok(()) }
            },
        )
    };
    let report = bind(&registry, NameCollisionPolicy::Fail, make_binding())
        .run(&cx)
        .await;
    assert!(matches!(
        report.outcome,
        Outcome::Err(ManagedSupervisorError::Registration {
            error: NameLeaseError::NameTaken { .. },
            ..
        })
    ));
    assert_eq!((report.started, report.joined), (0, 1));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(registry.lock().owns_lease(&held));

    let mut first = bind(&registry, NameCollisionPolicy::Wait, make_binding())
        .spawn(&cx)
        .unwrap();
    wait_for_waiters(&cx, &registry, 1).await;
    let mut second = bind(&registry, NameCollisionPolicy::Wait, make_binding())
        .spawn(&cx)
        .unwrap();
    wait_for_waiters(&cx, &registry, 2).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "waiting names cannot run their factories"
    );
    first.abort();
    let cancelled = first.join().await.unwrap();
    assert!(cancelled.outcome.is_cancelled());
    assert_eq!((cancelled.started, cancelled.joined), (0, 1));
    assert_eq!(registry.lock().waiter_count(), 1);
    assert!(registry.lock().owns_lease(&held));
    registry
        .lock()
        .unregister_owned_and_grant(&held, cx.now())
        .unwrap();
    held.release().unwrap();
    let report = second.join().await.unwrap();
    assert!(report.outcome.is_ok(), "{report:?}");
    assert_eq!((report.started, report.joined), (1, 1));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(registry.lock().is_empty());
    assert_eq!(registry.lock().waiter_count(), 0);
    assert!(registry.lock().take_granted().is_empty());
    eprintln!(
        "NAMED_SUPERVISOR scenario=collision_wait_cancel started={} joined={} waiters=0 registry=empty",
        report.started, report.joined
    );
}

async fn replace_fences_stale_lease(cx: Cx) {
    let registry = Arc::new(Mutex::new(NameRegistry::new()));
    let (parked, mut witness) = oneshot::channel();
    let old_registry = Arc::clone(&registry);
    let retired_lease = Arc::new(Mutex::new(None));
    let old_lease = Arc::clone(&retired_lease);
    let mut old = cx
        .spawn(move |holder| async move {
            let lease = old_registry
                .lock()
                .register(
                    "service",
                    holder.task_id(),
                    holder.region_id(),
                    holder.now(),
                )
                .unwrap();
            let (_keep_sender, mut stop) = mpsc::channel::<()>(1);
            assert!(witnessed(stop.recv(&holder), parked).await.is_err());
            // Cancellation dominates a task's typed return. Move the stale token
            // through an owned slot so the join cannot discard an armed lease.
            *old_lease.lock() = Some(lease);
        })
        .unwrap();
    witness.recv(&cx).await.unwrap();
    let (ready, mut new_identity) = mpsc::channel::<ManagedGeneration>(1);
    let new_registry = Arc::clone(&registry);
    let binding = ManagedChildBinding::new(
        "worker",
        ManagedRestartMode::Temporary,
        move |child: Cx, generation: ManagedGeneration| {
            assert_eq!(
                new_registry.lock().whereis("service"),
                Some(generation.task)
            );
            let ready = ready.clone();
            async move {
                ready.send(&child, generation).await.unwrap();
                let (_keep_sender, mut stop) = mpsc::channel::<()>(1);
                assert!(stop.recv(&child).await.is_err());
                Outcome::Cancelled(child.cancel_reason().unwrap())
            }
        },
    );
    let mut supervisor = bind(&registry, NameCollisionPolicy::Replace, binding)
        .spawn(&cx)
        .unwrap();
    let new = new_identity.recv(&cx).await.unwrap();
    let old_result = old.join(&cx).await;
    let mut stale = retired_lease
        .lock()
        .take()
        .expect("old holder published its lease");
    let stale_release = registry.lock().unregister_owned_and_grant(&stale, cx.now());
    stale.abort().unwrap();
    assert!(
        old_result.is_err(),
        "displaced actual task must observe cancellation"
    );
    assert!(matches!(
        stale_release,
        Err(NameLeaseError::PermissionDenied { .. })
    ));
    assert_eq!(registry.lock().whereis("service"), Some(new.task));
    supervisor.abort();
    assert!(supervisor.join().await.unwrap().outcome.is_cancelled());
    assert!(registry.lock().is_empty());
    eprintln!("NAMED_SUPERVISOR scenario=replace new={new:?} registry=empty");
}

async fn abandoned_controller_retains_name_through_cleanup(cx: Cx) {
    let registry = Arc::new(Mutex::new(NameRegistry::new()));
    let (ready, mut started) = oneshot::channel();
    let ready = Arc::new(Mutex::new(Some(ready)));
    let (release, cleanup) = oneshot::channel();
    let cleanup = Arc::new(Mutex::new(Some(cleanup)));
    let (pending, mut cleanup_parked) = oneshot::channel();
    let pending = Arc::new(Mutex::new(Some(pending)));
    let cleaned = Arc::new(AtomicBool::new(false));
    let child_cleaned = Arc::clone(&cleaned);
    let binding = ManagedChildBinding::new(
        "worker",
        ManagedRestartMode::Temporary,
        move |child: Cx, generation: ManagedGeneration| {
            let ready = ready.lock().take().unwrap();
            let mut cleanup = cleanup.lock().take().unwrap();
            let pending = pending.lock().take().unwrap();
            let cleaned = Arc::clone(&child_cleaned);
            async move {
                let (parked, mut descendant_started) = oneshot::channel();
                let descendant = child
                    .spawn(move |descendant| async move {
                        let (_keep_sender, mut stop) = mpsc::channel::<()>(1);
                        assert!(witnessed(stop.recv(&descendant), parked).await.is_err());
                        let mut cleanup = pin!(cleanup.recv(&descendant));
                        witnessed(
                            poll_fn(|task| descendant.masked(|| cleanup.as_mut().poll(task))),
                            pending,
                        )
                        .await
                        .unwrap();
                        cleaned.store(true, Ordering::Release);
                    })
                    .unwrap();
                descendant_started.recv(&child).await.unwrap();
                let (_keep_sender, mut stop) = mpsc::channel::<()>(1);
                ready.send_blocking(generation).unwrap();
                assert!(stop.recv(&child).await.is_err());
                drop(descendant);
                Outcome::Cancelled(child.cancel_reason().unwrap())
            }
        },
    );
    let managed = bind(&registry, NameCollisionPolicy::Fail, binding);
    let mut controller = Box::pin(managed.run(&cx));
    let generation = {
        let mut started = pin!(started.recv(&cx));
        poll_fn(|task| {
            assert!(
                controller.as_mut().poll(task).is_pending(),
                "controller must be live before abandonment"
            );
            started.as_mut().poll(task)
        })
        .await
        .unwrap()
    };
    drop(controller);
    cleanup_parked.recv(&cx).await.unwrap();
    assert_eq!(registry.lock().whereis("service"), Some(generation.task));
    assert!(!cleaned.load(Ordering::Acquire));

    let calls = Arc::new(AtomicUsize::new(0));
    let make_binding = || {
        let calls = Arc::clone(&calls);
        ManagedChildBinding::new(
            "worker",
            ManagedRestartMode::Temporary,
            move |_: Cx, _: ManagedGeneration| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Outcome::Ok(()) }
            },
        )
    };
    let refused = bind(&registry, NameCollisionPolicy::Fail, make_binding())
        .run(&cx)
        .await;
    assert!(matches!(
        refused.outcome,
        Outcome::Err(ManagedSupervisorError::Registration { .. })
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "abandoned cleanup retains exclusive discovery"
    );
    release.send_blocking(()).unwrap();
    let deadline = cx.now().as_nanos().saturating_add(2_000_000_000);
    while !registry.lock().is_empty() {
        assert!(
            cx.now().as_nanos() < deadline,
            "region finalizer did not release the abandoned name"
        );
        asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
    }
    assert!(cleaned.load(Ordering::Acquire));
    let restarted = bind(&registry, NameCollisionPolicy::Fail, make_binding())
        .run(&cx)
        .await;
    assert!(restarted.outcome.is_ok(), "{restarted:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(registry.lock().is_empty());
    eprintln!(
        "NAMED_SUPERVISOR scenario=abandoned_controller generation={generation:?} cleanup_finished=true registry=empty"
    );
}

async fn journey(cx: Cx) {
    restart_and_close(cx.clone()).await;
    collision_and_wait_cancel(cx.clone()).await;
    replace_fences_stale_lease(cx.clone()).await;
    abandoned_controller_retains_name_through_cleanup(cx).await;
}

#[test]
fn named_supervisor_lab_restarts_waits_replaces_and_closes() {
    for seed in [0x100_01, 0x100_02] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(50_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                journey(Cx::current().expect("executing lab task")).await;
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_with_auto_advance();
        assert!(matches!(join.try_join(), Ok(Some(()))));
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        let (tasks, wakes) = lab
            .state
            .cancel_request(root, &CancelReason::user("named test done"), None)
            .into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
        assert!(lab.state.region(root).is_none());
        eprintln!("NAMED_SUPERVISOR backend=lab seed={seed} live_tasks=0 pending_obligations=0");
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn named_supervisor_native_restarts_waits_replaces_and_closes() {
    use asupersync::runtime::RuntimeBuilder;
    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        }
        .build()
        .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("native root context");
            let mut task = cx.spawn(journey).unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), task.join(&cx))
                .await
                .unwrap()
                .unwrap();
        });
        assert!(runtime.is_quiescent());
        eprintln!("NAMED_SUPERVISOR backend=native workers={workers} quiescent=true");
    }
}
