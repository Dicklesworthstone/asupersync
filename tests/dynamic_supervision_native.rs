//! Public dynamic-worker journeys on native current-thread and parallel runtimes.
//! No test double replaces the scheduler, admission, channels or managed driver.

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::{Cx, DynamicSupervisorConfig, DynamicSupervisorError, DynamicWorkerConfig,
    SharedRestartConfig};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::supervision::{
    BackoffStrategy, BudgetRefusal, ChildSpec, EscalationPolicy, ManagedChildBinding,
    ManagedGeneration, ManagedRestartMode, ManagedSupervisor, ManagedSupervisorError,
    RestartPolicy, SupervisionConfig, SupervisorBuilder,
};
use asupersync::types::{Budget, Outcome};
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Poll, Waker};
use std::time::Duration;

fn policy() -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(
        ManagedRestartMode::Transient,
        SupervisionConfig::new(2, Duration::from_secs(60))
            .with_restart_policy(RestartPolicy::OneForOne)
            .with_backoff(BackoffStrategy::None),
    )
}

fn native_journey(parallel: bool) {
    let runtime = if parallel {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime root context");
        let mut controller = cx.spawn(|cx| async move {
            let mut owner = cx.open_dynamic_supervisor::<&'static str>(
                DynamicSupervisorConfig::new(2),
            ).await.unwrap();
            let (ready_tx, mut ready_rx) = mpsc::channel::<ManagedGeneration>(1);
            let calls = Arc::new(AtomicUsize::new(0));
            let retired = Arc::new(AtomicUsize::new(0));
            let worker_calls = Arc::clone(&calls);
            let worker_retired = Arc::clone(&retired);
            let service = owner.start_worker("service", policy(), move |cx: Cx, generation: ManagedGeneration| {
                let ready = ready_tx.clone();
                let retired = Arc::clone(&worker_retired);
                worker_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    let (_keep_sender, mut stop) = mpsc::channel::<()>(1);
                    ready.send(&cx, generation).await.unwrap();
                    let error = stop.recv(&cx).await.expect_err("service ends through cancellation");
                    assert!(matches!(error, mpsc::RecvError::Cancelled));
                    // Actual asynchronous application cleanup, not a fabricated
                    // native region-finalizer receipt.
                    asupersync::runtime::yield_now().await;
                    retired.fetch_add(1, Ordering::SeqCst);
                    Outcome::Cancelled(cx.cancel_reason().expect("retained cancellation attribution"))
                }
            }).await.unwrap();
            let real_generation = ready_rx.recv(&cx).await.unwrap();
            assert_eq!(real_generation.number, 1);
            assert_ne!(real_generation.task, cx.task_id());
            let restarting = owner.start_worker("retry", policy(), |_: Cx, generation: ManagedGeneration| async move {
                if generation.number == 1 { Outcome::Err("transient native failure") }
                else { Outcome::Ok(()) }
            }).await.unwrap();
            let finished = owner.wait_child(&restarting).await.unwrap();
            assert!(finished.close.is_ok());
            let report = finished.supervisor.unwrap();
            assert!(report.outcome.is_ok());
            assert_eq!(report.started, 2);
            assert_eq!(report.joined, 2);
            assert_eq!(report.restart_batches, 1);
            assert_eq!(report.children[0].generation.number, 2);
            assert_eq!(calls.load(Ordering::SeqCst), 1, "other worker's restarts stay isolated");
            assert_eq!(retired.load(Ordering::SeqCst), 0);
            let group = owner.terminate_children(&[service]).await.unwrap();
            assert_eq!(group.len(), 1);
            let stopped = group.into_iter().next().unwrap().unwrap();
            assert!(stopped.stop_requested);
            assert!(stopped.close.is_ok());
            let report = stopped.supervisor.unwrap();
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
            assert_eq!(report.restart_batches, 0);
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert!(owner.is_empty());
            let shutdown = owner.shutdown().await;
            assert!(shutdown.close.is_ok());
        }).unwrap();
        controller.join(&cx).await.unwrap();
    });
}

#[test]
fn native_current_thread_dynamic_workers_restart_and_drain() {
    native_journey(false);
}

#[test]
fn native_parallel_dynamic_workers_restart_and_drain() {
    native_journey(true);
}

#[derive(Default)]
struct CleanupGate {
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl CleanupGate {
    async fn wait(&self) {
        poll_fn(|cx| {
            let mut waiter = self.waiter.lock().unwrap();
            if self.open.load(Ordering::Acquire) { return Poll::Ready(()); }
            *waiter = Some(cx.waker().clone());
            Poll::Pending
        }).await;
    }

    fn release(&self) {
        self.open.store(true, Ordering::Release);
        let waiter = self.waiter.lock().unwrap().take();
        if let Some(waiter) = waiter { waiter.wake(); }
    }
}

async fn witnessed<F: Future>(future: F, parked: oneshot::Sender<()>) -> F::Output {
    let mut future = Box::pin(future);
    let mut parked = Some(parked);
    poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if result.is_pending() {
            if let Some(parked) = parked.take() { parked.send_blocking(()).unwrap(); }
        }
        result
    }).await
}

fn static_pair() -> ManagedSupervisor<&'static str> {
    fn legacy(
        _: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
        _: &mut asupersync::runtime::RuntimeState,
        _: &Cx,
    ) -> Result<asupersync::types::TaskId, asupersync::runtime::SpawnError> {
        panic!("managed binding must never invoke the legacy start hook")
    }
    let tree = SupervisorBuilder::new("static-pair")
        .child(ChildSpec::new("left", legacy))
        .child(ChildSpec::new("right", legacy))
        .compile().unwrap();
    let bindings = ["left", "right"].into_iter().map(|name| {
        ManagedChildBinding::new(name, ManagedRestartMode::Transient,
            |_: Cx, generation: ManagedGeneration| async move {
                if generation.number == 1 { Outcome::Err("static generation failed") }
                else { Outcome::Ok(()) }
            })
    }).collect();
    tree.bind_managed(bindings, policy().supervision).unwrap()
}

fn shared_native_journey(workers: usize) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new().worker_threads(workers).build().unwrap()
    };
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(cx.clone(), async move {
        let mut coordinator = cx.spawn(move |cx| async move {
            let mut owner = cx.open_dynamic_supervisor_with_shared_restarts::<&'static str>(
                DynamicSupervisorConfig::new(4),
                SharedRestartConfig::new(4, Duration::from_secs(3600)),
            ).await.unwrap();
            let (parked, mut park_witness) = oneshot::channel();
            let (cleaning, mut cleanup_witness) = oneshot::channel();
            let signals = Arc::new(Mutex::new(Some((parked, cleaning))));
            let gate = Arc::new(CleanupGate::default());
            let cleanup_gate = Arc::clone(&gate);
            let cleaned = Arc::new(AtomicBool::new(false));
            let child_cleaned = Arc::clone(&cleaned);
            let stable = owner.start_worker("stable", policy(),
                move |worker: Cx, _: ManagedGeneration| {
                    let (parked, cleaning) = signals.lock().unwrap().take().unwrap();
                    let gate = Arc::clone(&cleanup_gate);
                    let cleaned = Arc::clone(&child_cleaned);
                    async move {
                        let descendant = worker.spawn(move |child| async move {
                            witnessed(child.cancelled(), parked).await;
                            child.checkpoint().expect_err("actual descendant acknowledges cancellation");
                            witnessed(gate.wait(), cleaning).await;
                            cleaned.store(true, Ordering::Release);
                        }).unwrap();
                        worker.cancelled().await;
                        worker.checkpoint().expect_err("actual worker acknowledges cancellation");
                        drop(descendant);
                        Outcome::Cancelled(worker.cancel_reason().unwrap())
                    }
                }).await.unwrap();
            park_witness.recv(&cx).await.unwrap();
            let mut old_id = None;
            for expected in 1..=2 {
                let id = owner.start_worker("reused", policy(),
                    |_: Cx, generation: ManagedGeneration| async move {
                        if generation.number == 1 { Outcome::Err("dynamic generation failed") }
                        else { Outcome::Ok(()) }
                    }).await.unwrap();
                if let Some(old) = old_id.replace(id.clone()) { assert_ne!(old, id); }
                let completion = owner.wait_child(&id).await.unwrap();
                assert!(completion.close.is_ok());
                let report = completion.supervisor.unwrap();
                assert_eq!((report.started, report.joined, report.restart_batches), (2, 2, 1));
                assert_eq!(owner.shared_restart_status().unwrap().admitted, expected);
            }
            let pair = owner.start_child("static-pair", static_pair()).await.unwrap();
            let completion = owner.wait_child(&pair).await.unwrap();
            assert!(completion.close.is_ok());
            let report = completion.supervisor.unwrap();
            assert_eq!((report.started, report.joined, report.restart_batches), (4, 4, 2));
            assert_eq!(owner.shared_restart_status().unwrap().admitted, 4);
            assert!(!cleaned.load(Ordering::Acquire));

            let attempts = Arc::new(AtomicUsize::new(0));
            let calls = Arc::clone(&attempts);
            let mut resetting = policy();
            resetting.supervision.escalation = EscalationPolicy::ResetCounter;
            let denied = owner.start_worker("denied", resetting,
                move |_: Cx, _: ManagedGeneration| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Outcome::Err("the exact triggering failure") }
                }).await.unwrap();
            cleanup_witness.recv(&cx).await.unwrap();
            let completion = owner.wait_child(&denied).await.unwrap();
            assert!(completion.close.is_ok());
            let report = completion.supervisor.unwrap();
            assert!(matches!(report.outcome, Outcome::Err(ManagedSupervisorError::SharedRestartLimit {
                refusal: BudgetRefusal::WindowExhausted { max_restarts: 4, .. }, ..
            })));
            assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
            assert!(matches!(report.children[0].outcome, Outcome::Err("the exact triggering failure")));
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            let status = owner.shared_restart_status().unwrap();
            assert_eq!((status.admitted, status.recent), (4, 4));
            assert!(matches!(status.refusal, Some(BudgetRefusal::WindowExhausted { max_restarts: 4, .. })));
            assert!(matches!(owner.start_worker("late", policy(),
                |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).await,
                Err(DynamicSupervisorError::SharedRestartLimit(_))));
            assert!(cx.checkpoint().is_ok(), "shared meltdown stops its root, not the caller's parent");
            let mut shutdown = Box::pin(owner.shutdown());
            poll_fn(|task| {
                assert!(shutdown.as_mut().poll(task).is_pending(),
                    "owned descendant cleanup must prevent publication of quiescence");
                Poll::Ready(())
            }).await;
            assert!(!cleaned.load(Ordering::Acquire));
            gate.release();
            let report = shutdown.await;
            assert!(cleaned.load(Ordering::Acquire));
            assert!(report.close.is_ok());
            assert_eq!(report.children.len(), 1);
            assert_eq!(report.children[0].id, stable);
            assert!(report.children[0].close.is_ok());
            let child_report = report.children[0].supervisor.as_ref().unwrap();
            assert_eq!((child_report.started, child_report.joined), (1, 1));
            assert!(child_report.children[0].region_outcome.is_some());
        }).unwrap();
        coordinator.join(&cx).await.unwrap();
    });
    let drained = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
    assert_eq!((drained.live_tasks, drained.live_regions, drained.pending_obligations), (0, 0, 0));
    assert_eq!((drained.pending_spawns, drained.queued_finalizers), (0, 0));
    assert!(!drained.has_pending_obligation_posts);
}

fn shared_watchdog(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(45))
        .expect("shared native supervisor must complete before host watchdog");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}

#[test]
fn native_shared_restart_window_survives_name_reuse_and_drains_all_trees() {
    shared_watchdog(|| {
        for workers in [1, 2] { shared_native_journey(workers); }
    });
}

#[test]
fn native_shared_mailbox_exits_after_last_child_refuses_without_new_commands() {
    shared_watchdog(|| {
        for workers in [1, 2] {
            let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers) }.build().unwrap();
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            runtime.block_on_with_cx(cx.clone(), async move {
                let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox_with_shared_restarts(
                    DynamicSupervisorConfig::new(2), 2,
                    SharedRestartConfig::new(0, Duration::from_secs(3600)),
                ).unwrap();
                let mut request = client.submit_worker(&cx, "last", policy(),
                    |_: Cx, _: ManagedGeneration| async { Outcome::Err("last failure") }).unwrap();
                let mut child = request.admitted(&cx).await.unwrap();
                let completed = child.join().await.unwrap();
                assert!(completed.close.is_ok());
                let report = completed.supervisor.unwrap();
                assert!(matches!(report.outcome, Outcome::Err(ManagedSupervisorError::SharedRestartLimit { .. })));
                assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
                let report = service.join().await.unwrap();
                assert!(report.task_outcome.is_ok());
                let report = report.supervision.unwrap();
                assert!(report.children.is_empty());
                assert!(report.close.is_ok());
                assert!(client.shared_restart_status().unwrap().refusal.is_some());
                assert!(service.shared_restart_status().unwrap().refusal.is_some());
                assert!(cx.checkpoint().is_ok());
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!((report.live_tasks, report.live_regions, report.pending_obligations), (0, 0, 0));
        }
    });
}
