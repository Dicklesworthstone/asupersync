#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::supervision::{BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig};
use crate::types::{Budget, CancelKind, Outcome, RegionId};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn worker_config() -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(ManagedRestartMode::Temporary,
        SupervisionConfig::new(0, Duration::from_secs(60)).with_backoff(BackoffStrategy::None))
}

fn run_case<F, Fut>(case: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0xd5_0001).max_steps(65_536));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        case(Cx::current().expect("registered parent")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join().unwrap().expect("case completed within deterministic step limit");
    clean(&mut lab, root);
}

fn clean(lab: &mut LabRuntime, root: RegionId) {
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state.cancel_request(root,
            &CancelReason::user("service test complete"), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

#[test]
fn invalid_capacity_detached_authority_and_cancellation_refuse() {
    let cx = Cx::detached_cancel_context();
    assert!(matches!(cx.spawn_dynamic_supervisor_mailbox::<()>(DynamicSupervisorConfig::new(1), 0),
        Err(DynamicServiceError::InvalidCapacity)));
    assert!(matches!(cx.spawn_dynamic_supervisor_mailbox::<()>(DynamicSupervisorConfig::new(1), 1),
        Err(DynamicServiceError::Spawn(_))));
    cx.cancel_with(CancelKind::User, Some("do not submit"));
    assert!(matches!(cx.spawn_dynamic_supervisor_mailbox::<()>(DynamicSupervisorConfig::new(1), 1),
        Err(DynamicServiceError::Cancelled(_))));
}

#[test]
fn bounded_queue_and_abandoned_receipt_never_invoke_queued_factories() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(4), 1).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let first = client.submit_worker(&cx, "abandoned", worker_config(),
            move |_: Cx, _: ManagedGeneration| {
                count.fetch_add(1, Ordering::SeqCst);
                async { Outcome::Ok(()) }
            }).unwrap();
        // No await since spawn: the lab cannot have dequeued the first request.
        let count = Arc::clone(&calls);
        assert!(matches!(client.submit_worker(&cx, "refused", worker_config(),
            move |_: Cx, _: ManagedGeneration| {
                count.fetch_add(1, Ordering::SeqCst);
                async { Outcome::Ok(()) }
            }), Err(DynamicServiceError::MailboxFull)));
        drop(first);
        drop(client);
        let report = service.join().await.unwrap();
        assert!(report.task_outcome.is_ok());
        let owner = report.supervision.unwrap();
        assert!(owner.children.is_empty());
        assert!(owner.close.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn independent_clients_preserve_send_only_typed_outcomes() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<Cell<usize>>(
            DynamicSupervisorConfig::new(16), 16).unwrap();
        let mut callers = Vec::new();
        for index in 0..16 {
            let client = client.clone();
            callers.push(cx.spawn(move |cx| async move {
                let mut pending = client.submit_worker(&cx, format!("worker-{index:02}"), worker_config(),
                    move |_: Cx, _: ManagedGeneration| async move { Outcome::Err(Cell::new(index)) }).unwrap();
                let mut child = pending.admitted(&cx).await.unwrap();
                let id = child.id().clone();
                let completion = child.join().await.unwrap();
                assert_eq!(completion.id, id);
                assert!(completion.close.is_ok());
                let report = completion.supervisor.unwrap();
                assert_eq!((report.started, report.joined), (1, 1));
                assert!(matches!(&report.children[0].outcome, Outcome::Err(value) if value.get() == index));
            }).unwrap());
        }
        for mut caller in callers { caller.join(&cx).await.unwrap(); }
        drop(client);
        let report = service.join().await.unwrap();
        assert!(report.task_outcome.is_ok());
        let owner = report.supervision.unwrap();
        assert!(owner.children.is_empty(), "delivered results are not accumulated in the service");
        assert!(owner.close.is_ok());
    });
}

fn parked(
    ready: mpsc::Sender<()>, stopped: Arc<AtomicUsize>,
) -> impl ManagedChildFactory<()> {
    move |cx: Cx, _: ManagedGeneration| {
        let ready = ready.clone();
        let stopped = Arc::clone(&stopped);
        async move {
            let (_sender, mut wait) = mpsc::channel::<()>(1);
            ready.try_send(()).unwrap();
            assert!(matches!(wait.recv(&cx).await, Err(mpsc::RecvError::Cancelled)));
            stopped.fetch_add(1, Ordering::SeqCst);
            Outcome::Cancelled(cx.cancel_reason().expect("actual cancellation"))
        }
    }
}

#[test]
fn stop_bypasses_saturated_admission_without_stopping_a_sibling() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(3), 1).unwrap();
        let (ready, mut started) = mpsc::channel(2);
        let first_stopped = Arc::new(AtomicUsize::new(0));
        let sibling_stopped = Arc::new(AtomicUsize::new(0));
        let mut admission = client.submit_worker(&cx, "first", worker_config(),
            parked(ready.clone(), Arc::clone(&first_stopped))).unwrap();
        let mut first = admission.admitted(&cx).await.unwrap();
        started.recv(&cx).await.unwrap();
        let mut admission = client.submit_worker(&cx, "sibling", worker_config(),
            parked(ready, Arc::clone(&sibling_stopped))).unwrap();
        let mut sibling = admission.admitted(&cx).await.unwrap();
        started.recv(&cx).await.unwrap();
        let mut queued = client.submit_worker(&cx, "queued", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).unwrap();
        assert!(matches!(client.submit_worker(&cx, "overflow", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }),
            Err(DynamicServiceError::MailboxFull)));
        first.request_stop();
        let completion = first.join().await.unwrap();
        assert!(completion.stop_requested);
        assert!(completion.close.is_ok());
        assert_eq!(first_stopped.load(Ordering::SeqCst), 1);
        assert_eq!(sibling_stopped.load(Ordering::SeqCst), 0);
        let mut third = queued.admitted(&cx).await.unwrap();
        let _completion = third.join().await.unwrap();
        sibling.request_stop();
        let _completion = sibling.join().await.unwrap();
        drop(client);
        assert!(service.join().await.unwrap().supervision.unwrap().close.is_ok());
    });
}

#[test]
fn stalled_child_cleanup_does_not_block_new_admission_or_unrelated_completion() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(2), 2).unwrap();
        let (started, mut started_rx) = oneshot::channel();
        let (cleaning, mut cleaning_rx) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let setup = Arc::new(Mutex::new(Some((started, cleaning, released))));
        let mut admission = client.submit_worker(&cx, "slow", worker_config(),
            move |cx: Cx, _: ManagedGeneration| {
                let (started, cleaning, mut released) = setup.lock().take().unwrap();
                async move {
                    let (_sender, mut wait) = mpsc::channel::<()>(1);
                    started.send_blocking(()).unwrap();
                    assert!(matches!(wait.recv(&cx).await, Err(mpsc::RecvError::Cancelled)));
                    cleaning.send_blocking(()).unwrap();
                    // Real application cleanup; not a runtime-registered finalizer.
                    released.recv_uninterruptible().await.unwrap();
                    Outcome::Cancelled(cx.cancel_reason().unwrap())
                }
            }).unwrap();
        let mut slow = admission.admitted(&cx).await.unwrap();
        started_rx.recv(&cx).await.unwrap();
        slow.request_stop();
        cleaning_rx.recv(&cx).await.unwrap();
        let mut admission = client.submit_worker(&cx, "fast", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).unwrap();
        let mut fast = admission.admitted(&cx).await.unwrap();
        let result = fast.join().await.unwrap();
        assert!(result.close.is_ok());
        assert!(result.supervisor.unwrap().children[0].outcome.is_ok());
        release.send_blocking(()).unwrap();
        let _completion = slow.join().await.unwrap();
        drop(client);
        assert!(service.join().await.unwrap().supervision.unwrap().close.is_ok());
    });
}

#[test]
fn idle_service_abort_is_a_wake_source_and_retains_shutdown_receipt() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(1), 1).unwrap();
        let mut admission = client.submit_worker(&cx, "probe", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).unwrap();
        let mut child = admission.admitted(&cx).await.unwrap();
        let _completion = child.join().await.unwrap();
        // The service has reached its idle receive despite a still-live client.
        service.abort();
        let report = service.join().await.unwrap();
        assert!(matches!(report.task_outcome, Err(JoinError::Cancelled(_))));
        assert!(report.supervision.unwrap().close.is_ok());
        assert!(matches!(client.submit_worker(&cx, "late", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }), Err(DynamicServiceError::Closed)));
    });
}

#[test]
fn child_drop_stops_only_its_admission_and_old_handles_cannot_stop_name_reuse() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(2), 2).unwrap();
        let (ready, mut started) = mpsc::channel(1);
        let stopped = Arc::new(AtomicUsize::new(0));
        let mut admission = client.submit_worker(&cx, "reused", worker_config(),
            parked(ready.clone(), Arc::clone(&stopped))).unwrap();
        let mut old = admission.admitted(&cx).await.unwrap();
        started.recv(&cx).await.unwrap();
        old.request_stop();
        let _completion = old.join().await.unwrap();
        let mut admission = client.submit_worker(&cx, "reused", worker_config(),
            parked(ready, Arc::clone(&stopped))).unwrap();
        let child = admission.admitted(&cx).await.unwrap();
        started.recv(&cx).await.unwrap();
        assert_ne!(old.id(), child.id());
        assert!(child.id().generation() > old.id().generation());
        drop(old);
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        drop(child); // Independent stop channel closure, no command submission.
        drop(client);
        let report = service.join().await.unwrap();
        assert!(report.supervision.unwrap().close.is_ok());
        assert_eq!(stopped.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn graceful_seal_rejects_queued_work_and_preserves_running_work_until_natural_completion() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(2), 1).unwrap();
        let (ready, mut started) = oneshot::channel();
        let (release, receiver) = mpsc::channel::<()>(1);
        let setup = Arc::new(Mutex::new(Some((ready, receiver))));
        let mut admission = client.submit_worker(&cx, "running", worker_config(),
            move |cx: Cx, _: ManagedGeneration| {
                let (ready, mut receiver) = setup.lock().take().unwrap();
                async move {
                    ready.send_blocking(()).unwrap();
                    receiver.recv(&cx).await.expect("graceful seal must not cancel admitted work");
                    Outcome::Ok(())
                }
            }).unwrap();
        let mut child = admission.admitted(&cx).await.unwrap();
        started.recv(&cx).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let mut queued = client.submit_worker(&cx, "queued", worker_config(),
            move |_: Cx, _: ManagedGeneration| {
                count.fetch_add(1, Ordering::SeqCst);
                async { Outcome::Ok(()) }
            }).unwrap();
        service.begin_drain();
        service.begin_drain(); // Idempotent and does not escalate to Stop.
        assert!(matches!(client.submit_worker(&cx, "late", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }), Err(DynamicServiceError::Closed)));
        assert!(matches!(queued.admitted(&cx).await, Err(DynamicServiceError::Closed)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        release.try_send(()).unwrap();
        let completion = child.join().await.unwrap();
        assert!(!completion.stop_requested);
        assert!(completion.supervisor.unwrap().children[0].outcome.is_ok());
        let report = service.join().await.unwrap();
        assert!(report.task_outcome.is_ok());
        assert!(report.supervision.unwrap().close.is_ok());
        // A live client did not keep the explicitly drained service alive.
        drop(client);
    });
}

#[test]
fn cancellation_escalates_an_incomplete_graceful_drain_without_reopening_admission() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(2), 1).unwrap();
        let (ready, mut started) = mpsc::channel(1);
        let stopped = Arc::new(AtomicUsize::new(0));
        let mut admission = client.submit_worker(&cx, "parked", worker_config(),
            parked(ready, Arc::clone(&stopped))).unwrap();
        let mut child = admission.admitted(&cx).await.unwrap();
        started.recv(&cx).await.unwrap();
        let mut rejected = client.submit_worker(&cx, "reject", worker_config(),
            |_: Cx, _: ManagedGeneration| -> std::future::Ready<Outcome<(), ()>> { panic!("sealed queued factory must not run") }).unwrap();
        service.begin_drain();
        assert!(matches!(rejected.admitted(&cx).await, Err(DynamicServiceError::Closed)));
        assert_eq!(stopped.load(Ordering::SeqCst), 0);
        service.abort();
        service.begin_drain(); // A later, weaker request cannot undo cancellation.
        let completion = child.join().await.unwrap();
        assert!(completion.stop_requested);
        assert!(completion.close.is_ok());
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        let report = service.join().await.unwrap();
        assert!(matches!(report.task_outcome, Err(JoinError::Cancelled(_))));
        assert!(report.supervision.unwrap().close.is_ok());
    });
}

#[test]
fn cancelled_admission_observation_preserves_the_receipt_for_a_later_wait() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(1), 1).unwrap();
        let mut pending = client.submit_worker(&cx, "retained", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).unwrap();
        let cancelled = Cx::detached_cancel_context();
        cancelled.cancel_with(CancelKind::User, Some("pause this wait"));
        assert!(matches!(pending.admitted(&cancelled).await, Err(DynamicServiceError::Cancelled(_))));
        let mut child = pending.admitted(&cx).await.unwrap();
        let completion = child.join().await.unwrap();
        assert!(completion.close.is_ok());
        service.begin_drain();
        assert!(service.join().await.unwrap().supervision.unwrap().close.is_ok());
    });
}

#[test]
fn zero_child_capacity_refuses_after_mailbox_admission_without_invoking_factory() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(0), 1).unwrap();
        let mut pending = client.submit_worker(&cx, "zero", worker_config(),
            |_: Cx, _: ManagedGeneration| -> std::future::Ready<Outcome<(), ()>> { panic!("zero-capacity factory must not run") }).unwrap();
        assert!(matches!(pending.admitted(&cx).await,
            Err(DynamicServiceError::Supervisor(DynamicSupervisorError::Capacity))));
        service.begin_drain();
        assert!(service.join().await.unwrap().supervision.unwrap().close.is_ok());
    });
}

#[test]
fn a_factory_panic_is_reported_without_killing_the_service() {
    run_case(|cx| async move {
        let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<()>(
            DynamicSupervisorConfig::new(1), 1).unwrap();
        let mut pending = client.submit_worker(&cx, "panic", worker_config(),
            |_: Cx, _: ManagedGeneration| -> std::future::Ready<Outcome<(), ()>> {
                panic!("intentional managed factory construction panic")
            }).unwrap();
        let mut child = pending.admitted(&cx).await.unwrap();
        let result = child.join().await.unwrap();
        assert!(result.close.is_ok());
        assert!(result.supervisor.unwrap().children[0].outcome.is_panicked());
        let mut next = client.submit_worker(&cx, "after-panic", worker_config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).unwrap();
        let mut survivor = next.admitted(&cx).await.unwrap();
        assert!(survivor.join().await.unwrap().supervisor.unwrap().children[0].outcome.is_ok());
        service.begin_drain();
        assert!(service.join().await.unwrap().supervision.unwrap().close.is_ok());
    });
}

#[test]
fn observed_cancellation_does_not_register_fresh_wakers_while_cleanup_waits() {
    struct CountWake(AtomicUsize);
    impl std::task::Wake for CountWake {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let cx = Cx::detached_cancel_context();
    cx.cancel_with(CancelKind::User, Some("already observed"));
    let mut cancellation = Cancellation { cx, token: None, observed: false };
    assert!(cancellation.requested(&Context::from_waker(std::task::Waker::noop())));
    for _ in 0..32 {
        let count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&count));
        assert!(cancellation.requested(&Context::from_waker(&waker)));
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }
}
