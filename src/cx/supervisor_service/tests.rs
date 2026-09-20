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
