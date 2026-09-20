use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::supervision::{BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig};
use crate::types::{Budget, Outcome};
use std::sync::atomic::AtomicUsize;
use std::task::Wake;
use std::time::Duration;

fn config() -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(
        ManagedRestartMode::Temporary,
        SupervisionConfig::new(0, Duration::from_secs(60)).with_backoff(BackoffStrategy::None),
    )
}

async fn parked(cx: Cx, _: ManagedGeneration) -> Outcome<(), &'static str> {
    cx.cancelled().await;
    Outcome::Cancelled(cx.cancel_reason().expect("worker received real cancellation"))
}

async fn eventually(mut predicate: impl FnMut() -> bool) {
    for _ in 0..4096 {
        if predicate() { return; }
        crate::runtime::yield_now().await;
    }
    panic!("bounded test observation did not become true");
}

fn run_case<F, Fut>(factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0xd15c_0001).max_steps(100_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered test parent")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert!(join.try_join().unwrap().is_some(), "public service journey must finish");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::user("test complete"), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

fn report<E>(exit: DynamicServiceExit<E>) {
    assert!(matches!(exit.task_outcome, Ok(()) | Err(JoinError::Cancelled(_))));
    let report = exit.report.expect("controller published actual shutdown").unwrap();
    assert!(report.close.is_ok());
    assert!(report.children.is_empty());
}

fn stopped<E>(completion: DynamicChildCompletion<E>) {
    assert!(completion.close.is_ok());
    assert!(completion.stop_requested);
    match completion.supervisor {
        Ok(report) => assert!(matches!(report.outcome, Outcome::Ok(()) | Outcome::Cancelled(_))),
        Err(error) => assert!(matches!(error, JoinError::Cancelled(_))),
    }
}

#[test]
fn missing_runtime_and_zero_request_capacity_refuse_without_fake_readiness() {
    // Match the API's Cx<All> type without attaching a runtime gateway.
    let cx = Cx::for_testing();
    assert!(matches!(cx.spawn_dynamic_supervisor_service::<()>(DynamicServiceConfig::new(2, 0)),
        Err(DynamicControlError::Configuration)));
    assert!(matches!(cx.spawn_dynamic_supervisor_service::<()>(DynamicServiceConfig::new(2, 1)),
        Err(DynamicControlError::Spawn(_))));
}

#[test]
fn clients_support_send_but_not_sync_application_errors() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>() {}
    send_sync::<DynamicSupervisorClient<std::cell::Cell<u8>>>();
    send::<DynamicServiceHandle<std::cell::Cell<u8>>>();
}

#[test]
fn separate_tasks_admit_workers_and_receive_exact_typed_results() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(4, 8)).unwrap();
        let client = service.client();
        assert_ne!(client.ready(&cx).await.unwrap(), cx.region_id());
        let mut producers = Vec::new();
        for index in 0..4 {
            let client = client.clone();
            producers.push(cx.spawn(move |cx| async move {
                let id = client.start_worker(&cx, format!("worker-{index}"), config(),
                    |_: Cx, _: ManagedGeneration| async { Outcome::Err("domain failure") }).await.unwrap();
                let completion = client.wait_child(&cx, &id).await.unwrap();
                assert_eq!(completion.id, id);
                let worker = completion.supervisor.unwrap();
                assert!(matches!(worker.children[0].outcome, Outcome::Err("domain failure")));
                assert_eq!(worker.started, worker.joined);
                assert!(completion.close.is_ok());
            }).unwrap());
        }
        for mut producer in producers { producer.join(&cx).await.unwrap(); }
        eventually(|| client.children().is_empty() && client.outstanding_requests() == 0).await;
        report(service.shutdown().await);
        assert!(client.is_closed());
    });
}

#[test]
fn saturated_wait_capacity_cannot_block_the_stop_needed_by_the_wait() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(1, 1)).unwrap();
        let client = service.client();
        let id = client.start_worker(&cx, "worker", config(), parked).await.unwrap();
        eventually(|| client.outstanding_requests() == 0).await;
        let waiting = client.submit(&cx, Operation::Wait(id.clone())).unwrap();
        assert!(matches!(client.submit(&cx, Operation::Ready), Err(DynamicControlError::Busy)));
        client.request_stop(&id).unwrap();
        let response = waiting.await.unwrap();
        let Response::Completed(slot) = response else { panic!("wait response"); };
        let completion = slot.take().unwrap();
        assert_eq!(completion.id, id);
        assert!(completion.close.is_ok());
        eventually(|| client.children().is_empty() && client.outstanding_requests() == 0).await;
        let replacement = client.start_worker(&cx, "worker", config(), parked).await.unwrap();
        assert_ne!(replacement, id);
        assert!(matches!(client.request_stop(&id), Err(DynamicControlError::StaleChild)));
        stopped(client.terminate_child(&cx, &replacement).await.unwrap());
        report(service.shutdown().await);
    });
}

#[test]
fn abandoned_queued_start_never_invokes_a_factory() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(1, 2)).unwrap();
        let client = service.client();
        client.ready(&cx).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let wait = client.submit(&cx, Operation::Start("abandoned".into(), Work::Worker(config(), Box::new(
            move |cx: Cx, generation: ManagedGeneration| {
                observed.fetch_add(1, Ordering::SeqCst);
                parked(cx, generation)
            },
        )))).unwrap();
        drop(wait); // No await or scheduler turn between publication and abandonment.
        eventually(|| client.outstanding_requests() == 0).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(client.children().is_empty());
        report(service.shutdown().await);
    });
}

#[test]
fn abandoned_unclaimed_start_is_drained_and_returns_all_credit_without_another_command() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(1, 1)).unwrap();
        let client = service.client();
        let wait = client.submit(&cx, Operation::Start("abandoned".into(), Work::Worker(config(), Box::new(parked)))).unwrap();
        // Do not poll the response: admission has happened but receipt acceptance has not.
        eventually(|| wait.request.reply.lock().value.is_some()).await;
        assert_eq!(client.children().len(), 1);
        drop(wait);
        eventually(|| client.children().is_empty() && client.outstanding_requests() == 0).await;
        let id = client.start_worker(&cx, "replacement", config(), parked).await.unwrap();
        stopped(client.terminate_child(&cx, &id).await.unwrap());
        report(service.shutdown().await);
    });
}

#[test]
fn abandoned_ready_wait_does_not_consume_a_completed_application_error() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(1, 2)).unwrap();
        let client = service.client();
        let id = client.start_worker(&cx, "worker", config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Err("retain this result") }).await.unwrap();
        let wait = client.submit(&cx, Operation::Wait(id.clone())).unwrap();
        eventually(|| wait.request.reply.lock().value.is_some()).await;
        drop(wait);
        let completion = client.wait_child(&cx, &id).await.unwrap();
        let worker = completion.supervisor.unwrap();
        assert!(matches!(worker.children[0].outcome, Outcome::Err("retain this result")));
        assert!(matches!(client.wait_child(&cx, &id).await, Err(DynamicControlError::StaleChild)));
        report(service.shutdown().await);
    });
}

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, Option<Waker>)>,
    entered: AtomicBool,
}
impl Gate {
    async fn wait(&self) {
        poll_fn(|cx| {
            let replacement = cx.waker().clone();
            let (ready, old) = {
                let mut state = self.state.lock();
                (state.0, state.1.replace(replacement))
            };
            drop(old);
            self.entered.store(true, Ordering::Release);
            if ready { Poll::Ready(()) } else { Poll::Pending }
        }).await;
    }
    fn open(&self) {
        let wake = { let mut state = self.state.lock(); state.0 = true; state.1.take() };
        if let Some(waker) = wake { waker.wake(); }
    }
}

#[test]
fn pending_cleanup_does_not_block_unrelated_admission_or_completion() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(2, 4)).unwrap();
        let client = service.client();
        let gate = Arc::new(Gate::default());
        let cleanup = Arc::clone(&gate);
        let started = Arc::new(AtomicBool::new(false));
        let start = Arc::clone(&started);
        let a = client.start_worker(&cx, "a", config(), move |cx: Cx, _: ManagedGeneration| {
            let cleanup = Arc::clone(&cleanup);
            start.store(true, Ordering::Release);
            async move {
                cx.cancelled().await;
                // Application cleanup, explicitly not a runtime finalizer registration.
                cleanup.wait().await;
                Outcome::Cancelled(cx.cancel_reason().unwrap())
            }
        }).await.unwrap();
        eventually(|| started.load(Ordering::Acquire)).await;
        client.request_stop(&a).unwrap();
        let waiting_a = client.submit(&cx, Operation::Wait(a.clone())).unwrap();
        eventually(|| gate.entered.load(Ordering::Acquire)).await;
        let b = client.start_worker(&cx, "b", config(),
            |_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }).await.unwrap();
        assert!(client.wait_child(&cx, &b).await.unwrap().close.is_ok());
        assert!(waiting_a.request.reply.lock().value.is_none());
        gate.open();
        let Response::Completed(slot) = waiting_a.await.unwrap() else { panic!("wait response"); };
        assert_eq!(slot.take().unwrap().id, a);
        report(service.shutdown().await);
    });
}

#[derive(Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn closing_wakes_dequeued_requests_not_just_queued_ones() {
    let shared = Arc::new(Shared::<()> {
        mailbox: Mutex::new(Mailbox { queue: VecDeque::new(), routes: BTreeMap::new(), requests: Vec::new() }),
        credits: Arc::new(Credits { active: AtomicUsize::new(0), limit: 1 }),
        signal: Arc::new(Signal::default()),
    });
    let client = DynamicSupervisorClient { shared: Arc::clone(&shared) };
    let cx = Cx::for_testing();
    let mut wait = client.submit(&cx, Operation::Ready).unwrap();
    let dequeued = shared.mailbox.lock().queue.pop_front().unwrap();
    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&counter));
    assert!(Pin::new(&mut wait).poll(&mut Context::from_waker(&waker)).is_pending());
    shared.close();
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(matches!(Pin::new(&mut wait).poll(&mut Context::from_waker(&waker)), Poll::Ready(Err(DynamicControlError::Closed))));
    drop(dequeued);
    drop(wait);
    assert_eq!(client.outstanding_requests(), 0);
}

#[test]
fn dropped_service_handle_closes_clients_and_parent_region_still_drains_workers() {
    run_case(|cx| async move {
        let service = cx.spawn_dynamic_supervisor_service::<&'static str>(DynamicServiceConfig::new(1, 2)).unwrap();
        let client = service.client();
        client.start_worker(&cx, "worker", config(), parked).await.unwrap();
        drop(service);
        assert!(matches!(client.ready(&cx).await, Err(DynamicControlError::Closed)));
        // The service task and all its work still belong to this runtime region.
        // Explicitly observe its route retirement before returning the test parent.
        eventually(|| client.children().is_empty()).await;
    });
}
