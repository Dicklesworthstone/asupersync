use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::supervision::{
    BackoffStrategy, ChildSpec, ChildStart, ManagedChildBinding, ManagedChildFuture,
    ManagedGeneration, ManagedRestartMode, RestartPolicy, SupervisionConfig, SupervisorBuilder,
};
use crate::types::{Budget, Outcome};
use std::sync::atomic::AtomicUsize;
use std::task::Wake;
use std::time::Duration;

#[path = "unstarted_admission_tests.rs"]
mod unstarted_admission_tests;

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
        assert_eq!(client.outstanding_requests(), 0, "claimed admission returns credit before Ready");
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
        assert_eq!(client.outstanding_requests(), 0, "claimed admission returns credit before Ready");
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

fn standalone_client(limit: usize) -> DynamicSupervisorClient<()> {
    DynamicSupervisorClient {
        shared: Arc::new(Shared {
            mailbox: Mutex::new(Mailbox {
                queue: VecDeque::new(),
                routes: BTreeMap::new(),
                requests: Vec::new(),
            }),
            credits: Arc::new(Credits {
                active: AtomicUsize::new(0),
                limit,
            }),
            signal: Arc::new(Signal::default()),
        }),
    }
}

struct QueuedFactory {
    label: &'static str,
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    shared: Weak<Shared<()>>,
    panic_on_drop: bool,
    expect_shutdown: bool,
}

impl QueuedFactory {
    fn new(
        client: &DynamicSupervisorClient<()>,
        started: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicUsize>,
        label: &'static str,
        panic_on_drop: bool,
    ) -> Self {
        Self {
            label,
            started: Arc::clone(started),
            dropped: Arc::clone(dropped),
            shared: Arc::downgrade(&client.shared),
            panic_on_drop,
            expect_shutdown: true,
        }
    }

    fn record_start(&self) {
        self.started.fetch_add(1, Ordering::SeqCst);
    }
}

impl ManagedChildFactory<()> for QueuedFactory {
    fn start(&self, _: Cx, _: ManagedGeneration) -> ManagedChildFuture<()> {
        self.record_start();
        Box::pin(async { Outcome::Ok(()) })
    }
}

impl ChildStart for QueuedFactory {
    fn start(
        &mut self,
        _: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        _: &mut crate::runtime::RuntimeState,
        _: &Cx,
    ) -> Result<TaskId, SpawnError> {
        self.record_start();
        Err(SpawnError::RuntimeUnavailable)
    }
}

impl Drop for QueuedFactory {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
        let shared = self.shared.upgrade().expect("service still owns shutdown");
        let mailbox = shared.mailbox.try_lock().expect("factory retires unlocked");
        if self.expect_shutdown {
            assert!(shared.signal.closed.load(Ordering::Acquire));
            assert!(
                mailbox.queue.is_empty(),
                "detach the complete batch before callbacks"
            );
        }
        drop(mailbox);
        assert!(!self.panic_on_drop, "queued factory {}", self.label);
    }
}

#[test]
fn closing_retires_each_queued_worker_before_resuming_first_drop_panic() {
    let client = standalone_client(3);
    let cx = Cx::for_testing();
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let notified = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&notified));
    let mut poll_cx = Context::from_waker(&waker);
    let mut waits = Vec::new();
    for (label, panics) in [("first", true), ("second", true), ("abandoned", false)] {
        let factory = QueuedFactory::new(&client, &started, &dropped, label, panics);
        let mut wait = Box::pin(client.start_worker(&cx, label, config(), factory));
        assert!(wait.as_mut().poll(&mut poll_cx).is_pending());
        waits.push(wait);
    }
    drop(waits.pop().unwrap());
    let controller = Arc::new(CountWake::default());
    client
        .shared
        .signal
        .register(&Waker::from(Arc::clone(&controller)));
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.shared.close();
    }))
    .expect_err("preserve the first factory panic after complete retirement");
    assert_eq!(
        failure.downcast_ref::<String>().map(String::as_str),
        Some("queued factory first")
    );
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 3);
    assert_eq!(notified.0.load(Ordering::SeqCst), 2);
    assert_eq!(controller.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.outstanding_requests(),
        2,
        "abandoned request credit returned"
    );
    for wait in &mut waits {
        assert!(matches!(
            wait.as_mut().poll(&mut poll_cx),
            Poll::Ready(Err(DynamicControlError::Closed))
        ));
    }
    assert_eq!(client.outstanding_requests(), 0);
    assert!(client.shared.mailbox.lock().queue.is_empty());
    client.shared.close();
    eprintln!("dynamic_service_shutdown case=queued_workers started=0 retired=3 requests=0");
}

#[test]
fn closing_retires_every_capture_in_a_queued_managed_tree() {
    let client = standalone_client(1);
    let cx = Cx::for_testing();
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut builder =
        SupervisorBuilder::new("queued-tree").with_restart_policy(RestartPolicy::OneForOne);
    let mut bindings = Vec::new();
    for (name, legacy, factory, observer) in [
        ("first", "legacy-first", "factory-first", "observer-first"),
        ("second", "legacy-second", "factory-second", "observer-second"),
    ] {
        builder = builder.child(ChildSpec::new(
            name,
            QueuedFactory::new(&client, &started, &dropped, legacy, true),
        ));
        let observer = QueuedFactory::new(&client, &started, &dropped, observer, true);
        bindings.push(
            ManagedChildBinding::new(
                name,
                ManagedRestartMode::Temporary,
                QueuedFactory::new(&client, &started, &dropped, factory, true),
            )
            .with_cleanup_observer(Arc::new(move |_| {
                observer.record_start();
                None
            })),
        );
    }
    let supervisor = builder
        .compile()
        .unwrap()
        .bind_managed(
            bindings,
            SupervisionConfig::new(0, Duration::from_secs(60))
                .with_restart_policy(RestartPolicy::OneForOne),
        )
        .unwrap();
    let notified = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&notified));
    let mut poll_cx = Context::from_waker(&waker);
    let mut wait = Box::pin(client.start_child(&cx, "tree", supervisor));
    assert!(wait.as_mut().poll(&mut poll_cx).is_pending());
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.shared.close();
    }))
    .expect_err("all six independent captures retire before the first panic resumes");
    assert_eq!(
        failure.downcast_ref::<String>().map(String::as_str),
        Some("queued factory legacy-first")
    );
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 6);
    assert_eq!(notified.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        wait.as_mut().poll(&mut poll_cx),
        Poll::Ready(Err(DynamicControlError::Closed))
    ));
    assert_eq!(client.outstanding_requests(), 0);
    eprintln!("dynamic_service_shutdown case=queued_tree started=0 retired=6 requests=0");
}

#[test]
#[allow(clippy::too_many_lines)]
fn service_shutdown_and_owner_unwind_still_drain_live_workers() {
    for owner_unwind in [false, true] {
        run_case(move |cx| async move {
            let service = cx
                .spawn_dynamic_supervisor_service::<()>(DynamicServiceConfig::new(3, 3))
                .unwrap();
            let client = service.client();
            let running = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&running);
            client
                .start_worker(&cx, "live", config(), move |cx: Cx, _: ManagedGeneration| {
                    let observed = Arc::clone(&observed);
                    async move {
                        observed.store(true, Ordering::Release);
                        cx.cancelled().await;
                        Outcome::<(), ()>::Cancelled(cx.cancel_reason().unwrap())
                    }
                })
                .await
                .unwrap();
            eventually(|| running.load(Ordering::Acquire)).await;
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut first = Box::pin(client.start_worker(
                &cx,
                "first",
                config(),
                QueuedFactory::new(&client, &started, &dropped, "first", true),
            ));
            let mut second = Box::pin(client.start_worker(
                &cx,
                "second",
                config(),
                QueuedFactory::new(&client, &started, &dropped, "second", true),
            ));
            let notified = Arc::new(CountWake::default());
            let waker = Waker::from(Arc::clone(&notified));
            assert!(
                first
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert!(
                second
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            // No scheduler turn after these polls: both public start calls
            // are in the real controller mailbox when shutdown begins.
            if owner_unwind {
                let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _owner = service;
                    panic!("original owner unwind");
                }))
                .expect_err("owner panic survives cleanup failures");
                assert_eq!(
                    failure.downcast_ref::<&str>().copied(),
                    Some("original owner unwind")
                );
            } else {
                let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    service.request_shutdown();
                }))
                .expect_err("explicit shutdown preserves the first factory panic");
                assert_eq!(
                    failure.downcast_ref::<String>().map(String::as_str),
                    Some("queued factory first")
                );
                let exit = service.join().await;
                assert!(matches!(
                    exit.task_outcome,
                    Ok(()) | Err(JoinError::Cancelled(_))
                ));
                let mut report = exit.report.expect("controller reached shutdown").unwrap();
                assert!(report.close.is_ok());
                assert_eq!(report.children.len(), 1);
                stopped(report.children.pop().unwrap());
            }
            assert!(client.is_closed());
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 2);
            assert!(matches!(
                first.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(DynamicControlError::Closed))
            ));
            assert!(matches!(
                second.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(DynamicControlError::Closed))
            ));
            assert_eq!(client.outstanding_requests(), 0);
            eventually(|| client.children().is_empty()).await;
            eprintln!(
                "dynamic_service_shutdown case=live_service owner_unwind={owner_unwind} \
                 queued_started=0 retired=2 requests=0"
            );
        });
    }
}

struct ShutdownWake {
    wakes: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Wake for ShutdownWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        panic!("shutdown wake callback");
    }
}

impl Drop for ShutdownWake {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        panic!("shutdown wake final owner");
    }
}

#[test]
fn closing_contains_wake_and_final_waker_retirement_panics() {
    let client = standalone_client(1);
    let cx = Cx::for_testing();
    let mut wait = client.submit(&cx, Operation::Ready).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let make_waker = || {
        Waker::from(Arc::new(ShutdownWake {
            wakes: Arc::clone(&wakes),
            drops: Arc::clone(&drops),
        }))
    };
    // Each stored Waker is its final owner. Polling the waiter first would
    // retain another clone in its Cx cancellation registration and hide this.
    wait.request.reply.lock().waker = Some(make_waker());
    *client.shared.signal.waker.lock() = Some(make_waker());
    client.shared.close();
    assert_eq!(wakes.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    let waker = Waker::from(Arc::new(CountWake::default()));
    assert!(matches!(
        Pin::new(&mut wait).poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(DynamicControlError::Closed))
    ));
    assert_eq!(client.outstanding_requests(), 0);
    eprintln!("dynamic_service_shutdown case=panicking_wakers wakes=2 retired=2 requests=0");
}

fn panicking_tree_for_dequeue(
    client: &DynamicSupervisorClient<()>,
    started: &Arc<AtomicUsize>,
    dropped: &Arc<AtomicUsize>,
) -> ManagedSupervisor<()> {
    let mut builder =
        SupervisorBuilder::new("dequeued-tree").with_restart_policy(RestartPolicy::OneForOne);
    let mut bindings = Vec::new();
    for (name, legacy, factory) in [
        ("first", "legacy-first", "factory-first"),
        ("second", "legacy-second", "factory-second"),
    ] {
        let mut legacy = QueuedFactory::new(client, started, dropped, legacy, true);
        legacy.expect_shutdown = false;
        builder = builder.child(ChildSpec::new(name, legacy));
        let mut factory = QueuedFactory::new(client, started, dropped, factory, true);
        factory.expect_shutdown = false;
        bindings.push(ManagedChildBinding::new(
            name,
            ManagedRestartMode::Temporary,
            factory,
        ));
    }
    builder
        .compile()
        .unwrap()
        .bind_managed(
            bindings,
            SupervisionConfig::new(0, Duration::from_secs(60))
                .with_restart_policy(RestartPolicy::OneForOne),
        )
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn abandoned_or_refused_queued_trees_drain_accepted_work_before_panicking() {
    for case in [
        "abandoned",
        "capacity",
        "duplicate",
        "invalid-empty",
        "invalid-long",
    ] {
        run_case(move |cx| async move {
            let max_children = if matches!(case, "invalid-empty" | "invalid-long") {
                2
            } else {
                1
            };
            let service = cx
                .spawn_dynamic_supervisor_service::<()>(DynamicServiceConfig::new(max_children, 3))
                .unwrap();
            let client = service.client();
            let running = Arc::new(AtomicBool::new(false));
            let cleaned = Arc::new(AtomicBool::new(false));
            let entered = Arc::clone(&running);
            let completed = Arc::clone(&cleaned);
            client
                .start_worker(&cx, "live", config(), move |cx: Cx, _: ManagedGeneration| {
                    let entered = Arc::clone(&entered);
                    let completed = Arc::clone(&completed);
                    async move {
                        entered.store(true, Ordering::Release);
                        cx.cancelled().await;
                        // The controller must keep driving real asynchronous
                        // cleanup before publishing its own disposal panic.
                        crate::runtime::yield_now().await;
                        completed.store(true, Ordering::Release);
                        Outcome::<(), ()>::Cancelled(cx.cancel_reason().unwrap())
                    }
                })
                .await
                .unwrap();
            eventually(|| running.load(Ordering::Acquire)).await;
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
            let name = match case {
                "duplicate" => "live".to_owned(),
                "invalid-empty" => String::new(),
                "invalid-long" => "x".repeat(256),
                _ => "queued".to_owned(),
            };
            let mut pending = Some(Box::pin(client.start_child(&cx, name, tree)));
            let notified = Arc::new(CountWake::default());
            let waker = Waker::from(Arc::clone(&notified));
            assert!(
                pending
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            if case == "abandoned" {
                drop(pending.take());
            }
            let mut queued_ready = client.submit(&cx, Operation::Ready).unwrap();
            assert!(
                Pin::new(&mut queued_ready)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );

            // Unlike explicit shutdown, join never requests the stop. The
            // controller itself must discover the disposal failure and drain.
            let exit = service.join().await;
            let Err(JoinError::Panicked(payload)) = exit.task_outcome else {
                panic!("{case}: queued disposal must remain a controller panic");
            };
            assert_eq!(payload.message(), "queued factory legacy-first", "{case}");
            assert!(
                cleaned.load(Ordering::Acquire),
                "{case}: cleanup crossed Pending"
            );
            let mut report = exit.report.expect("shutdown report precedes panic").unwrap();
            assert!(report.close.is_ok(), "{case}");
            assert_eq!(report.children.len(), 1, "{case}");
            stopped(report.children.pop().unwrap());
            assert_eq!(started.load(Ordering::SeqCst), 0, "{case}");
            assert_eq!(dropped.load(Ordering::SeqCst), 4, "{case}");
            assert!(client.is_closed());
            assert!(client.children().is_empty());
            if let Some(mut pending) = pending {
                let Poll::Ready(Err(DynamicControlError::Child(error))) =
                    pending.as_mut().poll(&mut Context::from_waker(&waker))
                else {
                    panic!("{case}: preserve the queued admission refusal");
                };
                assert!(matches!(
                    (case, error.as_ref()),
                    ("capacity", DynamicSupervisorError::Capacity)
                        | ("duplicate", DynamicSupervisorError::DuplicateName)
                        | ("invalid-empty" | "invalid-long", DynamicSupervisorError::InvalidName)
                ));
            }
            assert!(matches!(
                Pin::new(&mut queued_ready).poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(DynamicControlError::Closed))
            ));
            assert_eq!(client.outstanding_requests(), 0, "{case}");
            eprintln!(
                "dynamic_service_dequeue case={case} queued_started=0 retired=4 \
                 accepted_drained=1 requests=0"
            );
        });
    }
}
