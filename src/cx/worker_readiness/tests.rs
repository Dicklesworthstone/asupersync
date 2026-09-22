use super::*;
use crate::channel::oneshot;
use crate::types::CancelKind;
use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

fn generation(cx: &Cx, number: u64) -> ManagedGeneration {
    ManagedGeneration { number, region: cx.region_id(), task: cx.task_id() }
}

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn counter() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    (Arc::clone(&counter), Waker::from(counter))
}

fn held() -> (impl ManagedChildFactory<&'static str>, WorkerReadiness) {
    initialized_worker(
        |_, _| async { Outcome::Ok(Cell::new(7_u8)) },
        |_, _, state| async move {
            let _state = state;
            std::future::pending::<Outcome<(), &'static str>>().await
        },
    )
}

#[test]
fn readiness_requires_completed_initialization_and_run_construction() {
    let cx = Cx::for_testing();
    let (release, receiving) = oneshot::channel::<()>();
    let incoming = Arc::new(Mutex::new(Some(receiving)));
    let calls = Arc::new(AtomicUsize::new(0));
    let initialized = Arc::clone(&calls);
    let slot = Arc::new(OnceLock::<WorkerReadiness>::new());
    let seen = Arc::clone(&slot);
    let (factory, readiness) = initialized_worker(
        move |_, _| {
            initialized.fetch_add(1, Ordering::SeqCst);
            let mut incoming = incoming.lock().take().unwrap();
            async move {
                incoming.recv_uninterruptible().await.unwrap();
                Outcome::<_, &'static str>::Ok(Cell::new(41_u8))
            }
        },
        move |_, _, state| {
            assert_eq!(seen.get().unwrap().state().phase, WorkerReadinessPhase::Initializing);
            assert_eq!(state.get(), 41);
            async move {
                let _state = state;
                std::future::pending::<Outcome<(), &'static str>>().await
            }
        },
    );
    slot.set(readiness.clone()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::NotStarted);
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "constructing the wrapper invokes no initializer");
    let (wakes, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(body.as_mut().poll(&mut task).is_pending());
    let mut waiting = Box::pin(readiness.wait_ready(&cx));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send_blocking(()).unwrap();
    assert!(body.as_mut().poll(&mut task).is_pending());
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    let Poll::Ready(Ok(ready)) = waiting.as_mut().poll(&mut task) else { panic!("initialized worker ready") };
    assert_eq!(ready.generation(), generation(&cx, 1));
    assert!(readiness.is_current(&ready));
    drop(waiting);
    drop(body);
    assert!(!readiness.is_current(&ready));
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
    drop(factory);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
}

#[test]
fn initialization_error_preserves_send_only_error_and_never_runs() {
    let cx = Cx::for_testing();
    let (factory, readiness) = initialized_worker(
        |_, _| async { Outcome::<Cell<u8>, _>::Err(Cell::new(93_u8)) },
        |_, _, _| -> std::future::Ready<Outcome<(), Cell<u8>>> { panic!("run after failed startup") },
    );
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    let Poll::Ready(Outcome::Err(error)) = body.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    else { panic!("original typed initialization error must return") };
    assert_eq!(error.get(), 93);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
}

struct PanicInit { poll: bool, retirement: bool }
impl Future for PanicInit {
    type Output = Outcome<Cell<u8>, &'static str>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.poll, "initializer poll panic");
        Poll::Ready(Outcome::Ok(Cell::new(7)))
    }
}
impl Drop for PanicInit {
    fn drop(&mut self) {
        assert!(!std::mem::take(&mut self.retirement), "initializer retirement panic");
    }
}

#[test]
fn all_initializer_panic_boundaries_withdraw_without_publishing_ready() {
    for boundary in 0..3 {
        let cx = Cx::for_testing();
        let (factory, readiness) = initialized_worker(
            move |_, _| {
                assert_ne!(boundary, 0, "initializer factory panic");
                PanicInit { poll: boundary == 1, retirement: boundary == 2 }
            },
            |_, _, _| -> std::future::Ready<Outcome<(), &'static str>> { panic!("run after initializer panic") },
        );
        let mut body = factory.start(cx.clone(), generation(&cx, 1));
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = body.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        }));
        assert!(failed.is_err());
        drop(body);
        assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
        drop(factory);
        assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
    }
}

#[test]
fn run_constructor_panic_is_not_successful_readiness() {
    let cx = Cx::for_testing();
    let (factory, readiness) = initialized_worker(
        |_, _| async { Outcome::<_, ()>::Ok(7_u8) },
        |_, _, _| -> std::future::Ready<Outcome<(), ()>> { panic!("run constructor panic") },
    );
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = body.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    })).is_err());
    drop(body);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
}

#[test]
fn late_success_after_cancel_hands_state_to_run_but_never_becomes_ready() {
    let cx = Cx::for_testing();
    let (release, incoming) = oneshot::channel::<()>();
    let incoming = Arc::new(Mutex::new(Some(incoming)));
    let released = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&released);
    let (factory, readiness) = initialized_worker(
        move |_, _| {
            let mut incoming = incoming.lock().take().unwrap();
            async move {
                incoming.recv_uninterruptible().await.unwrap();
                Outcome::<_, ()>::Ok(Cell::new(67_u8))
            }
        },
        move |cx, _, state| {
            observed.store(usize::from(state.get()), Ordering::SeqCst);
            async move {
                assert!(cx.checkpoint().is_err());
                Outcome::Cancelled(cx.cancel_reason().unwrap())
            }
        },
    );
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    let mut task = Context::from_waker(Waker::noop());
    assert!(body.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(body.as_mut().poll(&mut task).is_pending());
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Stopping);
    release.send_blocking(()).unwrap();
    assert!(matches!(body.as_mut().poll(&mut task), Poll::Ready(Outcome::Cancelled(_))));
    assert_eq!(released.load(Ordering::SeqCst), 67, "late state handed to its cleanup owner");
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
}

#[test]
fn cancellation_wakes_and_withdraws_ready_even_with_a_blind_parked_body() {
    let cx = Cx::for_testing();
    let (factory, readiness) = held();
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    let (wakes, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(body.as_mut().poll(&mut task).is_pending());
    let ready = futures_lite::future::block_on(readiness.wait_ready(&cx)).unwrap();
    cx.cancel_fast(CancelKind::User);
    assert!(wakes.0.load(Ordering::SeqCst) > 0, "wrapper registered real cancellation wake");
    assert!(body.as_mut().poll(&mut task).is_pending(), "no forced drop of a blind future");
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Stopping);
    assert!(!readiness.is_current(&ready));
    drop(body);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
}

#[test]
fn replacement_wait_ignores_old_readiness_and_refuses_foreign_observations() {
    let cx = Cx::for_testing();
    let (factory, readiness) = held();
    let mut first = factory.start(cx.clone(), generation(&cx, 1));
    let mut task = Context::from_waker(Waker::noop());
    assert!(first.as_mut().poll(&mut task).is_pending());
    let old = futures_lite::future::block_on(readiness.wait_ready(&cx)).unwrap();
    let (_foreign_factory, foreign) = held();
    assert!(matches!(futures_lite::future::block_on(foreign.wait_ready_after(&cx, &old)),
        Err(WorkerReadinessError::ForeignObservation)));
    let mut waiting = Box::pin(readiness.wait_ready_after(&cx, &old));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    drop(first);
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    let mut second = factory.start(cx.clone(), generation(&cx, 2));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert!(second.as_mut().poll(&mut task).is_pending());
    let Poll::Ready(Ok(new)) = waiting.as_mut().poll(&mut task) else { panic!("replacement ready") };
    assert_eq!(new.generation().number, 2);
    assert!(!readiness.is_current(&old));
    assert!(readiness.is_current(&new));
}

#[test]
fn stale_overlapping_and_mismatched_identities_fail_closed() {
    for scenario in 0..4 {
        let cx = Cx::for_testing();
        let (factory, readiness) = held();
        let mut task = Context::from_waker(Waker::noop());
        let mut first = Some(factory.start(cx.clone(), generation(&cx, 1)));
        assert!(first.as_mut().unwrap().as_mut().poll(&mut task).is_pending());
        let mut next = generation(&cx, 2);
        if scenario != 0 { drop(first.take()); }
        if scenario == 1 { next.number = 1; }
        if scenario == 2 { next.number = 0; }
        if scenario == 3 {
            next.task = crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(100, 100));
        }
        let mut invalid = factory.start(cx.clone(), next);
        assert!(matches!(invalid.as_mut().poll(&mut task), Poll::Ready(Outcome::Panicked(_))));
        assert!(matches!(futures_lite::future::block_on(readiness.wait_ready(&cx)),
            Err(WorkerReadinessError::InvalidGeneration)));
        drop(first);
        drop(factory);
        assert_eq!(readiness.state().phase, WorkerReadinessPhase::InvalidGeneration);
    }
}

#[test]
fn cancelling_and_dropping_observers_never_stops_worker_or_removes_peer_waiters() {
    let worker = Cx::for_testing();
    let observer = Cx::for_testing();
    let retained = Cx::for_testing();
    let (factory, readiness) = held();
    let peer = readiness.clone();
    let mut task = Context::from_waker(Waker::noop());
    let mut cancelled = Box::pin(readiness.wait_ready(&observer));
    let mut waiting = Box::pin(peer.wait_ready(&retained));
    assert!(cancelled.as_mut().poll(&mut task).is_pending());
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(readiness.shared.changed.waiter_count(), 2);
    observer.cancel_fast(CancelKind::User);
    assert!(matches!(cancelled.as_mut().poll(&mut task), Poll::Ready(Err(WorkerReadinessError::Cancelled))));
    drop(cancelled);
    assert_eq!(readiness.shared.changed.waiter_count(), 1);
    assert!(!worker.is_cancel_requested());
    let mut body = factory.start(worker.clone(), generation(&worker, 1));
    assert!(body.as_mut().poll(&mut task).is_pending());
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Ok(_))));
    drop(waiting);
    assert_eq!(readiness.shared.changed.waiter_count(), 0);
}

struct HostileWake;
impl Wake for HostileWake {
    fn wake(self: Arc<Self>) { panic!("observer callback panic"); }
}

#[test]
fn factory_abandonment_notifies_every_waiter_despite_a_hostile_callback() {
    let cx = Cx::for_testing();
    let (factory, readiness) = held();
    let mut first = Box::pin(readiness.wait_ready(&cx));
    let mut second = Box::pin(readiness.wait_ready(&cx));
    let hostile = Waker::from(Arc::new(HostileWake));
    let (wakes, waker) = counter();
    assert!(first.as_mut().poll(&mut Context::from_waker(&hostile)).is_pending());
    assert!(second.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(factory);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(second.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(WorkerReadinessError::Closed))));
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
}

#[test]
fn active_generation_outlives_factory_until_its_body_is_retired() {
    let cx = Cx::for_testing();
    let (factory, readiness) = held();
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    assert!(body.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(factory);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Ready);
    let ready = futures_lite::future::block_on(readiness.wait_ready(&cx)).unwrap();
    drop(body);
    assert!(!readiness.is_current(&ready));
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
}

#[test]
fn pre_cancelled_generation_skips_initializer_and_run() {
    let cx = Cx::for_testing();
    let (factory, readiness) = initialized_worker(
        |_, _| -> std::future::Ready<Outcome<u8, ()>> { panic!("cancelled initializer invoked") },
        |_, _, _| -> std::future::Ready<Outcome<(), ()>> { panic!("cancelled run invoked") },
    );
    cx.cancel_fast(CancelKind::User);
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    assert!(matches!(body.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Outcome::Cancelled(_))));
    assert!(readiness.try_ready().unwrap().is_none());
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
}

struct RunRetirementPanic;
impl Future for RunRetirementPanic {
    type Output = Outcome<(), ()>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Outcome::Ok(()))
    }
}
impl Drop for RunRetirementPanic {
    fn drop(&mut self) { panic!("run retirement panic"); }
}

#[test]
fn run_retirement_panic_cannot_leave_stale_readiness() {
    let cx = Cx::for_testing();
    let (factory, readiness) = initialized_worker(
        |_, _| async { Outcome::<_, ()>::Ok(()) },
        |_, _, ()| RunRetirementPanic,
    );
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = body.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    })).is_err());
    drop(body);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Retired);
    assert!(readiness.try_ready().unwrap().is_none());
}

struct ReentrantWake { readiness: WorkerReadiness, wakes: AtomicUsize }
impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        assert!(self.readiness.shared.state.try_lock().is_some(), "observer invoked under readiness lock");
        let _ = self.readiness.try_ready();
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn ready_publication_permits_reentrant_observation_without_state_lock() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<WorkerReadiness>();
    send_sync::<ReadyWorker>();
    let cx = Cx::for_testing();
    let (factory, readiness) = held();
    let wake = Arc::new(ReentrantWake { readiness: readiness.clone(), wakes: AtomicUsize::new(0) });
    let waker = Waker::from(Arc::clone(&wake));
    let mut waiting = Box::pin(readiness.wait_ready(&cx));
    assert!(waiting.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    let mut body = factory.start(cx.clone(), generation(&cx, 1));
    assert!(body.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    assert!(wake.wakes.load(Ordering::SeqCst) > 0);
    assert!(readiness.try_ready().unwrap().is_some());
    assert!(matches!(waiting.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Ok(_))));
}

fn lab_case<F, Fut>(factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    use crate::lab::{LabConfig, LabRuntime};
    use crate::types::Budget;
    let mut lab = LabRuntime::new(LabConfig::new(0x5ead_1e55).max_steps(16_384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("real initialized-worker owner")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join().unwrap().expect("bounded initialized-worker lab journey completes");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::shutdown(), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
}

#[test]
fn real_dynamic_initialization_failure_keeps_original_typed_error() {
    lab_case(|cx| async move {
        use crate::cx::DynamicSupervisorConfig;
        use crate::supervision::{ManagedRestartMode, SupervisionConfig};
        use std::time::Duration;
        let mut supervisor = cx.open_dynamic_supervisor::<Cell<u8>>(DynamicSupervisorConfig::new(1)).await.unwrap();
        let policy = DynamicWorkerConfig::new(ManagedRestartMode::Temporary, SupervisionConfig::new(1, Duration::from_secs(30)));
        let (id, readiness) = supervisor.start_initialized_worker("failed-startup", policy,
            |_, _| async { Outcome::<Cell<u8>, _>::Err(Cell::new(79)) },
            |_, _, _| -> std::future::Ready<Outcome<(), Cell<u8>>> { panic!("run after failed initialization") },
        ).await.unwrap();
        assert!(matches!(readiness.wait_ready(&cx).await, Err(WorkerReadinessError::Closed)));
        let completion = supervisor.wait_child(&id).await.unwrap();
        assert!(completion.close.is_ok());
        let report = completion.supervisor.unwrap();
        assert_eq!((report.started, report.joined, report.restart_batches), (1, 1, 0));
        assert!(matches!(&report.children[0].outcome, Outcome::Err(error) if error.get() == 79));
        assert!(supervisor.shutdown().await.close.is_ok());
    });
}

#[test]
fn zero_capacity_admission_never_runs_initializer() {
    lab_case(|cx| async move {
        use crate::cx::DynamicSupervisorConfig;
        use crate::supervision::{ManagedRestartMode, SupervisionConfig};
        use std::time::Duration;
        let mut supervisor = cx.open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(0)).await.unwrap();
        let policy = DynamicWorkerConfig::new(ManagedRestartMode::Temporary, SupervisionConfig::new(1, Duration::from_secs(30)));
        let refused = supervisor.start_initialized_worker("refused", policy,
            |_, _| -> std::future::Ready<Outcome<(), ()>> { panic!("initializer admission bypass") },
            |_, _, ()| -> std::future::Ready<Outcome<(), ()>> { panic!("run admission bypass") },
        ).await;
        assert!(matches!(refused, Err(DynamicSupervisorError::Capacity)));
        assert_eq!(supervisor.len(), 0);
        assert!(supervisor.shutdown().await.close.is_ok());
    });
}
