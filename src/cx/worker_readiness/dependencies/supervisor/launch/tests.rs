#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use super::super::{InitializedRunResult, InitializedChildBinding};
use crate::channel::oneshot;
use crate::cx::worker_readiness::WorkerReadinessPhase;
use crate::lab::{LabConfig, LabRuntime};
use crate::supervision::{BackoffStrategy, EscalationPolicy, ManagedGeneration, ManagedRestartMode, SupervisorBuilder};
use crate::types::Outcome;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;

// The entire work/close result remains typed, rather than being replaced by
// an opaque startup failure or requiring any user error to implement Clone.
type Failure = Box<InitializedRunResult<&'static str>>;

fn classify(result: InitializedRunResult<&'static str>) -> Outcome<(), Failure> {
    if result.as_ref().is_ok_and(|report| report.is_success()) {
        Outcome::Ok(())
    } else {
        Outcome::Err(Box::new(result))
    }
}

fn bind(bindings: Vec<InitializedChildBinding<Failure>>, max_restarts: u32) -> InitializedSupervisor<Failure> {
    let mut builder = SupervisorBuilder::new("startup-test");
    for binding in &bindings { builder = builder.child(binding.spec()); }
    let mut policy = SupervisionConfig::new(max_restarts, Duration::from_secs(60))
        .with_backoff(BackoffStrategy::None);
    policy.escalation = EscalationPolicy::Stop;
    builder.compile().unwrap().bind_initialized_owned(bindings, policy,
        InitializedTopologyLimits { max_children: 4, max_edges: 4 }).unwrap()
}

fn config(timeout: u64) -> InitializedStartConfig {
    InitializedStartConfig::new(Duration::from_millis(timeout), Budget::INFINITE)
}

fn run_case<F, Fut>(factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0x57_a271).max_steps(65536));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered startup test owner")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join().unwrap().expect("startup test finished in lab budget");
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

async fn witnessed<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut signal = Some(signal);
    poll_fn(|task| {
        let poll = future.as_mut().poll(task);
        if poll.is_pending() {
            if let Some(signal) = signal.take() { signal.send_blocking(()).unwrap(); }
        }
        poll
    }).await
}

fn idle(name: &'static str) -> InitializedChildBinding<Failure> {
    InitializedChildBinding::new(name, ManagedRestartMode::Temporary,
        |_, _| async { Outcome::<(), &'static str>::Ok(()) },
        |cx, _, ()| async move {
            cx.cancelled().await;
            assert!(cx.checkpoint().is_err());
            Outcome::<(), &'static str>::Cancelled(cx.cancel_reason().unwrap())
        }, classify)
}

#[test]
fn absolute_deadline_meets_parent_and_never_saturates_into_another_allowance() {
    assert_eq!(deadline(Time::from_nanos(10), Duration::from_nanos(15), None), Some(Time::from_nanos(25)));
    assert_eq!(deadline(Time::from_nanos(10), Duration::from_nanos(15), Some(Time::from_nanos(12))), Some(Time::from_nanos(12)));
    assert_eq!(deadline(Time::from_nanos(10), Duration::ZERO, None), Some(Time::from_nanos(10)));
    assert_eq!(deadline(Time::from_nanos(u64::MAX), Duration::from_nanos(1), None), None);
    assert_eq!(deadline(Time::ZERO, Duration::MAX, Some(Time::ZERO)), None);
}

#[test]
fn absent_timer_refuses_before_region_or_initializer_effects() {
    let cx = Cx::for_testing();
    let invoked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&invoked);
    let binding = InitializedChildBinding::new("never-started", ManagedRestartMode::Temporary,
        move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            async { Outcome::<(), &'static str>::Ok(()) }
        }, |_, _, ()| async { Outcome::<(), &'static str>::Ok(()) }, classify);
    let prepared = bind(vec![binding], 0);
    let readiness = prepared.readiness().clone();
    let error = futures_lite::future::block_on(prepared.start(&cx, config(1))).unwrap_err();
    assert!(matches!(error.cause, InitializedStartCause::NoTimer));
    assert!(error.cleanup.is_none());
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert_eq!(readiness.child("never-started").unwrap().state().phase, WorkerReadinessPhase::Closed);
}

#[test]
fn empty_topology_is_not_reported_as_a_running_service() {
    let cx = Cx::for_testing();
    let error = futures_lite::future::block_on(bind(Vec::new(), 0).start(&cx, config(1))).unwrap_err();
    assert!(matches!(error.cause, InitializedStartCause::EmptyTopology));
    assert!(error.cleanup.is_none());
}

#[test]
fn zero_startup_allowance_never_admits_a_worker() {
    run_case(|cx| async move {
        let initialized = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&initialized);
        let worker = InitializedChildBinding::new("zero", ManagedRestartMode::Temporary,
            move |_, _| {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Outcome::<(), &'static str>::Ok(()) }
            }, |_, _, ()| async { Outcome::<(), &'static str>::Ok(()) }, classify);
        let error = bind(vec![worker], 0).start(&cx, config(0)).await.unwrap_err();
        assert!(matches!(error.cause, InitializedStartCause::Deadline { .. }));
        assert!(error.cleanup.is_none());
        assert_eq!(initialized.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn successful_service_outlives_startup_allowance_and_joins_exact_typed_results() {
    run_case(|cx| async move {
        let mut running = bind(vec![idle("live")], 0).start(&cx, config(10)).await.unwrap();
        assert_eq!(running.initial_readiness().len(), 1);
        let timer = cx.timer_driver().unwrap();
        let later = timer.now().saturating_add_nanos(50_000_000);
        Sleep::with_timer_driver(later, timer).await;
        assert!(running.readiness().all().try_ready().unwrap().is_some(), "startup timer must not cancel a running service");
        assert!(running.initial_readiness().is_current());
        let exit = running.shutdown().await.unwrap();
        assert!(exit.stop_requested);
        assert!(exit.stop_error.is_none());
        assert!(exit.close.is_ok());
        let report = exit.controller.unwrap().unwrap();
        assert_eq!((report.started, report.joined), (1, 1));
        assert!(report.children[0].region_outcome.is_some());
        assert!(matches!(running.join().await, Err(JoinError::PolledAfterCompletion)));
    });
}

#[test]
fn failed_temporary_initialization_preserves_original_error_and_drains_live_sibling() {
    run_case(|cx| async move {
        let bad = InitializedChildBinding::new("bad", ManagedRestartMode::Temporary,
            |_, _| async { Outcome::<(), _>::Err("original initialization failure") },
            |_, _, ()| -> std::future::Ready<Outcome<(), &'static str>> { panic!("failed initializer must not run") }, classify);
        let prepared = bind(vec![bad, idle("survivor")], 0);
        let readiness = prepared.readiness().clone();
        let error = prepared.start(&cx, config(1000)).await.unwrap_err();
        assert!(matches!(error.cause, InitializedStartCause::Readiness(_) | InitializedStartCause::ControllerTerminated));
        let exit = error.cleanup.unwrap();
        assert!(exit.close.is_ok());
        let report = exit.controller.unwrap().unwrap();
        let bad = report.children.iter().find(|child| child.name.as_str() == "bad").unwrap();
        let Outcome::Err(original) = &bad.outcome else { panic!("typed startup failure missing"); };
        let original = original.as_ref().as_ref().unwrap();
        assert!(matches!(&original.work, Some(Ok(Outcome::Err("original initialization failure")))));
        assert!(original.close.is_ok());
        assert!(readiness.all().try_ready().is_err());
    });
}

#[test]
fn restart_budget_stop_cannot_leave_owned_startup_waiting_forever() {
    run_case(|cx| async move {
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let bad = InitializedChildBinding::new("stopped-transient", ManagedRestartMode::Transient,
            move |_, _| {
                count.fetch_add(1, Ordering::SeqCst);
                async { Outcome::<(), _>::Err("never ready") }
            }, |_, _, ()| async { Outcome::<(), &'static str>::Ok(()) }, classify);
        let error = bind(vec![bad, idle("live-sibling")], 0).start(&cx, config(10)).await.unwrap_err();
        assert!(matches!(error.cause, InitializedStartCause::Deadline { .. }));
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "no speculative restart outside the actual controller");
        let exit = error.cleanup.unwrap();
        assert!(exit.close.is_ok());
        let report = exit.controller.unwrap().unwrap();
        assert_eq!(report.restart_batches, 0);
        let bad = report.children.iter().find(|child| child.name.as_str() == "stopped-transient").unwrap();
        assert!(matches!(&bad.outcome, Outcome::Err(original)
            if matches!(&original.as_ref().as_ref().unwrap().work, Some(Ok(Outcome::Err("never ready"))))));
    });
}

#[test]
fn dropped_shutdown_wait_retains_the_same_pending_cleanup_and_report() {
    run_case(|cx| async move {
        let (release, gate) = oneshot::channel::<()>();
        let (parked, mut witness) = oneshot::channel();
        let cleanup = Arc::new(parking_lot::Mutex::new(Some((gate, parked))));
        let binding = InitializedChildBinding::new("cleanup", ManagedRestartMode::Temporary,
            |_, _| async { Outcome::<(), &'static str>::Ok(()) },
            move |worker, _: ManagedGeneration, ()| {
                let (mut gate, parked) = cleanup.lock().take().unwrap();
                async move {
                    worker.cancelled().await;
                    assert!(worker.checkpoint().is_err());
                    witnessed(poll_fn(|task| gate.poll_recv_uninterruptible(task)), parked).await.unwrap();
                    Outcome::<(), &'static str>::Cancelled(worker.cancel_reason().unwrap())
                }
            }, classify);
        let mut running = bind(vec![binding], 0).start(&cx, config(1000)).await.unwrap();
        {
            let mut stop = std::pin::pin!(running.shutdown());
            assert!(stop.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        witness.recv(&cx).await.unwrap();
        for _ in 0..3 {
            let mut join = std::pin::pin!(running.join());
            assert!(join.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        release.send_blocking(()).unwrap();
        let exit = running.join().await.unwrap();
        assert!(exit.close.is_ok());
        let report = exit.controller.unwrap().unwrap();
        assert_eq!((report.started, report.joined), (1, 1));
    });
}
