#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::mpsc;
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::RuntimeState;
use crate::supervision::{
    BackoffStrategy, ChildSpec, ManagedChildBinding, ManagedChildFactory, ManagedGeneration,
    ManagedRestartMode, RestartPolicy, SupervisionConfig, SupervisorBuilder,
};
use crate::types::{Budget, Outcome, TaskId};
use std::sync::atomic::{AtomicUsize, Ordering};

fn legacy_must_not_run(
    _: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
    _: &mut RuntimeState,
    _: &Cx,
) -> Result<TaskId, SpawnError> {
    panic!("dynamic managed admission must not invoke legacy ChildStart")
}

fn managed<E: 'static>(
    factory: impl ManagedChildFactory<E>,
    mode: ManagedRestartMode,
) -> ManagedSupervisor<E> {
    SupervisorBuilder::new("dynamic-test-tree")
        .with_restart_policy(RestartPolicy::OneForOne)
        .child(ChildSpec::new("worker", legacy_must_not_run))
        .compile().unwrap()
        .bind_managed(
            vec![ManagedChildBinding::new("worker", mode, factory)],
            SupervisionConfig::new(3, std::time::Duration::from_secs(60))
                .with_restart_policy(RestartPolicy::OneForOne)
                .with_backoff(BackoffStrategy::None),
        ).unwrap()
}

fn done() -> ManagedSupervisor<String> {
    managed(|_: Cx, _: ManagedGeneration| async { Outcome::Ok(()) }, ManagedRestartMode::Temporary)
}

fn parked(started: Arc<AtomicUsize>, stopped: Arc<AtomicUsize>) -> ManagedSupervisor<String> {
    managed(move |cx: Cx, _: ManagedGeneration| {
        let started = Arc::clone(&started);
        let stopped = Arc::clone(&stopped);
        async move {
            let (_keep_sender, mut receiver) = mpsc::channel::<()>(1);
            started.fetch_add(1, Ordering::SeqCst);
            let error = receiver.recv(&cx).await.expect_err("only cancellation ends this worker");
            assert!(matches!(error, mpsc::RecvError::Cancelled));
            stopped.fetch_add(1, Ordering::SeqCst);
            Outcome::Cancelled(cx.cancel_reason().expect("actual child cancellation"))
        }
    }, ManagedRestartMode::Transient)
}

fn clean(lab: &mut LabRuntime, root: RegionId) {
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state
            .cancel_request(root, &CancelReason::user("dynamic test finished"), None)
            .into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

fn run_case<F, Fut, T>(factory: F) -> T
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0xd1_0001).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered dynamic owner")).await
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    let result = join.try_join().unwrap().expect("dynamic owner completed within lab step bound");
    clean(&mut lab, root);
    result
}

async fn wait_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..512 {
        if counter.load(Ordering::SeqCst) == expected { return; }
        crate::runtime::yield_now().await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), expected, "worker must actually run");
}

#[test]
fn detached_owner_refuses_without_minting_a_fake_supervisor() {
    let cx = Cx::detached_cancel_context();
    let mut opening = std::pin::pin!(cx.open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(1)));
    let mut task_cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(opening.as_mut().poll(&mut task_cx),
        Poll::Ready(Err(DynamicSupervisorError::Region(error)))
            if matches!(&*error, ChildRegionError::NoRuntimeGateway)));
}

#[test]
fn zero_capacity_and_invalid_names_never_construct_a_worker() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(0)).await.unwrap();
        assert!(matches!(owner.start_child("x", done()).await, Err(DynamicSupervisorError::Capacity)));
        assert!(matches!(owner.start_child("", done()).await, Err(DynamicSupervisorError::InvalidName)));
        assert!(matches!(owner.start_child("x".repeat(256), done()).await, Err(DynamicSupervisorError::InvalidName)));
        assert!(owner.is_empty());
        assert_eq!(owner.capacity(), 0);
        assert!(owner.next_completed().await.unwrap().is_none());
        let report = owner.shutdown().await;
        assert!(report.children.is_empty());
        assert!(report.close.is_ok());
    });
}

#[test]
fn independent_children_preserve_typed_errors_and_keep_siblings_running() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(2)).await.unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let live = owner.start_child("live", parked(Arc::clone(&started), Arc::clone(&stopped))).await.unwrap();
        wait_count(&started, 1).await;
        let failing = managed(|_: Cx, _: ManagedGeneration| async {
            Outcome::Err(String::from("exact application failure"))
        }, ManagedRestartMode::Temporary);
        let failed = owner.start_child("failed", failing).await.unwrap();
        assert_ne!(failed.region_id(), live.region_id());
        let completion = owner.wait_child(&failed).await.unwrap();
        assert!(completion.close.is_ok());
        let report = completion.supervisor.unwrap();
        assert!(matches!(&report.children[0].outcome,
            Outcome::Err(message) if message == "exact application failure"));
        assert_eq!(report.started, report.joined);
        assert_eq!(owner.len(), 1);
        assert_eq!(stopped.load(Ordering::SeqCst), 0, "independent sibling remains live");
        assert_eq!(owner.children()[0].id, live);
        assert_eq!(owner.children()[0].id, live, "inspection never consumes state");
        let completion = owner.terminate_child(&live).await.unwrap();
        assert!(completion.stop_requested);
        assert!(completion.close.is_ok());
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn completed_unreaped_names_hold_capacity_and_stale_ids_cannot_stop_replacements() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(1)).await.unwrap();
        let old = owner.start_child("service", done()).await.unwrap();
        for _ in 0..32 { crate::runtime::yield_now().await; }
        assert!(matches!(owner.start_child("service", done()).await, Err(DynamicSupervisorError::DuplicateName)));
        assert!(matches!(owner.start_child("other", done()).await, Err(DynamicSupervisorError::Capacity)));
        let first = owner.wait_child(&old).await.unwrap();
        assert_eq!(first.id, old);
        assert!(first.close.is_ok());
        assert!(matches!(owner.wait_child(&old).await, Err(DynamicSupervisorError::StaleChild)));
        let replacement = owner.start_child("service", done()).await.unwrap();
        assert!(replacement.generation() > old.generation());
        assert_ne!(replacement.region_id(), old.region_id());
        assert!(matches!(owner.request_stop(&old), Err(DynamicSupervisorError::StaleChild)));
        assert_eq!(owner.children()[0].state, DynamicChildState::Submitted);
        let mut foreign = cx.open_dynamic_supervisor::<String>(DynamicSupervisorConfig::new(1)).await.unwrap();
        assert!(matches!(foreign.request_stop(&replacement), Err(DynamicSupervisorError::StaleChild)));
        assert!(foreign.shutdown().await.close.is_ok());
        owner.wait_child(&replacement).await.unwrap();
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn shutdown_seals_admission_and_stops_all_controllers_before_joining() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(3)).await.unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        for name in ["z", "a", "m"] {
            owner.start_child(name, parked(Arc::clone(&started), Arc::clone(&stopped))).await.unwrap();
        }
        wait_count(&started, 3).await;
        owner.begin_shutdown();
        owner.begin_shutdown();
        assert!(owner.is_closing());
        assert!(owner.children().iter().all(|child| child.state == DynamicChildState::Stopping));
        assert!(matches!(owner.start_child("new", done()).await, Err(DynamicSupervisorError::Closing)));
        let report = owner.shutdown().await;
        assert_eq!(report.children.iter().map(|child| child.id.name()).collect::<Vec<_>>(), ["a", "m", "z"]);
        assert_eq!(stopped.load(Ordering::SeqCst), 3);
        assert!(report.close.is_ok());
        for completion in report.children {
            assert!(completion.stop_requested);
            assert!(completion.close.is_ok());
            let managed = completion.supervisor.unwrap();
            assert_eq!(managed.started, 1);
            assert_eq!(managed.joined, 1);
            assert_eq!(managed.restart_batches, 0, "owner shutdown must not resurrect a transient worker");
        }
    });
}

#[test]
fn dropping_an_owner_keeps_children_under_the_enclosing_region_barrier() {
    run_case(|cx| async move {
        let enclosing = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let mut owner = enclosing.cx().open_dynamic_supervisor(DynamicSupervisorConfig::new(1)).await.unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        owner.start_child("live", parked(Arc::clone(&started), Arc::clone(&stopped))).await.unwrap();
        wait_count(&started, 1).await;
        drop(owner);
        enclosing.close().await.unwrap();
        assert_eq!(stopped.load(Ordering::SeqCst), 1, "the parent barrier must drain the real worker");
    });
}

#[path = "lifecycle_tests.rs"]
mod lifecycle;
