#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use super::super::{FactoryOwner, GenerationGuard, Shared, State};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

fn fixture() -> (FactoryOwner, WorkerReadiness, Cx) {
    let shared = Arc::new(Shared {
        state: parking_lot::Mutex::new(State {
            snapshot: WorkerReadinessState {
                generation: None, phase: WorkerReadinessPhase::NotStarted,
            },
            factory_alive: true, active: false,
        }),
        changed: crate::sync::Notify::new(),
    });
    (FactoryOwner(Arc::clone(&shared)), WorkerReadiness { shared }, Cx::for_testing())
}

fn start(owner: &FactoryOwner, cx: &Cx, number: u64) -> GenerationGuard {
    owner.begin(cx, ManagedGeneration {
        number, region: cx.region_id(), task: cx.task_id(),
    }).expect("valid generation")
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn counting_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

#[test]
fn empty_set_is_ready_and_loss_wait_only_observes_cancellation() {
    let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
    assert!(dependencies.is_empty());
    let snapshot = dependencies.try_ready().unwrap().unwrap();
    assert!(snapshot.is_empty());
    assert!(snapshot.is_current());
    let cx = Cx::for_testing();
    let mut lost = std::pin::pin!(snapshot.wait_lost(&cx));
    let mut task = Context::from_waker(Waker::noop());
    assert!(lost.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(crate::types::CancelKind::User);
    assert!(matches!(lost.as_mut().poll(&mut task), Poll::Ready(Err(DependencyError::Cancelled))));
    assert!(snapshot.is_current(), "observer cancellation is not dependency loss");
}

#[test]
fn count_and_duplicate_refusals_leave_prerequisites_untouched() {
    let (_oa, a, _ca) = fixture();
    let (_ob, b, _cb) = fixture();
    assert!(matches!(WorkerDependencies::new(vec![a.clone(), b.clone()], 1),
        Err(DependencyError::Capacity { requested: 2, limit: 1 })));
    assert!(matches!(WorkerDependencies::new(vec![a.clone(), b.clone(), b.clone(), a.clone()], 4),
        Err(DependencyError::Duplicate { index: 2 })));
    assert_eq!(a.state().phase, WorkerReadinessPhase::NotStarted);
    assert_eq!(b.state().phase, WorkerReadinessPhase::NotStarted);
}

#[test]
fn all_initializers_must_be_ready_and_snapshot_preserves_input_order() {
    let (oa, a, ca) = fixture();
    let (ob, b, cb) = fixture();
    let ga = start(&oa, &ca, 3);
    let gb = start(&ob, &cb, 7);
    let dependencies = WorkerDependencies::new(vec![b, a], 2).unwrap();
    ga.phase(WorkerReadinessPhase::Ready);
    assert!(dependencies.try_ready().unwrap().is_none());
    gb.phase(WorkerReadinessPhase::Ready);
    let snapshot = dependencies.try_ready().unwrap().unwrap();
    assert_eq!(snapshot.generations().map(|g| g.number).collect::<Vec<_>>(), [7, 3]);
    assert!(snapshot.is_current());
}

#[test]
fn previously_ready_values_from_disjoint_intervals_do_not_form_a_barrier() {
    let (oa, a, ca) = fixture();
    let (ob, b, cb) = fixture();
    let dependencies = WorkerDependencies::new(vec![a.clone(), b.clone()], 2).unwrap();
    let ga = start(&oa, &ca, 1);
    ga.phase(WorkerReadinessPhase::Ready);
    let first = a.try_ready().unwrap().unwrap();
    drop(ga);
    let gb = start(&ob, &cb, 1);
    gb.phase(WorkerReadinessPhase::Ready);
    let second = b.try_ready().unwrap().unwrap();
    // This is exactly the invalid vector that sequential wait_ready calls can
    // produce. The same second-pass predicate used by try_ready must reject it.
    let mixed = ReadyDependencies {
        set: Arc::clone(&dependencies.set), ready: vec![first, second],
    };
    assert!(!mixed.is_current());
    assert_eq!(mixed.first_lost().unwrap().index, 0);
    assert!(dependencies.try_ready().unwrap().is_none());
}

#[test]
fn closed_later_prerequisite_is_not_hidden_by_an_unstarted_first_worker() {
    let (_oa, a, _ca) = fixture();
    let (ob, b, _cb) = fixture();
    let dependencies = WorkerDependencies::new(vec![a, b], 2).unwrap();
    let cx = Cx::for_testing();
    let mut wait = std::pin::pin!(dependencies.wait_ready(&cx));
    let (count, waker) = counting_waker();
    let mut task = Context::from_waker(&waker);
    assert!(wait.as_mut().poll(&mut task).is_pending());
    drop(ob);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(wait.as_mut().poll(&mut task),
        Poll::Ready(Err(DependencyError::Worker { index: 1, cause: WorkerReadinessError::Closed }))));
}

#[test]
fn barrier_wait_rechecks_old_readiness_when_another_initializer_finishes() {
    let (oa, a, ca) = fixture();
    let (ob, b, cb) = fixture();
    let ga = start(&oa, &ca, 1);
    let gb = start(&ob, &cb, 1);
    ga.phase(WorkerReadinessPhase::Ready);
    let dependencies = WorkerDependencies::new(vec![a, b], 2).unwrap();
    let cx = Cx::for_testing();
    let mut wait = std::pin::pin!(dependencies.wait_ready(&cx));
    let mut task = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut task).is_pending());
    drop(ga);
    gb.phase(WorkerReadinessPhase::Ready);
    assert!(wait.as_mut().poll(&mut task).is_pending());
    let replacement = start(&oa, &ca, 2);
    replacement.phase(WorkerReadinessPhase::Ready);
    let Poll::Ready(Ok(snapshot)) = wait.as_mut().poll(&mut task) else {
        panic!("the new simultaneous generation vector is ready");
    };
    assert_eq!(snapshot.generations().map(|g| g.number).collect::<Vec<_>>(), [2, 1]);
}

#[test]
fn completed_restart_cannot_hide_loss_of_a_previous_generation() {
    let (owner, worker, cx) = fixture();
    let generation = start(&owner, &cx, 1);
    generation.phase(WorkerReadinessPhase::Ready);
    let dependencies = WorkerDependencies::new(vec![worker], 1).unwrap();
    let snapshot = dependencies.try_ready().unwrap().unwrap();
    drop(generation);
    let replacement = start(&owner, &cx, 2);
    replacement.phase(WorkerReadinessPhase::Ready);
    let observer = Cx::for_testing();
    let loss = futures_lite::future::block_on(snapshot.wait_lost(&observer)).unwrap();
    assert_eq!(loss.expected.number, 1);
    assert_eq!(loss.observed.generation.unwrap().number, 2);
    assert_eq!(loss.observed.phase, WorkerReadinessPhase::Ready);
    assert!(dependencies.try_ready().unwrap().unwrap().is_current());
    assert!(!snapshot.is_current());
}

#[test]
fn loss_wait_replaces_its_waker_without_missing_later_dependency_changes() {
    let (oa, a, ca) = fixture();
    let (ob, b, cb) = fixture();
    let ga = start(&oa, &ca, 1);
    let gb = start(&ob, &cb, 1);
    ga.phase(WorkerReadinessPhase::Ready);
    gb.phase(WorkerReadinessPhase::Ready);
    let snapshot = WorkerDependencies::new(vec![a, b], 2).unwrap().try_ready().unwrap().unwrap();
    let observer = Cx::for_testing();
    let mut wait = std::pin::pin!(snapshot.wait_lost(&observer));
    let (first, first_waker) = counting_waker();
    let (latest, latest_waker) = counting_waker();
    assert!(wait.as_mut().poll(&mut Context::from_waker(&first_waker)).is_pending());
    assert!(wait.as_mut().poll(&mut Context::from_waker(&latest_waker)).is_pending());
    gb.phase(WorkerReadinessPhase::Stopping);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert!(latest.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(wait.as_mut().poll(&mut Context::from_waker(&latest_waker)),
        Poll::Ready(Ok(DependencyLoss { index: 1, .. }))));
}

#[test]
fn dropping_barrier_wait_retires_its_notify_and_cancel_registrations() {
    let (_oa, a, _ca) = fixture();
    let (_ob, b, _cb) = fixture();
    let dependencies = WorkerDependencies::new(vec![a, b], 2).unwrap();
    let observer = Cx::for_testing();
    let (count, waker) = counting_waker();
    let baseline = Arc::strong_count(&count);
    for _ in 0..8 {
        let mut wait = Box::pin(dependencies.wait_ready(&observer));
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        assert!(Arc::strong_count(&count) > baseline);
        drop(wait);
        assert_eq!(Arc::strong_count(&count), baseline);
    }
}

#[test]
fn cancelling_one_observer_leaves_workers_and_other_observers_running() {
    let (owner, worker, cx) = fixture();
    let generation = start(&owner, &cx, 1);
    let dependencies = WorkerDependencies::new(vec![worker.clone()], 1).unwrap();
    let cancelled = Cx::for_testing();
    let survivor = Cx::for_testing();
    let mut first = std::pin::pin!(dependencies.wait_ready(&cancelled));
    let mut second = std::pin::pin!(dependencies.wait_ready(&survivor));
    let mut task = Context::from_waker(Waker::noop());
    assert!(first.as_mut().poll(&mut task).is_pending());
    assert!(second.as_mut().poll(&mut task).is_pending());
    cancelled.cancel_fast(crate::types::CancelKind::User);
    assert!(matches!(first.as_mut().poll(&mut task), Poll::Ready(Err(DependencyError::Cancelled))));
    assert_eq!(worker.state().phase, WorkerReadinessPhase::Initializing);
    assert!(!cx.is_cancel_requested());
    generation.phase(WorkerReadinessPhase::Ready);
    assert!(matches!(second.as_mut().poll(&mut task), Poll::Ready(Ok(_))));
}

#[test]
fn invalid_generation_is_terminal_even_with_other_pending_dependencies() {
    let (_oa, a, _ca) = fixture();
    let (ob, b, cb) = fixture();
    let _active = start(&ob, &cb, 1);
    assert!(ob.begin(&cb, ManagedGeneration {
        number: 2, region: cb.region_id(), task: cb.task_id(),
    }).is_none());
    assert!(matches!(WorkerDependencies::new(vec![a, b], 2).unwrap().try_ready(),
        Err(DependencyError::Worker { index: 1, cause: WorkerReadinessError::InvalidGeneration })));
}

#[test]
fn dependency_waits_are_send_without_holding_state_guards_across_pending() {
    fn assert_send<T: Send>(_: T) {}
    let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
    let observer = Cx::for_testing();
    assert_send(dependencies.wait_ready(&observer));
    let snapshot = dependencies.try_ready().unwrap().unwrap();
    assert_send(snapshot.wait_lost(&observer));
}

#[test]
fn concurrent_nonoverlapping_ready_intervals_never_produce_a_ready_vector() {
    let (oa, a, ca) = fixture();
    let (ob, b, cb) = fixture();
    let dependencies = WorkerDependencies::new(vec![a, b], 2).unwrap();
    let writer = std::thread::spawn(move || {
        for number in 1..=2000 {
            let ga = start(&oa, &ca, number);
            let gb = start(&ob, &cb, number);
            ga.phase(WorkerReadinessPhase::Ready);
            drop(ga); // A is no longer ready before B becomes ready.
            gb.phase(WorkerReadinessPhase::Ready);
            drop(gb);
        }
    });
    for _ in 0..4096 {
        assert!(!matches!(dependencies.try_ready(), Ok(Some(_))));
    }
    writer.join().unwrap();
    assert!(!matches!(dependencies.try_ready(), Ok(Some(_))));
}
