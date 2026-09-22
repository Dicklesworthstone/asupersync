use super::*;
use crate::cx::Scope;
use crate::runtime::{RuntimeState, SpawnError};
use crate::supervision::{ChildSpec, ChildStart, RestartPolicy, SupervisorCompileError};
use crate::types::{TaskId, policy::FailFast};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct Legacy;
impl ChildStart for Legacy {
    fn start(
        &mut self,
        _: &Scope<'static, FailFast>,
        _: &mut RuntimeState,
        _: &Cx,
    ) -> Result<TaskId, SpawnError> {
        panic!("initialized binding must not invoke legacy ChildStart")
    }
}

fn topology() -> CompiledSupervisor {
    // Forward declaration: this is deliberately not dependency insertion order.
    SupervisorBuilder::new("service")
        .child(ChildSpec::new("front", Legacy).depends_on("storage"))
        .child(ChildSpec::new("storage", Legacy))
        .compile().unwrap()
}

fn config() -> SupervisionConfig {
    SupervisionConfig::new(3, Duration::from_secs(60))
}

fn limits() -> InitializedTopologyLimits {
    InitializedTopologyLimits { max_children: 4, max_edges: 4 }
}

fn binding(name: &str, calls: &Arc<AtomicUsize>) -> InitializedChildBinding<()> {
    let initialized = Arc::clone(calls);
    let running = Arc::clone(calls);
    let classified = Arc::clone(calls);
    InitializedChildBinding::new(name, ManagedRestartMode::Temporary,
        move |_, _| {
            initialized.fetch_add(1, Ordering::SeqCst);
            // Deliberately not Sync; the work error is not Clone either.
            async { Outcome::<_, Cell<String>>::Ok(Cell::new(41u32)) }
        },
        move |_, _, value: Cell<u32>| {
            running.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(value.get(), 41);
                Outcome::<(), Cell<String>>::Ok(())
            }
        },
        move |result| {
            classified.fetch_add(1, Ordering::SeqCst);
            if result.as_ref().is_ok_and(DependencyScopeReport::is_success) {
                Outcome::Ok(())
            } else {
                Outcome::Err(())
            }
        },
    )
}

fn bindings(calls: &Arc<AtomicUsize>) -> Vec<InitializedChildBinding<()>> {
    vec![binding("storage", calls), binding("front", calls)]
}

#[test]
fn bind_reuses_compiled_forward_edges_without_running_user_code() {
    let calls = Arc::new(AtomicUsize::new(0));
    let compiled = topology();
    assert_eq!(compiled.child_start_order_names(), ["storage", "front"]);
    let (owner, readiness) = compiled.bind_initialized(bindings(&calls), config(), limits()).unwrap();
    assert_eq!(readiness.names().collect::<Vec<_>>(), ["front", "storage"]);
    assert_eq!(readiness.all().len(), 2);
    assert!(readiness.all().try_ready().unwrap().is_none());
    assert!(readiness.child("absent").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(owner);
    assert_eq!(readiness.child("front").unwrap().state().phase, WorkerReadinessPhase::Closed);
    assert_eq!(readiness.child("storage").unwrap().state().phase, WorkerReadinessPhase::Closed);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_graph_accepts_exact_zero_limits() {
    let compiled = SupervisorBuilder::new("empty").compile().unwrap();
    let (owner, readiness) = compiled.bind_initialized::<()>(Vec::new(), config(),
        InitializedTopologyLimits { max_children: 0, max_edges: 0 }).unwrap();
    assert!(readiness.all().try_ready().unwrap().unwrap().is_empty());
    assert_eq!(readiness.names().len(), 0);
    drop(owner);
}

#[test]
fn public_topology_mutations_cannot_bypass_cycle_or_order_validation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut cyclic = topology();
    cyclic.children[1].depends_on.push("front".into());
    assert!(matches!(cyclic.bind_initialized(bindings(&calls), config(), limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::Topology(
            SupervisorCompileError::CycleDetected { .. })))));
    let mut reordered = topology();
    reordered.start_order = vec![usize::MAX, 0];
    assert!(matches!(reordered.bind_initialized(bindings(&calls), config(), limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::StartOrder))));
    let mut missing_edge = topology();
    missing_edge.children[0].depends_on.push("absent".into());
    assert!(matches!(missing_edge.bind_initialized(bindings(&calls), config(), limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::Topology(
            SupervisorCompileError::UnknownDependency { .. })))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn binding_census_refuses_missing_unknown_and_duplicate_names() {
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(topology().bind_initialized(vec![binding("front", &calls)], config(), limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::Missing(_)))));
    assert!(matches!(topology().bind_initialized(vec![binding("elsewhere", &calls)], config(), limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::Unknown(_)))));
    assert!(matches!(topology().bind_initialized(vec![binding("front", &calls), binding("front", &calls)], config(), limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::Duplicate(_)))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn bounds_count_raw_edges_before_deduplicating_equivalent_dependencies() {
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(topology().bind_initialized(bindings(&calls), config(),
        InitializedTopologyLimits { max_children: 1, max_edges: 10 }),
        Err(InitializedBindError::Limit("children"))));
    let duplicate = || SupervisorBuilder::new("repeated-edge")
        .child(ChildSpec::new("front", Legacy).depends_on("storage").depends_on("storage"))
        .child(ChildSpec::new("storage", Legacy)).compile().unwrap();
    assert!(matches!(duplicate().bind_initialized(bindings(&calls), config(),
        InitializedTopologyLimits { max_children: 2, max_edges: 1 }),
        Err(InitializedBindError::Limit("edges"))));
    let (owner, _) = duplicate().bind_initialized(bindings(&calls), config(),
        InitializedTopologyLimits { max_children: 2, max_edges: 2 }).unwrap();
    drop(owner);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn deferred_readiness_and_conflicting_restart_policies_are_not_silently_accepted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let deferred = SupervisorBuilder::new("deferred")
        .child(ChildSpec::new("storage", Legacy).with_start_immediately(false)).compile().unwrap();
    assert!(matches!(deferred.bind_initialized(vec![binding("storage", &calls)], config(), limits()),
        Err(InitializedBindError::Deferred(_))));
    let mut conflicting = config();
    conflicting.restart_policy = RestartPolicy::OneForAll;
    assert!(matches!(topology().bind_initialized(bindings(&calls), conflicting, limits()),
        Err(InitializedBindError::Managed(ManagedSupervisorBindError::RestartPolicyMismatch))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_readiness_withdrawal_does_not_claim_live_body_retirement() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = binding("temporary", &calls);
    let readiness = retained.readiness();
    readiness.shared.state.lock().active = true;
    drop(TerminalReadiness { readiness: readiness.clone(), close: true });
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Stopping);
    assert!(!readiness.shared.state.lock().factory_alive);
    // A real GenerationGuard performs this final step after its body retires.
    readiness.shared.state.lock().active = false;
    drop(TerminalReadiness { readiness: readiness.clone(), close: true });
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
    drop(retained);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn nonclosing_terminal_guard_leaves_reusable_factory_authority_intact() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = binding("reusable", &calls);
    let readiness = retained.readiness();
    drop(TerminalReadiness { readiness: readiness.clone(), close: false });
    assert!(readiness.shared.state.lock().factory_alive);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::NotStarted);
    drop(retained);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
}

#[test]
fn temporary_retirement_is_owned_before_a_future_is_first_polled() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = binding("unpolled", &calls);
    let readiness = retained.readiness();
    let retirement = TerminalReadiness { readiness: readiness.clone(), close: true };
    let future = async move {
        let _terminal = retirement;
        std::future::pending::<()>().await;
    };
    drop(future);
    assert_eq!(readiness.state().phase, WorkerReadinessPhase::Closed);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(retained);
}
