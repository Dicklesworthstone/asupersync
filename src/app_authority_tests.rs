//! Application and legacy supervisor bootstrap must preserve caller authority.

use super::{AppSpawnError, AppSpec, AppStartError};
use crate::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use crate::cx::{Cx, Scope};
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::state::RuntimeState;
use crate::runtime::{SpawnError, TaskHandle};
use crate::supervision::{
    ChildSpec, NameRegistrationPolicy, SupervisionStrategy, SupervisorBuilder, SupervisorSpawnError,
};
use crate::types::policy::FailFast;
use crate::types::{
    Budget, CancelReason, CapabilityBudget, CapabilityBudgetRequirements, RegionId, TaskId, Time,
};
use std::sync::{Arc, Mutex};

pub(crate) const SPAWN_ONLY: CapMask =
    <CapSet<true, false, false, false, false> as CapSetRuntimeMask>::MASK;

/// Model a framework passing the ambient view from a restricted execution
/// scope. The returned full-typed Cx retains the public restriction's mask.
pub(crate) fn restricted_caller(cx: Cx, mask: CapMask) -> Cx {
    let _current = cx.set_current();
    let _restriction = Cx::push_restriction(mask);
    Cx::current().unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Authority {
    pub(crate) budget: Budget,
    pub(crate) envelope: CapabilityBudget,
    pub(crate) mask: CapMask,
    pub(crate) region: RegionId,
    pub(crate) task: TaskId,
}

impl Authority {
    pub(crate) fn capture(cx: &Cx) -> Self {
        Self {
            budget: cx.budget(),
            envelope: cx.capability_budget(),
            mask: cx.runtime_mask,
            region: cx.region_id(),
            task: cx.task_id(),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct ChildProbe {
    pub(crate) boot: Arc<Mutex<Option<Cx>>>,
    pub(crate) polled: Arc<Mutex<Option<(Authority, Authority)>>>,
    pub(crate) task: Arc<Mutex<Option<TaskHandle<()>>>>,
}

/// Keep the handle alive until the test joins it; dropping it would abort the
/// child and make a context-inheritance test accidentally test cancellation.
pub(crate) fn child_probe() -> (ChildSpec, ChildProbe) {
    let probe = ChildProbe::default();
    let retained = probe.clone();
    let child = ChildSpec {
        name: "worker".into(),
        start: Box::new(
            move |scope: &Scope<'static, FailFast>, state: &mut RuntimeState, cx: &Cx| {
                *retained.boot.lock().unwrap() = Some(cx.clone());
                let observed = Arc::clone(&retained.polled);
                let task = scope.spawn_registered(state, cx, move |child| async move {
                    let ambient = Cx::current().expect("executor installs the child context");
                    *observed.lock().unwrap() =
                        Some((Authority::capture(&child), Authority::capture(&ambient)));
                })?;
                let task_id = task.task_id();
                *retained.task.lock().unwrap() = Some(task);
                Ok(task_id)
            },
        ),
        restart: SupervisionStrategy::Stop,
        shutdown_budget: Budget::INFINITE,
        depends_on: Vec::new(),
        registration: NameRegistrationPolicy::None,
        start_immediately: true,
        required: true,
    };
    (child, probe)
}

pub(crate) fn admitted_authority(state: &RuntimeState, task: TaskId) -> Authority {
    Authority::capture(state.task(task).unwrap().cx.as_ref().unwrap())
}

pub(crate) fn assert_polled(probe: &ChildProbe, admitted: Authority) {
    let (child, ambient) = probe.polled.lock().unwrap().expect("child was polled");
    assert_eq!(
        child, ambient,
        "ambient lookup must retain the same authority"
    );
    assert_eq!(child.region, admitted.region);
    assert_eq!(child.task, admitted.task);
    assert_eq!(child.mask, admitted.mask);
    assert_eq!(child.envelope, admitted.envelope);
    assert_eq!(child.budget.deadline, admitted.budget.deadline);
    assert_eq!(child.budget.cost_quota, admitted.budget.cost_quota);
    assert_eq!(child.budget.priority, admitted.budget.priority);
    assert!(child.budget.poll_quota <= admitted.budget.poll_quota);
}

fn lab_caller(
    runtime: &mut LabRuntime,
    parent_budget: Budget,
    parent_envelope: CapabilityBudget,
    caller_budget: Budget,
    caller_envelope: CapabilityBudget,
) -> (RegionId, Cx) {
    let parent = runtime
        .state
        .create_root_region_with_capability_budget(parent_budget, parent_envelope);
    let cx = Cx::new(parent, TaskId::testing_default(), caller_budget);
    cx.apply_child_capability_budget(caller_envelope, CapabilityBudgetRequirements::NONE)
        .unwrap();
    (parent, cx)
}

fn run_child(runtime: &mut LabRuntime, probe: &ChildProbe, admitted: Authority, cx: &Cx) {
    runtime
        .scheduler
        .lock()
        .schedule(admitted.task, admitted.budget.priority);
    runtime.run_until_quiescent();
    let mut task = probe.task.lock().unwrap().take().unwrap();
    futures_lite::future::block_on(task.join(cx)).unwrap();
    assert_polled(probe, admitted);
}

#[test]
fn app_authority_meets_caller_spec_and_current_parent_in_lab() {
    for seed in [7, 19] {
        let mut runtime = LabRuntime::new(LabConfig::new(seed));
        let parent_budget = Budget::INFINITE
            .with_deadline(Time::from_millis(200))
            .with_poll_quota(90)
            .with_cost_quota(100)
            .with_priority(2);
        let caller_budget = Budget::INFINITE
            .with_deadline(Time::from_millis(100))
            .with_poll_quota(70)
            .with_cost_quota(300)
            .with_priority(7);
        let app_budget = Budget::INFINITE
            .with_deadline(Time::from_millis(300))
            .with_poll_quota(40)
            .with_cost_quota(200)
            .with_priority(3);
        let parent_envelope = CapabilityBudget::new()
            .with_memory_bytes(512)
            .with_cpu_units(80)
            .with_io_bytes(4096)
            .with_cleanup_budget(Budget::INFINITE.with_poll_quota(20))
            .with_artifact_bytes(128);
        let caller_envelope = CapabilityBudget::new()
            .with_memory_bytes(1024)
            .with_cpu_units(30)
            .with_io_bytes(256)
            .with_cleanup_budget(Budget::INFINITE.with_poll_quota(50).with_cost_quota(12))
            .with_artifact_bytes(512);
        let (parent, mut cx) = lab_caller(
            &mut runtime,
            parent_budget,
            parent_envelope,
            caller_budget,
            caller_envelope,
        );
        cx = restricted_caller(cx, SPAWN_ONLY);
        let (child, probe) = child_probe();
        let mut app = AppSpec::new("attenuated")
            .with_budget(app_budget)
            .child(child)
            .start(&mut runtime.state, &cx, parent)
            .unwrap();
        // Each limiting dimension has a different authority source; these
        // values deliberately do not calculate the expected result via meet.
        let expected_budget = Budget::INFINITE
            .with_deadline(Time::from_millis(100))
            .with_poll_quota(40)
            .with_cost_quota(100)
            .with_priority(7);
        let expected_envelope = CapabilityBudget::new()
            .with_memory_bytes(512)
            .with_cpu_units(30)
            .with_io_bytes(256)
            .with_cleanup_budget(Budget::INFINITE.with_poll_quota(20).with_cost_quota(12))
            .with_artifact_bytes(128);
        for region in [app.root_region(), app.supervisor().region] {
            let record = runtime.state.region(region).unwrap();
            assert_eq!(record.budget(), expected_budget);
            assert_eq!(record.capability_budget(), expected_envelope);
        }
        let boot = probe.boot.lock().unwrap().clone().unwrap();
        assert_eq!(boot.region_id(), app.root_region());
        assert_eq!(boot.budget(), expected_budget);
        assert_eq!(boot.capability_budget(), expected_envelope);
        assert_eq!(boot.runtime_mask, SPAWN_ONLY);
        let admitted = admitted_authority(&runtime.state, app.supervisor().started[0].task_id);
        assert_eq!(admitted.budget, expected_budget);
        assert_eq!(admitted.envelope, expected_envelope);
        assert_eq!(admitted.mask, SPAWN_ONLY);
        run_child(&mut runtime, &probe, admitted, &cx);
        app.stop(&mut runtime.state).unwrap();
        runtime.run_until_quiescent();
        app.join(&runtime.state).unwrap();
        assert_eq!(runtime.state.regions_len(), 1);
        assert_eq!(runtime.state.live_task_count(), 0);
    }
}

#[test]
fn app_authority_does_not_restore_removed_spawn_and_rolls_back_boot() {
    let mut runtime = LabRuntime::new(LabConfig::new(23));
    let (parent, mut cx) = lab_caller(
        &mut runtime,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
    );
    cx = restricted_caller(cx, CapMask::none());
    let (child, probe) = child_probe();
    let result = AppSpec::new("no-spawn")
        .child(child)
        .compile()
        .unwrap()
        .start(&mut runtime.state, &cx, parent);
    assert!(matches!(
        result,
        Err(AppSpawnError::SpawnFailed(
            SupervisorSpawnError::ChildStartFailed {
                err: SpawnError::RuntimeUnavailable,
                ..
            }
        ))
    ));
    assert_eq!(
        probe.boot.lock().unwrap().as_ref().unwrap().runtime_mask,
        CapMask::none()
    );
    assert!(probe.task.lock().unwrap().is_none());
    assert!(probe.polled.lock().unwrap().is_none());
    assert_eq!(runtime.state.live_task_count(), 0);
    assert_eq!(
        runtime.state.regions_len(),
        1,
        "failed boot must remove its regions"
    );
}

#[test]
fn supervisor_authority_direct_boot_preserves_context_only_limits() {
    let mut runtime = LabRuntime::new(LabConfig::new(29));
    let caller_budget = Budget::INFINITE.with_poll_quota(31).with_cost_quota(43);
    let envelope = CapabilityBudget::new()
        .with_memory_bytes(128)
        .with_io_bytes(256);
    let (parent, mut cx) = lab_caller(
        &mut runtime,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
        caller_budget,
        envelope,
    );
    cx = restricted_caller(cx, SPAWN_ONLY);
    let (child, probe) = child_probe();
    let supervisor = SupervisorBuilder::new("direct")
        .with_budget(Budget::INFINITE)
        .child(child)
        .compile()
        .unwrap()
        .spawn(&mut runtime.state, &cx, parent, Budget::INFINITE)
        .unwrap();
    assert_eq!(
        runtime.state.region(supervisor.region).unwrap().budget(),
        caller_budget
    );
    assert_eq!(
        runtime
            .state
            .region(supervisor.region)
            .unwrap()
            .capability_budget(),
        envelope
    );
    let admitted = admitted_authority(&runtime.state, supervisor.started[0].task_id);
    assert_eq!(admitted.budget, caller_budget);
    assert_eq!(admitted.envelope, envelope);
    assert_eq!(admitted.mask, SPAWN_ONLY);
    run_child(&mut runtime, &probe, admitted, &cx);
    runtime
        .state
        .close_region_command(supervisor.region, &CancelReason::shutdown());
    runtime.run_until_quiescent();
    assert_eq!(runtime.state.regions_len(), 1);
}

#[test]
fn supervisor_authority_explicit_budget_cannot_replace_supplied_parent_budget() {
    let mut runtime = LabRuntime::new(LabConfig::new(31));
    let (parent, cx) = lab_caller(
        &mut runtime,
        Budget::INFINITE.with_cost_quota(17),
        CapabilityBudget::UNSPECIFIED,
        Budget::INFINITE.with_priority(6),
        CapabilityBudget::UNSPECIFIED,
    );
    let (child, probe) = child_probe();
    let supervisor = SupervisorBuilder::new("supplied-parent")
        .with_budget(Budget::INFINITE.with_poll_quota(70))
        .child(child)
        .compile()
        .unwrap()
        .spawn(
            &mut runtime.state,
            &cx,
            parent,
            Budget::INFINITE.with_poll_quota(20),
        )
        .unwrap();
    let expected = Budget::INFINITE
        .with_poll_quota(20)
        .with_cost_quota(17)
        .with_priority(6);
    let admitted = admitted_authority(&runtime.state, supervisor.started[0].task_id);
    assert_eq!(
        runtime.state.region(supervisor.region).unwrap().budget(),
        expected
    );
    assert_eq!(admitted.budget, expected);
    run_child(&mut runtime, &probe, admitted, &cx);
    runtime
        .state
        .close_region_command(supervisor.region, &CancelReason::shutdown());
    runtime.run_until_quiescent();
    assert_eq!(runtime.state.regions_len(), 1);
}

#[test]
fn app_authority_zero_resource_envelope_is_not_replenished_by_bootstrap() {
    let mut runtime = LabRuntime::new(LabConfig::new(37));
    let zero = CapabilityBudget::new()
        .with_memory_bytes(0)
        .with_io_bytes(0);
    let (parent, cx) = lab_caller(
        &mut runtime,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
        Budget::INFINITE,
        zero,
    );
    let (child, probe) = child_probe();
    let mut app = AppSpec::new("zero-resource")
        .child(child)
        .start(&mut runtime.state, &cx, parent)
        .unwrap();
    let admitted = admitted_authority(&runtime.state, app.supervisor().started[0].task_id);
    assert_eq!(admitted.envelope, zero);
    run_child(&mut runtime, &probe, admitted, &cx);
    let observed = probe.polled.lock().unwrap().unwrap().0;
    let requirements = CapabilityBudgetRequirements {
        memory_bytes: true,
        ..CapabilityBudgetRequirements::NONE
    };
    assert!(observed.envelope.validate(requirements).is_err());
    app.stop(&mut runtime.state).unwrap();
    runtime.run_until_quiescent();
    app.join(&runtime.state).unwrap();
}

#[test]
fn app_authority_unrestricted_boot_retains_legacy_defaults() {
    let mut runtime = LabRuntime::new(LabConfig::new(41));
    let (parent, cx) = lab_caller(
        &mut runtime,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
    );
    let (child, probe) = child_probe();
    let mut app = AppSpec::new("unrestricted")
        .child(child)
        .start(&mut runtime.state, &cx, parent)
        .unwrap();
    let admitted = admitted_authority(&runtime.state, app.supervisor().started[0].task_id);
    assert_eq!(admitted.budget, Budget::INFINITE);
    assert_eq!(admitted.envelope, CapabilityBudget::UNSPECIFIED);
    assert_eq!(admitted.mask, CapMask::all());
    run_child(&mut runtime, &probe, admitted, &cx);
    app.stop(&mut runtime.state).unwrap();
    runtime.run_until_quiescent();
    app.join(&runtime.state).unwrap();
}

#[test]
fn app_authority_closed_parent_refusal_does_not_invoke_children() {
    let mut runtime = LabRuntime::new(LabConfig::new(43));
    let (parent, cx) = lab_caller(
        &mut runtime,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
        Budget::INFINITE,
        CapabilityBudget::UNSPECIFIED,
    );
    runtime.state.region(parent).unwrap().begin_close(None);
    let (child, probe) = child_probe();
    let result = AppSpec::new("closed-parent")
        .child(child)
        .start(&mut runtime.state, &cx, parent);
    assert!(matches!(
        result,
        Err(AppStartError::SpawnFailed(AppSpawnError::RegionCreate(_)))
    ));
    assert!(probe.boot.lock().unwrap().is_none());
    assert!(probe.task.lock().unwrap().is_none());
    assert_eq!(runtime.state.live_task_count(), 0);
    assert_eq!(runtime.state.regions_len(), 1);
}
