//! Execute legacy AppSpec bootstrap through the native worker/caller drivers.

use super::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::app::authority_tests::{
    SPAWN_ONLY, admitted_authority, assert_polled, child_probe, restricted_caller,
};
use crate::app::{AppSpawnError, AppSpec, AppStartError};
use crate::cx::cap::CapMask;
use crate::cx::macaroon::MacaroonToken;
use crate::cx::registry::RegistryHandle;
use crate::cx::{Cx, NameRegistry};
use crate::evidence_sink::{EvidenceSink, NullSink};
use crate::remote::{NodeId, RemoteCap};
use crate::runtime::SpawnError;
use crate::security::key::AuthKey;
use crate::supervision::{SupervisorBuilder, SupervisorSpawnError};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CapabilityBudget, CapabilityBudgetRequirements, SystemPressure, Time};
use std::sync::Arc;
use std::time::Duration;

fn runtime(current_thread: bool) -> Runtime {
    let builder = if current_thread {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(2)
    };
    // These state-threaded bootstrap APIs store tasks in the unified table.
    builder
        .with_sharded_state(false)
        .with_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_millis(0)),
        )))
        .build()
        .unwrap()
}

#[test]
fn app_authority_native_children_keep_limits_and_inherited_handles() {
    for current_thread in [true, false] {
        for detach_pool in [false, true] {
            let runtime = runtime(current_thread);
            let parent_budget = Budget::INFINITE.with_poll_quota(80).with_cost_quota(17);
            let parent_envelope = CapabilityBudget::new()
                .with_memory_bytes(96)
                .with_io_bytes(512);
            let parent = runtime
                .inner
                .state
                .lock()
                .unwrap()
                .create_child_region_with_capability_budget(
                    runtime.inner.root_region,
                    parent_budget,
                    parent_envelope,
                    CapabilityBudgetRequirements::NONE,
                )
                .unwrap();
            let registry = RegistryHandle::new(Arc::new(NameRegistry::new()));
            let pressure = Arc::new(SystemPressure::new());
            let evidence: Arc<dyn EvidenceSink> = Arc::new(NullSink);
            let caller_budget = Budget::INFINITE
                .with_deadline(Time::from_millis(100))
                .with_poll_quota(31)
                .with_cost_quota(29)
                .with_priority(6);
            let mut cx = runtime
                .request_cx_with_budget(caller_budget)
                .with_registry_handle(Some(registry.clone()))
                .with_pressure(Arc::clone(&pressure))
                .with_evidence_sink(Some(Arc::clone(&evidence)))
                .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("native-app")))
                .with_macaroon(MacaroonToken::mint(
                    &AuthKey::from_seed(59),
                    "application:test",
                    "native-app",
                ));
            assert!(cx.blocking_pool_handle().is_some());
            if detach_pool {
                cx = cx.with_blocking_pool_handle(None);
            }
            cx = restricted_caller(cx, SPAWN_ONLY);
            cx.apply_child_capability_budget(
                CapabilityBudget::new()
                    .with_memory_bytes(192)
                    .with_io_bytes(64),
                CapabilityBudgetRequirements::NONE,
            )
            .unwrap();
            let (child, probe) = child_probe();
            let expected_budget = Budget::INFINITE
                .with_deadline(Time::from_millis(100))
                .with_poll_quota(12)
                .with_cost_quota(17)
                .with_priority(6);
            let expected_envelope = CapabilityBudget::new()
                .with_memory_bytes(96)
                .with_io_bytes(64);
            let (mut app, admitted) = {
                let mut state = runtime.inner.state.lock().unwrap();
                let app = AppSpec::new("native-attenuated")
                    .with_budget(Budget::INFINITE.with_poll_quota(12).with_cost_quota(53))
                    .child(child)
                    .start(&mut state, &cx, parent)
                    .unwrap();
                for region in [app.root_region(), app.supervisor().region] {
                    let record = state.region(region).unwrap();
                    assert_eq!(record.budget(), expected_budget);
                    assert_eq!(record.capability_budget(), expected_envelope);
                }
                let task_id = app.supervisor().started[0].task_id;
                let admitted = admitted_authority(&state, task_id);
                assert_eq!(admitted.budget, expected_budget);
                assert_eq!(admitted.envelope, expected_envelope);
                assert_eq!(admitted.mask, SPAWN_ONLY);
                let boot = probe.boot.lock().unwrap().clone().unwrap();
                let child = state.task(task_id).unwrap().cx.as_ref().unwrap();
                for inherited in [&boot, child] {
                    assert_eq!(inherited.runtime_mask, SPAWN_ONLY);
                    assert_eq!(inherited.capability_budget(), expected_envelope);
                    assert_eq!(inherited.blocking_pool_handle().is_none(), detach_pool);
                    assert!(Arc::ptr_eq(
                        &inherited.registry_handle().unwrap().as_arc(),
                        &registry.as_arc()
                    ));
                    assert!(Arc::ptr_eq(
                        &inherited.pressure_handle().unwrap(),
                        &pressure
                    ));
                    assert!(Arc::ptr_eq(
                        &inherited.evidence_sink_handle().unwrap(),
                        &evidence
                    ));
                    assert!(Arc::ptr_eq(
                        &inherited.macaroon_handle().unwrap(),
                        &cx.macaroon_handle().unwrap()
                    ));
                    assert!(Arc::ptr_eq(
                        &inherited.remote_cap_handle().unwrap(),
                        &cx.remote_cap_handle().unwrap()
                    ));
                }
                (app, admitted)
            };
            runtime
                .inner
                .scheduler
                .inject_ready(admitted.task, admitted.budget.priority);
            let mut task = probe.task.lock().unwrap().take().unwrap();
            runtime.block_on(async { task.join(&Cx::current().unwrap()).await.unwrap() });
            assert_polled(&probe, admitted);
            app.stop(&mut runtime.inner.state.lock().unwrap()).unwrap();
            assert_eq!(
                runtime.drain_root_region(Duration::from_secs(5)),
                RootDrainOutcome::Quiescent
            );
            app.join(&runtime.inner.state.lock().unwrap()).unwrap();
            assert!(
                runtime.is_quiescent(),
                "a completed root drain must publish deferred app-stop cancellation"
            );
        }
    }
}

#[test]
fn app_authority_native_denied_spawn_cannot_be_laundered_by_bootstrap() {
    for current_thread in [true, false] {
        let runtime = runtime(current_thread);
        let mut cx = runtime.request_cx_with_budget(Budget::INFINITE);
        assert!(cx.blocking_pool_handle().is_some());
        cx = restricted_caller(cx, CapMask::none());
        let (child, probe) = child_probe();
        {
            let mut state = runtime.inner.state.lock().unwrap();
            let before_regions = state.regions_len();
            let result = AppSpec::new("native-denied").child(child).start(
                &mut state,
                &cx,
                runtime.inner.root_region,
            );
            assert!(matches!(
                result,
                Err(AppStartError::SpawnFailed(AppSpawnError::SpawnFailed(
                    SupervisorSpawnError::ChildStartFailed {
                        err: SpawnError::RuntimeUnavailable,
                        ..
                    }
                )))
            ));
            assert_eq!(state.live_task_count(), 0);
            assert_eq!(state.regions_len(), before_regions);
        }
        let boot = probe.boot.lock().unwrap().clone().unwrap();
        assert_eq!(boot.runtime_mask, CapMask::none());
        // Inheritance preserves the handle independently of permission to use
        // it; a public lookup still enforces the removed spawn capability.
        assert!(boot.blocking_pool_handle_for_inheritance().is_some());
        assert!(boot.blocking_pool_handle().is_none());
        assert!(probe.task.lock().unwrap().is_none());
        assert!(probe.polled.lock().unwrap().is_none());
        assert_eq!(
            runtime.drain_root_region(Duration::from_secs(5)),
            RootDrainOutcome::Quiescent
        );
        assert!(
            runtime.is_quiescent(),
            "a completed root drain must publish deferred failed-bootstrap cancellation"
        );
    }
}

#[test]
fn app_stop_root_drain_is_immediately_quiescent_on_native_workers() {
    for iteration in 0..100 {
        let runtime = runtime(false);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let mut app = {
            let mut state = runtime.inner.state.lock().unwrap();
            AppSpec::new("stop-drain-quiescence")
                .start(&mut state, &cx, runtime.inner.root_region)
                .expect("start native app")
        };
        app.stop(&mut runtime.inner.state.lock().unwrap())
            .expect("stop native app");
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
        assert!(
            runtime.is_quiescent(),
            "app-stop drain left parked cancellation at iteration {iteration}: {report:?}"
        );
        app.join(&runtime.inner.state.lock().unwrap())
            .expect("stopped app finished its close protocol");
    }
}

#[test]
fn supervisor_authority_native_direct_boot_keeps_caller_limits() {
    for current_thread in [true, false] {
        let runtime = runtime(current_thread);
        let budget = Budget::INFINITE.with_poll_quota(37).with_cost_quota(41);
        let envelope = CapabilityBudget::new()
            .with_cpu_units(7)
            .with_artifact_bytes(11);
        let mut cx = runtime.request_cx_with_budget(budget);
        cx = restricted_caller(cx, SPAWN_ONLY);
        cx.apply_child_capability_budget(envelope, CapabilityBudgetRequirements::NONE)
            .unwrap();
        let (child, probe) = child_probe();
        let admitted = {
            let mut state = runtime.inner.state.lock().unwrap();
            let supervisor = SupervisorBuilder::new("native-direct")
                .with_budget(Budget::INFINITE)
                .child(child)
                .compile()
                .unwrap()
                .spawn(&mut state, &cx, runtime.inner.root_region, Budget::INFINITE)
                .unwrap();
            let admitted = admitted_authority(&state, supervisor.started[0].task_id);
            assert_eq!(admitted.budget, budget);
            assert_eq!(admitted.envelope, envelope);
            assert_eq!(admitted.mask, SPAWN_ONLY);
            admitted
        };
        runtime
            .inner
            .scheduler
            .inject_ready(admitted.task, admitted.budget.priority);
        let mut task = probe.task.lock().unwrap().take().unwrap();
        runtime.block_on(async { task.join(&Cx::current().unwrap()).await.unwrap() });
        assert_polled(&probe, admitted);
        assert_eq!(
            runtime.drain_root_region(Duration::from_secs(5)),
            RootDrainOutcome::Quiescent
        );
        assert!(runtime.is_quiescent());
    }
}
