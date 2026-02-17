//! Minimal supervised Spork app example (OTP mental model).
//!
//! This example demonstrates, end-to-end:
//! - application start as a region-owned supervision tree
//! - supervisor starting a named GenServer child
//! - client `cast` + `call`
//! - cancel-correct shutdown (`request -> drain -> finalize`)
//! - name lease cleanup (`whereis` returns `None` after termination)

use asupersync::app::AppSpec;
use asupersync::cx::{Cx, NameRegistry, RegistryCap, RegistryHandle};
use asupersync::gen_server::{GenServer, NamedGenServerHandle, NamedSpawnError, Reply, SystemMsg};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::region::RegionState;
use asupersync::runtime::{RuntimeState, SpawnError};
use asupersync::supervision::{ChildSpec, SupervisionStrategy};
use asupersync::types::policy::FailFast;
use asupersync::types::{Budget, CancelReason, RegionId, TaskId, Time};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

type SharedRegistry = Arc<parking_lot::Mutex<NameRegistry>>;
type NamedHandleSlot = Arc<parking_lot::Mutex<Option<NamedGenServerHandle<Counter>>>>;

#[derive(Default)]
struct Counter {
    value: u64,
}

enum CounterCall {
    Get,
}

enum CounterCast {
    Add(u64),
}

impl GenServer for Counter {
    type Call = CounterCall;
    type Reply = u64;
    type Cast = CounterCast;
    type Info = SystemMsg;

    fn handle_call(
        &mut self,
        _cx: &Cx,
        request: Self::Call,
        reply: Reply<Self::Reply>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match request {
            CounterCall::Get => {
                let _ = reply.send(self.value);
            }
        }
        Box::pin(async {})
    }

    fn handle_cast(
        &mut self,
        _cx: &Cx,
        msg: Self::Cast,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match msg {
            CounterCast::Add(delta) => {
                self.value = self.value.saturating_add(delta);
            }
        }
        Box::pin(async {})
    }
}

fn counter_child(registry: &SharedRegistry, named_handle_slot: &NamedHandleSlot) -> ChildSpec {
    let registry_for_child = Arc::clone(registry);
    let named_handle_for_child = Arc::clone(named_handle_slot);

    ChildSpec::new(
        "counter",
        move |scope: &asupersync::Scope<'static, FailFast>,
              state: &mut RuntimeState,
              child_cx: &Cx| {
            let (named_handle, stored) = scope
                .spawn_named_gen_server(
                    state,
                    child_cx,
                    &mut registry_for_child.lock(),
                    "counter",
                    Counter::default(),
                    32,
                    Time::ZERO,
                )
                .map_err(|err| match err {
                    NamedSpawnError::Spawn(spawn_err) => spawn_err,
                    NamedSpawnError::NameTaken(name_err) => SpawnError::NameRegistrationFailed {
                        name: "counter".to_string(),
                        reason: name_err.to_string(),
                    },
                })?;

            let task_id = named_handle.task_id();
            state.store_spawned_task(task_id, stored);
            *named_handle_for_child.lock() = Some(named_handle);

            Ok(task_id)
        },
    )
    .with_restart(SupervisionStrategy::Stop)
}

fn request_cancel_and_drain(runtime: &mut LabRuntime, app_region: RegionId) {
    for _ in 0..8 {
        let to_cancel = runtime
            .state
            .cancel_request(app_region, &CancelReason::shutdown(), None);

        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in to_cancel {
                scheduler.schedule_cancel(task_id, priority);
            }
        }

        runtime.run_until_quiescent();
        runtime.state.advance_region_state(app_region);

        if runtime
            .state
            .region(app_region)
            .is_some_and(|region| region.state() == RegionState::Closed)
        {
            break;
        }
    }
}

fn stop_named_server(
    runtime: &mut LabRuntime,
    registry: &SharedRegistry,
    named_handle_slot: &NamedHandleSlot,
    counter_task: TaskId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut guard = named_handle_slot.lock();
    let handle = guard.as_mut().ok_or("counter handle missing at shutdown")?;
    handle.stop_and_release()?;
    drop(guard);

    {
        let mut scheduler = runtime.scheduler.lock();
        scheduler.schedule(counter_task, 0);
    }

    runtime.run_until_quiescent();
    registry.lock().unregister("counter")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arc::new(parking_lot::Mutex::new(NameRegistry::new()));
    let registry_cap = RegistryHandle::new(Arc::clone(&registry) as Arc<dyn RegistryCap>);
    let named_handle_slot: NamedHandleSlot = Arc::new(parking_lot::Mutex::new(None));

    let mut runtime = LabRuntime::new(LabConfig::default());
    let parent_region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::new(parent_region, TaskId::testing_default(), Budget::INFINITE);

    let app = AppSpec::new("counter_app")
        .with_registry(registry_cap)
        .child(counter_child(&registry, &named_handle_slot))
        .start(&mut runtime.state, &cx, parent_region)?;

    let app_region = app.root_region();

    let counter_task = registry
        .lock()
        .whereis("counter")
        .ok_or("counter must be registered")?;

    let server_ref = named_handle_slot
        .lock()
        .as_ref()
        .ok_or("counter handle missing")?
        .server_ref();

    server_ref.try_cast(CounterCast::Add(2))?;
    server_ref.try_cast(CounterCast::Add(3))?;

    let client_cx = cx.clone();
    let client_ref = server_ref;
    let (client_task, client_handle) =
        runtime
            .state
            .create_task(app_region, Budget::INFINITE, async move {
                client_ref
                    .call(&client_cx, CounterCall::Get)
                    .await
                    .expect("counter call must succeed")
            })?;

    {
        let mut scheduler = runtime.scheduler.lock();
        scheduler.schedule(counter_task, 0);
        scheduler.schedule(client_task, 0);
    }

    runtime.run_until_quiescent();

    let observed =
        futures_lite::future::block_on(client_handle.join(&cx)).expect("client join must succeed");
    assert_eq!(observed, 5);

    stop_named_server(&mut runtime, &registry, &named_handle_slot, counter_task)?;

    let _stopped = app.stop(&mut runtime.state)?;
    request_cancel_and_drain(&mut runtime, app_region);

    let app_region_record = runtime
        .state
        .region(app_region)
        .ok_or("app region missing after stop")?;
    assert_ne!(app_region_record.state(), RegionState::Open);
    assert!(
        app_region_record.cancel_reason().is_some(),
        "stop must mark cancel intent on the app region"
    );
    if app_region_record.state() == RegionState::Closed {
        assert!(app_region_record.is_quiescent());
    }

    assert!(
        registry.lock().whereis("counter").is_none(),
        "name lease must resolve on termination"
    );

    Ok(())
}
