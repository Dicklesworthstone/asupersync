//! Real named resources across managed routes, workers, restarts and drain.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::app::{
    AppSpecV1, ManagedAppBindError, ManagedAppBinding, ManagedAppResourceBinding,
    ManagedAppResourceError, ManagedAppResourceRequirement as Requirement, ManagedAppResources,
};
use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::{Cx, cap};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::supervision::{
    BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig,
};
use asupersync::sync::Notify;
use asupersync::types::{Budget, Outcome};
use asupersync::web::extract::Request;
use asupersync::web::{Response, StatusCode};
use asupersync::{LabConfig, LabRuntime};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

fn config() -> SupervisionConfig {
    SupervisionConfig::new(4, Duration::from_secs(60)).with_backoff(BackoffStrategy::None)
}

fn parse(value: Value) -> AppSpecV1 {
    serde_json::from_value(value).unwrap()
}

fn resource(name: &str, kind: &str, capability: &str) -> Value {
    json!({"name": name, "kind": kind, "capability": capability, "feature_flag": null})
}

fn manifest() -> Value {
    json!({
        "schema_version": "asupersync.appspec.v1", "name": "typed-resource-app",
        "services": [{
            "name": "api", "resources": ["state"], "actors": [], "background_jobs": [],
            "routes": [{
                "name": "add", "method": "POST", "path": "/add", "handler": "example::add",
                "required_capabilities": {
                    "cx_capabilities": ["messaging", "trace"],
                    "feature_flags": [], "resources": ["requests"]
                }
            }]
        }, {
            "name": "workers", "resources": ["state"], "routes": [], "background_jobs": [],
            "actors": [{
                "name": "counter", "entrypoint": "example::counter",
                "required_capabilities": {
                    "cx_capabilities": ["messaging", "trace"],
                    "feature_flags": [], "resources": ["inbox", "lifetime"]
                }
            }]
        }],
        "resources": [
            resource("requests", "message_bus", "messaging"),
            resource("inbox", "message_bus", "messaging"),
            resource("state", "memory", "trace"),
            resource("lifetime", "memory", "trace"),
            resource("hidden", "memory", "trace")
        ],
        "budgets": [], "slo_hooks": [], "observability": [],
        "supervision": {
            "root_group": "root",
            "groups": [
                {"name": "root", "services": ["api"], "restart_policy": "one_for_one"},
                {"name": "workers", "services": ["workers"], "restart_policy": "one_for_one"}
            ]
        },
        "compatibility": {
            "fail_closed_unknown_fields": true,
            "fail_closed_unknown_capabilities": true,
            "future_schema_requires_new_version": true
        }
    })
}

fn native<F, Fut>(workers: usize, scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new().worker_threads(workers).build().unwrap()
    };
    let completed = Arc::new(AtomicBool::new(false));
    let completion = Arc::clone(&completed);
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx))
            .await
            .expect("resource execution watchdog");
        completion.store(true, Ordering::Release);
    }));
    assert!(completed.load(Ordering::Acquire));
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

enum Command {
    Add(u64, oneshot::Sender<u64>),
    Fail,
}

#[derive(Clone)]
struct Inbox(Arc<Mutex<Option<mpsc::Receiver<Command>>>>);

struct InboxLease {
    inbox: Arc<Inbox>,
    receiver: Option<mpsc::Receiver<Command>>,
}

impl InboxLease {
    fn take(inbox: Arc<Inbox>) -> Self {
        let receiver = inbox.0.lock().unwrap().take().expect("exclusive generation");
        Self { inbox, receiver: Some(receiver) }
    }
}

impl Drop for InboxLease {
    fn drop(&mut self) {
        let retired = self.inbox.0.lock().unwrap().replace(self.receiver.take().unwrap());
        assert!(retired.is_none(), "generations overlap");
    }
}

#[derive(Default)]
struct State {
    sum: AtomicU64,
    starts: Mutex<Vec<ManagedGeneration>>,
    parked: AtomicUsize,
    draining: AtomicBool,
    release: AtomicBool,
    changed: Notify,
}

struct Lifetime(Arc<AtomicUsize>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn assert_no_ambient_effects(cx: &Cx) {
    let caps = cx.capabilities();
    assert!(!caps.spawn && !caps.time && !caps.entropy && !caps.io && !caps.remote);
    let ambient = Cx::current().unwrap();
    assert_eq!(ambient.task_id(), cx.task_id());
    assert!(!ambient.capabilities().spawn && !ambient.capabilities().io);
}

async fn resource_journey(cx: Cx) {
    let spec = parse(manifest());
    let declaration = |name: &str| {
        spec.resources.iter().find(|r| r.name == name).unwrap().clone()
    };
    let (sender, receiver) = mpsc::channel::<Command>(1);
    let state = Arc::new(State::default());
    let lifetime_drops = Arc::new(AtomicUsize::new(0));
    let hidden_drops = Arc::new(AtomicUsize::new(0));
    let resources = vec![
        ManagedAppResourceBinding::new(declaration("requests"), sender.clone()),
        ManagedAppResourceBinding::new(declaration("inbox"), Inbox(Arc::new(Mutex::new(Some(receiver))))),
        ManagedAppResourceBinding::new(declaration("state"), Arc::clone(&state)),
        ManagedAppResourceBinding::new(declaration("lifetime"), Lifetime(Arc::clone(&lifetime_drops))),
        ManagedAppResourceBinding::new(declaration("hidden"), Lifetime(Arc::clone(&hidden_drops))),
    ];
    let tree = spec.bind_managed_groups_with_resources(
        vec![
            ManagedAppBinding::route_with_resources(
                "api.route.add",
                vec![Requirement::of::<mpsc::Sender<Command>>("requests"), Requirement::of::<Arc<State>>("state")],
                |cx: Cx, _: Request, resources: ManagedAppResources| async move {
                    assert_no_ambient_effects(&cx);
                    assert_eq!(resources.names().collect::<Vec<_>>(), ["requests", "state"]);
                    assert!(matches!(resources.get::<Inbox>("inbox"), Err(ManagedAppResourceError::Undeclared(_))));
                    assert!(matches!(resources.get::<Lifetime>("hidden"), Err(ManagedAppResourceError::Undeclared(_))));
                    assert!(matches!(resources.get::<u32>("state"), Err(ManagedAppResourceError::TypeMismatch { .. })));
                    let sender = resources.get::<mpsc::Sender<Command>>("requests").unwrap();
                    let state = resources.get::<Arc<State>>("state").unwrap();
                    let (reply, mut answer) = oneshot::channel();
                    assert!(sender.send(&cx, Command::Add(3, reply)).await.is_ok());
                    let sum = answer.recv(&cx).await.unwrap();
                    assert_eq!(state.sum.load(Ordering::Acquire), sum);
                    Response::new(StatusCode::OK, sum.to_string())
                },
            ),
            ManagedAppBinding::worker_with_resources(
                "workers.actor.counter",
                ManagedRestartMode::Transient,
                vec![Requirement::of::<Inbox>("inbox"), Requirement::of::<Arc<State>>("state"), Requirement::of::<Lifetime>("lifetime")],
                |cx: Cx, generation: ManagedGeneration, resources: ManagedAppResources| async move {
                    assert_no_ambient_effects(&cx);
                    assert_eq!(resources.names().collect::<Vec<_>>(), ["inbox", "lifetime", "state"]);
                    assert!(matches!(resources.get::<mpsc::Sender<Command>>("requests"), Err(ManagedAppResourceError::Undeclared(_))));
                    let state = resources.get::<Arc<State>>("state").unwrap();
                    let lifetime = resources.get::<Lifetime>("lifetime").unwrap();
                    assert_eq!(generation.task, cx.task_id());
                    assert_eq!(generation.region, cx.region_id());
                    state.starts.lock().unwrap().push(generation);
                    let mut inbox = InboxLease::take(resources.get::<Inbox>("inbox").unwrap());
                    loop {
                        let mut receive = std::pin::pin!(inbox.receiver.as_mut().unwrap().recv(&cx));
                        let command = poll_fn(|task| {
                            let result = receive.as_mut().poll(task);
                            if result.is_pending() {
                                state.parked.fetch_add(1, Ordering::AcqRel);
                                state.changed.notify_waiters();
                            }
                            result
                        }).await;
                        match command {
                            Ok(Command::Add(value, reply)) => {
                                let next = state.sum.fetch_add(value, Ordering::AcqRel) + value;
                                assert!(reply.send_blocking(next).is_ok());
                            }
                            Ok(Command::Fail) => return Outcome::Err("restart with the same resource handles"),
                            Err(mpsc::RecvError::Cancelled) => {
                                assert_eq!(lifetime.0.load(Ordering::Acquire), 0);
                                state.draining.store(true, Ordering::Release);
                                state.changed.notify_waiters();
                                state.changed.wait_until(|| state.release.load(Ordering::Acquire)).await;
                                return Outcome::Cancelled(cx.cancel_reason().unwrap());
                            }
                            Err(_) => return Outcome::Ok(()),
                        }
                    }
                },
            ),
        ],
        resources,
        BTreeMap::from([("root".to_string(), config()), ("workers".to_string(), config())]),
    ).unwrap();
    // No scoped view retains an application-wide catalog or its unused value.
    assert_eq!(hidden_drops.load(Ordering::Acquire), 1);
    assert!(state.starts.lock().unwrap().is_empty());
    let router = tree.router();
    let mut tree = tree.start(&cx).unwrap();
    state.changed.wait_until(|| state.parked.load(Ordering::Acquire) > 0).await;
    while !tree.routes_ready() { yield_now().await; }
    let response = router.handle_with_cx(&cx, Request::new("POST", "/add")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"3");
    assert!(sender.send(&cx, Command::Fail).await.is_ok());
    state.changed.wait_until(|| state.starts.lock().unwrap().len() == 2 && sender.telemetry_snapshot(0).recv_waiter_count > 0).await;
    let response = router.handle_with_cx(&cx, Request::new("POST", "/add")).await;
    assert_eq!(response.body.as_ref(), b"6", "restart must reuse the original state and channel");
    let generations = state.starts.lock().unwrap().clone();
    assert_eq!(generations.iter().map(|g| g.number).collect::<Vec<_>>(), [1, 2]);
    assert_ne!(generations[0].task, generations[1].task);
    assert_ne!(generations[0].region, generations[1].region);
    while sender.telemetry_snapshot(0).recv_waiter_count == 0 { yield_now().await; }
    tree.abort();
    let mut join = Box::pin(tree.join());
    poll_fn(|task| { assert!(join.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
    state.changed.wait_until(|| state.draining.load(Ordering::Acquire)).await;
    assert_eq!(lifetime_drops.load(Ordering::Acquire), 0);
    poll_fn(|task| { assert!(join.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
    assert_eq!(router.handle_with_cx(&cx, Request::new("POST", "/add")).await.status, StatusCode::SERVICE_UNAVAILABLE);
    state.release.store(true, Ordering::Release);
    state.changed.notify_waiters();
    let report = join.await.unwrap();
    assert_eq!(report.root.started, report.root.joined);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].report.started, 2);
    assert_eq!(report.groups[0].report.joined, 2);
    assert_eq!(report.groups[0].report.restart_batches, 1);
    assert_eq!(lifetime_drops.load(Ordering::Acquire), 1);
    assert!(!cx.is_cancel_requested());
}

#[test]
fn named_resources_drive_real_routes_and_worker_restarts_on_native_runtimes() {
    for workers in [1, 2] { native(workers, resource_journey); }
}

#[test]
fn named_resources_reach_seeded_lab_quiescence_after_restart_and_held_drain() {
    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async {
            resource_journey(Cx::current().unwrap()).await;
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(matches!(join.try_join(), Ok(Some(()))), "seed={seed}: {report:?}");
        assert!(lab.state.tasks_is_empty());
        assert!(lab.state.obligations_iter().all(|(_, obligation)| !obligation.is_pending()));
        assert!(report.lab_test_passed(), "seed={seed}: {report:?}");
    }
}

fn simple_manifest() -> Value {
    let mut manifest = manifest();
    manifest["services"] = json!([{
        "name": "worker", "resources": [], "routes": [], "background_jobs": [],
        "actors": [{"name": "run", "entrypoint": "example::run", "required_capabilities": {
            "cx_capabilities": ["trace"], "feature_flags": [], "resources": ["state"]
        }}]
    }]);
    manifest["resources"] = json!([resource("state", "memory", "trace")]);
    manifest["supervision"]["groups"] = json!([{
        "name": "root", "services": ["worker"], "restart_policy": "one_for_one"
    }]);
    manifest
}

fn counted_binding(requirements: Vec<Requirement>, calls: Arc<AtomicUsize>) -> ManagedAppBinding<()> {
    ManagedAppBinding::worker_with_resources(
        "worker.actor.run", ManagedRestartMode::Temporary, requirements,
        move |_: Cx, _: ManagedGeneration, _: ManagedAppResources| {
            calls.fetch_add(1, Ordering::AcqRel);
            async { Outcome::Ok(()) }
        },
    )
}

#[test]
fn resource_preflight_rejects_missing_duplicate_extra_wrong_type_and_wrong_gate_before_work() {
    for case in 0..10 {
        let mut manifest = simple_manifest();
        if case == 8 { manifest["services"][0]["actors"][0]["required_capabilities"]["cx_capabilities"] = json!(["spawn"]); }
        if case == 9 { manifest["resources"][0]["capability"] = json!("messaging"); }
        let spec = parse(manifest);
        let declaration = spec.resources[0].clone();
        let mut resources = vec![ManagedAppResourceBinding::new(declaration.clone(), 7_u64)];
        let mut requirements = vec![Requirement::of::<u64>("state")];
        match case {
            0 => resources.clear(),
            1 => resources.push(ManagedAppResourceBinding::new(declaration.clone(), 8_u64)),
            2 => { let mut extra = declaration.clone(); extra.name = "extra".to_string(); resources.push(ManagedAppResourceBinding::new(extra, 8_u64)); }
            3 => { let mut wrong = declaration.clone(); wrong.kind = asupersync::app::AppResourceKindV1::Database; resources = vec![ManagedAppResourceBinding::new(wrong, 7_u64)]; }
            4 => requirements = vec![Requirement::of::<u32>("state")],
            5 => requirements.clear(),
            6 => requirements.push(Requirement::of::<u64>("extra")),
            7 => requirements.push(Requirement::of::<u64>("state")),
            _ => {}
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let result = spec.bind_managed_with_resources(vec![counted_binding(requirements, Arc::clone(&calls))], resources, config());
        let error = match result { Err(ManagedAppBindError::Resource(error)) => error, _ => panic!("case {case} did not refuse resource preflight") };
        let correct = match case {
            0 => matches!(error, ManagedAppResourceError::MissingBinding(_)),
            1 => matches!(error, ManagedAppResourceError::DuplicateBinding(_)),
            2 => matches!(error, ManagedAppResourceError::UnexpectedBinding(_)),
            3 => matches!(error, ManagedAppResourceError::DeclarationMismatch(_)),
            4 => matches!(error, ManagedAppResourceError::TypeMismatch { .. }),
            5 => matches!(error, ManagedAppResourceError::MissingRequirement { .. }),
            6 => matches!(error, ManagedAppResourceError::UnexpectedRequirement { .. }),
            7 => matches!(error, ManagedAppResourceError::DuplicateRequirement { .. }),
            8 => matches!(error, ManagedAppResourceError::MissingCapability { .. }),
            9 => matches!(error, ManagedAppResourceError::KindCapabilityMismatch(_)),
            _ => unreachable!(),
        };
        assert!(correct, "case {case}: {error:?}");
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
}

#[test]
fn resource_handles_do_not_mint_missing_runtime_io_authority() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let mut manifest = simple_manifest();
            manifest["resources"][0] = resource("state", "file_system", "io");
            manifest["services"][0]["actors"][0]["required_capabilities"]["cx_capabilities"] = json!(["io"]);
            let spec = parse(manifest);
            let resources = vec![ManagedAppResourceBinding::new(spec.resources[0].clone(), 7_u64)];
            let calls = Arc::new(AtomicUsize::new(0));
            let app = spec.bind_managed_with_resources(
                vec![counted_binding(vec![Requirement::of::<u64>("state")], Arc::clone(&calls))],
                resources, config(),
            ).unwrap();
            let restriction = cx.restrict::<cap::CapSet<true, true, true, false, true>>().set_current_restricted();
            let restricted = Cx::current().unwrap();
            assert!(matches!(app.start(&restricted), Err(ManagedAppBindError::Capability { capability: asupersync::app::AppCxCapabilityV1::Io, .. })));
            assert_eq!(calls.load(Ordering::Acquire), 0);
            drop(restriction);
        });
    }
}

#[test]
fn resource_feature_requirements_are_checked_before_any_factory_runs() {
    for (feature, enabled) in [("sqlite", cfg!(feature = "sqlite")), ("postgres", cfg!(feature = "postgres"))] {
        let mut manifest = simple_manifest();
        manifest["resources"][0]["feature_flag"] = json!(feature);
        let spec = parse(manifest);
        let resources = vec![ManagedAppResourceBinding::new(spec.resources[0].clone(), 7_u64)];
        let calls = Arc::new(AtomicUsize::new(0));
        let result = spec.bind_managed_with_resources(
            vec![counted_binding(vec![Requirement::of::<u64>("state")], Arc::clone(&calls))],
            resources,
            config(),
        );
        if enabled {
            assert!(result.is_ok(), "enabled resource feature {feature}");
        } else {
            assert!(matches!(result, Err(ManagedAppBindError::Feature { .. })), "disabled resource feature {feature}");
        }
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
}

#[test]
fn service_resource_union_is_explicit_and_legacy_accepted_shape_is_preserved() {
    let mut manifest = simple_manifest();
    manifest["services"][0]["resources"] = json!(["state"]);
    manifest["services"][0]["actors"][0]["required_capabilities"] = json!({
        "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
    });
    let plain = || ManagedAppBinding::<()>::worker("worker.actor.run", ManagedRestartMode::Temporary, |_: Cx, _| async { Outcome::Ok(()) });
    assert!(parse(manifest.clone()).bind_managed(vec![plain()], config()).is_ok());
    manifest["services"][0]["actors"][0]["required_capabilities"]["cx_capabilities"] = json!(["trace"]);
    let spec = parse(manifest.clone());
    let resources = vec![ManagedAppResourceBinding::new(spec.resources[0].clone(), 7_u64)];
    assert!(matches!(spec.bind_managed_with_resources(vec![plain()], resources, config()), Err(ManagedAppBindError::Resource(ManagedAppResourceError::MissingRequirement { .. }))));
    manifest["services"][0]["actors"][0]["required_capabilities"]["cx_capabilities"] = json!(["spawn"]);
    let spec = parse(manifest);
    let resources = vec![ManagedAppResourceBinding::new(spec.resources[0].clone(), 7_u64)];
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(spec.bind_managed_with_resources(vec![counted_binding(vec![Requirement::of::<u64>("state")], Arc::clone(&calls))], resources, config()), Err(ManagedAppBindError::Resource(ManagedAppResourceError::MissingCapability { .. }))));
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[test]
fn pure_work_refuses_service_inherited_handles_even_when_the_handle_claims_pure() {
    for capability in ["trace", "pure"] {
        let mut manifest = simple_manifest();
        manifest["resources"][0]["capability"] = json!(capability);
        manifest["services"][0]["resources"] = json!(["state"]);
        manifest["services"][0]["actors"][0]["required_capabilities"] = json!({
            "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
        });
        let spec = parse(manifest);
        let resources = vec![ManagedAppResourceBinding::new(spec.resources[0].clone(), 7_u64)];
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            spec.bind_managed_with_resources(
                vec![counted_binding(vec![Requirement::of::<u64>("state")], Arc::clone(&calls))],
                resources,
                config(),
            ),
            Err(ManagedAppBindError::Resource(ManagedAppResourceError::PureWorkHasResources(_)))
        ));
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
}

#[test]
fn resource_aware_signal_jobs_keep_bounded_serial_delivery() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let mut manifest = simple_manifest();
            manifest["services"][0]["actors"] = json!([]);
            manifest["services"][0]["resources"] = json!(["state"]);
            manifest["services"][0]["background_jobs"] = json!([{
                "name": "flush", "entrypoint": "example::flush", "trigger": {"signal": {"source": "flush"}},
                "required_capabilities": {"cx_capabilities": ["trace"], "feature_flags": [], "resources": ["state"]}
            }]);
            let spec = parse(manifest);
            let state = Arc::new(AtomicUsize::new(0));
            let resources = vec![ManagedAppResourceBinding::new(spec.resources[0].clone(), Arc::clone(&state))];
            let entered = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&entered);
            let release = Arc::new(AtomicBool::new(false));
            let released = Arc::clone(&release);
            let changed = Arc::new(Notify::new());
            let event = Arc::clone(&changed);
            let (sender, receiver) = mpsc::channel(2);
            let app = spec.bind_managed_with_resources(vec![
                ManagedAppBinding::<()>::signal_worker_with_resources(
                    "worker.job.flush", "flush", receiver, ManagedRestartMode::Temporary,
                    vec![Requirement::of::<Arc<AtomicUsize>>("state")],
                    move |cx: Cx, _: ManagedGeneration, resources: ManagedAppResources| {
                        let entered = Arc::clone(&observed);
                        let release = Arc::clone(&released);
                        let changed = Arc::clone(&event);
                        async move {
                            assert_no_ambient_effects(&cx);
                            assert_eq!(resources.names().collect::<Vec<_>>(), ["state"]);
                            let state = resources.get::<Arc<AtomicUsize>>("state").unwrap();
                            let index = entered.fetch_add(1, Ordering::AcqRel);
                            assert_eq!(state.load(Ordering::Acquire), index, "invocations overlap");
                            changed.notify_waiters();
                            if index == 0 { changed.wait_until(|| release.load(Ordering::Acquire)).await; }
                            state.fetch_add(1, Ordering::AcqRel);
                            Outcome::Ok(())
                        }
                    },
                )
            ], resources, config()).unwrap();
            let mut app = app.start(&cx).unwrap();
            assert!(sender.send(&cx, ()).await.is_ok());
            changed.wait_until(|| entered.load(Ordering::Acquire) == 1).await;
            assert!(sender.try_send(()).is_ok());
            assert!(sender.try_send(()).is_ok());
            assert!(matches!(sender.try_send(()), Err(mpsc::SendError::Full(()))));
            release.store(true, Ordering::Release);
            changed.notify_waiters();
            drop(sender);
            let report = app.join().await.unwrap();
            assert!(matches!(report.outcome, Outcome::Ok(())));
            assert_eq!(state.load(Ordering::Acquire), 3);
            assert_eq!(entered.load(Ordering::Acquire), 3);
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
        });
    }
}
