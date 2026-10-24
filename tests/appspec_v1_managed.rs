//! Executing AppSpec bindings: real native/Lab tasks, routes, limits and drain.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::app::{AppSpecV1, ManagedAppBindError, ManagedAppBinding};
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::supervision::{
    BackoffStrategy, ManagedGeneration, ManagedRestartMode, SupervisionConfig,
};
use asupersync::sync::Notify;
use asupersync::types::{Budget, CancelKind, CapabilityBudget, Outcome};
use asupersync::web::extract::Request;
use asupersync::web::{AsyncCxFnHandler, Response, StatusCode};
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

fn manifest_json() -> Value {
    json!({
        "schema_version": "asupersync.appspec.v1",
        "name": "managed-example",
        "services": [{
            "name": "api",
            "routes": [{
                "name": "health", "method": "GET", "path": "/health",
                "handler": "example::health",
                "required_capabilities": {
                    "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
                },
                "budget": "work"
            }],
            "actors": [{
                "name": "cache", "entrypoint": "example::cache",
                "required_capabilities": {
                    "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
                },
                "budget": "work"
            }],
            "background_jobs": [], "resources": []
        }],
        "resources": [],
        "budgets": [{"name": "work", "poll_quota": 64, "io_bytes": 512, "memory_bytes": 1024}],
        "slo_hooks": [],
        "supervision": {
            "root_group": "root",
            "groups": [{"name": "root", "services": ["api"], "restart_policy": "one_for_one"}]
        },
        "observability": [],
        "compatibility": {
            "fail_closed_unknown_fields": true,
            "fail_closed_unknown_capabilities": true,
            "future_schema_requires_new_version": true
        }
    })
}

fn parse(value: Value) -> AppSpecV1 {
    serde_json::from_value(value).unwrap()
}

fn config() -> SupervisionConfig {
    SupervisionConfig::new(4, Duration::from_secs(60)).with_backoff(BackoffStrategy::None)
}

fn native<F, Fut>(workers: usize, scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new()
            .worker_threads(workers)
            .build()
            .unwrap()
    };
    let completed = Arc::new(AtomicBool::new(false));
    let completion = Arc::clone(&completed);
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx.clone()))
            .await
            .expect("managed AppSpec watchdog");
        completion.store(true, Ordering::Release);
    }));
    assert!(
        completed.load(Ordering::Acquire),
        "native scenario did not complete"
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

fn assert_pure_work_context(cx: &Cx) {
    let caps = cx.capabilities();
    assert!(!caps.spawn && !caps.time && !caps.entropy && !caps.io && !caps.remote);
    assert!(cx.registry_handle().is_none());
    assert!(cx.budget().poll_quota <= 64);
    assert_eq!(cx.capability_budget().io_bytes, Some(128));
    assert_eq!(cx.capability_budget().memory_bytes, Some(256));
    let ambient = Cx::current().expect("user poll has an actual task context");
    assert_eq!(ambient.task_id(), cx.task_id());
    assert_eq!(ambient.region_id(), cx.region_id());
    assert!(!ambient.capabilities().spawn);
    assert!(
        ambient
            .spawn(|_| async { panic!("pure workload escaped through ambient spawn") })
            .is_err()
    );
}

async fn route_and_restart_scenario(cx: Cx) {
    route_and_restart_with_envelope(cx, false).await;
}

async fn route_and_restart_with_envelope(cx: Cx, context_only: bool) {
    let mut envelope = CapabilityBudget::UNSPECIFIED;
    envelope.io_bytes = Some(128);
    envelope.memory_bytes = Some(256);
    let mut spec = ChildRegionSpec::inherit();
    if context_only {
        // A context can be narrower than its owning region. Deriving an
        // application region must preserve that limit through route calls
        // and worker restarts, even when the manifest requests more.
        cx.apply_child_capability_budget(
            envelope,
            asupersync::types::CapabilityBudgetRequirements::NONE,
        )
        .unwrap();
    } else {
        spec.capability_budget = Some(envelope);
    }
    let parent = cx.open_child_region(spec).await.unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let route_calls = Arc::new(AtomicUsize::new(0));
    let actor_starts = Arc::clone(&starts);
    let calls = Arc::clone(&route_calls);
    let app = parse(manifest_json())
        .bind_managed(
            vec![
                ManagedAppBinding::route(
                    "api.route.health",
                    AsyncCxFnHandler::new(move |cx: Cx| {
                        let calls = Arc::clone(&calls);
                        async move {
                            assert_pure_work_context(&cx);
                            yield_now().await;
                            assert_pure_work_context(&cx);
                            calls.fetch_add(1, Ordering::AcqRel);
                            Response::new(StatusCode::OK, "healthy")
                        }
                    }),
                ),
                ManagedAppBinding::worker(
                    "api.actor.cache",
                    ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        // Construction and resumed polling both see the attenuated Cx.
                        assert_pure_work_context(&cx);
                        assert_eq!(generation.task, cx.task_id());
                        assert_eq!(generation.region, cx.region_id());
                        let attempt = actor_starts.fetch_add(1, Ordering::AcqRel);
                        async move {
                            yield_now().await;
                            assert_pure_work_context(&cx);
                            if attempt == 0 {
                                Outcome::Err("retry")
                            } else {
                                Outcome::Ok(())
                            }
                        }
                    },
                ),
            ],
            config(),
        )
        .unwrap();
    let router = app.router();
    assert_eq!(
        router
            .handle_with_cx(&cx, Request::new("GET", "/health"))
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        starts.load(Ordering::Acquire),
        0,
        "binding must not invoke factories"
    );
    let mut app = app.start(parent.cx()).unwrap();
    while !app.routes_ready() || starts.load(Ordering::Acquire) < 2 {
        yield_now().await;
    }
    let response = router
        .handle_with_cx(&cx, Request::new("GET", "/health"))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"healthy");
    assert_eq!(
        router
            .handle_with_cx(&cx, Request::new("POST", "/health"))
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(route_calls.load(Ordering::Acquire), 1);
    app.abort();
    let report = app.join().await.unwrap();
    assert_eq!(report.started, 3);
    assert_eq!(report.joined, report.started);
    assert_eq!(report.restart_batches, 1);
    assert!(matches!(report.outcome, Outcome::Cancelled(_)));
    assert!(!app.routes_ready());
    assert_eq!(
        router
            .handle_with_cx(&cx, Request::new("GET", "/health"))
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    parent.close().await.unwrap();
}

#[derive(Default)]
struct DrainWitness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    release: AtomicBool,
    retired: AtomicBool,
    changed: Notify,
}

struct Retired(Arc<DrainWitness>);
impl Drop for Retired {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

async fn stop_drains_request_scenario(cx: Cx) {
    let mut manifest = manifest_json();
    manifest["services"][0]["actors"] = json!([]);
    let witness = Arc::new(DrainWitness::default());
    let seen = Arc::clone(&witness);
    let app = parse(manifest)
        .bind_managed::<()>(
            vec![ManagedAppBinding::route(
                "api.route.health",
                AsyncCxFnHandler::new(move |cx: Cx| {
                    let seen = Arc::clone(&seen);
                    async move {
                        let _retired = Retired(Arc::clone(&seen));
                        let mut cancelled = std::pin::pin!(cx.cancelled());
                        poll_fn(|task| {
                            let progress = cancelled.as_mut().poll(task);
                            if progress.is_pending() {
                                seen.parked.store(true, Ordering::Release);
                                seen.changed.notify_waiters();
                            }
                            progress
                        })
                        .await;
                        assert!(cx.checkpoint().is_err());
                        assert!(cx.cancel_reason().is_some());
                        seen.cancelled.store(true, Ordering::Release);
                        seen.changed.notify_waiters();
                        seen.changed
                            .wait_until(|| seen.release.load(Ordering::Acquire))
                            .await;
                        Response::empty(StatusCode::OK)
                    }
                }),
            )],
            config(),
        )
        .unwrap();
    let mut app = app.start(&cx).unwrap();
    while !app.routes_ready() {
        yield_now().await;
    }
    let router = app.router();
    let mut request = cx
        .spawn(move |cx| async move {
            router
                .handle_with_cx(&cx, Request::new("GET", "/health"))
                .await
        })
        .unwrap();
    witness
        .changed
        .wait_until(|| witness.parked.load(Ordering::Acquire))
        .await;
    app.abort();
    witness
        .changed
        .wait_until(|| witness.cancelled.load(Ordering::Acquire))
        .await;
    let mut joined = std::pin::pin!(app.join());
    poll_fn(|task| {
        assert!(
            joined.as_mut().poll(task).is_pending(),
            "stop returned before request cleanup"
        );
        Poll::Ready(())
    })
    .await;
    assert!(!witness.retired.load(Ordering::Acquire));
    witness.release.store(true, Ordering::Release);
    witness.changed.notify_waiters();
    let report = joined.await.unwrap();
    assert_eq!(report.started, report.joined);
    assert!(witness.retired.load(Ordering::Acquire));
    let response = request.join(&cx).await.unwrap();
    // The handler acknowledged cancellation and intentionally completed a
    // response after cleanup; the normal TaskHandle contract preserves it.
    assert_eq!(response.status, StatusCode::OK);
}

async fn deadline_scenario(cx: Cx) {
    let mut manifest = manifest_json();
    manifest["services"][0]["routes"] = json!([]);
    manifest["services"][0]["actors"][0]["required_capabilities"]["cx_capabilities"] =
        json!(["time"]);
    manifest["budgets"][0]["deadline_ms"] = json!(50);
    let observed = Arc::new(AtomicBool::new(false));
    let parked = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&observed);
    let parked_work = Arc::clone(&parked);
    let app = parse(manifest)
        .bind_managed(
            vec![ManagedAppBinding::worker(
                "api.actor.cache",
                ManagedRestartMode::Temporary,
                move |cx: Cx, _| {
                    let seen = Arc::clone(&seen);
                    let parked_work = Arc::clone(&parked_work);
                    async move {
                        assert!(cx.budget().deadline.is_some());
                        // No workload timer or self-wake: the application must
                        // actively drive its declared deadline for this park.
                        let mut cancelled = std::pin::pin!(cx.cancelled());
                        poll_fn(|task| {
                            let progress = cancelled.as_mut().poll(task);
                            if progress.is_pending() {
                                parked_work.store(true, Ordering::Release);
                            }
                            progress
                        })
                        .await;
                        assert!(cx.checkpoint().is_err());
                        let reason = cx.cancel_reason().unwrap();
                        assert_eq!(reason.kind, CancelKind::Deadline);
                        seen.store(true, Ordering::Release);
                        Outcome::<(), ()>::Cancelled(reason)
                    }
                },
            )],
            config(),
        )
        .unwrap();
    let report = app.run(&cx).await.unwrap();
    assert!(
        observed.load(Ordering::Acquire),
        "the declared deadline must wake parked work"
    );
    assert!(
        parked.load(Ordering::Acquire),
        "deadline workload never actually parked"
    );
    assert_eq!(report.started, 1);
    assert_eq!(report.joined, 1);
    assert_eq!(report.restart_batches, 0);
}

async fn jobs_scenario(cx: Cx) {
    let mut manifest = manifest_json();
    manifest["services"][0]["routes"] = json!([]);
    manifest["services"][0]["actors"] = json!([]);
    manifest["services"][0]["background_jobs"] = json!([
        {
            "name": "startup", "entrypoint": "example::startup", "trigger": "startup",
            "required_capabilities": {"cx_capabilities": ["pure"], "feature_flags": [], "resources": []},
            "budget": "work"
        },
        {
            "name": "interval", "entrypoint": "example::interval", "trigger": {"interval": {"every_ms": 10}},
            "required_capabilities": {"cx_capabilities": ["time"], "feature_flags": [], "resources": []},
            "budget": "work"
        }
    ]);
    let startup_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&startup_calls);
    let ticks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observations = Arc::clone(&ticks);
    let changed = Arc::new(Notify::new());
    let notify = Arc::clone(&changed);
    let started_at = cx.now();
    let app = parse(manifest)
        .bind_managed(
            vec![
                ManagedAppBinding::worker(
                    "api.job.startup",
                    ManagedRestartMode::Temporary,
                    move |cx: Cx, _| {
                        assert!(!cx.capabilities().spawn);
                        calls.fetch_add(1, Ordering::AcqRel);
                        async { Outcome::<(), ()>::Ok(()) }
                    },
                ),
                ManagedAppBinding::worker(
                    "api.job.interval",
                    ManagedRestartMode::Temporary,
                    move |cx: Cx, generation: ManagedGeneration| {
                        let observations = Arc::clone(&observations);
                        let notify = Arc::clone(&notify);
                        async move {
                            assert!(cx.capabilities().time);
                            assert!(!cx.capabilities().spawn);
                            assert!(cx.budget().poll_quota <= 64);
                            observations.lock().unwrap().push((
                                cx.now(),
                                generation.region,
                                generation.task,
                            ));
                            notify.notify_waiters();
                            Outcome::<(), ()>::Ok(())
                        }
                    },
                ),
            ],
            config(),
        )
        .unwrap();
    assert_eq!(startup_calls.load(Ordering::Acquire), 0);
    let mut app = app.start(&cx).unwrap();
    changed
        .wait_until(|| ticks.lock().unwrap().len() >= 2)
        .await;
    app.abort();
    let report = app.join().await.unwrap();
    assert_eq!(startup_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        report.started, 2,
        "interval invocations share one managed generation"
    );
    assert_eq!(report.joined, 2);
    assert_eq!(report.restart_batches, 0);
    let ticks = ticks.lock().unwrap();
    assert!(ticks[0].0 >= started_at + Duration::from_millis(10));
    for pair in ticks.windows(2) {
        assert!(pair[1].0 >= pair[0].0 + Duration::from_millis(10));
        assert_ne!(
            pair[0].1, pair[1].1,
            "each invocation owns a fresh budget region"
        );
        assert_ne!(pair[0].2, pair[1].2, "each invocation owns an actual task");
    }
}

async fn interval_parent_deadline_scenario(cx: Cx) {
    let mut manifest = manifest_json();
    manifest["services"][0]["routes"] = json!([]);
    manifest["services"][0]["actors"] = json!([]);
    manifest["services"][0]["background_jobs"] = json!([{
        "name": "interval", "entrypoint": "example::interval",
        "trigger": {"interval": {"every_ms": 30_000}},
        "required_capabilities": {"cx_capabilities": ["pure"], "feature_flags": [], "resources": []}
    }]);
    let owner_deadline = cx.now() + Duration::from_millis(50);
    let parent = cx
        .open_child_region(
            ChildRegionSpec::inherit().with_budget(Budget::new().with_deadline(owner_deadline)),
        )
        .await
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let starts = Arc::clone(&calls);
    let app = parse(manifest)
        .bind_managed(
            vec![ManagedAppBinding::worker(
                "api.job.interval",
                ManagedRestartMode::Temporary,
                move |_: Cx, _| {
                    starts.fetch_add(1, Ordering::AcqRel);
                    async { Outcome::<(), ()>::Ok(()) }
                },
            )],
            config(),
        )
        .unwrap();
    let report = app.run(parent.cx()).await.unwrap();
    assert!(
        cx.now() < owner_deadline + Duration::from_secs(1),
        "interval waited past its inherited deadline"
    );
    assert_eq!(
        calls.load(Ordering::Acquire),
        0,
        "expired parent admitted an interval invocation"
    );
    assert_eq!(report.started, 1);
    assert_eq!(report.joined, 1);
    assert!(
        matches!(&report.children[0].outcome, Outcome::Cancelled(reason) if reason.kind == CancelKind::Deadline)
    );
    parent.close().await.unwrap();
}

#[test]
fn managed_app_executes_routes_restarts_and_enforces_context_on_native_workers() {
    for workers in [1, 4] {
        native(workers, route_and_restart_scenario);
    }
}

#[test]
fn managed_app_preserves_context_only_envelope_across_routes_and_restarts() {
    for workers in [1, 4] {
        native(workers, |cx| route_and_restart_with_envelope(cx, true));
    }
}

#[test]
fn managed_app_stop_waits_for_parked_request_cleanup_on_native_workers() {
    for workers in [1, 4] {
        native(workers, stop_drains_request_scenario);
    }
}

#[test]
fn managed_app_deadline_cancels_parked_work_on_native_workers() {
    for workers in [1, 4] {
        native(workers, deadline_scenario);
    }
}

#[test]
fn managed_app_executes_startup_and_interval_jobs_on_native_workers() {
    for workers in [1, 4] {
        native(workers, jobs_scenario);
    }
}

#[test]
fn managed_app_interval_wait_obeys_nearer_parent_deadline_on_native_workers() {
    for workers in [1, 4] {
        native(workers, interval_parent_deadline_scenario);
    }
}

#[test]
fn managed_app_lab_execution_reaches_quiescence() {
    use asupersync::{LabConfig, LabRuntime};
    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                let cx = Cx::current().unwrap();
                route_and_restart_scenario(cx.clone()).await;
                stop_drains_request_scenario(cx.clone()).await;
                deadline_scenario(cx.clone()).await;
                jobs_scenario(cx.clone()).await;
                interval_parent_deadline_scenario(cx).await;
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        // The deadline and interval scenarios park on virtual timers.
        // run_until_quiescent never advances virtual time, so it idled at
        // t=0 until max_steps; drive the timers, then take the report.
        let virtual_time = lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(
            matches!(join.try_join(), Ok(Some(()))),
            "{virtual_time:?} {report:?}"
        );
        assert!(lab.state.tasks_is_empty(), "managed app left live tasks");
        assert!(lab.state.obligations_iter().all(|(_, o)| !o.is_pending()));
        assert!(report.lab_test_passed(), "{report:?}");
    }
}

#[test]
fn managed_app_rejects_unbound_or_unsupported_work_before_factory_calls() {
    let starts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&starts);
    let missing = parse(manifest_json()).bind_managed(
        vec![ManagedAppBinding::worker(
            "api.actor.cache",
            ManagedRestartMode::Temporary,
            move |_: Cx, _| {
                seen.fetch_add(1, Ordering::AcqRel);
                async { Outcome::<(), ()>::Ok(()) }
            },
        )],
        config(),
    );
    assert!(
        matches!(missing, Err(ManagedAppBindError::Missing(name)) if name == "api.route.health")
    );
    assert_eq!(starts.load(Ordering::Acquire), 0);

    let mut signal = manifest_json();
    signal["services"][0]["routes"] = json!([]);
    signal["services"][0]["actors"] = json!([]);
    signal["services"][0]["background_jobs"] = json!([{
        "name": "signal", "entrypoint": "example::signal", "trigger": {"signal": {"source": "reload"}},
        "required_capabilities": {"cx_capabilities": ["pure"], "feature_flags": [], "resources": []}
    }]);
    let unsupported = parse(signal).bind_managed(
        vec![ManagedAppBinding::worker(
            "api.job.signal",
            ManagedRestartMode::Temporary,
            |_: Cx, _| async { Outcome::<(), ()>::Ok(()) },
        )],
        config(),
    );
    assert!(matches!(
        unsupported,
        Err(ManagedAppBindError::Unsupported { .. })
    ));
}

fn route_entry(name: &str, method: &str, path: &str) -> Value {
    json!({
        "name": name, "method": method, "path": path, "handler": "example::route",
        "required_capabilities": {
            "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
        },
        "budget": "work"
    })
}

fn bind_two_routes(
    first: (&str, &str),
    second: (&str, &str),
) -> Result<asupersync::app::ManagedApp<()>, ManagedAppBindError> {
    let mut manifest = manifest_json();
    manifest["services"][0]["actors"] = json!([]);
    manifest["services"][0]["routes"] = json!([
        route_entry("first", first.0, first.1),
        route_entry("second", second.0, second.1),
    ]);
    parse(manifest).bind_managed::<()>(
        vec![
            ManagedAppBinding::route(
                "api.route.first",
                AsyncCxFnHandler::new(|_: Cx| async { Response::new(StatusCode::OK, "first") }),
            ),
            ManagedAppBinding::route(
                "api.route.second",
                AsyncCxFnHandler::new(|_: Cx| async { Response::new(StatusCode::OK, "second") }),
            ),
        ],
        config(),
    )
}

/// Routes the web router merges or shadows are one route: a trailing slash or
/// a renamed parameter with the same method is a duplicate, refused before
/// any handler is silently unreachable (br-asupersync-mopkmt).
#[test]
fn managed_app_refuses_routes_the_router_would_merge_or_shadow() {
    for (first, second) in [
        (("GET", "/users"), ("GET", "/users/")),
        (("GET", "/users/:id"), ("GET", "/users/:uid")),
    ] {
        assert!(
            matches!(
                bind_two_routes(first, second),
                Err(ManagedAppBindError::Duplicate(name)) if name == "api.route.second"
            ),
            "{first:?} and {second:?} are one route"
        );
    }
    // Different methods on one route shape are merged into one method router,
    // so neither handler is shadowed.
    assert!(bind_two_routes(("GET", "/users/:id"), ("DELETE", "/users/:uid")).is_ok());
}

fn signal_job_manifest() -> Value {
    let mut manifest = manifest_json();
    manifest["services"][0]["routes"] = json!([]);
    manifest["services"][0]["actors"] = json!([]);
    manifest["services"][0]["background_jobs"] = json!([{
        "name": "reload", "entrypoint": "example::reload",
        "trigger": {"signal": {"source": "reload"}},
        "required_capabilities": {
            "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
        },
        "budget": "work"
    }]);
    manifest
}

fn signal_parent_spec() -> ChildRegionSpec {
    let mut envelope = CapabilityBudget::UNSPECIFIED;
    envelope.io_bytes = Some(128);
    envelope.memory_bytes = Some(256);
    let mut spec = ChildRegionSpec::inherit();
    spec.capability_budget = Some(envelope);
    spec
}

#[derive(Default)]
struct SignalSerialState {
    starts: AtomicUsize,
    active: AtomicUsize,
    retired: AtomicUsize,
    release_first: AtomicBool,
    generations: std::sync::Mutex<Vec<ManagedGeneration>>,
    changed: Notify,
}

struct SignalInvocationGuard(Arc<SignalSerialState>);

impl Drop for SignalInvocationGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.retired.fetch_add(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

fn enter_signal_invocation(
    state: &Arc<SignalSerialState>,
    cx: &Cx,
    generation: ManagedGeneration,
) -> (usize, SignalInvocationGuard) {
    assert_pure_work_context(cx);
    assert_eq!(generation.task, cx.task_id());
    assert_eq!(generation.region, cx.region_id());
    let index = state.starts.fetch_add(1, Ordering::AcqRel);
    assert_eq!(
        state.retired.load(Ordering::Acquire),
        index,
        "the preceding invocation must retire before the next factory"
    );
    assert_eq!(
        state.active.fetch_add(1, Ordering::AcqRel),
        0,
        "signal invocations must never overlap"
    );
    state.generations.lock().unwrap().push(generation);
    state.changed.notify_waiters();
    (index, SignalInvocationGuard(Arc::clone(state)))
}

fn assert_signal_invocations(state: &SignalSerialState, numbers: &[u64]) {
    assert_eq!(state.starts.load(Ordering::Acquire), numbers.len());
    assert_eq!(state.retired.load(Ordering::Acquire), numbers.len());
    assert_eq!(state.active.load(Ordering::Acquire), 0);
    let generations = state.generations.lock().unwrap();
    let observed: Vec<_> = generations.iter().map(|generation| generation.number).collect();
    assert_eq!(observed, numbers);
    for (index, invocation) in generations.iter().enumerate() {
        for previous in &generations[..index] {
            assert_ne!(invocation.region, previous.region, "fresh invocation region");
            assert_ne!(invocation.task, previous.task, "fresh invocation task");
        }
    }
}

async fn signal_queue_with_mode(cx: Cx, mode: ManagedRestartMode) {
    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let state = Arc::new(SignalSerialState::default());
    let seen = Arc::clone(&state);
    let (tx, rx) = asupersync::channel::mpsc::channel(2);
    let app = parse(signal_job_manifest())
        .bind_managed(
            vec![ManagedAppBinding::signal_worker(
                "api.job.reload",
                "reload",
                rx,
                mode,
                move |cx: Cx, generation: ManagedGeneration| {
                    let seen = Arc::clone(&seen);
                    let (index, retired) = enter_signal_invocation(&seen, &cx, generation);
                    async move {
                        let _retired = retired;
                        if index == 0 {
                            seen.changed
                                .wait_until(|| seen.release_first.load(Ordering::Acquire))
                                .await;
                        }
                        yield_now().await;
                        assert_pure_work_context(&cx);
                        Outcome::<(), ()>::Ok(())
                    }
                },
            )],
            config(),
        )
        .unwrap();
    assert_eq!(state.starts.load(Ordering::Acquire), 0);
    let mut app = app.start(parent.cx()).unwrap();
    while tx.telemetry_snapshot(0).recv_waiter_count == 0 {
        yield_now().await;
    }
    assert_eq!(
        state.starts.load(Ordering::Acquire),
        0,
        "starting a signal listener must not invoke its workload"
    );
    tx.try_send(()).unwrap();
    state
        .changed
        .wait_until(|| state.starts.load(Ordering::Acquire) == 1)
        .await;
    tx.try_send(()).unwrap();
    tx.try_send(()).unwrap();
    assert!(matches!(
        tx.try_send(()),
        Err(asupersync::channel::mpsc::SendError::Full(()))
    ));
    {
        let mut blocked = Box::pin(tx.send(&cx, ()));
        poll_fn(|task| {
            assert!(
                blocked.as_mut().poll(task).is_pending(),
                "a full signal queue must backpressure its sender"
            );
            Poll::Ready(())
        })
        .await;
        assert_eq!(state.starts.load(Ordering::Acquire), 1);
        assert_eq!(state.active.load(Ordering::Acquire), 1);
        state.release_first.store(true, Ordering::Release);
        state.changed.notify_waiters();
        blocked.await.unwrap();
    }
    // EOF is only observed after all four accepted notifications are drained.
    drop(tx);
    let report = app.join().await.unwrap();
    assert_signal_invocations(&state, &[1, 1, 1, 1]);
    assert_eq!(report.started, 1, "events share a managed generation");
    assert_eq!(report.joined, 1);
    assert_eq!(report.restart_batches, 0);
    assert!(matches!(report.outcome, Outcome::Ok(())));
    parent.close().await.unwrap();
}

async fn signal_queue_scenario(cx: Cx) {
    signal_queue_with_mode(cx.clone(), ManagedRestartMode::Temporary).await;
    signal_queue_with_mode(cx, ManagedRestartMode::Transient).await;
}

async fn signal_restart_scenario(cx: Cx) {
    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let state = Arc::new(SignalSerialState::default());
    let seen = Arc::clone(&state);
    let (tx, rx) = asupersync::channel::mpsc::channel(3);
    for _ in 0..3 {
        tx.try_send(()).unwrap();
    }
    drop(tx);
    let app = parse(signal_job_manifest())
        .bind_managed(
            vec![ManagedAppBinding::signal_worker(
                "api.job.reload",
                "reload",
                rx,
                ManagedRestartMode::Transient,
                move |cx: Cx, generation: ManagedGeneration| {
                    let (index, retired) = enter_signal_invocation(&seen, &cx, generation);
                    async move {
                        let _retired = retired;
                        yield_now().await;
                        assert_pure_work_context(&cx);
                        if index == 0 {
                            Outcome::Err("first event failed")
                        } else {
                            Outcome::Ok(())
                        }
                    }
                },
            )],
            config(),
        )
        .unwrap();
    let report = app.run(parent.cx()).await.unwrap();
    assert_signal_invocations(&state, &[1, 2, 2]);
    assert_eq!(report.started, 2);
    assert_eq!(report.joined, 2);
    assert_eq!(report.restart_batches, 1);
    assert!(matches!(report.outcome, Outcome::Ok(())));
    parent.close().await.unwrap();
}

async fn signal_cancel_drain_scenario(cx: Cx) {
    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let witness = Arc::new(DrainWitness::default());
    let seen = Arc::clone(&witness);
    let calls = Arc::new(AtomicUsize::new(0));
    let starts = Arc::clone(&calls);
    let (tx, rx) = asupersync::channel::mpsc::channel(1);
    let app = parse(signal_job_manifest())
        .bind_managed(
            vec![ManagedAppBinding::signal_worker(
                "api.job.reload",
                "reload",
                rx,
                ManagedRestartMode::Transient,
                move |cx: Cx, generation: ManagedGeneration| {
                    assert_pure_work_context(&cx);
                    assert_eq!(generation.task, cx.task_id());
                    assert_eq!(generation.region, cx.region_id());
                    starts.fetch_add(1, Ordering::AcqRel);
                    let seen = Arc::clone(&seen);
                    async move {
                        let _retired = Retired(Arc::clone(&seen));
                        let mut cancelled = std::pin::pin!(cx.cancelled());
                        poll_fn(|task| {
                            let progress = cancelled.as_mut().poll(task);
                            if progress.is_pending() {
                                seen.parked.store(true, Ordering::Release);
                                seen.changed.notify_waiters();
                            }
                            progress
                        })
                        .await;
                        assert!(cx.checkpoint().is_err());
                        let reason = cx.cancel_reason().expect("active signal cancellation");
                        seen.cancelled.store(true, Ordering::Release);
                        seen.changed.notify_waiters();
                        seen.changed
                            .wait_until(|| seen.release.load(Ordering::Acquire))
                            .await;
                        Outcome::<(), ()>::Cancelled(reason)
                    }
                },
            )],
            config(),
        )
        .unwrap();
    let mut app = app.start(parent.cx()).unwrap();
    tx.try_send(()).unwrap();
    witness
        .changed
        .wait_until(|| witness.parked.load(Ordering::Acquire))
        .await;
    tx.try_send(()).unwrap();
    assert!(matches!(
        tx.try_send(()),
        Err(asupersync::channel::mpsc::SendError::Full(()))
    ));
    app.abort();
    witness
        .changed
        .wait_until(|| witness.cancelled.load(Ordering::Acquire))
        .await;
    let mut joined = Box::pin(app.join());
    poll_fn(|task| {
        assert!(
            joined.as_mut().poll(task).is_pending(),
            "application joined before active signal cleanup retired"
        );
        Poll::Ready(())
    })
    .await;
    assert!(!witness.retired.load(Ordering::Acquire));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    witness.release.store(true, Ordering::Release);
    witness.changed.notify_waiters();
    let report = joined.await.unwrap();
    assert!(witness.retired.load(Ordering::Acquire));
    assert_eq!(
        calls.load(Ordering::Acquire),
        1,
        "stop must not admit the queued signal"
    );
    assert_eq!(report.started, 1);
    assert_eq!(report.joined, 1);
    assert_eq!(report.restart_batches, 0);
    assert!(matches!(report.outcome, Outcome::Cancelled(_)));
    assert!(tx.is_closed(), "joined app must release its signal receiver");
    assert!(matches!(
        tx.try_send(()),
        Err(asupersync::channel::mpsc::SendError::Disconnected(()))
    ));
    parent.close().await.unwrap();
}

#[test]
fn managed_app_signal_queue_is_bounded_serial_and_context_limited() {
    for workers in [1, 4] {
        native(workers, signal_queue_scenario);
    }
}

#[test]
fn managed_app_signal_restart_consumes_failed_event_and_retains_the_queue() {
    for workers in [1, 4] {
        native(workers, signal_restart_scenario);
    }
}

#[test]
fn managed_app_signal_stop_drains_active_work_and_closes_the_receiver() {
    for workers in [1, 4] {
        native(workers, signal_cancel_drain_scenario);
    }
}

#[test]
fn managed_app_signals_reach_seeded_lab_quiescence() {
    use asupersync::{LabConfig, LabRuntime};
    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                let cx = Cx::current().unwrap();
                signal_queue_scenario(cx.clone()).await;
                signal_restart_scenario(cx.clone()).await;
                signal_cancel_drain_scenario(cx.clone()).await;
                signal_idle_stop_scenario(cx.clone()).await;
                signal_parent_deadline_scenario(cx).await;
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        let virtual_time = lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(
            matches!(join.try_join(), Ok(Some(()))),
            "{virtual_time:?} {report:?}"
        );
        assert!(lab.state.tasks_is_empty(), "signal jobs left live tasks");
        assert!(lab.state.obligations_iter().all(|(_, o)| !o.is_pending()));
        assert!(report.lab_test_passed(), "{report:?}");
    }
}

#[test]
fn managed_app_signal_bindings_reject_mismatched_sources_and_kinds_before_work() {
    for case in 0..6 {
        let calls = Arc::new(AtomicUsize::new(0));
        let starts = Arc::clone(&calls);
        let mut manifest = signal_job_manifest();
        let mut name = "api.job.reload";
        let mut source = "reload";
        match case {
            1 => source = "another-source",
            2 => manifest["services"][0]["background_jobs"][0]["trigger"] = json!("startup"),
            3 => {
                manifest["services"][0]["background_jobs"] = json!([]);
                manifest["services"][0]["actors"] =
                    manifest_json()["services"][0]["actors"].clone();
                name = "api.actor.cache";
            }
            4 => source = "",
            5 => {
                manifest["services"][0]["background_jobs"][0]["trigger"] =
                    json!({"signal": {"source": ""}});
                source = "";
            }
            _ => {}
        }
        let (_sender, receiver) = asupersync::channel::mpsc::channel(1);
        let factory = move |_: Cx, _: ManagedGeneration| {
            starts.fetch_add(1, Ordering::AcqRel);
            async { Outcome::<(), ()>::Ok(()) }
        };
        let binding = if case == 0 {
            ManagedAppBinding::worker(name, ManagedRestartMode::Temporary, factory)
        } else {
            ManagedAppBinding::signal_worker(
                name,
                source,
                receiver,
                ManagedRestartMode::Temporary,
                factory,
            )
        };
        let result = parse(manifest).bind_managed(vec![binding], config());
        assert!(result.is_err(), "invalid signal binding case {case} was accepted");
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
}

async fn signal_idle_stop_scenario(cx: Cx) {
    let (sender, receiver) = asupersync::channel::mpsc::channel(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let starts = Arc::clone(&calls);
    let app = parse(signal_job_manifest())
        .bind_managed(
            vec![ManagedAppBinding::signal_worker(
                "api.job.reload",
                "reload",
                receiver,
                ManagedRestartMode::Temporary,
                move |_: Cx, _: ManagedGeneration| {
                    starts.fetch_add(1, Ordering::AcqRel);
                    async { Outcome::<(), ()>::Ok(()) }
                },
            )],
            config(),
        )
        .unwrap();
    let mut app = app.start(&cx).unwrap();
    while sender.telemetry_snapshot(0).recv_waiter_count == 0 {
        assert!(!sender.is_closed(), "signal worker exited before parking");
        yield_now().await;
    }
    assert_eq!(calls.load(Ordering::Acquire), 0);
    app.abort();
    let report = app.join().await.unwrap();
    assert_eq!(report.started, 1);
    assert_eq!(report.joined, 1);
    assert_eq!(report.restart_batches, 0);
    assert!(matches!(report.outcome, Outcome::Cancelled(_)));
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(sender.is_closed(), "stopped controller retained the signal receiver");
    assert!(matches!(
        sender.try_send(()),
        Err(asupersync::channel::mpsc::SendError::Disconnected(()))
    ));
}

async fn signal_parent_deadline_scenario(cx: Cx) {
    let owner_deadline = cx.now() + Duration::from_millis(250);
    let parent = cx
        .open_child_region(
            ChildRegionSpec::inherit().with_budget(Budget::new().with_deadline(owner_deadline)),
        )
        .await
        .unwrap();
    let (sender, receiver) = asupersync::channel::mpsc::channel(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let starts = Arc::clone(&calls);
    let app = parse(signal_job_manifest())
        .bind_managed(
            vec![ManagedAppBinding::signal_worker(
                "api.job.reload",
                "reload",
                receiver,
                ManagedRestartMode::Temporary,
                move |_: Cx, _: ManagedGeneration| {
                    starts.fetch_add(1, Ordering::AcqRel);
                    async { Outcome::<(), ()>::Ok(()) }
                },
            )],
            config(),
        )
        .unwrap();
    let mut app = app.start(parent.cx()).unwrap();
    // No notification, workload timer, or self-wake can finish this wait.
    // The actual generation's inherited deadline must wake its MPSC receive.
    while sender.telemetry_snapshot(0).recv_waiter_count == 0 {
        assert!(!sender.is_closed(), "deadline worker never parked on its source");
        yield_now().await;
    }
    let report = app.join().await.unwrap();
    assert!(
        cx.now() < owner_deadline + Duration::from_secs(1),
        "idle signal receive ignored its inherited deadline"
    );
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert_eq!(report.started, 1);
    assert_eq!(report.joined, 1);
    assert_eq!(report.restart_batches, 0);
    assert!(
        matches!(&report.children[0].outcome, Outcome::Cancelled(reason)
            if reason.kind == CancelKind::Deadline)
    );
    assert!(sender.is_closed());
    parent.close().await.unwrap();
}

#[test]
fn managed_app_signal_idle_stop_closes_source_on_native_workers() {
    for workers in [1, 4] {
        native(workers, signal_idle_stop_scenario);
    }
}

#[test]
fn managed_app_signal_wait_obeys_inherited_deadline_on_native_workers() {
    for workers in [1, 4] {
        native(workers, signal_parent_deadline_scenario);
    }
}

fn stop_group_manifest() -> Value {
    let mut manifest = manifest_json();
    manifest["supervision"]["groups"][0]["restart_policy"] = json!("stop");
    manifest["services"][0]["background_jobs"] = json!([{
        "name": "fail", "entrypoint": "example::fail", "trigger": "startup",
        "required_capabilities": {
            "cx_capabilities": ["pure"], "feature_flags": [], "resources": []
        },
        "budget": "work"
    }]);
    manifest
}

async fn parked_stop_sibling(cx: Cx, witness: Arc<DrainWitness>) -> Outcome<(), &'static str> {
    let _retired = Retired(Arc::clone(&witness));
    let mut cancelled = std::pin::pin!(cx.cancelled());
    poll_fn(|task| {
        let progress = cancelled.as_mut().poll(task);
        if progress.is_pending() {
            witness.parked.store(true, Ordering::Release);
            witness.changed.notify_waiters();
        }
        progress
    })
    .await;
    assert!(cx.checkpoint().is_err());
    let reason = cx.cancel_reason().expect("sibling cancellation");
    witness.cancelled.store(true, Ordering::Release);
    witness.changed.notify_waiters();
    witness
        .changed
        .wait_until(|| witness.release.load(Ordering::Acquire))
        .await;
    Outcome::Cancelled(reason)
}

async fn stop_group_failure_scenario(cx: Cx, mode: ManagedRestartMode, failure: u8) {
    use asupersync::app::ManagedAppWorkError;
    use asupersync::supervision::{EscalationPolicy, ManagedSupervisorError, RestartPolicy};

    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let witness = Arc::new(DrainWitness::default());
    let observer = Arc::clone(&witness);
    let fail_ready = Arc::new(AtomicBool::new(false));
    let fail_gate = Arc::new(Notify::new());
    let ready = Arc::clone(&fail_ready);
    let gate = Arc::clone(&fail_gate);
    let starts = Arc::new(AtomicUsize::new(0));
    let fail_starts = Arc::clone(&starts);
    let sibling_starts = Arc::new(AtomicUsize::new(0));
    let observed_starts = Arc::clone(&sibling_starts);
    // Even zero intensity plus ResetCounter must not convert the manifest's
    // Stop policy into an automatic replacement or a per-child silent stop.
    let config = SupervisionConfig::new(0, Duration::from_secs(60))
        .with_restart_policy(RestartPolicy::OneForAll)
        .with_backoff(BackoffStrategy::None)
        .with_escalation(EscalationPolicy::ResetCounter);
    let app = parse(stop_group_manifest())
        .bind_managed(
            vec![
                ManagedAppBinding::route(
                    "api.route.health",
                    AsyncCxFnHandler::new(|cx: Cx| async move {
                        assert_pure_work_context(&cx);
                        Response::new(StatusCode::OK, "healthy")
                    }),
                ),
                ManagedAppBinding::worker(
                    "api.actor.cache",
                    ManagedRestartMode::Permanent,
                    move |cx: Cx, _| {
                        assert_pure_work_context(&cx);
                        observed_starts.fetch_add(1, Ordering::AcqRel);
                        parked_stop_sibling(cx, Arc::clone(&observer))
                    },
                ),
                ManagedAppBinding::worker(
                    "api.job.fail",
                    mode,
                    move |cx: Cx, _| {
                        assert_pure_work_context(&cx);
                        fail_starts.fetch_add(1, Ordering::AcqRel);
                        gate.notify_waiters();
                        let ready = Arc::clone(&ready);
                        let gate = Arc::clone(&gate);
                        async move {
                            gate.wait_until(|| ready.load(Ordering::Acquire)).await;
                            match failure {
                                0 => Outcome::Err("stop policy domain failure"),
                                1 => Outcome::Panicked(asupersync::types::PanicPayload::new(
                                    "encoded stop policy panic",
                                )),
                                _ => panic!("actual stop policy poll panic"),
                            }
                        }
                    },
                ),
            ],
            config,
        )
        .unwrap();
    let mut app = app.start(parent.cx()).unwrap();
    witness
        .changed
        .wait_until(|| witness.parked.load(Ordering::Acquire))
        .await;
    fail_gate
        .wait_until(|| starts.load(Ordering::Acquire) == 1)
        .await;
    while !app.routes_ready() {
        yield_now().await;
    }
    let router = app.router();
    assert_eq!(
        router
            .handle_with_cx(&cx, Request::new("GET", "/health"))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(starts.load(Ordering::Acquire), 1);
    assert_eq!(sibling_starts.load(Ordering::Acquire), 1);
    fail_ready.store(true, Ordering::Release);
    fail_gate.notify_waiters();
    witness
        .changed
        .wait_until(|| witness.cancelled.load(Ordering::Acquire))
        .await;
    let mut joined = Box::pin(app.join());
    poll_fn(|task| {
        assert!(
            joined.as_mut().poll(task).is_pending(),
            "Stop group published before its parked sibling drained"
        );
        Poll::Ready(())
    })
    .await;
    assert!(!witness.retired.load(Ordering::Acquire));
    assert_eq!(starts.load(Ordering::Acquire), 1);
    assert_eq!(sibling_starts.load(Ordering::Acquire), 1);
    assert_eq!(
        router
            .handle_with_cx(&cx, Request::new("GET", "/health"))
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    witness.release.store(true, Ordering::Release);
    witness.changed.notify_waiters();
    let report = joined.await.unwrap();
    assert!(witness.retired.load(Ordering::Acquire));
    assert_eq!(report.started, 3);
    assert_eq!(report.joined, 3);
    assert_eq!(report.restart_batches, 0);
    assert_eq!(report.escalations, 0);
    let failed = report
        .children
        .iter()
        .find(|child| child.name.as_str() == "api.job.fail")
        .expect("failed generation retained");
    assert_eq!(failed.generation.number, 1);
    assert!(failed.region_outcome.is_some());
    assert!(failed.cleanup_outcome.as_ref().is_none_or(Outcome::is_ok));
    if failure == 0 {
        assert!(matches!(
            &report.outcome,
            Outcome::Err(ManagedSupervisorError::ChildFailed { child, generation })
                if child.as_str() == "api.job.fail" && *generation == failed.generation
        ));
        assert!(matches!(
            &failed.outcome,
            Outcome::Err(ManagedAppWorkError::Domain("stop policy domain failure"))
        ));
    } else {
        assert!(matches!(report.outcome, Outcome::Panicked(_)));
        assert!(matches!(failed.outcome, Outcome::Panicked(_)));
    }
    assert!(!cx.is_cancel_requested(), "ordinary group stop cancelled its parent");
    parent.close().await.unwrap();
}

struct StopPolicyCompletionProbe {
    cancelled: bool,
    retired: Arc<AtomicBool>,
    changed: Arc<Notify>,
}

impl asupersync::supervision::ManagedChildFactory<&'static str> for StopPolicyCompletionProbe {
    fn start(
        &self,
        _: Cx,
        _: ManagedGeneration,
    ) -> asupersync::supervision::ManagedChildFuture<&'static str> {
        let cancelled = self.cancelled;
        Box::pin(async move {
            if cancelled {
                Outcome::Cancelled(asupersync::types::CancelReason::user("normal child stop"))
            } else {
                Outcome::Ok(())
            }
        })
    }

    fn retired(&self) {
        self.retired.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

fn stop_policy_legacy_start(
    _: &asupersync::cx::Scope<'static>,
    _: &mut asupersync::runtime::RuntimeState,
    _: &Cx,
) -> Result<asupersync::types::TaskId, asupersync::runtime::SpawnError> {
    panic!("managed stop policy must not call legacy factories")
}

async fn stop_policy_nonfailure_scenario(cx: Cx) {
    use asupersync::supervision::{ChildSpec, ManagedChildBinding, SupervisorBuilder};

    for cancelled in [false, true] {
        let retired = Arc::new(AtomicBool::new(false));
        let changed = Arc::new(Notify::new());
        let witness = Arc::new(DrainWitness::default());
        let observer = Arc::clone(&witness);
        let supervisor = SupervisorBuilder::new("stop-nonfailure")
            .child(ChildSpec::new("finished", stop_policy_legacy_start))
            .child(ChildSpec::new("waiting", stop_policy_legacy_start))
            .compile()
            .unwrap()
            .bind_managed(
                vec![
                    ManagedChildBinding::new(
                        "finished",
                        ManagedRestartMode::Transient,
                        StopPolicyCompletionProbe {
                            cancelled,
                            retired: Arc::clone(&retired),
                            changed: Arc::clone(&changed),
                        },
                    ),
                    ManagedChildBinding::new(
                        "waiting",
                        ManagedRestartMode::Permanent,
                        move |cx: Cx, _| parked_stop_sibling(cx, Arc::clone(&observer)),
                    ),
                ],
                config(),
            )
            .unwrap()
            .with_stop_on_child_failure();
        let mut handle = supervisor.spawn(&cx).unwrap();
        changed
            .wait_until(|| retired.load(Ordering::Acquire))
            .await;
        witness
            .changed
            .wait_until(|| witness.parked.load(Ordering::Acquire))
            .await;
        // Retirement proves the controller processed the first completion.
        // The remaining sibling must still be alive under the Stop option.
        assert!(!witness.cancelled.load(Ordering::Acquire));
        {
            let mut joined = Box::pin(handle.join());
            poll_fn(|task| {
                assert!(joined.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        handle.abort();
        witness
            .changed
            .wait_until(|| witness.cancelled.load(Ordering::Acquire))
            .await;
        witness.release.store(true, Ordering::Release);
        witness.changed.notify_waiters();
        let report = handle.join().await.unwrap();
        assert!(matches!(report.outcome, Outcome::Cancelled(_)));
        assert_eq!(report.started, 2);
        assert_eq!(report.joined, 2);
        assert_eq!(report.restart_batches, 0);
        assert!(witness.retired.load(Ordering::Acquire));
        let finished = report
            .children
            .iter()
            .find(|child| child.name.as_str() == "finished")
            .unwrap();
        assert_eq!(finished.outcome.is_cancelled(), cancelled);
        assert_eq!(finished.outcome.is_ok(), !cancelled);
    }
}

#[test]
fn managed_app_stop_policy_drains_siblings_and_preserves_failure_on_native_workers() {
    for workers in [1, 4] {
        for mode in [
            ManagedRestartMode::Temporary,
            ManagedRestartMode::Transient,
            ManagedRestartMode::Permanent,
        ] {
            for failure in 0..3 {
                native(workers, move |cx| stop_group_failure_scenario(cx, mode, failure));
            }
        }
    }
}

#[test]
fn managed_stop_policy_keeps_siblings_alive_after_normal_child_completion() {
    for workers in [1, 4] {
        native(workers, stop_policy_nonfailure_scenario);
    }
}

#[test]
fn managed_app_stop_policy_preserves_legacy_lowering_refusal() {
    use asupersync::app::AppSpecV1CompileError;
    let manifest = stop_group_manifest();
    let result = parse(manifest).compile_with_child_specs(Vec::new());
    assert!(matches!(
        result,
        Err(AppSpecV1CompileError::UnsupportedRuntimeMapping { .. })
    ));
}

#[test]
fn managed_app_stop_policy_reaches_seeded_lab_quiescence() {
    use asupersync::{LabConfig, LabRuntime};

    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                let cx = Cx::current().unwrap();
                for mode in [
                    ManagedRestartMode::Temporary,
                    ManagedRestartMode::Transient,
                    ManagedRestartMode::Permanent,
                ] {
                    for failure in 0..3 {
                        stop_group_failure_scenario(cx.clone(), mode, failure).await;
                    }
                }
                stop_policy_nonfailure_scenario(cx).await;
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        let virtual_time = lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(
            matches!(join.try_join(), Ok(Some(()))),
            "{virtual_time:?} {report:?}"
        );
        assert!(lab.state.tasks_is_empty(), "Stop group left live tasks");
        assert!(lab.state.obligations_iter().all(|(_, o)| !o.is_pending()));
        assert!(report.lab_test_passed(), "{report:?}");
    }
}
