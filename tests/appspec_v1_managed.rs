//! Executing AppSpec bindings: real native/Lab tasks, routes, limits and drain.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::app::{
    AppSloHookKindV1, AppSpecV1, ManagedAppAdapters, ManagedAppBindError, ManagedAppBinding,
    ManagedAppSloBinding, ManagedAppSloDecision, ManagedAppWorkError,
};
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

fn grouped_manifest(root_policy: &str, worker_policy: &str) -> Value {
    let mut manifest = manifest_json();
    let mut workers = manifest["services"][0].clone();
    workers["name"] = json!("workers");
    workers["routes"][0]["path"] = json!("/workers");
    manifest["services"].as_array_mut().unwrap().push(workers);
    manifest["supervision"]["groups"] = json!([
        {"name": "root", "services": ["api"], "restart_policy": root_policy},
        {"name": "workers", "services": ["workers"], "restart_policy": worker_policy}
    ]);
    manifest
}

fn grouped_configs(
    root: SupervisionConfig,
    workers: SupervisionConfig,
) -> std::collections::BTreeMap<String, SupervisionConfig> {
    std::collections::BTreeMap::from([
        ("root".to_string(), root),
        ("workers".to_string(), workers),
    ])
}

fn grouped_route(name: &str, body: &'static str) -> ManagedAppBinding<&'static str> {
    ManagedAppBinding::route(
        name,
        AsyncCxFnHandler::new(move |cx: Cx| async move {
            assert_pure_work_context(&cx);
            Response::new(StatusCode::OK, body)
        }),
    )
}

async fn grouped_local_restart_scenario(cx: Cx) {
    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let root_starts = Arc::new(AtomicUsize::new(0));
    let worker_starts = Arc::new(AtomicUsize::new(0));
    let root_count = Arc::clone(&root_starts);
    let worker_count = Arc::clone(&worker_starts);
    let witness = Arc::new(DrainWitness::default());
    witness.release.store(true, Ordering::Release);
    let seen = Arc::clone(&witness);
    let tree = parse(grouped_manifest("one_for_one", "one_for_one"))
        .bind_managed_groups(
            vec![
                grouped_route("api.route.health", "root"),
                grouped_route("workers.route.health", "workers"),
                ManagedAppBinding::worker(
                    "api.actor.cache",
                    ManagedRestartMode::Temporary,
                    move |cx: Cx, _| {
                        assert_pure_work_context(&cx);
                        root_count.fetch_add(1, Ordering::AcqRel);
                        async { Outcome::Ok(()) }
                    },
                ),
                ManagedAppBinding::worker(
                    "workers.actor.cache",
                    ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        assert_pure_work_context(&cx);
                        let attempt = worker_count.fetch_add(1, Ordering::AcqRel);
                        let seen = Arc::clone(&seen);
                        async move {
                            assert_eq!(generation.number, attempt as u64 + 1);
                            if attempt == 0 {
                                Outcome::Err("local retry")
                            } else {
                                parked_stop_sibling(cx, seen).await
                            }
                        }
                    },
                ),
            ],
            grouped_configs(config(), config()),
        )
        .unwrap();
    let mut tree = tree.start(parent.cx()).unwrap();
    witness
        .changed
        .wait_until(|| witness.parked.load(Ordering::Acquire))
        .await;
    while !tree.routes_ready() {
        yield_now().await;
    }
    let router = tree.router();
    for (path, body) in [("/health", b"root".as_slice()), ("/workers", b"workers".as_slice())] {
        let response = router.handle_with_cx(&cx, Request::new("GET", path)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), body);
    }
    assert_eq!(root_starts.load(Ordering::Acquire), 1);
    assert_eq!(worker_starts.load(Ordering::Acquire), 2);
    tree.abort();
    let report = tree.join().await.unwrap();
    assert_eq!(report.root.started, 3);
    assert_eq!(report.root.joined, 3);
    assert_eq!(report.root.restart_batches, 0);
    assert_eq!(report.groups.len(), 1);
    let workers = &report.groups[0];
    assert_eq!(workers.name, "workers");
    assert_eq!(workers.generation.number, 1);
    assert_eq!(workers.report.started, 3);
    assert_eq!(workers.report.joined, 3);
    assert_eq!(workers.report.restart_batches, 1);
    assert!(matches!(report.root.outcome, Outcome::Cancelled(_)));
    assert!(!tree.routes_ready());
    assert!(witness.retired.load(Ordering::Acquire));
    parent.close().await.unwrap();
}

async fn grouped_parent_policy_scenario(cx: Cx, stop: bool, panic: bool) {
    use asupersync::app::ManagedAppWorkError;
    use asupersync::supervision::{ManagedSupervisorError, RestartPolicy};

    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let witness = Arc::new(DrainWitness::default());
    let observed = Arc::clone(&witness);
    let root_starts = Arc::new(AtomicUsize::new(0));
    let root_count = Arc::clone(&root_starts);
    let worker_starts = Arc::new(AtomicUsize::new(0));
    let worker_count = Arc::clone(&worker_starts);
    let fail = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Notify::new());
    let fail_gate = Arc::clone(&gate);
    let fail_ready = Arc::clone(&fail);
    let identities = Arc::new(std::sync::Mutex::new(Vec::new()));
    let worker_ids = Arc::clone(&identities);
    let tree = parse(grouped_manifest(if stop { "stop" } else { "one_for_all" }, "stop"))
        .bind_managed_groups(
            vec![
                grouped_route("api.route.health", "root"),
                grouped_route("workers.route.health", "workers"),
                ManagedAppBinding::worker(
                    "api.actor.cache",
                    ManagedRestartMode::Permanent,
                    move |cx: Cx, _| {
                        assert_pure_work_context(&cx);
                        if root_count.fetch_add(1, Ordering::AcqRel) > 0 {
                            assert!(observed.retired.load(Ordering::Acquire));
                        }
                        parked_stop_sibling(cx, Arc::clone(&observed))
                    },
                ),
                ManagedAppBinding::worker(
                    "workers.actor.cache",
                    ManagedRestartMode::Temporary,
                    move |cx: Cx, generation: ManagedGeneration| {
                        assert_pure_work_context(&cx);
                        worker_ids.lock().unwrap().push(generation);
                        let attempt = worker_count.fetch_add(1, Ordering::AcqRel);
                        let fail_ready = Arc::clone(&fail_ready);
                        let fail_gate = Arc::clone(&fail_gate);
                        async move {
                            if attempt == 0 {
                                fail_gate.wait_until(|| fail_ready.load(Ordering::Acquire)).await;
                                assert!(!panic, "nested group failure");
                                Outcome::Err("nested domain failure")
                            } else {
                                cx.cancelled().await;
                                assert!(cx.checkpoint().is_err());
                                Outcome::Cancelled(cx.cancel_reason().unwrap())
                            }
                        }
                    },
                ),
            ],
            grouped_configs(config().with_restart_policy(RestartPolicy::OneForAll), config()),
        )
        .unwrap();
    let mut tree = tree.start(parent.cx()).unwrap();
    witness
        .changed
        .wait_until(|| witness.parked.load(Ordering::Acquire))
        .await;
    while !tree.routes_ready() || worker_starts.load(Ordering::Acquire) != 1 {
        yield_now().await;
    }
    let router = tree.router();
    assert_eq!(
        router.handle_with_cx(&cx, Request::new("GET", "/workers")).await.status,
        StatusCode::OK
    );
    fail.store(true, Ordering::Release);
    gate.notify_waiters();
    witness
        .changed
        .wait_until(|| witness.cancelled.load(Ordering::Acquire))
        .await;
    assert_eq!(root_starts.load(Ordering::Acquire), 1);
    assert_eq!(worker_starts.load(Ordering::Acquire), 1);
    assert!(!witness.retired.load(Ordering::Acquire));
    for path in ["/health", "/workers"] {
        assert_eq!(
            router.handle_with_cx(&cx, Request::new("GET", path)).await.status,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    {
        let mut joined = std::pin::pin!(tree.join());
        poll_fn(|task| {
            assert!(joined.as_mut().poll(task).is_pending(), "tree returned before held cleanup");
            Poll::Ready(())
        }).await;
    }
    witness.release.store(true, Ordering::Release);
    witness.changed.notify_waiters();
    if !stop {
        while worker_starts.load(Ordering::Acquire) != 2 || !tree.routes_ready() {
            yield_now().await;
        }
        assert_eq!(root_starts.load(Ordering::Acquire), 2);
        {
            let identities = identities.lock().unwrap();
            assert_eq!(identities.len(), 2);
            assert_eq!(identities[0].number, 1);
            assert_eq!(identities[1].number, 1);
            assert_ne!(identities[0].task, identities[1].task);
            assert_ne!(identities[0].region, identities[1].region);
        }
        assert_eq!(
            router.handle_with_cx(&cx, Request::new("GET", "/workers")).await.status,
            StatusCode::OK
        );
        tree.abort();
    }
    let report = tree.join().await.unwrap();
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.root.started, if stop { 3 } else { 6 });
    assert_eq!(report.root.joined, report.root.started);
    assert_eq!(report.root.restart_batches, u64::from(!stop));
    assert_eq!(report.groups[0].generation.number, if stop { 1 } else { 2 });
    assert_eq!(report.groups[0].report.started, 2);
    assert_eq!(report.groups[0].report.joined, 2);
    assert_eq!(report.groups[0].report.restart_batches, 0);
    if stop {
        if panic {
            assert!(matches!(report.root.outcome, Outcome::Panicked(_)));
            assert!(matches!(report.groups[0].report.outcome, Outcome::Panicked(_)));
        } else {
            assert!(matches!(
                &report.root.outcome,
                Outcome::Err(ManagedSupervisorError::ChildFailed { child, .. })
                    if child.as_str() == "group:workers"
            ));
            let failed = report.groups[0].report.children.iter()
                .find(|child| child.name.as_str() == "workers.actor.cache").unwrap();
            assert!(matches!(
                &failed.outcome,
                Outcome::Err(ManagedAppWorkError::Domain("nested domain failure"))
            ));
        }
    } else {
        assert!(matches!(report.root.outcome, Outcome::Cancelled(_)));
    }
    assert!(!tree.routes_ready());
    assert!(!cx.is_cancel_requested());
    parent.close().await.unwrap();
}

#[test]
fn managed_app_groups_restart_locally_and_serve_all_routes_on_native_workers() {
    for workers in [1, 4] {
        native(workers, grouped_local_restart_scenario);
    }
}

#[test]
fn managed_app_groups_apply_root_stop_and_one_for_all_after_nested_drain() {
    for workers in [1, 4] {
        for stop in [false, true] {
            for panic in [false, true] {
                native(workers, move |cx| grouped_parent_policy_scenario(cx, stop, panic));
            }
        }
    }
}

#[test]
fn managed_app_groups_validate_all_configs_and_preserve_legacy_refusal() {
    use asupersync::supervision::{ManagedSupervisorBindError, RestartPolicy};

    assert!(matches!(
        parse(grouped_manifest("one_for_one", "one_for_one"))
            .bind_managed::<&'static str>(Vec::new(), config()),
        Err(ManagedAppBindError::Unsupported { .. })
    ));
    assert!(matches!(
        parse(grouped_manifest("one_for_one", "one_for_one"))
            .bind_managed_groups::<&'static str>(Vec::new(),
                std::collections::BTreeMap::from([("root".to_string(), config())])),
        Err(ManagedAppBindError::MissingGroupConfig(name)) if name == "workers"
    ));
    let mut extra = grouped_configs(config(), config());
    extra.insert("typo".to_string(), config());
    assert!(matches!(
        parse(grouped_manifest("one_for_one", "one_for_one"))
            .bind_managed_groups::<&'static str>(Vec::new(), extra),
        Err(ManagedAppBindError::UnexpectedGroupConfig(name)) if name == "typo"
    ));
    let starts = Arc::new(AtomicUsize::new(0));
    let bindings = || {
        let one = Arc::clone(&starts);
        let two = Arc::clone(&starts);
        vec![
            grouped_route("api.route.health", "root"),
            grouped_route("workers.route.health", "workers"),
            ManagedAppBinding::worker("api.actor.cache", ManagedRestartMode::Temporary,
                move |_: Cx, _| { one.fetch_add(1, Ordering::AcqRel); async { Outcome::Ok(()) } }),
            ManagedAppBinding::worker("workers.actor.cache", ManagedRestartMode::Temporary,
                move |_: Cx, _| { two.fetch_add(1, Ordering::AcqRel); async { Outcome::Ok(()) } }),
        ]
    };
    assert!(matches!(
        parse(grouped_manifest("one_for_one", "one_for_one"))
            .bind_managed_groups(bindings(), grouped_configs(config(),
                config().with_restart_policy(RestartPolicy::OneForAll))),
        Err(ManagedAppBindError::Supervisor(ManagedSupervisorBindError::RestartPolicyMismatch))
    ));
    let mut duplicate_route = grouped_manifest("one_for_one", "one_for_one");
    duplicate_route["services"][1]["routes"][0]["path"] = json!("/health/");
    assert!(matches!(
        parse(duplicate_route).bind_managed_groups(bindings(), grouped_configs(config(), config())),
        Err(ManagedAppBindError::Duplicate(_))
    ));
    assert_eq!(starts.load(Ordering::Acquire), 0, "preflight ran a factory");
}

async fn grouped_normal_completion_and_authority_scenario(cx: Cx) {
    use asupersync::app::AppCxCapabilityV1;

    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let mut manifest = grouped_manifest("one_for_one", "one_for_one");
    manifest["services"][0]["routes"] = json!([]);
    manifest["services"][1]["routes"] = json!([]);
    let starts = Arc::new(AtomicUsize::new(0));
    let bindings = || {
        ["api.actor.cache", "workers.actor.cache"]
            .into_iter()
            .map(|name| {
                let starts = Arc::clone(&starts);
                ManagedAppBinding::<&'static str>::worker(
                    name,
                    ManagedRestartMode::Temporary,
                    move |cx: Cx, generation: ManagedGeneration| {
                        assert_pure_work_context(&cx);
                        assert_eq!(generation.task, cx.task_id());
                        starts.fetch_add(1, Ordering::AcqRel);
                        async { Outcome::Ok(()) }
                    },
                )
            })
            .collect()
    };
    let mut denied = manifest.clone();
    denied["services"][1]["actors"][0]["required_capabilities"]["cx_capabilities"] =
        json!(["database"]);
    let denied = parse(denied)
        .bind_managed_groups(bindings(), grouped_configs(config(), config()))
        .unwrap();
    assert!(matches!(
        denied.start(parent.cx()),
        Err(ManagedAppBindError::Capability { unit, capability: AppCxCapabilityV1::Database })
            if unit == "workers.actor.cache"
    ));
    assert_eq!(starts.load(Ordering::Acquire), 0, "nested preflight published root work");
    let report = parse(manifest)
        .bind_managed_groups(bindings(), grouped_configs(config(), config()))
        .unwrap()
        .run(parent.cx())
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::Acquire), 2);
    assert!(matches!(report.root.outcome, Outcome::Ok(())));
    assert_eq!(report.root.started, 2);
    assert_eq!(report.root.joined, 2);
    assert_eq!(report.root.restart_batches, 0);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].generation.number, 1);
    assert!(matches!(report.groups[0].report.outcome, Outcome::Ok(())));
    assert_eq!(report.groups[0].report.started, 1);
    assert_eq!(report.groups[0].report.joined, 1);
    assert_eq!(report.groups[0].report.restart_batches, 0);
    parent.close().await.unwrap();
}

#[test]
fn managed_app_groups_preflight_nested_authority_and_finish_normal_work() {
    for workers in [1, 4] {
        native(workers, grouped_normal_completion_and_authority_scenario);
    }
}

async fn grouped_escalation_scenario(cx: Cx) {
    use asupersync::supervision::EscalationPolicy;

    let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&starts);
    let witness = Arc::new(DrainWitness::default());
    witness.release.store(true, Ordering::Release);
    let observed = Arc::clone(&witness);
    let tree = parse(grouped_manifest("one_for_one", "one_for_one"))
        .bind_managed_groups(
            vec![
                grouped_route("api.route.health", "root"),
                grouped_route("workers.route.health", "workers"),
                ManagedAppBinding::worker("api.actor.cache", ManagedRestartMode::Temporary,
                    |_: Cx, _| async { Outcome::Ok(()) }),
                ManagedAppBinding::worker("workers.actor.cache", ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        assert_pure_work_context(&cx);
                        let attempt = counter.fetch_add(1, Ordering::AcqRel);
                        let observed = Arc::clone(&observed);
                        async move {
                            assert_eq!(generation.number, 1, "inner restart allowance was exhausted");
                            if attempt == 0 {
                                Outcome::Err("escalate to group owner")
                            } else {
                                parked_stop_sibling(cx, observed).await
                            }
                        }
                    }),
            ],
            grouped_configs(config(), SupervisionConfig::new(0, Duration::from_secs(60))
                .with_backoff(BackoffStrategy::None)
                .with_escalation(EscalationPolicy::Escalate)),
        )
        .unwrap();
    let mut tree = tree.start(parent.cx()).unwrap();
    witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)).await;
    while !tree.routes_ready() {
        yield_now().await;
    }
    assert_eq!(starts.load(Ordering::Acquire), 2);
    assert!(!parent.cx().is_cancel_requested());
    tree.abort();
    let report = tree.join().await.unwrap();
    assert_eq!(report.root.restart_batches, 1);
    assert_eq!(report.root.started, 4);
    assert_eq!(report.root.joined, 4);
    assert_eq!(report.root.escalations, 0);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].generation.number, 2);
    assert_eq!(report.groups[0].report.restart_batches, 0);
    parent.close().await.unwrap();
}

#[test]
fn managed_app_groups_escalate_exhausted_inner_restart_to_root_replacement() {
    for workers in [1, 4] {
        native(workers, grouped_escalation_scenario);
    }
}

#[cfg(feature = "test-internals")]
#[test]
fn managed_app_groups_propagate_native_finalizer_failure_without_replacement() {
    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::new()
                .worker_threads(workers)
                .build()
                .unwrap()
        };
        let finalizer_runtime = runtime.handle();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = Arc::clone(&completed);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let scenario = async {
                let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
                let mut manifest = grouped_manifest("one_for_one", "one_for_one");
                manifest["services"][0]["routes"] = json!([]);
                manifest["services"][1]["routes"] = json!([]);
                let (release, receiver) = asupersync::channel::oneshot::channel::<()>();
                let receiver = Arc::new(std::sync::Mutex::new(Some(receiver)));
                let starts = Arc::new(AtomicUsize::new(0));
                let counter = Arc::clone(&starts);
                let identity = Arc::new(std::sync::Mutex::new(None));
                let published_identity = Arc::clone(&identity);
                let parked = Arc::new(AtomicBool::new(false));
                let saw_parked = Arc::clone(&parked);
                let changed = Arc::new(Notify::new());
                let parked_changed = Arc::clone(&changed);
                let tree = parse(manifest)
                    .bind_managed_groups(
                        vec![
                            ManagedAppBinding::<&'static str>::worker(
                                "api.actor.cache",
                                ManagedRestartMode::Temporary,
                                |_: Cx, _| async { Outcome::Ok(()) },
                            ),
                            ManagedAppBinding::worker(
                                "workers.actor.cache",
                                ManagedRestartMode::Transient,
                                move |cx: Cx, generation: ManagedGeneration| {
                                    counter.fetch_add(1, Ordering::AcqRel);
                                    *published_identity.lock().unwrap() = Some(generation);
                                    let mut receiver = receiver.lock().unwrap().take().unwrap();
                                    let parked = Arc::clone(&saw_parked);
                                    let changed = Arc::clone(&parked_changed);
                                    async move {
                                        let mut receive = std::pin::pin!(receiver.recv(&cx));
                                        poll_fn(|task| {
                                            let result = receive.as_mut().poll(task);
                                            if result.is_pending() {
                                                parked.store(true, Ordering::Release);
                                                changed.notify_waiters();
                                            }
                                            result
                                        })
                                        .await
                                        .unwrap();
                                        Outcome::Err("worker finished before failing cleanup")
                                    }
                                },
                            ),
                        ],
                        grouped_configs(config(), config()),
                    )
                    .unwrap();
                let mut tree = tree.start(parent.cx()).unwrap();
                changed
                    .wait_until(|| parked.load(Ordering::Acquire))
                    .await;
                let generation = identity.lock().unwrap().unwrap();
                let finalized = Arc::new(AtomicUsize::new(0));
                let finalizer_count = Arc::clone(&finalized);
                assert!(
                    finalizer_runtime.register_sync_finalizer_for_testing(
                        generation.region,
                        move || {
                            finalizer_count.fetch_add(1, Ordering::AcqRel);
                            panic!("real native nested invocation finalizer failure");
                        },
                    ),
                    "the parked invocation must still own an open native region"
                );
                release.send_blocking(()).unwrap();
                let report = tree.join().await.unwrap();
                assert_eq!(
                    starts.load(Ordering::Acquire),
                    1,
                    "failed native cleanup admitted a replacement"
                );
                assert_eq!(finalized.load(Ordering::Acquire), 1);
                assert!(matches!(report.root.outcome, Outcome::Panicked(_)));
                assert_eq!(report.root.started, 2);
                assert_eq!(report.root.joined, 2);
                assert_eq!(report.root.restart_batches, 0);
                assert_eq!(report.root.escalations, 1);
                assert!(report.root.region_outcome.is_some());
                assert_eq!(report.groups.len(), 1);
                assert_eq!(report.groups[0].generation.number, 1);
                let nested = &report.groups[0].report;
                assert!(matches!(nested.outcome, Outcome::Panicked(_)));
                assert_eq!(nested.started, 1);
                assert_eq!(nested.joined, 1);
                assert_eq!(nested.restart_batches, 0);
                assert_eq!(nested.escalations, 1);
                assert!(nested.region_outcome.is_some());
                assert!(matches!(
                    nested.children[0].cleanup_outcome,
                    Some(Outcome::Panicked(_))
                ));
                let outer = report
                    .root
                    .children
                    .iter()
                    .find(|child| child.name.as_str() == "group:workers")
                    .unwrap();
                assert!(matches!(outer.cleanup_outcome, Some(Outcome::Panicked(_))));
                assert!(outer.region_outcome.is_some());
                assert!(!cx.is_cancel_requested());
                parent.close().await.unwrap();
            };
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), scenario)
                .await
                .expect("native nested-finalizer watchdog");
            completion.store(true, Ordering::Release);
        }));
        assert!(completed.load(Ordering::Acquire));
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn managed_app_groups_propagate_real_invocation_finalizer_failure_without_replacement() {
    use asupersync::runtime::JoinError;
    use asupersync::{LabConfig, LabRuntime};

    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let mut manifest = grouped_manifest("one_for_one", "one_for_one");
        manifest["services"][0]["routes"] = json!([]);
        manifest["services"][1]["routes"] = json!([]);
        let (release, receiver) = asupersync::channel::oneshot::channel::<()>();
        let receiver = Arc::new(std::sync::Mutex::new(Some(receiver)));
        let starts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&starts);
        let identity = Arc::new(std::sync::Mutex::new(None));
        let published_identity = Arc::clone(&identity);
        let parked = Arc::new(AtomicBool::new(false));
        let saw_parked = Arc::clone(&parked);
        let tree = parse(manifest).bind_managed_groups(
            vec![
                ManagedAppBinding::<&'static str>::worker(
                    "api.actor.cache", ManagedRestartMode::Temporary,
                    |_: Cx, _| async { Outcome::Ok(()) }),
                ManagedAppBinding::worker(
                    "workers.actor.cache", ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        counter.fetch_add(1, Ordering::AcqRel);
                        *published_identity.lock().unwrap() = Some(generation);
                        let mut receiver = receiver.lock().unwrap().take().unwrap();
                        let parked = Arc::clone(&saw_parked);
                        async move {
                            let mut receive = std::pin::pin!(receiver.recv(&cx));
                            poll_fn(|task| {
                                let result = receive.as_mut().poll(task);
                                if result.is_pending() {
                                    parked.store(true, Ordering::Release);
                                }
                                result
                            }).await.unwrap();
                            Outcome::Err("worker finished before failing cleanup")
                        }
                    }),
            ],
            grouped_configs(config(), config()),
        ).unwrap();
        let output = Arc::new(std::sync::Mutex::new(None));
        let published = Arc::clone(&output);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
            let report = tree.run(&Cx::current().unwrap()).await.unwrap();
            *published.lock().unwrap() = Some(report);
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert!(parked.load(Ordering::Acquire), "worker did not reach actual Pending");
        let generation = identity.lock().unwrap().unwrap();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalizer_count = Arc::clone(&finalized);
        assert!(lab.state.register_async_finalizer(generation.region, async move {
            finalizer_count.fetch_add(1, Ordering::AcqRel);
            panic!("real nested invocation finalizer failure");
        }));
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert!(matches!(join.try_join(), Ok(Some(())) | Err(JoinError::Cancelled(_))));
        let report = output.lock().unwrap().take().expect("failed cleanup keeps its receipt");
        assert_eq!(starts.load(Ordering::Acquire), 1, "failed cleanup admitted replacement");
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert!(matches!(report.root.outcome, Outcome::Panicked(_)));
        assert_eq!(report.root.started, 2);
        assert_eq!(report.root.joined, 2);
        assert_eq!(report.root.restart_batches, 0);
        assert_eq!(report.root.escalations, 1);
        assert_eq!(report.groups.len(), 1);
        let nested = &report.groups[0].report;
        assert!(matches!(nested.outcome, Outcome::Panicked(_)));
        assert_eq!(nested.started, 1);
        assert_eq!(nested.joined, 1);
        assert_eq!(nested.restart_batches, 0);
        assert_eq!(nested.escalations, 1);
        assert!(matches!(nested.children[0].cleanup_outcome, Some(Outcome::Panicked(_))));
        let outer = report.root.children.iter()
            .find(|child| child.name.as_str() == "group:workers").unwrap();
        assert!(matches!(outer.cleanup_outcome, Some(Outcome::Panicked(_))));
        assert!(lab.state.region(generation.region).is_none());
        assert!(lab.state.tasks_is_empty());
        assert!(lab.state.obligations_iter().all(|(_, o)| !o.is_pending()));
        let outcome = lab.run_until_quiescent_with_report();
        assert!(outcome.lab_test_passed(), "seed={seed}: {outcome:?}");
    }
}

#[test]
fn managed_app_groups_reach_seeded_lab_quiescence() {
    use asupersync::{LabConfig, LabRuntime};

    for seed in [17, 41, 93] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async {
            let cx = Cx::current().unwrap();
            grouped_normal_completion_and_authority_scenario(cx.clone()).await;
            grouped_escalation_scenario(cx.clone()).await;
            grouped_local_restart_scenario(cx.clone()).await;
            grouped_parent_policy_scenario(cx.clone(), true, false).await;
            grouped_parent_policy_scenario(cx, false, false).await;
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        let virtual_time = lab.run_with_auto_advance();
        let report = lab.run_until_quiescent_with_report();
        assert!(matches!(join.try_join(), Ok(Some(()))), "seed={seed}: {virtual_time:?} {report:?}");
        assert!(lab.state.tasks_is_empty());
        assert!(lab.state.obligations_iter().all(|(_, o)| !o.is_pending()));
        assert!(report.lab_test_passed(), "seed={seed}: {report:?}");
    }
}

fn assert_managed_blocking_pool_access(cx: &Cx, expected: bool) {
    assert!(cx.capabilities().spawn, "structured spawn stays available");
    assert_eq!(cx.blocking_pool_handle().is_some(), expected);
    let ambient = Cx::current().expect("managed work has an ambient context");
    assert_eq!(ambient.task_id(), cx.task_id());
    assert_eq!(ambient.blocking_pool_handle().is_some(), expected);
}

async fn check_managed_blocking_pool_descendants(cx: Cx, expected: bool) {
    assert_managed_blocking_pool_access(&cx, expected);
    yield_now().await;
    assert_managed_blocking_pool_access(&cx, expected);

    let mut child = cx
        .spawn(move |child| async move {
            assert_managed_blocking_pool_access(&child, expected);
            let region = child
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            assert_eq!(region.cx().blocking_pool_handle().is_some(), expected);
            let mut nested = region
                .cx()
                .spawn(move |nested| async move {
                    assert_managed_blocking_pool_access(&nested, expected);
                    let called = Arc::new(AtomicBool::new(false));
                    let invocation = Arc::clone(&called);
                    let blocking = nested.spawn_blocking_drained(move |blocking_cx| {
                        assert!(blocking_cx.blocking_pool_handle().is_some());
                        invocation.store(true, Ordering::Release);
                        17_u32
                    });
                    if expected {
                        let mut blocking = blocking.expect("explicit Blocking grant has a pool");
                        assert_eq!(blocking.join().await.unwrap(), 17);
                        assert!(called.load(Ordering::Acquire));
                    } else {
                        assert!(matches!(
                            blocking,
                            Err(asupersync::runtime::SpawnError::RuntimeUnavailable)
                        ));
                        assert!(!called.load(Ordering::Acquire));
                    }
                })
                .unwrap();
            nested.join(&child).await.unwrap();
            region.close().await.unwrap();
        })
        .unwrap();
    child.join(&cx).await.unwrap();
}

async fn managed_blocking_pool_authority_scenario(cx: Cx) {
    assert!(cx.blocking_pool_handle().is_some(), "test requires a real pool");
    for capabilities in [
        json!(["spawn"]),
        json!(["blocking"]),
        json!(["spawn", "blocking"]),
    ] {
        let expected = capabilities
            .as_array()
            .unwrap()
            .iter()
            .any(|cap| cap == "blocking");
        let mut manifest = manifest_json();
        manifest["budgets"] = json!([]);
        for kind in ["routes", "actors"] {
            manifest["services"][0][kind][0]["budget"] = Value::Null;
            manifest["services"][0][kind][0]["required_capabilities"]["cx_capabilities"] =
                capabilities.clone();
        }
        let starts = Arc::new(AtomicUsize::new(0));
        let observed_starts = Arc::clone(&starts);
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_work = Arc::clone(&completed);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let app = parse(manifest)
            .bind_managed(
                vec![
                    ManagedAppBinding::route(
                        "api.route.health",
                        AsyncCxFnHandler::new(move |cx: Cx| {
                            assert_managed_blocking_pool_access(&cx, expected);
                            let calls = Arc::clone(&observed_calls);
                            async move {
                                check_managed_blocking_pool_descendants(cx, expected).await;
                                calls.fetch_add(1, Ordering::AcqRel);
                                Response::new(StatusCode::OK, "pool authority checked")
                            }
                        }),
                    ),
                    ManagedAppBinding::worker(
                        "api.actor.cache",
                        ManagedRestartMode::Transient,
                        move |cx: Cx, _: ManagedGeneration| {
                            assert_managed_blocking_pool_access(&cx, expected);
                            let attempt = observed_starts.fetch_add(1, Ordering::AcqRel);
                            let completed = Arc::clone(&completed_work);
                            async move {
                                check_managed_blocking_pool_descendants(cx, expected).await;
                                completed.fetch_add(1, Ordering::AcqRel);
                                if attempt == 0 {
                                    Outcome::Err("restart with the same authority")
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
        let mut app = app.start(&cx).unwrap();
        while !app.routes_ready() || completed.load(Ordering::Acquire) < 2 {
            yield_now().await;
        }
        let response = router
            .handle_with_cx(&cx, Request::new("GET", "/health"))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(starts.load(Ordering::Acquire), 2);
        app.abort();
        let report = app.join().await.unwrap();
        assert_eq!(report.started, 3);
        assert_eq!(report.joined, 3);
        assert_eq!(report.restart_batches, 1);
        assert!(matches!(report.outcome, Outcome::Cancelled(_)));
        assert!(!app.routes_ready());
    }
}

#[test]
fn managed_app_blocking_pool_authority_survives_routes_restarts_and_descendants() {
    for workers in [1, 2] {
        native(workers, managed_blocking_pool_authority_scenario);
    }
}

#[test]
fn managed_app_preserves_explicit_blocking_pool_through_child_regions() {
    use asupersync::runtime::{BlockingPool, BlockingPoolOptions};

    for workers in [1, 2] {
        let pool = BlockingPool::with_config(
            1,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "appspec-explicit".to_owned(),
                ..BlockingPoolOptions::default()
            },
        );
        let handle = pool.handle();
        native(workers, move |cx| async move {
            let cx = cx.with_blocking_pool_handle(Some(handle));
            let mut manifest = manifest_json();
            manifest["budgets"] = json!([]);
            manifest["services"][0]["routes"] = json!([]);
            manifest["services"][0]["actors"][0]["budget"] = Value::Null;
            manifest["services"][0]["actors"][0]["required_capabilities"]["cx_capabilities"] =
                json!(["blocking"]);
            let app = parse(manifest)
                .bind_managed(
                    vec![ManagedAppBinding::worker(
                        "api.actor.cache",
                        ManagedRestartMode::Temporary,
                        |cx: Cx, _: ManagedGeneration| async move {
                            assert_managed_blocking_pool_access(&cx, true);
                            let region = cx
                                .open_child_region(ChildRegionSpec::inherit())
                                .await
                                .unwrap();
                            let mut blocking = region
                                .cx()
                                .spawn_blocking_drained(|_| {
                                    std::thread::current().name().unwrap().to_owned()
                                })
                                .unwrap();
                            let thread_name = blocking.join().await.unwrap();
                            assert!(
                                thread_name.starts_with("appspec-explicit-blocking-"),
                                "child region replaced the explicit pool: {thread_name}"
                            );
                            region.close().await.unwrap();
                            Outcome::<(), ()>::Ok(())
                        },
                    )],
                    config(),
                )
                .unwrap();
            let report = app.run(&cx).await.unwrap();
            assert!(matches!(report.outcome, Outcome::Ok(())));
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
        });
        assert!(pool.shutdown_and_wait(Duration::from_secs(3)));
    }
}

fn slo_route_manifest() -> Value {
    let mut manifest = manifest_json();
    manifest["services"][0]["actors"] = json!([]);
    manifest["services"][0]["routes"][0]["slo_hook"] = json!("route_policy");
    manifest["slo_hooks"] = json!([{
        "name": "route_policy", "kind": "latency", "target": "api.route.health",
        "budget": "hook"
    }]);
    manifest["budgets"] = json!([
        {"name": "work", "poll_quota": 512, "deadline_ms": 10000,
            "io_bytes": 512, "memory_bytes": 96},
        {"name": "hook", "poll_quota": 256, "deadline_ms": 5000,
            "io_bytes": 128, "memory_bytes": 256}
    ]);
    manifest
}

fn allow_route_slo() -> ManagedAppSloBinding {
    ManagedAppSloBinding::new(
        "route_policy",
        AppSloHookKindV1::Latency,
        "api.route.health",
        |_, _| ManagedAppSloDecision::Admit(Budget::INFINITE),
    )
}

#[test]
fn managed_app_slo_preflight_is_exact_and_preserves_legacy_refusal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let bindings = || {
        let calls = Arc::clone(&calls);
        vec![ManagedAppBinding::<&'static str>::route(
            "api.route.health",
            AsyncCxFnHandler::new(move |_: Cx| {
                calls.fetch_add(1, Ordering::AcqRel);
                async { Response::empty(StatusCode::OK) }
            }),
        )]
    };
    assert!(matches!(
        parse(slo_route_manifest()).bind_managed(bindings(), config()),
        Err(ManagedAppBindError::Unsupported { .. })
    ));
    assert!(matches!(
        parse(slo_route_manifest()).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new(),
            config(),
        ),
        Err(ManagedAppBindError::Missing(name)) if name == "slo:route_policy"
    ));
    assert!(matches!(
        parse(slo_route_manifest()).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new()
                .slo_hook(allow_route_slo())
                .slo_hook(allow_route_slo()),
            config(),
        ),
        Err(ManagedAppBindError::Duplicate(name)) if name == "slo:route_policy"
    ));
    let extra = ManagedAppSloBinding::new(
        "extra",
        AppSloHookKindV1::Latency,
        "api.route.health",
        |_, _| ManagedAppSloDecision::Admit(Budget::INFINITE),
    );
    assert!(matches!(
        parse(slo_route_manifest()).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new()
                .slo_hook(allow_route_slo())
                .slo_hook(extra),
            config(),
        ),
        Err(ManagedAppBindError::Unexpected(name)) if name == "slo:extra"
    ));
    for (kind, target) in [
        (AppSloHookKindV1::ErrorRate, "api.route.health"),
        (AppSloHookKindV1::Latency, "api.actor.cache"),
    ] {
        let wrong = ManagedAppSloBinding::new("route_policy", kind, target, |_, _| {
            ManagedAppSloDecision::Admit(Budget::INFINITE)
        });
        assert!(matches!(
            parse(slo_route_manifest()).bind_managed_with_adapters(
                bindings(),
                ManagedAppAdapters::new().slo_hook(wrong),
                config(),
            ),
            Err(ManagedAppBindError::KindMismatch(name)) if name == "slo:route_policy"
        ));
    }
    let mut missing_target = slo_route_manifest();
    missing_target["slo_hooks"][0]["target"] = json!("missing.route.health");
    let missing_hook = ManagedAppSloBinding::new(
        "route_policy",
        AppSloHookKindV1::Latency,
        "missing.route.health",
        |_, _| ManagedAppSloDecision::Admit(Budget::INFINITE),
    );
    assert!(matches!(
        parse(missing_target).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new().slo_hook(missing_hook),
            config(),
        ),
        Err(ManagedAppBindError::Unsupported { .. })
    ));
    let mut mismatched_reference = manifest_json();
    mismatched_reference["services"][0]["routes"][0]["slo_hook"] = json!("actor_policy");
    mismatched_reference["slo_hooks"] = json!([{
        "name": "actor_policy", "kind": "latency", "target": "api.actor.cache"
    }]);
    let actor_hook = ManagedAppSloBinding::new(
        "actor_policy",
        AppSloHookKindV1::Latency,
        "api.actor.cache",
        |_, _| ManagedAppSloDecision::Admit(Budget::INFINITE),
    );
    assert!(matches!(
        parse(mismatched_reference).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new().slo_hook(actor_hook),
            config(),
        ),
        Err(ManagedAppBindError::KindMismatch(name)) if name == "slo:actor_policy"
    ));
    let mut invalid_budget = slo_route_manifest();
    invalid_budget["budgets"][1]["poll_quota"] = json!(u64::from(u32::MAX) + 1);
    assert!(matches!(
        parse(invalid_budget).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new().slo_hook(allow_route_slo()),
            config(),
        ),
        Err(ManagedAppBindError::Budget { .. })
    ));
    let mut duplicate_target = slo_route_manifest();
    duplicate_target["services"][0]["routes"][0]["slo_hook"] = Value::Null;
    duplicate_target["slo_hooks"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": "second", "kind": "latency", "target": "api.route.health"
        }));
    let second = ManagedAppSloBinding::new(
        "second",
        AppSloHookKindV1::Latency,
        "api.route.health",
        |_, _| ManagedAppSloDecision::Admit(Budget::INFINITE),
    );
    assert!(matches!(
        parse(duplicate_target).bind_managed_with_adapters(
            bindings(),
            ManagedAppAdapters::new()
                .slo_hook(allow_route_slo())
                .slo_hook(second),
            config(),
        ),
        Err(ManagedAppBindError::Duplicate(name)) if name == "slo-target:api.route.health"
    ));
    assert_eq!(
        calls.load(Ordering::Acquire),
        0,
        "preflight must not run user work"
    );
}

async fn managed_slo_route_scenario(cx: Cx) {
    let mut parent_spec = ChildRegionSpec::inherit()
        .with_budget(Budget::INFINITE.with_poll_quota(2048).with_cost_quota(96));
    parent_spec.capability_budget = Some(
        CapabilityBudget::new()
            .with_io_bytes(64)
            .with_memory_bytes(512),
    );
    let parent = cx.open_child_region(parent_spec).await.unwrap();
    let policies = Arc::new(AtomicUsize::new(0));
    let policy_calls = Arc::clone(&policies);
    let work = Arc::new(AtomicUsize::new(0));
    let work_calls = Arc::clone(&work);
    let hook = ManagedAppSloBinding::new(
        "route_policy",
        AppSloHookKindV1::Latency,
        "api.route.health",
        move |cx, admission| {
            assert_eq!(admission.unit, "api.route.health");
            assert!(admission.generation.is_none());
            assert_eq!(admission.budget.poll_quota, 256);
            assert_eq!(admission.budget.cost_quota, Some(96));
            assert!(admission.budget.deadline.unwrap() <= admission.now + Duration::from_secs(5));
            assert_eq!(admission.capability_budget.io_bytes, Some(64));
            assert_eq!(admission.capability_budget.memory_bytes, Some(96));
            let caps = cx.capabilities();
            assert!(!caps.spawn && !caps.time && !caps.entropy && !caps.io && !caps.remote);
            assert!(cx.blocking_pool_handle().is_none());
            let ambient = Cx::current().unwrap();
            assert_eq!(ambient.task_id(), cx.task_id());
            assert!(!ambient.capabilities().io && !ambient.capabilities().spawn);
            assert!(
                cx.spawn(|_| async { panic!("SLO callback escaped through explicit spawn") })
                    .is_err()
            );
            assert!(
                ambient
                    .spawn(|_| async { panic!("SLO callback escaped through ambient spawn") })
                    .is_err()
            );
            match policy_calls.fetch_add(1, Ordering::AcqRel) {
                0 => ManagedAppSloDecision::Reject("capacity closed".to_owned()),
                1 => panic!("policy failure is contained before admission"),
                2 => ManagedAppSloDecision::Admit(
                    Budget::INFINITE.with_poll_quota(128).with_cost_quota(11),
                ),
                3 => ManagedAppSloDecision::Admit(Budget::INFINITE),
                _ => panic!("unexpected admission"),
            }
        },
    );
    let app = parse(slo_route_manifest())
        .bind_managed_with_adapters(
            vec![ManagedAppBinding::<&'static str>::route(
                "api.route.health",
                AsyncCxFnHandler::new(move |cx: Cx| {
                    let call = work_calls.fetch_add(1, Ordering::AcqRel);
                    assert!(cx.budget().poll_quota <= if call == 0 { 128 } else { 256 });
                    assert!(cx.budget().cost_quota.unwrap() <= if call == 0 { 11 } else { 96 });
                    assert_eq!(cx.capability_budget().io_bytes, Some(64));
                    assert_eq!(cx.capability_budget().memory_bytes, Some(96));
                    assert!(
                        cx.budget().deadline.unwrap()
                            <= cx.now_for_observability() + Duration::from_secs(5)
                    );
                    assert!(!cx.capabilities().io && !cx.capabilities().spawn);
                    async { Response::new(StatusCode::OK, "admitted") }
                }),
            )],
            ManagedAppAdapters::new().slo_hook(hook),
            config(),
        )
        .unwrap();
    let router = app.router();
    let mut app = app.start(parent.cx()).unwrap();
    while !app.routes_ready() {
        yield_now().await;
    }
    for (index, status) in [
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::OK,
        StatusCode::OK,
    ]
    .into_iter()
    .enumerate()
    {
        let response = router
            .handle_with_cx(&cx, Request::new("GET", "/health"))
            .await;
        assert_eq!(response.status, status);
        assert_eq!(policies.load(Ordering::Acquire), index + 1);
        assert_eq!(work.load(Ordering::Acquire), (index + 1).saturating_sub(2));
    }
    app.abort();
    let report = app.join().await.unwrap();
    assert!(matches!(report.outcome, Outcome::Cancelled(_)));
    assert_eq!(report.started, 1);
    assert_eq!(report.joined, 1);
    assert!(!app.routes_ready());
    parent.close().await.unwrap();
    assert!(!cx.is_cancel_requested());
}

#[test]
fn managed_app_slo_routes_enforce_admission_authority_and_all_budget_layers() {
    for workers in [1, 2] {
        native(workers, managed_slo_route_scenario);
    }
}

async fn managed_slo_restart_scenario(cx: Cx) {
    let mut manifest = manifest_json();
    manifest["services"][0]["routes"] = json!([]);
    // Actor schemas have no slo_hook field. The explicit target is sufficient.
    manifest["slo_hooks"] = json!([{
        "name": "actor_policy", "kind": "error_rate", "target": "api.actor.cache"
    }]);
    let policies = Arc::new(AtomicUsize::new(0));
    let policy_calls = Arc::clone(&policies);
    let work = Arc::new(AtomicUsize::new(0));
    let work_calls = Arc::clone(&work);
    let hook = ManagedAppSloBinding::new(
        "actor_policy",
        AppSloHookKindV1::ErrorRate,
        "api.actor.cache",
        move |cx, admission| {
            assert_eq!(admission.unit, "api.actor.cache");
            assert!(admission.generation.is_some());
            assert!(!cx.capabilities().spawn);
            let attempt = policy_calls.fetch_add(1, Ordering::AcqRel);
            assert_eq!(
                admission.generation.unwrap().number,
                u64::try_from(attempt + 1).unwrap()
            );
            if attempt == 0 {
                ManagedAppSloDecision::Reject("first attempt refused".to_owned())
            } else {
                ManagedAppSloDecision::Admit(Budget::INFINITE.with_poll_quota(32))
            }
        },
    );
    let app = parse(manifest)
        .bind_managed_with_adapters(
            vec![ManagedAppBinding::worker(
                "api.actor.cache",
                ManagedRestartMode::Transient,
                move |cx: Cx, _: ManagedGeneration| {
                    assert!(cx.budget().poll_quota <= 32);
                    let attempt = work_calls.fetch_add(1, Ordering::AcqRel);
                    async move {
                        if attempt == 0 {
                            Outcome::Err("restart after admitted failure")
                        } else {
                            Outcome::Ok(())
                        }
                    }
                },
            )],
            ManagedAppAdapters::new().slo_hook(hook),
            config(),
        )
        .unwrap();
    let report = app.run(&cx).await.unwrap();
    assert_eq!(policies.load(Ordering::Acquire), 3);
    assert_eq!(work.load(Ordering::Acquire), 2);
    assert_eq!(report.started, 3);
    assert_eq!(report.joined, 3);
    assert_eq!(report.restart_batches, 2);
    assert_eq!(report.children.len(), 1);
    assert_eq!(report.children[0].generation.number, 3);
    assert!(matches!(report.children[0].outcome, Outcome::Ok(())));
    assert!(matches!(report.outcome, Outcome::Ok(())));
    assert!(!cx.is_cancel_requested());
}

#[test]
fn managed_app_slo_actor_target_is_rechecked_before_each_restart() {
    for workers in [1, 2] {
        native(workers, managed_slo_restart_scenario);
    }
}

async fn managed_slo_trigger_scenario(cx: Cx) {
    for trigger in ["startup", "interval", "signal"] {
        let mut manifest = signal_job_manifest();
        manifest["services"][0]["background_jobs"][0]["trigger"] = match trigger {
            "startup" => json!("startup"),
            "interval" => json!({"interval": {"every_ms": 1}}),
            _ => json!({"signal": {"source": "reload"}}),
        };
        manifest["services"][0]["background_jobs"][0]["slo_hook"] = json!("job_policy");
        manifest["slo_hooks"] = json!([{
            "name": "job_policy", "kind": "throughput", "target": "api.job.reload"
        }]);
        let policies = Arc::new(AtomicUsize::new(0));
        let policy_calls = Arc::clone(&policies);
        let work = Arc::new(AtomicUsize::new(0));
        let work_calls = Arc::clone(&work);
        let hook = ManagedAppSloBinding::new(
            "job_policy",
            AppSloHookKindV1::Throughput,
            "api.job.reload",
            move |cx, admission| {
                assert_eq!(admission.generation.unwrap().number, 1);
                assert!(!cx.capabilities().io && !cx.capabilities().spawn);
                let index = policy_calls.fetch_add(1, Ordering::AcqRel);
                if trigger != "startup" && index == 0 {
                    ManagedAppSloDecision::Admit(Budget::INFINITE)
                } else {
                    ManagedAppSloDecision::Reject("trigger admission closed".to_owned())
                }
            },
        );
        let factory = move |_: Cx, _: ManagedGeneration| {
            work_calls.fetch_add(1, Ordering::AcqRel);
            async { Outcome::<(), &'static str>::Ok(()) }
        };
        let (sender, receiver) = asupersync::channel::mpsc::channel(3);
        sender.try_send(()).unwrap();
        sender.try_send(()).unwrap();
        sender.try_send(()).unwrap();
        let binding = if trigger == "signal" {
            ManagedAppBinding::signal_worker(
                "api.job.reload",
                "reload",
                receiver,
                ManagedRestartMode::Temporary,
                factory,
            )
        } else {
            drop(receiver);
            ManagedAppBinding::worker("api.job.reload", ManagedRestartMode::Temporary, factory)
        };
        let app = parse(manifest)
            .bind_managed_with_adapters(
                vec![binding],
                ManagedAppAdapters::new().slo_hook(hook),
                config(),
            )
            .unwrap();
        let report = app.run(&cx).await.unwrap();
        assert_eq!(
            policies.load(Ordering::Acquire),
            if trigger == "startup" { 1 } else { 2 }
        );
        assert_eq!(work.load(Ordering::Acquire), usize::from(trigger != "startup"));
        assert_eq!(report.started, 1);
        assert_eq!(report.joined, 1);
        assert_eq!(report.restart_batches, 0);
        assert!(matches!(
            &report.children[0].outcome,
            Outcome::Err(ManagedAppWorkError::SloRejected { hook, reason })
                if hook == "job_policy" && reason == "trigger admission closed"
        ));
        assert!(
            sender.is_closed(),
            "rejected signal and pending queue cannot retain a receiver"
        );
    }
}

#[test]
fn managed_app_slo_gates_each_trigger_and_does_not_replay_rejected_signals() {
    for workers in [1, 2] {
        native(workers, managed_slo_trigger_scenario);
    }
}

#[test]
fn managed_app_slo_worker_panic_precedes_factory_and_drains_controller() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let mut manifest = manifest_json();
            manifest["services"][0]["routes"] = json!([]);
            manifest["slo_hooks"] = json!([{
                "name": "panic_policy", "kind": "saturation", "target": "api.actor.cache"
            }]);
            let work = Arc::new(AtomicUsize::new(0));
            let work_calls = Arc::clone(&work);
            let app = parse(manifest)
                .bind_managed_with_adapters(
                    vec![ManagedAppBinding::worker(
                        "api.actor.cache",
                        ManagedRestartMode::Temporary,
                        move |_: Cx, _: ManagedGeneration| {
                            work_calls.fetch_add(1, Ordering::AcqRel);
                            async { Outcome::<(), &'static str>::Ok(()) }
                        },
                    )],
                    ManagedAppAdapters::new().slo_hook(ManagedAppSloBinding::new(
                        "panic_policy",
                        AppSloHookKindV1::Saturation,
                        "api.actor.cache",
                        |_, _| panic!("policy callback panic"),
                    )),
                    config(),
                )
                .unwrap();
            let report = app.run(&cx).await.unwrap();
            assert_eq!(work.load(Ordering::Acquire), 0);
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
            assert_eq!(report.restart_batches, 0);
            assert!(matches!(
                &report.children[0].outcome,
                Outcome::Panicked(payload) if payload.message() == "policy callback panic"
            ));
        });
    }
}

mod managed_observability {
    use super::*;
    use asupersync::app::{
        AppObservabilitySinkKindV1 as SinkKind, ManagedAppEvent, ManagedAppEventOutcome as ResultKind,
        ManagedAppEventPhase as Phase, ManagedAppObservabilityBinding as Observer,
        ManagedAppResourceBinding, ManagedAppResourceError, ManagedAppResourceRequirement as Requires,
    };
    use std::sync::Mutex;

    fn sink(name: &str, kind: &str, capabilities: Value) -> Value {
        json!({
            "name": name, "kind": kind,
            "required_capabilities": {
                "cx_capabilities": capabilities, "feature_flags": [], "resources": []
            }
        })
    }

    fn route_manifest() -> Value {
        let mut manifest = manifest_json();
        manifest["services"][0]["actors"] = json!([]);
        manifest["observability"] = json!([sink("events", "trace", json!(["pure"]))]);
        manifest
    }

    fn routes() -> Vec<ManagedAppBinding<&'static str>> {
        vec![ManagedAppBinding::route(
            "api.route.health",
            AsyncCxFnHandler::new(|_: Cx| async { Response::empty(StatusCode::OK) }),
        )]
    }

    fn assert_observer_context(cx: &Cx, time: bool) {
        let caps = cx.capabilities();
        assert!(!caps.spawn && !caps.entropy && !caps.io && !caps.remote);
        assert_eq!(caps.time, time);
        assert_eq!(cx.timer_driver().is_some(), time);
        assert!(cx.blocking_pool_handle().is_none());
        assert!(cx.registry_handle().is_none());
        let ambient = Cx::current().expect("observer has explicit ambient context");
        assert_eq!(ambient.task_id(), cx.task_id());
        assert_eq!(ambient.region_id(), cx.region_id());
        assert!(!ambient.capabilities().spawn && !ambient.capabilities().io);
        assert_eq!(ambient.capabilities().time, time);
    }

    #[test]
    fn catalog_requires_exact_sinks_and_preserves_legacy_refusal() {
        let observer = || Observer::new("events", SinkKind::Trace, |_, _| {});
        assert!(matches!(
            parse(route_manifest()).bind_managed(routes(), config()),
            Err(ManagedAppBindError::Unsupported { .. })
        ));
        assert!(matches!(
            parse(route_manifest()).bind_managed_with_adapters(
                routes(), ManagedAppAdapters::new(), config()),
            Err(ManagedAppBindError::Missing(name)) if name == "observability:events"
        ));
        assert!(matches!(
            parse(route_manifest()).bind_managed_with_adapters(
                routes(), ManagedAppAdapters::new().observability(observer()).observability(observer()), config()),
            Err(ManagedAppBindError::Duplicate(name)) if name == "observability:events"
        ));
        assert!(matches!(
            parse(route_manifest()).bind_managed_with_adapters(
                routes(), ManagedAppAdapters::new().observability(
                    Observer::new("events", SinkKind::Metrics, |_, _| {})), config()),
            Err(ManagedAppBindError::KindMismatch(name)) if name == "observability:events"
        ));
        assert!(matches!(
            parse(route_manifest()).bind_managed_with_adapters(
                routes(), ManagedAppAdapters::new().observability(observer()).observability(
                    Observer::new("extra", SinkKind::Evidence, |_, _| {})), config()),
            Err(ManagedAppBindError::Unexpected(name)) if name == "observability:extra"
        ));
    }

    #[test]
    fn missing_sink_authority_refuses_before_any_factory_or_observer_runs() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let mut manifest = route_manifest();
                manifest["observability"][0]["required_capabilities"]["cx_capabilities"] =
                    json!(["remote"]);
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let app = parse(manifest).bind_managed_with_adapters(
                    routes(),
                    ManagedAppAdapters::new().observability(Observer::new(
                        "events", SinkKind::Trace, move |_, _| {
                            observed.fetch_add(1, Ordering::AcqRel);
                        })),
                    config(),
                ).unwrap();
                let router = app.router();
                assert!(matches!(app.start(&cx), Err(ManagedAppBindError::Capability {
                    unit, capability: asupersync::app::AppCxCapabilityV1::Remote
                }) if unit == "observability:events"));
                assert_eq!(router.handle_with_cx(&cx, Request::new("GET", "/health")).await.status,
                    StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(calls.load(Ordering::Acquire), 0);
            });
        }
    }

    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct ObserverPanicPayload(Arc<AtomicUsize>);
    impl Drop for ObserverPanicPayload {
        fn drop(&mut self) {
            let ambient = Cx::current().expect("panic payload retains observer context");
            assert_observer_context(&ambient, false);
            self.0.fetch_add(1, Ordering::AcqRel);
            panic!("observer panic payload destructor");
        }
    }

    async fn lifecycle_scenario(cx: Cx) {
        use asupersync::observability::{LogCollector, LogEntry, Metrics};

        let mut manifest = manifest_json();
        manifest["observability"] = json!([
            sink("panic", "trace", json!(["pure"])),
            sink("logs", "trace", json!(["trace"])),
            sink("counts", "metrics", json!(["time"])),
            sink("evidence", "evidence", json!(["pure"]))
        ]);
        let events = Arc::new(Mutex::new(Vec::<ManagedAppEvent>::new()));
        let records = Arc::clone(&events);
        let collector = LogCollector::new(32);
        let logs = collector.clone();
        let counter = Metrics::new().counter("app.boundaries");
        let metric = Arc::clone(&counter);
        let starts = Arc::new(AtomicUsize::new(0));
        let started = Arc::clone(&starts);
        let drops = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::clone(&drops);
        let retired = Arc::clone(&drops);
        let panic_drops = Arc::new(AtomicUsize::new(0));
        let panic_payload_drops = Arc::clone(&panic_drops);
        let parked = Arc::new(AtomicBool::new(false));
        let waiting = Arc::clone(&parked);
        let app = parse(manifest).bind_managed_with_adapters(
            vec![
                ManagedAppBinding::route("api.route.health", AsyncCxFnHandler::new(|cx: Cx| {
                    assert!(!cx.capabilities().time && !cx.capabilities().spawn);
                    async { Response::new(StatusCode::BAD_REQUEST, "typed response survives observers") }
                })),
                ManagedAppBinding::worker("api.actor.cache", ManagedRestartMode::Transient,
                    move |cx: Cx, _: ManagedGeneration| {
                        let attempt = started.fetch_add(1, Ordering::AcqRel);
                        let dropped = Arc::clone(&dropped);
                        let waiting = Arc::clone(&waiting);
                        async move {
                            let _drop = Dropped(dropped);
                            if attempt == 0 {
                                return Outcome::Err("restart after exact domain error");
                            }
                            let mut cancelled = std::pin::pin!(cx.cancelled());
                            poll_fn(|task| {
                                let result = cancelled.as_mut().poll(task);
                                if result.is_pending() {
                                    waiting.store(true, Ordering::Release);
                                }
                                result
                            }).await;
                            let _ = cx.checkpoint();
                            Outcome::Cancelled(cx.cancel_reason().unwrap())
                        }
                    }),
            ],
            ManagedAppAdapters::new()
                .observability(Observer::new("panic", SinkKind::Trace, move |_, _| {
                    std::panic::panic_any(ObserverPanicPayload(Arc::clone(&panic_payload_drops)));
                }))
                .observability(Observer::new("logs", SinkKind::Trace, move |cx, event| {
                    assert_observer_context(cx, false);
                    logs.log(LogEntry::info(format!("{} {:?}", event.unit, event.phase)));
                }))
                .observability(Observer::new("counts", SinkKind::Metrics, move |cx, _| {
                    // A Pure work unit does not mask its separately authorized sink.
                    assert_observer_context(cx, true);
                    metric.increment();
                }))
                .observability(Observer::new("evidence", SinkKind::Evidence, move |cx, event| {
                    assert_observer_context(cx, false);
                    if event.unit == "api.actor.cache" && event.phase == Phase::Finished {
                        assert!(retired.load(Ordering::Acquire)
                            >= usize::try_from(event.generation.unwrap().number).unwrap());
                    }
                    records.lock().unwrap().push(event.clone());
                })),
            config(),
        ).unwrap();
        let router = app.router();
        let mut app = app.start(&cx).unwrap();
        while !app.routes_ready() || !parked.load(Ordering::Acquire) {
            yield_now().await;
        }
        let response = router.handle_with_cx(&cx, Request::new("GET", "/health")).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        app.abort();
        let report = app.join().await.unwrap();
        assert_eq!(report.restart_batches, 1);
        assert_eq!(report.started, report.joined);
        assert_eq!(starts.load(Ordering::Acquire), 2);
        assert_eq!(drops.load(Ordering::Acquire), 2);
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 6);
        assert_eq!(collector.len(), 6);
        assert_eq!(counter.get(), 6);
        for start in events.iter().filter(|event| event.phase == Phase::Started) {
            let finish = events.iter().find(|event| {
                event.phase == Phase::Finished && event.region == start.region
            }).unwrap();
            assert_eq!(finish.task, start.task);
            assert!(finish.at >= start.at);
        }
        let finished: Vec<_> = events.iter().filter(|event| event.phase == Phase::Finished).collect();
        assert!(finished.iter().any(|event| event.unit == "api.route.health"
            && event.outcome == Some(ResultKind::Failed) && event.http_status == Some(400)));
        assert!(finished.iter().any(|event| event.generation.is_some_and(|g| g.number == 1)
            && event.outcome == Some(ResultKind::Failed)));
        assert!(finished.iter().any(|event| event.generation.is_some_and(|g| g.number == 2)
            && event.outcome == Some(ResultKind::Cancelled)));
        let stats = app.observability_stats();
        assert_eq!(stats.len(), 4);
        for stat in stats {
            if stat.name == "panic" {
                assert!(stat.disabled);
                assert!((1..=6).contains(&stat.attempted));
                assert_eq!((stat.delivered, stat.panicked), (0, stat.attempted));
                assert_eq!(u64::try_from(panic_drops.load(Ordering::Acquire)).unwrap(), stat.panicked);
            } else {
                assert!(!stat.disabled);
                assert_eq!(stat.attempted, 6);
                assert_eq!((stat.delivered, stat.panicked), (6, 0));
            }
        }
    }

    #[test]
    fn adapters_observe_real_routes_restarts_and_cancelled_cleanup_on_native_workers() {
        for workers in [1, 2] {
            native(workers, lifecycle_scenario);
        }
    }

    #[test]
    fn admission_refusal_and_panic_emit_no_false_work_start() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                for panics in [false, true] {
                    let mut manifest = manifest_json();
                    manifest["services"][0]["routes"] = json!([]);
                    manifest["slo_hooks"] = json!([{
                        "name": "admission", "kind": "saturation", "target": "api.actor.cache"
                    }]);
                    manifest["observability"] = json!([sink("events", "evidence", json!(["pure"]))]);
                    let events = Arc::new(Mutex::new(Vec::new()));
                    let records = Arc::clone(&events);
                    let work = Arc::new(AtomicUsize::new(0));
                    let work_calls = Arc::clone(&work);
                    let app = parse(manifest).bind_managed_with_adapters(
                        vec![ManagedAppBinding::worker("api.actor.cache", ManagedRestartMode::Temporary,
                            move |_: Cx, _| {
                                work_calls.fetch_add(1, Ordering::AcqRel);
                                async { Outcome::<(), &'static str>::Ok(()) }
                            })],
                        ManagedAppAdapters::new()
                            .slo_hook(ManagedAppSloBinding::new("admission", AppSloHookKindV1::Saturation,
                                "api.actor.cache", move |_, _| {
                                    assert!(!panics, "policy panic remains the result");
                                    ManagedAppSloDecision::Reject("saturated".to_owned())
                                }))
                            .observability(Observer::new("events", SinkKind::Evidence, move |_, event| {
                                records.lock().unwrap().push(event.clone());
                            })),
                        config(),
                    ).unwrap();
                    let mut app = app.start(&cx).unwrap();
                    let report = app.join().await.unwrap();
                    assert_eq!(work.load(Ordering::Acquire), 0, "refused factory ran");
                    if panics {
                        assert!(matches!(&report.children[0].outcome, Outcome::Panicked(payload)
                            if payload.message() == "policy panic remains the result"));
                    } else {
                        assert!(matches!(&report.children[0].outcome,
                            Outcome::Err(ManagedAppWorkError::SloRejected { reason, .. }) if reason == "saturated"));
                    }
                    let events = events.lock().unwrap();
                    assert_eq!(events.len(), 1);
                    assert_eq!(events[0].phase, Phase::AdmissionRejected);
                    assert_eq!(events[0].outcome, Some(if panics { ResultKind::Panicked } else { ResultKind::Rejected }));
                    assert!(events[0].region.is_none() && events[0].task.is_none());
                    assert_eq!(app.observability_stats()[0].delivered, 1);
                }
            });
        }
    }

    #[test]
    fn observers_follow_each_background_trigger_invocation() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                for trigger in ["startup", "interval", "signal"] {
                    let mut manifest = signal_job_manifest();
                    manifest["services"][0]["background_jobs"][0]["trigger"] = match trigger {
                        "startup" => json!("startup"),
                        "interval" => json!({"interval": {"every_ms": 1}}),
                        _ => json!({"signal": {"source": "reload"}}),
                    };
                    manifest["slo_hooks"] = json!([{
                        "name":"limit", "kind":"throughput", "target":"api.job.reload"
                    }]);
                    manifest["observability"] = json!([sink("events", "evidence", json!(["pure"]))]);
                    let events = Arc::new(Mutex::new(Vec::new()));
                    let records = Arc::clone(&events);
                    let admissions = Arc::new(AtomicUsize::new(0));
                    let count = Arc::clone(&admissions);
                    let factory = |_: Cx, _: ManagedGeneration| async { Outcome::<(), &'static str>::Ok(()) };
                    let (sender, receiver) = asupersync::channel::mpsc::channel(3);
                    sender.try_send(()).unwrap();
                    sender.try_send(()).unwrap();
                    let binding = if trigger == "signal" {
                        ManagedAppBinding::signal_worker("api.job.reload", "reload", receiver,
                            ManagedRestartMode::Temporary, factory)
                    } else {
                        drop(receiver);
                        ManagedAppBinding::worker("api.job.reload", ManagedRestartMode::Temporary, factory)
                    };
                    let app = parse(manifest).bind_managed_with_adapters(vec![binding],
                        ManagedAppAdapters::new()
                            .slo_hook(ManagedAppSloBinding::new("limit", AppSloHookKindV1::Throughput,
                                "api.job.reload", move |_, _| {
                                    if count.fetch_add(1, Ordering::AcqRel) == 0 {
                                        ManagedAppSloDecision::Admit(Budget::INFINITE)
                                    } else {
                                        ManagedAppSloDecision::Reject("stop this trigger".to_owned())
                                    }
                                }))
                            .observability(Observer::new("events", SinkKind::Evidence, move |_, event| {
                                records.lock().unwrap().push(event.clone());
                            })),
                        config()).unwrap();
                    let mut app = app.start(&cx).unwrap();
                    app.join().await.unwrap();
                    let events = events.lock().unwrap();
                    assert_eq!(events.len(), if trigger == "startup" { 2 } else { 3 });
                    assert_eq!(events[0].phase, Phase::Started);
                    assert_eq!(events[1].phase, Phase::Finished);
                    assert_eq!(events[1].outcome, Some(ResultKind::Succeeded));
                    assert_eq!(events[0].region, events[1].region);
                    if trigger != "startup" {
                        assert_eq!(events[2].phase, Phase::AdmissionRejected);
                        assert_eq!(events[2].outcome, Some(ResultKind::Rejected));
                        assert!(events[2].region.is_none());
                    }
                    assert!(events.iter().all(|event| event.kind == asupersync::app::AppSpecV1WorkUnitKind::BackgroundJob));
                    assert_eq!(app.observability_stats()[0].panicked, 0);
                }
            });
        }
    }

    #[test]
    fn sink_resources_are_typed_and_physically_scoped() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let mut manifest = route_manifest();
                manifest["resources"] = json!([
                    {"name":"events", "kind":"memory", "capability":"trace"},
                    {"name":"hidden", "kind":"memory", "capability":"trace"}
                ]);
                manifest["observability"][0]["required_capabilities"]["cx_capabilities"] = json!(["trace"]);
                manifest["observability"][0]["required_capabilities"]["resources"] = json!(["events"]);
                let spec = parse(manifest);
                let count = Arc::new(AtomicUsize::new(0));
                let hidden_drops = Arc::new(AtomicUsize::new(0));
                let resources = vec![
                    ManagedAppResourceBinding::new(spec.resources[0].clone(), Arc::clone(&count)),
                    ManagedAppResourceBinding::new(spec.resources[1].clone(), Dropped(Arc::clone(&hidden_drops))),
                ];
                let observer = Observer::with_resources("events", SinkKind::Trace,
                    vec![Requires::of::<Arc<AtomicUsize>>("events")], |cx, _, resources| {
                        assert_observer_context(cx, false);
                        assert_eq!(resources.names().collect::<Vec<_>>(), vec!["events"]);
                        assert!(matches!(resources.get::<Dropped>("hidden"), Err(ManagedAppResourceError::Undeclared(_))));
                        resources.get::<Arc<AtomicUsize>>("events").unwrap().fetch_add(1, Ordering::AcqRel);
                    });
                let app = spec.bind_managed_with_adapters(routes(),
                    ManagedAppAdapters::new().resources(resources).observability(observer), config()).unwrap();
                assert_eq!(hidden_drops.load(Ordering::Acquire), 1, "sink retained the whole catalog");
                let router = app.router();
                let mut app = app.start(&cx).unwrap();
                while !app.routes_ready() { yield_now().await; }
                assert_eq!(router.handle_with_cx(&cx, Request::new("GET", "/health")).await.status, StatusCode::OK);
                app.abort();
                app.join().await.unwrap();
                assert_eq!(count.load(Ordering::Acquire), 2);
                assert_eq!(app.observability_stats()[0].panicked, 0);
            });
        }
    }

    #[test]
    fn sink_resource_type_mismatch_is_a_preflight_error() {
        let mut manifest = route_manifest();
        manifest["resources"] = json!([
            {"name":"events", "kind":"memory", "capability":"trace"}
        ]);
        manifest["observability"][0]["required_capabilities"]["cx_capabilities"] = json!(["trace"]);
        manifest["observability"][0]["required_capabilities"]["resources"] = json!(["events"]);
        for include_requirement in [false, true] {
            let spec = parse(manifest.clone());
            let resource = ManagedAppResourceBinding::new(spec.resources[0].clone(), 7_u32);
            let requirements = if include_requirement {
                vec![Requires::of::<AtomicUsize>("events")]
            } else {
                Vec::new()
            };
            let result = spec.bind_managed_with_adapters(routes(),
                ManagedAppAdapters::new().resources(vec![resource]).observability(
                    Observer::with_resources("events", SinkKind::Trace, requirements,
                        |_, _, _| panic!("invalid resource adapter must never run"))),
                config());
            if include_requirement {
                assert!(matches!(result, Err(ManagedAppBindError::Resource(
                    ManagedAppResourceError::TypeMismatch { resource, .. })) if resource == "events"));
            } else {
                assert!(matches!(result, Err(ManagedAppBindError::Resource(
                    ManagedAppResourceError::MissingRequirement { unit, resource }))
                    if unit == "observability:events" && resource == "events"));
            }
        }
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn finished_event_follows_native_finalizers_and_reports_cleanup_panic() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let runtime = asupersync::runtime::Runtime::current_handle().unwrap();
                let parent = cx.open_child_region(signal_parent_spec()).await.unwrap();
                let mut manifest = manifest_json();
                manifest["services"][0]["routes"] = json!([]);
                manifest["observability"] = json!([sink("events", "evidence", json!(["pure"]))]);
                let (release, receiver) = asupersync::channel::oneshot::channel::<()>();
                let receiver = Arc::new(Mutex::new(Some(receiver)));
                let parked = Arc::new(AtomicBool::new(false));
                let waiting = Arc::clone(&parked);
                let events = Arc::new(Mutex::new(Vec::<ManagedAppEvent>::new()));
                let records = Arc::clone(&events);
                let finalized = Arc::new(AtomicUsize::new(0));
                let observed_finalizer = Arc::clone(&finalized);
                let app = parse(manifest).bind_managed_with_adapters(
                    vec![ManagedAppBinding::worker("api.actor.cache", ManagedRestartMode::Temporary,
                        move |cx: Cx, _| {
                            let mut receiver = receiver.lock().unwrap().take().unwrap();
                            let waiting = Arc::clone(&waiting);
                            async move {
                                let mut receive = std::pin::pin!(receiver.recv(&cx));
                                poll_fn(|task| {
                                    let result = receive.as_mut().poll(task);
                                    if result.is_pending() { waiting.store(true, Ordering::Release); }
                                    result
                                }).await.unwrap();
                                Outcome::<(), &'static str>::Ok(())
                            }
                        })],
                    ManagedAppAdapters::new().observability(Observer::new(
                        "events", SinkKind::Evidence, move |_, event| {
                            if event.phase == Phase::Finished {
                                assert_eq!(observed_finalizer.load(Ordering::Acquire), 1,
                                    "terminal telemetry preceded owned finalization");
                            }
                            records.lock().unwrap().push(event.clone());
                        })),
                    config(),
                ).unwrap();
                let mut app = app.start(parent.cx()).unwrap();
                while !parked.load(Ordering::Acquire) { yield_now().await; }
                let region = events.lock().unwrap()[0].region.unwrap();
                let finalizer_count = Arc::clone(&finalized);
                assert!(runtime.register_sync_finalizer_for_testing(region, move || {
                    finalizer_count.fetch_add(1, Ordering::AcqRel);
                    panic!("observed native finalizer failure");
                }));
                release.send_blocking(()).unwrap();
                let report = app.join().await.unwrap();
                assert!(matches!(&report.children[0].outcome, Outcome::Panicked(_)));
                {
                    let events = events.lock().unwrap();
                    assert_eq!(events.len(), 2);
                    let finish = &events[1];
                    assert_eq!(finish.phase, Phase::Finished);
                    assert_eq!(finish.outcome, Some(ResultKind::Panicked));
                    assert_eq!(finish.cleanup_outcome, Some(ResultKind::Panicked));
                    assert_eq!(finish.region_outcome, Some(ResultKind::Panicked));
                    assert!(finish.descendant_panicked);
                }
                assert_eq!(app.observability_stats()[0].panicked, 0);
                parent.close().await.unwrap();
            });
        }
    }
}
