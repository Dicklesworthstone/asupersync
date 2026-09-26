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
