//! Spork baseline benchmarks (bd-12vyy).
//!
//! Reproducible benchmarks for core Spork operations:
//! - GenServer call/cast
//! - Registry register/whereis
//! - Supervisor restart decision loop
//!
//! All benchmarks use deterministic inputs (fixed seeds) to ensure
//! reproducibility across runs.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use criterion::{criterion_group, criterion_main, Criterion};

use asupersync::cx::{Cx, NameRegistry, Scope};
use asupersync::gen_server::{CallError, GenServer, Reply, SystemMsg};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::supervision::{ChildSpec, RestartPolicy, SupervisorBuilder};
use asupersync::types::policy::FailFast;
use asupersync::types::{Budget, RegionId, TaskId, Time};

// =============================================================================
// GENSERVER BENCHMARKS
// =============================================================================

/// Minimal counter server for call/cast benchmarks.
struct BenchCounter {
    count: u64,
}

enum BenchCall {
    Add(u64),
}

enum BenchCast {
    Add(u64),
}

impl GenServer for BenchCounter {
    type Call = BenchCall;
    type Reply = u64;
    type Cast = BenchCast;
    type Info = SystemMsg;

    fn handle_call(
        &mut self,
        _cx: &Cx,
        request: BenchCall,
        reply: Reply<u64>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match request {
            BenchCall::Add(n) => {
                self.count += n;
                let _ = reply.send(self.count);
            }
        }
        Box::pin(async {})
    }

    fn handle_cast(
        &mut self,
        _cx: &Cx,
        msg: BenchCast,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match msg {
            BenchCast::Add(n) => self.count += n,
        }
        Box::pin(async {})
    }
}

fn bench_genserver_call(c: &mut Criterion) {
    let mut group = c.benchmark_group("spork/genserver");

    group.bench_function("call_roundtrip", |b| {
        b.iter(|| {
            let budget = Budget::new().with_poll_quota(100_000);
            let mut runtime = LabRuntime::new(LabConfig::new(42));
            let region = runtime.state.create_root_region(budget);
            let cx = Cx::for_testing();
            let scope = Scope::<FailFast>::new(region, budget);

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, BenchCounter { count: 0 }, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let server_ref = handle.server_ref();
            let result: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
            let result_clone = Arc::clone(&result);

            let (ch, cs) = scope
                .spawn(&mut runtime.state, &cx, move |cx| async move {
                    let r = server_ref.call(&cx, BenchCall::Add(1)).await;
                    *result_clone.lock().unwrap() = Some(r);
                })
                .unwrap();
            let client_id = ch.task_id();
            runtime.state.store_spawned_task(client_id, cs);

            {
                let mut sched = runtime.scheduler.lock().unwrap();
                sched.schedule(server_task_id, 0);
                sched.schedule(client_id, 0);
            }
            runtime.run_until_idle();
            {
                let mut sched = runtime.scheduler.lock().unwrap();
                sched.schedule(server_task_id, 0);
                sched.schedule(client_id, 0);
            }
            runtime.run_until_idle();

            let guard = result.lock().unwrap();
            std::hint::black_box(guard.is_some())
        })
    });

    group.bench_function("cast_fire_and_forget", |b| {
        b.iter(|| {
            let budget = Budget::new().with_poll_quota(100_000);
            let mut runtime = LabRuntime::new(LabConfig::new(42));
            let region = runtime.state.create_root_region(budget);
            let cx = Cx::for_testing();
            let scope = Scope::<FailFast>::new(region, budget);

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, BenchCounter { count: 0 }, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let server_ref = handle.server_ref();

            // Fire 10 casts without waiting for processing.
            for i in 0..10 {
                let _ = server_ref.try_cast(BenchCast::Add(i));
            }

            runtime
                .scheduler
                .lock()
                .unwrap()
                .schedule(server_task_id, 0);
            runtime.run_until_idle();

            std::hint::black_box(())
        })
    });

    group.bench_function("spawn_server", |b| {
        b.iter(|| {
            let budget = Budget::new().with_poll_quota(100_000);
            let mut runtime = LabRuntime::new(LabConfig::new(42));
            let region = runtime.state.create_root_region(budget);
            let cx = Cx::for_testing();
            let scope = Scope::<FailFast>::new(region, budget);

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, BenchCounter { count: 0 }, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            std::hint::black_box(server_task_id)
        })
    });

    group.finish();
}

// =============================================================================
// REGISTRY BENCHMARKS
// =============================================================================

fn bench_registry_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("spork/registry");

    group.bench_function("register_single", |b| {
        b.iter(|| {
            let mut registry = NameRegistry::new();
            let task_id = TaskId::new_for_test(1, 0);
            let region = RegionId::new_for_test(0, 0);
            let now = Time::ZERO;
            let mut lease = registry
                .register("bench_name", task_id, region, now)
                .unwrap();
            let _ = lease.abort();
            std::hint::black_box(())
        })
    });

    group.bench_function("register_100_unique", |b| {
        b.iter(|| {
            let mut registry = NameRegistry::new();
            let region = RegionId::new_for_test(0, 0);
            let now = Time::ZERO;
            let mut leases = Vec::with_capacity(100);
            for i in 0..100u32 {
                let task_id = TaskId::new_for_test(i + 1, 0);
                let name = format!("name_{i}");
                leases.push(registry.register(name, task_id, region, now).unwrap());
            }
            for lease in &mut leases {
                let _ = lease.abort();
            }
            std::hint::black_box(())
        })
    });

    group.bench_function("whereis_hit", |b| {
        let mut registry = NameRegistry::new();
        let task_id = TaskId::new_for_test(1, 0);
        let region = RegionId::new_for_test(0, 0);
        let now = Time::ZERO;
        // Keep the lease alive for the duration of the benchmark.
        let mut lease = registry.register("target", task_id, region, now).unwrap();

        b.iter(|| std::hint::black_box(registry.whereis("target")));

        let _ = lease.abort();
    });

    group.bench_function("whereis_miss", |b| {
        let registry = NameRegistry::new();
        b.iter(|| std::hint::black_box(registry.whereis("nonexistent")))
    });

    group.bench_function("register_unregister_cycle", |b| {
        b.iter(|| {
            let mut registry = NameRegistry::new();
            let task_id = TaskId::new_for_test(1, 0);
            let region = RegionId::new_for_test(0, 0);
            let now = Time::ZERO;
            let mut lease = registry
                .register("cycle_name", task_id, region, now)
                .unwrap();
            let _ = lease.abort();
            let _ = registry.unregister("cycle_name");
            std::hint::black_box(())
        })
    });

    group.finish();
}

// =============================================================================
// SUPERVISOR BENCHMARKS
// =============================================================================

/// No-op child start factory for benchmarks.
#[allow(clippy::unnecessary_wraps)]
fn noop_child_start(
    _scope: &Scope<'static, FailFast>,
    _state: &mut asupersync::runtime::RuntimeState,
    _cx: &Cx,
) -> Result<TaskId, asupersync::runtime::SpawnError> {
    Ok(TaskId::new_for_test(99, 0))
}

fn bench_supervisor_restart_decision(c: &mut Criterion) {
    let mut group = c.benchmark_group("spork/supervisor");

    group.bench_function("restart_plan_one_for_one_3_children", |b| {
        let compiled = SupervisorBuilder::new("bench_sup")
            .child(ChildSpec::new("child_a", noop_child_start))
            .child(ChildSpec::new("child_b", noop_child_start))
            .child(ChildSpec::new("child_c", noop_child_start))
            .compile()
            .unwrap();

        b.iter(|| std::hint::black_box(compiled.restart_plan_for("child_b")))
    });

    group.bench_function("restart_plan_one_for_all_5_children", |b| {
        let compiled = SupervisorBuilder::new("bench_sup_all")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("c1", noop_child_start))
            .child(ChildSpec::new("c2", noop_child_start))
            .child(ChildSpec::new("c3", noop_child_start))
            .child(ChildSpec::new("c4", noop_child_start))
            .child(ChildSpec::new("c5", noop_child_start))
            .compile()
            .unwrap();

        b.iter(|| std::hint::black_box(compiled.restart_plan_for("c3")))
    });

    group.bench_function("restart_plan_rest_for_one_5_children", |b| {
        let compiled = SupervisorBuilder::new("bench_sup_rest")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(ChildSpec::new("c1", noop_child_start))
            .child(ChildSpec::new("c2", noop_child_start))
            .child(ChildSpec::new("c3", noop_child_start))
            .child(ChildSpec::new("c4", noop_child_start))
            .child(ChildSpec::new("c5", noop_child_start))
            .compile()
            .unwrap();

        b.iter(|| std::hint::black_box(compiled.restart_plan_for("c2")))
    });

    group.bench_function("compile_supervisor_10_children", |b| {
        b.iter(|| {
            let mut builder = SupervisorBuilder::new("compile_bench");
            for i in 0..10 {
                builder = builder.child(ChildSpec::new(format!("child_{i}"), noop_child_start));
            }
            std::hint::black_box(builder.compile().unwrap())
        })
    });

    group.finish();
}

// =============================================================================
// HARNESS BENCHMARKS
// =============================================================================

fn bench_harness_lifecycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("spork/harness");

    group.bench_function("empty_app_lifecycle", |b| {
        b.iter(|| {
            let app = asupersync::app::AppSpec::new("bench_app");
            let harness = asupersync::lab::SporkAppHarness::with_seed(42, app).unwrap();
            let report = harness.run_to_report().unwrap();
            std::hint::black_box(report.run.trace_fingerprint)
        })
    });

    group.bench_function("lab_runtime_create", |b| {
        b.iter(|| {
            let runtime = LabRuntime::new(LabConfig::new(42));
            std::hint::black_box(runtime.now())
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_genserver_call,
    bench_registry_operations,
    bench_supervisor_restart_decision,
    bench_harness_lifecycle,
);

criterion_main!(benches);
