//! Golden snapshot for LabRuntime replay seed determinism.

mod common;

use common::init_test_logging;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::trace::{TraceEventKey, canonicalize, trace_event_key};
use asupersync::types::Budget;
use insta::assert_json_snapshot;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct SeedReplayScenarioGolden {
    name: &'static str,
    seed: u64,
    worker_count: usize,
    report: ScrubbedReportGolden,
    trace: ScrubbedTraceGolden,
}

#[derive(Debug, Serialize)]
struct ScrubbedTraceGolden {
    len: usize,
    fingerprint: u64,
    certificate: TraceCertificateGolden,
    canonical_depth: usize,
    canonical_layers: Vec<Vec<TraceEventKey>>,
}

#[derive(Debug, Serialize)]
struct TraceCertificateGolden {
    event_hash: u64,
    event_count: u64,
    schedule_hash: u64,
}

#[derive(Debug, Serialize)]
struct ScrubbedReportGolden {
    quiescent: bool,
    steps_delta: u64,
    steps_total: u64,
    invariant_violations: Vec<String>,
    temporal_failures: Vec<String>,
    oracle_total: usize,
    oracle_passed: usize,
    oracle_failed: usize,
}

fn build_scenario<F>(name: &'static str, config: LabConfig, setup: F) -> SeedReplayScenarioGolden
where
    F: Fn(&mut LabRuntime) + Copy,
{
    let first = run_once(name, config.clone(), setup);
    let second = run_once(name, config, setup);

    let first_bytes = serde_json::to_vec(&first).expect("serialize first scenario");
    let second_bytes = serde_json::to_vec(&second).expect("serialize second scenario");

    assert_eq!(
        first_bytes, second_bytes,
        "same-seed replay diverged for scenario {name}"
    );

    first
}

fn run_once<F>(name: &'static str, config: LabConfig, setup: F) -> SeedReplayScenarioGolden
where
    F: Fn(&mut LabRuntime),
{
    let seed = config.seed;
    let worker_count = config.worker_count;
    let mut runtime = LabRuntime::new(config);
    setup(&mut runtime);

    let report = runtime.run_until_quiescent_with_report();
    let events = runtime.trace().snapshot();
    let canonical = canonicalize(&events);
    let canonical_layers = canonical
        .layers()
        .iter()
        .map(|layer| layer.iter().map(trace_event_key).collect())
        .collect();

    SeedReplayScenarioGolden {
        name,
        seed,
        worker_count,
        report: ScrubbedReportGolden {
            quiescent: report.quiescent,
            steps_delta: report.steps_delta,
            steps_total: report.steps_total,
            invariant_violations: report.invariant_violations.clone(),
            temporal_failures: report.temporal_invariant_failures.clone(),
            oracle_total: report.oracle_report.total,
            oracle_passed: report.oracle_report.passed,
            oracle_failed: report.oracle_report.failed,
        },
        trace: ScrubbedTraceGolden {
            len: report.trace_len,
            fingerprint: report.trace_fingerprint,
            certificate: TraceCertificateGolden {
                event_hash: report.trace_certificate.event_hash,
                event_count: report.trace_certificate.event_count,
                schedule_hash: report.trace_certificate.schedule_hash,
            },
            canonical_depth: canonical.depth(),
            canonical_layers,
        },
    }
}

fn single_worker_yield_fanout() -> SeedReplayScenarioGolden {
    let config = LabConfig::new(0x51A1_F0A0)
        .worker_count(1)
        .trace_capacity(2_048)
        .max_steps(4_096);

    build_scenario("single_worker_yield_fanout", config, |runtime| {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        for yields in [1usize, 2, 3] {
            let (task_id, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    for _ in 0..yields {
                        yield_now().await;
                    }
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }
    })
}

fn multi_worker_priority_mix() -> SeedReplayScenarioGolden {
    let config = LabConfig::new(0x71CE_900D)
        .worker_count(4)
        .trace_capacity(4_096)
        .max_steps(8_192);

    build_scenario("multi_worker_priority_mix", config, |runtime| {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        for (priority, yields) in [(9u8, 0usize), (6, 1), (3, 2), (1, 3)] {
            let (task_id, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    for _ in 0..yields {
                        yield_now().await;
                    }
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, priority);
        }
    })
}

fn nested_region_yield_mix() -> SeedReplayScenarioGolden {
    let config = LabConfig::new(0x903D_8EED)
        .worker_count(2)
        .trace_capacity(2_048)
        .max_steps(4_096);

    build_scenario("nested_region_yield_mix", config, |runtime| {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");

        let (root_task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                yield_now().await;
            })
            .expect("create root task");
        let (child_task_a, _handle) = runtime
            .state
            .create_task(child, Budget::INFINITE, async {
                yield_now().await;
                yield_now().await;
            })
            .expect("create child task");
        let (child_task_b, _handle) = runtime
            .state
            .create_task(child, Budget::INFINITE, async {
                for _ in 0..3 {
                    yield_now().await;
                }
            })
            .expect("create child task");

        {
            let mut scheduler = runtime.scheduler.lock();
            scheduler.schedule(root_task, 4);
            scheduler.schedule(child_task_a, 7);
            scheduler.schedule(child_task_b, 2);
        }
    })
}

#[test]
fn seed_replay_trace_determinism() {
    init_test_logging();

    let golden = vec![
        single_worker_yield_fanout(),
        multi_worker_priority_mix(),
        nested_region_yield_mix(),
    ];

    assert_json_snapshot!("seed_replay_trace_determinism", golden);
}
