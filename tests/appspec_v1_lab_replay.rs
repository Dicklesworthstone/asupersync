//! AppSpec v1 deterministic lab replay (3gaiun.2.3 / [APPSPEC][A3]).
//!
//! Executes the minimal AppSpec topology end-to-end through the lab runtime and
//! proves the A3 "deterministic lab replay for the minimal topology" acceptance
//! criterion with a real, executed proof (not a contracted-only snapshot):
//!
//! - the minimal single-service manifest compiles via the A2 compiler and runs
//!   to **region-close quiescence with no orphan tasks** under the lab runtime,
//!   for each declared deterministic seed (1, 2, 3);
//! - replaying the same seed yields an identical Foata-canonical trace
//!   fingerprint (deterministic replay).
//!
//! Scope note: this exercises the **single-supervision-group** lowering that the
//! A2 compiler actually implements. The richer multi-group region tree in the
//! `minimal-http-worker-topology` artifact snapshot remains a contracted
//! topology pending A2 multi-group sub-supervisor lowering; it is not claimed as
//! executed here. No broad runtime-correctness or workspace-health claim is made.

use asupersync::app::{AppSpec, AppSpecV1};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::SporkAppHarness;
use asupersync::runtime::RuntimeState;
use asupersync::supervision::{ChildSpec, SupervisionStrategy};
use asupersync::types::policy::FailFast;
use serde_json::json;

/// The executable minimal-http-worker topology, lowered as a single supervision
/// group (matching the A2 compiler's implemented capability).
fn minimal_http_worker_manifest() -> AppSpecV1 {
    serde_json::from_value(json!({
        "schema_version": "asupersync.appspec.v1",
        "name": "minimal-http-worker",
        "services": [{
            "name": "api",
            "routes": [{
                "name": "health",
                "method": "GET",
                "path": "/health",
                "handler": "minimal_http_worker::health",
                "required_capabilities": {
                    "cx_capabilities": ["net", "trace"],
                    "feature_flags": ["native-runtime"],
                    "resources": ["public_socket"]
                },
                "budget": "api_request"
            }],
            "actors": [],
            "background_jobs": [{
                "name": "worker",
                "entrypoint": "minimal_http_worker::worker",
                "trigger": "startup",
                "required_capabilities": {
                    "cx_capabilities": ["trace"],
                    "feature_flags": [],
                    "resources": []
                },
                "budget": "worker_batch"
            }],
            "resources": ["public_socket"],
            "budget": "worker_batch"
        }],
        "resources": [
            { "name": "public_socket", "kind": "socket", "capability": "net" }
        ],
        "budgets": [
            { "name": "api_request", "poll_quota": 1000 },
            { "name": "worker_batch", "deadline_ms": 5000 }
        ],
        "slo_hooks": [],
        "supervision": {
            "root_group": "root",
            "groups": [
                { "name": "root", "services": ["api"], "restart_policy": "one_for_one" }
            ]
        },
        "observability": [{
            "name": "trace-ledger",
            "kind": "trace",
            "required_capabilities": {
                "cx_capabilities": ["trace"],
                "feature_flags": [],
                "resources": []
            }
        }],
        "compatibility": {
            "fail_closed_unknown_fields": true,
            "fail_closed_unknown_capabilities": true,
            "future_schema_requires_new_version": true
        }
    }))
    .expect("minimal-http-worker manifest deserializes")
}

/// A trivial, non-leaking child factory: a task that completes immediately, with
/// `Stop` restart so normal completion does not re-spawn.
fn completing_child(name: &str) -> ChildSpec {
    ChildSpec::new(
        name,
        |scope: &Scope<'static, FailFast>, state: &mut RuntimeState, _cx: &Cx| {
            let region = scope.region_id();
            let budget = scope.budget();
            let (task_id, _) = state.create_task(region, budget, async {})?;
            Ok(task_id)
        },
    )
    .with_restart(SupervisionStrategy::Stop)
}

/// Lower the manifest into a runnable builder `AppSpec`, one factory per work unit.
fn build_app() -> AppSpec {
    let manifest = minimal_http_worker_manifest();
    let names: Vec<String> = manifest
        .compiler_plan()
        .expect("plan compiles")
        .children
        .iter()
        .map(|child| child.name.clone())
        .collect();
    assert_eq!(
        names,
        vec!["api.route.health", "api.job.worker"],
        "single-group minimal topology lowers to a route and a background job"
    );
    manifest
        .compile_with_child_specs(names.iter().map(|name| completing_child(name)))
        .expect("single-group manifest lowers into a builder AppSpec")
}

/// Schedule the supervisor's started child tasks so the lab runtime runs them.
fn schedule_children(harness: &SporkAppHarness) {
    if let Some(app) = harness.app_handle() {
        let task_ids: Vec<_> = app.supervisor().started.iter().map(|c| c.task_id).collect();
        let mut sched = harness.runtime().scheduler.lock();
        for tid in task_ids {
            sched.schedule(tid, 0);
        }
    }
}

/// Run the minimal topology under a given seed, assert region-close quiescence
/// with no orphan tasks, and return the Foata-canonical trace fingerprint.
fn run_seed_to_quiescence(seed: u64) -> u64 {
    let harness = SporkAppHarness::with_seed(seed, build_app()).expect("harness starts the app");
    schedule_children(&harness);
    let report = harness.run_to_report().expect("app stops cleanly");

    assert!(
        report.run.quiescent,
        "seed {seed}: region close must reach quiescence"
    );
    assert!(
        report.run.oracle_report.all_passed(),
        "seed {seed}: no orphan tasks / obligation leaks, got {:?}",
        report.run.oracle_report.to_json()
    );
    assert!(
        report.run.invariant_violations.is_empty(),
        "seed {seed}: no runtime invariant violations, got {:?}",
        report.run.invariant_violations
    );
    report.run.trace_fingerprint
}

#[test]
fn minimal_topology_replays_to_quiescence_for_each_declared_seed() {
    for seed in [1_u64, 2, 3] {
        let _ = run_seed_to_quiescence(seed);
    }
}

#[test]
fn minimal_topology_replay_is_deterministic_per_seed() {
    let first = run_seed_to_quiescence(1);
    let second = run_seed_to_quiescence(1);
    assert_eq!(
        first, second,
        "same seed must produce an identical Foata-canonical trace fingerprint"
    );
}
