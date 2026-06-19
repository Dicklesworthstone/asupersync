//! Production reference AppSpec journey (bead asupersync-idea-wizard-fifth-wave-3gaiun.2.4 / [APPSPEC][A4]).
//!
//! A runnable, inspectable end-to-end journey a new user can read top to bottom
//! to see why AppSpec beats ad-hoc wiring **without hiding `Cx` or region
//! semantics**. It declares a single-service topology with the full surface:
//!
//! * an HTTP route (`GET /health`) and an ingest route (`POST /enqueue`);
//! * a startup background worker plus a bounded-queue drainer job (the bounded
//!   queue is expressed as the `ingest_queue` budget's `poll_quota` depth);
//! * a named resource (`public_socket`) and per-unit + per-service budgets;
//! * a latency SLO policy hook;
//! * a structured trace observability sink;
//! * a supervision group with an explicit restart policy (graceful shutdown via
//!   region close).
//!
//! It then runs the lowered topology through the deterministic lab runtime for
//! each declared seed, proves **region-close quiescence with no orphan tasks**
//! and **deterministic replay** (identical Foata-canonical trace fingerprint),
//! rehearses a **fail-closed** path (a multi-group topology the A2 lowering does
//! not support is rejected, not silently mis-wired), and emits the e2e
//! artifacts: an `events.ndjson` stream of structured lifecycle events and a
//! `summary.json` aggregate.
//!
//! The journey factories are caller-supplied `ChildSpec`s that create tasks via
//! `state.create_task(region, budget, ..)` — the region and budget come from the
//! `Scope`, so `Cx`/region ownership stays explicit and visible.
//!
//! Run it:
//!   cargo run --example appspec_reference_journey
//!
//! Remote-required RCH validation:
//!   RCH_REQUIRE_REMOTE=1 rch exec -- cargo run --example appspec_reference_journey
//!
//! Scope note: this exercises the **single-supervision-group** lowering the A2
//! compiler implements. Per-unit handler symbol resolution and multi-group
//! sub-supervisor lowering remain out of scope (and the latter is rehearsed here
//! precisely to show it fails closed). No broad runtime-correctness claim is made
//! beyond the asserted quiescence/determinism of this topology.

use asupersync::app::{AppSpec, AppSpecV1};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::SporkAppHarness;
use asupersync::runtime::RuntimeState;
use asupersync::supervision::{ChildSpec, SupervisionStrategy};
use asupersync::types::policy::FailFast;
use serde_json::{Value, json};

/// The production reference topology, lowered as a single supervision group.
fn reference_manifest() -> AppSpecV1 {
    serde_json::from_value(json!({
        "schema_version": "asupersync.appspec.v1",
        "name": "reference-journey",
        "services": [{
            "name": "api",
            "routes": [
                {
                    "name": "health",
                    "method": "GET",
                    "path": "/health",
                    "handler": "reference_journey::health",
                    "required_capabilities": {
                        "cx_capabilities": ["net", "trace"],
                        "feature_flags": ["native-runtime"],
                        "resources": ["public_socket"]
                    },
                    "budget": "api_request"
                },
                {
                    "name": "enqueue",
                    "method": "POST",
                    "path": "/enqueue",
                    "handler": "reference_journey::enqueue",
                    "required_capabilities": {
                        "cx_capabilities": ["net", "trace"],
                        "feature_flags": ["native-runtime"],
                        "resources": ["public_socket"]
                    },
                    "budget": "api_request"
                }
            ],
            "actors": [],
            "background_jobs": [
                {
                    "name": "worker",
                    "entrypoint": "reference_journey::worker",
                    "trigger": "startup",
                    "required_capabilities": {
                        "cx_capabilities": ["trace"],
                        "feature_flags": [],
                        "resources": []
                    },
                    "budget": "worker_batch"
                },
                {
                    "name": "queue_drainer",
                    "entrypoint": "reference_journey::drain_queue",
                    "trigger": "startup",
                    "required_capabilities": {
                        "cx_capabilities": ["trace"],
                        "feature_flags": [],
                        "resources": []
                    },
                    "budget": "ingest_queue"
                }
            ],
            "resources": ["public_socket"],
            "budget": "worker_batch"
        }],
        "resources": [
            { "name": "public_socket", "kind": "socket", "capability": "net" }
        ],
        "budgets": [
            { "name": "api_request", "poll_quota": 1000 },
            { "name": "worker_batch", "deadline_ms": 5000 },
            { "name": "ingest_queue", "poll_quota": 256 }
        ],
        "slo_hooks": [
            { "name": "request_latency_p50", "kind": "latency", "target": "api.route.health", "budget": "api_request" }
        ],
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
    .expect("reference-journey manifest deserializes")
}

/// A multi-group variant the single-group A2 lowering must reject (fail-closed
/// rehearsal). It is a valid manifest (validation passes, `compiler_plan`
/// succeeds), but `compile_with_child_specs` refuses to invent a runtime mapping
/// for more than one supervision group.
fn multi_group_manifest() -> AppSpecV1 {
    serde_json::from_value(json!({
        "schema_version": "asupersync.appspec.v1",
        "name": "reference-journey-multi-group",
        "services": [
            {
                "name": "api",
                "routes": [{
                    "name": "health",
                    "method": "GET",
                    "path": "/health",
                    "handler": "reference_journey::health",
                    "required_capabilities": {
                        "cx_capabilities": ["net", "trace"],
                        "feature_flags": ["native-runtime"],
                        "resources": ["public_socket"]
                    },
                    "budget": "api_request"
                }],
                "actors": [],
                "background_jobs": [],
                "resources": ["public_socket"],
                "budget": "api_request"
            },
            {
                "name": "ingest",
                "routes": [],
                "actors": [],
                "background_jobs": [{
                    "name": "intake",
                    "entrypoint": "reference_journey::intake",
                    "trigger": "startup",
                    "required_capabilities": {
                        "cx_capabilities": ["trace"],
                        "feature_flags": [],
                        "resources": []
                    },
                    "budget": "worker_batch"
                }],
                "resources": [],
                "budget": "worker_batch"
            }
        ],
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
                { "name": "root", "services": ["api"], "restart_policy": "one_for_one" },
                { "name": "ingest_grp", "services": ["ingest"], "restart_policy": "one_for_one" }
            ]
        },
        "observability": [],
        "compatibility": {
            "fail_closed_unknown_fields": true,
            "fail_closed_unknown_capabilities": true,
            "future_schema_requires_new_version": true
        }
    }))
    .expect("multi-group manifest deserializes")
}

/// A non-leaking child factory: a task that completes immediately under a `Stop`
/// restart policy so normal completion does not re-spawn. The region and budget
/// come from the `Scope`, keeping `Cx`/region ownership explicit.
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

/// Lower the reference manifest into a runnable builder `AppSpec`, one factory
/// per compiled work unit (names taken from the compiler plan).
fn build_app() -> (AppSpec, Vec<String>) {
    let manifest = reference_manifest();
    let names: Vec<String> = manifest
        .compiler_plan()
        .expect("reference manifest compiles")
        .children
        .iter()
        .map(|child| child.name.clone())
        .collect();
    let app = manifest
        .compile_with_child_specs(names.iter().map(|name| completing_child(name)))
        .expect("single-group reference manifest lowers into a builder AppSpec");
    (app, names)
}

/// Schedule the supervisor's started child tasks so the lab runtime runs them.
/// (The harness starts but does not auto-schedule started children.)
fn schedule_children(harness: &SporkAppHarness) {
    if let Some(app) = harness.app_handle() {
        let task_ids: Vec<_> = app.supervisor().started.iter().map(|c| c.task_id).collect();
        let mut sched = harness.runtime().scheduler.lock();
        for tid in task_ids {
            sched.schedule(tid, 0);
        }
    }
}

/// Run the reference topology under a seed, assert region-close quiescence with
/// no orphan tasks / invariant violations, and return the trace fingerprint.
fn run_seed_to_quiescence(seed: u64) -> u64 {
    let (app, _) = build_app();
    let harness = SporkAppHarness::with_seed(seed, app).expect("harness starts the app");
    schedule_children(&harness);
    let report = harness.run_to_report().expect("app stops cleanly");

    assert!(
        report.run.quiescent,
        "seed {seed}: region close must reach quiescence",
    );
    assert!(
        report.run.oracle_report.all_passed(),
        "seed {seed}: no orphan tasks / obligation leaks, got {:?}",
        report.run.oracle_report.to_json(),
    );
    assert!(
        report.run.invariant_violations.is_empty(),
        "seed {seed}: no runtime invariant violations, got {:?}",
        report.run.invariant_violations,
    );
    report.run.trace_fingerprint
}

fn main() {
    let seeds = [1_u64, 2, 3];
    let mut events: Vec<Value> = Vec::new();

    // 1. Compile the declarative manifest into a deterministic plan.
    let manifest = reference_manifest();
    let plan = manifest
        .compiler_plan()
        .expect("reference manifest compiles");
    let lowered: Vec<String> = plan.children.iter().map(|c| c.name.clone()).collect();
    let topology = manifest.topology_report().expect("topology report renders");
    events.push(json!({
        "event": "manifest_compiled",
        "app": plan.app_name,
        "lowered_children": lowered,
        "observability_sinks": plan.observability_sinks.len(),
        "budgets": plan.budgets.len(),
    }));

    // 2. Run the lowered topology to region-close quiescence per seed.
    let mut fingerprints: Vec<u64> = Vec::new();
    for seed in seeds {
        let fingerprint = run_seed_to_quiescence(seed);
        fingerprints.push(fingerprint);
        events.push(json!({
            "event": "seed_run",
            "seed": seed,
            "quiescent": true,
            "orphan_tasks": 0,
            "trace_fingerprint": fingerprint,
        }));
    }

    // 3. Deterministic replay: same seed → identical Foata-canonical fingerprint.
    let replay = run_seed_to_quiescence(seeds[0]);
    let deterministic = replay == fingerprints[0];
    assert!(
        deterministic,
        "seed {} replay must produce an identical trace fingerprint",
        seeds[0],
    );
    events.push(json!({
        "event": "replay_verified",
        "seed": seeds[0],
        "deterministic": deterministic,
        "trace_fingerprint": replay,
    }));

    // 4. Failure rehearsal: a multi-group topology fails closed at lowering
    //    instead of being silently mis-wired.
    let rehearsal = multi_group_manifest().compile_with_child_specs(std::iter::empty());
    let rehearsal_error =
        rehearsal.expect_err("multi-group topology must fail closed at builder lowering");
    events.push(json!({
        "event": "failure_rehearsal",
        "scenario": "multi_group_topology",
        "outcome": "fail_closed",
        "error": format!("{rehearsal_error}"),
    }));

    // Emit the e2e artifacts. events.ndjson is the structured-log stream;
    // summary.json is the aggregate a CI gate or human can diff.
    let summary = json!({
        "app": plan.app_name,
        "lowered_children": lowered,
        "seeds": seeds,
        "trace_fingerprints": fingerprints,
        "deterministic_replay": deterministic,
        "quiescent": true,
        "orphan_tasks": 0,
        "failure_rehearsal": "multi_group_topology=fail_closed",
        "ergonomics": {
            "declarative_manifest_lines": "~95 JSON lines declare the full topology",
            "imperative_wiring_avoided": "no hand-rolled supervisor tree, budget plumbing, or shutdown ordering",
        },
    });

    println!("# events.ndjson");
    for event in &events {
        println!(
            "{}",
            serde_json::to_string(event).expect("event serializes")
        );
    }
    println!("# summary.json");
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).expect("summary serializes"),
    );
    println!("# topology.txt");
    println!("{topology}");
    eprintln!(
        "appspec reference journey OK: {} seeds quiescent, deterministic replay={}, fail-closed rehearsal verified",
        seeds.len(),
        deterministic,
    );
}
