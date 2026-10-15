//! AppSpec v1 compiler contract (3gaiun.2.2 / [APPSPEC][A2]).
//!
//! These integration tests link the library in non-test mode (immune to peer
//! `#[cfg(test)]` breakage) and prove the A2 compiler acceptance criteria:
//!
//! 1. A minimal single-service manifest lowers, via `compile_with_child_specs`,
//!    into a runnable builder `AppSpec`, is started under the lab runtime, and
//!    reaches **region-close quiescence with no orphan tasks** after `stop`.
//! 2. Invalid-capability manifests **fail closed** (ambient authority rejected;
//!    unknown capability strings rejected at the serde boundary).
//! 3. The multi-group runtime-mapping boundary is **explicit and fail-closed**.
//! 4. Missing / duplicate / unexpected child factories **fail closed**.
//! 5. The generated topology renders **deterministically** for docs/artifacts.
//!
//! No broad runtime-correctness claim is made: these tests cover the AppSpec v1
//! compiler/lowering surface only.

use asupersync::app::{AppSpecV1, AppSpecV1CompileError, AppSpecV1ValidationError};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{SporkAppHarness, SporkScenarioConfig};
use asupersync::runtime::RuntimeState;
use asupersync::supervision::{ChildSpec, SupervisionStrategy};
use asupersync::types::policy::FailFast;
use serde_json::{Value, json};

/// A minimal but complete, valid manifest: one service with one route, one
/// actor, and one background job, supervised by a single `one_for_one` group.
fn minimal_manifest_json() -> Value {
    json!({
        "schema_version": "asupersync.appspec.v1",
        "name": "demo",
        "services": [{
            "name": "api",
            "routes": [{
                "name": "ping",
                "method": "GET",
                "path": "/ping",
                "handler": "demo::ping",
                "required_capabilities": {
                    "cx_capabilities": ["net", "trace"],
                    "feature_flags": ["native-runtime"],
                    "resources": ["public_socket"]
                },
                "budget": "request",
                "slo_hook": "ping_latency"
            }],
            "actors": [{
                "name": "warmer",
                "entrypoint": "demo::warmer",
                "required_capabilities": {
                    "cx_capabilities": ["spawn", "time"],
                    "feature_flags": [],
                    "resources": []
                },
                "budget": "background"
            }],
            "background_jobs": [{
                "name": "tick",
                "entrypoint": "demo::tick",
                "trigger": { "interval": { "every_ms": 1000 } },
                "required_capabilities": {
                    "cx_capabilities": ["time"],
                    "feature_flags": [],
                    "resources": ["timer"]
                },
                "budget": "background",
                "slo_hook": "ping_latency"
            }],
            "resources": ["public_socket", "timer"],
            "budget": "background"
        }],
        "resources": [
            { "name": "public_socket", "kind": "socket", "capability": "net" },
            { "name": "timer", "kind": "timer", "capability": "time" }
        ],
        "budgets": [
            { "name": "request", "poll_quota": 1000 },
            { "name": "background", "deadline_ms": 5000 }
        ],
        "slo_hooks": [
            { "name": "ping_latency", "kind": "latency", "target": "api.route.ping" }
        ],
        "supervision": {
            "root_group": "core",
            "groups": [
                { "name": "core", "services": ["api"], "restart_policy": "one_for_one" }
            ]
        },
        "observability": [{
            "name": "metrics",
            "kind": "metrics",
            "required_capabilities": {
                "cx_capabilities": ["trace"],
                "feature_flags": ["metrics"],
                "resources": []
            }
        }],
        "compatibility": {
            "fail_closed_unknown_fields": true,
            "fail_closed_unknown_capabilities": true,
            "future_schema_requires_new_version": true
        }
    })
}

fn parse_manifest(value: Value) -> AppSpecV1 {
    serde_json::from_value(value).expect("manifest deserializes")
}

/// A trivial, non-leaking child factory: spawns a task that completes
/// immediately. `Stop` restart so normal completion does not re-spawn.
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

/// Schedule the supervisor's started child tasks so the lab runtime runs them.
///
/// The harness starts the app but does not auto-schedule the root child tasks;
/// the conformance harness does this explicitly, so we mirror it here.
fn schedule_children(harness: &SporkAppHarness) {
    if let Some(app) = harness.app_handle() {
        let task_ids: Vec<_> = app.supervisor().started.iter().map(|c| c.task_id).collect();
        let mut sched = harness.runtime().scheduler.lock();
        for tid in task_ids {
            sched.schedule(tid, 0);
        }
    }
}

#[test]
fn minimal_manifest_compiles_starts_and_reaches_region_close_quiescence() {
    let manifest = parse_manifest(minimal_manifest_json());

    // The compiler plan names exactly the work units the caller must supply.
    let plan = manifest.compiler_plan().expect("minimal plan compiles");
    let names: Vec<&str> = plan.children.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["api.route.ping", "api.actor.warmer", "api.job.tick"],
        "compiler plan enumerates route/actor/job work units in deterministic order"
    );

    // Lower into the builder AppSpec with one explicit factory per work unit.
    let app = manifest
        .compile_with_child_specs(names.iter().map(|name| completing_child(name)))
        .expect("minimal manifest lowers into a builder AppSpec");

    // Drive the full lifecycle: quiesce -> stop -> quiesce -> report.
    let harness = SporkAppHarness::new(SporkScenarioConfig::default().to_lab_config(), app)
        .expect("harness starts the compiled app");
    schedule_children(&harness);
    let report = harness.run_to_report().expect("app stops cleanly");

    assert!(
        report.run.quiescent,
        "region close must reach quiescence (no runnable tasks / pending timers)"
    );
    assert!(
        report.run.oracle_report.all_passed(),
        "no orphan tasks / obligation leaks: oracle report must pass, got {:?}",
        report.run.oracle_report.to_json()
    );
    assert!(
        report.run.invariant_violations.is_empty(),
        "no runtime invariant violations, got {:?}",
        report.run.invariant_violations
    );
    assert!(
        report.passed(),
        "compiled-app spork report must pass overall"
    );
}

#[test]
fn ambient_authority_route_fails_closed() {
    // A route that declares no Cx capabilities hides ambient authority.
    let mut value = minimal_manifest_json();
    value["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"] = json!([]);
    let manifest = parse_manifest(value);

    let err = manifest
        .compiler_plan()
        .expect_err("ambient-authority route must fail closed");
    match err {
        AppSpecV1CompileError::Validation(AppSpecV1ValidationError::AmbientAuthority { owner }) => {
            assert!(
                owner.contains("route.ping"),
                "diagnostic must name the offending route, got {owner:?}"
            );
        }
        other => panic!("expected AmbientAuthority validation error, got {other:?}"),
    }
}

#[test]
fn unknown_capability_token_fails_closed_at_serde() {
    // An undeclared capability family must be rejected at the parse boundary.
    let mut value = minimal_manifest_json();
    value["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"] =
        json!(["net", "telepathy"]);
    let parsed: Result<AppSpecV1, _> = serde_json::from_value(value);
    assert!(
        parsed.is_err(),
        "unknown capability token must be rejected by serde (fail closed)"
    );
}

#[test]
fn pure_capability_with_effects_fails_closed() {
    // `pure` combined with any other authority is contradictory.
    let mut value = minimal_manifest_json();
    value["services"][0]["routes"][0]["required_capabilities"]["cx_capabilities"] =
        json!(["pure", "net"]);
    let manifest = parse_manifest(value);
    match manifest.compiler_plan() {
        Err(AppSpecV1CompileError::Validation(
            AppSpecV1ValidationError::PureAuthorityHasEffects { .. },
        )) => {}
        other => panic!("expected PureAuthorityHasEffects, got {other:?}"),
    }
}

#[test]
fn multi_group_lowering_boundary_is_explicit_and_fail_closed() {
    // Two supervision groups: the pure compiler plan supports it, but the
    // builder-AppSpec lowering refuses it with a stable diagnostic instead of
    // silently flattening the restart boundary.
    let mut value = minimal_manifest_json();
    value["services"] = json!([
        {
            "name": "api",
            "routes": [{
                "name": "ping",
                "method": "GET",
                "path": "/ping",
                "handler": "demo::ping",
                "required_capabilities": {
                    "cx_capabilities": ["net"], "feature_flags": [], "resources": []
                }
            }],
            "actors": [],
            "background_jobs": [],
            "resources": []
        },
        {
            "name": "workers",
            "routes": [],
            "actors": [{
                "name": "cruncher",
                "entrypoint": "demo::cruncher",
                "required_capabilities": {
                    "cx_capabilities": ["spawn"], "feature_flags": [], "resources": []
                }
            }],
            "background_jobs": [],
            "resources": []
        }
    ]);
    value["supervision"] = json!({
        "root_group": "core",
        "groups": [
            { "name": "core", "services": ["api"], "restart_policy": "one_for_one" },
            { "name": "batch", "services": ["workers"], "restart_policy": "one_for_all" }
        ]
    });
    let manifest = parse_manifest(value);

    // Plan is valid and renders both groups.
    let plan = manifest.compiler_plan().expect("multi-group plan is valid");
    assert_eq!(plan.service_groups.len(), 2);
    let report = plan.topology_report();
    assert!(report.contains("group core (one_for_one)"));
    assert!(report.contains("group batch (one_for_all)"));

    // Lowering to the single-group builder fails closed.
    match manifest.compile_with_child_specs([completing_child("api.route.ping")]) {
        Err(AppSpecV1CompileError::UnsupportedRuntimeMapping { reason }) => {
            assert!(reason.contains("one supervision group"));
        }
        other => panic!("expected UnsupportedRuntimeMapping, got {other:?}"),
    }
}

#[test]
fn missing_duplicate_and_unexpected_child_factories_fail_closed() {
    // Missing: supply only one of the three required factories.
    let manifest = parse_manifest(minimal_manifest_json());
    match manifest.compile_with_child_specs([completing_child("api.route.ping")]) {
        Err(AppSpecV1CompileError::MissingChildSpec { name }) => {
            assert!(name == "api.actor.warmer" || name == "api.job.tick");
        }
        other => panic!("expected MissingChildSpec, got {other:?}"),
    }

    // Duplicate: two factories with the same name.
    let manifest = parse_manifest(minimal_manifest_json());
    match manifest.compile_with_child_specs([
        completing_child("api.route.ping"),
        completing_child("api.route.ping"),
    ]) {
        Err(AppSpecV1CompileError::DuplicateChildSpec { name }) => {
            assert_eq!(name, "api.route.ping");
        }
        other => panic!("expected DuplicateChildSpec, got {other:?}"),
    }

    // Unexpected: a factory no work unit needs.
    let manifest = parse_manifest(minimal_manifest_json());
    match manifest.compile_with_child_specs([
        completing_child("api.route.ping"),
        completing_child("api.actor.warmer"),
        completing_child("api.job.tick"),
        completing_child("api.route.ghost"),
    ]) {
        Err(AppSpecV1CompileError::UnexpectedChildSpec { name }) => {
            assert_eq!(name, "api.route.ghost");
        }
        other => panic!("expected UnexpectedChildSpec, got {other:?}"),
    }
}

#[test]
fn topology_report_is_deterministic_and_complete() {
    let manifest = parse_manifest(minimal_manifest_json());
    let first = manifest.topology_report().expect("report renders");
    let second = manifest.topology_report().expect("report renders again");
    assert_eq!(first, second, "topology report must be byte-stable");

    // Content contract: header, supervision tree, work units with full detail,
    // observability sinks, and no-claim boundaries.
    assert!(first.starts_with("# AppSpec v1 generated topology\n"));
    assert!(first.contains("app: demo\n"));
    assert!(first.contains("root_group: core (one_for_one)\n"));
    assert!(first.contains("budgets: request, background\n"));
    assert!(first.contains("  group core (one_for_one)\n"));
    assert!(first.contains("    service api\n"));
    assert!(first.contains(
        "      route  api.route.ping  GET /ping -> demo::ping  budget=request  slo=ping_latency  \
         caps=cx:net,trace|feat:native-runtime|res:public_socket\n"
    ));
    assert!(first.contains(
        "      actor  api.actor.warmer  -> demo::warmer  budget=background  caps=cx:spawn,time\n"
    ));
    assert!(first.contains(
        "      job    api.job.tick  trigger=interval(every_ms=1000) -> demo::tick  \
         budget=background  slo=ping_latency  caps=cx:time|res:timer\n"
    ));
    assert!(first.contains("  sink metrics (metrics)  caps=cx:trace|feat:metrics\n"));
    assert!(first.contains("no-claim boundaries:\n"));
    assert!(first.contains("  - Does not resolve handler symbols into Rust functions.\n"));
}
