//! Scenario-level crashpack attachment/linking contract tests (bd-1wen4).

use asupersync::app::AppSpec;
use asupersync::lab::{
    SporkAppHarness, SporkScenarioConfig, SporkScenarioRunner, SporkScenarioSpec,
};
use asupersync::record::ObligationKind;
use asupersync::supervision::ChildSpec;

fn leaking_child() -> ChildSpec {
    ChildSpec::new(
        "leaker",
        |scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
         state: &mut asupersync::runtime::RuntimeState,
         _cx: &asupersync::cx::Cx| {
            let region = scope.region_id();
            let budget = scope.budget();
            let (task_id, _) = state.create_task(region, budget, async {})?;
            state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task_id,
                    region,
                    Some("scenario leak".to_string()),
                )
                .expect("create leaked obligation");
            Ok(task_id)
        },
    )
}

#[test]
fn scenario_report_includes_deterministic_crashpack_linkage() {
    let mut runner = SporkScenarioRunner::new();
    let scenario = SporkScenarioSpec::new("crashpack.linking", |_| {
        AppSpec::new("crashpack_linking_app").child(leaking_child())
    })
    .with_description("intentionally leaks an obligation to force crashpack linkage")
    .with_default_config(SporkScenarioConfig {
        seed: 77,
        worker_count: 1,
        trace_capacity: 2048,
        max_steps: Some(50_000),
        panic_on_obligation_leak: false,
        panic_on_futurelock: false,
    });
    runner.register(scenario).expect("register scenario");

    let result_a = runner.run("crashpack.linking").expect("run scenario A");
    let result_b = runner.run("crashpack.linking").expect("run scenario B");
    assert!(!result_a.passed(), "leaking scenario should fail");

    let json_a = result_a.to_json();
    let json_b = result_b.to_json();
    assert_eq!(
        json_a["report"]["crashpack"], json_b["report"]["crashpack"],
        "crashpack linkage must be deterministic for same seed"
    );

    let crashpack = &json_a["report"]["crashpack"];
    assert!(crashpack.is_object(), "crashpack linkage must be present");

    let crashpack_path = crashpack["path"].as_str().expect("crashpack path string");
    let attachment_path = json_a["report"]["attachments"]
        .as_array()
        .expect("attachments array")
        .iter()
        .find(|entry| entry["kind"] == "crashpack")
        .and_then(|entry| entry["path"].as_str())
        .expect("crashpack attachment path");
    assert_eq!(crashpack_path, attachment_path);

    assert!(
        crashpack["id"]
            .as_str()
            .expect("crashpack id")
            .starts_with("crashpack-"),
        "crashpack id must have stable prefix"
    );
    assert_eq!(
        crashpack["fingerprint"], json_a["report"]["fingerprints"]["trace"],
        "link fingerprint must match report trace fingerprint"
    );

    let command_line = crashpack["replay"]["command_line"]
        .as_str()
        .expect("replay command line");
    assert!(
        command_line.contains("--crashpack"),
        "replay command must include crashpack flag"
    );
    assert!(
        command_line.contains(crashpack_path),
        "replay command must include crashpack path"
    );
}

#[test]
fn scenario_failure_builds_crashpack_with_manifest_and_divergent_prefix() {
    let config = SporkScenarioConfig {
        seed: 88,
        worker_count: 1,
        trace_capacity: 2048,
        max_steps: Some(50_000),
        panic_on_obligation_leak: false,
        panic_on_futurelock: false,
    };
    let app = AppSpec::new("crashpack_manifest_app").child(leaking_child());
    let mut harness = SporkAppHarness::new(config.to_lab_config(), app).expect("new harness");

    harness.run_until_idle();
    let run = harness.runtime_mut().report();
    let crashpack = harness
        .runtime()
        .build_crashpack_for_report(&run)
        .expect("failing scenario should produce crashpack");

    assert!(crashpack.manifest.is_compatible());
    assert!(crashpack.has_divergent_prefix());
    assert!(!crashpack.divergent_prefix.is_empty());
    assert!(
        crashpack
            .manifest
            .has_attachment(&asupersync::trace::crashpack::AttachmentKind::DivergentPrefix),
        "manifest should enumerate divergent prefix attachment"
    );

    harness
        .stop_app()
        .expect("stop app after crashpack capture");
}
