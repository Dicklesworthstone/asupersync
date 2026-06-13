#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/runtime_trace_inspector_visualization_v1.json";
const DOCS_PATH: &str = "docs/runtime_trace_inspector_visualization.md";
const TEST_PATH: &str = "tests/runtime_trace_inspector_visualization_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.9";
const INPUT_SCHEMA_ID: &str = "asupersync.runtime-trace-inspector-input.v1";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_runtime_trace_inspector_visualization";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

fn assert_remote_required_cargo_command(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    for required in [
        TARGET_DIR,
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "cargo test -p asupersync --test runtime_trace_inspector_visualization_contract",
        "--no-default-features",
        "-- --nocapture",
    ] {
        assert!(
            command.contains(required),
            "proof command missing {required}: {command}"
        );
    }
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "local fallback",
        "executing locally",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

fn render_contract_html(artifact: &Value) -> String {
    let renderer = object(artifact, "static_html_renderer");
    let root_id = string(renderer, "root_dom_id");
    let redaction = object(artifact, "redaction_profile");
    let policy_id = string(redaction, "policy_id");

    let mut html = format!("<main id=\"{root_id}\" data-schema=\"{INPUT_SCHEMA_ID}\">");
    for id in array(renderer, "required_dom_ids") {
        let id = id.as_str().expect("dom id string");
        let label = id.replace('-', " ");
        if id == "redaction-status" {
            html.push_str(&format!(
                "<section id=\"{id}\" data-policy=\"{policy_id}\"></section>"
            ));
        } else if id == "no-claim-boundaries" {
            html.push_str(&format!(
                "<section id=\"{id}\" aria-label=\"No-claim boundaries\"></section>"
            ));
        } else if id == "trace-timeline" {
            html.push_str(
                "<section id=\"trace-timeline\" aria-label=\"Trace timeline\"></section>",
            );
        } else if id == "task-state-table" {
            html.push_str("<section id=\"task-state-table\" aria-label=\"Task states\"></section>");
        } else {
            html.push_str(&format!(
                "<section id=\"{id}\" aria-label=\"{label}\"></section>"
            ));
        }
    }
    for class_name in array(renderer, "required_css_classes") {
        let class_name = class_name.as_str().expect("css class string");
        html.push_str(&format!("<span class=\"{class_name}\"></span>"));
    }
    html.push_str("</main>");
    html
}

#[test]
fn artifact_docs_and_remote_validation_are_wired() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("runtime-trace-inspector-visualization-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        artifact.get("artifact_path").and_then(Value::as_str),
        Some(ARTIFACT_PATH)
    );
    assert_eq!(
        artifact.get("docs_path").and_then(Value::as_str),
        Some(DOCS_PATH)
    );
    assert_eq!(
        artifact.get("contract_test").and_then(Value::as_str),
        Some(TEST_PATH)
    );

    for path in array(&artifact, "source_paths") {
        assert_live_path(path.as_str().expect("source path string"));
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(ARTIFACT_PATH), "docs must link artifact");
    assert!(docs.contains(BEAD_ID), "docs must link bead");
    for marker in array(&artifact, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = object(&artifact, "validation");
    assert_remote_required_cargo_command(string(validation, "rch_command"));
    assert!(bool_field(validation, "no_local_cargo_fallback"));
}

#[test]
fn input_schema_covers_trace_inspector_scheduler_and_evidence_inputs() {
    let artifact = artifact();
    let input_schema = object(&artifact, "input_schema");
    assert_eq!(
        input_schema.get("schema_id").and_then(Value::as_str),
        Some(INPUT_SCHEMA_ID)
    );
    assert!(
        string(input_schema, "ordering_policy").contains("logical_time_nanos"),
        "ordering policy must use logical time"
    );
    assert!(
        string(input_schema, "clock_policy").contains("cannot reorder"),
        "wall clock must not reorder visual rows"
    );

    let required = string_set(&artifact, "required_input_ids");
    let inputs = array(input_schema, "inputs");
    assert_eq!(inputs.len(), required.len());

    let mut actual = BTreeSet::new();
    for input in inputs {
        let input_id = string(input, "input_id");
        actual.insert(input_id.to_owned());
        assert!(
            !array(input, "required_fields").is_empty(),
            "{input_id} must define required fields"
        );
        assert!(
            !array(input, "visual_channels").is_empty(),
            "{input_id} must define visual channels"
        );
        assert!(
            string(input, "failure_policy").contains("block")
                || string(input, "failure_policy").contains("demotes"),
            "{input_id} must define fail-closed behavior"
        );
        for path in array(input, "source_paths") {
            assert_live_path(path.as_str().expect("input source path"));
        }
    }

    assert_eq!(actual, required);
}

#[test]
fn static_html_renderer_has_stable_dom_and_golden_fragments() {
    let artifact = artifact();
    let renderer = object(&artifact, "static_html_renderer");
    assert_eq!(
        renderer.get("renderer_id").and_then(Value::as_str),
        Some("runtime-trace-inspector-static-html-contract")
    );
    assert_eq!(
        renderer.get("surface").and_then(Value::as_str),
        Some("static-html")
    );
    assert!(
        string(renderer, "support_class").contains("not production dashboard"),
        "renderer support class must prevent overclaiming"
    );

    let required_dom_ids = string_set(renderer, "required_dom_ids");
    for id in [
        "trace-timeline",
        "region-tree",
        "task-state-table",
        "obligation-holdings",
        "cancel-propagation",
        "scheduler-lanes",
        "evidence-links",
        "redaction-status",
        "no-claim-boundaries",
    ] {
        assert!(required_dom_ids.contains(id), "missing DOM id {id}");
    }

    let html = render_contract_html(&artifact);
    for fragment in array(renderer, "golden_dom_fragments") {
        let fragment = fragment.as_str().expect("golden fragment string");
        assert!(html.contains(fragment), "rendered HTML missing {fragment}");
    }
    for class_name in array(renderer, "required_css_classes") {
        let class_name = class_name.as_str().expect("css class string");
        assert!(
            html.contains(&format!("class=\"{class_name}\"")),
            "rendered HTML missing class {class_name}"
        );
    }
    assert!(
        string(renderer, "dom_test_policy").contains("screenshots are deferred"),
        "screenshot deferral must be explicit"
    );
}

#[test]
fn redaction_profile_blocks_sensitive_trace_payloads() {
    let artifact = artifact();
    let redaction = object(&artifact, "redaction_profile");
    assert_eq!(
        redaction.get("policy_id").and_then(Value::as_str),
        Some("runtime-trace-inspector-redaction-v1")
    );
    assert_eq!(
        redaction.get("source_redactor").and_then(Value::as_str),
        Some("redact_browser_trace_event")
    );
    for path in array(redaction, "source_paths") {
        assert_live_path(path.as_str().expect("redaction source path"));
    }

    let preserve = string_set(redaction, "preserve_fields");
    for field in ["TaskId", "RegionId", "ObligationId", "logical_time_nanos"] {
        assert!(
            preserve.contains(field),
            "must preserve structural field {field}"
        );
    }

    let forbidden = string_set(redaction, "forbidden_fields");
    for field in [
        "panic message payload",
        "cancel reason free text",
        "worker id free text",
        "message body",
        "secrets, tokens, credentials, or API keys",
    ] {
        assert!(forbidden.contains(field), "must forbid {field}");
    }

    assert!(
        string(redaction, "failure_policy").contains("blocked redaction panel"),
        "redaction failure must block rendering"
    );

    for fixture in array(&artifact, "fail_closed_fixtures") {
        assert_eq!(
            fixture.get("expected_verdict").and_then(Value::as_str),
            Some("blocked")
        );
        assert!(
            string(fixture, "expected_reason").contains("reject")
                || string(fixture, "expected_reason").contains("blocked"),
            "fixture must fail closed"
        );
    }
}

#[test]
fn proof_lane_and_no_claims_prevent_visualization_overclaiming() {
    let artifact = artifact();
    let lanes = array(&artifact, "proof_lanes");
    assert_eq!(lanes.len(), 1);
    let lane = &lanes[0];
    assert_eq!(
        lane.get("lane_id").and_then(Value::as_str),
        Some("runtime-trace-inspector-visualization-contract")
    );
    assert_remote_required_cargo_command(string(lane, "command"));
    assert!(bool_field(lane, "no_local_cargo_fallback"));
    assert!(
        array(lane, "does_not_cover")
            .iter()
            .any(|item| item.as_str() == Some("production debug-server route")),
        "lane must not claim production debug-server route"
    );

    let no_claims = array(&artifact, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim string"))
        .collect::<Vec<_>>();
    for required in [
        "does not implement a production debug-server route",
        "does not provide browser screenshot coverage",
        "does not prove runtime correctness",
        "does not prove trace correctness",
        "does not prove scheduler correctness",
        "does not prove broad workspace health",
        "does not authorize local Cargo fallback",
    ] {
        assert!(no_claims.contains(&required), "missing no-claim {required}");
    }
}
