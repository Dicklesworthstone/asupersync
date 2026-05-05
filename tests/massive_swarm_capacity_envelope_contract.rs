#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const ARTIFACT_PATH: &str = "artifacts/wave2/massive_swarm_capacity_envelope_evidence.json";
const REGISTRY_PATH: &str = "artifacts/wave2_capability_evidence_registry_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_json(relative: &str) -> JsonValue {
    let path = repo_path(relative);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a serde_json::Map<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn optional_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bool_value(value: &JsonValue, key: &str) -> bool {
    value
        .get(key)
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_value(value: &JsonValue, key: &str) -> u64 {
    value
        .get(key)
        .and_then(JsonValue::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn f64_value(value: &JsonValue, key: &str) -> f64 {
    value
        .get(key)
        .and_then(JsonValue::as_f64)
        .unwrap_or_else(|| panic!("{key} must be a number"))
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn artifact() -> JsonValue {
    read_repo_json(ARTIFACT_PATH)
}

fn row_for_profile<'a>(artifact: &'a JsonValue, profile: &str) -> &'a JsonValue {
    array(artifact, "profile_matrix")
        .iter()
        .find(|row| row.get("profile").and_then(JsonValue::as_str) == Some(profile))
        .unwrap_or_else(|| panic!("missing profile row {profile}"))
}

fn registry_row_for_owner<'a>(registry: &'a JsonValue, owner: &str) -> &'a JsonValue {
    array(registry, "capability_rows")
        .iter()
        .find(|row| row.get("owner_bead_id").and_then(JsonValue::as_str) == Some(owner))
        .unwrap_or_else(|| panic!("missing registry row for {owner}"))
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-j1dwk6".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

#[test]
fn artifact_declares_truthful_schema_sources_and_required_logs() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("massive-swarm-capacity-envelope-evidence-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-j1dwk6")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("massive_swarm_capacity_envelope")
    );

    for path_key in ["runner_script", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).is_file(),
            "{path_key} path must exist: {path}"
        );
    }
    for source_path in array(&artifact, "source_evidence_paths") {
        let source_path = source_path.as_str().expect("source path string");
        assert!(
            repo_path(source_path).exists(),
            "source evidence path must exist: {source_path}"
        );
    }

    let expected_log_fields = [
        "bead_id",
        "scenario_id",
        "host_cpu_count",
        "host_memory_gib",
        "profile",
        "seed",
        "task_count",
        "region_count",
        "obligation_count",
        "worker_count",
        "numa_policy",
        "p50_us",
        "p95_us",
        "p99_us",
        "p999_us",
        "max_rss_bytes",
        "trace_bytes",
        "cancellation_drain_us",
        "fallback_reason",
        "no_win_reason",
        "unsupported_reason",
        "artifact_path",
        "verdict",
        "first_failure",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        string_set(&artifact, "required_log_fields"),
        expected_log_fields
    );

    let metric_policy = object(&artifact, "metric_policy");
    assert!(
        metric_policy
            .get("large_host_truthfulness")
            .and_then(JsonValue::as_str)
            .unwrap_or("missing large_host_truthfulness")
            .contains("never emit verdict=pass"),
        "metric policy must prevent fake large-host proof"
    );

    log_contract_event(
        "artifact-schema",
        &[
            (
                "source_evidence_paths",
                array(&artifact, "source_evidence_paths").len().to_string(),
            ),
            (
                "required_log_fields",
                array(&artifact, "required_log_fields").len().to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn profile_matrix_covers_fast_standard_and_large_host_without_collapsing_scope() {
    let artifact = artifact();
    let profiles = array(&artifact, "profile_matrix");
    let profile_ids = profiles
        .iter()
        .map(|row| string(row, "profile").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        profile_ids,
        ["fast", "standard", "large-host"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>()
    );

    for row in profiles {
        let profile = string(row, "profile");
        assert!(string(row, "scenario_id").starts_with("AA-MASSIVE-SWARM-CAPACITY-"));
        assert!(u64_value(row, "seed") > 0, "{profile}: seed");
        assert!(u64_value(row, "task_count") > 0, "{profile}: tasks");
        assert!(u64_value(row, "region_count") > 0, "{profile}: regions");
        assert!(
            u64_value(row, "obligation_count") >= u64_value(row, "task_count"),
            "{profile}: obligations should cover task effects"
        );
        assert!(u64_value(row, "worker_count") > 0, "{profile}: workers");
        assert!(
            u64_value(row, "p50_us") <= u64_value(row, "p95_us")
                && u64_value(row, "p95_us") <= u64_value(row, "p99_us")
                && u64_value(row, "p99_us") <= u64_value(row, "p999_us"),
            "{profile}: latency percentiles must be monotonic"
        );
        assert!(
            u64_value(row, "max_rss_bytes") > u64_value(row, "trace_bytes"),
            "{profile}: RSS envelope must dominate retained trace budget"
        );
        assert!(
            !array(row, "source_scenario_refs").is_empty(),
            "{profile}: profile must cite source scenario refs"
        );
        assert_eq!(
            string(row, "expected_supported_verdict"),
            "pass",
            "{profile}: supported profiles must pass"
        );
    }

    let fast = row_for_profile(&artifact, "fast");
    let standard = row_for_profile(&artifact, "standard");
    let large = row_for_profile(&artifact, "large-host");
    assert!(
        u64_value(fast, "task_count") < u64_value(standard, "task_count")
            && u64_value(standard, "task_count") < u64_value(large, "task_count"),
        "profiles must scale from CI to operator to large-host envelope"
    );
    assert!(
        !bool_value(fast, "requires_large_host")
            && !bool_value(standard, "requires_large_host")
            && bool_value(large, "requires_large_host")
    );

    log_contract_event(
        "profile-matrix",
        &[
            ("profiles", profiles.len().to_string()),
            (
                "large_host_task_count",
                u64_value(large, "task_count").to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn large_host_gate_and_no_win_sources_are_explicit() {
    let artifact = artifact();
    let host_shape = object(&artifact, "host_shape_requirement");
    assert_eq!(
        host_shape
            .get("large_host_min_cpu_count")
            .and_then(JsonValue::as_u64),
        Some(64)
    );
    assert_eq!(
        host_shape
            .get("large_host_min_memory_gib")
            .and_then(JsonValue::as_u64),
        Some(256)
    );
    assert!(
        host_shape
            .get("unsupported_skip_policy")
            .and_then(JsonValue::as_str)
            .unwrap_or("missing unsupported_skip_policy")
            .contains("verdict=skip")
    );

    let large = row_for_profile(&artifact, "large-host");
    let refs = string_set(large, "source_scenario_refs");
    for required in [
        "AA-CAPACITY-ENVELOPE-LOCALITY-CERT-64C-256G",
        "AA-CAPACITY-ENVELOPE-NO-WIN-64C-256G",
        "AA-ADAPTIVE-BATCH-SIZING-NO-WIN-64P",
        "AA-TRACE-STORAGE-LARGE-MEMORY-256G",
    ] {
        assert!(refs.contains(required), "large-host missing ref {required}");
    }
    assert!(
        optional_string(large, "no_win_reason").contains("refuses_640_agents"),
        "large-host profile must retain no-win behavior"
    );
    assert!(
        optional_string(large, "fallback_reason").contains("conservative_baseline"),
        "large-host profile must retain conservative fallback behavior"
    );

    let scenario_refs = array(&artifact, "existing_capacity_scenario_refs");
    let roles = scenario_refs
        .iter()
        .map(|row| string(row, "role").to_string())
        .collect::<BTreeSet<_>>();
    for role in [
        "64c_256g_certificate",
        "no_win_conservative_fallback",
        "stale_evidence_fallback",
        "under_sampled_fallback",
        "calibration_drift_fallback",
    ] {
        assert!(
            roles.contains(role),
            "missing capacity scenario role {role}"
        );
    }

    log_contract_event(
        "large-host-gate",
        &[
            ("source_refs", refs.len().to_string()),
            ("capacity_scenario_roles", roles.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn runner_emits_all_required_logs_and_truthful_large_host_skip() {
    let output_root = repo_path("target/massive-swarm-capacity-envelope-contract");
    let output = Command::new("bash")
        .arg(repo_path("scripts/run_massive_swarm_capacity_envelope.sh"))
        .arg("--output-root")
        .arg(&output_root)
        .arg("--profile")
        .arg("all")
        .arg("--run-id")
        .arg("contract")
        .output()
        .expect("run massive swarm capacity envelope script");
    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = output_root.join("run_contract/run_report.json");
    let log_path = output_root.join("run_contract/run.log");
    let report = serde_json::from_str::<JsonValue>(
        &std::fs::read_to_string(&report_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", report_path.display())),
    )
    .unwrap_or_else(|err| panic!("parse {}: {err}", report_path.display()));
    assert_eq!(
        report.get("schema_version").and_then(JsonValue::as_str),
        Some("massive-swarm-capacity-envelope-run-report-v1")
    );
    assert_eq!(
        report.get("validation_passed").and_then(JsonValue::as_bool),
        Some(true)
    );

    let required_fields = string_set(&report, "required_log_fields");
    let rows = array(&report, "log_rows");
    assert_eq!(rows.len(), 3, "runner must emit fast, standard, large-host");
    let log_body = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", log_path.display()));
    assert_eq!(log_body.lines().count(), 3, "run.log row count");

    for row in rows {
        let profile = string(row, "profile");
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "{profile}: missing required log field {field}"
            );
            assert!(
                log_body.contains(&format!("{field}=")),
                "run.log should include key {field}"
            );
        }
        assert!(u64_value(row, "p999_us") >= u64_value(row, "p99_us"));
        assert!(u64_value(row, "max_rss_bytes") > u64_value(row, "trace_bytes"));
        assert_eq!(
            optional_string(row, "artifact_path"),
            "target/massive-swarm-capacity-envelope-contract/run_contract/run_report.json"
        );
    }

    let large = rows
        .iter()
        .find(|row| row.get("profile").and_then(JsonValue::as_str) == Some("large-host"))
        .expect("large-host row");
    let host_cpu = u64_value(large, "host_cpu_count");
    let host_memory_gib = f64_value(large, "host_memory_gib");
    if host_cpu < 64 || host_memory_gib < 256.0 {
        assert_eq!(optional_string(large, "verdict"), "skip");
        assert_eq!(
            optional_string(large, "first_failure"),
            "host_shape_unsupported"
        );
        assert!(
            !optional_string(large, "unsupported_reason").is_empty(),
            "unsupported large-host run needs explicit reason"
        );
    } else {
        assert_eq!(optional_string(large, "verdict"), "pass");
        assert_eq!(optional_string(large, "unsupported_reason"), "");
        assert_eq!(optional_string(large, "first_failure"), "");
    }

    log_contract_event(
        "runner-logs",
        &[
            ("rows", rows.len().to_string()),
            ("host_cpu_count", host_cpu.to_string()),
            ("host_memory_gib", format!("{host_memory_gib:.2}")),
            (
                "large_host_verdict",
                optional_string(large, "verdict").to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn registry_promotes_massive_swarm_capacity_row_to_artifact_backed_evidence() {
    let registry = read_repo_json(REGISTRY_PATH);
    let row = registry_row_for_owner(&registry, "asupersync-j1dwk6");
    assert_eq!(
        string(row, "capability_id"),
        "massive_swarm_capacity_envelope"
    );
    assert_eq!(string(row, "promotion_state"), "promoted");
    assert_eq!(
        string(row, "support_class_after"),
        "artifact-contract-backed"
    );
    assert_eq!(
        optional_string(row, "unsupported_reason"),
        "",
        "promoted registry row must not carry a row-level unsupported reason"
    );
    assert!(
        optional_string(row, "fallback_target").contains("large-host"),
        "fallback target should mention large-host skip behavior"
    );

    let source_paths = string_set(row, "source_paths");
    for required in [
        ARTIFACT_PATH,
        "scripts/run_massive_swarm_capacity_envelope.sh",
        "tests/massive_swarm_capacity_envelope_contract.rs",
    ] {
        assert!(
            source_paths.contains(required),
            "registry source_paths missing {required}"
        );
    }

    let artifact_paths = string_set(row, "artifact_paths");
    assert!(
        artifact_paths.contains(ARTIFACT_PATH),
        "registry artifact_paths must include the new evidence artifact"
    );
    assert!(
        array(row, "planned_artifact_paths").is_empty(),
        "promoted row should have no planned artifact paths remaining"
    );

    let unit_commands = array(row, "unit_proof_commands")
        .iter()
        .map(|entry| entry.as_str().expect("unit command string"))
        .collect::<Vec<_>>();
    assert!(
        unit_commands
            .iter()
            .any(|command| command.contains("rch exec --")
                && command.contains("--test massive_swarm_capacity_envelope_contract")),
        "registry must contain an rch-backed unit proof command"
    );
    let e2e_commands = array(row, "e2e_proof_commands")
        .iter()
        .map(|entry| entry.as_str().expect("e2e command string"))
        .collect::<Vec<_>>();
    assert!(
        e2e_commands
            .iter()
            .any(|command| command.contains("scripts/run_massive_swarm_capacity_envelope.sh")),
        "registry must contain the new e2e runner"
    );

    log_contract_event(
        "registry-row",
        &[
            ("source_paths", source_paths.len().to_string()),
            ("artifact_paths", artifact_paths.len().to_string()),
            ("unit_commands", unit_commands.len().to_string()),
            ("e2e_commands", e2e_commands.len().to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
