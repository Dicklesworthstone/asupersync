//! Contract test for mock-code-finder stale audit normalization artifacts.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

fn repo_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn json_file(path: &str) -> Value {
    let text = fs::read_to_string(repo_path(path)).expect("read json artifact");
    serde_json::from_str(&text).expect("parse json artifact")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array field {key}"))
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

#[test]
fn stale_audit_normalization_contract_names_each_module() {
    let contract = json_file("artifacts/mock_code_finder_stale_audit_normalization_v1.json");
    assert_eq!(str_field(&contract, "bead_id"), "asupersync-dq4");
    assert_eq!(
        str_field(&contract, "schema_version"),
        "mock-code-finder-evidence-jsonl-schema-v1"
    );

    let scenarios = array(&contract, "required_scenarios");
    assert_eq!(scenarios.len(), 6);

    let mut ids = BTreeSet::new();
    for scenario in scenarios {
        let id = str_field(scenario, "scenario_id");
        assert!(ids.insert(id.to_string()), "duplicate scenario id {id}");

        let module = str_field(scenario, "module");
        assert!(
            repo_path(module).exists(),
            "normalization module must exist: {module}"
        );
        let cargo_features = array(scenario, "cargo_features");
        assert!(
            !cargo_features.is_empty(),
            "scenario {id} must list cargo features required for proof"
        );
        let proof_commands = array(scenario, "proof_commands");
        assert!(
            !proof_commands.is_empty(),
            "scenario {id} must list proof commands"
        );
        for command in proof_commands {
            let command = command
                .as_str()
                .unwrap_or_else(|| panic!("proof command for {id} must be a string"));
            assert!(
                command.starts_with("rch exec -- "),
                "proof command for {id} must run through rch: {command}"
            );
        }

        let outcome = str_field(scenario, "outcome");
        assert!(
            matches!(
                outcome,
                "production-backed executable assertion"
                    | "linked blocker for still-real gap"
                    | "truthful historical note"
            ),
            "unexpected outcome for {id}: {outcome}"
        );
    }
}

#[test]
fn stale_audit_evidence_script_emits_valid_jsonl() {
    let artifact_root = repo_path("target/mock-code-finder/asupersync-dq4-contract-test")
        .display()
        .to_string();
    let output = Command::new("bash")
        .arg(repo_path(
            "scripts/run_stale_audit_normalization_evidence.sh",
        ))
        .env("STUB_SCAN_ARTIFACT_ROOT", &artifact_root)
        .output()
        .expect("run stale audit evidence script");

    assert!(
        output.status.success(),
        "script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let jsonl_path = Path::new(&artifact_root).join("stale-audit-normalization.jsonl");
    let jsonl = fs::read_to_string(&jsonl_path).expect("read generated jsonl");
    let mut count = 0;
    let mut scenarios = BTreeSet::new();
    for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
        count += 1;
        let record: Value = serde_json::from_str(line).expect("parse jsonl record");
        assert_eq!(
            str_field(&record, "schema_version"),
            "mock-code-finder-evidence-jsonl-schema-v1"
        );
        assert_eq!(str_field(&record, "bead_id"), "asupersync-dq4");
        assert_eq!(str_field(&record, "support_class"), "production_live");
        assert_eq!(str_field(&record, "verdict"), "pass");
        assert_eq!(str_field(&record, "evidence_quality"), "live");
        assert_eq!(str_field(&record, "blocker_bead_id"), "");
        let scenario_id = str_field(&record, "scenario_id");
        let cargo_features: BTreeSet<_> = array(&record, "cargo_features")
            .iter()
            .map(|feature| {
                feature
                    .as_str()
                    .unwrap_or_else(|| panic!("cargo feature for {scenario_id} must be a string"))
                    .to_string()
            })
            .collect();
        assert!(
            cargo_features.contains("test-internals"),
            "{scenario_id} must include test-internals in proof features"
        );
        if scenario_id == "otel-span-obligation-leak-detection" {
            assert!(
                cargo_features.contains("metrics"),
                "span leak proof must enable metrics"
            );
        }
        if scenario_id == "otlp-add-attributes-production-seam" {
            assert!(
                cargo_features.contains("metrics"),
                "add_attributes proof must enable metrics"
            );
            assert!(
                cargo_features.contains("tracing-integration"),
                "add_attributes proof must enable tracing-integration"
            );
        }
        let proof_commands = array(&record, "proof_commands");
        assert!(
            proof_commands.iter().any(|command| command
                .as_str()
                .is_some_and(|text| text.contains("rch exec --"))),
            "{scenario_id} must include an rch proof command"
        );
        assert!(scenarios.insert(scenario_id.to_string()));
    }
    assert_eq!(count, 6);

    let summary_path = Path::new(&artifact_root).join("stale-audit-normalization.summary.json");
    let summary_text = fs::read_to_string(summary_path).expect("read generated summary");
    let summary: Value = serde_json::from_str(&summary_text).expect("parse generated summary");
    let row = summary
        .get(jsonl_path.to_string_lossy().as_ref())
        .unwrap_or_else(|| panic!("summary missing row for {}", jsonl_path.display()));
    assert_eq!(row["records"], 6);
    assert_eq!(row["verdicts"]["pass"], 6);
    assert_eq!(row["support_class"]["production_live"], 6);
    assert_eq!(row["evidence_quality"]["live"], 6);
}

#[test]
fn normalized_audit_files_do_not_claim_fixed_gaps_are_active() {
    let checks = [
        (
            "tests/kafka_offset_commit_retry_audit.rs",
            "NO RETRY LOGIC IMPLEMENTED",
        ),
        (
            "src/observability/head_based_sampling_audit_test.rs",
            "Demonstrating current head-based sampling defect",
        ),
        (
            "src/observability/span_lifecycle_obligation_leak_audit_test.rs",
            "Obligation leak detection not implemented",
        ),
        (
            "tests/grpc_compression_flag_audit.rs",
            "Header validation not implemented",
        ),
        (
            "tests/grpc_server_deadline_propagation_audit.rs",
            "No server-side maximum cap is applied",
        ),
    ];

    for (path, stale_marker) in checks {
        let text = fs::read_to_string(repo_path(path)).expect("read normalized source file");
        assert!(
            !text.contains(stale_marker),
            "{path} still contains stale active-defect marker: {stale_marker}"
        );
    }
}
