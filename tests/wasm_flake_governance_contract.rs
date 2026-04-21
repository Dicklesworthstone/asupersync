#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use std::fs;
use std::path::Path;
use std::process::Command;

fn load_json(path: &Path) -> serde_json::Value {
    let raw = fs::read_to_string(path).expect("failed to read JSON file");
    serde_json::from_str(&raw).expect("failed to parse JSON")
}

#[test]
fn wasm_flake_policy_declares_release_blocking_thresholds() {
    let policy = load_json(Path::new(".github/wasm_flake_governance_policy.json"));

    assert_eq!(
        policy["schema_version"], "wasm-flake-governance-policy-v1",
        "policy schema must be pinned"
    );

    let thresholds = policy["quality_thresholds"]
        .as_object()
        .expect("quality_thresholds must be object");

    for key in [
        "max_flake_rate_pct",
        "max_false_positive_rate_pct",
        "max_unresolved_high_severity_flakes",
        "max_unresolved_critical_severity_flakes",
        "max_critical_test_failures",
    ] {
        assert!(
            thresholds.contains_key(key),
            "quality_thresholds missing required key: {key}"
        );
    }

    let detection = policy["detection"]
        .as_object()
        .expect("detection must be object");
    assert_eq!(
        detection["dashboard_schema_version"], "sem-variance-dashboard-v1",
        "dashboard schema contract drift"
    );

    let required_suites = detection["required_suites"]
        .as_array()
        .expect("required_suites must be array");
    assert!(
        required_suites
            .iter()
            .any(|suite| suite == "witness_seed_equivalence"),
        "required_suites must include witness_seed_equivalence"
    );
    assert!(
        required_suites
            .iter()
            .any(|suite| suite == "cross_seed_replay"),
        "required_suites must include cross_seed_replay"
    );
}

#[test]
fn wasm_flake_playbook_documents_detection_quarantine_and_forensics_commands() {
    let doc = fs::read_to_string("docs/wasm_flake_governance_and_forensics.md")
        .expect("failed to read flake governance playbook doc");

    for token in [
        "scripts/run_semantic_flake_detector.sh --iterations 5 --json",
        "bash scripts/check_semantic_signal_quality.sh",
        "python3 ./scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json",
        "bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics",
        "TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh",
        "python3 ./scripts/check_incident_forensics_playbook.py",
        "artifacts/wasm/release/rollback_safety_report.json",
        "artifacts/wasm/release/incident_response_packet.json",
        "artifacts/npm/rollback_outcome.json",
        "artifact-revocation strategy",
        "postmortem-required fields",
        "trace_pointer",
        "reactivation_criteria",
    ] {
        assert!(
            doc.contains(token),
            "flake governance playbook missing required token: {token}"
        );
    }
}

#[test]
fn wasm_flake_governance_checker_self_test_passes() {
    assert!(
        Path::new("scripts/check_wasm_flake_governance.py").exists(),
        "governance checker script must exist"
    );

    let output = Command::new("python3")
        .arg("scripts/check_wasm_flake_governance.py")
        .arg("--self-test")
        .output()
        .expect("failed to run governance checker self-test");

    assert!(
        output.status.success(),
        "governance checker self-test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("all 9 self-tests passed"),
        "self-test output missing success marker: {stdout}"
    );
}
