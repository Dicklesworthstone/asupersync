#![allow(missing_docs)]

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn wasm_pilot_observability_playbook_documents_contract_and_commands() {
    let doc = fs::read_to_string("docs/wasm_pilot_observability_contract.md")
        .expect("failed to read wasm pilot observability contract doc");

    for token in [
        "wasm-pilot-observability-contract-v1",
        "asupersync-pilot-observability-v1",
        "python3 scripts/evaluate_wasm_pilot_cohort.py --self-test",
        "--telemetry-input",
        "--telemetry-output",
        "--telemetry-log-output",
        "bash scripts/test_wasm_pilot_observability_e2e.sh",
        "owner_route",
        "replay_command",
        "trace_pointer",
    ] {
        assert!(
            doc.contains(token),
            "pilot observability contract doc missing required token: {token}"
        );
    }
}

#[test]
fn wasm_pilot_observability_evaluator_self_test_passes() {
    assert!(
        Path::new("scripts/evaluate_wasm_pilot_cohort.py").exists(),
        "pilot evaluator script must exist"
    );

    let output = Command::new("python3")
        .arg("scripts/evaluate_wasm_pilot_cohort.py")
        .arg("--self-test")
        .output()
        .expect("failed to run pilot evaluator self-test");

    assert!(
        output.status.success(),
        "pilot evaluator self-test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn wasm_pilot_observability_e2e_failure_injection_gate_passes() {
    assert!(
        Path::new("scripts/test_wasm_pilot_observability_e2e.sh").exists(),
        "pilot observability e2e script must exist"
    );

    let output = Command::new("bash")
        .arg("scripts/test_wasm_pilot_observability_e2e.sh")
        .output()
        .expect("failed to run pilot observability e2e script");

    assert!(
        output.status.success(),
        "pilot observability e2e script failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
