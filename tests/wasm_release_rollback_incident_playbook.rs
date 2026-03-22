//! WASM release rollback and incident playbook enforcement (WASM-15.5).
//!
//! Ensures the rollback/incident playbook is present, complete, and wired into
//! deterministic CI certification and release workflow controls.

use std::path::Path;

fn load_playbook() -> String {
    std::fs::read_to_string("docs/wasm_release_rollback_incident_playbook.md")
        .expect("failed to load rollback/incident playbook")
}

fn load_release_strategy() -> String {
    std::fs::read_to_string("docs/wasm_release_channel_strategy.md")
        .expect("failed to load wasm release channel strategy")
}

fn load_ci_workflow() -> String {
    std::fs::read_to_string(".github/workflows/ci.yml").expect("failed to load CI workflow")
}

fn load_publish_workflow() -> String {
    std::fs::read_to_string(".github/workflows/publish.yml")
        .expect("failed to load publish workflow")
}

#[test]
fn playbook_exists() {
    assert!(
        Path::new("docs/wasm_release_rollback_incident_playbook.md").exists(),
        "rollback/incident playbook must exist"
    );
}

#[test]
fn playbook_references_bead_and_contract() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("asupersync-umelq.15.5"),
        "playbook must reference bead asupersync-umelq.15.5"
    );
    assert!(
        playbook.contains("wasm-release-rollback-incident-playbook-v1"),
        "playbook must define contract id"
    );
}

#[test]
fn playbook_defines_required_operational_sections() {
    let playbook = load_playbook();
    let required = [
        "Incident Severity Classification",
        "Incident Command Roles",
        "Deterministic Triage Command Bundle",
        "Rollback Triggers",
        "Rollback Procedure",
        "Communication Protocol",
        "Artifact revocation strategy",
        "Postmortem Requirements",
        "CI Certification Contract",
    ];
    let mut missing = Vec::new();
    for token in &required {
        if !playbook.contains(token) {
            missing.push(*token);
        }
    }
    assert!(
        missing.is_empty(),
        "playbook missing required sections:\n{}",
        missing
            .iter()
            .map(|token| format!("  - {token}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn playbook_includes_deterministic_repro_commands() {
    let playbook = load_playbook();
    let required = [
        "python3 scripts/check_wasm_optimization_policy.py",
        "python3 scripts/check_wasm_dependency_policy.py",
        "python3 scripts/check_security_release_gate.py",
        "rch exec -- cargo test -p asupersync --test wasm_bundler_compatibility -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture",
    ];
    for cmd in required {
        assert!(
            playbook.contains(cmd),
            "playbook missing deterministic command: {cmd}"
        );
    }
}

#[test]
fn playbook_requires_release_and_npm_rollback_artifacts() {
    let playbook = load_playbook();
    let required_artifacts = [
        "artifacts/security_release_gate_report.json",
        "artifacts/wasm_dependency_audit_summary.json",
        "artifacts/wasm_optimization_pipeline_summary.json",
        "artifacts/npm/publish_outcome.json",
        "artifacts/npm/rollback_outcome.json",
        "artifacts/npm/rollback_actions.txt",
        "surface_evidence_paths",
        "browser-run.json",
        "scenario_inventory",
    ];
    for artifact in required_artifacts {
        assert!(
            playbook.contains(artifact),
            "playbook missing required artifact reference: {artifact}"
        );
    }
}

#[test]
fn playbook_references_release_channel_strategy_and_publish_workflow() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("docs/wasm_release_channel_strategy.md"),
        "playbook must reference release channel strategy"
    );
    assert!(
        playbook.contains(".github/workflows/publish.yml"),
        "playbook must reference publish workflow controls"
    );
    assert!(
        playbook.contains("rollback_npm_to_version") && playbook.contains("rollback_reason"),
        "playbook must document rollback workflow inputs"
    );
}

#[test]
fn playbook_defines_vnext_surface_specific_rollbacks() {
    let playbook = load_playbook();
    for token in [
        "Dedicated Web Worker",
        "browser-run.json",
        "scenario_inventory",
        "Service-worker bounded broker registration + durable handoff",
        "Shared-worker bounded coordinator attach + downgrade",
        "guarded canary-only",
        "preview_only",
        "service_worker_not_yet_shipped",
        "service_worker_direct_runtime_not_shipped",
        "shared_worker_direct_runtime_not_shipped",
    ] {
        assert!(
            playbook.contains(token),
            "playbook missing vNext rollback governance token: {token}"
        );
    }
}

#[test]
fn release_strategy_cross_references_playbook() {
    let strategy = load_release_strategy();
    assert!(
        strategy.contains("wasm_release_rollback_incident_playbook.md"),
        "release channel strategy must cross-reference rollback/incident playbook"
    );
}

#[test]
fn ci_workflow_has_playbook_certification_step_and_artifacts() {
    let ci = load_ci_workflow();
    let required = [
        "WASM rollback and incident playbook certification",
        "cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture",
        "artifacts/wasm_release_rollback_playbook_summary.json",
        "artifacts/wasm_release_rollback_playbook_test.log",
    ];
    for token in required {
        assert!(
            ci.contains(token),
            "ci workflow missing rollback playbook certification token: {token}"
        );
    }
}

#[test]
fn publish_workflow_contains_actionable_rollback_controls() {
    let publish = load_publish_workflow();
    let required = [
        "rollback_npm_to_version",
        "rollback_reason",
        "Execute npm dist-tag rollback",
        "npm dist-tag add",
        "artifacts/npm/rollback_outcome.json",
        "Emit rollback guidance artifact on failure",
        "artifacts/wasm/release/rollback_instructions.md",
    ];
    for token in required {
        assert!(
            publish.contains(token),
            "publish workflow missing rollback control token: {token}"
        );
    }
}
