//! Deterministic replay flake detector runner validation (SEM-12.15)
//!
//! Validates that the SEM-12.15 runner script exists and declares the
//! required flake/variance surfaces for deterministic replay workflows.

use std::path::Path;

fn load_runner() -> String {
    std::fs::read_to_string("scripts/run_semantic_flake_detector.sh")
        .expect("failed to load semantic flake detector runner")
}

#[test]
fn flake_runner_exists() {
    assert!(
        Path::new("scripts/run_semantic_flake_detector.sh").exists(),
        "flake detector runner must exist"
    );
}

#[test]
fn flake_runner_has_bash_shebang() {
    let script = load_runner();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "runner must use /usr/bin/env bash shebang"
    );
}

#[test]
fn flake_runner_supports_required_flags() {
    let script = load_runner();
    let required = [
        "--iterations",
        "--seed",
        "--suite",
        "--ci",
        "--json",
        "--duration-threshold",
    ];

    for flag in &required {
        assert!(
            script.contains(flag),
            "runner missing required flag: {flag}"
        );
    }
}

#[test]
fn flake_runner_declares_replay_suites() {
    let script = load_runner();
    assert!(
        script.contains("semantic_witness_replay_e2e")
            && script.contains("e2e_w7_1_seed_equivalence"),
        "runner must execute witness seed-equivalence replay suite"
    );
    assert!(
        script.contains("replay_e2e_suite") && script.contains("cross_seed_replay_suite"),
        "runner must execute cross-seed replay suite"
    );
}

#[test]
fn flake_runner_declares_variance_dashboard_schema() {
    let script = load_runner();
    assert!(
        script.contains("sem-variance-dashboard-v1"),
        "runner must emit sem-variance-dashboard-v1 dashboard schema"
    );
    assert!(
        script.contains("variance_dashboard.json"),
        "runner must write variance_dashboard.json artifact"
    );
    assert!(
        script.contains("variance_events.ndjson"),
        "runner must write variance_events.ndjson structured log artifact"
    );
}

#[test]
fn flake_runner_declares_instability_signals() {
    let script = load_runner();
    let signals = [
        "status_variance",
        "duration_variance",
        "timeout_or_deadline_pressure",
        "panic_path",
        "trace_divergence",
    ];
    for signal in &signals {
        assert!(
            script.contains(signal),
            "runner missing instability signal: {signal}"
        );
    }
}

#[test]
fn flake_runner_uses_rch_offload_for_cargo() {
    let script = load_runner();
    assert!(
        script.contains("rch") && script.contains("exec --"),
        "runner must support rch offload path for cargo-heavy commands"
    );
}

#[test]
fn flake_runner_emits_replay_commands() {
    let script = load_runner();
    assert!(
        script.contains("replay_command"),
        "runner must include replay_command field in dashboard output"
    );
}
