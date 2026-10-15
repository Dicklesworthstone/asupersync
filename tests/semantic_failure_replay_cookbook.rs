//! Semantic Failure Replay Cookbook Validation (SEM-12.12)
//!
//! Validates that the failure replay cookbook, rerun shortcut script, and
//! triage decision tree exist, cover all failure classes, and provide
//! deterministic rerun commands with proper correlation context.
//!
//! Bead: asupersync-3cddg.12.12

use std::path::Path;

fn load_cookbook() -> String {
    std::fs::read_to_string("docs/semantic_failure_replay_cookbook.md")
        .expect("failed to load failure replay cookbook")
}

fn load_rerun_script() -> String {
    std::fs::read_to_string("scripts/semantic_rerun.sh")
        .expect("failed to load semantic rerun script")
}

// ─── Cookbook infrastructure ─────────────────────────────────────

#[test]
fn cookbook_exists() {
    assert!(
        Path::new("docs/semantic_failure_replay_cookbook.md").exists(),
        "Failure replay cookbook must exist"
    );
}

#[test]
fn cookbook_references_bead() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("asupersync-3cddg.12.12"),
        "Cookbook must reference its own bead ID"
    );
}

#[test]
fn rerun_script_exists() {
    assert!(
        Path::new("scripts/semantic_rerun.sh").exists(),
        "Semantic rerun script must exist"
    );
}

#[test]
fn rerun_script_is_bash() {
    let script = load_rerun_script();
    assert!(
        script.starts_with("#!/usr/bin/env bash"),
        "Rerun script must use /usr/bin/env bash shebang"
    );
}

// ─── Decision tree coverage ─────────────────────────────────────

#[test]
fn cookbook_has_triage_decision_tree() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Triage Decision Tree") || cookbook.contains("triage decision tree"),
        "Cookbook must include triage decision tree"
    );
}

#[test]
fn cookbook_decision_tree_covers_all_suites() {
    let cookbook = load_cookbook();

    let suites = ["docs", "golden", "lean", "tla", "logging", "coverage"];

    let mut missing = Vec::new();
    for suite in &suites {
        if !cookbook.contains(suite) {
            missing.push(*suite);
        }
    }
    assert!(
        missing.is_empty(),
        "Decision tree missing suite references:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn cookbook_decision_tree_covers_all_gates() {
    let cookbook = load_cookbook();

    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !cookbook.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Decision tree missing gate references:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Failure class recipes ──────────────────────────────────────

#[test]
fn cookbook_covers_failure_classes() {
    let cookbook = load_cookbook();

    let classes = [
        "Documentation Alignment",
        "Golden Fixture",
        "Lean Proof",
        "TLA+ Scenario",
        "Logging Schema",
        "Coverage Gate",
        "Runtime Conformance",
        "Property/Law",
        "Cross-Artifact E2E",
    ];

    let mut missing = Vec::new();
    for class in &classes {
        if !cookbook.contains(class) {
            missing.push(*class);
        }
    }
    assert!(
        missing.is_empty(),
        "Cookbook missing failure class recipes:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn cookbook_recipes_have_rerun_commands() {
    let cookbook = load_cookbook();

    // Each recipe section should reference semantic_rerun.sh
    assert!(
        cookbook.contains("semantic_rerun.sh"),
        "Cookbook recipes must reference the rerun script"
    );

    // Must have cargo test commands
    assert!(
        cookbook.contains("cargo test"),
        "Cookbook must include cargo test commands for direct reruns"
    );
}

#[test]
fn cookbook_recipes_have_root_cause_checklists() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Root cause checklist") || cookbook.contains("root cause"),
        "Cookbook recipes must include root cause checklists"
    );
}

#[test]
fn cookbook_recipes_have_expected_artifacts() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Expected artifacts") || cookbook.contains("expected artifacts"),
        "Cookbook recipes must list expected artifacts"
    );
}

#[test]
fn cookbook_recipes_have_remediation_owners() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Remediation owner") || cookbook.contains("remediation owner"),
        "Cookbook recipes must identify remediation owners"
    );
}

// ─── Rerun script suites ────────────────────────────────────────

#[test]
fn rerun_script_supports_all_suites() {
    let script = load_rerun_script();

    let suites = [
        "docs",
        "golden",
        "lean",
        "tla",
        "logging",
        "coverage",
        "runtime",
        "laws",
        "e2e",
        "all",
        "forensics",
    ];

    let mut missing = Vec::new();
    for suite in &suites {
        // Check for suite in the case dispatch
        if !script.contains(suite) {
            missing.push(*suite);
        }
    }
    assert!(
        missing.is_empty(),
        "Rerun script missing suite support:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn rerun_script_supports_seed() {
    let script = load_rerun_script();
    assert!(
        script.contains("--seed"),
        "Rerun script must support --seed flag for deterministic replay"
    );
    assert!(
        script.contains("SEED"),
        "Rerun script must use SEED variable"
    );
}

#[test]
fn rerun_script_supports_verbose() {
    let script = load_rerun_script();
    assert!(
        script.contains("--verbose"),
        "Rerun script must support --verbose flag"
    );
    assert!(
        script.contains("--nocapture"),
        "Verbose mode must pass --nocapture to cargo test"
    );
}

#[test]
fn rerun_script_supports_json() {
    let script = load_rerun_script();
    assert!(
        script.contains("--json"),
        "Rerun script must support --json flag"
    );
    assert!(
        script.contains("semantic-rerun-v1"),
        "JSON output must use versioned schema"
    );
}

#[test]
fn rerun_script_includes_correlation_ids() {
    let script = load_rerun_script();
    assert!(
        script.contains("run_id") || script.contains("RUN_ID"),
        "Rerun script must generate correlation run_id"
    );
    assert!(
        script.contains("rerun_command"),
        "JSON output must include reproducible rerun command"
    );
}

// ─── Deterministic replay ───────────────────────────────────────

#[test]
fn cookbook_includes_deterministic_replay() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Deterministic Replay") || cookbook.contains("deterministic replay"),
        "Cookbook must include deterministic replay section"
    );
}

#[test]
fn cookbook_documents_correlation_ids() {
    let cookbook = load_cookbook();

    let ids = ["run_id", "entry_id", "thread_id", "witness_id"];
    let mut missing = Vec::new();
    for id in &ids {
        if !cookbook.contains(id) {
            missing.push(*id);
        }
    }
    assert!(
        missing.is_empty(),
        "Cookbook missing correlation ID documentation:\n{}",
        missing
            .iter()
            .map(|id| format!("  - {id}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Quick reference ────────────────────────────────────────────

#[test]
fn cookbook_has_quick_reference_table() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Quick Reference") || cookbook.contains("One-Command Rerun"),
        "Cookbook must include quick reference table"
    );
}

#[test]
fn cookbook_quick_ref_covers_all_suites() {
    let cookbook = load_cookbook();

    let suite_commands = [
        "semantic_rerun.sh docs",
        "semantic_rerun.sh golden",
        "semantic_rerun.sh lean",
        "semantic_rerun.sh tla",
        "semantic_rerun.sh logging",
        "semantic_rerun.sh coverage",
        "semantic_rerun.sh runtime",
        "semantic_rerun.sh laws",
        "semantic_rerun.sh e2e",
        "semantic_rerun.sh forensics",
    ];

    let mut missing = Vec::new();
    for cmd in &suite_commands {
        if !cookbook.contains(cmd) {
            missing.push(*cmd);
        }
    }
    assert!(
        missing.is_empty(),
        "Quick reference missing rerun commands:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Exit codes ─────────────────────────────────────────────────

#[test]
fn rerun_script_exit_codes() {
    let script = load_rerun_script();
    assert!(
        script.contains("exit 0") && script.contains("exit 1") && script.contains("exit 2"),
        "Rerun script must use exit codes 0 (success), 1 (test failure), 2 (usage error)"
    );
}

// ─── Full diagnostic run ────────────────────────────────────────

#[test]
fn cookbook_includes_full_diagnostic_procedure() {
    let cookbook = load_cookbook();
    assert!(
        cookbook.contains("Full Diagnostic") || cookbook.contains("full diagnostic"),
        "Cookbook must include full diagnostic run procedure"
    );
    assert!(
        cookbook.contains("run_semantic_verification.sh"),
        "Full diagnostic must reference unified verification runner"
    );
    assert!(
        cookbook.contains("assemble_evidence_bundle.sh"),
        "Full diagnostic must reference evidence bundle assembly"
    );
    assert!(
        cookbook.contains("generate_verification_summary.sh"),
        "Full diagnostic must reference summary generator"
    );
}

// ─── Rerun script references bead ───────────────────────────────

#[test]
fn rerun_script_references_bead() {
    let script = load_rerun_script();
    assert!(
        script.contains("asupersync-3cddg.12.12"),
        "Rerun script must reference its own bead ID"
    );
}

// ─── Summary integration ────────────────────────────────────────

#[test]
fn rerun_script_integrates_summary() {
    let script = load_rerun_script();
    assert!(
        script.contains("--summary") || script.contains("GENERATE_SUMMARY"),
        "Rerun script must support optional summary generation"
    );
    assert!(
        script.contains("generate_verification_summary.sh"),
        "Rerun script must integrate with the summary generator"
    );
}
