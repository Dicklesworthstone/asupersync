#![allow(clippy::all)]
//! Semantic Maintainer Playbook Validation (SEM-11.2)
//!
//! Validates that the maintainer playbook exists, covers required topics,
//! references key documents, and provides actionable guidance for new
//! contributors and ongoing semantic maintenance.
//!
//! Bead: asupersync-3cddg.11.2

use std::path::Path;

fn load_playbook() -> String {
    std::fs::read_to_string("docs/semantic_maintainer_playbook.md")
        .expect("failed to load maintainer playbook")
}

// ─── Playbook infrastructure ──────────────────────────────────────

#[test]
fn playbook_exists() {
    assert!(
        Path::new("docs/semantic_maintainer_playbook.md").exists(),
        "Maintainer playbook must exist"
    );
}

#[test]
fn playbook_references_bead() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("asupersync-3cddg.11.2"),
        "Playbook must reference its own bead ID"
    );
}

// ─── Quick start and onboarding ───────────────────────────────────

#[test]
fn playbook_has_quick_start() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Quick Start") || playbook.contains("quick start"),
        "Playbook must include quick start section"
    );
}

#[test]
fn playbook_has_first_day_checklist() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("First-Day Checklist") || playbook.contains("first-day checklist"),
        "Playbook must include first-day checklist"
    );
}

#[test]
fn playbook_has_onboarding_workflow() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Onboarding") || playbook.contains("onboarding"),
        "Playbook must include onboarding workflow"
    );
}

// ─── Key concepts ─────────────────────────────────────────────────

#[test]
fn playbook_documents_canonical_contract() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("semantic_contract_schema.md"),
        "Playbook must reference canonical contract schema"
    );
    assert!(
        playbook.contains("47"),
        "Playbook must mention 47 canonical rules"
    );
}

#[test]
fn playbook_documents_evidence_classes() {
    let playbook = load_playbook();
    let classes = ["UT", "PT", "OC", "E2E", "LOG", "DOC", "CI"];
    let mut missing = Vec::new();
    for class in &classes {
        if !playbook.contains(class) {
            missing.push(*class);
        }
    }
    assert!(
        missing.is_empty(),
        "Playbook missing evidence class references:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn playbook_documents_readiness_gates() {
    let playbook = load_playbook();
    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !playbook.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "Playbook missing gate references:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn playbook_documents_semantic_domains() {
    let playbook = load_playbook();
    let domains = [
        "cancellation",
        "obligation",
        "region",
        "outcome",
        "ownership",
        "combinator",
        "capability",
        "determinism",
    ];
    let mut missing = Vec::new();
    for domain in &domains {
        if !playbook.contains(domain) {
            missing.push(*domain);
        }
    }
    assert!(
        missing.is_empty(),
        "Playbook missing domain references:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Verification runner guidance ─────────────────────────────────

#[test]
fn playbook_documents_unified_runner() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("run_semantic_verification.sh"),
        "Playbook must reference unified verification runner"
    );
}

#[test]
fn playbook_documents_rerun_shortcuts() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("semantic_rerun.sh"),
        "Playbook must reference rerun shortcuts"
    );
}

#[test]
fn playbook_documents_evidence_bundle() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("assemble_evidence_bundle.sh"),
        "Playbook must reference evidence bundle assembly"
    );
}

#[test]
fn playbook_documents_summary_generator() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("generate_verification_summary.sh"),
        "Playbook must reference summary generator"
    );
}

#[test]
fn playbook_documents_rerun_suites() {
    let playbook = load_playbook();
    let suites = [
        "semantic_rerun.sh all",
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
    for suite in &suites {
        if !playbook.contains(suite) {
            missing.push(*suite);
        }
    }
    assert!(
        missing.is_empty(),
        "Playbook missing rerun suite references:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Testing expectations ─────────────────────────────────────────

#[test]
fn playbook_documents_quality_gates() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("cargo check"),
        "Playbook must include cargo check in quality gates"
    );
    assert!(
        playbook.contains("cargo clippy"),
        "Playbook must include cargo clippy in quality gates"
    );
    assert!(
        playbook.contains("cargo fmt"),
        "Playbook must include cargo fmt in quality gates"
    );
}

#[test]
fn playbook_documents_no_mock_policy() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("No-Mock")
            || playbook.contains("no-mock")
            || playbook.contains("No mock"),
        "Playbook must document the no-mock testing policy"
    );
}

#[test]
fn playbook_documents_deterministic_replay() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Deterministic") || playbook.contains("deterministic"),
        "Playbook must document deterministic replay"
    );
    assert!(
        playbook.contains("SEED"),
        "Playbook must document SEED usage for deterministic runs"
    );
}

#[test]
fn playbook_documents_logging_standards() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("schema_version"),
        "Playbook must reference logging schema fields"
    );
    assert!(
        playbook.contains("semantic_verification_log_schema.md"),
        "Playbook must reference log schema document"
    );
}

// ─── Failure diagnosis ────────────────────────────────────────────

#[test]
fn playbook_references_failure_cookbook() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("semantic_failure_replay_cookbook.md"),
        "Playbook must reference failure-replay cookbook"
    );
}

#[test]
fn playbook_has_triage_guidance() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Triage") || playbook.contains("triage"),
        "Playbook must include triage guidance"
    );
}

#[test]
fn playbook_has_diagnostic_pipeline() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Full Diagnostic") || playbook.contains("full diagnostic"),
        "Playbook must include full diagnostic pipeline"
    );
}

// ─── Document cross-references ────────────────────────────────────

#[test]
fn playbook_references_key_documents() {
    let playbook = load_playbook();
    let docs = [
        "semantic_contract_schema.md",
        "semantic_verification_matrix.md",
        "semantic_runtime_gap_matrix.md",
        "semantic_gate_evaluation_report.md",
        "semantic_harmonization_report.md",
        "semantic_residual_risk_register.md",
        "semantic_harmonization_charter.md",
        "semantic_failure_replay_cookbook.md",
        "semantic_verification_log_schema.md",
    ];
    let mut missing = Vec::new();
    for doc in &docs {
        if !playbook.contains(doc) {
            missing.push(*doc);
        }
    }
    assert!(
        missing.is_empty(),
        "Playbook missing key document references:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Governance and process ───────────────────────────────────────

#[test]
fn playbook_documents_semantic_change_review() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Semantic Change Review") || playbook.contains("semantic change"),
        "Playbook must document semantic change review process"
    );
}

#[test]
fn playbook_documents_governance_escalation() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Governance")
            || playbook.contains("governance")
            || playbook.contains("escalation"),
        "Playbook must document governance escalation paths"
    );
}

#[test]
fn playbook_documents_unsafe_code_policy() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("unsafe") || playbook.contains("Unsafe"),
        "Playbook must document unsafe code policy"
    );
}

// ─── Recurring audit ──────────────────────────────────────────────

#[test]
fn playbook_has_audit_procedure() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Recurring Audit")
            || playbook.contains("Audit Procedure")
            || playbook.contains("audit"),
        "Playbook must include recurring audit procedure"
    );
}

#[test]
fn playbook_has_audit_checklist() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Audit Checklist") || playbook.contains("audit checklist"),
        "Playbook must include audit checklist"
    );
}

#[test]
fn playbook_documents_drift_detection() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Drift Detection")
            || playbook.contains("drift detection")
            || playbook.contains("drift"),
        "Playbook must document drift detection procedures"
    );
}

// ─── Current status ───────────────────────────────────────────────

#[test]
fn playbook_documents_current_status() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("Phase 1") || playbook.contains("phase 1"),
        "Playbook must document current Phase 1 status"
    );
    assert!(
        playbook.contains("PASS") || playbook.contains("pass"),
        "Playbook must document gate pass status"
    );
}

// ─── Reproducibility ──────────────────────────────────────────────

#[test]
fn playbook_documents_rch_usage() {
    let playbook = load_playbook();
    assert!(
        playbook.contains("rch"),
        "Playbook must document rch for remote compilation"
    );
}

#[test]
fn playbook_documents_correlation_ids() {
    let playbook = load_playbook();
    let ids = ["run_id", "entry_id", "witness_id"];
    let mut missing = Vec::new();
    for id in &ids {
        if !playbook.contains(id) {
            missing.push(*id);
        }
    }
    assert!(
        missing.is_empty(),
        "Playbook missing correlation ID documentation:\n{}",
        missing
            .iter()
            .map(|id| format!("  - {id}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
