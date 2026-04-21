#![allow(clippy::all)]
//! Semantic Enablement FAQ Validation (SEM-11.3)
//!
//! Validates that the enablement FAQ exists, covers key topic areas,
//! references the correct documents, and provides actionable answers
//! for contributors.
//!
//! Bead: asupersync-3cddg.11.3

use std::path::Path;

fn load_faq() -> String {
    std::fs::read_to_string("docs/semantic_enablement_faq.md")
        .expect("failed to load enablement FAQ")
}

// ─── FAQ infrastructure ───────────────────────────────────────────

#[test]
fn faq_exists() {
    assert!(
        Path::new("docs/semantic_enablement_faq.md").exists(),
        "Enablement FAQ must exist"
    );
}

#[test]
fn faq_references_bead() {
    let faq = load_faq();
    assert!(
        faq.contains("asupersync-3cddg.11.3"),
        "FAQ must reference its own bead ID"
    );
}

#[test]
fn faq_references_playbook() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_maintainer_playbook.md"),
        "FAQ must reference the maintainer playbook"
    );
}

// ─── Topic coverage: General ──────────────────────────────────────

#[test]
fn faq_covers_what_is_harmonization() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic harmonization"),
        "FAQ must explain semantic harmonization"
    );
}

#[test]
fn faq_covers_canonical_contract() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_contract_schema.md"),
        "FAQ must reference canonical contract"
    );
    assert!(faq.contains("47"), "FAQ must mention 47 canonical rules");
}

#[test]
fn faq_covers_semantic_domains() {
    let faq = load_faq();
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
        if !faq.contains(domain) {
            missing.push(*domain);
        }
    }
    assert!(
        missing.is_empty(),
        "FAQ missing domain coverage:\n{}",
        missing
            .iter()
            .map(|d| format!("  - {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn faq_covers_current_status() {
    let faq = load_faq();
    assert!(
        faq.contains("Phase 1") && faq.contains("PASS"),
        "FAQ must document current Phase 1 PASS status"
    );
    assert!(
        faq.contains("semantic_harmonization_report.md"),
        "FAQ must reference harmonization report"
    );
}

// ─── Topic coverage: Verification ─────────────────────────────────

#[test]
fn faq_covers_verification_suite() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_rerun.sh"),
        "FAQ must reference rerun shortcuts"
    );
    assert!(
        faq.contains("run_semantic_verification.sh"),
        "FAQ must reference unified runner"
    );
}

#[test]
fn faq_covers_failure_diagnosis() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_failure_replay_cookbook.md"),
        "FAQ must reference failure-replay cookbook"
    );
}

#[test]
fn faq_covers_quality_gates() {
    let faq = load_faq();
    assert!(
        faq.contains("cargo check") && faq.contains("cargo clippy") && faq.contains("cargo fmt"),
        "FAQ must list quality gate commands"
    );
}

#[test]
fn faq_covers_evidence_bundle() {
    let faq = load_faq();
    assert!(
        faq.contains("assemble_evidence_bundle.sh"),
        "FAQ must document evidence bundle assembly"
    );
    assert!(
        faq.contains("generate_verification_summary.sh"),
        "FAQ must document summary generation"
    );
}

#[test]
fn faq_covers_evidence_classes() {
    let faq = load_faq();
    let classes = ["UT", "PT", "OC", "E2E", "LOG", "DOC", "CI"];
    let mut missing = Vec::new();
    for class in &classes {
        if !faq.contains(class) {
            missing.push(*class);
        }
    }
    assert!(
        missing.is_empty(),
        "FAQ missing evidence class references:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn faq_covers_readiness_gates() {
    let faq = load_faq();
    let gates = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"];
    let mut missing = Vec::new();
    for gate in &gates {
        if !faq.contains(gate) {
            missing.push(*gate);
        }
    }
    assert!(
        missing.is_empty(),
        "FAQ missing gate references:\n{}",
        missing
            .iter()
            .map(|g| format!("  - {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Topic coverage: Development workflow ─────────────────────────

#[test]
fn faq_covers_rule_annotations() {
    let faq = load_faq();
    assert!(
        faq.contains("Rule #"),
        "FAQ must show rule annotation examples"
    );
}

#[test]
fn faq_covers_no_mock_policy() {
    let faq = load_faq();
    assert!(
        faq.contains("no-mock") || faq.contains("No-Mock") || faq.contains("No mock"),
        "FAQ must document no-mock policy"
    );
}

#[test]
fn faq_covers_deterministic_replay() {
    let faq = load_faq();
    assert!(
        faq.contains("SEED"),
        "FAQ must document SEED-based deterministic replay"
    );
}

#[test]
fn faq_covers_rch_usage() {
    let faq = load_faq();
    assert!(
        faq.contains("rch exec"),
        "FAQ must document rch remote compilation"
    );
}

// ─── Topic coverage: Governance ───────────────────────────────────

#[test]
fn faq_covers_adr_decisions() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_adr_decisions.md"),
        "FAQ must reference ADR decisions ledger"
    );
}

#[test]
fn faq_covers_charter_reference() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_harmonization_charter.md"),
        "FAQ must reference harmonization charter"
    );
}

#[test]
fn faq_covers_unsafe_policy() {
    let faq = load_faq();
    assert!(
        faq.contains("deny(unsafe_code)") || faq.contains("unsafe"),
        "FAQ must document unsafe code policy"
    );
}

#[test]
fn faq_covers_change_freeze() {
    let faq = load_faq();
    assert!(
        faq.contains("semantic_change_freeze_workflow.md") || faq.contains("change freeze"),
        "FAQ must reference change freeze workflow"
    );
}

// ─── Topic coverage: Coordination ─────────────────────────────────

#[test]
fn faq_covers_agent_coordination() {
    let faq = load_faq();
    assert!(
        faq.contains("Agent Mail") || faq.contains("agent mail"),
        "FAQ must document agent coordination via mail"
    );
}

#[test]
fn faq_covers_bead_workflow() {
    let faq = load_faq();
    assert!(
        faq.contains("br update") || faq.contains("br close") || faq.contains("br ready"),
        "FAQ must document bead workflow commands"
    );
}

#[test]
fn faq_covers_file_reservations() {
    let faq = load_faq();
    assert!(
        faq.contains("file_reservation") || faq.contains("Reserve files"),
        "FAQ must document file reservation for conflict prevention"
    );
}

// ─── Topic coverage: Troubleshooting ──────────────────────────────

#[test]
fn faq_covers_compilation_errors() {
    let faq = load_faq();
    assert!(
        faq.contains("cargo clean") || faq.contains("compilation error"),
        "FAQ must document compilation error troubleshooting"
    );
}

#[test]
fn faq_covers_fmt_drift() {
    let faq = load_faq();
    assert!(
        faq.contains("formatting drift") || faq.contains("fmt"),
        "FAQ must document formatting drift handling"
    );
}

// ─── Structure ────────────────────────────────────────────────────

#[test]
fn faq_has_numbered_questions() {
    let faq = load_faq();
    // Should have at least 20 numbered questions
    let question_count = faq.matches("### Q").count();
    assert!(
        question_count >= 20,
        "FAQ must have at least 20 questions, found {question_count}"
    );
}

#[test]
fn faq_has_section_headers() {
    let faq = load_faq();
    let sections = [
        "General",
        "Verification",
        "Development Workflow",
        "Governance",
        "Coordination",
        "Troubleshooting",
    ];
    let mut missing = Vec::new();
    for section in &sections {
        if !faq.contains(section) {
            missing.push(*section);
        }
    }
    assert!(
        missing.is_empty(),
        "FAQ missing section headers:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
