#![allow(clippy::all)]
//! TLA+ Abstraction Boundaries and Runtime Correspondence Validation (SEM-07.5)
//!
//! Validates that the abstraction boundaries document exists, documents
//! each ADR-approved abstraction, provides state/action/invariant
//! correspondence tables, and includes a soundness argument.
//!
//! Bead: asupersync-3cddg.7.5

use std::path::Path;

fn load_doc() -> String {
    std::fs::read_to_string("docs/semantic_tla_abstraction_boundaries.md")
        .expect("failed to load TLA abstraction boundaries document")
}

// ─── Document infrastructure ──────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new("docs/semantic_tla_abstraction_boundaries.md").exists(),
        "Abstraction boundaries document must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-3cddg.7.5"),
        "Document must reference its own bead ID"
    );
}

// ─── Abstraction inventory ──────────────────────────────────────

#[test]
fn doc_covers_all_adr_abstractions() {
    let doc = load_doc();
    let abstractions = [
        ("ADR-003", "Cancel Reason"),
        ("ADR-004", "Finalizer"),
        ("ADR-005", "Combinator"),
        ("ADR-006", "Capability"),
        ("ADR-007", "Determinism"),
        ("ADR-008", "Outcome Severity"),
    ];
    let mut missing = Vec::new();
    for (adr, topic) in &abstractions {
        if !doc.contains(adr) || !doc.contains(topic) {
            missing.push(format!("{adr} ({topic})"));
        }
    }
    assert!(
        missing.is_empty(),
        "Document missing ADR abstraction sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_covers_non_adr_abstractions() {
    let doc = load_doc();
    assert!(
        doc.contains("Mask Depth Bounded"),
        "Must document mask depth bound abstraction"
    );
    assert!(
        doc.contains("No Time") || doc.contains("Deadline"),
        "Must document time/deadline abstraction"
    );
    assert!(
        doc.contains("Obligation Kind"),
        "Must document obligation kind abstraction"
    );
}

#[test]
fn doc_abstractions_have_soundness_rationale() {
    let doc = load_doc();
    assert!(
        doc.contains("Soundness"),
        "Each abstraction must include soundness rationale"
    );
}

#[test]
fn doc_abstractions_identify_affected_rules() {
    let doc = load_doc();
    assert!(
        doc.contains("Rules affected"),
        "Each abstraction must identify affected canonical rules"
    );
}

#[test]
fn doc_abstractions_identify_alternative_assurance() {
    let doc = load_doc();
    let layers = ["Lean", "runtime oracle", "type system"];
    let mut missing = Vec::new();
    for layer in &layers {
        if !doc.contains(layer) {
            missing.push(*layer);
        }
    }
    assert!(
        missing.is_empty(),
        "Document missing alternative assurance layers:\n{}",
        missing
            .iter()
            .map(|l| format!("  - {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── State correspondence ───────────────────────────────────────

#[test]
fn doc_has_variable_correspondence() {
    let doc = load_doc();
    let variables = [
        "taskState",
        "taskRegion",
        "taskMask",
        "regionState",
        "regionChildren",
        "regionLedger",
        "obState",
        "obHolder",
        "obRegion",
    ];
    let mut missing = Vec::new();
    for var in &variables {
        if !doc.contains(var) {
            missing.push(*var);
        }
    }
    assert!(
        missing.is_empty(),
        "Document missing TLA+ variable correspondence entries:\n{}",
        missing
            .iter()
            .map(|v| format!("  - {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_has_state_enum_correspondence() {
    let doc = load_doc();
    // Task lifecycle states
    assert!(
        doc.contains("Spawned") && doc.contains("Running") && doc.contains("Completed"),
        "Must document task lifecycle state correspondence"
    );
    // Region lifecycle states
    assert!(
        doc.contains("Quiescent") && doc.contains("ChildrenDone"),
        "Must document region lifecycle state correspondence"
    );
    // Obligation lifecycle states
    assert!(
        doc.contains("Reserved") && doc.contains("Committed") && doc.contains("Leaked"),
        "Must document obligation lifecycle state correspondence"
    );
}

#[test]
fn doc_state_correspondence_includes_lean() {
    let doc = load_doc();
    assert!(
        doc.contains("TaskState.Spawned") || doc.contains("Lean"),
        "State correspondence must include Lean equivalents"
    );
}

// ─── Action correspondence ──────────────────────────────────────

#[test]
fn doc_has_action_correspondence() {
    let doc = load_doc();
    let actions = [
        "Spawn",
        "CancelRequest",
        "CancelAcknowledge",
        "CloseBegin",
        "CloseCancelChildren",
        "ReserveObligation",
        "CommitObligation",
        "AbortObligation",
    ];
    let mut missing = Vec::new();
    for action in &actions {
        if !doc.contains(action) {
            missing.push(*action);
        }
    }
    assert!(
        missing.is_empty(),
        "Document missing TLA+ action correspondence entries:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_action_correspondence_includes_lean_steps() {
    let doc = load_doc();
    assert!(
        doc.contains("Step.spawn") && doc.contains("Step.cancelRequest"),
        "Action correspondence must include Lean Step constructors"
    );
}

#[test]
fn doc_action_correspondence_includes_runtime() {
    let doc = load_doc();
    assert!(
        doc.contains("region.rs") && doc.contains("obligation.rs"),
        "Action correspondence must include runtime function references"
    );
}

// ─── Invariant correspondence ───────────────────────────────────

#[test]
fn doc_has_invariant_correspondence() {
    let doc = load_doc();
    let invariants = [
        "TypeInvariant",
        "WellFormedInvariant",
        "NoOrphanTasks",
        "NoLeakedObligations",
        "CloseImpliesQuiescent",
        "MaskBoundedInvariant",
        "MaskMonotoneInvariant",
        "CancelIdempotenceStructural",
        "AssumptionEnvelopeInvariant",
    ];
    let mut missing = Vec::new();
    for inv in &invariants {
        if !doc.contains(inv) {
            missing.push(*inv);
        }
    }
    assert!(
        missing.is_empty(),
        "Document missing invariant correspondence entries:\n{}",
        missing
            .iter()
            .map(|i| format!("  - {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_documents_invariants_not_in_tla() {
    let doc = load_doc();
    assert!(
        doc.contains("Not in TLA") || doc.contains("Covered Elsewhere"),
        "Must document invariants not checked by TLA+"
    );
}

#[test]
fn doc_documents_liveness_property() {
    let doc = load_doc();
    assert!(
        doc.contains("CancelTerminates"),
        "Must document CancelTerminates liveness property"
    );
    assert!(
        doc.contains("LiveSpec"),
        "Must document LiveSpec requirement for liveness"
    );
}

// ─── Spork integration ──────────────────────────────────────────

#[test]
fn doc_documents_spork_invariants() {
    let doc = load_doc();
    assert!(
        doc.contains("ReplyLinearityInvariant") && doc.contains("SINV-1"),
        "Must document ReplyLinearityInvariant (SINV-1)"
    );
    assert!(
        doc.contains("RegistryLeaseInvariant") && doc.contains("SINV-3"),
        "Must document RegistryLeaseInvariant (SINV-3)"
    );
}

// ─── ADR cross-reference ────────────────────────────────────────

#[test]
fn doc_has_adr_cross_reference_table() {
    let doc = load_doc();
    let adrs = [
        "ADR-003", "ADR-004", "ADR-005", "ADR-006", "ADR-007", "ADR-008",
    ];
    let mut missing = Vec::new();
    for adr in &adrs {
        if !doc.contains(adr) {
            missing.push(*adr);
        }
    }
    assert!(
        missing.is_empty(),
        "Document missing ADR cross-references:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Soundness argument ─────────────────────────────────────────

#[test]
fn doc_has_soundness_argument() {
    let doc = load_doc();
    assert!(
        doc.contains("Soundness Argument") || doc.contains("soundness argument"),
        "Must include formal soundness argument section"
    );
}

#[test]
fn doc_soundness_covers_conservative_projection() {
    let doc = load_doc();
    assert!(
        doc.contains("conservative") || doc.contains("Conservative"),
        "Soundness must argue conservative projection"
    );
}

#[test]
fn doc_soundness_covers_assumption_envelope() {
    let doc = load_doc();
    assert!(
        doc.contains("AssumptionEnvelopeInvariant"),
        "Soundness must reference assumption envelope invariant"
    );
}

#[test]
fn doc_documents_limitations() {
    let doc = load_doc();
    assert!(
        doc.contains("Limitations") || doc.contains("limitations"),
        "Must document model limitations"
    );
}

// ─── Reviewer guidance ──────────────────────────────────────────

#[test]
fn doc_has_reviewer_checklist() {
    let doc = load_doc();
    assert!(
        doc.contains("Reviewer Checklist") || doc.contains("reviewer checklist"),
        "Must include reviewer checklist"
    );
}
