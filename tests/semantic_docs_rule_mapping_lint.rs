#![allow(warnings)]
#![allow(clippy::all)]
//! Docs-to-Rule-ID Mapping Lint Tests (SEM-05.1)
//!
//! Validates that the section-to-rule-ID mapping in
//! `docs/semantic_docs_rule_mapping.md` is internally consistent and
//! covers all 47 canonical rule IDs.
//!
//! Bead: asupersync-3cddg.5.1
//! Rule IDs verified: all 47

/// All 47 canonical rule IDs from SEM-04.1.
const CANONICAL_RULE_IDS: [&str; 47] = [
    "rule.cancel.request",
    "rule.cancel.acknowledge",
    "rule.cancel.drain",
    "rule.cancel.finalize",
    "inv.cancel.idempotence",
    "inv.cancel.propagates_down",
    "def.cancel.reason_kinds",
    "def.cancel.severity_ordering",
    "prog.cancel.drains",
    "rule.cancel.checkpoint_masked",
    "inv.cancel.mask_bounded",
    "inv.cancel.mask_monotone",
    "rule.obligation.reserve",
    "rule.obligation.commit",
    "rule.obligation.abort",
    "rule.obligation.leak",
    "inv.obligation.no_leak",
    "inv.obligation.linear",
    "inv.obligation.bounded",
    "inv.obligation.ledger_empty_on_close",
    "prog.obligation.resolves",
    "rule.region.close_begin",
    "rule.region.close_cancel_children",
    "rule.region.close_children_done",
    "rule.region.close_run_finalizer",
    "rule.region.close_complete",
    "inv.region.quiescence",
    "prog.region.close_terminates",
    "def.outcome.four_valued",
    "def.outcome.severity_lattice",
    "def.outcome.join_semantics",
    "def.cancel.reason_ordering",
    "inv.ownership.single_owner",
    "inv.ownership.task_owned",
    "def.ownership.region_tree",
    "rule.ownership.spawn",
    "comb.join",
    "comb.race",
    "comb.timeout",
    "inv.combinator.loser_drained",
    "law.race.never_abandon",
    "law.join.assoc",
    "law.race.comm",
    "inv.capability.no_ambient",
    "def.capability.cx_scope",
    "inv.determinism.replayable",
    "def.determinism.seed_equivalence",
];

/// Rule IDs documented as gap (not mapped to FOS sections).
const GAP_RULE_IDS: [&str; 2] = ["inv.capability.no_ambient", "def.capability.cx_scope"];

fn load_mapping_doc() -> String {
    std::fs::read_to_string("docs/semantic_docs_rule_mapping.md")
        .expect("failed to load docs/semantic_docs_rule_mapping.md")
}

fn load_fos_doc() -> String {
    std::fs::read_to_string("docs/asupersync_v4_formal_semantics.md")
        .expect("failed to load docs/asupersync_v4_formal_semantics.md")
}

#[test]
fn mapping_references_all_canonical_rule_ids() {
    let mapping = load_mapping_doc();

    let mut missing = Vec::new();
    for rule_id in &CANONICAL_RULE_IDS {
        if !mapping.contains(rule_id) {
            missing.push(*rule_id);
        }
    }

    assert!(
        missing.is_empty(),
        "Mapping doc is missing {} rule IDs: {:?}",
        missing.len(),
        missing
    );
}

#[test]
fn mapping_machine_lintable_index_present() {
    let mapping = load_mapping_doc();

    // The machine-lintable index section must exist
    assert!(
        mapping.contains("## 6. Machine-Lintable Rule-ID Index"),
        "mapping doc must contain machine-lintable index section"
    );

    // Extract the index lines (between ``` markers in section 6)
    let index_start = mapping
        .find("# Format: FOS_SECTION")
        .expect("index must have format header");
    let index_section = &mapping[index_start..];
    let index_end = index_section.find("```").unwrap_or(index_section.len());
    let index = &index_section[..index_end];

    // Count entries
    let entry_count = index
        .lines()
        .filter(|line| line.contains('|') && !line.starts_with('#'))
        .count();
    assert!(
        entry_count >= 45,
        "machine-lintable index must have at least 45 entries (got {entry_count})"
    );
}

#[test]
fn mapping_machine_lintable_index_valid_rule_ids() {
    let mapping = load_mapping_doc();

    let index_start = mapping
        .find("# Format: FOS_SECTION")
        .expect("index must have format header");
    let index_section = &mapping[index_start..];
    let index_end = index_section.find("```").unwrap_or(index_section.len());
    let index = &index_section[..index_end];

    for line in index.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        assert!(
            parts.len() == 4,
            "index line must have 4 pipe-separated fields: {line}"
        );
        let rule_id = parts[2].trim();
        assert!(
            CANONICAL_RULE_IDS.contains(&rule_id),
            "index references unknown rule_id: '{rule_id}' in line: {line}"
        );
    }
}

#[test]
fn mapping_gap_rules_documented() {
    let mapping = load_mapping_doc();

    for rule_id in &GAP_RULE_IDS {
        // Gap rules must appear in the coverage gaps section
        assert!(
            mapping.contains(&format!("`{rule_id}`")),
            "gap rule {rule_id} must be documented in mapping"
        );
    }

    // Coverage summary must mention 45/47
    assert!(
        mapping.contains("45/47"),
        "coverage summary must note 45/47 mapped rules"
    );
}

#[test]
fn mapping_coverage_summary_accurate() {
    let mapping = load_mapping_doc();

    // Domain coverage must show correct totals
    let expected_domains = [
        ("cancel", "12/12"),
        ("obligation", "9/9"),
        ("region", "7/7"),
        ("outcome", "4/4"),
        ("ownership", "4/4"),
        ("combinator", "7/7"),
        ("capability", "0/2"),
        ("determinism", "2/2"),
    ];

    for (domain, coverage) in &expected_domains {
        assert!(
            mapping.contains(coverage),
            "domain '{domain}' coverage '{coverage}' not found in summary"
        );
    }
}

#[test]
fn mapping_abstraction_simplifications_documented() {
    let mapping = load_mapping_doc();

    // CancelKind simplification must be documented
    assert!(
        mapping.contains("CancelKind Simplification"),
        "CancelKind simplification must be documented"
    );
    assert!(
        mapping.contains("11 variants"),
        "must note runtime has 11 CancelKind variants"
    );

    // Budget simplification must be documented
    assert!(
        mapping.contains("Budget Algebra Simplification"),
        "budget simplification must be documented"
    );
}

#[test]
fn mapping_terminology_check_aligned() {
    let mapping = load_mapping_doc();

    // Key terms must appear in terminology alignment table
    let key_terms = [
        "Outcome",
        "Severity",
        "CancelReason",
        "CancelKind",
        "Budget",
        "TaskState",
        "RegionState",
        "ObligationState",
        "ObligationKind",
        "Quiescent(r)",
        "LoserDrained(t1,t2)",
    ];

    for term in &key_terms {
        assert!(
            mapping.contains(term),
            "term '{term}' must appear in terminology alignment"
        );
    }
}

#[test]
fn fos_section_headers_exist() {
    let fos = load_fos_doc();

    // Verify key sections referenced in the mapping actually exist in the FOS
    let expected_sections = [
        "## 1. Domains",
        "### 1.2 Outcomes",
        "### 1.3 Cancel Reasons",
        "### 1.7 Obligation States",
        "### 1.9 Linear resources",
        "## 3. Transition Rules",
        "### 3.1 Task Lifecycle",
        "### 3.2 Cancellation Protocol",
        "### 3.3 Region Lifecycle",
        "### 3.4 Obligations",
        "## 4. Derived Combinators",
        "## 5. Invariants",
        "## 6. Progress Properties",
        "## 7. Algebraic Laws",
        "## 8. Test Oracle Usage",
    ];

    for section in &expected_sections {
        assert!(
            fos.contains(section),
            "FOS must contain section header: {section}"
        );
    }
}

#[test]
fn fos_transition_rules_mentioned_in_mapping() {
    let mapping = load_mapping_doc();

    // All major FOS transition names must appear in the mapping
    let transition_names = [
        "SPAWN",
        "CANCEL-REQUEST",
        "CANCEL-ACKNOWLEDGE",
        "CHECKPOINT-MASKED",
        "CANCEL-DRAIN",
        "CANCEL-FINALIZE",
        "CLOSE-BEGIN",
        "CLOSE-CANCEL-CHILDREN",
        "CLOSE-CHILDREN-DONE",
        "CLOSE-RUN-FINALIZER",
        "CLOSE-COMPLETE",
        "RESERVE",
        "COMMIT",
        "ABORT",
        "LEAK",
    ];

    for name in &transition_names {
        assert!(
            mapping.contains(name),
            "mapping must reference FOS transition: {name}"
        );
    }
}

#[test]
fn fos_invariant_names_mentioned_in_mapping() {
    let mapping = load_mapping_doc();

    let invariant_names = [
        "INV-TREE",
        "INV-TASK-OWNED",
        "INV-QUIESCENCE",
        "INV-CANCEL-PROPAGATES",
        "INV-OBLIGATION-BOUNDED",
        "INV-OBLIGATION-LINEAR",
        "INV-LEDGER-EMPTY",
        "INV-MASK-BOUNDED",
        "INV-LOSER-DRAINED",
    ];

    for name in &invariant_names {
        assert!(
            mapping.contains(name),
            "mapping must reference FOS invariant: {name}"
        );
    }
}
