//! Contract tests for the Tokio non-functional closure criteria (2oh2u.1.2.3).
//!
//! Validates that the criteria document covers all 28 capability domains,
//! uses consistent threshold formats, and includes regression gates.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// All 28 capability domain IDs from the functional parity contracts.
const DOMAIN_IDS: &[&str] = &[
    "NF01", "NF02", "NF03", "NF04", "NF05", "NF06", "NF07", "NF08", "NF09", "NF10", "NF11", "NF12",
    "NF13", "NF14", "NF15", "NF16", "NF17", "NF18", "NF19", "NF20", "NF21", "NF22", "NF23", "NF24",
    "NF25", "NF26", "NF27", "NF28",
];

/// Domains that are deferred (M0/M1 maturity).
const DEFERRED_DOMAINS: &[&str] = &["NF15", "NF28"];

/// Reliability/stability criteria IDs.
const RELIABILITY_IDS: &[&str] = &["RS01", "RS02", "RS03", "RS04", "RS05", "RS06", "RS07"];

fn load_criteria_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_nonfunctional_closure_criteria.md");
    std::fs::read_to_string(path).expect("criteria document must exist")
}

fn extract_domain_sections(doc: &str) -> BTreeMap<String, String> {
    let mut sections = BTreeMap::new();
    let mut current_domain = None;
    let mut current_content = String::new();

    for line in doc.lines() {
        if line.starts_with("### NF") {
            if let Some(domain) = current_domain.take() {
                sections.insert(domain, current_content.clone());
            }
            let id = line
                .trim_start_matches('#')
                .trim()
                .split([' ', '\u{2014}'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            current_domain = Some(id);
            current_content.clear();
        } else if current_domain.is_some() {
            current_content.push_str(line);
            current_content.push('\n');
        }
    }
    if let Some(domain) = current_domain {
        sections.insert(domain, current_content);
    }
    sections
}

fn extract_criterion_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        // Match patterns like "NF01.1" or "RS01"
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim();
            if (id.starts_with("NF") || id.starts_with("RS"))
                && id.len() >= 4
                && id.chars().nth(2).is_some_and(|c| c.is_ascii_digit())
            {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn criteria_document_exists_and_is_nonempty() {
    let doc = load_criteria_doc();
    assert!(
        doc.len() > 1000,
        "criteria document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn criteria_document_references_correct_bead() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("asupersync-2oh2u.1.2.3"),
        "document must reference bead 2oh2u.1.2.3"
    );
    assert!(
        doc.contains("[T1.2.b]"),
        "document must reference track T1.2.b"
    );
}

#[test]
fn all_28_domains_have_sections() {
    let doc = load_criteria_doc();
    let sections = extract_domain_sections(&doc);

    for domain_id in DOMAIN_IDS {
        assert!(
            sections.contains_key(*domain_id),
            "missing section for domain {domain_id}"
        );
    }
}

#[test]
fn each_active_domain_has_at_least_three_criteria() {
    let doc = load_criteria_doc();
    let sections = extract_domain_sections(&doc);

    for domain_id in DOMAIN_IDS {
        if DEFERRED_DOMAINS.contains(domain_id) {
            continue;
        }
        let content = sections
            .get(*domain_id)
            .unwrap_or_else(|| panic!("missing section for {domain_id}"));
        let criterion_count = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim().trim_start_matches('|').trim();
                trimmed.starts_with(domain_id)
            })
            .count();
        assert!(
            criterion_count >= 3,
            "domain {domain_id} must have >= 3 criteria, found {criterion_count}"
        );
    }
}

#[test]
fn each_active_domain_has_regression_gate() {
    let doc = load_criteria_doc();
    let sections = extract_domain_sections(&doc);

    for domain_id in DOMAIN_IDS {
        if DEFERRED_DOMAINS.contains(domain_id) {
            continue;
        }
        let content = sections
            .get(*domain_id)
            .unwrap_or_else(|| panic!("missing section for {domain_id}"));
        assert!(
            content.contains("regression") || content.contains("NR gate"),
            "domain {domain_id} must include a no-regression gate"
        );
    }
}

#[test]
fn deferred_domains_are_marked() {
    let doc = load_criteria_doc();
    for domain_id in DEFERRED_DOMAINS {
        assert!(
            doc.contains(&format!("{domain_id} —")) || doc.contains(&format!("### {domain_id}")),
            "deferred domain {domain_id} must have a section"
        );
        assert!(
            doc.contains("[DEFERRED]"),
            "deferred domains must use [DEFERRED] marker"
        );
    }
}

#[test]
fn reliability_criteria_are_present() {
    let doc = load_criteria_doc();
    let ids = extract_criterion_ids(&doc);

    for rs_id in RELIABILITY_IDS {
        assert!(
            ids.contains(*rs_id),
            "missing reliability criterion {rs_id}"
        );
    }
}

#[test]
fn document_includes_measurement_methodology() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("Measurement Framework") || doc.contains("Measurement Conditions"),
        "document must include measurement methodology section"
    );
    assert!(
        doc.contains("release") || doc.contains("--release"),
        "benchmarks must specify release profile"
    );
}

#[test]
fn document_includes_regression_policy() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("Regression") && (doc.contains("20%") || doc.contains("Hard fail")),
        "document must include regression policy with hard-fail thresholds"
    );
}

#[test]
fn document_includes_resource_budget_constraints() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("Resource Budget"),
        "document must include resource budget section"
    );
    assert!(
        doc.contains("Per-Connection") || doc.contains("Per-Task"),
        "resource budgets must cover per-connection and per-task overhead"
    );
}

#[test]
fn document_includes_ci_integration() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("CI Integration") || doc.contains("CI Gate"),
        "document must include CI integration section"
    );
    assert!(
        doc.contains("cargo bench") || doc.contains("criterion"),
        "CI section must reference benchmark tooling"
    );
}

#[test]
fn domain_ids_are_monotonically_numbered() {
    let doc = load_criteria_doc();
    let ids = extract_criterion_ids(&doc);

    // Check that NF domains have sequential IDs
    let nf_ids: Vec<u8> = ids
        .iter()
        .filter(|id| id.starts_with("NF") && !id.contains('.'))
        .filter_map(|id| id[2..].parse::<u8>().ok())
        .collect();

    if !nf_ids.is_empty() {
        let min = *nf_ids.iter().min().unwrap();
        let max = *nf_ids.iter().max().unwrap();
        // Domains should span 1..=28
        assert_eq!(min, 1, "first domain should be NF01");
        assert_eq!(max, 28, "last domain should be NF28");
    }
}

#[test]
fn threshold_values_use_standard_units() {
    let doc = load_criteria_doc();
    // Check that common units are used consistently
    let has_microseconds = doc.contains("us") || doc.contains("μs");
    let has_milliseconds = doc.contains("ms");
    let has_throughput = doc.contains("msg/sec") || doc.contains("ops/sec") || doc.contains("/sec");
    let has_memory = doc.contains("bytes") || doc.contains("KB") || doc.contains("MB");

    assert!(
        has_microseconds,
        "document should include microsecond-level latency thresholds"
    );
    assert!(
        has_milliseconds,
        "document should include millisecond-level thresholds"
    );
    assert!(
        has_throughput,
        "document should include throughput thresholds"
    );
    assert!(has_memory, "document should include memory thresholds");
}

#[test]
fn criteria_count_is_comprehensive() {
    let doc = load_criteria_doc();
    let ids = extract_criterion_ids(&doc);

    // At minimum: 26 active domains * 3 criteria + 7 RS + deferred markers
    let nf_count = ids.iter().filter(|id| id.starts_with("NF")).count();
    let rs_count = ids.iter().filter(|id| id.starts_with("RS")).count();

    assert!(
        nf_count >= 80,
        "should have >= 80 NF criteria across 28 domains, found {nf_count}"
    );
    assert!(
        rs_count >= 7,
        "should have >= 7 RS criteria, found {rs_count}"
    );
}

#[test]
fn document_references_functional_parity_dependency() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("T1.2.a") || doc.contains("functional parity"),
        "document must reference T1.2.a (functional parity contracts) as dependency"
    );
}

#[test]
fn document_references_risk_register_dependency() {
    let doc = load_criteria_doc();
    assert!(
        doc.contains("T1.1.c") || doc.contains("risk register"),
        "document must reference T1.1.c (risk register) as dependency"
    );
}
