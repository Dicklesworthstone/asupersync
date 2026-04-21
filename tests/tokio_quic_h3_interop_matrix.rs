#![allow(clippy::all)]
#![allow(clippy::cast_precision_loss)]
//! Contract tests for the QUIC/H3 Interoperability Matrix.
//!
//! Bead: asupersync-2oh2u.4.6 ([T4.6])
//!
//! Validates:
//! 1. Machine-readable JSON artifact consistency and completeness
//! 2. Gap register integrity (IDs, priorities, severities)
//! 3. Peer compatibility scores within valid bounds
//! 4. Drift detection rule coverage
//! 5. Cross-implementation issue linkage to gaps
//! 6. Summary metrics consistency

#[macro_use]
mod common;

mod asupersync {
    pub use crate::test_complete;
}

use std::collections::HashSet;

/// Load the JSON artifact at compile time.
const MATRIX_JSON: &str = include_str!("../docs/tokio_quic_h3_interop_matrix.json");
/// Load the markdown artifact at compile time.
const MATRIX_MD: &str = include_str!("../docs/tokio_quic_h3_interop_matrix.md");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(MATRIX_JSON).expect("matrix JSON must parse")
}

fn init_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

// ════════════════════════════════════════════════════════════════════════
// JSON Structural Integrity
// ════════════════════════════════════════════════════════════════════════

#[test]
fn json_parses_and_has_required_fields() {
    init_test("json_parses_and_has_required_fields");
    let v = parse_json();
    assert!(v.get("bead_id").is_some(), "missing bead_id");
    assert!(v.get("title").is_some(), "missing title");
    assert!(v.get("version").is_some(), "missing version");
    assert!(v.get("generated_at").is_some(), "missing generated_at");
    assert!(v.get("generated_by").is_some(), "missing generated_by");
    assert!(
        v.get("source_markdown").is_some(),
        "missing source_markdown"
    );
    assert!(v.get("domains").is_some(), "missing domains");
    assert!(v.get("peers").is_some(), "missing peers");
    assert!(
        v.get("asupersync_stack").is_some(),
        "missing asupersync_stack"
    );
    assert!(v.get("transport_gaps").is_some(), "missing transport_gaps");
    assert!(v.get("h3_gaps").is_some(), "missing h3_gaps");
    assert!(
        v.get("cross_impl_issues").is_some(),
        "missing cross_impl_issues"
    );
    assert!(v.get("summary").is_some(), "missing summary");
    assert!(
        v.get("drift_detection").is_some(),
        "missing drift_detection"
    );
    asupersync::test_complete!("json_parses_and_has_required_fields");
}

#[test]
fn bead_id_matches() {
    init_test("bead_id_matches");
    let v = parse_json();
    assert_eq!(v["bead_id"].as_str().unwrap(), "asupersync-2oh2u.4.6");
    asupersync::test_complete!("bead_id_matches");
}

#[test]
fn domains_include_quic_and_h3() {
    init_test("domains_include_quic_and_h3");
    let v = parse_json();
    let domains: Vec<&str> = v["domains"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d.as_str())
        .collect();
    assert!(domains.contains(&"quic"), "missing quic domain");
    assert!(domains.contains(&"http3"), "missing http3 domain");
    assert!(
        domains.contains(&"interoperability"),
        "missing interoperability domain"
    );
    asupersync::test_complete!("domains_include_quic_and_h3");
}

// ════════════════════════════════════════════════════════════════════════
// Peer Inventory
// ════════════════════════════════════════════════════════════════════════

#[test]
fn minimum_five_peers() {
    init_test("minimum_five_peers");
    let v = parse_json();
    let peers = v["peers"].as_array().unwrap();
    assert!(peers.len() >= 5, "expected >= 5 peers, got {}", peers.len());
    asupersync::test_complete!("minimum_five_peers");
}

#[test]
fn peers_have_required_fields() {
    init_test("peers_have_required_fields");
    let v = parse_json();
    for peer in v["peers"].as_array().unwrap() {
        let name = peer
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<missing>");
        assert!(
            peer.get("version_baseline").is_some(),
            "{name}: missing version_baseline"
        );
        assert!(peer.get("language").is_some(), "{name}: missing language");
        assert!(peer.get("role").is_some(), "{name}: missing role");
        assert!(
            peer.get("compatibility_score").is_some(),
            "{name}: missing compatibility_score"
        );
        assert!(
            peer.get("compatibility_breakdown").is_some(),
            "{name}: missing compatibility_breakdown"
        );
    }
    asupersync::test_complete!("peers_have_required_fields");
}

#[test]
fn peer_compatibility_scores_in_range() {
    init_test("peer_compatibility_scores_in_range");
    let v = parse_json();
    for peer in v["peers"].as_array().unwrap() {
        let name = peer["name"].as_str().unwrap();
        let score = peer["compatibility_score"].as_f64().unwrap();
        assert!(
            (0.0..=1.0).contains(&score),
            "{name}: score {score} not in [0.0, 1.0]"
        );
    }
    asupersync::test_complete!("peer_compatibility_scores_in_range");
}

#[test]
fn peer_breakdown_values_in_range() {
    init_test("peer_breakdown_values_in_range");
    let v = parse_json();
    for peer in v["peers"].as_array().unwrap() {
        let name = peer["name"].as_str().unwrap();
        let breakdown = peer["compatibility_breakdown"].as_object().unwrap();
        for (area, val) in breakdown {
            let score = val.as_f64().unwrap();
            assert!(
                (0.0..=1.0).contains(&score),
                "{name}.{area}: score {score} not in [0.0, 1.0]"
            );
        }
    }
    asupersync::test_complete!("peer_breakdown_values_in_range");
}

#[test]
fn peer_names_include_key_implementations() {
    init_test("peer_names_include_key_implementations");
    let v = parse_json();
    let names: HashSet<&str> = v["peers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert!(names.contains("quinn"), "missing quinn peer");
    assert!(names.contains("s2n-quic"), "missing s2n-quic peer");
    assert!(names.contains("ngtcp2"), "missing ngtcp2 peer");
    asupersync::test_complete!("peer_names_include_key_implementations");
}

#[test]
fn cross_language_peer_present() {
    init_test("cross_language_peer_present");
    let v = parse_json();
    let has_non_rust = v["peers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["language"].as_str().is_some_and(|lang| lang != "Rust"));
    assert!(
        has_non_rust,
        "must include at least one non-Rust peer for cross-language validation"
    );
    asupersync::test_complete!("cross_language_peer_present");
}

// ════════════════════════════════════════════════════════════════════════
// Asupersync Stack Metadata
// ════════════════════════════════════════════════════════════════════════

#[test]
fn stack_layers_present() {
    init_test("stack_layers_present");
    let v = parse_json();
    let layers = v["asupersync_stack"]["layers"].as_array().unwrap();
    assert!(
        layers.len() >= 4,
        "expected >= 4 stack layers, got {}",
        layers.len()
    );

    let layer_names: HashSet<&str> = layers.iter().filter_map(|l| l["name"].as_str()).collect();
    assert!(
        layer_names.contains("protocol_core"),
        "missing protocol_core layer"
    );
    assert!(
        layer_names.contains("native_connection"),
        "missing native_connection layer"
    );
    assert!(layer_names.contains("h3_codec"), "missing h3_codec layer");
    asupersync::test_complete!("stack_layers_present");
}

#[test]
fn stack_total_loc_positive() {
    init_test("stack_total_loc_positive");
    let v = parse_json();
    let total = v["asupersync_stack"]["total_loc"].as_u64().unwrap();
    assert!(total > 5000, "total_loc {total} seems too low");
    asupersync::test_complete!("stack_total_loc_positive");
}

#[test]
fn stack_test_files_listed() {
    init_test("stack_test_files_listed");
    let v = parse_json();
    let test_files = v["asupersync_stack"]["test_files"].as_array().unwrap();
    assert!(
        test_files.len() >= 3,
        "expected >= 3 test files, got {}",
        test_files.len()
    );
    asupersync::test_complete!("stack_test_files_listed");
}

// ════════════════════════════════════════════════════════════════════════
// Transport Gap Register
// ════════════════════════════════════════════════════════════════════════

#[test]
fn transport_gaps_non_empty() {
    init_test("transport_gaps_non_empty");
    let v = parse_json();
    let gaps = v["transport_gaps"].as_array().unwrap();
    assert!(
        gaps.len() >= 10,
        "expected >= 10 transport gaps, got {}",
        gaps.len()
    );
    asupersync::test_complete!("transport_gaps_non_empty");
}

#[test]
fn transport_gap_ids_unique() {
    init_test("transport_gap_ids_unique");
    let v = parse_json();
    let ids: Vec<&str> = v["transport_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["id"].as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(
        ids.len(),
        unique.len(),
        "duplicate transport gap IDs detected"
    );
    asupersync::test_complete!("transport_gap_ids_unique");
}

#[test]
fn transport_gap_ids_prefixed() {
    init_test("transport_gap_ids_prefixed");
    let v = parse_json();
    for gap in v["transport_gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(
            id.starts_with("QI-G"),
            "transport gap ID {id} must start with QI-G"
        );
    }
    asupersync::test_complete!("transport_gap_ids_prefixed");
}

#[test]
fn transport_gaps_have_required_fields() {
    init_test("transport_gaps_have_required_fields");
    let v = parse_json();
    let valid_severities: HashSet<&str> = ["critical", "high", "medium", "low"]
        .iter()
        .copied()
        .collect();
    let valid_priorities: HashSet<&str> = ["P0", "P1", "P2"].iter().copied().collect();

    for gap in v["transport_gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(gap.get("title").is_some(), "{id}: missing title");
        assert!(gap.get("severity").is_some(), "{id}: missing severity");
        assert!(gap.get("priority").is_some(), "{id}: missing priority");
        assert!(
            gap.get("blocking_bead").is_some(),
            "{id}: missing blocking_bead"
        );

        let sev = gap["severity"].as_str().unwrap();
        assert!(
            valid_severities.contains(sev),
            "{id}: invalid severity '{sev}'"
        );

        let pri = gap["priority"].as_str().unwrap();
        assert!(
            valid_priorities.contains(pri),
            "{id}: invalid priority '{pri}'"
        );
    }
    asupersync::test_complete!("transport_gaps_have_required_fields");
}

// ════════════════════════════════════════════════════════════════════════
// HTTP/3 Gap Register
// ════════════════════════════════════════════════════════════════════════

#[test]
fn h3_gaps_non_empty() {
    init_test("h3_gaps_non_empty");
    let v = parse_json();
    let gaps = v["h3_gaps"].as_array().unwrap();
    assert!(gaps.len() >= 8, "expected >= 8 H3 gaps, got {}", gaps.len());
    asupersync::test_complete!("h3_gaps_non_empty");
}

#[test]
fn h3_gap_ids_unique() {
    init_test("h3_gap_ids_unique");
    let v = parse_json();
    let ids: Vec<&str> = v["h3_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["id"].as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate H3 gap IDs detected");
    asupersync::test_complete!("h3_gap_ids_unique");
}

#[test]
fn h3_gap_ids_prefixed() {
    init_test("h3_gap_ids_prefixed");
    let v = parse_json();
    for gap in v["h3_gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(
            id.starts_with("H3I-G"),
            "H3 gap ID {id} must start with H3I-G"
        );
    }
    asupersync::test_complete!("h3_gap_ids_prefixed");
}

#[test]
fn h3_gaps_have_required_fields() {
    init_test("h3_gaps_have_required_fields");
    let v = parse_json();
    let valid_severities: HashSet<&str> = ["critical", "high", "medium", "low"]
        .iter()
        .copied()
        .collect();

    for gap in v["h3_gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(gap.get("title").is_some(), "{id}: missing title");
        assert!(gap.get("severity").is_some(), "{id}: missing severity");
        assert!(gap.get("priority").is_some(), "{id}: missing priority");

        let sev = gap["severity"].as_str().unwrap();
        assert!(
            valid_severities.contains(sev),
            "{id}: invalid severity '{sev}'"
        );
    }
    asupersync::test_complete!("h3_gaps_have_required_fields");
}

// ════════════════════════════════════════════════════════════════════════
// Cross-Implementation Issues
// ════════════════════════════════════════════════════════════════════════

#[test]
fn cross_impl_issues_non_empty() {
    init_test("cross_impl_issues_non_empty");
    let v = parse_json();
    let issues = v["cross_impl_issues"].as_array().unwrap();
    assert!(
        issues.len() >= 3,
        "expected >= 3 cross-impl issues, got {}",
        issues.len()
    );
    asupersync::test_complete!("cross_impl_issues_non_empty");
}

#[test]
fn cross_impl_ids_unique() {
    init_test("cross_impl_ids_unique");
    let v = parse_json();
    let ids: Vec<&str> = v["cross_impl_issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["id"].as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate cross-impl issue IDs");
    asupersync::test_complete!("cross_impl_ids_unique");
}

#[test]
fn cross_impl_issues_link_to_gaps() {
    init_test("cross_impl_issues_link_to_gaps");
    let v = parse_json();

    // Collect all gap IDs.
    let mut all_gap_ids: HashSet<String> = HashSet::new();
    for gap in v["transport_gaps"].as_array().unwrap() {
        all_gap_ids.insert(gap["id"].as_str().unwrap().to_string());
    }
    for gap in v["h3_gaps"].as_array().unwrap() {
        all_gap_ids.insert(gap["id"].as_str().unwrap().to_string());
    }

    // Every cross-impl issue must link to a known gap via blocked_by.
    for issue in v["cross_impl_issues"].as_array().unwrap() {
        let id = issue["id"].as_str().unwrap();
        let blocked_by = issue["blocked_by"].as_str().unwrap();
        assert!(
            all_gap_ids.contains(blocked_by),
            "cross-impl issue {id} references unknown gap {blocked_by}"
        );
    }
    asupersync::test_complete!("cross_impl_issues_link_to_gaps");
}

#[test]
fn cross_impl_issues_have_affected_peers() {
    init_test("cross_impl_issues_have_affected_peers");
    let v = parse_json();
    for issue in v["cross_impl_issues"].as_array().unwrap() {
        let id = issue["id"].as_str().unwrap();
        let peers = issue["affected_peers"].as_array().unwrap();
        assert!(
            !peers.is_empty(),
            "cross-impl issue {id} has no affected_peers"
        );
    }
    asupersync::test_complete!("cross_impl_issues_have_affected_peers");
}

// ════════════════════════════════════════════════════════════════════════
// Summary Metrics Consistency
// ════════════════════════════════════════════════════════════════════════

#[test]
fn summary_total_gaps_matches() {
    init_test("summary_total_gaps_matches");
    let v = parse_json();
    let transport_count = v["transport_gaps"].as_array().unwrap().len();
    let h3_count = v["h3_gaps"].as_array().unwrap().len();
    let claimed_transport = v["summary"]["total_transport_gaps"].as_u64().unwrap() as usize;
    let claimed_h3 = v["summary"]["total_h3_gaps"].as_u64().unwrap() as usize;
    let claimed_total = v["summary"]["total_gaps"].as_u64().unwrap() as usize;

    assert_eq!(
        transport_count, claimed_transport,
        "transport gap count mismatch"
    );
    assert_eq!(h3_count, claimed_h3, "h3 gap count mismatch");
    assert_eq!(
        transport_count + h3_count,
        claimed_total,
        "total gap count mismatch"
    );
    asupersync::test_complete!("summary_total_gaps_matches");
}

#[test]
fn summary_critical_count_matches() {
    init_test("summary_critical_count_matches");
    let v = parse_json();

    let mut p0_count = 0usize;
    for gap in v["transport_gaps"].as_array().unwrap() {
        if gap["priority"].as_str() == Some("P0") {
            p0_count += 1;
        }
    }
    for gap in v["h3_gaps"].as_array().unwrap() {
        if gap["priority"].as_str() == Some("P0") {
            p0_count += 1;
        }
    }

    let claimed = v["summary"]["critical_p0_gaps"].as_u64().unwrap() as usize;
    assert_eq!(
        p0_count, claimed,
        "P0 gap count mismatch: actual={p0_count}, claimed={claimed}"
    );
    asupersync::test_complete!("summary_critical_count_matches");
}

#[test]
fn summary_cross_impl_count_matches() {
    init_test("summary_cross_impl_count_matches");
    let v = parse_json();
    let actual = v["cross_impl_issues"].as_array().unwrap().len();
    let claimed = v["summary"]["cross_impl_issues"].as_u64().unwrap() as usize;
    assert_eq!(actual, claimed, "cross-impl issue count mismatch");
    asupersync::test_complete!("summary_cross_impl_count_matches");
}

#[test]
fn summary_best_worst_peer_in_peers() {
    init_test("summary_best_worst_peer_in_peers");
    let v = parse_json();
    let peer_names: HashSet<&str> = v["peers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();

    let best = v["summary"]["best_peer_compat"]["peer"].as_str().unwrap();
    let worst = v["summary"]["worst_peer_compat"]["peer"].as_str().unwrap();
    assert!(
        peer_names.contains(best),
        "best peer '{best}' not in peer list"
    );
    assert!(
        peer_names.contains(worst),
        "worst peer '{worst}' not in peer list"
    );
    asupersync::test_complete!("summary_best_worst_peer_in_peers");
}

// ════════════════════════════════════════════════════════════════════════
// Drift Detection
// ════════════════════════════════════════════════════════════════════════

#[test]
fn drift_rules_present() {
    init_test("drift_rules_present");
    let v = parse_json();
    let rules = v["drift_detection"]["rules"].as_array().unwrap();
    assert!(
        rules.len() >= 4,
        "expected >= 4 drift rules, got {}",
        rules.len()
    );

    let rule_ids: HashSet<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(rule_ids.contains("DRIFT-Q1"), "missing DRIFT-Q1 (new RFC)");
    assert!(
        rule_ids.contains("DRIFT-Q2"),
        "missing DRIFT-Q2 (quinn release)"
    );
    assert!(
        rule_ids.contains("DRIFT-Q4"),
        "missing DRIFT-Q4 (asupersync change)"
    );
    asupersync::test_complete!("drift_rules_present");
}

#[test]
fn staleness_policy_present() {
    init_test("staleness_policy_present");
    let v = parse_json();
    let policy = v["drift_detection"]["staleness_policy"]
        .as_object()
        .unwrap();
    assert!(
        policy.contains_key("markdown_max_age_days"),
        "missing markdown max age"
    );
    assert!(
        policy.contains_key("json_max_age_days"),
        "missing json max age"
    );
    assert!(
        policy.contains_key("test_suite_trigger"),
        "missing test suite trigger"
    );
    assert!(
        policy.contains_key("peer_baseline_max_age_days"),
        "missing peer baseline max age"
    );
    asupersync::test_complete!("staleness_policy_present");
}

// ════════════════════════════════════════════════════════════════════════
// Markdown Cross-Reference
// ════════════════════════════════════════════════════════════════════════

#[test]
fn markdown_references_all_transport_gaps() {
    init_test("markdown_references_all_transport_gaps");
    let v = parse_json();
    for gap in v["transport_gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(
            MATRIX_MD.contains(id),
            "transport gap {id} not found in markdown"
        );
    }
    asupersync::test_complete!("markdown_references_all_transport_gaps");
}

#[test]
fn markdown_references_all_h3_gaps() {
    init_test("markdown_references_all_h3_gaps");
    let v = parse_json();
    for gap in v["h3_gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(MATRIX_MD.contains(id), "h3 gap {id} not found in markdown");
    }
    asupersync::test_complete!("markdown_references_all_h3_gaps");
}

#[test]
fn markdown_references_all_cross_impl_issues() {
    init_test("markdown_references_all_cross_impl_issues");
    let v = parse_json();
    for issue in v["cross_impl_issues"].as_array().unwrap() {
        let id = issue["id"].as_str().unwrap();
        assert!(
            MATRIX_MD.contains(id),
            "cross-impl issue {id} not found in markdown"
        );
    }
    asupersync::test_complete!("markdown_references_all_cross_impl_issues");
}

#[test]
fn markdown_references_all_peers() {
    init_test("markdown_references_all_peers");
    let v = parse_json();
    for peer in v["peers"].as_array().unwrap() {
        let name = peer["name"].as_str().unwrap();
        assert!(
            MATRIX_MD.contains(name),
            "peer '{name}' not found in markdown"
        );
    }
    asupersync::test_complete!("markdown_references_all_peers");
}

#[test]
fn markdown_contains_heat_map() {
    init_test("markdown_contains_heat_map");
    assert!(
        MATRIX_MD.contains("Heat Map") || MATRIX_MD.contains("heat map"),
        "markdown must contain compatibility heat map"
    );
    asupersync::test_complete!("markdown_contains_heat_map");
}

#[test]
fn markdown_contains_wave_plan() {
    init_test("markdown_contains_wave_plan");
    assert!(
        MATRIX_MD.contains("Wave 1") && MATRIX_MD.contains("Wave 2"),
        "markdown must contain interop readiness wave plan"
    );
    asupersync::test_complete!("markdown_contains_wave_plan");
}

// ════════════════════════════════════════════════════════════════════════
// RFC Coverage
// ════════════════════════════════════════════════════════════════════════

#[test]
fn gaps_reference_rfcs() {
    init_test("gaps_reference_rfcs");
    let v = parse_json();
    let mut rfc_referenced = 0;
    let total_gaps =
        v["transport_gaps"].as_array().unwrap().len() + v["h3_gaps"].as_array().unwrap().len();

    for gap in v["transport_gaps"].as_array().unwrap() {
        if gap.get("rfc").and_then(|r| r.as_str()).is_some() {
            rfc_referenced += 1;
        }
    }
    for gap in v["h3_gaps"].as_array().unwrap() {
        if gap.get("rfc").and_then(|r| r.as_str()).is_some() {
            rfc_referenced += 1;
        }
    }

    // At least 80% of gaps should reference an RFC.
    let coverage = f64::from(rfc_referenced) / total_gaps as f64;
    assert!(
        coverage >= 0.80,
        "RFC coverage {coverage:.2} below 0.80 threshold"
    );
    asupersync::test_complete!("gaps_reference_rfcs");
}

#[test]
fn core_rfcs_referenced_in_markdown() {
    init_test("core_rfcs_referenced_in_markdown");
    // RFC 9000 (QUIC), 9001 (TLS), 9002 (Loss), 9114 (HTTP/3), 9204 (QPACK)
    let required_rfcs = ["9000", "9001", "9002", "9114", "9204"];
    for rfc in &required_rfcs {
        assert!(
            MATRIX_MD.contains(rfc),
            "RFC {rfc} not referenced in markdown"
        );
    }
    asupersync::test_complete!("core_rfcs_referenced_in_markdown");
}
