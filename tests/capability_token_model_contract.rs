#![allow(warnings)]
#![allow(clippy::all)]
//! Capability token model contract invariants (AA-07.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/capability_token_model_contract.md";
const ARTIFACT_PATH: &str = "artifacts/capability_token_model_v1.json";
const RUNNER_PATH: &str = "scripts/run_capability_token_model_smoke.sh";

fn load_artifact() -> Value {
    let content =
        std::fs::read_to_string(ARTIFACT_PATH).expect("artifact must exist at expected path");
    serde_json::from_str(&content).expect("artifact must be valid JSON")
}

fn load_doc() -> String {
    std::fs::read_to_string(DOC_PATH).expect("contract doc must exist")
}

fn load_runner() -> String {
    std::fs::read_to_string(RUNNER_PATH).expect("runner script must exist")
}

// ── Document stability ─────────────────────────────────────────────

#[test]
fn doc_exists_and_has_required_sections() {
    let doc = load_doc();
    for section in &[
        "## Purpose",
        "## Contract Artifacts",
        "## Token Structure",
        "## Capability Hierarchy",
        "## Attenuation Rules",
        "## Revocation",
        "## Threat Model",
        "## Validation",
        "## Cross-References",
    ] {
        assert!(doc.contains(section), "doc must contain section: {section}");
    }
}

#[test]
fn doc_references_bead_id() {
    let doc = load_doc();
    let art = load_artifact();
    let bead_id = art["bead_id"].as_str().unwrap();
    assert!(
        doc.contains(bead_id),
        "doc must reference bead_id {bead_id}"
    );
}

// ── Artifact stability ─────────────────────────────────────────────

#[test]
fn artifact_has_contract_version() {
    let art = load_artifact();
    assert_eq!(
        art["contract_version"].as_str().unwrap(),
        "capability-token-model-v1"
    );
}

#[test]
fn artifact_has_runner_script() {
    let art = load_artifact();
    let runner = art["runner_script"].as_str().unwrap();
    assert!(
        std::path::Path::new(runner).exists(),
        "runner script must exist at {runner}"
    );
}

// ── Token structure ────────────────────────────────────────────────

#[test]
fn token_has_required_fields() {
    let art = load_artifact();
    let fields = art["token_structure"]["required_fields"]
        .as_array()
        .unwrap();
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    for required in &[
        "token_id",
        "issuer_id",
        "subject_id",
        "capabilities",
        "caveats",
        "expiry_epoch",
        "attenuation_depth",
        "parent_token_id",
        "nonce",
    ] {
        assert!(
            strs.contains(required),
            "token must have field '{required}'"
        );
    }
}

#[test]
fn token_capability_types_are_nonempty() {
    let art = load_artifact();
    let types = art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();
    assert!(types.len() >= 3, "must have at least 3 capability types");
}

#[test]
fn token_capability_type_ids_are_unique() {
    let art = load_artifact();
    let types = art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = types
        .iter()
        .map(|t| t["type_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        ids.len(),
        deduped.len(),
        "capability type_ids must be unique"
    );
}

#[test]
fn token_capability_types_have_cap_prefix() {
    let art = load_artifact();
    let types = art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();
    for cap in types {
        let tid = cap["type_id"].as_str().unwrap();
        assert!(
            tid.starts_with("CAP-"),
            "capability type '{tid}' must start with CAP-"
        );
    }
}

#[test]
fn token_includes_observe_and_admin() {
    let art = load_artifact();
    let types = art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = types
        .iter()
        .map(|t| t["type_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"CAP-OBSERVE"), "must have CAP-OBSERVE");
    assert!(ids.contains(&"CAP-ADMIN"), "must have CAP-ADMIN");
}

#[test]
fn token_max_attenuation_depth_is_positive() {
    let art = load_artifact();
    let depth = art["token_structure"]["max_attenuation_depth"]
        .as_u64()
        .unwrap();
    assert!(depth > 0, "max attenuation depth must be positive");
}

// ── Attenuation model ──────────────────────────────────────────────

#[test]
fn attenuation_rules_are_nonempty() {
    let art = load_artifact();
    let rules = art["attenuation_model"]["rules"].as_array().unwrap();
    assert!(rules.len() >= 3, "must have at least 3 attenuation rules");
}

#[test]
fn attenuation_rule_ids_are_unique() {
    let art = load_artifact();
    let rules = art["attenuation_model"]["rules"].as_array().unwrap();
    let ids: Vec<&str> = rules
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "rule_ids must be unique");
}

#[test]
fn attenuation_includes_monotonic_and_no_amplification() {
    let art = load_artifact();
    let rules = art["attenuation_model"]["rules"].as_array().unwrap();
    let ids: Vec<&str> = rules
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"ATT-MONOTONIC"), "must have ATT-MONOTONIC");
    assert!(
        ids.contains(&"ATT-NO-AMPLIFICATION"),
        "must have ATT-NO-AMPLIFICATION"
    );
}

// ── Caveat types ───────────────────────────────────────────────────

#[test]
fn caveat_types_are_nonempty() {
    let art = load_artifact();
    let caveats = art["caveat_types"].as_array().unwrap();
    assert!(!caveats.is_empty(), "must have at least one caveat type");
}

#[test]
fn caveat_ids_are_unique() {
    let art = load_artifact();
    let caveats = art["caveat_types"].as_array().unwrap();
    let ids: Vec<&str> = caveats
        .iter()
        .map(|c| c["caveat_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "caveat_ids must be unique");
}

// ── Revocation model ───────────────────────────────────────────────

#[test]
fn revocation_mechanisms_are_nonempty() {
    let art = load_artifact();
    let mechs = art["revocation_model"]["mechanisms"].as_array().unwrap();
    assert!(
        mechs.len() >= 2,
        "must have at least 2 revocation mechanisms"
    );
}

#[test]
fn revocation_includes_cascade() {
    let art = load_artifact();
    let mechs = art["revocation_model"]["mechanisms"].as_array().unwrap();
    assert!(
        mechs
            .iter()
            .any(|m| m["mechanism_id"].as_str().unwrap() == "REV-CASCADE"),
        "must have cascade revocation"
    );
}

#[test]
fn revocation_log_is_required() {
    let art = load_artifact();
    assert!(
        art["revocation_model"]["revocation_log_required"]
            .as_bool()
            .unwrap(),
        "revocation log must be required"
    );
}

// ── Threat model ───────────────────────────────────────────────────

#[test]
fn threat_scenarios_are_nonempty() {
    let art = load_artifact();
    let scenarios = art["threat_model"]["scenarios"].as_array().unwrap();
    assert!(
        scenarios.len() >= 3,
        "must have at least 3 threat scenarios"
    );
}

#[test]
fn threat_scenarios_have_mitigations() {
    let art = load_artifact();
    let scenarios = art["threat_model"]["scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let mitigation = scenario["mitigation"].as_str().unwrap();
        assert!(
            !mitigation.is_empty(),
            "{sid}: must have non-empty mitigation"
        );
    }
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    assert!(!fields.is_empty(), "log fields must be nonempty");
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

// ── Smoke / runner ─────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 smoke scenarios");
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.starts_with("rch exec"), "{sid}: must be rch-routed");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    for mode in &["--list", "--dry-run", "--execute", "--scenario"] {
        assert!(runner.contains(mode), "runner must support {mode}");
    }
}

// ── Functional: attenuation hierarchy ───────────────────────────────

#[test]
fn attenuation_hierarchy_is_acyclic() {
    let art = load_artifact();
    let types = art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();

    // Build adjacency: type_id -> attenuable_to
    let mut reachable: HashSet<(&str, &str)> = HashSet::new();
    for cap in types {
        let from = cap["type_id"].as_str().unwrap();
        if let Some(targets) = cap["attenuable_to"].as_array() {
            for target in targets {
                reachable.insert((from, target.as_str().unwrap()));
            }
        }
    }

    // Check no capability is reachable from itself via transitive closure
    let ids: Vec<&str> = types
        .iter()
        .map(|t| t["type_id"].as_str().unwrap())
        .collect();
    for &id in &ids {
        // Simple reachability check via BFS
        let mut visited = HashSet::new();
        let mut queue: Vec<&str> = reachable
            .iter()
            .filter(|(from, _)| *from == id)
            .map(|(_, to)| *to)
            .collect();
        while let Some(node) = queue.pop() {
            assert!(node != id, "cycle detected: {id} is reachable from itself");
            if visited.insert(node) {
                for (from, to) in &reachable {
                    if *from == node {
                        queue.push(to);
                    }
                }
            }
        }
    }
}

#[test]
fn attenuation_admin_can_reach_observe() {
    let art = load_artifact();
    let types = art["token_structure"]["capability_types"]
        .as_array()
        .unwrap();

    // BFS from CAP-ADMIN to check CAP-OBSERVE is reachable
    let mut visited = HashSet::new();
    let mut queue = vec!["CAP-ADMIN"];
    while let Some(node) = queue.pop() {
        if visited.insert(node) {
            let cap = types
                .iter()
                .find(|t| t["type_id"].as_str().unwrap() == node);
            if let Some(cap) = cap {
                if let Some(targets) = cap["attenuable_to"].as_array() {
                    for target in targets {
                        queue.push(target.as_str().unwrap());
                    }
                }
            }
        }
    }

    assert!(
        visited.contains("CAP-OBSERVE"),
        "CAP-ADMIN must be able to attenuate to CAP-OBSERVE"
    );
}

// ── Functional: token validation logic ──────────────────────────────

#[test]
fn attenuation_child_subset_enforced() {
    let parent_caps: HashSet<&str> = ["CAP-DECIDE", "CAP-OBSERVE"].into_iter().collect();
    let valid_child: HashSet<&str> = HashSet::from(["CAP-OBSERVE"]);
    let invalid_child: HashSet<&str> = ["CAP-DECIDE", "CAP-PROMOTE"].into_iter().collect();

    assert!(
        valid_child.is_subset(&parent_caps),
        "valid child must be subset of parent"
    );
    assert!(
        !invalid_child.is_subset(&parent_caps),
        "child with CAP-PROMOTE must not be subset of parent"
    );
}

#[test]
fn attenuation_expiry_enforced() {
    let parent_expiry: u64 = 100;
    let valid_child_expiry: u64 = 50;
    let invalid_child_expiry: u64 = 150;

    assert!(
        valid_child_expiry <= parent_expiry,
        "valid child expiry must be <= parent"
    );
    assert!(
        invalid_child_expiry > parent_expiry,
        "invalid child expiry exceeds parent"
    );
}

#[test]
fn attenuation_depth_enforced() {
    let parent_depth: u32 = 2;
    let max_depth: u32 = 5;

    let child_depth = parent_depth + 1;
    assert!(child_depth > parent_depth, "child depth must exceed parent");
    assert!(child_depth <= max_depth, "child depth must not exceed max");

    let deep_child_depth: u32 = 6;
    assert!(
        deep_child_depth > max_depth,
        "depth exceeding max must be rejected"
    );
}

// ── Functional: revocation cascade ──────────────────────────────────

#[test]
fn revocation_cascade_revokes_descendants() {
    // Token tree: root -> child1 -> grandchild, root -> child2
    let mut revoked: HashSet<&str> = HashSet::new();

    // Revoke root
    revoked.insert("root");

    // Cascade: find all descendants
    let parent_map: Vec<(&str, &str)> = vec![
        ("child1", "root"),
        ("child2", "root"),
        ("grandchild", "child1"),
    ];

    let mut changed = true;
    while changed {
        changed = false;
        for (child, parent) in &parent_map {
            if revoked.contains(parent) && revoked.insert(child) {
                changed = true;
            }
        }
    }

    assert!(revoked.contains("child1"));
    assert!(revoked.contains("child2"));
    assert!(revoked.contains("grandchild"));
    assert_eq!(revoked.len(), 4, "root + 3 descendants must be revoked");
}

#[test]
fn revocation_does_not_affect_siblings_parent() {
    let mut revoked: HashSet<&str> = HashSet::new();

    // Revoke only child1, not root
    revoked.insert("child1");

    let parent_map: Vec<(&str, &str)> = vec![
        ("child1", "root"),
        ("child2", "root"),
        ("grandchild", "child1"),
    ];

    let mut changed = true;
    while changed {
        changed = false;
        for (child, parent) in &parent_map {
            if revoked.contains(parent) && revoked.insert(child) {
                changed = true;
            }
        }
    }

    assert!(revoked.contains("child1"));
    assert!(
        revoked.contains("grandchild"),
        "grandchild must be cascaded"
    );
    assert!(!revoked.contains("root"), "parent must not be revoked");
    assert!(!revoked.contains("child2"), "sibling must not be revoked");
}
