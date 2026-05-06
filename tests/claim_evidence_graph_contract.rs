//! Claim/evidence graph contract invariants (AA-10.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{HashMap, HashSet};

const DOC_PATH: &str = "docs/claim_evidence_graph_contract.md";
const ARTIFACT_PATH: &str = "artifacts/claim_evidence_graph_v1.json";
const RUNNER_PATH: &str = "scripts/run_claim_evidence_graph_smoke.sh";

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
        "## Graph Schema",
        "## Bundle Contract",
        "## Structured Logging Contract",
        "## Comparator-Smoke Runner",
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
        "claim-evidence-graph-v1"
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

// ── Schema: node types ─────────────────────────────────────────────

#[test]
fn schema_has_node_types() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    assert!(nodes.len() >= 5, "must have at least 5 node types");
}

#[test]
fn schema_node_types_have_required_fields() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    for node in nodes {
        let tid = node["type_id"].as_str().unwrap();
        assert!(
            node["description"].is_string(),
            "{tid}: must have description"
        );
        let fields = node["required_fields"].as_array().unwrap();
        assert!(
            !fields.is_empty(),
            "{tid}: must have at least one required field"
        );
    }
}

#[test]
fn schema_node_type_ids_are_unique() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    let ids: Vec<&str> = nodes
        .iter()
        .map(|n| n["type_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "node type_ids must be unique");
}

#[test]
fn schema_includes_core_node_types() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    let ids: Vec<&str> = nodes
        .iter()
        .map(|n| n["type_id"].as_str().unwrap())
        .collect();
    for required in &["CLAIM", "EVIDENCE", "POLICY", "TRACE", "TEST", "ROLLBACK"] {
        assert!(
            ids.contains(required),
            "schema must include node type {required}"
        );
    }
}

#[test]
fn schema_claim_has_status_values() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    let claim = nodes
        .iter()
        .find(|n| n["type_id"].as_str().unwrap() == "CLAIM")
        .unwrap();
    let statuses: Vec<&str> = claim["status_values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    for required in &["asserted", "evidenced", "verified", "revoked"] {
        assert!(
            statuses.contains(required),
            "CLAIM must have status '{required}'"
        );
    }
}

#[test]
fn schema_claim_has_category_values() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    let claim = nodes
        .iter()
        .find(|n| n["type_id"].as_str().unwrap() == "CLAIM")
        .unwrap();
    let categories: Vec<&str> = claim["category_values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(
        categories.contains(&"safety"),
        "CLAIM must have 'safety' category"
    );
    assert!(
        categories.contains(&"performance"),
        "CLAIM must have 'performance' category"
    );
}

// ── Schema: edge types ─────────────────────────────────────────────

#[test]
fn schema_has_edge_types() {
    let art = load_artifact();
    let edges = art["graph_schema"]["edge_types"].as_array().unwrap();
    assert!(edges.len() >= 5, "must have at least 5 edge types");
}

#[test]
fn schema_edge_types_have_required_fields() {
    let art = load_artifact();
    let edges = art["graph_schema"]["edge_types"].as_array().unwrap();
    for edge in edges {
        let eid = edge["edge_id"].as_str().unwrap();
        assert!(
            edge["from"].is_string(),
            "{eid}: must have 'from' node type"
        );
        assert!(edge["to"].is_string(), "{eid}: must have 'to' node type");
        assert!(
            edge["description"].is_string(),
            "{eid}: must have description"
        );
    }
}

#[test]
fn schema_edge_type_ids_are_unique() {
    let art = load_artifact();
    let edges = art["graph_schema"]["edge_types"].as_array().unwrap();
    let ids: Vec<&str> = edges
        .iter()
        .map(|e| e["edge_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "edge_ids must be unique");
}

#[test]
fn schema_edge_endpoints_reference_valid_node_types() {
    let art = load_artifact();
    let nodes = art["graph_schema"]["node_types"].as_array().unwrap();
    let node_ids: HashSet<&str> = nodes
        .iter()
        .map(|n| n["type_id"].as_str().unwrap())
        .collect();
    let edges = art["graph_schema"]["edge_types"].as_array().unwrap();
    for edge in edges {
        let eid = edge["edge_id"].as_str().unwrap();
        let from = edge["from"].as_str().unwrap();
        let to = edge["to"].as_str().unwrap();
        assert!(
            node_ids.contains(from),
            "{eid}: 'from' type '{from}' not in node types"
        );
        assert!(
            node_ids.contains(to),
            "{eid}: 'to' type '{to}' not in node types"
        );
    }
}

#[test]
fn schema_includes_supports_and_refutes_edges() {
    let art = load_artifact();
    let edges = art["graph_schema"]["edge_types"].as_array().unwrap();
    let ids: Vec<&str> = edges
        .iter()
        .map(|e| e["edge_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"SUPPORTS"), "must have SUPPORTS edge");
    assert!(ids.contains(&"REFUTES"), "must have REFUTES edge");
}

// ── Bundle contract ────────────────────────────────────────────────

#[test]
fn bundle_has_required_sections() {
    let art = load_artifact();
    let required = art["bundle_contract"]["required_sections"]
        .as_array()
        .unwrap();
    let strs: Vec<&str> = required.iter().map(|s| s.as_str().unwrap()).collect();
    for section in &["claims", "evidence", "policies", "edges"] {
        assert!(
            strs.contains(section),
            "bundle must require section '{section}'"
        );
    }
}

#[test]
fn bundle_validation_rules_are_nonempty() {
    let art = load_artifact();
    let rules = art["bundle_contract"]["validation_rules"]
        .as_array()
        .unwrap();
    assert!(!rules.is_empty(), "must have at least one validation rule");
}

#[test]
fn bundle_validation_rules_have_required_fields() {
    let art = load_artifact();
    let rules = art["bundle_contract"]["validation_rules"]
        .as_array()
        .unwrap();
    for rule in rules {
        let rid = rule["rule_id"].as_str().unwrap();
        assert!(
            rule["description"].is_string(),
            "{rid}: must have description"
        );
        let sev = rule["severity"].as_str().unwrap();
        assert!(
            sev == "error" || sev == "warning",
            "{rid}: severity must be error or warning, got {sev}"
        );
    }
}

#[test]
fn bundle_validation_rule_ids_are_unique() {
    let art = load_artifact();
    let rules = art["bundle_contract"]["validation_rules"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = rules
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "rule_ids must be unique");
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    assert!(!fields.is_empty(), "structured log fields must be nonempty");
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

// ── Smoke scenarios ────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 smoke scenarios");
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(
            cmd.starts_with("rch exec"),
            "{sid}: command must be rch-routed"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    assert!(runner.contains("--list"), "runner must support --list");
    assert!(
        runner.contains("--dry-run"),
        "runner must support --dry-run"
    );
    assert!(
        runner.contains("--execute"),
        "runner must support --execute"
    );
    assert!(
        runner.contains("--scenario"),
        "runner must support --scenario"
    );
}

// ── Functional: graph validation logic ──────────────────────────────

/// A minimal in-memory graph for validation testing.
struct TestGraph {
    claims: HashMap<String, TestClaim>,
    evidence: HashMap<String, TestEvidence>,
    policies: HashMap<String, TestPolicy>,
    edges: Vec<TestEdge>,
    rollbacks: HashMap<String, TestRollback>,
}

struct TestClaim {
    category: String,
    status: String,
}

struct TestEvidence {
    _kind: String,
}

struct TestPolicy {
    enforcement: String,
}

struct TestEdge {
    edge_type: String,
    from_id: String,
    to_id: String,
}

struct TestRollback {
    _claim_id: String,
    command: String,
}

impl TestGraph {
    fn new() -> Self {
        Self {
            claims: HashMap::new(),
            evidence: HashMap::new(),
            policies: HashMap::new(),
            edges: Vec::new(),
            rollbacks: HashMap::new(),
        }
    }

    /// V-CLAIM-EVIDENCE: evidenced/verified claims must have SUPPORTS edges
    fn validate_claim_evidence(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (cid, claim) in &self.claims {
            if claim.status == "evidenced" || claim.status == "verified" {
                let has_support = self
                    .edges
                    .iter()
                    .any(|e| e.edge_type == "SUPPORTS" && e.to_id == *cid);
                if !has_support {
                    errors.push(format!(
                        "V-CLAIM-EVIDENCE: claim {cid} is {status} but has no SUPPORTS edge",
                        status = claim.status
                    ));
                }
            }
        }
        errors
    }

    /// V-EDGE-REFS: all edge endpoints must reference existing nodes
    fn validate_edge_refs(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let all_ids: HashSet<&str> = self
            .claims
            .keys()
            .chain(self.evidence.keys())
            .chain(self.policies.keys())
            .chain(self.rollbacks.keys())
            .map(String::as_str)
            .collect();
        for edge in &self.edges {
            if !all_ids.contains(edge.from_id.as_str()) {
                errors.push(format!(
                    "V-EDGE-REFS: edge from '{}' references nonexistent node",
                    edge.from_id
                ));
            }
            if !all_ids.contains(edge.to_id.as_str()) {
                errors.push(format!(
                    "V-EDGE-REFS: edge to '{}' references nonexistent node",
                    edge.to_id
                ));
            }
        }
        errors
    }

    /// V-POLICY-COVERAGE: safety claims must have mandatory policy
    fn validate_policy_coverage(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (cid, claim) in &self.claims {
            if claim.category == "safety" {
                let has_mandatory_policy = self.edges.iter().any(|e| {
                    e.edge_type == "GOVERNS"
                        && e.to_id == *cid
                        && self
                            .policies
                            .get(&e.from_id)
                            .is_some_and(|p| p.enforcement == "mandatory")
                });
                if !has_mandatory_policy {
                    errors.push(format!(
                        "V-POLICY-COVERAGE: safety claim {cid} not governed by mandatory policy"
                    ));
                }
            }
        }
        errors
    }

    /// V-ROLLBACK-COMMAND: rollbacks must have non-empty commands
    fn validate_rollback_commands(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (rid, rb) in &self.rollbacks {
            if rb.command.is_empty() {
                errors.push(format!(
                    "V-ROLLBACK-COMMAND: rollback {rid} has empty command"
                ));
            }
        }
        errors
    }
}

#[test]
fn validation_claim_evidence_passes_with_supports_edge() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "evidenced".into(),
        },
    );
    g.evidence.insert(
        "E1".into(),
        TestEvidence {
            _kind: "test_result".into(),
        },
    );
    g.edges.push(TestEdge {
        edge_type: "SUPPORTS".into(),
        from_id: "E1".into(),
        to_id: "C1".into(),
    });
    let errors = g.validate_claim_evidence();
    assert!(errors.is_empty(), "should pass: {errors:?}");
}

#[test]
fn validation_claim_evidence_fails_without_supports_edge() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "verified".into(),
        },
    );
    let errors = g.validate_claim_evidence();
    assert_eq!(
        errors.len(),
        1,
        "should fail for unsupported verified claim"
    );
    assert!(errors[0].contains("V-CLAIM-EVIDENCE"));
}

#[test]
fn validation_claim_evidence_skips_asserted() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "asserted".into(),
        },
    );
    let errors = g.validate_claim_evidence();
    assert!(errors.is_empty(), "asserted claims need no evidence");
}

#[test]
fn validation_edge_refs_passes_with_valid_refs() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "asserted".into(),
        },
    );
    g.evidence.insert(
        "E1".into(),
        TestEvidence {
            _kind: "benchmark".into(),
        },
    );
    g.edges.push(TestEdge {
        edge_type: "SUPPORTS".into(),
        from_id: "E1".into(),
        to_id: "C1".into(),
    });
    let errors = g.validate_edge_refs();
    assert!(errors.is_empty(), "should pass: {errors:?}");
}

#[test]
fn validation_edge_refs_fails_with_dangling_ref() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "asserted".into(),
        },
    );
    g.edges.push(TestEdge {
        edge_type: "SUPPORTS".into(),
        from_id: "NONEXISTENT".into(),
        to_id: "C1".into(),
    });
    let errors = g.validate_edge_refs();
    assert_eq!(errors.len(), 1, "should fail for dangling from_id");
    assert!(errors[0].contains("V-EDGE-REFS"));
}

#[test]
fn validation_policy_coverage_passes_with_mandatory_policy() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "verified".into(),
        },
    );
    g.policies.insert(
        "P1".into(),
        TestPolicy {
            enforcement: "mandatory".into(),
        },
    );
    g.edges.push(TestEdge {
        edge_type: "GOVERNS".into(),
        from_id: "P1".into(),
        to_id: "C1".into(),
    });
    let errors = g.validate_policy_coverage();
    assert!(errors.is_empty(), "should pass: {errors:?}");
}

#[test]
fn validation_policy_coverage_fails_without_mandatory_policy() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "safety".into(),
            status: "verified".into(),
        },
    );
    g.policies.insert(
        "P1".into(),
        TestPolicy {
            enforcement: "advisory".into(),
        },
    );
    g.edges.push(TestEdge {
        edge_type: "GOVERNS".into(),
        from_id: "P1".into(),
        to_id: "C1".into(),
    });
    let errors = g.validate_policy_coverage();
    assert_eq!(
        errors.len(),
        1,
        "advisory policy does not satisfy safety claim"
    );
    assert!(errors[0].contains("V-POLICY-COVERAGE"));
}

#[test]
fn validation_policy_coverage_skips_non_safety_claims() {
    let mut g = TestGraph::new();
    g.claims.insert(
        "C1".into(),
        TestClaim {
            category: "performance".into(),
            status: "verified".into(),
        },
    );
    let errors = g.validate_policy_coverage();
    assert!(
        errors.is_empty(),
        "performance claims do not require mandatory policy"
    );
}

#[test]
fn validation_rollback_command_passes() {
    let mut g = TestGraph::new();
    g.rollbacks.insert(
        "R1".into(),
        TestRollback {
            _claim_id: "C1".into(),
            command: "cargo test --test regression".into(),
        },
    );
    let errors = g.validate_rollback_commands();
    assert!(errors.is_empty(), "should pass: {errors:?}");
}

#[test]
fn validation_rollback_command_fails_empty() {
    let mut g = TestGraph::new();
    g.rollbacks.insert(
        "R1".into(),
        TestRollback {
            _claim_id: "C1".into(),
            command: String::new(),
        },
    );
    let errors = g.validate_rollback_commands();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("V-ROLLBACK-COMMAND"));
}

#[test]
fn validation_full_bundle_roundtrip() {
    let mut g = TestGraph::new();

    // Claim
    g.claims.insert(
        "C-P99".into(),
        TestClaim {
            category: "safety".into(),
            status: "verified".into(),
        },
    );

    // Evidence
    g.evidence.insert(
        "E-BENCH".into(),
        TestEvidence {
            _kind: "benchmark".into(),
        },
    );

    // Policy
    g.policies.insert(
        "P-TAIL".into(),
        TestPolicy {
            enforcement: "mandatory".into(),
        },
    );

    // Rollback
    g.rollbacks.insert(
        "R-P99".into(),
        TestRollback {
            _claim_id: "C-P99".into(),
            command: "scripts/rollback_fast_path.sh".into(),
        },
    );

    // Edges
    g.edges.push(TestEdge {
        edge_type: "SUPPORTS".into(),
        from_id: "E-BENCH".into(),
        to_id: "C-P99".into(),
    });
    g.edges.push(TestEdge {
        edge_type: "GOVERNS".into(),
        from_id: "P-TAIL".into(),
        to_id: "C-P99".into(),
    });
    g.edges.push(TestEdge {
        edge_type: "TRIGGERS".into(),
        from_id: "C-P99".into(),
        to_id: "R-P99".into(),
    });

    // All validations pass
    assert!(g.validate_claim_evidence().is_empty());
    assert!(g.validate_edge_refs().is_empty());
    assert!(g.validate_policy_coverage().is_empty());
    assert!(g.validate_rollback_commands().is_empty());
}
