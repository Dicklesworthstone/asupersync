//! Contract tests for compatibility crate scaffolding/versioning policy (2oh2u.7.3).
//!
//! Validates explicit policy IDs, enforcement mappings, promotion/rollback
//! gates, ownership/escalation workflow, and policy anchors in compat crate
//! metadata/source.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_policy_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_compatibility_crate_scaffolding_policy.md");
    std::fs::read_to_string(path).expect("compat scaffolding policy document must exist")
}

fn load_compat_cargo() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml");
    std::fs::read_to_string(path).expect("compat Cargo.toml must exist")
}

fn load_compat_lib() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs");
    std::fs::read_to_string(path).expect("compat lib.rs must exist")
}

fn extract_ids(doc: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in doc.lines() {
        if !line.contains(prefix) {
            continue;
        }
        for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.')) {
            if token.starts_with(prefix) {
                out.insert(token.to_string());
            }
        }
    }
    out
}

#[test]
fn policy_doc_exists_and_is_substantial() {
    let doc = load_policy_doc();
    assert!(
        doc.len() > 6_500,
        "policy doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn policy_doc_references_correct_bead_and_dependency() {
    let doc = load_policy_doc();
    for token in ["asupersync-2oh2u.7.3", "[T7.3]", "Dependencies", "T7.2"] {
        assert!(
            doc.contains(token),
            "missing bead/dependency token: {token}"
        );
    }
}

#[test]
fn policy_doc_has_explicit_policy_ids_and_enforcement_map() {
    let doc = load_policy_doc();
    let ids = extract_ids(&doc, "POL-T7.3-");
    assert!(
        ids.len() >= 10,
        "expected at least 10 policy IDs, found {}",
        ids.len()
    );
    for required in [
        "POL-T7.3-01",
        "POL-T7.3-02",
        "POL-T7.3-03",
        "POL-T7.3-06",
        "POL-T7.3-08",
        "POL-T7.3-10",
    ] {
        assert!(
            ids.contains(required),
            "missing required policy id: {required}"
        );
    }
    assert!(
        doc.contains("Enforcement Mechanism") && doc.contains("Evidence Artifact"),
        "policy map must include enforcement and evidence columns"
    );
}

#[test]
fn policy_doc_defines_objective_promotion_and_rollback_gates() {
    let doc = load_policy_doc();
    let promote_ids = extract_ids(&doc, "GATE-T7.3-PROM-");
    let rollback_ids = extract_ids(&doc, "RB-T7.3-");
    assert!(
        promote_ids.len() >= 5,
        "expected >=5 promotion gates, found {}",
        promote_ids.len()
    );
    assert!(
        rollback_ids.len() >= 5,
        "expected >=5 rollback triggers, found {}",
        rollback_ids.len()
    );
    for required in [
        "GATE-T7.3-PROM-01",
        "GATE-T7.3-PROM-03",
        "GATE-T7.3-PROM-05",
        "RB-T7.3-01",
        "RB-T7.3-03",
        "RB-T7.3-05",
    ] {
        assert!(
            doc.contains(required),
            "missing required gate/rollback id: {required}"
        );
    }
}

#[test]
fn policy_doc_includes_ownership_escalation_and_exception_workflow() {
    let doc = load_policy_doc();
    for token in [
        "Ownership Model",
        "Escalation Thread",
        "Exception Workflow",
        "bounded validity window (TTL)",
        "owner approval",
        "asupersync-2oh2u.7.3",
    ] {
        assert!(
            doc.contains(token),
            "missing ownership/escalation token: {token}"
        );
    }
}

#[test]
fn policy_doc_declares_rch_ci_bundle() {
    let doc = load_policy_doc();
    for token in [
        "rch exec -- cargo test --test tokio_compatibility_crate_scaffolding_policy -- --nocapture",
        "rch exec -- cargo test --test tokio_adapter_boundary_architecture -- --nocapture",
        "rch exec -- cargo check --all-targets -q",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
    ] {
        assert!(doc.contains(token), "missing CI command token: {token}");
    }
}

#[test]
fn compat_cargo_contains_policy_metadata_and_scaffolding_guards() {
    let cargo = load_compat_cargo();
    for token in [
        "[package.metadata.asupersync_compat_policy]",
        "policy_version = \"1.0.0\"",
        "compatibility_line = \"0.2.x\"",
        "release_train = \"tokio-compat\"",
        "owner_track = \"asupersync-2oh2u.7\"",
        "default = []",
        "unsafe_code = \"deny\"",
    ] {
        assert!(
            cargo.contains(token),
            "missing Cargo policy/scaffolding token: {token}"
        );
    }
}

#[test]
fn compat_lib_exports_policy_constants() {
    let lib = load_compat_lib();
    for token in [
        "pub const COMPAT_POLICY_VERSION: &str = \"1.0.0\";",
        "pub const COMPATIBILITY_LINE: &str = \"0.1.x\";",
        "pub const OWNER_TRACK_ID: &str = \"asupersync-2oh2u.7\";",
        "fn compatibility_policy_constants_are_present()",
    ] {
        assert!(lib.contains(token), "missing compat-lib token: {token}");
    }
}

#[test]
fn policy_doc_links_evidence_and_revision_history() {
    let doc = load_policy_doc();
    for token in [
        "asupersync-tokio-compat/Cargo.toml",
        "asupersync-tokio-compat/src/lib.rs",
        "tests/tokio_compatibility_crate_scaffolding_policy.rs",
        "| 2026-03-03 | WhiteDesert | Initial T7.3 scaffolding + versioning policy contract (v1.0) |",
    ] {
        assert!(
            doc.contains(token),
            "missing evidence/history token: {token}"
        );
    }
}
