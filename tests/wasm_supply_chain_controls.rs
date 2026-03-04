#![allow(missing_docs)]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn load_json(path: &Path) -> serde_json::Value {
    let raw = fs::read_to_string(path).expect("failed to read JSON file");
    serde_json::from_str(&raw).expect("failed to parse JSON")
}

fn sha256_hex(path: &Path) -> String {
    let bytes = fs::read(path).expect("failed to read artifact bytes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{digest:x}")
}

#[test]
fn security_release_policy_declares_supply_chain_artifact_gate() {
    let policy = load_json(Path::new(".github/security_release_policy.json"));
    let blocking = policy["release_blocking_criteria"]
        .as_array()
        .expect("release_blocking_criteria must be an array");

    let gate = blocking
        .iter()
        .find(|entry| entry["id"] == "SEC-BLOCK-07")
        .expect("SEC-BLOCK-07 must be declared");

    assert_eq!(gate["category"], "supply_chain_artifact_integrity");
    assert_eq!(gate["blocks_release"], true);

    let required = gate["required_artifacts"]
        .as_array()
        .expect("required_artifacts must be an array");
    assert!(
        required
            .iter()
            .any(|entry| entry == "docs/wasm_browser_sbom_v1.json"),
        "required_artifacts must include SBOM artifact"
    );
    assert!(
        required
            .iter()
            .any(|entry| entry == "docs/wasm_browser_provenance_attestation_v1.json"),
        "required_artifacts must include provenance artifact"
    );
    assert_eq!(
        gate["integrity_manifest"],
        "docs/wasm_browser_artifact_integrity_manifest_v1.json"
    );
}

#[test]
fn artifact_integrity_manifest_matches_committed_artifacts() {
    let manifest_path = Path::new("docs/wasm_browser_artifact_integrity_manifest_v1.json");
    let manifest = load_json(manifest_path);

    assert_eq!(
        manifest["schema_version"],
        "asupersync-wasm-artifact-integrity-v1"
    );
    assert_eq!(manifest["bead"], "asupersync-umelq.14.3");
    assert_eq!(manifest["hash_algorithm"], "sha256");

    let entries = manifest["entries"]
        .as_array()
        .expect("manifest entries must be an array");
    assert!(
        entries.len() >= 2,
        "manifest should include at least two entries"
    );

    let mut seen: BTreeMap<PathBuf, String> = BTreeMap::new();
    for entry in entries {
        let path = PathBuf::from(
            entry["path"]
                .as_str()
                .expect("manifest entry path must be string"),
        );
        let sha256 = entry["sha256"]
            .as_str()
            .expect("manifest entry sha256 must be string")
            .to_string();
        assert_eq!(sha256.len(), 64, "manifest sha256 must be 64 hex chars");
        assert!(
            seen.insert(path.clone(), sha256.clone()).is_none(),
            "manifest should not contain duplicate artifact paths"
        );

        assert!(path.exists(), "manifest artifact path must exist: {path:?}");
        let actual = sha256_hex(&path);
        assert_eq!(
            actual,
            sha256,
            "integrity manifest digest drift for {}",
            path.display()
        );
    }

    assert!(
        seen.contains_key(&PathBuf::from("docs/wasm_browser_sbom_v1.json")),
        "manifest must include SBOM artifact"
    );
    assert!(
        seen.contains_key(&PathBuf::from(
            "docs/wasm_browser_provenance_attestation_v1.json"
        )),
        "manifest must include provenance artifact"
    );
}

#[test]
fn dependency_audit_docs_reference_supply_chain_bundle_and_repro_commands() {
    let policy_doc = fs::read_to_string("docs/wasm_dependency_audit_policy.md")
        .expect("failed to read wasm dependency audit policy doc");
    let audit_doc = fs::read_to_string("docs/wasm_dependency_audit.md")
        .expect("failed to read wasm dependency audit doc");

    for expected in [
        "docs/wasm_browser_sbom_v1.json",
        "docs/wasm_browser_provenance_attestation_v1.json",
        "docs/wasm_browser_artifact_integrity_manifest_v1.json",
        "python3 scripts/check_security_release_gate.py \\\n  --policy .github/security_release_policy.json \\\n  --check-deps \\\n  --dep-policy .github/wasm_dependency_policy.json",
    ] {
        assert!(
            policy_doc.contains(expected) || audit_doc.contains(expected),
            "supply-chain docs missing required token: {expected}"
        );
    }
}

#[test]
fn publish_workflow_declares_release_contract_traceability_controls() {
    let workflow = fs::read_to_string(".github/workflows/publish.yml")
        .expect("failed to read publish workflow");

    for expected in [
        "WASM_RELEASE_CONTRACT_ID: wasm-release-channel-strategy-v1",
        "WASM_RELEASE_BEAD_ID: asupersync-umelq.15.2",
        "security_policy = Path(\".github/security_release_policy.json\")",
        "\"release_blocking_criteria\": criteria",
        "Path(\"artifacts/wasm/release/release_traceability.json\").write_text",
        "Path(\"artifacts/wasm/release/rollback_safety_report.json\").write_text",
        "Path(\"artifacts/wasm/release/incident_response_packet.json\").write_text",
        "\"schema_version\": \"wasm-rollback-safety-v1\"",
        "\"schema_version\": \"wasm-release-incident-response-v1\"",
        "\"rollback_safety_checks\": [",
        "\"artifact_revocation_strategy\": {",
        "\"postmortem_requirements\": [",
        "bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics",
        "TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh",
        "python3 ./scripts/check_incident_forensics_playbook.py",
        "artifacts/wasm/release/release_traceability.json",
        "artifacts/wasm/release/rollback_safety_report.json",
        "artifacts/wasm/release/incident_response_packet.json",
        "if: ${{ always() }}",
    ] {
        assert!(
            workflow.contains(expected),
            "publish workflow missing release traceability control token: {expected}"
        );
    }
}

#[test]
fn publish_workflow_and_strategy_doc_align_on_npm_artifact_contract() {
    let workflow = fs::read_to_string(".github/workflows/publish.yml")
        .expect("failed to read publish workflow");
    let strategy = fs::read_to_string("docs/wasm_release_channel_strategy.md")
        .expect("failed to read wasm release strategy");

    for expected in [
        "artifacts/npm/package_json_paths.txt",
        "artifacts/npm/npm_release_assumptions.json",
        "artifacts/npm/publish_outcome.json",
        "artifacts/npm/rollback_outcome.json",
        "packages/*/package.json",
    ] {
        assert!(
            workflow.contains(expected),
            "publish workflow missing npm artifact contract token: {expected}"
        );
        assert!(
            strategy.contains(expected),
            "strategy doc missing npm artifact contract token: {expected}"
        );
    }

    assert!(
        workflow.contains("rollback_reason is required when rollback_npm_to_version is set."),
        "publish workflow must enforce rollback reason requirement"
    );
    assert!(
        strategy.contains("Rollback mode requires both target version and operator reason"),
        "strategy doc must document rollback reason requirement"
    );
    assert!(
        strategy.contains("Missing package manifests are treated as an explicit controlled skip"),
        "strategy doc must document controlled skip behavior for missing package manifests"
    );
}
