#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DASHBOARD_CONTRACT_PATH: &str = "artifacts/atp_completion_dashboard_contract_v1.json";
const RECONCILIATION_DOC_PATH: &str = "docs/atp_proof_reconciliation/README.md";
const RECONCILIATION_PATH: &str = "artifacts/atp_proof_reconciliation_v1.json";
const RECONCILIATION_TEST_PATH: &str = "tests/atp_proof_reconciliation_contract.rs";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn entries_by_bead(reconciliation: &Value) -> BTreeMap<String, Value> {
    array(reconciliation, "entries")
        .iter()
        .map(|entry| (string(entry, "bead_id").to_string(), entry.clone()))
        .collect()
}

fn required_claims() -> BTreeSet<String> {
    [
        "asupersync-9tty78",
        "asupersync-33lyim",
        "asupersync-fkfntf",
        "asupersync-m20jwv",
        "asupersync-utdpso",
        "asupersync-z6ehte",
        "asupersync-xvaftm",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[test]
fn reconciliation_inventory_covers_required_closed_atp_n_claims() {
    let reconciliation = json(RECONCILIATION_PATH);
    assert_eq!(
        reconciliation["schema_version"].as_str(),
        Some("asupersync.atp.proof_reconciliation.v1")
    );
    assert_eq!(
        reconciliation["generated_for_bead"].as_str(),
        Some("asupersync-vk4kcf.15")
    );

    let required_from_artifact = string_set(&reconciliation, "required_closed_atp_n_claims");
    assert_eq!(required_from_artifact, required_claims());

    let entries = entries_by_bead(&reconciliation);
    assert_eq!(
        entries.keys().cloned().collect::<BTreeSet<_>>(),
        required_claims()
    );

    let allowed_statuses = string_set_from_catalog(&reconciliation, "status_catalog", "status");
    for (bead_id, entry) in &entries {
        for field in [
            "title",
            "closed_at",
            "close_reason",
            "claimed_guarantee",
            "claimed_proof_command",
            "last_known_commit",
            "current_command_result",
            "release_proof_policy",
        ] {
            string(entry, field);
        }
        let status = string(entry, "current_status");
        assert!(
            allowed_statuses.contains(status),
            "{bead_id}: unknown current_status {status}"
        );
        assert!(
            !array(entry, "current_artifact_paths").is_empty(),
            "{bead_id}: current_artifact_paths must be nonempty"
        );
        assert!(
            !array(entry, "live_evidence").is_empty(),
            "{bead_id}: live_evidence must be nonempty"
        );
    }
}

#[test]
fn stale_or_superseded_claims_cannot_satisfy_release_proof() {
    let reconciliation = json(RECONCILIATION_PATH);
    let entries = entries_by_bead(&reconciliation);

    for (bead_id, entry) in &entries {
        let status = string(entry, "current_status");
        let release_policy = string(entry, "release_proof_policy");
        assert_ne!(
            release_policy, "satisfies_atp_nr13",
            "{bead_id}: historical ATP-N closures must not directly satisfy ATP-NR13"
        );

        match status {
            "stale_overbroad" | "superseded_by_atp_nr" | "blocked_frontier" => {
                assert_eq!(
                    release_policy, "does_not_satisfy_atp_nr13",
                    "{bead_id}: stale/superseded/blocked claims must be excluded from release proof"
                );
                assert!(
                    !array(entry, "replacement_gates").is_empty(),
                    "{bead_id}: stale or superseded claim must route to replacement gates"
                );
            }
            "accepted_foundation" => {
                assert_eq!(
                    release_policy, "foundation_only",
                    "{bead_id}: accepted foundation still requires current release gates"
                );
                assert!(
                    !array(entry, "release_gate_dependencies").is_empty(),
                    "{bead_id}: accepted foundation must name release gate dependencies"
                );
            }
            other => panic!("{bead_id}: unexpected status {other}"),
        }
    }

    let summary = reconciliation
        .get("reconciliation_summary")
        .and_then(Value::as_object)
        .expect("reconciliation_summary object");
    assert_eq!(
        summary
            .get("historical_claims_that_directly_satisfy_atp_nr13")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        summary
            .get("claims_not_allowed_for_release")
            .and_then(Value::as_u64),
        Some(entries.len() as u64)
    );
}

#[test]
fn live_evidence_paths_exist_and_include_expected_foundations() {
    let reconciliation = json(RECONCILIATION_PATH);
    let entries = entries_by_bead(&reconciliation);

    for (bead_id, entry) in &entries {
        for path in string_set(entry, "current_artifact_paths") {
            assert!(
                repo_path(&path).exists(),
                "{bead_id}: artifact path must exist: {path}"
            );
        }
        for evidence in array(entry, "live_evidence") {
            let path = string(evidence, "path");
            string(evidence, "finding");
            assert!(
                repo_path(path).exists(),
                "{bead_id}: evidence path must exist: {path}"
            );
        }
    }

    let logging = entries
        .get("asupersync-utdpso")
        .expect("logging contract entry");
    assert_eq!(string(logging, "current_status"), "accepted_foundation");
    let logging_paths = string_set(logging, "current_artifact_paths");
    assert!(logging_paths.contains("docs/atp_log_schema.md"));
    assert!(logging_paths.contains("tests/atp_fixture_golden_log_corpus.rs"));

    let unit_coverage = entries
        .get("asupersync-9tty78")
        .expect("unit coverage entry");
    assert_eq!(string(unit_coverage, "current_status"), "stale_overbroad");
    assert!(read_repo_file("docs/atp_coverage_ledger.md").contains("TESTED: 0"));
}

#[test]
fn dashboard_contract_consumes_reconciliation_as_atp_nr14_input() {
    let dashboard = json(DASHBOARD_CONTRACT_PATH);
    let proof_sources = string_set(&dashboard, "proof_sources");
    assert!(
        proof_sources.contains(RECONCILIATION_PATH),
        "ATP-NR0 dashboard contract must include proof reconciliation as a proof source"
    );

    let nr14 = array(&dashboard, "required_release_gates")
        .iter()
        .find(|gate| gate["gate_id"].as_str() == Some("ATP-NR14"))
        .expect("ATP-NR14 release gate");
    assert_eq!(nr14["bead_id"].as_str(), Some("asupersync-vk4kcf.15"));
    assert_eq!(
        nr14["proof_command"].as_str(),
        Some(
            "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p9 cargo test -p asupersync --test atp_proof_reconciliation_contract -- --nocapture"
        )
    );

    let required_artifacts = string_set(nr14, "required_artifacts");
    for required in [
        RECONCILIATION_PATH,
        RECONCILIATION_DOC_PATH,
        RECONCILIATION_TEST_PATH,
    ] {
        assert!(
            required_artifacts.contains(required),
            "ATP-NR14 must require {required}"
        );
    }
}

fn string_set_from_catalog(value: &Value, catalog_key: &str, field: &str) -> BTreeSet<String> {
    array(value, catalog_key)
        .iter()
        .map(|row| string(row, field).to_string())
        .collect()
}
