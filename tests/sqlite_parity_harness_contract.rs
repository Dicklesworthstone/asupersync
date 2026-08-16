//! Contract for the cycle-safe neutral SQLite parity harness.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOT_MANIFEST: &str = include_str!("../Cargo.toml");
const ROOT_LOCK: &str = include_str!("../Cargo.lock");
const CONSUMER_MANIFEST: &str = include_str!("fixtures/sqlite-parity-consumer/Cargo.toml");
const CONSUMER_LOCK: &str = include_str!("fixtures/sqlite-parity-consumer/Cargo.lock");
const VECTORS: &str = include_str!("../artifacts/sqlite_conformance_vectors_v1.json");
const HARNESS: &str = include_str!("../artifacts/sqlite_parity_harness_v1.json");
const DOC: &str = include_str!("../docs/sqlite_parity_harness.md");

fn parse_json(source: &str) -> Value {
    serde_json::from_str(source).expect("contract JSON must parse")
}

fn sha256(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

#[test]
fn dependency_direction_is_cycle_safe_and_runtime_is_unified() {
    let root_manifest = ROOT_MANIFEST.to_ascii_lowercase();
    assert!(!root_manifest.contains("fsqlite"));
    assert!(!root_manifest.contains("frankensqlite"));
    assert!(!ROOT_LOCK.contains("name = \"fsqlite\""));

    assert!(CONSUMER_MANIFEST.contains("[workspace]"));
    assert!(CONSUMER_MANIFEST.contains("asupersync = { path = \"../../..\""));
    assert!(
        CONSUMER_MANIFEST
            .contains("git = \"https://github.com/Dicklesworthstone/frankensqlite.git\"")
    );
    assert!(CONSUMER_MANIFEST.contains("rev = \"92f9e9833f859ebcbe27e9fef16d9cad4372bbd7\""));
    assert!(CONSUMER_MANIFEST.contains("features = [\"native\", \"async-api\"]"));
    assert!(CONSUMER_MANIFEST.contains("fsqlite-types = { git ="));
    assert!(CONSUMER_MANIFEST.contains("[patch.crates-io]"));
    assert!(CONSUMER_LOCK.contains("name = \"asupersync-sqlite-parity-consumer\""));
    assert!(CONSUMER_LOCK.contains("name = \"fsqlite\""));
    assert_eq!(
        CONSUMER_LOCK.matches("name = \"asupersync\"").count(),
        1,
        "the patched consumer must resolve exactly one asupersync package"
    );
    assert!(CONSUMER_LOCK.contains(
        "git+https://github.com/Dicklesworthstone/frankensqlite.git?rev=92f9e9833f859ebcbe27e9fef16d9cad4372bbd7#92f9e9833f859ebcbe27e9fef16d9cad4372bbd7"
    ));
}

#[test]
fn vector_schema_is_versioned_complete_and_deterministic() {
    let vectors = parse_json(VECTORS);
    assert_eq!(vectors["schema_version"], 2);
    assert_eq!(vectors["suite_id"], "sqlite-neutral-parity-v1");
    assert_eq!(vectors["capability_id"], "CAP-SQLITE");

    let normalization = vectors["normalization"]
        .as_object()
        .expect("normalization object");
    let normalization_fields = [
        "integer",
        "real",
        "text",
        "blob",
        "null",
        "error",
        "column_order",
        "row_order",
        "pool",
        "quiescence",
    ];
    assert_eq!(
        normalization.keys().cloned().collect::<BTreeSet<_>>(),
        normalization_fields
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );
    assert!(normalization.values().all(|value| {
        value
            .as_str()
            .is_some_and(|description| !description.is_empty())
    }));

    let cases = vectors["vectors"].as_array().expect("vector array");
    assert_eq!(cases.len(), 6);
    let expected_vectors = [
        (
            "SQLITE-PARITY-P2-MEMORY-CONFIG-001",
            "in_memory_configuration",
        ),
        ("SQLITE-PARITY-P2-PATH-OPEN-002", "file_path_round_trip"),
        ("SQLITE-PARITY-P2-OPEN-FAILURE-003", "missing_parent_path"),
        ("SQLITE-PARITY-P2-CANCELLED-OPEN-004", "pre_cancelled_open"),
        ("SQLITE-PARITY-P2-POOL-CANCEL-005", "admission_exhaustion"),
        (
            "SQLITE-PARITY-P2-URI-UNSUPPORTED-006",
            "uri_filename_unsupported",
        ),
    ];
    for (case, (expected_id, expected_kind)) in cases.iter().zip(expected_vectors) {
        assert_eq!(case["id"], expected_id);
        assert_eq!(case["scenario"]["kind"], expected_kind);
        for field in [
            "status",
            "error_class",
            "open_state",
            "configuration_state",
            "admission_state",
            "blocking_bridge_state",
            "cancellation_state",
            "close_state",
        ] {
            assert!(
                case["expected"].get(field).is_some(),
                "missing expected.{field}"
            );
        }
        let resource = case["expected"]["resource_state"]
            .as_object()
            .expect("resource state");
        for field in [
            "connection",
            "open_transactions",
            "admission_capacity",
            "admission_available",
            "admission_waiters",
            "admission_cancellations",
            "blocking_pending",
            "blocking_busy",
            "blocking_active",
            "region_state",
            "background_work",
        ] {
            assert!(
                resource.contains_key(field),
                "missing resource_state.{field}"
            );
        }
        assert_eq!(resource["open_transactions"], 0);
        assert_eq!(resource["admission_waiters"], 0);
        assert_eq!(resource["blocking_pending"], 0);
        assert_eq!(resource["blocking_busy"], 0);
        assert_eq!(resource["blocking_active"], 0);
        assert_eq!(resource["region_state"], "closed");
        assert!(matches!(
            resource["connection"].as_str(),
            Some("closed" | "not_opened")
        ));
    }
    assert!(
        cases[..5]
            .iter()
            .all(|case| case["unsupported"].as_array().is_some_and(Vec::is_empty))
    );
    let unsupported = cases[5]["unsupported"]
        .as_array()
        .expect("URI unsupported rows");
    assert_eq!(unsupported.len(), 2);
    assert_eq!(unsupported[0]["engine"], "asupersync");
    assert_eq!(unsupported[1]["engine"], "frankensqlite");
}

#[test]
fn harness_receipt_pins_sources_profile_target_host_and_budget_defer() {
    let harness = parse_json(HARNESS);
    assert_eq!(harness["schema_version"], 2);
    assert_eq!(harness["placement"]["kind"], "neutral_standalone_consumer");
    assert_eq!(harness["placement"]["workspace_member"], false);
    assert_eq!(
        harness["placement"]["asupersync_root_has_frankensqlite_edge"],
        false
    );
    assert_eq!(
        harness["phase2"]["pins"]["frankensqlite"]["revision"],
        "92f9e9833f859ebcbe27e9fef16d9cad4372bbd7"
    );
    assert_eq!(
        harness["phase2"]["pins"]["lockfile_sha256"],
        sha256(CONSUMER_LOCK)
    );
    assert_eq!(
        harness["phase2"]["vector_contract"]["sha256"],
        sha256(VECTORS)
    );
    assert_eq!(
        harness["phase1_validation_frontier"]["status"],
        "BLOCKED_UPSTREAM_COMPILE"
    );
    for field in ["cargo_profile", "target", "host"] {
        assert!(
            harness["phase2"]["pins"][field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "missing phase2.pins.{field}"
        );
    }
    assert_eq!(
        harness["combined_graph_budget"]["terminal_outcome"],
        "DEFER"
    );
    assert_eq!(
        harness["phase1_execution"]["clean_overlay"]["base"],
        harness["phase1_pins"]["asupersync"]["revision"]
    );
    assert_eq!(
        harness["phase1_execution"]["clean_overlay"]["no_overlay"],
        true
    );
    assert!(
        harness["phase2"]["execution"]["command"]
            .as_str()
            .is_some_and(|command| command.contains("cargo run --locked"))
    );
    assert!(
        harness["no_claims"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 5)
    );
}

#[test]
fn clean_phase2_execution_receipt_matches_all_declared_vectors() {
    let harness = parse_json(HARNESS);
    assert_eq!(harness["phase1_execution"]["status"], "PASS");
    assert_eq!(harness["phase2"]["execution"]["status"], "PASS");
    let evidence = &harness["phase2"]["execution"]["evidence"];
    assert_eq!(evidence["evidence_schema_version"], 1);
    assert_eq!(evidence["vector_schema_version"], 2);
    assert_eq!(evidence["suite_id"], "sqlite-neutral-parity-v1");
    assert_eq!(evidence["capability_id"], "CAP-SQLITE");
    assert_eq!(
        evidence["provenance"]["asupersync_revision"],
        harness["phase2"]["pins"]["asupersync"]["revision"]
    );
    assert_eq!(
        evidence["provenance"]["frankensqlite_revision"],
        harness["phase2"]["pins"]["frankensqlite"]["revision"]
    );
    assert_eq!(evidence["comparison"]["comparable"], true);
    assert_eq!(evidence["comparison"]["compared_vectors"], 6);
    assert_eq!(
        evidence["comparison"]["mismatches"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let engines = evidence["engine_results"]
        .as_array()
        .expect("engine evidence");
    assert_eq!(engines.len(), 2);
    assert_eq!(engines[0]["engine"], "asupersync");
    assert_eq!(engines[1]["engine"], "frankensqlite");
    assert_eq!(engines[0]["vectors"].as_array().map(Vec::len), Some(6));
    assert_eq!(engines[1]["vectors"].as_array().map(Vec::len), Some(6));
    for (asupersync, frankensqlite) in engines[0]["vectors"]
        .as_array()
        .expect("asupersync vector evidence")
        .iter()
        .zip(
            engines[1]["vectors"]
                .as_array()
                .expect("FrankenSQLite vector evidence"),
        )
    {
        assert_eq!(asupersync["vector_id"], frankensqlite["vector_id"]);
        assert_eq!(asupersync["outcome"], frankensqlite["outcome"]);
        let resource = &asupersync["outcome"]["resource_state"];
        assert_eq!(resource["open_transactions"], 0);
        assert_eq!(resource["admission_waiters"], 0);
        assert_eq!(resource["blocking_pending"], 0);
        assert_eq!(resource["blocking_busy"], 0);
        assert_eq!(resource["blocking_active"], 0);
        assert_eq!(resource["region_state"], "closed");
        assert_eq!(
            resource["background_work"],
            "none_observed_after_runtime_shutdown"
        );
    }
}

#[test]
fn operator_doc_preserves_reproduction_and_no_claim_boundaries() {
    for marker in [
        "neutral consumer",
        "independent `Cargo.lock`",
        "SQLITE-PARITY-P2-POOL-CANCEL-005",
        "consumer-owned admission semaphore",
        "ASUPERSYNC_SOURCE_REVISION=<source-commit>",
        "cargo run --locked",
        "terminal `DEFER`",
        "does not authorize dependency cutover",
    ] {
        assert!(
            DOC.contains(marker),
            "missing documentation marker {marker}"
        );
    }
}
