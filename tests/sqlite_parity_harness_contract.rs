//! Contract for the cycle-safe neutral SQLite parity harness.

use std::collections::BTreeSet;

use serde_json::Value;

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
    assert_eq!(vectors["schema_version"], 1);
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
    assert_eq!(cases.len(), 1);
    let smoke = &cases[0];
    assert_eq!(smoke["id"], "SQLITE-PARITY-SMOKE-001");
    assert!(
        smoke["setup"]
            .as_array()
            .is_some_and(|setup| !setup.is_empty())
    );
    let operations = smoke["operations"].as_array().expect("operation array");
    assert_eq!(operations.len(), 2);
    for (index, operation) in operations.iter().enumerate() {
        assert_eq!(
            operation["sequence"].as_u64(),
            Some(u64::try_from(index + 1).expect("small operation index"))
        );
        for field in [
            "status",
            "affected_rows",
            "values",
            "error_class",
            "transaction_state",
            "cancellation_state",
            "resource_state",
        ] {
            assert!(
                operation["expected"].get(field).is_some(),
                "missing expected.{field}"
            );
        }
    }
    assert!(smoke["expected_final_state"].is_object());
    assert!(smoke["unsupported"].is_array());
}

#[test]
fn harness_receipt_pins_sources_profile_target_host_and_budget_defer() {
    let harness = parse_json(HARNESS);
    assert_eq!(harness["schema_version"], 1);
    assert_eq!(harness["placement"]["kind"], "neutral_standalone_consumer");
    assert_eq!(harness["placement"]["workspace_member"], false);
    assert_eq!(
        harness["placement"]["asupersync_root_has_frankensqlite_edge"],
        false
    );
    assert_eq!(
        harness["pins"]["frankensqlite"]["revision"],
        "92f9e9833f859ebcbe27e9fef16d9cad4372bbd7"
    );
    assert_eq!(
        harness["validation_frontier"]["status"],
        "BLOCKED_UPSTREAM_COMPILE"
    );
    for field in ["cargo_profile", "target", "host"] {
        assert!(
            harness["pins"][field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "missing pins.{field}"
        );
    }
    assert_eq!(
        harness["combined_graph_budget"]["terminal_outcome"],
        "DEFER"
    );
    assert_eq!(
        harness["execution"]["clean_overlay"]["base"],
        harness["pins"]["asupersync"]["revision"]
    );
    assert_eq!(harness["execution"]["clean_overlay"]["no_overlay"], true);
    assert!(
        harness["execution"]["command"]
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
fn clean_execution_receipt_matches_the_smoke_vector() {
    let harness = parse_json(HARNESS);
    assert_eq!(harness["execution"]["status"], "PASS");
    let evidence = &harness["execution"]["evidence"];
    assert_eq!(evidence["evidence_schema_version"], 1);
    assert_eq!(evidence["vector_schema_version"], 1);
    assert_eq!(evidence["suite_id"], "sqlite-neutral-parity-v1");
    assert_eq!(evidence["capability_id"], "CAP-SQLITE");
    assert_eq!(
        evidence["provenance"]["asupersync_revision"],
        harness["pins"]["asupersync"]["revision"]
    );
    assert_eq!(
        evidence["provenance"]["frankensqlite_revision"],
        harness["pins"]["frankensqlite"]["revision"]
    );
    assert_eq!(evidence["comparison"]["comparable"], true);
    assert_eq!(evidence["comparison"]["compared_vectors"], 1);
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
    assert_eq!(engines[0]["vectors"], engines[1]["vectors"]);
    assert_eq!(
        engines[0]["vectors"][0]["vector_id"],
        "SQLITE-PARITY-SMOKE-001"
    );
}

#[test]
fn operator_doc_preserves_reproduction_and_no_claim_boundaries() {
    for marker in [
        "neutral consumer",
        "independent `Cargo.lock`",
        "SQLITE-PARITY-SMOKE-001",
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
