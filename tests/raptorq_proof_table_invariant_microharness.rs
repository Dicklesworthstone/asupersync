//! Module-scoped proof microharness for the RaptorQ table-invariant proof lane.

#![allow(missing_docs)]

use asupersync::raptorq::proof::ProofArtifactDistributionError;
use serde_json::json;

const BLOCKED_BEAD_ID: &str = "asupersync-to7e65.12";
const IMPLEMENTATION_BEAD_ID: &str = "asupersync-l5m170.1";
const PROOF_TARGET: &str = "raptorq-proof-table-invariant";

fn proof_bead_id() -> String {
    std::env::var("ASUPERSYNC_PROOF_BEAD").unwrap_or_else(|_| BLOCKED_BEAD_ID.to_string())
}

#[test]
fn table_invariant_display_preserves_corruption_evidence() {
    let err = ProofArtifactDistributionError::RfcTableInvariantViolation {
        invariant: "K' >= K",
        details: "K=10 K'=9 from RFC systematic index table".to_string(),
    };

    let display = err.to_string();
    assert!(display.contains("RFC 6330 table invariant violation"));
    assert!(display.contains("K' >= K"));
    assert!(display.contains("K=10 K'=9"));
    assert!(
        !matches!(
            err,
            ProofArtifactDistributionError::UnsupportedSourceBlock { .. }
        ),
        "table corruption must stay distinct from unsupported source-block sizing"
    );
    assert!(
        !display.contains("maximum supported is 0"),
        "the old placeholder/sentinel proof text must not reappear"
    );
}

#[test]
fn table_invariant_serialization_is_explicit_corruption() {
    let err = ProofArtifactDistributionError::RfcTableInvariantViolation {
        invariant: "L = K' + S + H",
        details: "K'=20 S=4 H=2 L=21".to_string(),
    };

    let value = serde_json::to_value(&err).expect("proof error serializes");

    assert_eq!(
        value,
        json!({
            "RfcTableInvariantViolation": {
                "invariant": "L = K' + S + H",
                "details": "K'=20 S=4 H=2 L=21",
            }
        })
    );
    assert!(value.get("UnsupportedSourceBlock").is_none());
}

#[test]
fn microharness_declares_mapping_guarantee_and_exclusions() {
    let event = json!({
        "schema_version": "module-microharness-test-event-v1",
        "implementation_bead_id": IMPLEMENTATION_BEAD_ID,
        "blocked_bead_id": proof_bead_id(),
        "proof_target": PROOF_TARGET,
        "guarantee": "RaptorQ proof-artifact RFC table corruption is reported and serialized as explicit invariant evidence, not as an unsupported source-block placeholder or sentinel.",
        "exclusions": [
            "does not run the broad lib-test graph",
            "does not prove full RaptorQ encode/decode recovery",
            "does not replace the final mock-code-finder stub ratchet or release proof gates"
        ],
        "cargo_test_target": "raptorq_proof_table_invariant_microharness",
    });

    println!(
        "ASUPERSYNC_MICROHARNESS_EVENT {}",
        serde_json::to_string(&event).expect("event json")
    );

    assert_eq!(event["implementation_bead_id"], IMPLEMENTATION_BEAD_ID);
    assert_eq!(event["blocked_bead_id"], BLOCKED_BEAD_ID);
    assert_eq!(event["proof_target"], PROOF_TARGET);
    assert_eq!(
        event["cargo_test_target"],
        "raptorq_proof_table_invariant_microharness"
    );
    assert!(
        event["exclusions"]
            .as_array()
            .expect("exclusion rows")
            .iter()
            .any(|row| row.as_str() == Some("does not run the broad lib-test graph"))
    );
}
