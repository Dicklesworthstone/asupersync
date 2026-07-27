//! Independent vector, property, mutation, and fuzz contract for the owned LZ4 codec.
//!
//! Bead: asupersync-0h6myr.4.3
//! Capability: CAP-TRACE-LZ4
//! Fixture: artifacts/lz4_owned_codec_corpus_v1.json
//!
//! This is test-only evidence. It does not integrate the owned codec into
//! production trace paths or authorize dependency removal.

#![cfg(feature = "test-internals")]
#![allow(missing_docs)]

use asupersync::trace::lz4_harness;
use proptest::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/lz4_owned_codec_corpus_v1.json";
const DOC_PATH: &str = "docs/lz4_owned_codec_corpus.md";
const A1_ARTIFACT_PATH: &str = "artifacts/lz4_surface_artifact_inventory_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const FUZZ_MANIFEST_PATH: &str = "fuzz/Cargo.toml";
const FUZZ_TARGET_PATH: &str = "fuzz/fuzz_targets/trace_compression.rs";
const BEAD_ID: &str = "asupersync-0h6myr.4.3";
const CAPABILITY_ID: &str = "CAP-TRACE-LZ4";
const TRACE_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const TEST_LIMIT_BYTES: usize = 64 * 1024;
const MAX_EXPANSION_RATIO: usize = 256;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_file(path: &str) -> String {
    String::from_utf8(read_repo_bytes(path))
        .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bytes(row: &Value, key: &str) -> Vec<u8> {
    hex::decode(text(row, key)).unwrap_or_else(|error| {
        panic!(
            "{} {key} must be valid hex: {error}",
            text(row, "vector_id")
        )
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn row_ids(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .map(|row| text(row, "vector_id").to_owned())
        .collect()
}

#[test]
fn corpus_schema_scope_and_handoff_are_fail_closed() {
    let corpus = artifact();
    assert_eq!(corpus["schema_version"], 1);
    assert_eq!(text(&corpus, "artifact_id"), "lz4-owned-codec-corpus-v1");
    assert_eq!(text(&corpus, "program_id"), "asupersync-ir2uf0");
    assert_eq!(text(&corpus, "bead_id"), BEAD_ID);
    assert_eq!(text(&corpus, "capability_id"), CAPABILITY_ID);
    assert_eq!(
        text(&corpus, "a2_codec_revision"),
        "747e8620af2532372f61bfdcbdc6243b457e599f"
    );

    let format = object(&corpus, "format_contract");
    assert_eq!(format["container"], "LZ4_SIZE_PREPENDED_BLOCK");
    assert_eq!(format["block_count"], 1);
    assert_eq!(format["frame_format_supported"], false);
    assert_eq!(format["dictionary_supported"], false);
    assert_eq!(format["block_checksum_supported"], false);
    assert_eq!(format["content_checksum_supported"], false);

    let valid = array(&corpus, "valid_vectors");
    let malformed = array(&corpus, "malformed_vectors");
    let budgets = array(&corpus, "budget_vectors");
    assert_eq!(valid.len(), 6);
    assert_eq!(malformed.len(), 17);
    assert_eq!(budgets.len(), 4);
    assert_eq!(row_ids(valid).len(), valid.len());
    assert_eq!(row_ids(malformed).len(), malformed.len());
    assert_eq!(row_ids(budgets).len(), budgets.len());

    let provenance = object(&corpus, "vector_provenance");
    assert_eq!(
        provenance["independence_state"],
        "INDEPENDENT_EXPECTED_BYTES"
    );
    assert!(text(&Value::Object(provenance.clone()), "method").contains("without using lz4_flex"));

    let handoff = object(&corpus, "a4_handoff");
    assert_eq!(handoff["persistent_block_corpus_state"], "COMPLETE");
    assert_eq!(
        handoff["historical_full_trace_corpus_state"],
        "ROUTED_TO_A4"
    );

    let boundaries = array(&corpus, "no_claim_boundaries");
    assert!(boundaries.len() >= 9);
    let joined = boundaries
        .iter()
        .map(|row| row.as_str().expect("no-claim boundary must be text"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "does not integrate",
        "does not prove historical full-trace compatibility",
        "does not prove performance",
        "does not authorize production cutover",
        "permission to delete files",
    ] {
        assert!(
            joined.contains(required),
            "missing no-claim boundary: {required}"
        );
    }
}

#[test]
fn independent_valid_vectors_decode_with_owned_and_incumbent_codecs() {
    for row in array(&artifact(), "valid_vectors") {
        let encoded = bytes(row, "encoded_hex");
        let expected = bytes(row, "decoded_hex");
        let decoded = lz4_harness::decode(
            &encoded,
            TRACE_LIMIT_BYTES,
            TRACE_LIMIT_BYTES,
            MAX_EXPANSION_RATIO,
        )
        .unwrap_or_else(|error| {
            panic!("{} owned decode failed: {error:?}", text(row, "vector_id"))
        });
        assert_eq!(decoded, expected, "{} owned decode", text(row, "vector_id"));
        assert_eq!(
            lz4_flex::decompress_size_prepended(&encoded).unwrap_or_else(|error| panic!(
                "{} incumbent decode failed: {error}",
                text(row, "vector_id")
            )),
            expected,
            "{} incumbent decode",
            text(row, "vector_id")
        );

        let first = lz4_harness::encode(&expected, TRACE_LIMIT_BYTES, TRACE_LIMIT_BYTES)
            .unwrap_or_else(|error| {
                panic!("{} owned encode failed: {error:?}", text(row, "vector_id"))
            });
        let second = lz4_harness::encode(&expected, TRACE_LIMIT_BYTES, TRACE_LIMIT_BYTES)
            .expect("the same bounded input must encode again");
        assert_eq!(
            first,
            second,
            "{} deterministic encode",
            text(row, "vector_id")
        );
        assert_eq!(
            lz4_flex::decompress_size_prepended(&first)
                .expect("incumbent must decode owned output"),
            expected
        );
    }
}

#[test]
fn malformed_vectors_have_exact_owned_error_classes() {
    for row in array(&artifact(), "malformed_vectors") {
        let encoded = bytes(row, "encoded_hex");
        let error = lz4_harness::decode(
            &encoded,
            TRACE_LIMIT_BYTES,
            TRACE_LIMIT_BYTES,
            MAX_EXPANSION_RATIO,
        )
        .expect_err("malformed corpus row must fail");
        assert_eq!(
            error.as_str(),
            text(row, "expected_error_class"),
            "{}",
            text(row, "vector_id")
        );
    }
}

#[test]
fn budget_vectors_fail_before_crossing_their_declared_envelopes() {
    for row in array(&artifact(), "budget_vectors") {
        assert_eq!(text(row, "operation"), "decode");
        let encoded = bytes(row, "encoded_hex");
        let error = lz4_harness::decode(
            &encoded,
            usize::try_from(row["max_compressed_bytes"].as_u64().expect("u64 limit"))
                .expect("limit fits usize"),
            usize::try_from(row["max_decompressed_bytes"].as_u64().expect("u64 limit"))
                .expect("limit fits usize"),
            usize::try_from(row["max_expansion_ratio"].as_u64().expect("u64 ratio"))
                .expect("ratio fits usize"),
        )
        .expect_err("budget corpus row must fail");
        assert_eq!(
            error.as_str(),
            text(row, "expected_error_class"),
            "{}",
            text(row, "vector_id")
        );
    }
}

#[test]
fn every_truncation_and_single_bit_mutation_stays_bounded() {
    for row in array(&artifact(), "valid_vectors") {
        let encoded = bytes(row, "encoded_hex");

        for truncate_at in 0..encoded.len() {
            if let Ok(decoded) = lz4_harness::decode(
                &encoded[..truncate_at],
                TEST_LIMIT_BYTES,
                TEST_LIMIT_BYTES,
                MAX_EXPANSION_RATIO,
            ) {
                assert!(decoded.len() <= TEST_LIMIT_BYTES);
            }
        }

        for byte_index in 0..encoded.len() {
            for bit in 0..u8::BITS {
                let mut mutated = encoded.clone();
                mutated[byte_index] ^= 1 << bit;
                if let Ok(decoded) = lz4_harness::decode(
                    &mutated,
                    TEST_LIMIT_BYTES,
                    TEST_LIMIT_BYTES,
                    MAX_EXPANSION_RATIO,
                ) {
                    assert!(decoded.len() <= TEST_LIMIT_BYTES);
                    assert_eq!(
                        lz4_flex::decompress_size_prepended(&mutated)
                            .expect("incumbent must decode every owned-accepted mutation"),
                        decoded
                    );
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_payloads_roundtrip_deterministically_across_both_codecs(
        payload in proptest::collection::vec(any::<u8>(), 0..=32 * 1024)
    ) {
        let first = lz4_harness::encode(&payload, TEST_LIMIT_BYTES, TEST_LIMIT_BYTES)
            .expect("bounded property payload must encode");
        let second = lz4_harness::encode(&payload, TEST_LIMIT_BYTES, TEST_LIMIT_BYTES)
            .expect("bounded property payload must re-encode");
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(
            lz4_harness::decode(
                &first,
                TEST_LIMIT_BYTES,
                TEST_LIMIT_BYTES,
                MAX_EXPANSION_RATIO
            ).expect("owned output must decode"),
            payload.clone()
        );
        prop_assert_eq!(
            lz4_flex::decompress_size_prepended(&first)
                .expect("incumbent must decode owned output"),
            payload.clone()
        );

        let incumbent = lz4_flex::compress_prepend_size(&payload);
        prop_assert_eq!(
            lz4_harness::decode(
                &incumbent,
                TEST_LIMIT_BYTES,
                TEST_LIMIT_BYTES,
                MAX_EXPANSION_RATIO
            ).expect("owned decoder must accept incumbent output"),
            payload.clone()
        );
    }
}

#[test]
fn fuzz_target_is_current_version_bounded_and_campaign_scoped() {
    let corpus = artifact();
    let fuzz = object(&corpus, "fuzz_contract");
    let manifest = read_repo_file(FUZZ_MANIFEST_PATH);
    let target = read_repo_file(FUZZ_TARGET_PATH);

    assert!(manifest.contains("lz4_flex = \"=0.14.0\""));
    assert!(!manifest.contains("lz4_flex = \"0.13\""));
    assert_eq!(
        sha256_hex(manifest.as_bytes()),
        text(&Value::Object(fuzz.clone()), "a3_manifest_sha256")
    );
    assert_eq!(
        sha256_hex(target.as_bytes()),
        text(&Value::Object(fuzz.clone()), "a3_target_sha256")
    );

    for marker in [
        "asupersync::trace::lz4_harness",
        "MAX_FUZZ_COMPRESSED_BYTES",
        "MAX_FUZZ_DECOMPRESSED_BYTES",
        "MAX_EXPANSION_RATIO",
        "incumbent must decode owned output",
        "owned decoder must accept current incumbent output",
    ] {
        assert!(target.contains(marker), "missing fuzz marker: {marker}");
    }
    assert!(!target.contains("block::decompress"));
    assert!(!target.contains("MAX_RAW_DECOMPRESSED_LEN"));

    let fuzz_value = Value::Object(fuzz.clone());
    let execution = object(&fuzz_value, "execution_receipt");
    assert_eq!(execution["executions"], 11_010_692);
    assert_eq!(execution["elapsed_seconds"], 61);
    assert_eq!(execution["reported_rss_mb"], 227);
    assert_eq!(execution["exit_code"], 0);
    assert!(
        execution["instrumentation"]
            .as_str()
            .expect("instrumentation must be text")
            .contains("without cargo-fuzz sanitizer or coverage instrumentation")
    );
}

#[test]
fn a1_gaps_are_resolved_without_rewriting_historical_baseline_evidence() {
    let corpus = artifact();
    let disposition = object(&corpus, "baseline_evidence_disposition");
    assert_eq!(disposition["historical_evidence_id"], "EVD-TRACE-LZ4");
    assert_eq!(disposition["historical_state"], "SEMANTIC_FILTERING_ONLY");
    assert_eq!(disposition["a3_receipt"], "LZ4-EVD-A3-CORPUS");

    let a1 = parse_repo_json(A1_ARTIFACT_PATH);
    let gaps = array(&a1, "observed_semantic_gaps");
    for gap_id in ["LZ4-GAP-05", "LZ4-GAP-06"] {
        let gap = gaps
            .iter()
            .find(|row| row["gap_id"] == gap_id)
            .unwrap_or_else(|| panic!("A1 must retain {gap_id}"));
        assert_eq!(gap["owner"], BEAD_ID);
        assert!(text(gap, "state").starts_with("ROUTED"));
    }

    let baseline = parse_repo_json(BASELINE_PATH);
    let evidence = array(&baseline, "evidence_catalog")
        .iter()
        .find(|row| row["evidence_id"] == "EVD-TRACE-LZ4")
        .expect("historical evidence row must remain present");
    assert_eq!(
        evidence["fixture_paths"],
        serde_json::json!(["tests/trace_compression_conformance.rs"])
    );
}

#[test]
fn operator_doc_names_replay_commands_and_no_claim_boundaries() {
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        BEAD_ID,
        CAPABILITY_ID,
        "LZ4_SIZE_PREPENDED_BLOCK",
        "lz4_owned_codec_corpus_contract",
        "fuzz_trace_compression",
        "11,010,692 executions",
        "no sanitizer or coverage claim",
        "A4",
        "A5",
        "No production cutover",
        "No permission to delete files",
    ] {
        assert!(doc.contains(marker), "missing docs marker: {marker}");
    }
}
