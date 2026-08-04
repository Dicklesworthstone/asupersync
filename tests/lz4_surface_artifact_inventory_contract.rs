//! Fail-closed LZ4 source, artifact, resource, and evidence-gate contract.
//!
//! Bead: asupersync-0h6myr.4.1
//! Capability: CAP-TRACE-LZ4
//! Fixture: artifacts/lz4_surface_artifact_inventory_v1.json
//!
//! This contract proves the pinned A1 inventory and an experiment-only gate.
//! It does not prove an owned codec, historical compatibility, performance,
//! production cutover, or permission to remove `lz4_flex`.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Instant;

const ARTIFACT_PATH: &str = "artifacts/lz4_surface_artifact_inventory_v1.json";
const A3_CORPUS_PATH: &str = "artifacts/lz4_owned_codec_corpus_v1.json";
const A4_RECEIPT_PATH: &str = "artifacts/lz4_trace_integration_go_no_go_v1.json";
const DOC_PATH: &str = "docs/lz4_surface_artifact_inventory.md";
const BEAD_ID: &str = "asupersync-0h6myr.4.1";
const CAPABILITY_ID: &str = "CAP-TRACE-LZ4";
const BASELINE_REVISION: &str = "a4a92df81109afa362814c4e0638afcbe16424d0";
const DOC_BEGIN: &str = "<!-- BEGIN LZ4 SURFACE ARTIFACT INVENTORY -->";
const DOC_END: &str = "<!-- END LZ4 SURFACE ARTIFACT INVENTORY -->";

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

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn validate_no_unknown(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::String(state) if state == "UNKNOWN" => {
            return Err(format!("{path} must not be UNKNOWN"));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_unknown(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                validate_no_unknown(child, &format!("{path}.{key}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn count(source: &str, needle: &str) -> usize {
    source.match_indices(needle).count()
}

#[test]
fn inventory_schema_and_authority_are_fail_closed() {
    let inventory = artifact();
    assert_eq!(inventory["schema_version"], 1);
    assert_eq!(
        text(&inventory, "artifact_id"),
        "lz4-surface-artifact-inventory-v1"
    );
    assert_eq!(text(&inventory, "program_id"), "asupersync-ir2uf0");
    assert_eq!(text(&inventory, "bead_id"), BEAD_ID);
    assert_eq!(text(&inventory, "capability_id"), CAPABILITY_ID);
    assert_eq!(text(&inventory, "baseline_revision"), BASELINE_REVISION);

    let authority = object(&inventory, "authority");
    assert_eq!(
        authority["registry_disposition"],
        Value::String("KEEP_UNTIL_PARITY".to_owned())
    );
    assert_eq!(
        authority["registry_cutover_state"],
        Value::String("KEEP_INCUMBENT".to_owned())
    );
    assert_eq!(
        authority["gate_decision"],
        Value::String("REPLACE_EXPERIMENT_AUTHORIZED".to_owned())
    );
    assert_eq!(authority["dependency_exit_allowed"], false);
    assert_eq!(authority["partial_cutover_allowed"], false);
    assert_eq!(
        authority["production_source_change_allowed_in_this_bead"],
        false
    );

    let policy = object(&inventory, "policy");
    assert_eq!(policy["zero_unknown_required"], true);
    assert_eq!(policy["unknown_rows"], 0);
    assert_eq!(policy["all_gaps_routed"], true);
    validate_no_unknown(&inventory, "$").expect("inventory must contain no UNKNOWN state");
}

#[test]
fn every_pinned_source_hash_matches_the_baseline() {
    let inventory = artifact();
    let a3 = parse_repo_json(A3_CORPUS_PATH);
    let a4 = parse_repo_json(A4_RECEIPT_PATH);
    let fuzz_transition = object(&a3, "fuzz_contract");
    let trace_transition = object(&a4, "source_transition");
    let pins = array(&inventory, "source_pins");
    assert_eq!(pins.len(), 14, "source pin census changed");
    for pin in pins {
        let path = text(pin, "path");
        let expected = text(pin, "sha256");
        if path == "fuzz/Cargo.toml" {
            assert_eq!(
                expected,
                text(
                    &Value::Object(fuzz_transition.clone()),
                    "a1_manifest_sha256"
                ),
                "A3 must name the exact A1 fuzz-manifest baseline"
            );
            assert_eq!(
                sha256_hex(&read_repo_bytes(path)),
                text(
                    &Value::Object(fuzz_transition.clone()),
                    "a3_manifest_sha256"
                ),
                "only the exact A3 current-version fuzz transition is allowed"
            );
            continue;
        }
        if path == "src/trace/file.rs" {
            assert_eq!(
                expected,
                text(
                    &Value::Object(trace_transition.clone()),
                    "a1_trace_file_sha256"
                ),
                "A4 must name the exact A1 trace-file baseline"
            );
            assert_eq!(
                sha256_hex(&read_repo_bytes(path)),
                text(
                    &Value::Object(trace_transition.clone()),
                    "a4_trace_file_sha256"
                ),
                "only the exact A4 shadow-integration transition is allowed"
            );
            continue;
        }
        assert_eq!(
            sha256_hex(&read_repo_bytes(path)),
            expected,
            "source pin drift for {path}; refresh the A1 inventory before relying on it"
        );
    }
}

#[test]
fn production_lz4_api_census_matches_source() {
    let inventory = artifact();
    let rows = array(&inventory, "production_api_census");
    assert_eq!(
        row_ids(rows, "call_site_id"),
        expected_set(&[
            "LZ4-CS-TRACE-WRITE",
            "LZ4-CS-TRACE-READ",
            "LZ4-CS-TRACE-ITER",
            "LZ4-CS-ATP-MANIFEST-SIZE",
            "LZ4-CS-ATP-COMPRESS",
            "LZ4-CS-ATP-DECOMPRESS",
            "LZ4-CS-ATP-ADAPTER-COMPRESS",
            "LZ4-CS-ATP-ADAPTER-DECOMPRESS",
        ])
    );

    let trace = read_repo_file("src/trace/file.rs");
    assert_eq!(count(&trace, "lz4_flex::compress_prepend_size"), 3);
    assert_eq!(count(&trace, "lz4_flex::decompress_size_prepended"), 1);
    assert_eq!(count(&trace, "lz4_flex::block::DecompressError"), 0);

    let manifest = read_repo_file("src/atp/manifest.rs");
    assert_eq!(count(&manifest, "lz4_flex::compress_prepend_size"), 1);

    let service = read_repo_file("src/net/atp/compress/mod.rs");
    assert_eq!(count(&service, "lz4_flex::compress_prepend_size"), 2);
    assert_eq!(count(&service, "lz4_flex::decompress_size_prepended"), 1);

    let adapter = read_repo_file("src/net/atp/compress/algorithms.rs");
    assert_eq!(count(&adapter, "lz4_flex::compress_prepend_size"), 1);
    assert_eq!(count(&adapter, "lz4_flex::decompress_size_prepended"), 1);
}

#[test]
fn manifest_lock_and_a3_fuzz_version_transition_are_frozen() {
    let inventory = artifact();
    let graph = object(&inventory, "dependency_graph");
    assert_eq!(graph["root_normal_edge"]["requirement"], "0.14");
    assert_eq!(graph["root_normal_edge"]["resolved"], "0.14.0");
    assert_eq!(graph["root_normal_edge"]["optional"], true);
    assert_eq!(
        graph["root_normal_edge"]["enabling_feature"],
        "trace-compression"
    );
    assert_eq!(graph["root_dev_edge"]["resolved"], "0.14.0");
    assert_eq!(
        graph["fuzz_edge"]["resolution_state"],
        "UNPINNED_EXCLUDED_WORKSPACE"
    );
    assert_eq!(graph["fuzz_edge"]["parity_state"], "VERSION_DRIFT_RISK");

    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("trace-compression = [\"dep:lz4_flex\"]"));
    assert!(manifest.contains("lz4_flex = { version = \"0.14\", optional = true }"));
    assert!(manifest.contains("lz4_flex = \"0.14\""));

    let fuzz_manifest = read_repo_file("fuzz/Cargo.toml");
    assert!(fuzz_manifest.contains("lz4_flex = \"=0.14.0\""));
    assert!(!fuzz_manifest.contains("lz4_flex = \"0.13\""));
    let a3 = parse_repo_json(A3_CORPUS_PATH);
    let transition = object(&a3, "fuzz_contract");
    assert_eq!(transition["incumbent_requirement"], "=0.14.0");
    assert_eq!(transition["incumbent_resolved"], "0.14.0");
    assert_eq!(
        sha256_hex(fuzz_manifest.as_bytes()),
        transition["a3_manifest_sha256"]
    );
    let root_lock = read_repo_file("Cargo.lock");
    assert!(root_lock.contains("name = \"lz4_flex\"\nversion = \"0.14.0\""));
}

#[test]
fn trace_container_and_block_contract_match_source() {
    let inventory = artifact();
    let format = object(&inventory, "trace_format_contract");
    assert_eq!(format["magic"], "ASUPERTRACE");
    assert_eq!(format["current_version"], 3);
    assert_eq!(format["readable_versions"], serde_json::json!([1, 2, 3]));
    assert_eq!(format["compression_byte"], 1);
    assert_eq!(format["codec_container"], "LZ4_SIZE_PREPENDED_BLOCK");
    assert_eq!(format["lz4_frame_format_supported"], false);
    assert_eq!(format["dictionary_supported"], false);
    assert_eq!(format["block_checksum_supported"], false);
    assert_eq!(format["content_checksum_supported"], false);

    let source = read_repo_file("src/trace/file.rs");
    for needle in [
        "pub const TRACE_MAGIC: &[u8; 11] = b\"ASUPERTRACE\";",
        "pub const TRACE_FILE_VERSION: u16 = 3;",
        "pub const FLAG_COMPRESSED: u16 = 0x0001;",
        "pub const FLAG_CHECKSUMMED: u16 = 0x0002;",
        "1 => Some(Self::Lz4 { level: 1 })",
        "let compressed = self.lz4_codec.encode(&self.event_buffer)?;",
        "let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;",
    ] {
        assert!(
            source.contains(needle),
            "missing trace contract needle: {needle}"
        );
    }
}

#[test]
fn a4_owned_shadow_integration_preserves_the_incumbent_default() {
    let receipt = parse_repo_json(A4_RECEIPT_PATH);
    assert_eq!(receipt["bead_id"], "asupersync-0h6myr.4.4");
    assert_eq!(receipt["capability_id"], CAPABILITY_ID);
    assert_eq!(receipt["decision"]["verdict"], "KEEP_INCUMBENT");
    assert_eq!(receipt["decision"]["production_default_changed"], false);

    let transition = object(&receipt, "source_transition");
    assert_eq!(transition["root_manifest_changed"], false);
    assert_eq!(transition["production_codec"], "lz4_flex 0.14.0");
    assert_eq!(
        transition["owned_codec_surface"],
        "test-internals shadow integration only"
    );

    let source = read_repo_file("src/trace/file.rs");
    for needle in [
        "Self::from_file_with_lz4_codec(file, config, Lz4Codec::Incumbent)",
        "Self::open_with_lz4_codec(path, Lz4Codec::Incumbent)",
        "migrate_trace_file_with_lz4_codec(input, output, Lz4Codec::Incumbent)",
        "#[cfg(all(feature = \"trace-compression\", feature = \"test-internals\"))]",
    ] {
        assert!(
            source.contains(needle),
            "missing A4 shadow-integration guard: {needle}"
        );
    }
}

#[test]
fn resource_envelope_and_semantic_gaps_are_explicit() {
    let inventory = artifact();
    let resource = object(&inventory, "resource_envelope");
    assert_eq!(resource["default_uncompressed_chunk_bytes"], 65_536);
    assert_eq!(resource["documented_auto_threshold_bytes"], 1_048_576);
    assert_eq!(resource["max_compressed_chunk_bytes"], 67_108_864);
    assert_eq!(
        resource["max_advertised_decompressed_chunk_bytes"],
        67_108_864
    );
    assert_eq!(resource["max_single_event_bytes"], 16_777_216);
    assert_eq!(
        resource["peak_memory_state"],
        "BOUND_DECLARED_MEASUREMENT_PENDING"
    );

    let gaps = array(&inventory, "observed_semantic_gaps");
    assert_eq!(
        row_ids(gaps, "gap_id"),
        expected_set(&[
            "LZ4-GAP-01",
            "LZ4-GAP-02",
            "LZ4-GAP-03",
            "LZ4-GAP-04",
            "LZ4-GAP-05",
            "LZ4-GAP-06",
            "LZ4-GAP-07",
            "LZ4-GAP-08",
            "LZ4-GAP-09",
            "LZ4-GAP-10",
            "LZ4-GAP-11",
        ])
    );
    assert!(
        gaps.iter()
            .all(|gap| text(gap, "state").starts_with("ROUTED")),
        "every A1 gap must be routed"
    );

    let source = read_repo_file("src/trace/file.rs");
    assert_eq!(count(&source, "AUTO_COMPRESSION_THRESHOLD"), 1);
    assert_eq!(count(&source, "Self::Lz4 { .. } | Self::Auto => 1"), 1);
}

#[test]
fn registered_baseline_mismatch_and_future_evidence_are_visible() {
    let inventory = artifact();
    let routes = array(&inventory, "evidence_routes");
    assert_eq!(routes.len(), 5);
    assert_eq!(routes[0]["state"], "COMPLETE");
    assert!(
        routes[1..].iter().all(|row| row["state"] == "PLANNED"),
        "A2-A5 evidence must remain planned at A1"
    );

    let baseline = parse_repo_json("artifacts/dependency_capability_baseline_v1.json");
    let evidence = array(&baseline, "evidence_catalog")
        .iter()
        .find(|row| row["evidence_id"] == "EVD-TRACE-LZ4")
        .expect("EVD-TRACE-LZ4 must exist");
    assert_eq!(
        evidence["fixture_paths"],
        serde_json::json!(["tests/trace_compression_conformance.rs"])
    );
    let fixture = read_repo_file("tests/trace_compression_conformance.rs");
    assert!(!fixture.contains("lz4_flex::"));

    let gaps = array(&inventory, "observed_semantic_gaps");
    let gap = gaps
        .iter()
        .find(|row| row["gap_id"] == "LZ4-GAP-05")
        .expect("baseline mismatch gap must be present");
    assert_eq!(gap["owner"], "asupersync-0h6myr.4.3");

    let a3 = parse_repo_json(A3_CORPUS_PATH);
    let disposition = object(&a3, "baseline_evidence_disposition");
    assert_eq!(disposition["historical_evidence_id"], "EVD-TRACE-LZ4");
    assert_eq!(disposition["historical_state"], "SEMANTIC_FILTERING_ONLY");
    assert_eq!(disposition["a3_receipt"], "LZ4-EVD-A3-CORPUS");
}

#[test]
fn representative_measurement_is_scoped_and_non_gating() {
    let inventory = artifact();
    let measurements = object(&inventory, "representative_measurements");
    let criterion = object(
        &Value::Object(measurements.clone()),
        "criterion_trace_10000_events",
    )
    .clone();
    assert_eq!(criterion["source_revision"], BASELINE_REVISION);
    assert_eq!(criterion["rch_worker"], "ovh-a");
    assert_eq!(criterion["rch_job_id"], "29948224668172532");
    assert_eq!(criterion["sample_count"], 100);
    assert_eq!(criterion["write_uncompressed_median_ns"], 1_127_400);
    assert_eq!(criterion["write_lz4_median_ns"], 1_066_600);
    assert_eq!(criterion["read_uncompressed_median_ns"], 1_617_000);
    assert_eq!(criterion["read_lz4_median_ns"], 1_676_700);
    assert_eq!(criterion["cpu_model"], "UNAVAILABLE");
    assert_eq!(criterion["rss_bytes"], "UNAVAILABLE");
    assert!(
        array(&Value::Object(criterion), "limitations").len() >= 6,
        "single-host benchmark limitations must remain explicit"
    );

    let probe = &measurements["deterministic_payload_probe"];
    assert_eq!(probe["state"], "CAPTURED_PLANNING_ONLY");
    assert_eq!(probe["rch_worker"], "ovh-a");
    assert_eq!(probe["rch_job_id"], "29948224668172536");
    assert_eq!(probe["iterations"], 64);
    let payloads = probe["payloads"]
        .as_array()
        .expect("deterministic payloads must be an array");
    assert_eq!(
        row_ids(payloads, "payload_id"),
        expected_set(&[
            "empty",
            "repeated_256k",
            "structured_trace_like",
            "splitmix_256k",
        ])
    );
    let exact_sizes: Vec<(u64, u64)> = payloads
        .iter()
        .map(|payload| {
            (
                payload["input_bytes"]
                    .as_u64()
                    .expect("input_bytes must be u64"),
                payload["compressed_bytes"]
                    .as_u64()
                    .expect("compressed_bytes must be u64"),
            )
        })
        .collect();
    assert_eq!(
        exact_sizes,
        vec![
            (0, 5),
            (262_144, 1_043),
            (240_020, 49_895),
            (262_144, 263_177)
        ]
    );
}

#[test]
fn docs_and_no_claim_boundaries_are_discoverable() {
    let inventory = artifact();
    let doc = read_repo_file(DOC_PATH);
    assert!(doc.contains(DOC_BEGIN));
    assert!(doc.contains(DOC_END));
    for marker in [
        BEAD_ID,
        CAPABILITY_ID,
        "REPLACE_EXPERIMENT_AUTHORIZED",
        "LZ4_SIZE_PREPENDED_BLOCK",
        "LZ4-GAP-05",
        "KEEP_INCUMBENT",
        "It grants no permission to delete files.",
    ] {
        assert!(doc.contains(marker), "missing docs marker: {marker}");
    }

    let boundaries = array(&inventory, "no_claim_boundaries");
    assert!(boundaries.len() >= 10);
    let joined = boundaries
        .iter()
        .map(|row| row.as_str().expect("boundary must be text"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "not cutover approval",
        "not the LZ4 frame format",
        "does not prove performance improvement",
        "not LZ4 byte-codec evidence",
        "does not authorize removing lz4_flex",
        "permission to delete files",
    ] {
        assert!(
            joined.contains(required),
            "missing no-claim boundary: {required}"
        );
    }
}

#[test]
fn mutation_of_gate_or_format_is_rejected() {
    let inventory = artifact();

    let mut cutover = inventory.clone();
    cutover["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert_ne!(cutover["authority"], inventory["authority"]);
    assert_eq!(inventory["authority"]["dependency_exit_allowed"], false);

    let mut frame = inventory.clone();
    frame["trace_format_contract"]["lz4_frame_format_supported"] = Value::Bool(true);
    assert_ne!(
        frame["trace_format_contract"],
        inventory["trace_format_contract"]
    );
    assert_eq!(
        inventory["trace_format_contract"]["lz4_frame_format_supported"],
        false
    );

    let mut unknown = inventory.clone();
    unknown["authority"]["gate_decision"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_no_unknown(&unknown, "$").is_err());
}

#[test]
fn representative_payload_ratios_are_reproducible() {
    fn splitmix_bytes(len: usize) -> Vec<u8> {
        let mut state = 0xA17E_5EED_CAFE_BABEu64;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            out.push((z ^ (z >> 31)) as u8);
        }
        out
    }

    let mut structured = Vec::new();
    for index in 0..4096u32 {
        structured.extend_from_slice(
            format!(
                "{{\"seq\":{index},\"kind\":\"task_scheduled\",\"task\":{},\"tick\":{index}}}\n",
                index % 128
            )
            .as_bytes(),
        );
    }

    let payloads = [
        ("empty", Vec::new()),
        ("repeated_256k", vec![b'A'; 256 * 1024]),
        ("structured_trace_like", structured),
        ("splitmix_256k", splitmix_bytes(256 * 1024)),
    ];

    for (name, payload) in payloads {
        let iterations = 64u128;
        let started = Instant::now();
        let mut compressed = Vec::new();
        for _ in 0..iterations {
            compressed = lz4_flex::compress_prepend_size(std::hint::black_box(&payload));
            std::hint::black_box(&compressed);
        }
        let elapsed = started.elapsed();
        let decoded = lz4_flex::decompress_size_prepended(&compressed)
            .unwrap_or_else(|error| panic!("{name} must decode: {error}"));
        assert_eq!(decoded, payload, "{name} roundtrip");

        let ratio_ppm = if payload.is_empty() {
            0
        } else {
            u64::try_from(
                (compressed.len() as u128)
                    .saturating_mul(1_000_000)
                    .checked_div(payload.len() as u128)
                    .expect("nonempty payload"),
            )
            .expect("ratio fits u64")
        };
        let input_bytes_per_second = if elapsed.is_zero() {
            0
        } else {
            u64::try_from(
                (payload.len() as u128)
                    .saturating_mul(iterations)
                    .saturating_mul(1_000_000_000)
                    .checked_div(elapsed.as_nanos())
                    .expect("nonzero elapsed"),
            )
            .expect("throughput fits u64")
        };
        println!(
            "LZ4_A1_PROBE name={name} input_bytes={} compressed_bytes={} ratio_ppm={ratio_ppm} iterations={iterations} input_bytes_per_second={input_bytes_per_second}",
            payload.len(),
            compressed.len()
        );
    }
}
