//! Contract checks for the terminal DEFLATE A1 inventory.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const ARTIFACT_PATH: &str = "artifacts/deflate_surface_inventory_v1.json";
const RUNBOOK_PATH: &str = "docs/deflate_surface_inventory.md";

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo_path(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn artifact() -> &'static Value {
    static ARTIFACT: OnceLock<Value> = OnceLock::new();
    ARTIFACT.get_or_init(|| {
        serde_json::from_str(&read(ARTIFACT_PATH))
            .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
    })
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value[key]
        .as_object()
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn identity_and_terminal_keep_are_fail_closed() {
    let artifact = artifact();
    assert_eq!(number(artifact, "schema_version"), 1);
    assert_eq!(
        text(artifact, "artifact_id"),
        "deflate-surface-inventory-v1"
    );
    assert_eq!(text(artifact, "bead_id"), "asupersync-0h6myr.5.1");
    assert_eq!(text(artifact, "capability_id"), "CAP-HTTP-COMPRESSION");
    assert_eq!(text(artifact, "authority"), "INVENTORY_EVIDENCE_ONLY");
    assert_eq!(artifact["production_change_made"], false);

    let decision = object(artifact, "decision");
    assert_eq!(decision["status"], "KEEP");
    assert_eq!(decision["disposition"], "KEEP_INCUMBENT");
    assert_eq!(decision["dependency"], "flate2");
    assert_eq!(decision["dependency_exit_allowed"], false);
    assert_eq!(decision["owned_replacement_authorized"], false);
    assert_eq!(
        decision["implementation_followups_authorized"],
        serde_json::json!([])
    );
    assert!(!text(&Value::Object(decision.clone()), "reason").is_empty());
}

#[test]
fn dependency_edges_backend_and_marginal_graph_are_exact() {
    let resolution = object(artifact(), "dependency_resolution");
    let resolution_value = Value::Object(resolution.clone());
    let edges = array(&resolution_value, "manifest_edges");
    assert_eq!(edges.len(), 2);
    assert_eq!(
        edges
            .iter()
            .map(|edge| text(edge, "edge_id"))
            .collect::<BTreeSet<_>>(),
        ["dev:flate2", "normal:flate2"].into_iter().collect()
    );
    assert_eq!(edges[0]["optional"], true);
    assert_eq!(edges[1]["optional"], false);

    let package = object(&resolution_value, "lock_package");
    assert_eq!(package["name"], "flate2");
    assert_eq!(package["version"], "1.1.9");
    assert_eq!(
        package["direct_dependencies"],
        serde_json::json!(["crc32fast 1.5.0", "miniz_oxide 0.8.9"])
    );

    let backend = object(&resolution_value, "selected_backend");
    assert_eq!(backend["feature"], "rust_backend");
    assert_eq!(backend["implementation"], "miniz_oxide 0.8.9");
    assert!(backend["system_library"].is_null());
    assert_eq!(backend["native_build_script_active"], false);
    assert_eq!(backend["host_specific_backend_selection"], false);

    assert_eq!(
        resolution["compression_profile_marginal_packages"],
        serde_json::json!([
            "flate2 1.1.9",
            "miniz_oxide 0.8.9",
            "adler2 2.0.1",
            "simd-adler32 0.3.10"
        ])
    );
    let tree = object(&resolution_value, "tree_command_status");
    assert_eq!(tree["status"], "NO_CLAIM_RCH_NON_COMPILATION_REFUSAL");
    assert_eq!(tree["error_code"], "RCH-E301");
}

#[test]
fn profile_matrix_separates_pass_unsupported_and_unrun_cells() {
    let matrix = array(artifact(), "profile_matrix");
    let by_id = |cell_id: &str| {
        matrix
            .iter()
            .find(|row| text(row, "cell_id") == cell_id)
            .unwrap_or_else(|| panic!("missing profile cell {cell_id}"))
    };

    let default = by_id("DEFAULT-X86_64-LINUX");
    assert_eq!(default["status"], "PASS");
    assert_eq!(default["flate2_normal_edge_active"], false);
    assert_eq!(default["exit_code"], 0);

    let compression = by_id("COMPRESSION-ALL-TARGETS-X86_64-LINUX");
    assert_eq!(compression["status"], "PASS");
    assert_eq!(compression["flate2_normal_edge_active"], true);
    assert_eq!(compression["backend"], "rust_backend/miniz_oxide");
    assert_eq!(compression["exit_code"], 0);

    let wasm = by_id("COMPRESSION-WASM32-UNKNOWN-UNKNOWN");
    assert_eq!(wasm["status"], "UNSUPPORTED_WORKER_TARGET_MISSING");
    assert_eq!(wasm["exit_code"], 101);
    for cell_id in [
        "COMPRESSION-AARCH64-APPLE-DARWIN",
        "COMPRESSION-X86_64-WINDOWS-MSVC",
    ] {
        assert_eq!(by_id(cell_id)["status"], "NO_CLAIM_NOT_RUN");
    }
}

#[test]
fn live_persisted_test_and_orphaned_surfaces_are_distinguished() {
    let inventory = array(artifact(), "surface_inventory");
    let actual = inventory
        .iter()
        .map(|row| text(row, "surface_id"))
        .collect::<BTreeSet<_>>();
    let expected = [
        "DEFLATE-HTTP-CODECS",
        "DEFLATE-GRPC-FRAMES",
        "DEFLATE-ATP-TRANSPORT",
        "DEFLATE-ATP-CACHE-PERSISTENCE",
        "DEFLATE-ATP-MAILBOX-PERSISTENCE",
        "DEFLATE-ATP-MANIFEST-METADATA",
        "DEFLATE-OTLP-HTTP",
        "DEFLATE-METRICS-TEST-HARNESS",
        "DEFLATE-ORPHANED-ATP-ENGINE",
        "DEFLATE-DEV-COMPRESSED-FRAME-HARNESS",
        "DEFLATE-WEBSOCKET-EXTENSION",
        "DEFLATE-KAFKA-EXTERNAL-BACKEND",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    for row in inventory {
        assert!(
            repo_path(text(row, "source_path")).is_file(),
            "source path must exist for {}",
            text(row, "surface_id")
        );
        assert!(!array(row, "formats").is_empty());
        assert!(!array(row, "apis").is_empty());
        assert!(!text(row, "streaming").is_empty());
        assert!(!text(row, "limits").is_empty());
    }

    let by_id = |surface_id: &str| {
        inventory
            .iter()
            .find(|row| text(row, "surface_id") == surface_id)
            .unwrap_or_else(|| panic!("missing surface {surface_id}"))
    };
    assert_eq!(by_id("DEFLATE-HTTP-CODECS")["status"], "LIVE_PRODUCTION");
    assert_eq!(
        by_id("DEFLATE-ATP-CACHE-PERSISTENCE")["status"],
        "LIVE_PERSISTED_FORMAT"
    );
    assert_eq!(
        by_id("DEFLATE-ATP-MAILBOX-PERSISTENCE")["status"],
        "LIVE_PERSISTED_FORMAT"
    );
    assert_eq!(by_id("DEFLATE-METRICS-TEST-HARNESS")["status"], "TEST_ONLY");
    assert_eq!(
        by_id("DEFLATE-ORPHANED-ATP-ENGINE")["status"],
        "EXCLUDED_ORPHANED_SOURCE"
    );
    assert_eq!(
        by_id("DEFLATE-ORPHANED-ATP-ENGINE")["downstream_consumers"],
        serde_json::json!([])
    );
    assert_eq!(
        by_id("DEFLATE-ATP-TRANSPORT")["status"],
        "LIVE_PUBLIC_UNWIRED"
    );
    assert_eq!(
        by_id("DEFLATE-ATP-TRANSPORT")["production_callsite_count"],
        0
    );
    assert_eq!(
        by_id("DEFLATE-WEBSOCKET-EXTENSION")["status"],
        "ADVERTISEMENT_ONLY_NO_CODEC"
    );
    assert_eq!(
        by_id("DEFLATE-KAFKA-EXTERNAL-BACKEND")["status"],
        "EXTERNAL_BACKEND_NOT_FLATE2"
    );
}

#[test]
fn raw_zlib_gzip_dictionary_member_and_flush_scope_is_frozen() {
    let format = object(artifact(), "format_scope");
    let format_value = Value::Object(format.clone());

    let gzip = object(&format_value, "gzip");
    assert_eq!(gzip["required"], true);
    assert_eq!(gzip["rfc"], "RFC 1952");
    assert_eq!(gzip["header_customization"], false);
    assert_eq!(gzip["checksum_and_size_trailer"], true);
    assert_eq!(gzip["default_level"], 6);

    let raw = object(&format_value, "raw_deflate");
    assert_eq!(raw["required"], true);
    assert_eq!(raw["rfc"], "RFC 1951");
    assert_eq!(raw["empty_stream_hex"], "0300");

    let zlib = object(&format_value, "zlib_wrapper");
    assert_eq!(zlib["required_by_current_bytes"], false);
    assert_eq!(zlib["rfc"], "RFC 1950");
    assert_eq!(zlib["direct_api_uses"], 0);
    assert_eq!(zlib["status"], "ABSENT");

    let dictionary = object(&format_value, "preset_dictionary");
    assert_eq!(dictionary["supported"], false);
    assert_eq!(dictionary["direct_api_uses"], 0);
    assert_eq!(dictionary["status"], "ABSENT");

    let flush = object(&format_value, "flush_and_finish");
    for key in [
        "http_gzip_compress",
        "http_deflate_compress",
        "http_gzip_decompress",
        "http_deflate_decompress",
        "one_shot_callers",
    ] {
        assert!(!text(&Value::Object(flush.clone()), key).is_empty());
    }
}

#[test]
fn source_text_matches_the_frozen_format_and_owner_claims() {
    let manifest = read("Cargo.toml");
    assert!(manifest.contains("compression = [\"dep:flate2\", \"dep:brotli\"]"));
    assert!(manifest.contains("flate2 = { version = \"1.1\", optional = true }"));
    assert!(manifest.contains("flate2 = \"1.1\""));

    let lock = read("Cargo.lock");
    assert!(lock.contains("name = \"flate2\"\nversion = \"1.1.9\""));
    assert!(lock.contains("\"miniz_oxide\""));

    let http = read("src/http/compress.rs");
    assert!(http.contains("flate2::write::GzEncoder"));
    assert!(http.contains("flate2::write::DeflateEncoder"));
    assert!(http.contains("pub fn with_level(level: flate2::Compression)"));
    assert!(http.contains("vec![0x03, 0x00]"));
    assert!(!http.contains("flate2::write::ZlibEncoder"));
    assert!(!http.contains("flate2::write::ZlibDecoder"));

    let atp_mod = read("src/net/atp/mod.rs");
    assert!(atp_mod.contains("pub mod transport_common;"));
    assert!(!atp_mod.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "pub mod compress;" || trimmed == "mod compress;"
    }));

    for live_path in [
        "src/grpc/codec.rs",
        "src/net/atp/transport_common/compression.rs",
        "src/atp/cache/storage.rs",
        "src/atp/mailbox/storage.rs",
        "src/atp/manifest.rs",
        "src/observability/otel.rs",
    ] {
        assert!(
            read(live_path).contains("flate2"),
            "{live_path} must remain a direct live owner"
        );
    }
}

#[test]
fn payload_evidence_and_authority_conflict_remain_honest() {
    let baseline = object(artifact(), "payload_baseline");
    let baseline_value = Value::Object(baseline.clone());
    let production = object(&baseline_value, "production_telemetry");
    assert_eq!(production["status"], "NO_CLAIM_NOT_CAPTURED");
    assert_eq!(production["distributions"], serde_json::json!([]));

    let fixtures = object(&baseline_value, "source_fixture_distribution");
    assert_eq!(fixtures["status"], "FIXTURE_ONLY");
    assert_eq!(fixtures["minimum_plaintext_bytes"], 0);
    assert_eq!(fixtures["maximum_plaintext_bytes"], 16_384);
    assert!(array(&Value::Object(fixtures.clone()), "representative_cells").len() >= 6);

    let reconciliation = object(artifact(), "evidence_reconciliation");
    assert_eq!(reconciliation["capability_registry"], "BASELINE_PLANNED");
    assert_eq!(reconciliation["capability_baseline"], "EXECUTABLE_COMPLETE");
    assert_eq!(reconciliation["actual_service_scenario"], "NOT_REGISTERED");
    assert_eq!(reconciliation["cutover_eligible"], false);
}

#[test]
fn exit_blockers_parity_scope_and_no_claims_are_complete() {
    let gaps = array(artifact(), "gaps");
    assert_eq!(gaps.len(), 17);
    assert_eq!(
        gaps.iter()
            .map(|gap| text(gap, "gap_id").to_string())
            .collect::<BTreeSet<_>>(),
        (1..=17)
            .map(|index| format!("DEF-A1-{index:02}"))
            .collect::<BTreeSet<_>>()
    );
    assert!(gaps.iter().filter(|gap| gap["blocks_exit"] == true).count() >= 15);

    let parity = array(artifact(), "required_parity_scope");
    assert!(parity.len() >= 10);
    let parity_text = parity
        .iter()
        .map(|value| value.as_str().expect("parity row must be text"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "feature-off",
        "raw RFC 1951",
        "ASUPCACHE",
        "ASUPMBX1",
        "gRPC",
        "OTLP",
        "cache and mailbox",
        "Kafka",
        "Brotli",
    ] {
        assert!(
            parity_text.contains(required),
            "missing parity marker {required}"
        );
    }

    let no_claims = array(artifact(), "no_claims");
    assert!(no_claims.len() >= 7);
    let no_claim_text = no_claims
        .iter()
        .map(|value| value.as_str().expect("no-claim row must be text"))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "No dependency removal",
        "No production payload distribution",
        "No Apple",
        "No registered real-service",
        "No zlib-wrapper",
        "No production ATP transport wiring",
        "No cache or mailbox decoder-allocation safety",
        "not release readiness",
        "Brotli",
    ] {
        assert!(
            no_claim_text.contains(required),
            "missing no-claim marker {required}"
        );
    }
}

#[test]
fn every_source_pin_matches_current_bytes_and_line_count() {
    let pins = array(artifact(), "source_pins");
    assert!(pins.len() >= 28);
    let mut seen = BTreeSet::new();

    for pin in pins {
        let path = text(pin, "path");
        assert!(seen.insert(path), "duplicate source pin {path}");
        let bytes = std::fs::read(repo_path(path))
            .unwrap_or_else(|error| panic!("read pinned source {path}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "source hash drift for {path}"
        );
        let source = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("pinned source {path} must be UTF-8: {error}"));
        assert_eq!(
            source.lines().count() as u64,
            number(pin, "line_count"),
            "line-count drift for {path}"
        );
    }
}

#[test]
fn runbook_contains_decision_scope_and_no_claim_markers() {
    let runbook = read(RUNBOOK_PATH);
    for marker in [
        "# DEFLATE surface and backend inventory",
        "KEEP_INCUMBENT",
        "rust_backend",
        "raw RFC 1951",
        "ASUPCACHE",
        "ASUPMBX1",
        "permessage-deflate",
        "Payload evidence",
        "Evidence conflicts and exit blockers",
        "Rollback and no-claim boundary",
        "does not authorize removing `flate2`",
    ] {
        assert!(runbook.contains(marker), "missing runbook marker {marker}");
    }

    let ignore = read(".gitignore");
    assert!(ignore.contains("!artifacts/deflate_surface_inventory_v1.json"));
}
