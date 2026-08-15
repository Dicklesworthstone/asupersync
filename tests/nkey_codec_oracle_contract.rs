//! Executable pre-cutover contract for the bounded NKey codec oracle.
//!
//! Beads: `asupersync-dep-p4-nkeys-poc60v.1.2.1` through
//! `asupersync-dep-p4-nkeys-poc60v.1.2.4`.
//! The incumbent remains the production implementation. This test-only lane
//! proves byte-codec comparisons and graph isolation only; it does not prove
//! signer authorization, secret zeroization, cryptographic soundness, or
//! production-cutover readiness.

#![allow(missing_docs)]

#[path = "dependency_oracles/nkeys/mod.rs"]
mod nkeys_oracle;
#[path = "../src/security/keys/nkey_codec.rs"]
mod owned_nkey_codec;

use nkeys::{KeyPair, KeyPairType};
use nkeys_oracle::{
    CodecError, EncodedKind, Field, MAX_DECODED_BYTES, MAX_ENCODED_CHARS, NonCanonicalKind,
    PROVENANCE, crc16_xmodem, decode_and_verify, decoded_capacity_for, encode_with_checksum,
    encoded_len_for,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const POLICY_PATH: &str = "artifacts/dependency_oracle_policy_v1.json";
const SPEC_PATH: &str = "artifacts/nkey_normative_spec_v1.json";
const RECEIPT_PATH: &str = "artifacts/nkey_codec_terminal_receipt_v1.json";
const HARNESS_PATH: &str = "tests/dependency_oracles/nkeys";
const MODULE_PATH: &str = "tests/dependency_oracles/nkeys/mod.rs";
const ORACLE_ID: &str = "nkeys-reference";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must remain valid JSON: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_json_sha256(value: &Value) -> String {
    let mut encoded = serde_json::to_vec(value).expect("canonical JSON value must serialize");
    encoded.push(b'\n');
    sha256_hex(&encoded)
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

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn decode_hex_32(encoded: &str) -> [u8; 32] {
    hex::decode(encoded)
        .unwrap_or_else(|error| panic!("invalid hex vector: {error}"))
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected 32 bytes, got {}", bytes.len()))
}

fn key_pair_type(name: &str) -> KeyPairType {
    match name {
        "Server" => KeyPairType::Server,
        "Cluster" => KeyPairType::Cluster,
        "Operator" => KeyPairType::Operator,
        "Account" => KeyPairType::Account,
        "User" => KeyPairType::User,
        "Module" => KeyPairType::Module,
        "Service" => KeyPairType::Service,
        "Curve" => KeyPairType::Curve,
        other => panic!("unknown vector key kind {other}"),
    }
}

fn prefix_byte(key_type: &KeyPairType) -> u8 {
    match key_type {
        KeyPairType::Server => 104,
        KeyPairType::Cluster => 16,
        KeyPairType::Operator => 112,
        KeyPairType::Account => 0,
        KeyPairType::User => 160,
        KeyPairType::Module => 96,
        KeyPairType::Service => 168,
        KeyPairType::Curve => 184,
    }
}

fn packed_seed_prefix(prefix: u8) -> [u8; 2] {
    [0x90 | (prefix >> 5), (prefix & 0x1f) << 3]
}

fn independently_framed_body(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 2);
    frame.extend_from_slice(body);
    frame.extend_from_slice(&crc16_xmodem(body).to_le_bytes());
    frame
}

fn replace_ascii_byte(source: &str, index: usize, replacement: u8) -> String {
    let mut bytes = source.as_bytes().to_vec();
    bytes[index] = replacement;
    String::from_utf8(bytes).expect("NKey test mutation remains ASCII")
}

#[derive(Debug, Eq, PartialEq)]
struct ManifestEdge {
    manifest: String,
    section: String,
    alias: String,
    package: String,
}

fn collect_manifests(directory: &Path, manifests: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
    for entry in entries {
        let entry = entry.expect("repository directory entry must be readable");
        let file_type = entry
            .file_type()
            .expect("repository directory entry type must be readable");
        let path = entry.path();
        if file_type.is_dir() {
            if matches!(
                entry.file_name().to_str(),
                Some(".git" | ".beads" | "target" | "node_modules")
            ) {
                continue;
            }
            collect_manifests(&path, manifests);
        } else if file_type.is_file() && entry.file_name() == "Cargo.toml" {
            manifests.push(path);
        }
    }
}

fn collect_dependency_edges(
    value: &toml::Value,
    manifest: &str,
    path: &mut Vec<String>,
    edges: &mut Vec<ManifestEdge>,
) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        path.push(key.clone());
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            if let Some(dependencies) = child.as_table() {
                for (alias, dependency) in dependencies {
                    let package = dependency
                        .as_table()
                        .and_then(|table| table.get("package"))
                        .and_then(toml::Value::as_str)
                        .unwrap_or(alias);
                    if matches!(package, "nkeys" | "async-nats" | "nats") {
                        edges.push(ManifestEdge {
                            manifest: manifest.to_owned(),
                            section: path.join("."),
                            alias: alias.clone(),
                            package: package.to_owned(),
                        });
                    }
                }
            }
        }
        collect_dependency_edges(child, manifest, path, edges);
        path.pop();
    }
}

fn nkey_and_reference_client_edges() -> Vec<ManifestEdge> {
    let mut manifests = Vec::new();
    collect_manifests(&repo_root(), &mut manifests);
    manifests.sort();

    let mut edges = Vec::new();
    for manifest in manifests {
        let relative = manifest
            .strip_prefix(repo_root())
            .expect("manifest must be inside repository")
            .to_string_lossy()
            .into_owned();
        let parsed: toml::Value = toml::from_str(
            &std::fs::read_to_string(&manifest)
                .unwrap_or_else(|error| panic!("failed to read {relative}: {error}")),
        )
        .unwrap_or_else(|error| panic!("failed to parse {relative}: {error}"));
        collect_dependency_edges(&parsed, &relative, &mut Vec::new(), &mut edges);
    }
    edges
}

#[test]
fn provenance_policy_and_corpus_are_pinned_and_fail_closed() {
    assert!(repo_root().join(HARNESS_PATH).is_dir());
    assert!(repo_root().join(MODULE_PATH).is_file());

    let policy = parse_repo_json(POLICY_PATH);
    let row = find_row(array(&policy, "oracle_registry"), "oracle_id", ORACLE_ID);
    assert_eq!(text(row, "oracle_class"), "PURE_RUST_IN_WORKSPACE_ORACLE");
    assert_eq!(text(row, "lifecycle_state"), "planned");
    assert_eq!(
        text(row, "current_graph_state"),
        "incumbent-production-edge"
    );
    assert_eq!(
        text(row, "harness_location"),
        "repo://tests/dependency_oracles/nkeys"
    );
    assert_eq!(
        string_set(row, "allowed_profiles"),
        [
            "workspace-dev",
            "workspace-fuzz-quarantine",
            "external-cargo-harness",
            "frozen-fixture-only",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_eq!(
        string_set(row, "forbidden_profiles"),
        ["workspace-normal", "workspace-build", "workspace-release"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(
        text(row, "feature_unification_check"),
        "required-before-activation"
    );
    assert_eq!(
        text(row, "cycle_safety"),
        "NATS-reference-client-must-not-enter-production-identity-graph"
    );
    assert_eq!(
        text(row, "secret_redaction"),
        "required; only synthetic seeds may enter fixtures and logs"
    );
    assert_eq!(
        text(row, "no_claim_boundary"),
        "Agreement with nkeys does not prove signer authorization, secret zeroization, or cryptographic soundness."
    );
    assert_eq!(
        text(row, "unsafe_status"),
        "cryptographic-transitive-audit-required-before-activation"
    );
    assert!(
        !policy
            .pointer("/manifest_reconciliation/active_oracle_registry")
            .and_then(Value::as_array)
            .expect("active registry")
            .iter()
            .any(|entry| entry.get("package_name").and_then(Value::as_str) == Some("nkeys"))
    );

    let spec_bytes = std::fs::read(repo_root().join(SPEC_PATH)).expect("read NKey spec");
    assert_eq!(
        sha256_hex(&spec_bytes),
        PROVENANCE.normative_artifact_sha256
    );
    let spec: Value = serde_json::from_slice(&spec_bytes).expect("parse NKey spec");
    let rust = spec
        .pointer("/upstream_baselines/rust_incumbent")
        .expect("Rust baseline");
    assert_eq!(text(rust, "package"), PROVENANCE.rust_package);
    assert_eq!(text(rust, "version"), PROVENANCE.rust_version);
    assert_eq!(text(rust, "crates_io_checksum"), PROVENANCE.rust_checksum);
    assert_eq!(text(rust, "repository"), PROVENANCE.rust_repository);
    assert_eq!(array(rust, "default_features"), Vec::<Value>::new());
    assert_eq!(array(rust, "enabled_features"), Vec::<Value>::new());
    assert_eq!(
        rust.get("xkeys_feature_enabled").and_then(Value::as_bool),
        Some(false)
    );

    let official = spec
        .pointer("/upstream_baselines/official_go_reference")
        .expect("official Go baseline");
    assert_eq!(text(official, "package"), PROVENANCE.official_go_package);
    assert_eq!(text(official, "version"), PROVENANCE.official_go_version);
    assert_eq!(text(official, "commit"), PROVENANCE.official_go_commit);
    assert_eq!(PROVENANCE.rust_license_spdx, "Apache-2.0");
    assert_eq!(PROVENANCE.official_go_license_spdx, "Apache-2.0");
    assert_eq!(
        PROVENANCE.license_blob_git_sha,
        "261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64"
    );
    assert!(PROVENANCE.graph_disposition.contains("no oracle edge"));
    assert!(
        PROVENANCE
            .unsafe_disposition
            .contains("cutover audit remains required")
    );
    assert!(
        PROVENANCE
            .lifecycle_disposition
            .contains("policy remains planned")
    );

    let corpus = object(&spec, "vector_corpus");
    for (key, expected) in [
        (
            "independent_ed25519_vectors",
            PROVENANCE.independent_rows_sha256,
        ),
        ("private_vectors", PROVENANCE.private_rows_sha256),
        (
            "official_historical_vectors",
            PROVENANCE.official_rows_sha256,
        ),
        ("malformed_vectors", PROVENANCE.malformed_rows_sha256),
        ("cross_prefix_vectors", PROVENANCE.cross_prefix_rows_sha256),
    ] {
        assert_eq!(
            canonical_json_sha256(corpus.get(key).unwrap_or_else(|| panic!("missing {key}"))),
            expected,
            "{key} provenance hash drifted"
        );
    }
    assert_eq!(
        text(
            corpus
                .get("independent_generator")
                .expect("independent generator"),
            "independence_note"
        ),
        "The generator did not import or execute Rust nkeys. The focused Rust contract recomputes codec values with a small independent implementation and compares the incumbent separately."
    );
}

#[test]
fn terminal_receipt_pins_the_complete_n2_surface_without_cutover_overclaim() {
    let receipt = parse_repo_json(RECEIPT_PATH);
    assert_eq!(number(&receipt, "schema_version"), 1);
    assert_eq!(
        text(&receipt, "artifact_id"),
        "nkey-codec-terminal-receipt-v1"
    );
    assert_eq!(text(&receipt, "program_id"), "dependency-sovereignty");
    assert_eq!(
        text(&receipt, "bead_id"),
        "asupersync-dep-p4-nkeys-poc60v.1.2.4"
    );
    assert_eq!(text(&receipt, "capability_id"), "CAP-NKEY-CODEC");

    let pins = array(&receipt, "source_pins");
    assert_eq!(pins.len(), 3);
    assert_eq!(
        pins.iter()
            .map(|pin| text(pin, "path").to_owned())
            .collect::<BTreeSet<_>>(),
        [
            "artifacts/nkey_normative_spec_v1.json",
            "src/security/keys/nkey_codec.rs",
            "tests/dependency_oracles/nkeys/mod.rs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    for pin in pins {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            text(pin, "sha256"),
            sha256_hex(&bytes),
            "{path} digest drifted"
        );
        assert_eq!(
            number(pin, "line_count"),
            u64::try_from(read_repo_file(path).lines().count())
                .expect("repository line count fits in u64"),
            "{path} line count drifted"
        );
        assert!(!text(pin, "role").is_empty());
    }

    let upstream = Value::Object(object(&receipt, "upstream_provenance").clone());
    assert_eq!(
        text(&upstream, "rust_incumbent_package"),
        PROVENANCE.rust_package
    );
    assert_eq!(
        text(&upstream, "rust_incumbent_version"),
        PROVENANCE.rust_version
    );
    assert_eq!(
        text(&upstream, "rust_incumbent_checksum"),
        PROVENANCE.rust_checksum
    );
    assert_eq!(
        text(&upstream, "official_go_package"),
        PROVENANCE.official_go_package
    );
    assert_eq!(
        text(&upstream, "official_go_version"),
        PROVENANCE.official_go_version
    );
    assert_eq!(
        text(&upstream, "official_go_commit"),
        PROVENANCE.official_go_commit
    );

    let digests = Value::Object(object(&receipt, "corpus_digests").clone());
    for (key, expected) in [
        (
            "independent_ed25519_vectors",
            PROVENANCE.independent_rows_sha256,
        ),
        ("private_vectors", PROVENANCE.private_rows_sha256),
        (
            "official_historical_vectors",
            PROVENANCE.official_rows_sha256,
        ),
        ("malformed_vectors", PROVENANCE.malformed_rows_sha256),
        ("cross_prefix_vectors", PROVENANCE.cross_prefix_rows_sha256),
    ] {
        assert_eq!(text(&digests, key), expected, "{key} receipt drifted");
    }

    let spec = parse_repo_json(SPEC_PATH);
    let corpus = object(&spec, "vector_corpus");
    let coverage = Value::Object(object(&receipt, "coverage").clone());
    assert_eq!(number(&coverage, "aligned_prefix_rows"), 32);
    assert_eq!(number(&coverage, "unaligned_prefix_rejections"), 224);
    assert_eq!(number(&coverage, "deterministic_generated_cases"), 64);
    for (receipt_key, corpus_key) in [
        ("independent_ed25519_rows", "independent_ed25519_vectors"),
        ("private_layout_rows", "private_vectors"),
        ("official_historical_rows", "official_historical_vectors"),
        ("malformed_rows", "malformed_vectors"),
        ("cross_prefix_rows", "cross_prefix_vectors"),
    ] {
        assert_eq!(
            number(&coverage, receipt_key),
            u64::try_from(
                corpus
                    .get(corpus_key)
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("missing {corpus_key}"))
                    .len()
            )
            .expect("corpus row count fits in u64")
        );
    }
    assert!(boolean(
        &coverage,
        "unknown_aligned_prefix_is_structurally_valid"
    ));
    assert_eq!(
        text(&coverage, "semantic_prefix_policy_owner"),
        "asupersync-dep-p4-nkeys-poc60v.1.4"
    );

    let resources = Value::Object(object(&receipt, "resource_envelope").clone());
    for (key, expected) in [
        ("checksum_bytes", owned_nkey_codec::CHECKSUM_BYTES),
        ("max_body_bytes", owned_nkey_codec::MAX_BODY_BYTES),
        ("max_frame_bytes", owned_nkey_codec::MAX_FRAME_BYTES),
        (
            "max_base32_decoded_bytes",
            owned_nkey_codec::MAX_FRAME_BYTES,
        ),
        (
            "max_base32_encoded_chars",
            owned_nkey_codec::MAX_BASE32_ENCODED_CHARS,
        ),
        ("seed_payload_bytes", owned_nkey_codec::SEED_PAYLOAD_BYTES),
        ("seed_body_bytes", owned_nkey_codec::SEED_BODY_BYTES),
        ("seed_frame_bytes", owned_nkey_codec::SEED_FRAME_BYTES),
        ("seed_encoded_chars", owned_nkey_codec::SEED_ENCODED_CHARS),
        ("generated_case_count", 64),
    ] {
        assert_eq!(
            number(&resources, key),
            u64::try_from(expected).expect("resource bound fits in u64"),
            "{key} drifted"
        );
    }

    let decision = Value::Object(object(&receipt, "decision").clone());
    assert!(boolean(&decision, "terminal_receipt_complete"));
    assert_eq!(text(&decision, "implementation_state"), "COMPLETE");
    assert_eq!(text(&decision, "incumbent_state"), "KEEP_INCUMBENT");
    for key in [
        "cutover_eligible",
        "dependency_removal_authorized",
        "production_integration_authorized",
        "semantic_prefix_policy_complete",
    ] {
        assert!(!boolean(&decision, key), "{key} must remain false");
    }

    let validation = Value::Object(object(&receipt, "validation_contract").clone());
    assert_eq!(
        text(&validation, "focused_test_target"),
        "nkey_codec_oracle_contract"
    );
    assert!(boolean(&validation, "remote_required"));
    assert!(!boolean(&validation, "local_fallback_allowed"));

    assert_eq!(
        string_set(&receipt, "no_claim_boundaries"),
        [
            "does_not_prove_key_construction",
            "does_not_prove_signer_policy",
            "does_not_prove_secret_disposition_or_zeroization",
            "does_not_prove_authentication",
            "does_not_prove_performance",
            "does_not_prove_broad_workspace_health",
            "does_not_authorize_production_integration_or_cutover",
            "does_not_authorize_dependency_removal",
            "does_not_prove_release_readiness",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn manifest_and_lock_keep_the_oracle_out_of_normal_build_and_release_graphs() {
    let edges = nkey_and_reference_client_edges();
    assert_eq!(
        edges,
        [ManifestEdge {
            manifest: "Cargo.toml".to_owned(),
            section: "dependencies".to_owned(),
            alias: "nkeys".to_owned(),
            package: "nkeys".to_owned(),
        }],
        "only the existing production-incumbent edge is allowed; a test oracle or NATS reference client must not enter any workspace manifest"
    );

    let manifest: toml::Value =
        toml::from_str(&read_repo_file("Cargo.toml")).expect("root manifest must parse");
    assert_eq!(
        manifest
            .get("dependencies")
            .and_then(|value| value.get("nkeys"))
            .and_then(toml::Value::as_str),
        Some(PROVENANCE.rust_version),
        "a table-valued dependency with features/default-feature drift must fail closed"
    );

    let lock: toml::Value =
        toml::from_str(&read_repo_file("Cargo.lock")).expect("lockfile must parse");
    let package = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("lock packages")
        .iter()
        .find(|package| {
            package.get("name").and_then(toml::Value::as_str) == Some("nkeys")
                && package.get("version").and_then(toml::Value::as_str)
                    == Some(PROVENANCE.rust_version)
        })
        .expect("pinned nkeys lock package");
    assert_eq!(
        package.get("source").and_then(toml::Value::as_str),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );
    assert_eq!(
        package.get("checksum").and_then(toml::Value::as_str),
        Some(PROVENANCE.rust_checksum)
    );
    assert_eq!(
        package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .expect("nkeys dependencies")
            .iter()
            .map(|value| value.as_str().expect("dependency string"))
            .collect::<BTreeSet<_>>(),
        [
            "data-encoding",
            "ed25519",
            "ed25519-dalek",
            "getrandom 0.2.17",
            "log",
            "rand 0.8.7",
            "signatory",
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn bounded_formulas_and_typed_failures_are_exact_redacted_and_atomic() {
    assert_eq!(encoded_len_for(35), Ok(56));
    assert_eq!(encoded_len_for(36), Ok(58));
    assert_eq!(encoded_len_for(67), Ok(108));
    assert_eq!(decoded_capacity_for(56), Ok(35));
    assert_eq!(decoded_capacity_for(58), Ok(36));
    assert_eq!(decoded_capacity_for(108), Ok(67));
    assert_eq!(MAX_DECODED_BYTES, 67);
    assert_eq!(MAX_ENCODED_CHARS, 108);
    assert_eq!(encoded_len_for(68).unwrap_err().class(), "resource");
    assert_eq!(decoded_capacity_for(109).unwrap_err().class(), "resource");
    assert_eq!(encoded_len_for(usize::MAX).unwrap_err().class(), "resource");
    assert_eq!(
        decoded_capacity_for(usize::MAX).unwrap_err().class(),
        "resource"
    );

    let spec = parse_repo_json(SPEC_PATH);
    let corpus = object(&spec, "vector_corpus");
    let rows = corpus
        .get("independent_ed25519_vectors")
        .and_then(Value::as_array)
        .expect("independent rows");
    let seed = text(find_row(rows, "vector_id", "NKEY-VEC-INDEP-U"), "seed");

    let short = "A".repeat(55);
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &short),
        Err(CodecError::Length {
            field: Field::Seed,
            actual: 55,
            expected: 58,
        })
    );

    let alphabet = replace_ascii_byte(seed, 10, b'!');
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &alphabet),
        Err(CodecError::Alphabet {
            field: Field::Seed,
            index: 10,
        })
    );

    let lowercase = seed.to_ascii_lowercase();
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &lowercase),
        Err(CodecError::NonCanonical {
            field: Field::Seed,
            kind: NonCanonicalKind::Lowercase,
            index: Some(0),
        })
    );
    let padded = replace_ascii_byte(seed, seed.len() - 1, b'=');
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &padded),
        Err(CodecError::NonCanonical {
            field: Field::Seed,
            kind: NonCanonicalKind::Padding,
            index: Some(57),
        })
    );
    let whitespace = replace_ascii_byte(seed, 10, b' ');
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &whitespace),
        Err(CodecError::NonCanonical {
            field: Field::Seed,
            kind: NonCanonicalKind::Whitespace,
            index: Some(10),
        })
    );
    let separated = replace_ascii_byte(seed, 10, b'_');
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &separated),
        Err(CodecError::NonCanonical {
            field: Field::Seed,
            kind: NonCanonicalKind::Separator,
            index: Some(10),
        })
    );
    let trailing_bits = replace_ascii_byte(seed, seed.len() - 1, b'Z');
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &trailing_bits),
        Err(CodecError::NonCanonical {
            field: Field::Seed,
            kind: NonCanonicalKind::TrailingBits,
            index: Some(57),
        })
    );

    let checksum_replacement = if seed.as_bytes()[12] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let checksum = replace_ascii_byte(seed, 12, checksum_replacement);
    assert_eq!(
        decode_and_verify(EncodedKind::Seed, &checksum),
        Err(CodecError::Checksum { field: Field::Seed })
    );

    let oversized = "A".repeat(MAX_ENCODED_CHARS + 1);
    assert_eq!(
        decode_and_verify(EncodedKind::Public, &oversized),
        Err(CodecError::Resource {
            field: Field::Public,
            requested: 109,
            limit: 108,
        })
    );
    assert_eq!(
        encode_with_checksum(EncodedKind::Seed, &[0; 33]),
        Err(CodecError::Length {
            field: Field::Seed,
            actual: 33,
            expected: 34,
        })
    );

    for input in [
        &short,
        &alphabet,
        &lowercase,
        &padded,
        &whitespace,
        &separated,
        &trailing_bits,
        &checksum,
        &oversized,
    ] {
        let before = input.clone();
        let error = decode_and_verify(EncodedKind::Seed, input).unwrap_err();
        assert_eq!(*input, before, "failed decode must not mutate caller input");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("SUAAAAICAMCA"));
        assert!(!debug.contains("SUAAAAICAMCA"));
        assert!(!display.contains("0001020304050607"));
        assert!(!debug.contains("0001020304050607"));
    }
}

#[test]
fn owned_base32_matches_the_frozen_independent_n1_corpus() {
    let spec = parse_repo_json(SPEC_PATH);
    let corpus = object(&spec, "vector_corpus");
    let raw_seed = decode_hex_32(
        corpus
            .get("raw_secret_hex")
            .and_then(Value::as_str)
            .expect("raw secret vector"),
    );
    let public = decode_hex_32(
        corpus
            .get("ed25519_public_hex")
            .and_then(Value::as_str)
            .expect("public vector"),
    );
    let limits = owned_nkey_codec::Base32Limits::default();

    for vector in corpus
        .get("independent_ed25519_vectors")
        .and_then(Value::as_array)
        .expect("independent rows")
    {
        let key_type = key_pair_type(text(vector, "kind"));
        let prefix = prefix_byte(&key_type);

        let mut seed_body = packed_seed_prefix(prefix).to_vec();
        seed_body.extend_from_slice(&raw_seed);
        let seed_frame = independently_framed_body(&seed_body);
        assert_eq!(
            owned_nkey_codec::pack_seed_prefix(prefix),
            Ok(packed_seed_prefix(prefix)),
            "{} prefix packing",
            text(vector, "vector_id")
        );
        assert_eq!(
            owned_nkey_codec::encode_seed_payload(prefix, &raw_seed).as_deref(),
            Ok(text(vector, "seed")),
            "{} composed seed encoding",
            text(vector, "vector_id")
        );
        assert_eq!(
            owned_nkey_codec::decode_seed_payload(text(vector, "seed")),
            Ok((prefix, raw_seed)),
            "{} composed seed decoding",
            text(vector, "vector_id")
        );
        assert_eq!(
            owned_nkey_codec::encode_base32(&seed_frame, limits).as_deref(),
            Ok(text(vector, "seed"))
        );
        assert_eq!(
            owned_nkey_codec::decode_base32(text(vector, "seed"), limits),
            Ok(seed_frame)
        );

        let mut public_body = vec![prefix];
        public_body.extend_from_slice(&public);
        let public_frame = independently_framed_body(&public_body);
        assert_eq!(
            owned_nkey_codec::encode_base32(&public_frame, limits).as_deref(),
            Ok(text(vector, "public"))
        );
        assert_eq!(
            owned_nkey_codec::decode_base32(text(vector, "public"), limits),
            Ok(public_frame)
        );
    }

    for vector in corpus
        .get("private_vectors")
        .and_then(Value::as_array)
        .expect("private rows")
    {
        let mut body = vec![120];
        body.extend_from_slice(&raw_seed);
        if text(vector, "vector_id") == "NKEY-VEC-INDEP-P-ED" {
            body.extend_from_slice(&public);
        }
        let frame = independently_framed_body(&body);
        assert_eq!(
            owned_nkey_codec::encode_base32(&frame, limits).as_deref(),
            Ok(text(vector, "encoded"))
        );
        assert_eq!(
            owned_nkey_codec::decode_base32(text(vector, "encoded"), limits),
            Ok(frame)
        );
    }
}

#[test]
fn prefix_composition_rejects_structural_mutations_before_key_construction() {
    let spec = parse_repo_json(SPEC_PATH);
    let corpus = object(&spec, "vector_corpus");
    let raw_seed = decode_hex_32(
        corpus
            .get("raw_secret_hex")
            .and_then(Value::as_str)
            .expect("raw secret vector"),
    );

    let encode_mutated_seed = |packed: [u8; 2]| {
        let mut body = packed.to_vec();
        body.extend_from_slice(&raw_seed);
        let frame = independently_framed_body(&body);
        owned_nkey_codec::encode_base32(&frame, owned_nkey_codec::Base32Limits::default())
            .expect("structural mutation remains valid Base32 with a valid checksum")
    };

    for (packed, expected) in [
        ([0x88, 0], owned_nkey_codec::NonCanonicalReason::SeedOuter),
        (
            [0x90, 1],
            owned_nkey_codec::NonCanonicalReason::SeedUnusedBits,
        ),
        (
            [0x90, 8],
            owned_nkey_codec::NonCanonicalReason::SeedPrefixAlignment,
        ),
    ] {
        let encoded = encode_mutated_seed(packed);
        let before = encoded.clone();
        assert!(matches!(
            owned_nkey_codec::decode_seed_payload(&encoded),
            Err(owned_nkey_codec::NkeyCodecError::NonCanonical { reason, .. })
                if reason == expected
        ));
        assert_eq!(encoded, before, "failed decode remains caller-atomic");
    }

    let known_unknown = find_row(
        corpus
            .get("cross_prefix_vectors")
            .and_then(Value::as_array)
            .expect("cross-prefix rows"),
        "vector_id",
        "NKEY-VEC-CROSS-UNKNOWN-SEED-24",
    );
    assert_eq!(
        owned_nkey_codec::decode_seed_payload(text(known_unknown, "input")),
        Ok((24, raw_seed)),
        "N2 proves structural prefix validity only; N4 owns the allowed-kind policy"
    );
}

#[test]
fn independent_and_private_rows_match_the_bounded_scaffold_and_incumbent() {
    let spec = parse_repo_json(SPEC_PATH);
    let corpus = object(&spec, "vector_corpus");
    let raw_seed = decode_hex_32(
        corpus
            .get("raw_secret_hex")
            .and_then(Value::as_str)
            .expect("raw secret vector"),
    );
    let public = decode_hex_32(
        corpus
            .get("ed25519_public_hex")
            .and_then(Value::as_str)
            .expect("public vector"),
    );

    for vector in corpus
        .get("independent_ed25519_vectors")
        .and_then(Value::as_array)
        .expect("independent rows")
    {
        let key_type = key_pair_type(text(vector, "kind"));
        let prefix = prefix_byte(&key_type);
        let mut seed_body = packed_seed_prefix(prefix).to_vec();
        seed_body.extend_from_slice(&raw_seed);
        assert_eq!(
            encode_with_checksum(EncodedKind::Seed, &seed_body).expect("bounded seed encode"),
            text(vector, "seed")
        );
        assert_eq!(
            decode_and_verify(EncodedKind::Seed, text(vector, "seed"))
                .expect("bounded seed decode"),
            seed_body
        );

        let mut public_body = vec![prefix];
        public_body.extend_from_slice(&public);
        assert_eq!(
            encode_with_checksum(EncodedKind::Public, &public_body).expect("bounded public encode"),
            text(vector, "public")
        );
        assert_eq!(
            decode_and_verify(EncodedKind::Public, text(vector, "public"))
                .expect("bounded public decode"),
            public_body
        );

        let incumbent = KeyPair::from_seed(text(vector, "seed")).expect("incumbent seed decode");
        assert_eq!(incumbent.key_pair_type(), key_type);
        assert_eq!(incumbent.public_key(), text(vector, "public"));
    }

    let private_rows = corpus
        .get("private_vectors")
        .and_then(Value::as_array)
        .expect("private rows");
    let x = find_row(private_rows, "vector_id", "NKEY-VEC-INDEP-P-X");
    let mut x_body = vec![120];
    x_body.extend_from_slice(&raw_seed);
    assert_eq!(
        encode_with_checksum(EncodedKind::PrivateX25519, &x_body).expect("bounded P-X encode"),
        text(x, "encoded")
    );
    assert_eq!(
        decode_and_verify(EncodedKind::PrivateX25519, text(x, "encoded"))
            .expect("bounded P-X decode"),
        x_body
    );

    let ed = find_row(private_rows, "vector_id", "NKEY-VEC-INDEP-P-ED");
    let mut ed_body = vec![120];
    ed_body.extend_from_slice(&raw_seed);
    ed_body.extend_from_slice(&public);
    assert_eq!(
        encode_with_checksum(EncodedKind::PrivateEd25519, &ed_body).expect("bounded P-Ed encode"),
        text(ed, "encoded")
    );
    assert_eq!(
        decode_and_verify(EncodedKind::PrivateEd25519, text(ed, "encoded"))
            .expect("bounded P-Ed decode"),
        ed_body
    );
}

#[test]
fn official_rows_match_or_preserve_the_known_curve_no_claim_boundary() {
    let spec = parse_repo_json(SPEC_PATH);
    let rows = spec
        .pointer("/vector_corpus/official_historical_vectors")
        .and_then(Value::as_array)
        .expect("official rows");

    let account = find_row(rows, "vector_id", "NKEY-VEC-RUST-GO-ACCOUNT");
    let account_body = decode_and_verify(EncodedKind::Seed, text(account, "seed"))
        .expect("bounded official Account decode");
    assert_eq!(account_body.len(), EncodedKind::Seed.body_len());
    let incumbent = KeyPair::from_seed(text(account, "seed")).expect("incumbent Account decode");
    assert_eq!(incumbent.key_pair_type(), KeyPairType::Account);
    assert_eq!(incumbent.public_key(), text(account, "public"));
    assert_eq!(
        owned_nkey_codec::decode_seed_payload(text(account, "seed")),
        Ok((
            0,
            <[u8; 32]>::try_from(&account_body[2..]).expect("Account payload")
        ))
    );

    let user = find_row(rows, "vector_id", "NKEY-VEC-GO-BENCH-U");
    let user_body = decode_and_verify(EncodedKind::Seed, text(user, "seed"))
        .expect("bounded official User decode");
    assert_eq!(user_body.len(), EncodedKind::Seed.body_len());
    assert_eq!(
        KeyPair::from_seed(text(user, "seed"))
            .expect("incumbent User decode")
            .key_pair_type(),
        KeyPairType::User
    );
    assert_eq!(
        owned_nkey_codec::decode_seed_payload(text(user, "seed")),
        Ok((
            160,
            <[u8; 32]>::try_from(&user_body[2..]).expect("User payload")
        ))
    );

    let curve = find_row(rows, "vector_id", "NKEY-VEC-RUST-GO-X25519");
    let curve_body = decode_and_verify(EncodedKind::Seed, text(curve, "seed"))
        .expect("bounded official Curve codec decode");
    let (prefix, raw) =
        nkeys::decode_seed(text(curve, "seed")).expect("incumbent Curve codec decode");
    assert_eq!(prefix, 184);
    assert_eq!(&curve_body[2..], raw.as_slice());
    assert_eq!(
        owned_nkey_codec::decode_seed_payload(text(curve, "seed")),
        Ok((
            184,
            <[u8; 32]>::try_from(raw.as_slice()).expect("Curve payload")
        ))
    );
    assert_ne!(
        KeyPair::from_seed(text(curve, "seed"))
            .expect("observed base KeyPair Curve decode")
            .public_key(),
        text(curve, "public"),
        "codec agreement must not be promoted into a false X25519 key-authority claim"
    );
}

#[test]
fn primitive_module_exposes_no_key_or_signer_authority() {
    let source = read_repo_file(MODULE_PATH);
    for forbidden in [
        "nkeys::",
        "KeyPair",
        "SigningKey",
        "VerifyingKey",
        "SecretKey",
        "XKey",
        "fn sign(",
        "fn verify_signature(",
        "rand::",
        "pub(crate)",
        "pub fn",
        "pub struct",
        "pub enum",
    ] {
        assert!(
            !source.contains(forbidden),
            "test-only primitive module gained forbidden authority or visibility: {forbidden}"
        );
    }
}
