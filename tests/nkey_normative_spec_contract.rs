//! Fail-closed contract for the complete NKey normative specification.
//!
//! Bead: asupersync-dep-p4-nkeys-poc60v.1.1
//! Artifact: artifacts/nkey_normative_spec_v1.json
//!
//! This contract freezes source/API provenance, canonical prefix and format
//! rules, independent and historical vectors, the complete signer matrix,
//! routed incumbent defects, and downstream evidence ownership. It does not
//! implement an owned codec, prove live NATS interoperability, authorize
//! production cutover, or permit removal of the incumbent dependency.

#![allow(missing_docs)]

use nkeys::error::ErrorKind;
use nkeys::{KeyPair, KeyPairType};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr;

const ARTIFACT_PATH: &str = "artifacts/nkey_normative_spec_v1.json";
const DOC_PATH: &str = "docs/nkey_normative_spec.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const ADR_REGISTRY_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const BEAD_ID: &str = "asupersync-dep-p4-nkeys-poc60v.1.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-NKEY-AUTH";
const BASELINE_REVISION: &str = "d14477867f3b8d3472443b87ba0851a440af61a6";
const DOC_BEGIN: &str = "<!-- BEGIN NKEY NORMATIVE SPEC -->";
const DOC_END: &str = "<!-- END NKEY NORMATIVE SPEC -->";

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

fn map_array<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn map_text<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
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

fn map_string_set(value: &serde_json::Map<String, Value>, key: &str) -> BTreeSet<String> {
    map_array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
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
    hex::encode(Sha256::digest(bytes))
}

fn line_count(bytes: &[u8]) -> usize {
    std::str::from_utf8(bytes)
        .expect("pinned source is UTF-8")
        .lines()
        .count()
}

fn decode_hex_32(encoded: &str) -> [u8; 32] {
    hex::decode(encoded)
        .unwrap_or_else(|error| panic!("invalid hex vector: {error}"))
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected 32 bytes, got {}", bytes.len()))
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    hex::decode(encoded).unwrap_or_else(|error| panic!("invalid hex vector: {error}"))
}

fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn base32_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut accumulator = 0u32;
    let mut bits = 0u32;

    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((accumulator >> bits) & 0x1f) as usize;
            out.push(char::from(ALPHABET[index]));
        }
        if bits == 0 {
            accumulator = 0;
        } else {
            accumulator &= (1u32 << bits) - 1;
        }
    }
    if bits != 0 {
        let index = ((accumulator << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[index]));
    }
    out
}

fn encode_prefix(prefix: &[u8], payload: &[u8]) -> String {
    let mut raw = Vec::with_capacity(prefix.len() + payload.len() + 2);
    raw.extend_from_slice(prefix);
    raw.extend_from_slice(payload);
    raw.extend_from_slice(&crc16_xmodem(&raw).to_le_bytes());
    base32_no_pad(&raw)
}

fn encode_seed(prefix: u8, raw_seed: &[u8; 32]) -> String {
    let packed = [0x90 | (prefix >> 5), (prefix & 0x1f) << 3];
    encode_prefix(&packed, raw_seed)
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
        other => panic!("unknown vector key type {other}"),
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

fn incumbent_error_kind(name: &str) -> ErrorKind {
    match name {
        "InvalidPrefix" => ErrorKind::InvalidPrefix,
        "InvalidKeyLength" => ErrorKind::InvalidKeyLength,
        "VerifyError" => ErrorKind::VerifyError,
        "SignatureError" => ErrorKind::SignatureError,
        "ChecksumFailure" => ErrorKind::ChecksumFailure,
        "CodecFailure" => ErrorKind::CodecFailure,
        "IncorrectKeyType" => ErrorKind::IncorrectKeyType,
        "InvalidPayload" => ErrorKind::InvalidPayload,
        "InvalidSignatureLength" => ErrorKind::InvalidSignatureLength,
        other => panic!("unknown incumbent error kind {other}"),
    }
}

fn validate_inventory(spec: &Value) -> Result<(), String> {
    if spec.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "nkey-normative-spec-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
    ] {
        if spec.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(spec, "authority");
    for (key, expected) in [
        (
            "decision",
            "FULL_NOMINAL_FORMAT_WITH_FAIL_CLOSED_ROLE_POLICY",
        ),
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("registry_evidence_state", "BASELINE_PLANNED"),
        ("registry_cutover_state", "KEEP_INCUMBENT"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("normative_core_children_authorized")
        .and_then(Value::as_bool)
        != Some(true)
        || authority
            .get("production_integration_authorized")
            .and_then(Value::as_bool)
            != Some(false)
        || authority
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || authority.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || authority.get("ambiguous_rows").and_then(Value::as_u64) != Some(0)
    {
        return Err("authority must be zero-unknown and cutover-blocked".to_owned());
    }

    let policy = object(spec, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy
            .get("missing_evidence_is_parity")
            .and_then(Value::as_bool)
            != Some(false)
        || policy
            .get("current_defects_are_compatibility_requirements")
            .and_then(Value::as_bool)
            != Some(false)
        || policy
            .get("cryptographic_validity_implies_authorization")
            .and_then(Value::as_bool)
            != Some(false)
        || policy.get("crc_is_authentication").and_then(Value::as_bool) != Some(false)
    {
        return Err("policy must remain fail-closed".to_owned());
    }
    validate_no_unknown(spec, "$")?;

    let expected_prefixes: BTreeSet<String> = [
        "NKEY-PREFIX-A",
        "NKEY-PREFIX-C",
        "NKEY-PREFIX-M",
        "NKEY-PREFIX-N",
        "NKEY-PREFIX-O",
        "NKEY-PREFIX-P-ED25519",
        "NKEY-PREFIX-P-X25519",
        "NKEY-PREFIX-S",
        "NKEY-PREFIX-U",
        "NKEY-PREFIX-V",
        "NKEY-PREFIX-X",
        "NKEY-PREFIX-Z",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(spec, "prefix_matrix"), "prefix_id") != expected_prefixes {
        return Err("prefix matrix drifted".to_owned());
    }

    let expected_operations: BTreeSet<String> = [
        "NKEY-OP-ED-SEED",
        "NKEY-OP-ED-PUBLIC",
        "NKEY-OP-X-SEED",
        "NKEY-OP-X-PUBLIC",
        "NKEY-OP-UNTYPED-P",
        "NKEY-OP-RUST-CURVE-AS-ED",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(spec, "operation_matrix"), "operation_id") != expected_operations {
        return Err("operation matrix drifted".to_owned());
    }

    let expected_policies: BTreeSet<String> = [
        "NKEY-POL-O-SELF",
        "NKEY-POL-O-DELEGATED",
        "NKEY-POL-O-IDENTITY-ACCOUNT",
        "NKEY-POL-A-IDENTITY-USER",
        "NKEY-POL-A-DELEGATED-USER",
        "NKEY-POL-U-NONCE",
        "NKEY-POL-UNLISTED-DELEGATE",
        "NKEY-POL-CROSS-O-U",
        "NKEY-POL-CROSS-A-A",
        "NKEY-POL-U-ISSUER",
        "NKEY-POL-NCMV-ISSUER",
        "NKEY-POL-X-ISSUER",
        "NKEY-POL-ISSUER-MISSING",
        "NKEY-POL-CHAIN-UNTRUSTED",
        "NKEY-POL-ALGORITHM",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let policies = array(spec, "signer_policy_matrix");
    if row_ids(policies, "policy_id") != expected_policies {
        return Err("signer policy matrix drifted".to_owned());
    }
    if policies.iter().any(|row| {
        !matches!(
            row.get("decision").and_then(Value::as_str),
            Some("ALLOW" | "DENY")
        )
    }) {
        return Err("every signer policy row must explicitly ALLOW or DENY".to_owned());
    }

    let errors = object(spec, "error_contract");
    let expected_incumbent_errors: BTreeSet<String> = [
        "InvalidPrefix",
        "InvalidKeyLength",
        "VerifyError",
        "SignatureError",
        "ChecksumFailure",
        "CodecFailure",
        "IncorrectKeyType",
        "InvalidPayload",
        "InvalidSignatureLength",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if map_string_set(errors, "incumbent_error_kinds") != expected_incumbent_errors {
        return Err("incumbent error-kind baseline drifted".to_owned());
    }
    let expected_normative_errors: BTreeSet<String> =
        (1..=17).map(|index| format!("NKEY-E{index:03}")).collect();
    if row_ids(map_array(errors, "normative_error_ids"), "error_id") != expected_normative_errors {
        return Err("normative error taxonomy must retain NKEY-E001..E017".to_owned());
    }

    for (key, expected_count, id_key) in [
        ("public_and_downstream_api", 8, "api_id"),
        ("downstream_workflows", 7, "journey_id"),
        ("observed_gaps", 14, "gap_id"),
    ] {
        let rows = array(spec, key);
        if rows.len() != expected_count || row_ids(rows, id_key).len() != expected_count {
            return Err(format!("{key} must contain {expected_count} unique rows"));
        }
    }
    let expected_gaps: BTreeSet<String> = (1..=14)
        .map(|index| format!("NKEY-N1-GAP-{index:02}"))
        .collect();
    let gaps = array(spec, "observed_gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("gap matrix must retain NKEY-N1-GAP-01..14".to_owned());
    }
    for gap in gaps {
        if text(gap, "state") != "ROUTED"
            || text(gap, "owner").is_empty()
            || text(gap, "normative_resolution").is_empty()
        {
            return Err(format!(
                "{} must be resolved and routed",
                text(gap, "gap_id")
            ));
        }
    }

    let vectors = object(spec, "vector_corpus");
    for (key, count, id_key) in [
        ("independent_ed25519_vectors", 8, "vector_id"),
        ("private_vectors", 2, "vector_id"),
        ("official_historical_vectors", 3, "vector_id"),
        ("malformed_vectors", 7, "vector_id"),
        ("cross_prefix_vectors", 3, "vector_id"),
    ] {
        let rows = map_array(vectors, key);
        if rows.len() != count || row_ids(rows, id_key).len() != count {
            return Err(format!("vector_corpus.{key} must contain {count} rows"));
        }
    }

    let evidence = object(spec, "evidence_plan");
    if evidence.get("current_runner_state").and_then(Value::as_str) != Some("PLANNED_MISSING")
        || map_string_set(evidence, "scenario_ids")
            != [
                "nkey_all_forms",
                "nkey_nats_auth",
                "nkey_jwt_authorization",
                "nkey_secret_redaction",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err("evidence plan must retain all four missing scenarios".to_owned());
    }

    Ok(())
}

#[test]
fn nkey_spec_is_complete_zero_unknown_and_cutover_blocked() {
    validate_inventory(&artifact()).expect("NKey normative specification must be valid");
}

#[test]
fn source_pins_and_public_signature_fragments_are_current() {
    let spec = artifact();
    for pin in array(&spec, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "{path} source hash drifted; re-audit NKey behavior"
        );
        assert_eq!(
            line_count(&bytes),
            pin.get("line_count")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{path} line_count must be numeric"))
                as usize,
            "{path} line count drifted"
        );
    }

    for api in array(&spec, "public_and_downstream_api") {
        let Some(path) = api.get("source_path").and_then(Value::as_str) else {
            continue;
        };
        let fragment = text(api, "source_fragment");
        assert!(
            read_repo_file(path).contains(fragment),
            "{} source fragment disappeared from {path}: {fragment}",
            text(api, "api_id")
        );
    }
}

#[test]
fn capability_and_adr_authorities_still_keep_the_incumbent() {
    let registry = parse_repo_json(REGISTRY_PATH);
    let capability = array(&registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("CAP-NKEY-AUTH registry row");
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );
    assert_eq!(
        capability.get("evidence_state").and_then(Value::as_str),
        Some("BASELINE_PLANNED")
    );
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        string_set(capability, "source_owners"),
        [
            "Cargo.toml",
            "src/agent_swarm/control_plane.rs",
            "src/atp/identity/mod.rs",
            "src/atp/policy/verification.rs",
            "src/messaging/nats.rs",
            "src/runtime/config.rs",
            "src/security/keys/mod.rs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let adr_registry = parse_repo_json(ADR_REGISTRY_PATH);
    let adr = array(&adr_registry, "adrs")
        .iter()
        .find(|row| row.get("adr_id").and_then(Value::as_str) == Some("DEP-ADR-007"))
        .expect("DEP-ADR-007 row");
    assert_eq!(
        adr.get("decision").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );
    assert_eq!(
        adr.pointer("/cutover/dependency_exit_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn independent_codec_and_signature_vectors_match_the_incumbent() {
    let spec = artifact();
    let corpus = object(&spec, "vector_corpus");
    let raw_seed = decode_hex_32(
        corpus
            .get("raw_secret_hex")
            .and_then(Value::as_str)
            .expect("raw_secret_hex"),
    );
    let public_bytes = decode_hex_32(
        corpus
            .get("ed25519_public_hex")
            .and_then(Value::as_str)
            .expect("ed25519_public_hex"),
    );
    let message = corpus
        .get("message_utf8")
        .and_then(Value::as_str)
        .expect("message_utf8")
        .as_bytes();
    let expected_signature = decode_hex(
        corpus
            .get("ed25519_signature_hex")
            .and_then(Value::as_str)
            .expect("ed25519_signature_hex"),
    );

    for vector in map_array(corpus, "independent_ed25519_vectors") {
        let kind = key_pair_type(text(vector, "kind"));
        let prefix = prefix_byte(&kind);
        assert_eq!(
            encode_seed(prefix, &raw_seed),
            text(vector, "seed"),
            "{} independent seed codec mismatch",
            text(vector, "vector_id")
        );
        assert_eq!(
            encode_prefix(&[prefix], &public_bytes),
            text(vector, "public"),
            "{} independent public codec mismatch",
            text(vector, "vector_id")
        );

        let pair =
            KeyPair::new_from_raw(kind.clone(), raw_seed).expect("deterministic incumbent key");
        assert_eq!(pair.key_pair_type(), kind);
        assert_eq!(pair.seed().expect("seed encoding"), text(vector, "seed"));
        assert_eq!(pair.public_key(), text(vector, "public"));
        assert_eq!(
            pair.sign(message).expect("deterministic signature"),
            expected_signature
        );

        let from_seed = KeyPair::from_seed(text(vector, "seed")).expect("incumbent seed parse");
        assert_eq!(from_seed.key_pair_type(), kind);
        assert_eq!(from_seed.public_key(), text(vector, "public"));
        let from_public =
            KeyPair::from_public_key(text(vector, "public")).expect("incumbent public parse");
        assert_eq!(from_public.key_pair_type(), kind);
        from_public
            .verify(message, &expected_signature)
            .expect("public-only verification");
    }
}

#[test]
fn both_private_payload_forms_are_frozen_independently() {
    let spec = artifact();
    let corpus = object(&spec, "vector_corpus");
    let raw_seed = decode_hex_32(
        corpus
            .get("raw_secret_hex")
            .and_then(Value::as_str)
            .expect("raw_secret_hex"),
    );
    let public_bytes = decode_hex_32(
        corpus
            .get("ed25519_public_hex")
            .and_then(Value::as_str)
            .expect("ed25519_public_hex"),
    );
    let private_vectors = map_array(corpus, "private_vectors");

    let x_private = find_row(private_vectors, "vector_id", "NKEY-VEC-INDEP-P-X");
    assert_eq!(encode_prefix(&[120], &raw_seed), text(x_private, "encoded"));
    assert_eq!(text(x_private, "encoded").len(), 56);

    let mut expanded_ed25519 = Vec::with_capacity(64);
    expanded_ed25519.extend_from_slice(&raw_seed);
    expanded_ed25519.extend_from_slice(&public_bytes);
    let ed_private = find_row(private_vectors, "vector_id", "NKEY-VEC-INDEP-P-ED");
    assert_eq!(
        encode_prefix(&[120], &expanded_ed25519),
        text(ed_private, "encoded")
    );
    assert_eq!(text(ed_private, "encoded").len(), 108);
}

#[test]
fn historical_go_vectors_and_curve_mismatch_are_explicit() {
    let spec = artifact();
    let corpus = object(&spec, "vector_corpus");
    let vectors = map_array(corpus, "official_historical_vectors");

    let account = find_row(vectors, "vector_id", "NKEY-VEC-RUST-GO-ACCOUNT");
    let account_pair = KeyPair::from_seed(text(account, "seed")).expect("Go account seed");
    assert_eq!(account_pair.key_pair_type(), KeyPairType::Account);
    assert_eq!(account_pair.public_key(), text(account, "public"));
    assert_eq!(
        account_pair.seed().expect("account seed"),
        text(account, "seed")
    );

    let go_user = find_row(vectors, "vector_id", "NKEY-VEC-GO-BENCH-U");
    let go_user_pair = KeyPair::from_seed(text(go_user, "seed")).expect("Go benchmark User seed");
    assert_eq!(go_user_pair.key_pair_type(), KeyPairType::User);
    assert_eq!(
        go_user_pair.seed().expect("User seed round trip"),
        text(go_user, "seed")
    );

    let curve = find_row(vectors, "vector_id", "NKEY-VEC-RUST-GO-X25519");
    let (decoded_prefix, _) =
        nkeys::decode_seed(text(curve, "seed")).expect("codec accepts official SX seed");
    assert_eq!(decoded_prefix, 184);
    let mislabeled_ed =
        KeyPair::from_seed(text(curve, "seed")).expect("base incumbent accepts SX seed");
    assert_eq!(mislabeled_ed.key_pair_type(), KeyPairType::Curve);
    assert_ne!(
        mislabeled_ed.public_key(),
        text(curve, "public"),
        "base KeyPair must remain recorded as non-X25519 behavior"
    );
    assert!(
        mislabeled_ed.sign(b"curve-must-not-sign").is_ok(),
        "the observed incumbent Curve signing defect must stay visible"
    );
}

#[test]
fn malformed_and_cross_prefix_corpus_matches_observed_baseline() {
    let spec = artifact();
    let corpus = object(&spec, "vector_corpus");

    for vector in map_array(corpus, "malformed_vectors") {
        let actual = match text(vector, "operation") {
            "from_seed" => KeyPair::from_seed(text(vector, "input"))
                .expect_err("malformed seed must fail")
                .kind(),
            "from_public_key" => KeyPair::from_public_key(text(vector, "input"))
                .expect_err("malformed public key must fail")
                .kind(),
            "verify_empty_signature" => KeyPair::new_from_raw(KeyPairType::User, [7; 32])
                .expect("test key")
                .verify(b"", b"")
                .expect_err("empty signature must fail")
                .kind(),
            other => panic!("unknown malformed operation {other}"),
        };
        assert_eq!(
            actual,
            incumbent_error_kind(text(vector, "incumbent_error_kind")),
            "{} incumbent error drifted",
            text(vector, "vector_id")
        );
        assert!(
            text(vector, "normative_error_id").starts_with("NKEY-E"),
            "{} lacks normative error mapping",
            text(vector, "vector_id")
        );
    }

    let cross = map_array(corpus, "cross_prefix_vectors");
    let unknown_seed = find_row(cross, "vector_id", "NKEY-VEC-CROSS-UNKNOWN-SEED-24");
    let (inner, raw) =
        nkeys::decode_seed(text(unknown_seed, "input")).expect("valid-checksum cross-prefix seed");
    assert_eq!(inner, 24);
    assert_eq!(raw, decode_hex_32(map_text(corpus, "raw_secret_hex")));
    let silently_operator =
        KeyPair::from_seed(text(unknown_seed, "input")).expect("observed fallback behavior");
    assert_eq!(
        silently_operator.key_pair_type(),
        KeyPairType::Operator,
        "unknown inner prefix must remain captured as an incumbent type-confusion defect"
    );
    assert_ne!(
        silently_operator.seed().expect("re-encoded fallback seed"),
        text(unknown_seed, "input")
    );

    let unknown_public = find_row(cross, "vector_id", "NKEY-VEC-CROSS-Z-PUBLIC");
    assert_eq!(
        KeyPair::from_public_key(text(unknown_public, "input"))
            .expect_err("Z public key must fail")
            .kind(),
        ErrorKind::InvalidPrefix
    );
    assert_eq!(
        KeyPairType::from_str("definitely-not-a-key-kind").expect("observed fallback"),
        KeyPairType::Module,
        "unknown textual type fallback must remain captured as non-normative"
    );
}

#[test]
fn incumbent_keypair_trait_and_secret_baseline_is_frozen() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_clone<T: Clone>() {}

    assert_send_sync::<KeyPair>();
    assert_clone::<KeyPair>();

    let pair = KeyPair::new_from_raw(KeyPairType::User, [11; 32]).expect("test key");
    let seed = pair.seed().expect("secret seed string");
    let cloned = pair.clone();
    assert_eq!(cloned.seed().expect("cloned secret seed"), seed);
    assert!(!format!("{pair:?}").contains(&seed));

    let public_only = KeyPair::from_public_key(&pair.public_key()).expect("public key");
    assert_eq!(
        public_only
            .sign(b"forbidden")
            .expect_err("public-only sign")
            .kind(),
        ErrorKind::SignatureError
    );
    assert_eq!(
        public_only.seed().expect_err("public-only seed").kind(),
        ErrorKind::IncorrectKeyType
    );
}

#[test]
fn planned_e2e_scenarios_are_not_silently_reported_as_present() {
    let runner = read_repo_file(RUNNER_PATH);
    let spec = artifact();
    let evidence = object(&spec, "evidence_plan");
    assert_eq!(
        evidence.get("current_runner_state").and_then(Value::as_str),
        Some("PLANNED_MISSING")
    );
    for scenario in map_array(evidence, "scenario_ids") {
        let scenario = scenario.as_str().expect("scenario ID string");
        assert!(
            !runner.contains(scenario),
            "{scenario} is now present in the runner; refresh the evidence baseline"
        );
    }
}

#[test]
fn companion_document_preserves_decisions_and_no_claim_boundary() {
    let doc = read_repo_file(DOC_PATH);
    let begin = doc.find(DOC_BEGIN).expect("NKey doc begin marker");
    let end = doc.find(DOC_END).expect("NKey doc end marker");
    assert!(begin < end);

    for required in [
        "zero unknown or ambiguous rows",
        "64-byte expanded Ed25519 private material",
        "32-byte X25519 secret material",
        "Cryptographic validity does not imply authorization.",
        "Curve keys never implement signing traits",
        "SDAAAAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4HYPT4",
        "PLANNED`, never silently green",
        "No local Cargo fallback is approved.",
        "It authorizes no deletion, production cutover or `nkeys` removal.",
    ] {
        assert!(
            doc.contains(required),
            "companion document lost required statement: {required}"
        );
    }
}
