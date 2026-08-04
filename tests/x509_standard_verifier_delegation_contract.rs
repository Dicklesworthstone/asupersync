//! Fail-closed contract for the X.509 A2 standard-verifier delegation packet.

#![cfg(feature = "tls")]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/x509_standard_verifier_delegation_v1.json";
const INVENTORY_PATH: &str = "artifacts/x509_validation_ownership_inventory_v1.json";
const DOC_PATH: &str = "docs/x509_standard_verifier_delegation.md";
const SHARED_SOURCE: &str = "src/net/quic_native/handshake_driver.rs";
const ATP_SOURCE: &str = "src/bin/atp.rs";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn parse(path: &str) -> Value {
    serde_json::from_str(&read(path)).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value[key]
        .as_object()
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|candidate| candidate[key].as_str() == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter()
        .map(|candidate| {
            candidate[key]
                .as_str()
                .unwrap_or_else(|| panic!("{key} must be text"))
                .to_owned()
        })
        .collect()
}

fn sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn line_count(path: &Path) -> usize {
    read(
        path.strip_prefix(root())
            .expect("workspace path")
            .to_str()
            .expect("UTF-8 path"),
    )
    .lines()
    .count()
}

fn validate(value: &Value) -> Result<(), String> {
    if value["schema_version"].as_u64() != Some(1)
        || text(value, "artifact_id") != "x509-standard-verifier-delegation-v1"
        || text(value, "bead_id") != "asupersync-0h6myr.3.2"
        || text(value, "capability_id") != "CAP-TLS-X509"
    {
        return Err("identity fields drifted".to_owned());
    }

    let decision = object(value, "decision");
    if decision["state"].as_str() != Some("STANDARD_FIRST_SHARED_EXACT_LEAF_POLICY")
        || decision["standard_validation_owner"]
            .as_str()
            .is_none_or(|owner| !owner.contains("rustls-webpki"))
        || decision["atp_duplicate_parser_removed"].as_bool() != Some(true)
        || decision["runtime_behavior_changed"].as_bool() != Some(true)
        || decision["dependency_exit_allowed"].as_bool() != Some(false)
        || decision["manifest_changed"].as_bool() != Some(false)
        || decision["lockfile_changed"].as_bool() != Some(false)
        || decision["cutover_authorized"].as_bool() != Some(false)
    {
        return Err("decision authority drifted".to_owned());
    }

    let source_contracts = array(value, "source_contracts");
    let expected_source_contracts = BTreeSet::from([
        ATP_SOURCE.to_owned(),
        "Cargo.lock".to_owned(),
        "Cargo.toml".to_owned(),
        INVENTORY_PATH.to_owned(),
        SHARED_SOURCE.to_owned(),
        "docs/x509_validation_ownership_inventory.md".to_owned(),
        "tests/x509_validation_ownership_inventory_contract.rs".to_owned(),
    ]);
    if ids(source_contracts, "path") != expected_source_contracts {
        return Err("source contract path set drifted".to_owned());
    }

    let path_ids = ids(array(value, "verifier_paths"), "path_id");
    if path_ids
        != BTreeSet::from([
            "X509-A2-ATP-CLI".to_owned(),
            "X509-A2-NATIVE-QUIC".to_owned(),
        ])
    {
        return Err("verifier path set drifted".to_owned());
    }
    for path in array(value, "verifier_paths") {
        if path["standard_first"].as_bool() != Some(true)
            || path["fallback_error_class"].as_str() != Some("CertificateError::UnknownIssuer")
            || path["handshake_signatures_delegated"].as_bool() != Some(true)
            || path["state"].as_str() != Some("ACTIVE")
        {
            return Err(format!("verifier path {} broadened", text(path, "path_id")));
        }
    }

    let expected_checks = BTreeSet::from([
        "X509-A2-CA-POLICY".to_owned(),
        "X509-A2-CERT-SIGNATURE".to_owned(),
        "X509-A2-CHAIN-PATH".to_owned(),
        "X509-A2-CRITICAL-CONSTRAINT-REVOCATION".to_owned(),
        "X509-A2-EKU".to_owned(),
        "X509-A2-HANDSHAKE-SIGNATURE".to_owned(),
        "X509-A2-KEY-USAGE".to_owned(),
        "X509-A2-SERVER-NAME".to_owned(),
        "X509-A2-TRUST-ANCHOR".to_owned(),
        "X509-A2-VALIDITY".to_owned(),
    ]);
    if ids(array(value, "standard_delegation_matrix"), "check_id") != expected_checks {
        return Err("delegation check matrix drifted".to_owned());
    }

    let invariants = object(value, "fallback_invariants");
    for key in [
        "webpki_invoked_first",
        "exact_complete_leaf_der_required",
        "trailing_der_rejected",
        "validity_required",
        "explicit_server_auth_required",
        "digital_signature_required_when_key_usage_present",
        "exact_dns_or_ip_san_required",
        "tls12_signature_delegated",
        "tls13_signature_delegated",
        "supported_schemes_delegated",
        "root_hints_delegated",
        "all_other_webpki_errors_returned_unchanged",
    ] {
        if invariants[key].as_bool() != Some(true) {
            return Err(format!("fallback invariant {key} is not true"));
        }
    }
    let allowed_errors = invariants["allowed_webpki_error_classes"]
        .as_array()
        .ok_or_else(|| "allowed_webpki_error_classes must be an array".to_owned())?;
    if allowed_errors.as_slice() != [Value::String("CertificateError::UnknownIssuer".to_owned())] {
        return Err("fallback error allow-set broadened".to_owned());
    }

    let residues = array(value, "retained_local_policy");
    if ids(residues, "residue_id")
        != BTreeSet::from([
            "X509-R2-CA-ADMISSION".to_owned(),
            "X509-R3-ACCEPTOR-PREFLIGHT".to_owned(),
            "X509-R4-NATIVE-PIN-FALLBACK".to_owned(),
            "X509-R5-ATP-PIN-FALLBACK".to_owned(),
        ])
    {
        return Err("retained residue set drifted".to_owned());
    }
    if row(residues, "residue_id", "X509-R5-ATP-PIN-FALLBACK")["state"].as_str()
        != Some("RESOLVED_BY_DELEGATION_TO_X509-R4")
    {
        return Err("ATP duplicate residue is no longer resolved".to_owned());
    }

    let expected_gaps = BTreeMap::from([
        ("X509-GAP-02", "CLOSED_BY_A2_SHARED_POLICY"),
        ("X509-GAP-03", "CLOSED_BY_A2_SHARED_POLICY"),
        ("X509-GAP-04", "A2_DECIDED_KEEP_A8_E2E_PENDING"),
        ("X509-GAP-05", "A2_DECIDED_KEEP_A8_E2E_PENDING"),
        ("X509-GAP-06", "A2_DECIDED_KEEP_A8_E2E_PENDING"),
        ("X509-GAP-11", "A2_DECIDED_KEEP_A8_E2E_PENDING"),
    ]);
    let gaps = array(value, "routed_gap_disposition");
    if ids(gaps, "gap_id") != expected_gaps.keys().map(|gap| (*gap).to_owned()).collect() {
        return Err("gap disposition set drifted".to_owned());
    }
    for (gap_id, state) in expected_gaps {
        if row(gaps, "gap_id", gap_id)["state"].as_str() != Some(state) {
            return Err(format!("{gap_id} state drifted"));
        }
    }

    let receipts = array(value, "execution_receipts");
    if receipts.len() != 5
        || receipts.iter().any(|receipt| {
            receipt["exit_code"].as_i64() != Some(0)
                || receipt["failed"].as_u64() != Some(0)
                || receipt["passed"].as_u64().is_none_or(|passed| passed == 0)
        })
    {
        return Err("focused execution receipts are incomplete".to_owned());
    }

    if value["downstream_e2e_contract"]["scenario_id"].as_str() != Some("tls_x509_interop")
        || value["downstream_e2e_contract"]["owner"].as_str() != Some("asupersync-0h6myr.3.8")
        || value["downstream_e2e_contract"]["state"].as_str() != Some("PLANNED")
    {
        return Err("downstream A8 handoff drifted".to_owned());
    }
    if array(value, "rollback_triggers").len() < 8 || array(value, "no_claim_boundaries").len() < 8
    {
        return Err("rollback or no-claim boundaries are incomplete".to_owned());
    }

    Ok(())
}

#[test]
fn artifact_is_valid_and_fail_closed() {
    let artifact = parse(ARTIFACT_PATH);
    validate(&artifact).expect("canonical A2 artifact");
}

#[test]
fn source_contract_hashes_and_lengths_are_exact() {
    let artifact = parse(ARTIFACT_PATH);
    let contracts = array(&artifact, "source_contracts");
    let expected = BTreeSet::from([
        ATP_SOURCE.to_owned(),
        "Cargo.lock".to_owned(),
        "Cargo.toml".to_owned(),
        INVENTORY_PATH.to_owned(),
        SHARED_SOURCE.to_owned(),
        "docs/x509_validation_ownership_inventory.md".to_owned(),
        "tests/x509_validation_ownership_inventory_contract.rs".to_owned(),
    ]);
    assert_eq!(
        ids(contracts, "path"),
        expected,
        "source contract path set drifted"
    );
    for contract in contracts {
        let relative = text(contract, "path");
        let path = root().join(relative);
        assert_eq!(
            text(contract, "sha256"),
            sha256(&path),
            "{relative} hash drifted"
        );
        assert_eq!(
            contract["line_count"].as_u64(),
            Some(line_count(&path) as u64),
            "{relative} line count drifted"
        );
    }
}

#[test]
fn shared_wrapper_is_standard_first_and_narrow() {
    let source = read(SHARED_SOURCE);
    for marker in [
        "pub fn webpki_server_verifier_with_exact_leaf_fallback",
        "self.webpki.verify_server_cert(",
        "if is_unknown_issuer(&error)",
        ".any(|pinned| pinned.as_ref() == end_entity.as_ref())",
        "if !remaining.is_empty()",
        "Some(usage) if usage.value.server_auth",
        "!usage.value.digital_signature()",
        "self.webpki.verify_tls12_signature",
        "self.webpki.verify_tls13_signature",
        "self.webpki.supported_verify_schemes()",
        "self.webpki.root_hint_subjects()",
    ] {
        assert!(source.contains(marker), "shared wrapper missing {marker:?}");
    }
    assert!(
        !source.contains("usage.value.server_auth || usage.value.any"),
        "shared fallback must not accept anyExtendedKeyUsage"
    );
}

#[test]
fn atp_delegates_without_an_independent_parser_or_verifier() {
    let source = read(ATP_SOURCE);
    for marker in [
        "fn quic_cli_client_config(",
        "WebPkiServerVerifier::builder_with_provider",
        "webpki_server_verifier_with_exact_leaf_fallback(",
        "code: \"client_verifier_build_failed\"",
    ] {
        assert!(source.contains(marker), "ATP caller missing {marker:?}");
    }
    for forbidden in [
        "QuicCliServerVerifier",
        "verify_quic_cli_pinned_leaf",
        "x509_parser::",
    ] {
        assert!(
            !source.contains(forbidden),
            "ATP restored forbidden duplicate {forbidden:?}"
        );
    }
}

#[test]
fn focused_failure_matrix_and_local_policy_owners_remain_present() {
    let shared = read(SHARED_SOURCE);
    for test in [
        "fn exact_leaf_shape_enforces_validity_bounds",
        "fn exact_leaf_shape_requires_server_auth_and_digital_signature",
        "fn exact_leaf_shape_rejects_missing_eku_and_trailing_der",
        "fn exact_leaf_fallback_never_overrides_standard_signature_or_name_errors",
        "fn exact_pinned_leaf_still_rejects_wrong_server_name",
    ] {
        assert!(shared.contains(test), "missing focused test {test}");
    }
    let connector = read("src/tls/connector.rs");
    for marker in [
        "fn is_ca_certificate",
        "fn test_is_ca_certificate_rejects_self_signed_leaf",
        "fn add_root_certificate_strict_ca_rejects_self_signed_leaf",
    ] {
        assert!(
            connector.contains(marker),
            "CA policy owner missing {marker}"
        );
    }
    let acceptor = read("src/tls/acceptor.rs");
    for marker in [
        "fn validate_certificate_chain",
        "fn test_certificate_validation_rejects_empty_chain",
        "fn test_disable_strict_cert_validation_allows_invalid_certs",
    ] {
        assert!(
            acceptor.contains(marker),
            "acceptor policy owner missing {marker}"
        );
    }
}

#[test]
fn a1_inventory_reconciles_with_the_a2_decision() {
    let inventory = parse(INVENTORY_PATH);
    assert_eq!(
        inventory["authority"]["residue_status"].as_str(),
        Some("A2_SHARED_PIN_DELEGATION_COMPLETE_A3_SPEC_PENDING")
    );
    assert_eq!(
        inventory["occurrence_census"]["active_production_call_sites"].as_u64(),
        Some(4)
    );
    let paths: BTreeSet<_> = inventory["occurrence_census"]["paths"]
        .as_array()
        .expect("inventory parser paths")
        .iter()
        .map(|path| path.as_str().expect("path text"))
        .collect();
    assert!(
        !paths.contains(ATP_SOURCE),
        "ATP must not remain a parser site"
    );

    let residues = array(&inventory, "provisional_residue");
    assert_eq!(
        row(residues, "residue_id", "X509-R4-NATIVE-PIN-FALLBACK")["state"].as_str(),
        Some("A2_SHARED_POLICY_ACTIVE_PENDING_A3_OWNED_READER")
    );
    assert_eq!(
        row(residues, "residue_id", "X509-R5-ATP-PIN-FALLBACK")["state"].as_str(),
        Some("RESOLVED_BY_A2_DELEGATION_TO_X509-R4")
    );

    let gaps = array(&inventory, "routed_gaps");
    for gap_id in ["X509-GAP-02", "X509-GAP-03"] {
        assert_eq!(
            row(gaps, "gap_id", gap_id)["state"].as_str(),
            Some("CLOSED_BY_A2_SHARED_POLICY")
        );
    }
    for gap_id in ["X509-GAP-04", "X509-GAP-05", "X509-GAP-06", "X509-GAP-11"] {
        assert_eq!(
            row(gaps, "gap_id", gap_id)["state"].as_str(),
            Some("A2_DECIDED_KEEP_A8_E2E_PENDING")
        );
    }
}

#[test]
fn cargo_dependency_surface_is_unchanged() {
    let manifest = read("Cargo.toml");
    let lockfile = read("Cargo.lock");
    assert!(manifest.contains("x509-parser = { version = \"0.18\", optional = true }"));
    assert!(manifest.contains("\"dep:x509-parser\""));
    assert!(lockfile.contains("name = \"x509-parser\""));
}

#[test]
fn operator_documentation_records_decision_and_no_claims() {
    let document = read(DOC_PATH);
    for marker in [
        "X509_STANDARD_VERIFIER_DELEGATION_BEGIN",
        "X509_STANDARD_VERIFIER_DELEGATION_END",
        "STANDARD_FIRST_SHARED_EXACT_LEAF_POLICY",
        "webpki_server_verifier_with_exact_leaf_fallback",
        "CertificateError::UnknownIssuer",
        "client_verifier_build_failed",
        "X509-GAP-02",
        "X509-GAP-11",
        "tls_x509_interop",
        "No-claim boundary",
        "does not authorize removing `x509-parser`",
        "does not claim issuer-path validation",
    ] {
        assert!(document.contains(marker), "operator doc missing {marker:?}");
    }
}

#[test]
fn mutations_reject_broad_fallback_and_cutover_authority() {
    let canonical = parse(ARTIFACT_PATH);

    let mut broad = canonical.clone();
    broad["fallback_invariants"]["allowed_webpki_error_classes"] = serde_json::json!([
        "CertificateError::UnknownIssuer",
        "CertificateError::BadSignature"
    ]);
    assert!(validate(&broad).is_err());

    let mut missing_source = canonical.clone();
    missing_source["source_contracts"]
        .as_array_mut()
        .expect("source contracts")
        .pop();
    assert!(validate(&missing_source).is_err());

    let mut cutover = canonical;
    cutover["decision"]["cutover_authorized"] = Value::Bool(true);
    assert!(validate(&cutover).is_err());
}
