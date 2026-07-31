//! Contract and delegated-verifier checks for the X.509 A5 adversarial corpus.

#![cfg(feature = "tls")]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use asupersync::net::quic_native::tls::{QuicServerIdentityVerifier, QuicTlsError};
use asupersync::tls::{Certificate, CertificateChain, RootCertStore};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/x509_adversarial_corpus_v1.json";
const DOC_PATH: &str = "docs/x509_adversarial_corpus.md";
const A4_SOURCE: &str = "src/tls/der_min.rs";
const FUZZ_MANIFEST: &str = "fuzz/Cargo.toml";
const FUZZ_TARGET: &str = "fuzz/fuzz_targets/x509_der_residue.rs";
const FIXTURE_DIR: &str = "tests/fixtures/x509_adversarial";
const FIXTURE_TIME_SECONDS: u64 = 1_790_000_000;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).expect("contract text must be readable")
}

fn parse(path: &str) -> Value {
    serde_json::from_str(&read(path)).expect("contract JSON must parse")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value[key]
        .as_array()
        .expect("contract field must be an array")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().expect("contract field must be text")
}

fn ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn sha256(path: &Path) -> String {
    let bytes = fs::read(path).expect("pinned source must be readable");
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn line_count(path: &Path) -> usize {
    fs::read(path)
        .expect("line-count source must be readable")
        .split(|byte| *byte == b'\n')
        .count()
        .saturating_sub(1)
}

fn fixture(path: &str) -> Certificate {
    Certificate::from_pem(
        &fs::read(root().join(path)).expect("certificate fixture must be readable"),
    )
    .expect("certificate fixture must parse")
    .into_iter()
    .next()
    .expect("fixture must contain a certificate")
}

fn verify(root_path: &str, leaf_path: &str, hostname: &str) -> Result<(), QuicTlsError> {
    let root_certificate = fixture(root_path);
    let mut roots = RootCertStore::empty();
    roots
        .add(&root_certificate)
        .expect("generated root fixture must be accepted");
    let verifier =
        QuicServerIdentityVerifier::from_root_store(roots).expect("WebPKI verifier builds");
    verifier
        .verify_server_chain(
            hostname,
            CertificateChain::from(vec![fixture(leaf_path)]),
            rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(FIXTURE_TIME_SECONDS)),
        )
        .map(|_| ())
}

#[test]
fn artifact_identity_case_set_and_receipts_are_fail_closed() {
    let artifact = parse(ARTIFACT_PATH);
    assert_eq!(artifact["schema_version"].as_u64(), Some(1));
    assert_eq!(
        artifact["artifact_id"].as_str(),
        Some("x509-adversarial-corpus-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-0h6myr.3.5"));
    assert_eq!(artifact["capability_id"].as_str(), Some("CAP-TLS-X509"));
    assert_eq!(
        artifact["authority"]["state"].as_str(),
        Some("A5_EVIDENCE_ONLY")
    );

    let expected_cases = BTreeSet::from([
        "X509-A5-ABSENT-SAN".to_owned(),
        "X509-A5-CA-FALSE".to_owned(),
        "X509-A5-CA-TRUE".to_owned(),
        "X509-A5-DER-LENGTH".to_owned(),
        "X509-A5-DER-TAG".to_owned(),
        "X509-A5-DUPLICATE-SAN-EXTENSION".to_owned(),
        "X509-A5-EXPIRED".to_owned(),
        "X509-A5-FUTURE".to_owned(),
        "X509-A5-MALFORMED-SPKI".to_owned(),
        "X509-A5-NAME-CONSTRAINT-ALLOWED".to_owned(),
        "X509-A5-NAME-CONSTRAINT-BLOCKED".to_owned(),
        "X509-A5-OVERSIZED".to_owned(),
        "X509-A5-REAL-VALID-CHAIN".to_owned(),
        "X509-A5-TRAILING-DER".to_owned(),
        "X509-A5-UNKNOWN-CRITICAL".to_owned(),
        "X509-A5-WILDCARD-DEPTH".to_owned(),
        "X509-A5-WILDCARD-VALID".to_owned(),
        "X509-A5-WRONG-EKU".to_owned(),
        "X509-A5-WRONG-KU".to_owned(),
    ]);
    assert_eq!(ids(array(&artifact, "cases"), "case_id"), expected_cases);
    for case in array(&artifact, "cases") {
        assert!(
            case["provenance_id"].as_str().is_some(),
            "case provenance missing"
        );
        assert!(
            case["expected_security_outcome"].as_str().is_some(),
            "case outcome missing"
        );
        assert!(
            case["evidence_test"].as_str().is_some(),
            "case evidence test missing"
        );
        assert!(
            case["divergence"].as_str().is_some(),
            "case differential disposition missing"
        );
    }

    let receipts = array(&artifact, "execution_receipts");
    assert!(receipts.len() >= 6);
    assert!(receipts.iter().all(|receipt| {
        receipt["status"].as_str() == Some("PASS") && receipt["exit_code"].as_i64() == Some(0)
    }));
    assert!(array(&artifact, "no_claim_boundaries").len() >= 8);
    assert!(array(&artifact, "rollback_triggers").len() >= 6);
}

#[test]
fn source_and_fixture_pins_are_exact() {
    let artifact = parse(ARTIFACT_PATH);
    let expected_paths = BTreeSet::from([
        A4_SOURCE.to_owned(),
        FUZZ_MANIFEST.to_owned(),
        FUZZ_TARGET.to_owned(),
        format!("{FIXTURE_DIR}/allowed.crt"),
        format!("{FIXTURE_DIR}/blocked.crt"),
        format!("{FIXTURE_DIR}/ca.crt"),
        format!("{FIXTURE_DIR}/wildcard.crt"),
        "tests/fixtures/tls/server.crt".to_owned(),
    ]);
    let pins = array(&artifact, "source_pins");
    assert_eq!(ids(pins, "path"), expected_paths);
    for pin in pins {
        let relative = text(pin, "path");
        let path = root().join(relative);
        assert_eq!(text(pin, "sha256"), sha256(&path), "{relative} hash");
        assert_eq!(
            pin["line_count"].as_u64(),
            Some(line_count(&path) as u64),
            "{relative} line count"
        );
    }
}

#[test]
fn fuzz_target_is_exact_source_bounded_and_oracle_free() {
    let target = read(FUZZ_TARGET);
    for marker in [
        "#[path = \"../../src/tls/der_min.rs\"]",
        "MAX_CERTIFICATE_DER_BYTES_USIZE",
        "MAX_PEM_CERTIFICATES_PER_INPUT",
        "assert_eq!(spki_first, spki_second)",
        "assert_error_is_bounded",
        "rustls_pemfile::certs",
    ] {
        assert!(target.contains(marker), "fuzz target missing {marker:?}");
    }
    for forbidden in [
        "x509_parser",
        "WebPkiServerVerifier",
        "unwrap_unchecked",
        "unsafe {",
    ] {
        assert!(
            !target.contains(forbidden),
            "fuzz target restored forbidden oracle/surface {forbidden:?}"
        );
    }
    let manifest = read(FUZZ_MANIFEST);
    assert!(manifest.contains("name = \"x509_der_residue\""));
    assert!(manifest.contains("path = \"fuzz_targets/x509_der_residue.rs\""));
}

#[test]
fn delegated_name_constraints_accept_only_the_permitted_subtree() {
    let root = format!("{FIXTURE_DIR}/ca.crt");
    let allowed = format!("{FIXTURE_DIR}/allowed.crt");
    let blocked = format!("{FIXTURE_DIR}/blocked.crt");

    verify(&root, &allowed, "api.allowed.example")
        .expect("permitted DNS subtree must verify through WebPKI");
    let error = verify(&root, &blocked, "blocked.example")
        .expect_err("name-constraint violation must fail closed");
    assert!(matches!(
        error,
        QuicTlsError::ServerCertificateRejected {
            code: "server_certificate_invalid"
        }
    ));
}

#[test]
fn delegated_wildcard_semantics_are_one_label_only() {
    let wildcard = format!("{FIXTURE_DIR}/wildcard.crt");
    verify(&wildcard, &wildcard, "api.example.com").expect("one-label wildcard match must verify");
    for rejected in ["example.com", "deep.api.example.com", "not-example.test"] {
        assert!(
            verify(&wildcard, &wildcard, rejected).is_err(),
            "{rejected} must not match *.example.com"
        );
    }
}

#[test]
fn runbook_and_artifact_keep_authority_narrow() {
    let document = read(DOC_PATH);
    for marker in [
        "A5 evidence only",
        "Intentional differential divergence",
        "Bounded fuzz contract",
        "No call-site migration",
        "No dependency cutover",
    ] {
        assert!(document.contains(marker), "runbook missing {marker:?}");
    }
    let artifact = parse(ARTIFACT_PATH);
    assert_eq!(
        artifact["downstream_handoff"]["owner"].as_str(),
        Some("asupersync-0h6myr.3.6")
    );
    assert_eq!(
        artifact["downstream_handoff"]["state"].as_str(),
        Some("PLANNED")
    );
}
