//! Fail-closed X.509 call-path and validation-owner inventory contract.
//!
//! Bead: asupersync-0h6myr.3.1
//! Capability: CAP-TLS-X509
//! Fixture: artifacts/x509_validation_ownership_inventory_v1.json
//!
//! This contract proves a source-pinned inventory, exact production
//! x509-parser occurrence census, explicit rustls/WebPKI and local ownership,
//! routed gaps, and the A2 delegation update to the provisional residue. It
//! does not prove parser correctness, certificate interoperability,
//! performance, or permission to remove the incumbent dependency.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/x509_validation_ownership_inventory_v1.json";
const DOC_PATH: &str = "docs/x509_validation_ownership_inventory.md";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const CUTOVER_POLICY_PATH: &str = "artifacts/dependency_cutover_policy_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const API_SURFACE_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-0h6myr.3.1";
const CAPABILITY_ID: &str = "CAP-TLS-X509";
const BASELINE_REVISION: &str = "3c09dad6aa59566964724ffe6c9dc99359bfd180";
const DOC_BEGIN: &str = "<!-- BEGIN X509 VALIDATION OWNERSHIP INVENTORY -->";
const DOC_END: &str = "<!-- END X509 VALIDATION OWNERSHIP INVENTORY -->";

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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
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

fn validate_inventory_structure(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "x509-validation-ownership-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("registry_cutover_state", "KEEP_INCUMBENT"),
        ("cutover_policy_class", "SECURITY_SENSITIVE"),
        (
            "standard_validation_owner",
            "rustls-0.23.42/rustls-webpki-0.103.13",
        ),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
        || authority
            .get("parser_code_allowed_in_this_bead")
            .and_then(Value::as_bool)
            != Some(false)
        || authority.get("residue_status").and_then(Value::as_str)
            != Some("A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING")
    {
        return Err(
            "A1 must record A3 approval while forbidding parser implementation and dependency exit"
                .to_owned(),
        );
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy.get("inventory_state").and_then(Value::as_str)
            != Some("BASELINED_WITH_ROUTED_GAPS")
        || policy
            .get("missing_or_ambiguous_owner_action")
            .and_then(Value::as_str)
            != Some("KEEP_X509_PARSER_AND_BLOCK_CUTOVER")
    {
        return Err("policy must remain zero-unknown and fail closed".to_owned());
    }
    validate_no_unknown(inventory, "$")?;

    let expected_call_sites = expected_set(&[
        "X509-CS-SPKI-PIN",
        "X509-CS-ROOT-CA-ADMISSION",
        "X509-CS-ACCEPTOR-PREFLIGHT",
        "X509-CS-NATIVE-QUIC-PIN-FALLBACK",
        "X509-CS-ATP-CLI-PIN-FALLBACK",
    ]);
    let call_sites = array(inventory, "call_sites");
    if call_sites.len() != 5 || row_ids(call_sites, "call_site_id") != expected_call_sites {
        return Err("call_sites must contain the exact five active sites".to_owned());
    }
    for row in call_sites {
        for key in [
            "path",
            "function",
            "cfg",
            "input",
            "standard_verifier_before",
            "standard_verifier_after",
            "custom_verifier_bypass",
            "error_behavior",
            "owner",
            "delegation_verdict",
        ] {
            if text(row, key).is_empty() {
                return Err(format!(
                    "{}.{key} must be nonempty",
                    text(row, "call_site_id")
                ));
            }
        }
        if array(row, "symbols").is_empty()
            || array(row, "checks_or_extractions").is_empty()
            || array(row, "residue_ids").is_empty()
            || array(row, "source_markers").len() < 3
        {
            return Err(format!(
                "{} must map symbols, behavior, residue, and source markers",
                text(row, "call_site_id")
            ));
        }
    }
    let native = find_row(
        call_sites,
        "call_site_id",
        "X509-CS-NATIVE-QUIC-PIN-FALLBACK",
    );
    let atp = find_row(call_sites, "call_site_id", "X509-CS-ATP-CLI-PIN-FALLBACK");
    if !text(native, "custom_verifier_bypass").contains("only UnknownIssuer")
        || !text(atp, "custom_verifier_bypass").contains("only UnknownIssuer")
        || native.get("full_input_consumed").and_then(Value::as_bool) != Some(true)
        || atp.get("full_input_consumed").and_then(Value::as_bool) != Some(true)
        || text(atp, "delegation_verdict") != "A2_DELEGATED_TO_SHARED_EXPLICIT_PIN_POLICY"
    {
        return Err("the shared exact-pin fallback boundary must remain explicit".to_owned());
    }

    let expected_verifiers = expected_set(&[
        "X509-VP-TLS-STANDARD",
        "X509-VP-TLS-CRL",
        "X509-VP-TLS-RAW-CONFIG",
        "X509-VP-TLS-MTLS",
        "X509-VP-QUIC-IDENTITY",
        "X509-VP-NATIVE-QUIC-PIN",
        "X509-VP-ATP-CLI-PIN",
        "X509-VP-LEGACY-QUIC",
        "X509-VP-CFG-OFF",
    ]);
    let verifiers = array(inventory, "verifier_paths");
    if verifiers.len() != 9 || row_ids(verifiers, "path_id") != expected_verifiers {
        return Err("verifier_paths must contain the exact nine path classes".to_owned());
    }
    if text(
        find_row(verifiers, "path_id", "X509-VP-TLS-RAW-CONFIG"),
        "state",
    ) != "CALLER_OWNED"
        || find_row(verifiers, "path_id", "X509-VP-TLS-CRL")
            .get("standard_checks_bypassed")
            .and_then(Value::as_bool)
            != Some(false)
        || !text(
            find_row(verifiers, "path_id", "X509-VP-ATP-CLI-PIN"),
            "standard_checks_bypassed",
        )
        .contains("only UnknownIssuer")
    {
        return Err("custom verifier ownership or bypass boundary drifted".to_owned());
    }

    let expected_checks = expected_set(&[
        "X509-CHK-DER-CANONICALITY",
        "X509-CHK-CHAIN-PATH",
        "X509-CHK-CERT-SIGNATURE",
        "X509-CHK-HANDSHAKE-SIGNATURE",
        "X509-CHK-TRUST-ANCHOR",
        "X509-CHK-VALIDITY",
        "X509-CHK-EKU",
        "X509-CHK-KEY-USAGE",
        "X509-CHK-SAN-NAME",
        "X509-CHK-BASIC-CONSTRAINTS",
        "X509-CHK-NAME-CONSTRAINTS",
        "X509-CHK-CRITICAL-EXTENSIONS",
        "X509-CHK-DUPLICATE-EXTENSIONS",
        "X509-CHK-REVOCATION",
        "X509-CHK-SPKI-EXTRACTION",
        "X509-CHK-OWN-CERT-PREFLIGHT",
    ]);
    let checks = array(inventory, "check_ownership_matrix");
    if checks.len() != 16 || row_ids(checks, "check_id") != expected_checks {
        return Err("check_ownership_matrix must contain the exact sixteen checks".to_owned());
    }
    for row in checks {
        for key in [
            "requirement",
            "standard_server",
            "mtls_client",
            "native_pin_fallback",
            "atp_pin_fallback",
            "local_auxiliary",
            "delegation",
            "preservation",
        ] {
            if text(row, key).is_empty() {
                return Err(format!("{}.{key} must be nonempty", text(row, "check_id")));
            }
        }
    }
    let key_usage = find_row(checks, "check_id", "X509-CHK-KEY-USAGE");
    if !text(key_usage, "standard_server").contains("intentionally ignores")
        || !text(key_usage, "native_pin_fallback").contains("digitalSignature")
        || !text(key_usage, "atp_pin_fallback").contains("digitalSignature")
    {
        return Err("the shared pin-only KeyUsage policy must remain explicit".to_owned());
    }
    let cert_signature = find_row(checks, "check_id", "X509-CHK-CERT-SIGNATURE");
    let handshake_signature = find_row(checks, "check_id", "X509-CHK-HANDSHAKE-SIGNATURE");
    if text(cert_signature, "native_pin_fallback").contains("delegated")
        || text(handshake_signature, "native_pin_fallback")
            != "delegated to the inner WebPkiServerVerifier"
    {
        return Err("issuer signatures and TLS CertificateVerify must stay distinct".to_owned());
    }

    let expected_residue = expected_set(&[
        "X509-R1-SPKI",
        "X509-R2-CA-ADMISSION",
        "X509-R3-ACCEPTOR-PREFLIGHT",
        "X509-R4-NATIVE-PIN-FALLBACK",
        "X509-R5-ATP-PIN-FALLBACK",
    ]);
    let residue = array(inventory, "provisional_residue");
    if residue.len() != 5 || row_ids(residue, "residue_id") != expected_residue {
        return Err("provisional_residue must contain exactly R1 through R5".to_owned());
    }
    for row in residue {
        let expected_state = match text(row, "residue_id") {
            "X509-R1-SPKI"
            | "X509-R2-CA-ADMISSION"
            | "X509-R3-ACCEPTOR-PREFLIGHT"
            | "X509-R4-NATIVE-PIN-FALLBACK" => "A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING",
            "X509-R5-ATP-PIN-FALLBACK" => "RESOLVED_BY_A2_DELEGATION_TO_X509-R4",
            other => return Err(format!("unexpected residue {other}")),
        };
        if text(row, "state") != expected_state
            || text(row, "scope").is_empty()
            || text(row, "current_owner").is_empty()
            || array(row, "allowed_checks").is_empty()
            || !array(row, "forbidden_checks").iter().any(|check| {
                check
                    .as_str()
                    .is_some_and(|check| check.contains("path building"))
            })
        {
            return Err(format!(
                "{} must stay explicitly dispositioned, bounded, and unable to build paths",
                text(row, "residue_id")
            ));
        }
    }

    let expected_cells = expected_set(&[
        "X509-CELL-CFG-OFF",
        "X509-CELL-TLS-NATIVE",
        "X509-CELL-ATP-CLI",
        "X509-CELL-TLS-WASM",
    ]);
    let cells = array(inventory, "feature_target_matrix");
    if cells.len() != 4 || row_ids(cells, "cell_id") != expected_cells {
        return Err("feature_target_matrix must contain the exact four cells".to_owned());
    }
    if text(find_row(cells, "cell_id", "X509-CELL-TLS-WASM"), "state") != "UNSUPPORTED_NO_CLAIM"
        || !array(
            find_row(cells, "cell_id", "X509-CELL-CFG-OFF"),
            "active_call_sites",
        )
        .is_empty()
    {
        return Err("wasm and cfg-disabled boundaries must remain fail closed".to_owned());
    }
    let mapped_sites: BTreeSet<String> = cells
        .iter()
        .flat_map(|row| {
            array(row, "active_call_sites").iter().map(|entry| {
                entry
                    .as_str()
                    .expect("active_call_sites entries must be strings")
                    .to_owned()
            })
        })
        .collect();
    if mapped_sites != expected_call_sites {
        return Err("every call site must appear in a feature/target cell".to_owned());
    }

    let expected_diagnostics = expected_set(&[
        "X509-DIAG-TLS-RUSTLS",
        "X509-DIAG-TLS-PIN",
        "X509-DIAG-ACCEPTOR-PREFLIGHT",
        "X509-DIAG-ROOT-ADMISSION",
        "X509-DIAG-QUIC-IDENTITY",
        "X509-DIAG-QUIC-HANDSHAKE",
        "X509-DIAG-CFG-OFF",
    ]);
    let diagnostics = array(inventory, "public_and_operator_diagnostics");
    if diagnostics.len() != 7 || row_ids(diagnostics, "diagnostic_id") != expected_diagnostics {
        return Err("public/operator diagnostic inventory drifted".to_owned());
    }
    for row in diagnostics {
        if row.get("secret_safe").and_then(Value::as_bool) != Some(true)
            || text(row, "surface").is_empty()
            || text(row, "behavior").is_empty()
        {
            return Err(format!(
                "{} must be mapped and secret-safe",
                text(row, "diagnostic_id")
            ));
        }
    }

    let expected_journeys = expected_set(&[
        "X509-JOURNEY-TLS-CLIENT",
        "X509-JOURNEY-TLS-SERVER-MTLS",
        "X509-JOURNEY-TLS-PINNING",
        "X509-JOURNEY-NATIVE-QUIC",
        "X509-JOURNEY-ATP-QUIC",
        "X509-JOURNEY-HTTP-H1",
        "X509-JOURNEY-MESSAGING",
        "X509-JOURNEY-POSTGRES",
        "X509-JOURNEY-PLATFORMS",
    ]);
    let journeys = array(inventory, "supported_journeys");
    if journeys.len() != 9 || row_ids(journeys, "journey_id") != expected_journeys {
        return Err("supported journey inventory drifted".to_owned());
    }
    for row in journeys {
        if !matches!(text(row, "state"), "ACTIVE" | "PLANNED")
            || text(row, "aggregate_e2e_owner") != "asupersync-0h6myr.3.8"
            || array(row, "entry_points").is_empty()
            || array(row, "verifier_path_ids").is_empty()
            || text(row, "current_evidence").is_empty()
        {
            return Err(format!(
                "{} must have paths, evidence state, and A8 ownership",
                text(row, "journey_id")
            ));
        }
    }

    let gaps = array(inventory, "routed_gaps");
    let expected_gaps: BTreeSet<String> = (1..=12)
        .map(|suffix| format!("X509-GAP-{suffix:02}"))
        .collect();
    if gaps.len() != 12 || row_ids(gaps, "gap_id") != expected_gaps {
        return Err("routed_gaps must retain X509-GAP-01 through 12".to_owned());
    }
    for row in gaps {
        let expected_state = match text(row, "gap_id") {
            "X509-GAP-01" => "A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING",
            "X509-GAP-02" | "X509-GAP-03" => "CLOSED_BY_A2_SHARED_POLICY",
            "X509-GAP-04" | "X509-GAP-05" | "X509-GAP-06" | "X509-GAP-11" => {
                "A2_DECIDED_KEEP_A8_E2E_PENDING"
            }
            _ => "ROUTED",
        };
        if text(row, "state") != expected_state
            || text(row, "owner").is_empty()
            || text(row, "finding").is_empty()
        {
            return Err(format!(
                "{} must remain explicit and correctly dispositioned",
                text(row, "gap_id")
            ));
        }
    }

    let residue_contract = object(inventory, "der_residue_spec_contract");
    for (key, expected) in [
        ("artifact", "artifacts/x509_der_residue_spec_v1.json"),
        ("document", "docs/x509_der_residue_spec.md"),
        ("test", "tests/x509_der_residue_spec_contract.rs"),
        ("state", "APPROVED"),
        ("reviewer", "/root/architecture_trace"),
        (
            "reviewed_draft_sha256",
            "9a1d64225bbce6fbcf671964f2f567d7b9cdb500929f61a2e0b46872b4bbcfd2",
        ),
        (
            "reviewed_normative_payload_sha256",
            "8a619557ce3a8d87833d7e8733ac89a5fe78a1286c7cdb93c9c88bbd37e17274",
        ),
        ("implementation_owner", "asupersync-0h6myr.3.4"),
    ] {
        if residue_contract.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("der_residue_spec_contract.{key} drifted"));
        }
    }
    if residue_contract
        .get("cutover_allowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("A3 approval must not authorize cutover".to_owned());
    }

    let downstream = object(inventory, "downstream_e2e_contract");
    if downstream.get("scenario_id").and_then(Value::as_str) != Some("tls_x509_interop")
        || downstream.get("state").and_then(Value::as_str) != Some("PLANNED")
        || downstream.get("owner").and_then(Value::as_str) != Some("asupersync-0h6myr.3.8")
        || downstream
            .get("required_dimensions")
            .and_then(Value::as_array)
            .is_none_or(|rows| rows.len() < 10)
    {
        return Err("the canonical A8 E2E obligation must remain explicit".to_owned());
    }

    if array(inventory, "rollback_triggers").len() != 8
        || array(inventory, "no_claim_boundaries").len() != 8
    {
        return Err("rollback and no-claim boundaries must remain complete".to_owned());
    }
    Ok(())
}

fn collect_x509_source_paths(dir: &Path, paths: &mut BTreeSet<String>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.expect("source directory entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_x509_source_paths(&path, paths);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            if source.contains("x509_parser::") {
                let relative = path
                    .strip_prefix(repo_root())
                    .expect("source path must be inside repository")
                    .to_string_lossy()
                    .replace('\\', "/");
                paths.insert(relative);
            }
        }
    }
}

fn lock_version(lockfile: &str, package_name: &str) -> Option<String> {
    for package in lockfile.split("[[package]]") {
        let mut name = None;
        let mut version = None;
        for line in package.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("name = \"") {
                name = value.strip_suffix('"');
            } else if let Some(value) = line.strip_prefix("version = \"") {
                version = value.strip_suffix('"');
            }
        }
        if name == Some(package_name) {
            return version.map(str::to_owned);
        }
    }
    None
}

#[test]
fn inventory_structure_is_complete_and_fail_closed() {
    let inventory = artifact();
    validate_inventory_structure(&inventory).expect("canonical X.509 inventory must validate");
}

#[test]
fn source_pins_match_the_audited_revision() {
    let inventory = artifact();
    let pins = array(&inventory, "source_pins");
    assert_eq!(pins.len(), 15, "source pin count must remain exact");
    assert_eq!(
        row_ids(pins, "path").len(),
        pins.len(),
        "source pin paths must be unique"
    );
    for pin in pins {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let actual_hash = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let actual_lines = u64::try_from(
            std::str::from_utf8(&bytes)
                .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
                .lines()
                .count(),
        )
        .expect("source line count must fit in u64");
        assert_eq!(
            actual_hash,
            text(pin, "sha256"),
            "{path} changed; refresh the X.509 call-path audit"
        );
        assert_eq!(
            Some(actual_lines),
            pin.get("line_count").and_then(Value::as_u64),
            "{path} line count drifted"
        );
    }
}

#[test]
fn production_x509_parser_occurrences_are_exact_and_source_marked() {
    let inventory = artifact();
    let expected_paths = expected_set(&[
        "src/net/quic_native/handshake_driver.rs",
        "src/tls/acceptor.rs",
        "src/tls/connector.rs",
        "src/tls/types.rs",
    ]);
    let mut actual_paths = BTreeSet::new();
    collect_x509_source_paths(&repo_root().join("src"), &mut actual_paths);
    assert_eq!(
        actual_paths, expected_paths,
        "production x509-parser source ownership drifted"
    );

    let call_sites = array(&inventory, "call_sites");
    let expected_call_site_paths = expected_paths
        .iter()
        .cloned()
        .chain(["src/bin/atp.rs".to_owned()])
        .collect::<BTreeSet<_>>();
    assert_eq!(
        call_sites
            .iter()
            .map(|row| text(row, "path").to_owned())
            .collect::<BTreeSet<_>>(),
        expected_call_site_paths
    );
    let census = inventory
        .get("occurrence_census")
        .expect("occurrence_census must be present");
    assert_eq!(
        census
            .get("active_production_call_site_files")
            .and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(string_set(census, "paths"), expected_paths);
    for row in call_sites {
        let source = read_repo_file(text(row, "path"));
        for marker in array(row, "source_markers") {
            let marker = marker
                .as_str()
                .expect("source marker entries must be strings");
            assert!(
                source.contains(marker),
                "{} lost source marker {marker:?}",
                text(row, "call_site_id")
            );
        }
    }
}

#[test]
fn locked_versions_and_manifest_edges_match() {
    let lockfile = read_repo_file("Cargo.lock");
    assert_eq!(
        lock_version(&lockfile, "x509-parser").as_deref(),
        Some("0.18.1")
    );
    assert_eq!(
        lock_version(&lockfile, "rustls").as_deref(),
        Some("0.23.42")
    );
    assert_eq!(
        lock_version(&lockfile, "rustls-webpki").as_deref(),
        Some("0.103.13")
    );

    let manifest = read_repo_file("Cargo.toml");
    for marker in [
        "tls = [\"dep:rustls\", \"dep:rustls-pki-types\", \"rustls/ring\", \"dep:rustls-pemfile\", \"dep:x509-parser\"]",
        "atp-cli = [\"dep:clap\", \"tls\", \"dep:rustls-native-certs\"]",
        "rustls = { version = \"0.23.39\", default-features = false, features = [\"std\", \"tls12\"], optional = true }",
        "x509-parser = { version = \"0.18\", optional = true }",
        "required-features = [\"atp-cli\"]",
    ] {
        assert!(
            manifest.contains(marker),
            "manifest ownership marker drifted: {marker}"
        );
    }
}

#[test]
fn authority_artifacts_keep_x509_incumbent_and_cutover_blocked() {
    let registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(capability, "disposition"), "KEEP_UNTIL_PARITY");
    assert_eq!(text(capability, "cutover_state"), "KEEP_INCUMBENT");
    assert_eq!(
        capability
            .get("baseline")
            .and_then(Value::as_object)
            .and_then(|baseline| baseline.get("owner_bead"))
            .and_then(Value::as_str),
        Some(BEAD_ID)
    );

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_row = find_row(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(
        text(baseline_row, "baseline_state"),
        "EXECUTABLE_PARTIAL_BLOCKING"
    );
    assert_eq!(
        baseline_row
            .get("cutover_eligible")
            .and_then(Value::as_bool),
        Some(false)
    );

    let cutover = parse_repo_json(CUTOVER_POLICY_PATH);
    let binding = find_row(
        array(&cutover, "capability_bindings"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(binding, "migration_class"), "SECURITY_SENSITIVE");
    assert_eq!(
        binding
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );

    let api_map = parse_repo_json(API_SURFACE_MAP_PATH);
    let tls_rows: Vec<&Value> = array(&api_map, "root_exports")
        .iter()
        .filter(|row| row.get("name").and_then(Value::as_str) == Some("tls"))
        .collect();
    assert!(
        !tls_rows.is_empty(),
        "root API map must retain the public tls module"
    );
    assert!(
        tls_rows
            .iter()
            .all(|row| row.get("stability").and_then(Value::as_str) == Some("preview")),
        "tls root surface must remain preview in the API map"
    );
}

#[test]
fn marginal_graph_has_the_exact_eight_x509_cells() {
    let inventory = artifact();
    let expected = inventory
        .get("marginal_graph")
        .expect("marginal_graph must be present");
    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    let measurements: Vec<&Value> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| {
            row.get("direct_root_edge").and_then(Value::as_str) == Some("normal:x509-parser")
        })
        .collect();
    assert_eq!(
        measurements.len() as u64,
        expected
            .get("measurement_count")
            .and_then(Value::as_u64)
            .expect("measurement_count must be numeric")
    );
    assert_eq!(measurements.len(), 8);
    assert_eq!(
        measurements
            .iter()
            .map(|row| text(row, "feature_profile").to_owned())
            .collect::<BTreeSet<_>>(),
        string_set(expected, "profiles")
    );
    assert_eq!(
        measurements
            .iter()
            .map(|row| text(row, "target_triple").to_owned())
            .collect::<BTreeSet<_>>(),
        string_set(expected, "targets")
    );
    assert!(
        measurements
            .iter()
            .all(|row| text(row, "unsafe_exposure_class") == "SAFE-OWN")
    );
}

#[test]
fn operator_documentation_covers_paths_residue_gaps_and_no_claims() {
    let document = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        DOC_END,
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "four active production parser call sites",
        "X509-CS-NATIVE-QUIC-PIN-FALLBACK",
        "X509-CS-ATP-CLI-PIN-FALLBACK",
        "only when:",
        "Only `UnknownIssuer`",
        "webpki_server_verifier_with_exact_leaf_fallback",
        "X509-R1-SPKI",
        "X509-R5-ATP-PIN-FALLBACK",
        "X509-GAP-01",
        "X509-GAP-12",
        "A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING",
        "artifacts/x509_der_residue_spec_v1.json",
        "8a619557ce3a8d87833d7e8733ac89a5fe78a1286c7cdb93c9c88bbd37e17274",
        "tls_x509_interop",
        "No local Cargo fallback",
        "does not authorize removing `x509-parser`",
    ] {
        assert!(
            document.contains(marker),
            "operator document missing marker {marker:?}"
        );
    }
}

#[test]
fn mutation_missing_call_site_is_rejected() {
    let mut inventory = artifact();
    inventory
        .get_mut("call_sites")
        .and_then(Value::as_array_mut)
        .expect("call_sites must be mutable")
        .pop();
    assert!(
        validate_inventory_structure(&inventory)
            .expect_err("missing call site must fail")
            .contains("exact five")
    );
}

#[test]
fn mutation_unknown_or_unrouted_gap_is_rejected() {
    let mut inventory = artifact();
    inventory["routed_gaps"][0]["state"] = Value::String("UNKNOWN".to_owned());
    assert!(
        validate_inventory_structure(&inventory)
            .expect_err("UNKNOWN gap must fail")
            .contains("UNKNOWN")
    );

    let mut inventory = artifact();
    inventory["routed_gaps"][0]["state"] = Value::String("ACTIVE".to_owned());
    assert!(
        validate_inventory_structure(&inventory)
            .expect_err("unrouted gap must fail")
            .contains("correctly dispositioned")
    );
}

#[test]
fn mutation_broadened_fallback_or_dependency_exit_is_rejected() {
    let mut inventory = artifact();
    let call_sites = inventory
        .get_mut("call_sites")
        .and_then(Value::as_array_mut)
        .expect("call_sites must be mutable");
    let native = call_sites
        .iter_mut()
        .find(|row| {
            row.get("call_site_id").and_then(Value::as_str)
                == Some("X509-CS-NATIVE-QUIC-PIN-FALLBACK")
        })
        .expect("native fallback row must exist");
    native["custom_verifier_bypass"] = Value::String("all errors".to_owned());
    assert!(
        validate_inventory_structure(&inventory)
            .expect_err("broadened fallback must fail")
            .contains("fallback boundary")
    );

    let mut inventory = artifact();
    inventory["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(
        validate_inventory_structure(&inventory)
            .expect_err("A1 dependency exit must fail")
            .contains("forbid")
    );
}

#[test]
fn mutation_residue_scope_expansion_is_rejected() {
    let mut inventory = artifact();
    inventory["provisional_residue"][0]["forbidden_checks"] = Value::Array(Vec::new());
    assert!(
        validate_inventory_structure(&inventory)
            .expect_err("unbounded residue must fail")
            .contains("unable to build paths")
    );
}
