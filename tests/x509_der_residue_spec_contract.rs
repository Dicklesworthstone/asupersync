//! Fail-closed contract for the X.509 A3 minimal DER residue specification.

#![cfg(feature = "tls")]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/x509_der_residue_spec_v1.json";
const DOC_PATH: &str = "docs/x509_der_residue_spec.md";
const INVENTORY_PATH: &str = "artifacts/x509_validation_ownership_inventory_v1.json";
const EXPECTED_NORMATIVE_PAYLOAD_SHA256: &str =
    "308855e598e0e0d663241b19263aeb2f3bdd1101630b5c8c9018bb8421a8c1de";
const EXPECTED_REVIEWED_DRAFT_SHA256: &str =
    "121b4ad0fc39ecd7085566b9a51219e413b1d09ff0de61ed7c3720b311d6b4d9";
const A1_RECONCILIATION_PATHS: [&str; 3] = [
    "artifacts/x509_validation_ownership_inventory_v1.json",
    "docs/x509_validation_ownership_inventory.md",
    "tests/x509_validation_ownership_inventory_contract.rs",
];
const A1_DERIVED_A2_PATH: &str = "artifacts/x509_standard_verifier_delegation_v1.json";
const REVIEWED_A2_SHA256: &str =
    "f7f3b9773f2f1af7b1a0640c627cd3d7f02d3dcf46c9b3f498f4cb251c06074c";
const ROOT_MANIFEST_PATH: &str = "Cargo.toml";
const REVIEWED_ROOT_MANIFEST_SHA256: &str =
    "10514efc995cfd40db1e52eee55d712cc25852b9320c1c51775d04fe19c17239";
const REVIEWED_ROOT_MANIFEST_LINE_COUNT: u64 = 1_051;

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

fn strings(value: &Value, key: &str) -> BTreeSet<String> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be text"))
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
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .lines()
        .count()
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => output.extend_from_slice(
            serde_json::to_string(string)
                .expect("serializing a JSON string cannot fail")
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonical_json(value, output);
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonical_json(&Value::String(key.clone()), output);
                output.push(b':');
                canonical_json(&object[key], output);
            }
            output.push(b'}');
        }
    }
}

fn normative_projection(value: &Value) -> Result<Value, String> {
    let mut projection = value.clone();
    projection
        .as_object_mut()
        .ok_or_else(|| "artifact root must be an object".to_owned())?
        .remove("review_gate")
        .ok_or_else(|| "review_gate must exist".to_owned())?;
    for source in projection["source_contracts"]
        .as_array_mut()
        .ok_or_else(|| "source_contracts must be an array".to_owned())?
    {
        let source = source
            .as_object_mut()
            .ok_or_else(|| "source contract must be an object".to_owned())?;
        if source["path"]
            .as_str()
            .is_some_and(|path| A1_RECONCILIATION_PATHS.contains(&path))
        {
            source.remove("sha256");
            source.remove("line_count");
        } else if source["path"].as_str() == Some(A1_DERIVED_A2_PATH) {
            // The live A2 packet embeds the mutable A1 content pin. Normalize
            // only that transitive whole-file identity back to the exact A2
            // bytes reviewed for this A3 specification. This keeps routine
            // A1 reconciliation from falsely changing the independently
            // reviewed normative policy while the live source-contract row
            // still fails closed against current repository bytes.
            source.insert(
                "sha256".to_owned(),
                Value::String(REVIEWED_A2_SHA256.to_owned()),
            );
        } else if source["path"].as_str() == Some(ROOT_MANIFEST_PATH) {
            // Package-version and evidence-pin reconciliation changes the root
            // manifest identity without changing this reviewed DER policy.
            // Preserve the reviewed manifest identity in the normative
            // projection while the live source-contract row remains exact.
            source.insert(
                "sha256".to_owned(),
                Value::String(REVIEWED_ROOT_MANIFEST_SHA256.to_owned()),
            );
            source.insert(
                "line_count".to_owned(),
                Value::from(REVIEWED_ROOT_MANIFEST_LINE_COUNT),
            );
        }
    }
    Ok(projection)
}

fn normative_payload_sha256(value: &Value) -> Result<String, String> {
    let projection = normative_projection(value)?;
    let mut bytes = Vec::new();
    canonical_json(&projection, &mut bytes);
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(hex)
}

fn validate_structure(value: &Value) -> Result<(), String> {
    let computed_normative_hash = normative_payload_sha256(value)?;
    let review = object(value, "review_gate");
    if review["candidate_normative_payload_sha256"].as_str()
        != Some(computed_normative_hash.as_str())
        || computed_normative_hash != EXPECTED_NORMATIVE_PAYLOAD_SHA256
    {
        return Err("normative payload hash drifted".to_owned());
    }
    if review["normative_projection"]
        != json!({
            "algorithm": "SHA-256",
            "canonicalization": "compact JSON with object keys sorted lexicographically and array order preserved",
            "excluded_top_level_fields": ["review_gate"],
            "excluded_a1_reconciliation_fields": {
                "paths": [
                    "artifacts/x509_validation_ownership_inventory_v1.json",
                    "docs/x509_validation_ownership_inventory.md",
                    "tests/x509_validation_ownership_inventory_contract.rs"
                ],
                "fields": ["sha256", "line_count"],
                "reason": "A1 records approval only after independent review; excluding only these mutable pins avoids a review-hash cycle while retaining each path and role."
            },
            "normalized_a1_derived_fields": {
                "path": A1_DERIVED_A2_PATH,
                "field": "sha256",
                "reviewed_value": REVIEWED_A2_SHA256,
                "reason": "The live A2 whole-file identity changes when its excluded A1 content pin is reconciled; the A3 normative projection retains the exact A2 identity independently reviewed for this specification."
            },
            "normalized_release_manifest_fields": {
                "path": ROOT_MANIFEST_PATH,
                "fields": ["sha256", "line_count"],
                "reviewed_sha256": REVIEWED_ROOT_MANIFEST_SHA256,
                "reviewed_line_count": REVIEWED_ROOT_MANIFEST_LINE_COUNT,
                "reason": "Package-version and evidence-pin reconciliation changes the live root manifest identity without changing this independently reviewed DER policy."
            }
        })
    {
        return Err("normative projection definition drifted".to_owned());
    }

    if value["schema_version"].as_u64() != Some(1)
        || text(value, "artifact_id") != "x509-der-residue-spec-v1"
        || text(value, "bead_id") != "asupersync-0h6myr.3.3"
        || text(value, "capability_id") != "CAP-TLS-X509"
    {
        return Err("identity fields drifted".to_owned());
    }

    let authority = object(value, "authority");
    if authority["state"].as_str() != Some("SPECIFICATION_ONLY_NO_IMPLEMENTATION")
        || authority["dependency_exit_allowed"].as_bool() != Some(false)
        || authority["manifest_change_allowed"].as_bool() != Some(false)
        || authority["lockfile_change_allowed"].as_bool() != Some(false)
        || authority["cutover_allowed"].as_bool() != Some(false)
        || authority["production_reader_allowed_in_this_bead"].as_bool() != Some(false)
        || authority["next_implementation_owner"].as_str() != Some("asupersync-0h6myr.3.4")
    {
        return Err("A3 authority drifted".to_owned());
    }

    let expected_sources = BTreeSet::from([
        "Cargo.lock".to_owned(),
        "Cargo.toml".to_owned(),
        "artifacts/x509_standard_verifier_delegation_v1.json".to_owned(),
        INVENTORY_PATH.to_owned(),
        "docs/x509_standard_verifier_delegation.md".to_owned(),
        "docs/x509_validation_ownership_inventory.md".to_owned(),
        "src/net/quic_native/handshake_driver.rs".to_owned(),
        "src/tls/acceptor.rs".to_owned(),
        "src/tls/connector.rs".to_owned(),
        "src/tls/types.rs".to_owned(),
        "tests/x509_standard_verifier_delegation_contract.rs".to_owned(),
        "tests/x509_validation_ownership_inventory_contract.rs".to_owned(),
    ]);
    if ids(array(value, "source_contracts"), "path") != expected_sources {
        return Err("source contract path set drifted".to_owned());
    }

    let threat = object(value, "threat_model");
    let channel_ids = ids(
        threat["untrusted_input_channels"]
            .as_array()
            .ok_or_else(|| "untrusted_input_channels must be an array".to_owned())?,
        "channel_id",
    );
    if channel_ids
        != BTreeSet::from([
            "X509-THREAT-PEER-LEAF".to_owned(),
            "X509-THREAT-PIN-INPUT".to_owned(),
            "X509-THREAT-ROOT-BUNDLE".to_owned(),
            "X509-THREAT-SERVER-CHAIN".to_owned(),
        ])
    {
        return Err("untrusted input channel set drifted".to_owned());
    }
    let expected_attacks = BTreeSet::from([
        "X509-ATTACK-AMBIGUOUS-EXTENSIONS".to_owned(),
        "X509-ATTACK-AUTHORITY-CREEP".to_owned(),
        "X509-ATTACK-CRITICAL-BYPASS".to_owned(),
        "X509-ATTACK-DEPTH-COUNT".to_owned(),
        "X509-ATTACK-DIAGNOSTIC-LEAK".to_owned(),
        "X509-ATTACK-LENGTH".to_owned(),
        "X509-ATTACK-TIME-STRING".to_owned(),
        "X509-ATTACK-TRUNCATION-TRAILING".to_owned(),
    ]);
    let attacks = threat["attack_classes"]
        .as_array()
        .ok_or_else(|| "attack_classes must be an array".to_owned())?;
    if ids(attacks, "attack_id") != expected_attacks
        || attacks.iter().any(|attack| {
            attack["vector"].as_str().is_none_or(str::is_empty)
                || attack["required_control"]
                    .as_str()
                    .is_none_or(str::is_empty)
        })
    {
        return Err("threat controls are incomplete".to_owned());
    }

    let api = object(value, "api_contract");
    if api["visibility"].as_str() != Some("crate-private until A6 migration proves a public need")
        || api["input"].as_str()
            != Some("one complete certificate DER byte slice and one compile-time profile")
    {
        return Err("API visibility or input authority drifted".to_owned());
    }
    let expected_ambient = BTreeSet::from([
        "certificate chain".to_owned(),
        "current time".to_owned(),
        "filesystem access".to_owned(),
        "global configuration".to_owned(),
        "network access".to_owned(),
        "revocation policy".to_owned(),
        "server name".to_owned(),
        "signature algorithms".to_owned(),
        "trust store".to_owned(),
    ]);
    if strings(&Value::Object(api.clone()), "ambient_inputs_forbidden") != expected_ambient {
        return Err("ambient input prohibition drifted".to_owned());
    }
    let expected_forbidden = BTreeSet::from([
        "algorithm strength or negotiation policy".to_owned(),
        "certificate signature verification".to_owned(),
        "certificate-policy evaluation".to_owned(),
        "chain construction".to_owned(),
        "hostname or IP matching".to_owned(),
        "name-constraint evaluation".to_owned(),
        "revocation or OCSP decisions".to_owned(),
        "TLS handshake signature verification".to_owned(),
        "trust-anchor selection or validation".to_owned(),
        "wildcard interpretation".to_owned(),
    ]);
    if strings(&Value::Object(api.clone()), "forbidden_capabilities") != expected_forbidden {
        return Err("forbidden capability set drifted".to_owned());
    }
    let shape = api["implementation_shape"]
        .as_object()
        .ok_or_else(|| "implementation_shape must be an object".to_owned())?;
    for key in [
        "unsafe_code",
        "recursion",
        "panics_on_input",
        "unchecked_arithmetic",
    ] {
        if shape[key].as_bool() != Some(false) {
            return Err(format!("{key} must remain false"));
        }
    }
    if shape["borrow_selected_der"].as_bool() != Some(true) {
        return Err("selected DER must remain borrowed".to_owned());
    }

    validate_profiles(value)?;
    validate_limits(value)?;
    validate_canonicality_and_errors(value)?;

    let extension = object(value, "extension_policy");
    if Value::Object(extension.clone())
        != json!({
            "duplicate_extension_oids": "REJECT_FOR_ALL_PROFILES",
            "duplicate_eku_purposes": "REJECT_FOR_PINNED_LEAF_PROFILE",
            "unknown_noncritical_extensions": "OPAQUE_AND_IGNORED_AFTER_BOUNDED_OUTER_EXTENSION_PARSE",
            "unknown_critical_spki_root_acceptor_profiles": "NOT_INTERPRETED; no critical-extension acceptance claim; the downstream owner remains responsible",
            "unknown_critical_pinned_leaf_profile": "REJECT",
            "critical_default": "critical FALSE must be omitted; explicit FALSE is noncanonical DER and rejected",
            "selected_extension_full_consumption": true,
            "selected_extension_contracts": {
                "basic_constraints": "SEQUENCE with optional cA BOOLEAN DEFAULT FALSE followed by optional nonnegative minimal pathLenConstraint INTEGER; explicit cA FALSE is rejected, pathLenConstraint requires cA TRUE, and the sequence is fully consumed.",
                "key_usage": "One fully consumed BIT STRING in DER NamedBitList form; at least one named bit is set, all trailing zero bits are removed, no set bit exceeds bit 8, and digitalSignature bit 0 is returned as a fact.",
                "extended_key_usage": "A fully consumed nonempty SEQUENCE of unique, canonical, bounded OIDs; serverAuth 1.3.6.1.5.5.7.3.1 presence is returned as a fact.",
                "subject_alt_name": "A fully consumed nonempty GeneralNames SEQUENCE. dNSName is primitive context tag 2 with 1 through 253 IA5 ASCII bytes; A3 performs no DNS-label grammar or normalization. iPAddress is primitive context tag 7 with exactly 4 or 16 octets. In a noncritical SAN, every other GeneralName choice must have canonical outer context-specific TLV framing and bounded content but constructed contents remain opaque and carry no nested-DER canonicality claim. Any unsupported choice in a critical SAN is X509-DER-UNKNOWN-CRITICAL."
            }
        })
    {
        return Err("duplicate or critical-extension policy drifted".to_owned());
    }

    let time = object(value, "time_policy");
    for key in [
        "utc_time",
        "generalized_time",
        "tag_choice",
        "calendar",
        "output",
        "ordering",
    ] {
        if time[key].as_str().is_none_or(str::is_empty) {
            return Err(format!("time policy {key} missing"));
        }
    }
    let string = object(value, "string_policy");
    if strings(&Value::Object(string.clone()), "selected_subject_oids")
        != BTreeSet::from([
            "2.5.4.10".to_owned(),
            "2.5.4.11".to_owned(),
            "2.5.4.3".to_owned(),
        ])
        || string["presence_rule"]
            .as_str()
            .is_none_or(|rule| !rule.contains("nonempty canonical"))
        || strings(
            &Value::Object(string.clone()),
            "accepted_directory_string_tags",
        ) != BTreeSet::from([
            "BMPString".to_owned(),
            "PrintableString".to_owned(),
            "UTF8String".to_owned(),
            "UniversalString".to_owned(),
        ])
        || array(&Value::Object(string.clone()), "validation").len() != 4
        || array(&Value::Object(string.clone()), "forbidden_operations").len() != 5
        || string["teletex_policy"].as_str().is_none_or(|policy| {
            !policy.contains("max_directory_string_bytes")
                || !policy.contains("SubjectIdentityPresence=false")
                || !policy.contains("does not emit X509-DER-STRING")
        })
    {
        return Err("DirectoryString policy drifted".to_owned());
    }

    if array(value, "test_obligations").len() != 14
        || array(value, "rollback_triggers").len() != 8
        || array(value, "no_claim_boundaries").len() != 8
    {
        return Err("test, rollback, or no-claim boundary set is incomplete".to_owned());
    }
    if value["downstream_handoff"]["implementation_owner"].as_str() != Some("asupersync-0h6myr.3.4")
        || value["downstream_handoff"]["cutover_owner"].as_str() != Some("asupersync-0h6myr.3.9")
    {
        return Err("downstream handoff drifted".to_owned());
    }

    Ok(())
}

fn validate_profiles(value: &Value) -> Result<(), String> {
    let profiles = array(value, "profiles");
    let expected = json!([
        {
            "profile_id": "X509-PROFILE-SPKI",
            "residue_id": "X509-R1-SPKI",
            "planned_function": "extract_spki_der",
            "outputs": ["SpkiDerSlice"],
            "selected_fields": [
                "Certificate.tbsCertificate.subjectPublicKeyInfo complete encoded TLV"
            ],
            "caller_owned_policy": "SHA-256 hashing and pin comparison",
            "unknown_critical_behavior":
                "NOT_INTERPRETED; standard verifier or caller remains authoritative",
            "duplicate_extension_behavior": "REJECT_ANY_DUPLICATE_EXTENSION_OID",
            "forbidden_inputs": ["server name", "roots", "intermediates", "clock"]
        },
        {
            "profile_id": "X509-PROFILE-ROOT-CA",
            "residue_id": "X509-R2-CA-ADMISSION",
            "planned_function": "inspect_basic_constraints_ca",
            "outputs": ["BasicConstraintsFact::{Absent,Present{ca}}"],
            "selected_fields": [
                "BasicConstraints extension presence and cA DEFAULT false fact when present"
            ],
            "caller_owned_policy":
                "require extension presence and ca=true before insertion; preserve existing diagnostics",
            "unknown_critical_behavior":
                "NOT_REJECTED_BY_READER; no critical-extension acceptance claim; the downstream trust-anchor owner remains responsible",
            "duplicate_extension_behavior": "REJECT_ANY_DUPLICATE_EXTENSION_OID",
            "forbidden_inputs": ["trust store", "chain", "server name", "clock"]
        },
        {
            "profile_id": "X509-PROFILE-ACCEPTOR-PREFLIGHT",
            "residue_id": "X509-R3-ACCEPTOR-PREFLIGHT",
            "planned_function": "inspect_server_chain_metadata",
            "outputs": ["ValidityWindowUnixSeconds", "SubjectIdentityPresence"],
            "selected_fields": [
                "notBefore",
                "notAfter",
                "presence of nonempty CN, OU, or O DirectoryString"
            ],
            "caller_owned_policy":
                "current-time comparison, chain index diagnostics, and strict-mode enablement",
            "unknown_critical_behavior":
                "NOT_REJECTED_BY_READER; remote standard verifiers own extension semantics",
            "duplicate_extension_behavior": "REJECT_ANY_DUPLICATE_EXTENSION_OID",
            "forbidden_inputs": ["clock", "roots", "server name", "signature algorithms"]
        },
        {
            "profile_id": "X509-PROFILE-PINNED-LEAF",
            "residue_id": "X509-R4-NATIVE-PIN-FALLBACK",
            "planned_function": "inspect_pinned_leaf_shape",
            "outputs": [
                "ValidityWindowUnixSeconds",
                "ExtendedKeyUsageFact::{Absent,Present{server_auth}}",
                "KeyUsageFact::{Absent,Present{digital_signature}}",
                "SubjectAltNameFact::{Absent,Present{dns_names,ip_addresses}}"
            ],
            "selected_fields": [
                "notBefore",
                "notAfter",
                "ExtendedKeyUsage extension presence and serverAuth purpose presence when present",
                "KeyUsage extension presence and digitalSignature bit when present",
                "SubjectAltName extension presence plus bounded DNS and IP entries when present"
            ],
            "caller_owned_policy":
                "require EKU presence with serverAuth, reject present KU without digitalSignature, require SAN presence and exact case-insensitive DNS or exact IP match, and compare current time after the A2 UnknownIssuer plus exact-leaf gate",
            "unknown_critical_behavior":
                "REJECT_UNLESS_OID_IS_IN_PIN_PROFILE_UNDERSTOOD_CRITICAL_ALLOW_SET",
            "understood_critical_extension_oids": ["2.5.29.15", "2.5.29.17", "2.5.29.37"],
            "duplicate_extension_behavior": "REJECT_ANY_DUPLICATE_EXTENSION_OID",
            "forbidden_inputs": ["clock", "server name", "roots", "intermediates", "signatures"]
        }
    ]);
    if profiles != expected.as_array().expect("expected profiles are an array") {
        return Err("exact profile contract drifted".to_owned());
    }

    Ok(())
}

fn validate_limits(value: &Value) -> Result<(), String> {
    let limits = object(value, "resource_limits");
    let expected = BTreeMap::from([
        ("max_bit_string_content_bytes", 262_144),
        ("max_certificate_der_bytes", 1_048_576),
        ("max_directory_string_bytes", 4_096),
        ("max_dns_san_bytes", 253),
        ("max_eku_purpose_count", 64),
        ("max_extension_count", 64),
        ("max_extension_value_bytes", 262_144),
        ("max_integer_content_bytes", 262_144),
        ("max_oid_content_bytes", 64),
        ("max_san_entry_count", 128),
        ("max_spki_der_bytes", 262_144),
        ("max_subject_attributes", 256),
        ("max_subject_rdns", 128),
        ("max_tlv_depth", 16),
        ("max_tlv_nodes", 4_096),
    ]);
    if limits.len() != expected.len() {
        return Err("resource limit key set drifted".to_owned());
    }
    for (key, expected_value) in expected {
        if limits[key].as_u64() != Some(expected_value) {
            return Err(format!("resource limit {key} drifted"));
        }
    }
    if value["resource_accounting"]
        != json!({
            "depth": "The outer Certificate TLV is depth 1. Every entered constructed child increments depth by one. A selected extension's inner root TLV is one deeper than its extnValue OCTET STRING, and all entered inner constructed TLVs count.",
            "nodes": "The outer Certificate TLV is node 1. Every successfully decoded outer or selected-extension inner TLV header increments the node count exactly once, including primitive TLVs and the extnValue OCTET STRING.",
            "traversal_frontier": {
                "entered_outer_schema": "Certificate and TBSCertificate; explicit version and INTEGER; both signature AlgorithmIdentifier SEQUENCE values and their algorithm OIDs; Certificate signatureValue BIT STRING; issuer and subject Name/RDN/AttributeTypeAndValue; validity and both time values; SubjectPublicKeyInfo, its AlgorithmIdentifier, and subjectPublicKey BIT STRING; issuerUniqueID and subjectUniqueID BIT STRING headers; Extensions wrapper/sequence, every Extension row, extnID, critical, and extnValue.",
                "opaque_outer_values": "AlgorithmIdentifier parameters and unselected AttributeTypeAndValue values are each counted as one bounded complete TLV but their constructed contents are not entered.",
                "entered_selected_values": "Supported DirectoryString values and, when selected by the active profile, the complete BasicConstraints, KeyUsage, ExtendedKeyUsage, and SubjectAltName inner grammars.",
                "opaque_general_names": "In a noncritical SAN, unsupported GeneralName alternatives are counted as one bounded context-specific TLV and their constructed contents are not entered; in a critical SAN they are rejected before exposure.",
                "test_only_parser_frontier": "A4 may exercise the private TLV reader directly with bounded schema-independent TLV fixtures for max_tlv_depth and max_tlv_nodes; this grants no production generic-reader API."
            },
            "enforcement": "Certificate size is checked before traversal. Every remaining resource limit is checked before the corresponding slice, allocation, collection insertion, or child entry.",
            "value_limit_scope": "OID, INTEGER, and BIT STRING limits apply to every entered outer mandatory field and selected inner value. max_subject_rdns and max_subject_attributes apply to the subject Name only; issuer Name is structurally traversed but its collections are not retained.",
            "derived_invariants": "Any accepted canonical value under max_certificate_der_bytes uses at most three length octets; a nonminimal longer encoding is X509-DER-NONMINIMAL-LENGTH and a minimal declaration beyond the bounded input is X509-DER-BOUNDS or X509-DER-UNEXPECTED-EOF. IP SAN length is a semantic domain of exactly 4 or 16 octets, not a monotonic resource limit.",
            "boundary_evidence": "Certificate size uses well-formed N-1 and N inputs plus an N+1 input rejected before traversal. Private TLV-reader depth and node ceilings use isolated bounded N-1, N, and N+1 fixtures. Every other monotonic resource limit uses profile-valid N-1 and N fixtures plus an N+1 exact limit error. IP SAN uses accepted 4/16-octet cases and semantic rejection of every other length; length-octet behavior uses canonical short/long, nonminimal, overflow, bounds, and EOF fixtures rather than a fictitious monotonic limit."
        })
    {
        return Err("resource accounting drifted".to_owned());
    }
    Ok(())
}

fn validate_canonicality_and_errors(value: &Value) -> Result<(), String> {
    let rules = array(value, "canonicality_rules");
    let expected_rules = [
        (
            "X509-DER-CANON-01",
            "Input is one nonempty complete Certificate SEQUENCE and no trailing byte remains.",
            "X509-DER-EMPTY-OR-TRAILING",
        ),
        (
            "X509-DER-CANON-02",
            "Only DER definite lengths are accepted; BER/CER indefinite length is rejected.",
            "X509-DER-INDEFINITE-LENGTH",
        ),
        (
            "X509-DER-CANON-03",
            "Length uses short form for values through 127 and the shortest nonzero long form otherwise.",
            "X509-DER-NONMINIMAL-LENGTH",
        ),
        (
            "X509-DER-CANON-04",
            "Every offset plus header or content length uses checked arithmetic and stays within the containing TLV and input.",
            "X509-DER-BOUNDS",
        ),
        (
            "X509-DER-CANON-05",
            "High-tag-number form is rejected; every traversed schema tag has the required class, number, and constructed bit.",
            "X509-DER-TAG",
        ),
        (
            "X509-DER-CANON-06",
            "SEQUENCE and SET are constructed; BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OID, and selected strings/times are primitive.",
            "X509-DER-CONSTRUCTED-BIT",
        ),
        (
            "X509-DER-CANON-07",
            "BOOLEAN content is exactly one octet and is 00 for false or FF for true.",
            "X509-DER-BOOLEAN",
        ),
        (
            "X509-DER-CANON-08",
            "INTEGER content is nonempty and has no redundant sign octet.",
            "X509-DER-INTEGER",
        ),
        (
            "X509-DER-CANON-09",
            "BIT STRING content contains at least the unused-bit-count octet, its count is 0 through 7, and every declared unused bit is zero; KeyUsage additionally uses DER NamedBitList form with all trailing zero bits removed, no set bit above bit 8, and at least one named bit set.",
            "X509-DER-BIT-STRING",
        ),
        (
            "X509-DER-CANON-10",
            "NULL content length is zero.",
            "X509-DER-NULL",
        ),
        (
            "X509-DER-CANON-11",
            "OID subidentifiers use minimal terminating base-128 form, do not overflow u64, and stay within the OID byte limit.",
            "X509-DER-OID",
        ),
        (
            "X509-DER-CANON-12",
            "Every SET OF traversed by the schema is ordered lexicographically by complete encoded child TLV bytes.",
            "X509-DER-SET-ORDER",
        ),
        (
            "X509-DER-CANON-13",
            "Explicit DEFAULT values are rejected for every entered value: v1 Certificate version and Extension critical FALSE globally, plus BasicConstraints cA FALSE whenever that selected extension grammar is entered.",
            "X509-DER-EXPLICIT-DEFAULT",
        ),
        (
            "X509-DER-CANON-14",
            "Every mandatory Certificate and TBSCertificate field appears once in schema order; optional context tags appear at most once and in order.",
            "X509-DER-SCHEMA",
        ),
        (
            "X509-DER-CANON-15",
            "Every Extension SEQUENCE is extnID, optional critical BOOLEAN, and extnValue OCTET STRING with full Extension consumption.",
            "X509-DER-EXTENSION-SHAPE",
        ),
        (
            "X509-DER-CANON-16",
            "Every extension OID occurs at most once, independent of profile.",
            "X509-DER-DUPLICATE-EXTENSION",
        ),
        (
            "X509-DER-CANON-17",
            "Every selected extension value is fully consumed and satisfies its exact selected_extension_contracts entry for BasicConstraints, KeyUsage, ExtendedKeyUsage, or SubjectAltName.",
            "X509-DER-SELECTED-EXTENSION",
        ),
        (
            "X509-DER-CANON-18",
            "Under X509-PROFILE-PINNED-LEAF, no ExtendedKeyUsage purpose OID repeats; CANON-17 separately requires the sequence to be nonempty.",
            "X509-DER-DUPLICATE-EKU",
        ),
    ];
    if rules.len() != expected_rules.len()
        || rules
            .iter()
            .zip(expected_rules)
            .any(|(actual, (rule_id, requirement, error_code))| {
                actual
                    != &json!({
                        "rule_id": rule_id,
                        "requirement": requirement,
                        "error_code": error_code,
                        "testable": true
                    })
            })
    {
        return Err("exact canonicality rule set drifted".to_owned());
    }

    let error_shape = object(value, "error_shape");
    if Value::Object(error_shape.clone())
        != json!({
            "class": "closed enum containing exactly the thirty error_taxonomy codes",
            "offset": "absolute zero-based byte position in the original certificate input, checked and no greater than input length; offset zero is valid for X509-DER-EMPTY-OR-TRAILING on empty input, and otherwise one-past-end input length is permitted only for X509-DER-UNEXPECTED-EOF",
            "numeric_detail": "optional fixed-shape u64 observed and limit values, each bounded by max_certificate_der_bytes; no strings or attacker-selected field names",
            "raw_peer_bytes": false,
            "raw_peer_text": false,
            "raw_oid_text": false,
            "cryptographic_detail": false
        })
    {
        return Err("stable error shape drifted".to_owned());
    }
    let errors = array(value, "error_taxonomy");
    let expected_errors = BTreeMap::from([
        (
            "X509-DER-BIT-STRING",
            "BIT STRING content missing, unused bit count invalid, unused bit nonzero, or KeyUsage NamedBitList nonminimal, empty, or above bit 8",
        ),
        (
            "X509-DER-BOOLEAN",
            "BOOLEAN length or canonical value invalid",
        ),
        ("X509-DER-BOUNDS", "child exceeds parent or input bounds"),
        (
            "X509-DER-CERTIFICATE-LIMIT",
            "certificate exceeds max_certificate_der_bytes",
        ),
        (
            "X509-DER-CONSTRUCTED-BIT",
            "known tag has wrong primitive or constructed form",
        ),
        (
            "X509-DER-COUNT-LIMIT",
            "extensions, subject RDNs, subject attributes, EKUs, or SAN entries exceed their hard limit",
        ),
        ("X509-DER-DEPTH-LIMIT", "traversal exceeds max_tlv_depth"),
        (
            "X509-DER-DUPLICATE-EKU",
            "ExtendedKeyUsage repeats a purpose OID",
        ),
        (
            "X509-DER-DUPLICATE-EXTENSION",
            "two Extension rows carry the same extnID",
        ),
        (
            "X509-DER-EMPTY-OR-TRAILING",
            "empty input or byte remaining after outer Certificate",
        ),
        (
            "X509-DER-EXPLICIT-DEFAULT",
            "DER DEFAULT value is explicitly encoded",
        ),
        (
            "X509-DER-EXTENSION-SHAPE",
            "Extension fields malformed, reordered, repeated, or not fully consumed",
        ),
        ("X509-DER-INDEFINITE-LENGTH", "length octet 80"),
        (
            "X509-DER-INTEGER",
            "INTEGER empty or redundantly sign-extended",
        ),
        (
            "X509-DER-LENGTH-OVERFLOW",
            "length or checked offset arithmetic overflows",
        ),
        (
            "X509-DER-MISSING-SELECTED-FIELD",
            "profile-mandatory SPKI or validity field absent; optional BasicConstraints, EKU, KU, and SAN absence is returned as a fact",
        ),
        ("X509-DER-NODE-LIMIT", "traversal exceeds max_tlv_nodes"),
        (
            "X509-DER-NONMINIMAL-LENGTH",
            "long form for value through 127, leading zero length octet, or more length octets than the shortest encoding",
        ),
        ("X509-DER-NULL", "NULL has content"),
        (
            "X509-DER-OID",
            "OID is empty, unterminated, nonminimal, overflowing, or over limit",
        ),
        (
            "X509-DER-SCHEMA",
            "mandatory field missing, repeated, reordered, or unexpected",
        ),
        (
            "X509-DER-SELECTED-EXTENSION",
            "selected extension violates its exact BasicConstraints, KeyUsage, ExtendedKeyUsage, or SubjectAltName inner contract or has trailing content",
        ),
        (
            "X509-DER-SET-ORDER",
            "SET OF children are not ordered by encoded bytes",
        ),
        (
            "X509-DER-STRING",
            "selected supported UTF8String, PrintableString, BMPString, or UniversalString encoding invalid; bounded TeletexString is an unsupported absence fact, not this error",
        ),
        (
            "X509-DER-TAG",
            "high-tag form or unexpected class or tag number",
        ),
        (
            "X509-DER-TIME",
            "time tag, width, digits, Z suffix, calendar, or Unix conversion invalid",
        ),
        (
            "X509-DER-UNEXPECTED-EOF",
            "header or content ends outside its containing TLV",
        ),
        (
            "X509-DER-UNKNOWN-CRITICAL",
            "pinned-leaf profile sees a critical OID outside its understood allow-set or an allow-listed critical extension containing unsupported semantics",
        ),
        (
            "X509-DER-VALIDITY-ORDER",
            "notBefore is greater than notAfter",
        ),
        (
            "X509-DER-VALUE-LIMIT",
            "entered OID, INTEGER, BIT STRING, SPKI, extension value, supported DirectoryString, or DNS SAN exceeds its hard limit",
        ),
    ]);
    let actual_errors: BTreeMap<_, _> = errors
        .iter()
        .map(|error| (text(error, "code"), text(error, "trigger")))
        .collect();
    if actual_errors != expected_errors {
        return Err("exact thirty-class error taxonomy drifted".to_owned());
    }

    Ok(())
}

fn validate_review(value: &Value) -> Result<(), String> {
    let review = object(value, "review_gate");
    if review["required"].as_bool() != Some(true)
        || review["state"].as_str() != Some("APPROVED")
        || review["implementation_may_begin"].as_bool() != Some(true)
    {
        return Err("independent review is not approved".to_owned());
    }
    let author = review["author"]
        .as_str()
        .ok_or_else(|| "author must be recorded".to_owned())?;
    let reviewer = review["reviewer"]
        .as_str()
        .ok_or_else(|| "reviewer must be recorded".to_owned())?;
    let receipt_reviewer = review["review_receipt"]["agent_task"]
        .as_str()
        .ok_or_else(|| "review receipt agent_task must be recorded".to_owned())?;
    if author != "GreenCove"
        || reviewer != "/root/x509_final_registry_review"
        || reviewer != receipt_reviewer
        || reviewer == author
    {
        return Err("reviewer must be independent".to_owned());
    }
    let computed_normative_hash = normative_payload_sha256(value)?;
    if review["review_channel"].as_str() != Some("collaboration_agent")
        || review["review_receipt"]
            != json!({
                "agent_task": "/root/x509_final_registry_review",
                "decision": "APPROVE",
                "reviewed_normative_payload_sha256": EXPECTED_NORMATIVE_PAYLOAD_SHA256
            })
        || review["reviewed_draft_sha256"].as_str() != Some(EXPECTED_REVIEWED_DRAFT_SHA256)
        || !is_lower_hex_sha256(EXPECTED_REVIEWED_DRAFT_SHA256)
        || review["reviewed_normative_payload_sha256"].as_str()
            != Some(EXPECTED_NORMATIVE_PAYLOAD_SHA256)
        || review["candidate_normative_payload_sha256"].as_str()
            != Some(EXPECTED_NORMATIVE_PAYLOAD_SHA256)
        || computed_normative_hash != EXPECTED_NORMATIVE_PAYLOAD_SHA256
    {
        return Err("review evidence is incomplete".to_owned());
    }
    Ok(())
}

#[test]
fn canonical_spec_is_structurally_valid() {
    let artifact = parse(ARTIFACT_PATH);
    validate_structure(&artifact).expect("canonical A3 structure");
}

#[test]
fn independent_review_gate_is_approved() {
    let artifact = parse(ARTIFACT_PATH);
    validate_review(&artifact).expect("canonical A3 review gate");
}

#[test]
fn source_contract_hashes_and_lengths_are_exact() {
    let artifact = parse(ARTIFACT_PATH);
    for contract in array(&artifact, "source_contracts") {
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
fn inventory_residue_and_gap_state_reconcile_with_a3() {
    let inventory = parse(INVENTORY_PATH);
    assert_eq!(
        inventory["authority"]["residue_status"].as_str(),
        Some("A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING")
    );
    let residues = array(&inventory, "provisional_residue");
    for residue_id in [
        "X509-R1-SPKI",
        "X509-R2-CA-ADMISSION",
        "X509-R3-ACCEPTOR-PREFLIGHT",
        "X509-R4-NATIVE-PIN-FALLBACK",
    ] {
        assert_eq!(
            row(residues, "residue_id", residue_id)["state"].as_str(),
            Some("A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING"),
            "{residue_id} state drifted"
        );
    }
    assert_eq!(
        row(residues, "residue_id", "X509-R5-ATP-PIN-FALLBACK")["state"].as_str(),
        Some("RESOLVED_BY_A2_DELEGATION_TO_X509-R4")
    );
    let gap = row(array(&inventory, "routed_gaps"), "gap_id", "X509-GAP-01");
    assert_eq!(
        gap["state"].as_str(),
        Some("A3_SPEC_APPROVED_A4_IMPLEMENTATION_PENDING")
    );
    assert_eq!(
        inventory["der_residue_spec_contract"]["artifact"].as_str(),
        Some(ARTIFACT_PATH)
    );
    assert_eq!(
        inventory["der_residue_spec_contract"]["state"].as_str(),
        Some("APPROVED")
    );
}

#[test]
fn operator_documentation_covers_authority_limits_rules_review_and_no_claims() {
    let document = read(DOC_PATH);
    for marker in [
        "X509_DER_RESIDUE_SPEC_BEGIN",
        "X509_DER_RESIDUE_SPEC_END",
        "SPECIFICATION_ONLY_NO_IMPLEMENTATION",
        "X509-PROFILE-SPKI",
        "X509-PROFILE-ROOT-CA",
        "X509-PROFILE-ACCEPTOR-PREFLIGHT",
        "X509-PROFILE-PINNED-LEAF",
        "1,048,576 bytes",
        "eighteen individually testable rules",
        "X509-DER-*",
        "review_gate.state = APPROVED",
        "implementation_may_begin = true",
        "No-claim boundary",
        "does not implement or prove a reader",
        "Only A9 may decide a dependency cutover",
    ] {
        assert!(document.contains(marker), "operator doc missing {marker:?}");
    }
}

#[test]
fn mutations_fail_closed() {
    let canonical = parse(ARTIFACT_PATH);

    let mut pending_review = canonical.clone();
    pending_review["review_gate"]["state"] = Value::String("PENDING".to_owned());
    pending_review["review_gate"]["implementation_may_begin"] = Value::Bool(false);
    assert!(validate_review(&pending_review).is_err());

    let mut self_review = canonical.clone();
    let author = self_review["review_gate"]["author"].clone();
    self_review["review_gate"]["reviewer"] = author;
    assert!(validate_review(&self_review).is_err());

    let mut rewritten_identities = canonical.clone();
    rewritten_identities["review_gate"]["author"] = Value::String("OtherAuthor".to_owned());
    rewritten_identities["review_gate"]["reviewer"] = Value::String("OtherReviewer".to_owned());
    rewritten_identities["review_gate"]["review_receipt"]["agent_task"] =
        Value::String("OtherReviewer".to_owned());
    assert!(validate_review(&rewritten_identities).is_err());

    let mut receipt_mismatch = canonical.clone();
    receipt_mismatch["review_gate"]["reviewer"] =
        Value::String("/root/different_reviewer".to_owned());
    assert!(validate_review(&receipt_mismatch).is_err());

    let mut review_hash_drift = canonical.clone();
    review_hash_drift["review_gate"]["reviewed_normative_payload_sha256"] =
        Value::String("0".repeat(64));
    assert!(validate_review(&review_hash_drift).is_err());

    let mut ambient_clock = canonical.clone();
    ambient_clock["api_contract"]["ambient_inputs_forbidden"]
        .as_array_mut()
        .expect("ambient inputs")
        .retain(|entry| entry.as_str() != Some("current time"));
    assert!(validate_structure(&ambient_clock).is_err());

    let mut unlimited = canonical.clone();
    unlimited["resource_limits"]["max_tlv_depth"] = Value::Number(0.into());
    assert!(validate_structure(&unlimited).is_err());

    let mut missing_rule = canonical.clone();
    missing_rule["canonicality_rules"]
        .as_array_mut()
        .expect("rules")
        .pop();
    assert!(validate_structure(&missing_rule).is_err());

    let mut permissive_critical = canonical.clone();
    permissive_critical["extension_policy"]["unknown_critical_pinned_leaf_profile"] =
        Value::String("ACCEPT".to_owned());
    assert!(validate_structure(&permissive_critical).is_err());

    let mut duplicate_extensions = canonical.clone();
    duplicate_extensions["extension_policy"]["duplicate_extension_oids"] =
        Value::String("ACCEPT".to_owned());
    assert!(validate_structure(&duplicate_extensions).is_err());

    let mut renamed_error = canonical.clone();
    renamed_error["error_taxonomy"][0]["code"] = Value::String("X509-DER-RENAMED".to_owned());
    assert!(validate_structure(&renamed_error).is_err());

    let mut raw_text = canonical.clone();
    raw_text["error_shape"]["raw_peer_text"] = Value::Bool(true);
    assert!(validate_structure(&raw_text).is_err());

    let mut offset_drift = canonical.clone();
    offset_drift["error_shape"]["offset"] = Value::String("relative unchecked offset".to_owned());
    assert!(validate_structure(&offset_drift).is_err());

    let mut hidden_absence = canonical.clone();
    hidden_absence["profiles"][1]["outputs"] = json!(["BasicConstraintsCaFlag"]);
    assert!(validate_structure(&hidden_absence).is_err());

    let mut broadened_pin = canonical;
    broadened_pin["profiles"]
        .as_array_mut()
        .expect("profiles")
        .iter_mut()
        .find(|profile| profile["profile_id"].as_str() == Some("X509-PROFILE-PINNED-LEAF"))
        .expect("pin profile")["understood_critical_extension_oids"]
        .as_array_mut()
        .expect("critical allow-set")
        .push(Value::String("2.5.29.30".to_owned()));
    assert!(validate_structure(&broadened_pin).is_err());
}
