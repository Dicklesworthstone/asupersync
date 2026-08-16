//! Fail-closed typed-format inventory contract.
//!
//! Bead: asupersync-5z2scg.3.1
//! Capabilities: CAP-PERSISTED-TRACE-SNAPSHOT, CAP-SERDE-GENERIC
//! Fixture: artifacts/typed_format_registry_v1.json
//!
//! This lane reconciles the A1 evidence registry with the accepted ADR, Cargo
//! pins, direct lexical call-site inventory, public/generic source contract,
//! persisted source owners, corpus aggregates, and human documentation.
//!
//! It proves no serialization round trip, historical migration, fuzz result,
//! broad workspace health, dependency removal, format removal, or cutover.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/typed_format_registry_v1.json";
const DOC_PATH: &str = "docs/typed_format_registry.md";
const SNAPSHOT_DOC_PATH: &str = "docs/runtime_snapshot_codec.md";
const DECISION_REGISTRY_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";
const DECISION_DOC_PATH: &str = "docs/adr/dep_plan_adr_001_serde_generic_formats.md";
const DECISION_ID: &str = "DEP-ADR-001";
const BEAD_ID: &str = "asupersync-5z2scg.3.1";
const A6_BEAD_ID: &str = "asupersync-5z2scg.3.6";
const A7_BEAD_ID: &str = "asupersync-5z2scg.3.7";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CONSUMER_MANIFEST_PATH: &str =
    "tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml";
const CONSUMER_LOCK_PATH: &str =
    "tests/fixtures/dependency-capability-baseline-consumer/Cargo.lock";
const CONSUMER_SOURCE_PATH: &str =
    "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs";
const HISTORICAL_CONSUMER_MANIFEST_PATH: &str =
    "tests/fixtures/typed-format-cross-version-consumer/Cargo.toml";
const HISTORICAL_CONSUMER_LOCK_PATH: &str =
    "tests/fixtures/typed-format-cross-version-consumer/Cargo.lock";
const HISTORICAL_CONSUMER_SOURCE_PATH: &str =
    "tests/fixtures/typed-format-cross-version-consumer/src/lib.rs";
const HISTORICAL_CORPUS_PATH: &str = "tests/fixtures/typed-format-historical-corpus/v0.3.9.json";
const HISTORICAL_E2E_PATH: &str = "tests/typed_format_cross_version_e2e.rs";
const V039_COMMIT: &str = "e7e0af2fe0fc5037a087296e22e5eb57a2c1d50a";
const V039_CRATE_CHECKSUM: &str =
    "1cbadf37dce3015a059ffe058804d958026e8b276d665116015e3126d2673cfe";
const MESSAGEPACK_GOLDEN: &str = "95cfffffffffffffffff81a7426f756e646564cfffffffffffffffff82a0a0a7756e69636f6465ac4772c3bcc39f6520f09fa6809600017fcc80ccfeccffd38000000000000000";
const BINCODE_GOLDEN: &str = "ffffffffffffffff02000000ffffffffffffffff0200000000000000000000000000000000000000000000000700000000000000756e69636f64650c000000000000004772c3bcc39f6520f09fa680060000000000000000017f80feff010000000000000080";
const EXPECTED_ROOT_COUNT: usize = 13;
const EXPECTED_FORMAT_COUNT: usize = 4;
const EXPECTED_PERSISTED_SURFACE_COUNT: usize = 13;

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
    serde_json::from_slice(&read_repo_bytes(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn registry() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
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

fn nonempty_text(value: &Value, key: &str) -> Result<(), String> {
    let Some(candidate) = value.get(key).and_then(Value::as_str) else {
        return Err(format!("{key} must be a string"));
    };
    if candidate.trim().is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    Ok(())
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

fn find_by_id<'a>(rows: &'a [Value], key: &str, id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing {key}={id}"))
}

fn find_by_id_mut<'a>(rows: &'a mut [Value], key: &str, id: &str) -> &'a mut Value {
    rows.iter_mut()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing {key}={id}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex length must be even");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex must be ASCII");
            u8::from_str_radix(pair, 16).expect("hex byte")
        })
        .collect()
}

fn visit_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("failed to read entry in {}: {error}", dir.display()));
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to stat {}: {error}", path.display()));
        if file_type.is_dir() {
            visit_files(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

fn repo_relative(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or_else(|error| panic!("{} must be below repository root: {error}", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
}

fn files_below(root: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit_files(&repo_root().join(root), &mut files);
    files.sort_by_key(|path| repo_relative(path));
    files
}

fn scanned_rust_files(root: &str, excluded: &BTreeSet<String>) -> Vec<PathBuf> {
    files_below(root)
        .into_iter()
        .filter(|path| path.extension() == Some(OsStr::new("rs")))
        .filter(|path| !excluded.contains(&repo_relative(path)))
        .collect()
}

fn literal_count(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn scan_root(root: &str, tokens: &[String], excluded: &BTreeSet<String>) -> BTreeMap<String, u64> {
    let files = scanned_rust_files(root, excluded);
    let mut counts = BTreeMap::from([(
        "rust_files".to_owned(),
        u64::try_from(files.len()).expect("Rust file count fits u64"),
    )]);
    for token in tokens {
        counts.insert(token.clone(), 0);
    }
    for path in files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} must be UTF-8: {error}", path.display()));
        for token in tokens {
            *counts.get_mut(token).expect("token was initialized") +=
                u64::try_from(literal_count(&source, token)).expect("token count fits u64");
        }
    }
    counts
}

fn source_paths_with_token(root: &str, token: &str) -> BTreeSet<String> {
    scanned_rust_files(root, &BTreeSet::new())
        .into_iter()
        .filter_map(|path| {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} must be UTF-8: {error}", path.display()));
            source.contains(token).then(|| repo_relative(&path))
        })
        .collect()
}

fn corpus_receipt(path: &str) -> (u64, u64, String) {
    let files = files_below(path);
    let mut byte_count = 0u64;
    let mut digest_lines = String::new();
    for file in &files {
        let bytes = std::fs::read(file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        byte_count += u64::try_from(bytes.len()).expect("file length fits u64");
        writeln!(
            &mut digest_lines,
            "{}  {}",
            sha256_hex(&bytes),
            repo_relative(file)
        )
        .expect("writing to String cannot fail");
    }
    (
        u64::try_from(files.len()).expect("corpus file count fits u64"),
        byte_count,
        sha256_hex(digest_lines.as_bytes()),
    )
}

fn validate_registry_shape(value: &Value) -> Result<(), String> {
    for key in [
        "artifact_id",
        "program_id",
        "bead_id",
        "title",
        "policy_as_of_date_utc",
        "policy_as_of_commit",
    ] {
        nonempty_text(value, key)?;
    }
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    let scan = value
        .get("scan_profile")
        .ok_or("scan_profile must be an object")?;
    let roots = scan
        .get("roots")
        .and_then(Value::as_array)
        .ok_or("scan_profile.roots must be an array")?;
    if roots.len() != EXPECTED_ROOT_COUNT {
        return Err(format!(
            "scan_profile.roots must contain {EXPECTED_ROOT_COUNT} rows"
        ));
    }
    let mut scan_paths = BTreeSet::new();
    for root in roots {
        nonempty_text(root, "path")?;
        nonempty_text(root, "classification")?;
        if !scan_paths.insert(text(root, "path")) {
            return Err(format!("duplicate scan root {}", text(root, "path")));
        }
    }

    let allowed_compatibility: BTreeSet<&str> = value
        .get("allowed_compatibility_classes")
        .and_then(Value::as_array)
        .ok_or("allowed_compatibility_classes must be an array")?
        .iter()
        .map(|entry| entry.as_str().ok_or("compatibility class must be a string"))
        .collect::<Result<_, _>>()?;
    if allowed_compatibility
        != BTreeSet::from([
            "DOWNSTREAM_DEFINED",
            "EXACT_BYTES",
            "SEMANTIC",
            "UNKNOWN_BLOCKING",
        ])
    {
        return Err("compatibility allow-list drifted".to_owned());
    }

    let allowed_evidence_states: BTreeSet<&str> = value
        .get("allowed_evidence_states")
        .and_then(Value::as_array)
        .ok_or("allowed_evidence_states must be an array")?
        .iter()
        .map(|entry| entry.as_str().ok_or("evidence state must be a string"))
        .collect::<Result<_, _>>()?;
    if allowed_evidence_states
        != BTreeSet::from([
            "BASELINE_EXISTING",
            "CURRENT_CORPUS_ONLY",
            "HISTORICAL_CORPUS_VERIFIED",
            "UNKNOWN_BLOCKING",
        ])
    {
        return Err("evidence-state allow-list drifted".to_owned());
    }

    let allowed_dispositions: BTreeSet<&str> = value
        .get("allowed_dependency_dispositions")
        .and_then(Value::as_array)
        .ok_or("allowed_dependency_dispositions must be an array")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or("dependency disposition must be a string")
        })
        .collect::<Result<_, _>>()?;
    if allowed_dispositions != BTreeSet::from(["KEEP", "REPLACE"]) {
        return Err("dependency disposition allow-list drifted".to_owned());
    }

    let profiles = value
        .get("format_profiles")
        .and_then(Value::as_array)
        .ok_or("format_profiles must be an array")?;
    if profiles.len() != EXPECTED_FORMAT_COUNT {
        return Err(format!(
            "format_profiles must contain {EXPECTED_FORMAT_COUNT} rows"
        ));
    }
    let expected_formats = BTreeMap::from([
        ("Bincode", 2u64),
        ("Custom", 255u64),
        ("Json", 3u64),
        ("MessagePack", 1u64),
    ]);
    let observed_formats: BTreeMap<&str, u64> = profiles
        .iter()
        .map(|profile| {
            let format = profile
                .get("format")
                .and_then(Value::as_str)
                .ok_or("format profile format must be a string")?;
            let discriminant = profile
                .get("discriminant")
                .and_then(Value::as_u64)
                .ok_or("format profile discriminant must be an integer")?;
            for key in [
                "backend",
                "generic_compatibility_class",
                "persisted_compatibility_class",
                "canonical_ordering",
                "resource_bounds",
                "error_contract",
                "version_policy",
                "migration_policy",
                "state",
            ] {
                nonempty_text(profile, key)?;
            }
            if !allowed_compatibility.contains(text(profile, "generic_compatibility_class"))
                || !allowed_compatibility.contains(text(profile, "persisted_compatibility_class"))
            {
                return Err(format!("{format} has an unregistered compatibility class"));
            }
            if array(profile, "public_generic_bounds").is_empty() {
                return Err(format!("{format} must state public generic bounds"));
            }
            Ok((format, discriminant))
        })
        .collect::<Result<_, String>>()?;
    if observed_formats != expected_formats {
        return Err("format discriminants drifted".to_owned());
    }
    let bincode = find_by_id(profiles, "format", "Bincode");
    if !text(bincode, "backend").contains("bincode-next 3.1.1")
        || !text(bincode, "canonical_ordering").contains("config::legacy()")
    {
        return Err("Bincode package/configuration baseline drifted".to_owned());
    }
    let custom = find_by_id(profiles, "format", "Custom");
    if text(custom, "state") != "CURRENT_CORPUS_ONLY"
        || !text(custom, "migration_policy").contains("standalone baseline consumer")
        || !text(custom, "migration_policy").contains("does not prove")
    {
        return Err(
            "Custom must record its finite fixture without claiming replacement parity".to_owned(),
        );
    }

    let decisions = value
        .get("generic_dependency_decisions")
        .and_then(Value::as_array)
        .ok_or("generic_dependency_decisions must be an array")?;
    if decisions.len() != 2 {
        return Err("generic_dependency_decisions must contain two rows".to_owned());
    }
    let observed_decisions: BTreeSet<&str> = decisions
        .iter()
        .filter_map(|decision| decision.get("format").and_then(Value::as_str))
        .collect();
    if observed_decisions != BTreeSet::from(["Bincode", "MessagePack"]) {
        return Err("generic dependency decision roster drifted".to_owned());
    }
    for decision in decisions {
        let format = text(decision, "format");
        for key in [
            "bead_id",
            "capability_id",
            "disposition",
            "incumbent_package",
            "incumbent_version",
            "incumbent_checksum",
            "public_surface",
            "configuration",
            "rationale",
            "replacement_gate",
            "evidence_state",
            "no_claim_boundary",
            "proof_command",
        ] {
            nonempty_text(decision, key)?;
        }
        if text(decision, "bead_id") != A6_BEAD_ID
            || text(decision, "capability_id") != "CAP-SERDE-GENERIC"
        {
            return Err(format!("{format} decision authority drifted"));
        }
        let disposition = text(decision, "disposition");
        if !allowed_dispositions.contains(disposition) {
            return Err(format!(
                "{format} has an unregistered dependency disposition"
            ));
        }
        if disposition == "KEEP" && !text(decision, "replacement_gate").contains("REPLACE") {
            return Err(format!(
                "{format} KEEP decision must retain the REPLACE gate"
            ));
        }
        if disposition == "REPLACE"
            && decision
                .get("replacement_parity")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            return Err(format!(
                "{format} REPLACE decision requires replacement_parity evidence"
            ));
        }
        for key in [
            "fixture_paths",
            "fixture_tests",
            "accepted_data_model",
            "accepted_exclusions",
            "errors_and_limits",
            "dependency_closure",
        ] {
            if decision
                .get(key)
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                return Err(format!("{format}.{key} must be a nonempty array"));
            }
        }
        if array(decision, "accepted_data_model").len() < 7 {
            return Err(format!("{format} accepted data model was narrowed"));
        }
        if text(decision, "evidence_state") != "CURRENT_CORPUS_ONLY" {
            return Err(format!(
                "{format} generic evidence must remain current-corpus only"
            ));
        }
        let golden = decision
            .get("exact_payload_golden")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("{format}.exact_payload_golden must be an object"))?;
        let fixture = golden
            .get("fixture")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{format} golden fixture must be a string"))?;
        let hex = golden
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{format} golden hex must be a string"))?;
        let byte_count = golden
            .get("byte_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{format} golden byte_count must be an integer"))?;
        if fixture != "ConsumerRecord::boundary_fixture()"
            || hex.is_empty()
            || hex.len() != usize::try_from(byte_count).expect("golden byte count fits usize") * 2
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!("{format} exact payload golden is malformed"));
        }
        let measurement = decision
            .get("source_measurement")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("{format}.source_measurement must be an object"))?;
        if measurement
            .get("method")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || measurement
                .get("crate_src_rust_lines")
                .and_then(Value::as_u64)
                .is_none_or(|lines| lines == 0)
        {
            return Err(format!("{format} source measurement is incomplete"));
        }
        let proof_command = text(decision, "proof_command");
        for marker in [
            "RCH_REQUIRE_REMOTE=1 rch exec",
            "--base HEAD",
            "--clean-overlay",
            CONSUMER_SOURCE_PATH,
            CONSUMER_LOCK_PATH,
            "--locked",
        ] {
            if !proof_command.contains(marker) {
                return Err(format!("{format} proof command missing {marker}"));
            }
        }
        if !text(decision, "no_claim_boundary")
            .to_ascii_lowercase()
            .contains("does not prove")
        {
            return Err(format!(
                "{format} decision must state a negative no-claim boundary"
            ));
        }
    }

    let public = value
        .get("public_generic_surfaces")
        .and_then(Value::as_array)
        .ok_or("public_generic_surfaces must be an array")?;
    let public_ids: BTreeSet<&str> = public
        .iter()
        .filter_map(|surface| surface.get("surface_id").and_then(Value::as_str))
        .collect();
    if public_ids != BTreeSet::from(["PUB-SERDE-CODEC", "PUB-TYPED-SYMBOL"]) {
        return Err("public generic surface roster drifted".to_owned());
    }
    let serde_surface = find_by_id(public, "surface_id", "PUB-SERDE-CODEC");
    let generic_contract = text(serde_surface, "generic_contract");
    if !generic_contract.contains("Arbitrary downstream")
        || !generic_contract.contains("DeserializeOwned")
        || !generic_contract.contains("no seal")
    {
        return Err("arbitrary downstream Serde must remain first-class".to_owned());
    }
    if string_set(serde_surface, "formats")
        != BTreeSet::from([
            "Bincode".to_owned(),
            "Custom".to_owned(),
            "Json".to_owned(),
            "MessagePack".to_owned(),
        ])
    {
        return Err("public Serde format roster drifted".to_owned());
    }

    let persisted = value
        .get("persisted_surfaces")
        .and_then(Value::as_array)
        .ok_or("persisted_surfaces must be an array")?;
    if persisted.len() != EXPECTED_PERSISTED_SURFACE_COUNT {
        return Err(format!(
            "persisted_surfaces must contain {EXPECTED_PERSISTED_SURFACE_COUNT} rows"
        ));
    }
    let expected_persisted = BTreeSet::from([
        "PERSIST-ATP-CRASHPACK",
        "PERSIST-BROWSER-TRACE-JSON",
        "PERSIST-CRASHPACK",
        "PERSIST-DISTRIBUTED-SNAPSHOT",
        "PERSIST-GOLDEN-TRACE-JSON",
        "PERSIST-INCIDENT-JSON",
        "PERSIST-LAB-SCENARIO-AND-EXPLORER-JSON",
        "PERSIST-LAB-SNAPSHOT-HASH",
        "PERSIST-REPLAY-BLOB",
        "PERSIST-TRACE-FILE",
        "PERSIST-TRACE-STREAM",
        "PERSIST-TYPED-SYMBOL",
        "TOOL-TRACE-CLI-CONSUMER",
    ]);
    let observed_persisted: BTreeSet<&str> = persisted
        .iter()
        .filter_map(|surface| surface.get("surface_id").and_then(Value::as_str))
        .collect();
    if observed_persisted != expected_persisted {
        return Err("persisted surface roster drifted".to_owned());
    }
    let corpora = value
        .get("corpora")
        .and_then(Value::as_array)
        .ok_or("corpora must be an array")?;
    for corpus in corpora {
        for key in ["corpus_id", "compatibility_class", "state", "provenance"] {
            nonempty_text(corpus, key)?;
        }
        if !allowed_compatibility.contains(text(corpus, "compatibility_class")) {
            return Err(format!(
                "{} has an unregistered compatibility class",
                text(corpus, "corpus_id")
            ));
        }
        if !allowed_evidence_states.contains(text(corpus, "state")) {
            return Err(format!(
                "{} has an unregistered evidence state",
                text(corpus, "corpus_id")
            ));
        }
    }
    let corpus_ids: BTreeSet<&str> = corpora
        .iter()
        .filter_map(|corpus| corpus.get("corpus_id").and_then(Value::as_str))
        .collect();
    for surface in persisted {
        for key in [
            "surface_id",
            "owner",
            "backend",
            "compatibility_class",
            "exactness_detail",
            "canonical_ordering",
            "resource_bounds",
            "version_policy",
            "error_contract",
            "migration_policy",
            "state",
            "no_claim_boundary",
        ] {
            nonempty_text(surface, key)?;
        }
        if !allowed_compatibility.contains(text(surface, "compatibility_class")) {
            return Err(format!(
                "{} has an unregistered compatibility class",
                text(surface, "surface_id")
            ));
        }
        if !allowed_evidence_states.contains(text(surface, "state")) {
            return Err(format!(
                "{} has an unregistered evidence state",
                text(surface, "surface_id")
            ));
        }
        for key in ["source_paths", "writers", "readers", "corpus_ids"] {
            let entries = surface.get(key).and_then(Value::as_array).ok_or_else(|| {
                format!("{}.{} must be an array", text(surface, "surface_id"), key)
            })?;
            if key != "corpus_ids" && entries.is_empty() {
                return Err(format!(
                    "{}.{} must not be empty",
                    text(surface, "surface_id"),
                    key
                ));
            }
        }
        for corpus_id in array(surface, "corpus_ids") {
            let corpus_id = corpus_id
                .as_str()
                .ok_or("surface corpus id must be a string")?;
            if !corpus_ids.contains(corpus_id) {
                return Err(format!(
                    "{} references unknown corpus {corpus_id}",
                    text(surface, "surface_id")
                ));
            }
        }
        if text(surface, "state") == "UNKNOWN_BLOCKING"
            && !["not", "no ", "only"].iter().any(|marker| {
                text(surface, "no_claim_boundary")
                    .to_ascii_lowercase()
                    .contains(marker)
            })
        {
            return Err(format!(
                "{} must state a negative no-claim boundary",
                text(surface, "surface_id")
            ));
        }
    }

    let blockers = value
        .get("unknown_blockers")
        .and_then(Value::as_array)
        .ok_or("unknown_blockers must be an array")?;
    if !blockers.is_empty() {
        return Err("A7 historical blockers must remain resolved".to_owned());
    }
    for blocker in blockers {
        for key in ["blocker_id", "owner_bead", "missing_evidence", "effect"] {
            nonempty_text(blocker, key)?;
        }
        if array(blocker, "affected_surfaces").is_empty() {
            return Err(format!(
                "{} must identify affected surfaces",
                text(blocker, "blocker_id")
            ));
        }
        if !text(blocker, "effect")
            .to_ascii_lowercase()
            .contains("block")
        {
            return Err(format!("{} must fail closed", text(blocker, "blocker_id")));
        }
    }

    let consumers = value
        .get("downstream_consumers")
        .and_then(Value::as_array)
        .ok_or("downstream_consumers must be an array")?;
    for consumer in consumers {
        for key in ["consumer_id", "owner", "evidence", "state"] {
            nonempty_text(consumer, key)?;
        }
        if !allowed_evidence_states.contains(text(consumer, "state")) {
            return Err(format!(
                "{} has an unregistered evidence state",
                text(consumer, "consumer_id")
            ));
        }
        if array(consumer, "formats").is_empty() {
            return Err(format!(
                "{} must retain at least one format",
                text(consumer, "consumer_id")
            ));
        }
    }
    let standalone = find_by_id(consumers, "consumer_id", "CONSUMER-STANDALONE-BASELINE");
    if text(standalone, "state") != "CURRENT_CORPUS_ONLY"
        || string_set(standalone, "paths")
            != BTreeSet::from([
                CONSUMER_MANIFEST_PATH.to_owned(),
                CONSUMER_LOCK_PATH.to_owned(),
                CONSUMER_SOURCE_PATH.to_owned(),
            ])
        || !text(standalone, "evidence").contains("complete accepted owned Serde model")
        || !text(standalone, "evidence").contains("1 MiB")
        || !text(standalone, "evidence").contains("128 recursive levels")
    {
        return Err("the locked A6 downstream consumer receipt must stay exact".to_owned());
    }
    let custom_consumer = find_by_id(consumers, "consumer_id", "CONSUMER-REAL-CUSTOM-CODEC");
    if text(custom_consumer, "state") != "CURRENT_CORPUS_ONLY"
        || string_set(custom_consumer, "paths") != BTreeSet::from([CONSUMER_SOURCE_PATH.to_owned()])
    {
        return Err("the real Custom consumer receipt must stay exact".to_owned());
    }
    let external = find_by_id(
        consumers,
        "consumer_id",
        "CONSUMER-EXTERNAL-HISTORICAL-ARTIFACTS",
    );
    if text(external, "owner") != A7_BEAD_ID
        || text(external, "state") != "HISTORICAL_CORPUS_VERIFIED"
        || string_set(external, "paths")
            != BTreeSet::from([
                HISTORICAL_CONSUMER_MANIFEST_PATH.to_owned(),
                HISTORICAL_CONSUMER_LOCK_PATH.to_owned(),
                HISTORICAL_CONSUMER_SOURCE_PATH.to_owned(),
                HISTORICAL_CORPUS_PATH.to_owned(),
                HISTORICAL_E2E_PATH.to_owned(),
            ])
        || !text(external, "evidence").contains("published crates.io")
        || !text(external, "evidence").contains("atomic output")
    {
        return Err("the A7 historical consumer receipt must stay exact".to_owned());
    }

    Ok(())
}

#[test]
fn metadata_and_accepted_adr_authority_are_exact() {
    let registry = registry();
    validate_registry_shape(&registry).unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(text(&registry, "artifact_id"), "typed-format-registry-v1");
    assert_eq!(text(&registry, "program_id"), PROGRAM_ID);
    assert_eq!(text(&registry, "bead_id"), BEAD_ID);
    assert_eq!(
        string_set(&registry, "capability_ids"),
        BTreeSet::from([
            "CAP-PERSISTED-TRACE-SNAPSHOT".to_owned(),
            "CAP-SERDE-GENERIC".to_owned(),
        ])
    );

    let authority = registry
        .get("authority")
        .and_then(Value::as_object)
        .expect("authority must be an object");
    assert_eq!(
        authority
            .get("decision_registry_path")
            .and_then(Value::as_str),
        Some(DECISION_REGISTRY_PATH)
    );
    assert_eq!(
        authority.get("decision_doc_path").and_then(Value::as_str),
        Some(DECISION_DOC_PATH)
    );
    assert_eq!(
        authority.get("decision_id").and_then(Value::as_str),
        Some(DECISION_ID)
    );
    assert_eq!(
        authority.get("decision").and_then(Value::as_str),
        Some("ADDITIVE_COEXISTENCE")
    );
    assert_eq!(
        authority
            .get("generic_cutover_state")
            .and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        authority
            .get("persisted_cutover_state")
            .and_then(Value::as_str),
        Some("BLOCKED_PENDING_EVIDENCE")
    );

    let decision_registry = parse_repo_json(DECISION_REGISTRY_PATH);
    let adr = find_by_id(array(&decision_registry, "adrs"), "adr_id", DECISION_ID);
    assert_eq!(text(adr, "decision"), "ADDITIVE_COEXISTENCE");
    assert_eq!(
        string_set(adr, "capability_ids"),
        string_set(&registry, "capability_ids")
    );
    let cutover = adr
        .get("cutover")
        .and_then(Value::as_object)
        .expect("accepted ADR cutover must be an object");
    assert_eq!(
        cutover
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );
    let per_capability = cutover
        .get("per_capability")
        .and_then(Value::as_array)
        .expect("accepted ADR per_capability must be an array");
    assert_eq!(
        find_by_id(per_capability, "capability_id", "CAP-SERDE-GENERIC")
            .get("cutover_state")
            .and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        find_by_id(
            per_capability,
            "capability_id",
            "CAP-PERSISTED-TRACE-SNAPSHOT"
        )
        .get("cutover_state")
        .and_then(Value::as_str),
        Some("BLOCKED_PENDING_EVIDENCE")
    );
}

#[test]
fn dependency_manifest_and_lock_pins_are_live() {
    let registry = registry();
    let dependencies = array(&registry, "dependency_pins");
    assert_eq!(dependencies.len(), 3);

    let manifest = read_repo_file("Cargo.toml");
    for expected in [
        "rmp-serde = \"1.3\"",
        "serde_json = \"1.0\"",
        "bincode = { package = \"bincode-next\", version = \"3.1.1\", features = [\"serde\"] }",
    ] {
        assert!(
            manifest.contains(expected),
            "Cargo manifest dependency pin drifted: {expected}"
        );
    }

    let lock = read_repo_file("Cargo.lock");
    for dependency in dependencies {
        for key in [
            "logical_name",
            "manifest_key",
            "package",
            "manifest_requirement",
            "lock_version",
            "lock_checksum",
            "configuration",
            "state",
        ] {
            let value = text(dependency, key);
            assert!(
                !value.trim().is_empty(),
                "dependency {key} must not be empty"
            );
        }
        let expected_block = format!(
            "name = \"{}\"\nversion = \"{}\"",
            text(dependency, "package"),
            text(dependency, "lock_version")
        );
        assert!(
            lock.contains(&expected_block),
            "Cargo.lock package/version drifted: {expected_block}"
        );
        let checksum = format!("checksum = \"{}\"", text(dependency, "lock_checksum"));
        assert!(
            lock.contains(&checksum),
            "Cargo.lock checksum drifted for {}",
            text(dependency, "package")
        );
    }
}

#[test]
fn binary_generic_keep_receipts_and_downstream_fixture_are_exact() {
    let registry = registry();
    let decisions = array(&registry, "generic_dependency_decisions");
    assert_eq!(decisions.len(), 2);

    let expected_paths = BTreeSet::from([
        CONSUMER_MANIFEST_PATH.to_owned(),
        CONSUMER_LOCK_PATH.to_owned(),
        CONSUMER_SOURCE_PATH.to_owned(),
    ]);
    let expected_tests = BTreeSet::from([
        "binary_format_bytes_are_explicit_downstream_goldens".to_owned(),
        "binary_formats_cover_the_complete_owned_serde_model".to_owned(),
        "binary_formats_preserve_errors_trailing_bytes_recovery_and_large_owned_values".to_owned(),
    ]);

    for decision in decisions {
        assert_eq!(text(decision, "bead_id"), A6_BEAD_ID);
        assert_eq!(text(decision, "capability_id"), "CAP-SERDE-GENERIC");
        assert_eq!(text(decision, "disposition"), "KEEP");
        assert_eq!(text(decision, "evidence_state"), "CURRENT_CORPUS_ONLY");
        assert_eq!(string_set(decision, "fixture_paths"), expected_paths);
        assert_eq!(string_set(decision, "fixture_tests"), expected_tests);
        assert!(
            text(decision, "replacement_gate").contains("differential")
                && text(decision, "replacement_gate").contains("property")
                && text(decision, "replacement_gate").contains("fuzz")
                && text(decision, "replacement_gate").contains("ergonomic"),
            "{} replacement gate was weakened",
            text(decision, "format")
        );

        let golden = decision
            .get("exact_payload_golden")
            .and_then(Value::as_object)
            .expect("exact_payload_golden must be an object");
        let measurement = decision
            .get("source_measurement")
            .and_then(Value::as_object)
            .expect("source_measurement must be an object");
        match text(decision, "format") {
            "MessagePack" => {
                assert_eq!(text(decision, "incumbent_package"), "rmp-serde");
                assert_eq!(text(decision, "incumbent_version"), "1.3.1");
                assert_eq!(
                    text(decision, "incumbent_checksum"),
                    "72f81bee8c8ef9b577d1681a70ebbc962c232461e397b22c208c43c04b67a155"
                );
                assert_eq!(golden.get("byte_count").and_then(Value::as_u64), Some(71));
                assert_eq!(
                    golden.get("hex").and_then(Value::as_str),
                    Some(MESSAGEPACK_GOLDEN)
                );
                assert_eq!(
                    measurement
                        .get("crate_src_rust_lines")
                        .and_then(Value::as_u64),
                    Some(3_207)
                );
                assert_eq!(
                    string_set(decision, "dependency_closure"),
                    BTreeSet::from(["rmp".to_owned(), "serde".to_owned()])
                );
            }
            "Bincode" => {
                assert_eq!(text(decision, "incumbent_package"), "bincode-next");
                assert_eq!(text(decision, "incumbent_version"), "3.1.1");
                assert_eq!(
                    text(decision, "incumbent_checksum"),
                    "1d6626829353ae29293be5c86f42de5f0468bc758af074b0c7d08f07e538ccbc"
                );
                assert!(text(decision, "configuration").contains("config::legacy()"));
                assert_eq!(golden.get("byte_count").and_then(Value::as_u64), Some(102));
                assert_eq!(
                    golden.get("hex").and_then(Value::as_str),
                    Some(BINCODE_GOLDEN)
                );
                assert_eq!(
                    measurement
                        .get("crate_src_rust_lines")
                        .and_then(Value::as_u64),
                    Some(18_992)
                );
                assert_eq!(
                    measurement
                        .get("serde_bridge_rust_lines")
                        .and_then(Value::as_u64),
                    Some(1_564)
                );
                assert!(
                    array(decision, "accepted_exclusions").iter().any(|entry| {
                        entry
                            .as_str()
                            .is_some_and(|value| value.contains("deserialize_any"))
                    }),
                    "Bincode decision must fence deserialize_any"
                );
            }
            format => panic!("unexpected generic dependency decision {format}"),
        }

        let errors_and_limits = array(decision, "errors_and_limits")
            .iter()
            .map(|entry| entry.as_str().expect("error/limit entry must be a string"))
            .collect::<Vec<_>>()
            .join(" ");
        for marker in ["truncation", "Trailing bytes", "1 MiB", "128", "no global"] {
            assert!(
                errors_and_limits.contains(marker),
                "{} decision missing error/limit marker {marker}",
                text(decision, "format")
            );
        }
    }

    let source = read_repo_file(CONSUMER_SOURCE_PATH);
    for marker in [
        "struct ConsumerSerdeModel",
        "serializer.serialize_bytes(&self.0)",
        "deserializer.deserialize_byte_buf(ConsumerBytesVisitor)",
        "fn binary_formats_cover_the_complete_owned_serde_model()",
        "fn binary_format_bytes_are_explicit_downstream_goldens()",
        "fn binary_formats_preserve_errors_trailing_bytes_recovery_and_large_owned_values()",
        "consumer-forced encode failure",
        "1024 * 1024",
        "ConsumerNested::with_depth(128)",
        MESSAGEPACK_GOLDEN,
        BINCODE_GOLDEN,
    ] {
        assert!(
            source.contains(marker),
            "A6 downstream fixture missing marker: {marker}"
        );
    }
}

#[test]
fn lexical_scan_profile_covers_every_registered_root() {
    let registry = registry();
    let scan = registry
        .get("scan_profile")
        .expect("scan_profile must exist");
    let roots = array(scan, "roots");
    assert_eq!(roots.len(), EXPECTED_ROOT_COUNT);
    let tokens: Vec<String> = array(scan, "tokens")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("scan token must be a string")
                .to_owned()
        })
        .collect();
    let excluded: BTreeSet<String> = array(scan, "excluded_paths")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("excluded path must be a string")
                .to_owned()
        })
        .collect();
    assert_eq!(
        excluded,
        BTreeSet::from(["tests/typed_format_registry_contract.rs".to_owned()])
    );

    let mut totals = BTreeMap::from([("rust_files".to_owned(), 0u64)]);
    for token in &tokens {
        totals.insert(token.clone(), 0);
    }
    let mut observed_roots = BTreeSet::new();
    for root in roots {
        let path = text(root, "path");
        assert!(observed_roots.insert(path), "duplicate scan root {path}");
        assert!(
            !text(root, "classification").trim().is_empty(),
            "{path} must have a classification"
        );
        let observed = scan_root(path, &tokens, &excluded);
        for key in std::iter::once("rust_files").chain(tokens.iter().map(String::as_str)) {
            let expected = root
                .get(key)
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{path}.{key} must be an integer"));
            assert_eq!(
                observed.get(key).copied(),
                Some(expected),
                "lexical scan drift in {path} for {key}"
            );
            *totals.get_mut(key).expect("total key was initialized") += expected;
        }
    }

    let expected_totals = scan
        .get("totals")
        .and_then(Value::as_object)
        .expect("scan_profile.totals must be an object");
    for (key, observed) in totals {
        assert_eq!(
            expected_totals.get(&key).and_then(Value::as_u64),
            Some(observed),
            "scan total drift for {key}"
        );
    }
}

#[test]
fn direct_production_backend_file_rosters_are_exact() {
    let registry = registry();
    let inventories = array(&registry, "production_backend_files");

    for token in ["rmp_serde::", "bincode::"] {
        let inventory = find_by_id(inventories, "token", token);
        let expected: BTreeSet<String> = array(inventory, "paths")
            .iter()
            .map(|path| {
                path.as_str()
                    .expect("backend path must be a string")
                    .to_owned()
            })
            .collect();
        assert_eq!(
            source_paths_with_token("src", token),
            expected,
            "direct production backend file roster drifted for {token}"
        );
    }

    let json = find_by_id(inventories, "token", "serde_json::");
    assert_eq!(
        json.get("path_count").and_then(Value::as_u64),
        Some(
            u64::try_from(source_paths_with_token("src", "serde_json::").len())
                .expect("path count fits u64")
        ),
        "direct serde_json source path count drifted"
    );
    assert!(
        text(json, "classification").contains("Persisted/public exceptions"),
        "JSON inventory must explain its explicit persisted overrides"
    );
}

#[test]
fn public_generic_and_container_invariants_match_source() {
    let typed = read_repo_file("src/types/typed_symbol.rs");
    for expected in [
        "pub const TYPED_SYMBOL_MAGIC: [u8; 4] = *b\"TSYM\";",
        "pub const TYPED_SYMBOL_HEADER_LEN: usize = 27;",
        "Self::MessagePack => 1,",
        "Self::Bincode => 2,",
        "Self::Json => 3,",
        "Self::Custom => 255,",
        "impl<T: Serialize> Serializer<T> for SerdeCodec",
        "impl<T: DeserializeOwned> Deserializer<T> for SerdeCodec",
        "bincode::config::legacy()",
        "SerializationFormat::Custom => Err",
        "let max_payload = symbol_size.saturating_sub(TYPED_SYMBOL_HEADER_LEN);",
    ] {
        assert!(
            typed.contains(expected),
            "typed-symbol public/generic invariant drifted: {expected}"
        );
    }

    let trace = read_repo_file("src/trace/file.rs");
    for expected in [
        "pub const TRACE_MAGIC: &[u8; 11] = b\"ASUPERTRACE\";",
        "pub const TRACE_FILE_VERSION: u16 = 3;",
        "pub const FLAG_CHECKSUMMED: u16 = 0x0002;",
        "pub const TRACE_CHECKSUM_LEN: usize = 32;",
        "pub const MAX_META_LEN: usize = 1024 * 1024;",
        "pub const MAX_EVENT_PREALLOC: usize = 10_000_000;",
        "pub const MAX_EVENT_LEN: usize = 16 * 1024 * 1024;",
        "pub const MAX_COMPRESSED_CHUNK_LEN: usize = 64 * 1024 * 1024;",
        "if metadata.version != REPLAY_SCHEMA_VERSION",
        "pub fn recover_trace_prefix(",
        "pub fn migrate_trace_file(",
    ] {
        assert!(
            trace.contains(expected),
            "trace-file invariant drifted: {expected}"
        );
    }

    let replay = read_repo_file("src/trace/replay.rs");
    assert!(replay.contains("pub const REPLAY_SCHEMA_VERSION: u32 = 1;"));
    let compat = read_repo_file("src/trace/compat.rs");
    assert!(compat.contains("pub const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;"));
    assert!(compat.contains("pub fn read_event_compat("));
    assert!(compat.contains("without silently skipping"));
    let crashpack = read_repo_file("src/trace/crashpack.rs");
    assert!(crashpack.contains("pub const CRASHPACK_SCHEMA_VERSION: u32 = 1;"));
    assert!(crashpack.contains("pub const MINIMUM_SUPPORTED_SCHEMA_VERSION: u32 = 1;"));

    let snapshot = read_repo_file("src/distributed/snapshot.rs");
    for expected in [
        "const SNAP_MAGIC: &[u8; 4] = b\"SNAP\";",
        "const SNAP_VERSION: u8 = 2;",
        "bincode::config::legacy()",
        "const SNAPSHOT_ARENA_ID_MAX_INDEX: u32 = 1_000_000;",
    ] {
        assert!(
            snapshot.contains(expected),
            "distributed-snapshot invariant drifted: {expected}"
        );
    }

    let lab_snapshot = read_repo_file("src/lab/snapshot_restore.rs");
    for expected in [
        "pub const SNAPSHOT_ARTIFACT_MAGIC: [u8; 8] = *b\"ASUPSNAP\";",
        "pub const SNAPSHOT_ARTIFACT_VERSION: u16 = 1;",
        "pub const SCHEMA_VERSION: u32 = 2;",
        "pub const MINIMUM_SUPPORTED_SCHEMA_VERSION: u32 = 1;",
        "serde_json::to_vec(hash_input)",
        "const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;",
        "Sha256::digest(&payload)",
        "[ASUP-E404] snapshot artifact",
    ] {
        assert!(
            lab_snapshot.contains(expected),
            "lab snapshot hash invariant drifted: {expected}"
        );
    }
}

#[test]
fn every_registered_source_path_exists_and_source_pins_match() {
    let registry = registry();
    for section in ["persisted_surfaces", "downstream_consumers"] {
        for row in array(&registry, section) {
            let Some(paths) = row.get("source_paths").or_else(|| row.get("paths")) else {
                panic!("{section} row must carry source_paths or paths");
            };
            for path in paths
                .as_array()
                .unwrap_or_else(|| panic!("{section} paths must be an array"))
            {
                let path = path.as_str().expect("registered path must be a string");
                assert!(
                    repo_root().join(path).exists(),
                    "registered source/consumer path is missing: {path}"
                );
            }
        }
    }

    let pins = array(&registry, "source_pins");
    assert!(
        pins.len() >= 30,
        "high-risk source pin roster unexpectedly narrowed"
    );
    let mut seen = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(seen.insert(path), "duplicate source pin {path}");
        assert_eq!(
            sha256_hex(&read_repo_bytes(path)),
            text(pin, "sha256"),
            "source pin drifted for {path}; re-audit the affected surface"
        );
    }
}

#[test]
fn corpus_receipts_and_published_v039_provenance_are_fail_closed() {
    let registry = registry();
    let corpora = array(&registry, "corpora");
    assert_eq!(corpora.len(), 5);

    for corpus in corpora {
        let corpus_id = text(corpus, "corpus_id");
        let state = text(corpus, "state");
        let path = corpus.get("path");
        let path = path
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{corpus_id} must have a path"));
        let (file_count, byte_count, aggregate) = corpus_receipt(path);
        assert_eq!(
            corpus.get("file_count").and_then(Value::as_u64),
            Some(file_count),
            "{corpus_id} file count drifted"
        );
        assert_eq!(
            corpus.get("byte_count").and_then(Value::as_u64),
            Some(byte_count),
            "{corpus_id} byte count drifted"
        );
        assert_eq!(
            corpus.get("aggregate_sha256").and_then(Value::as_str),
            Some(aggregate.as_str()),
            "{corpus_id} aggregate digest drifted"
        );
        assert_eq!(
            corpus.get("aggregate_algorithm").and_then(Value::as_str),
            Some("SHA-256 of sorted lines '<file_sha256>  <repo_relative_path>\\n'")
        );
        if corpus_id == "CORPUS-HISTORICAL-V039" {
            assert_eq!(state, "HISTORICAL_CORPUS_VERIFIED");
            assert_eq!(path, "tests/fixtures/typed-format-historical-corpus");
            assert!(text(corpus, "provenance").contains(V039_COMMIT));
            assert!(text(corpus, "provenance").contains(V039_CRATE_CHECKSUM));
        } else {
            assert_ne!(state, "HISTORICAL_CORPUS_VERIFIED");
            assert!(
                text(corpus, "provenance").contains("Current")
                    || text(corpus, "provenance").contains("current"),
                "{corpus_id} must not imply historical provenance"
            );
        }
    }

    let historical = find_by_id(corpora, "corpus_id", "CORPUS-HISTORICAL-V039");
    assert_eq!(text(historical, "compatibility_class"), "EXACT_BYTES");
    assert_eq!(
        historical.get("file_count").and_then(Value::as_u64),
        Some(1)
    );

    let manifest = parse_repo_json(HISTORICAL_CORPUS_PATH);
    assert_eq!(
        text(&manifest, "schema_version"),
        "typed-format-historical-corpus-v1"
    );
    assert_eq!(text(&manifest, "bead_id"), A7_BEAD_ID);
    let source_release = manifest
        .get("source_release")
        .and_then(Value::as_object)
        .expect("source_release must be an object");
    assert_eq!(
        source_release.get("version").and_then(Value::as_str),
        Some("0.3.9")
    );
    assert_eq!(
        source_release.get("git_tag").and_then(Value::as_str),
        Some("v0.3.9")
    );
    assert_eq!(
        source_release.get("git_commit").and_then(Value::as_str),
        Some(V039_COMMIT)
    );
    assert_eq!(
        source_release
            .get("crate_checksum_sha256")
            .and_then(Value::as_str),
        Some(V039_CRATE_CHECKSUM)
    );

    let artifacts = array(&manifest, "artifacts");
    assert_eq!(artifacts.len(), 7);
    let artifact_ids: BTreeSet<&str> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("artifact_id").and_then(Value::as_str))
        .collect();
    assert_eq!(
        artifact_ids,
        BTreeSet::from([
            "distributed-snapshot-v2",
            "replay-blob-v039",
            "runtime-snapshot-v1",
            "trace-v2-boundary",
            "trace-v2-large",
            "typed-symbol-v039-bincode",
            "typed-symbol-v039-messagepack",
        ])
    );
    for artifact in artifacts {
        for key in [
            "artifact_id",
            "surface_id",
            "format",
            "sha256",
            "semantic_fingerprint",
        ] {
            nonempty_text(artifact, key)
                .unwrap_or_else(|error| panic!("historical artifact invalid: {error}"));
        }
        let byte_len = artifact
            .get("byte_len")
            .and_then(Value::as_u64)
            .expect("historical artifact byte_len");
        assert!(byte_len > 0);
        if let Some(hex) = artifact.get("bytes_hex").and_then(Value::as_str) {
            assert_eq!(
                hex.len(),
                usize::try_from(byte_len).expect("byte length fits usize") * 2
            );
            assert_eq!(
                sha256_hex(&decode_hex(hex)),
                text(artifact, "sha256"),
                "{} exact bytes drifted",
                text(artifact, "artifact_id")
            );
        } else {
            assert_eq!(text(artifact, "artifact_id"), "trace-v2-large");
            assert_eq!(
                artifact["extra"]["committed_representation"].as_str(),
                Some("digest-and-published-writer-recipe")
            );
            assert_eq!(artifact["extra"]["event_count"].as_u64(), Some(4096));
        }
    }

    let fixture_manifest = read_repo_file(HISTORICAL_CONSUMER_MANIFEST_PATH);
    assert!(fixture_manifest.contains("version = \"=0.3.9\""));
    assert!(fixture_manifest.contains("[workspace]"));
    let fixture_lock = read_repo_file(HISTORICAL_CONSUMER_LOCK_PATH);
    assert!(fixture_lock.contains("name = \"asupersync\""));
    assert!(fixture_lock.contains("version = \"0.3.9\""));
    assert!(fixture_lock.contains(V039_CRATE_CHECKSUM));
    let fixture_source = read_repo_file(HISTORICAL_CONSUMER_SOURCE_PATH);
    for marker in [
        "asupersync_v039",
        "asupersync_current",
        "LegacyTypedSymbolIdentity",
        "OpaqueCodec",
        "trace-v2-large",
        "../../typed-format-historical-corpus/v0.3.9.json",
        "generated_bytes[6..14].fill(0)",
        "generated_bytes[15..23].fill(0)",
        "committed provenance tuple admits exact historical bytes",
    ] {
        assert!(
            fixture_source.contains(marker),
            "historical writer fixture missing {marker}"
        );
    }
}

#[test]
fn documentation_and_validation_boundary_are_discoverable() {
    let registry = registry();
    let validation = registry
        .get("validation")
        .and_then(Value::as_object)
        .expect("validation must be an object");
    assert_eq!(
        validation.get("contract_test").and_then(Value::as_str),
        Some("tests/typed_format_registry_contract.rs")
    );
    assert_eq!(
        validation.get("doc_path").and_then(Value::as_str),
        Some(DOC_PATH)
    );
    let command = validation
        .get("proof_command")
        .and_then(Value::as_str)
        .expect("proof command must be a string");
    for expected in [
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "--base HEAD",
        "--clean-overlay",
        "--overlay-path tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs",
        "--overlay-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.lock",
        "--overlay-path src/types/typed_symbol.rs",
        "--overlay-path src/types/mod.rs",
        "--overlay-path src/trace/file.rs",
        "--overlay-path tests/fixtures/typed-format-cross-version-consumer/Cargo.toml",
        "--overlay-path tests/fixtures/typed-format-cross-version-consumer/Cargo.lock",
        "--overlay-path tests/fixtures/typed-format-cross-version-consumer/src/lib.rs",
        "--overlay-path tests/fixtures/typed-format-cross-version-consumer/src/bin/capture.rs",
        "--overlay-path tests/fixtures/typed-format-historical-corpus/v0.3.9.json",
        "--overlay-path tests/typed_format_cross_version_e2e.rs",
        "--overlay-path scripts/run_dependency_sovereignty_e2e.sh",
        "--overlay-path artifacts/typed_format_registry_v1.json",
        "--overlay-path docs/typed_format_registry.md",
        "--overlay-path tests/typed_format_registry_contract.rs",
        "--test typed_format_registry_contract",
    ] {
        assert!(
            command.contains(expected),
            "proof command missing {expected}"
        );
    }
    let no_claim = validation
        .get("no_claim_boundary")
        .and_then(Value::as_str)
        .expect("validation no-claim boundary must be a string");
    for forbidden_claim in ["does not execute", "dependency removal", "cutover"] {
        assert!(
            no_claim.contains(forbidden_claim),
            "validation boundary missing {forbidden_claim}"
        );
    }

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        "# Typed format registry",
        "CAP-SERDE-GENERIC",
        "CAP-PERSISTED-TRACE-SNAPSHOT",
        "EXACT_BYTES",
        "SEMANTIC",
        "UNKNOWN_BLOCKING",
        "HISTORICAL_CORPUS_VERIFIED",
        "SerializationFormat::Custom",
        "bincode::config::legacy()",
        "ASUPERTRACE",
        "SHA-256",
        "trace migrate",
        "recover_trace_prefix",
        "RestorableSnapshot",
        "ASUPSNAP",
        "ASUP-E404",
        "runtime_snapshot_codec.md",
        "asupersync-5z2scg.3.6",
        "asupersync-5z2scg.3.7",
        "Published v0.3.9",
        "LegacyTypedSymbolIdentity",
        "4,096-event",
        "atomic",
        "## A6 generic MessagePack/Bincode decision",
        "3,207",
        "18,992",
        "1,564",
        "DeserializeOwned",
        "deserialize_any",
        "trailing bytes",
        "1 MiB",
        "128 recursive levels",
        "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay",
        "does not execute serialization round trips",
    ] {
        assert!(
            docs.contains(marker),
            "typed-format documentation missing marker: {marker}"
        );
    }

    let snapshot_docs = read_repo_file(SNAPSHOT_DOC_PATH);
    for marker in [
        "# Runtime snapshot codec",
        "52-byte header",
        "`ASUPSNAP`",
        "Schema version 2",
        "## Full and incremental artifacts",
        "`SnapshotLimits::DEFAULT`",
        "Reversible migration",
        "`asupersync::fs::write_atomic`",
        "[ASUP-E404]",
        "does not prove an external historical corpus",
    ] {
        assert!(
            snapshot_docs.contains(marker),
            "runtime-snapshot documentation missing marker: {marker}"
        );
    }
}

#[test]
fn malformed_registry_fixtures_fail_closed() {
    let baseline = registry();

    let mut missing_root = baseline.clone();
    missing_root["scan_profile"]["roots"]
        .as_array_mut()
        .expect("roots must be an array")
        .pop();
    assert!(
        validate_registry_shape(&missing_root)
            .expect_err("missing scan root must fail")
            .contains("scan_profile.roots")
    );

    let mut changed_discriminant = baseline.clone();
    find_by_id_mut(
        changed_discriminant["format_profiles"]
            .as_array_mut()
            .expect("format_profiles must be an array"),
        "format",
        "Bincode",
    )["discriminant"] = Value::from(7);
    assert!(
        validate_registry_shape(&changed_discriminant)
            .expect_err("changed discriminant must fail")
            .contains("discriminants")
    );

    let mut changed_config = baseline.clone();
    find_by_id_mut(
        changed_config["format_profiles"]
            .as_array_mut()
            .expect("format_profiles must be an array"),
        "format",
        "Bincode",
    )["canonical_ordering"] = Value::from("configuration unspecified");
    assert!(
        validate_registry_shape(&changed_config)
            .expect_err("missing legacy config must fail")
            .contains("Bincode")
    );

    let mut missing_reader = baseline.clone();
    find_by_id_mut(
        missing_reader["persisted_surfaces"]
            .as_array_mut()
            .expect("persisted_surfaces must be an array"),
        "surface_id",
        "PERSIST-TRACE-FILE",
    )["readers"] = Value::Array(Vec::new());
    assert!(
        validate_registry_shape(&missing_reader)
            .expect_err("missing downstream reader must fail")
            .contains("readers")
    );

    let mut promoted_custom = baseline.clone();
    find_by_id_mut(
        promoted_custom["format_profiles"]
            .as_array_mut()
            .expect("format_profiles must be an array"),
        "format",
        "Custom",
    )["state"] = Value::from("BASELINE_EXISTING");
    assert!(
        validate_registry_shape(&promoted_custom)
            .expect_err("finite Custom evidence must not be promoted to a general baseline")
            .contains("Custom")
    );

    let mut invalid_disposition = baseline.clone();
    find_by_id_mut(
        invalid_disposition["generic_dependency_decisions"]
            .as_array_mut()
            .expect("generic_dependency_decisions must be an array"),
        "format",
        "MessagePack",
    )["disposition"] = Value::from("DISCARD");
    assert!(
        validate_registry_shape(&invalid_disposition)
            .expect_err("unregistered dependency disposition must fail")
            .contains("disposition")
    );

    let mut missing_golden = baseline.clone();
    find_by_id_mut(
        missing_golden["generic_dependency_decisions"]
            .as_array_mut()
            .expect("generic_dependency_decisions must be an array"),
        "format",
        "Bincode",
    )["exact_payload_golden"] = Value::Null;
    assert!(
        validate_registry_shape(&missing_golden)
            .expect_err("missing binary golden must fail")
            .contains("exact_payload_golden")
    );

    let mut unjustified_replacement = baseline.clone();
    find_by_id_mut(
        unjustified_replacement["generic_dependency_decisions"]
            .as_array_mut()
            .expect("generic_dependency_decisions must be an array"),
        "format",
        "MessagePack",
    )["disposition"] = Value::from("REPLACE");
    assert!(
        validate_registry_shape(&unjustified_replacement)
            .expect_err("REPLACE without parity evidence must fail")
            .contains("replacement_parity")
    );

    let mut invalid_historical_state = baseline;
    find_by_id_mut(
        invalid_historical_state["downstream_consumers"]
            .as_array_mut()
            .expect("downstream_consumers must be an array"),
        "consumer_id",
        "CONSUMER-EXTERNAL-HISTORICAL-ARTIFACTS",
    )["state"] = Value::from("ASSUMED_COMPATIBLE");
    assert!(
        validate_registry_shape(&invalid_historical_state)
            .expect_err("unregistered historical evidence state must fail")
            .contains("evidence state")
    );
}
