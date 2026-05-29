#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const ORACLE_PATH: &str = "artifacts/roundtrip_oracle_v1.json";
const EXPECTED_VERSION: &str = "roundtrip-oracle-v1";
const EXPECTED_BEAD: &str = "asupersync-wr5m5s";
const ENTRY_PREFIX: &str = "roundtrip.";
const CATEGORY_PREFIX: &str = "RoundtripCategory::";
const EXPECTED_PROOF_TARGET: &str = "--test roundtrip_oracle_contract";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> TestResult<String> {
    std::fs::read_to_string(repo_path(relative)).map_err(|err| format!("read {relative}: {err}"))
}

fn oracle() -> TestResult<Value> {
    serde_json::from_str(&read_repo_file(ORACLE_PATH)?)
        .map_err(|err| format!("parse {ORACLE_PATH}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))?;
    if text.trim().is_empty() {
        return Err(format!("{key} must be nonempty"));
    }
    Ok(text)
}

fn bool_field(value: &Value, key: &str) -> TestResult<bool> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a bool"))
}

fn string_vec(value: &Value, key: &str) -> TestResult<Vec<String>> {
    array(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{key} entries must be strings"))
        })
        .collect()
}

fn required_categories() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "RoundtripCategory::TypedIdSerde",
        "RoundtripCategory::WasmAbiSerde",
        "RoundtripCategory::RegionSnapshotBinary",
        "RoundtripCategory::TraceEventSerde",
        "RoundtripCategory::OracleReportSerde",
        "RoundtripCategory::CrashpackReplaySerde",
        "RoundtripCategory::ScenarioSerde",
        "RoundtripCategory::CodecFrame",
        "RoundtripCategory::ProtocolEnvelope",
        "RoundtripCategory::MessagingConfig",
        "RoundtripCategory::RaptorQEncodeDecode",
        "RoundtripCategory::TlaProjection",
        "RoundtripCategory::RedisResp3Wire",
    ])
}

#[test]
fn oracle_identity_and_rules_are_pinned() -> TestResult {
    let oracle = oracle()?;
    assert_eq!(string(&oracle, "contract_version")?, EXPECTED_VERSION);
    assert_eq!(string(&oracle, "bead_id")?, EXPECTED_BEAD);

    let source = Value::Object(object(&oracle, "source_of_truth")?.clone());
    assert_eq!(string(&source, "artifact")?, ORACLE_PATH);
    assert_eq!(
        string(&source, "contract_test")?,
        "tests/roundtrip_oracle_contract.rs"
    );
    let proof_command = string(&source, "proof_command")?;
    assert!(
        proof_command.starts_with("rch exec -- env "),
        "proof command must run through rch: {proof_command}"
    );
    assert!(
        proof_command.contains(EXPECTED_PROOF_TARGET),
        "proof command must target this contract: {proof_command}"
    );

    let rules = Value::Object(object(&oracle, "oracle_rules")?.clone());
    assert_eq!(string(&rules, "entry_id_prefix")?, ENTRY_PREFIX);
    assert_eq!(string(&rules, "category_prefix")?, CATEGORY_PREFIX);
    assert!(bool_field(&rules, "source_paths_are_repo_relative")?);
    assert!(bool_field(&rules, "source_markers_must_exist")?);
    assert!(bool_field(&rules, "proof_command_must_use_rch")?);
    assert!(bool_field(&rules, "risk_focus_must_be_nonempty")?);
    assert!(bool_field(&rules, "equality_oracle_must_be_nonempty")?);
    Ok(())
}

#[test]
fn categories_are_complete_unique_and_grepable() -> TestResult {
    let oracle = oracle()?;
    let mut seen = BTreeSet::new();

    for category in array(&oracle, "roundtrip_categories")? {
        let tag = string(category, "tag")?;
        assert!(
            tag.starts_with(CATEGORY_PREFIX),
            "category must be grep-able with {CATEGORY_PREFIX}: {tag}"
        );
        assert!(
            tag[CATEGORY_PREFIX.len()..]
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric()),
            "category suffix should be stable ASCII identifier text: {tag}"
        );
        assert!(!string(category, "description")?.is_empty());
        assert!(seen.insert(tag.to_string()), "duplicate category {tag}");
    }

    let expected: BTreeSet<String> = required_categories()
        .into_iter()
        .map(str::to_string)
        .collect();
    assert_eq!(seen, expected, "RoundtripCategory tag set drifted");
    Ok(())
}

#[test]
fn roundtrip_entries_are_source_backed_and_category_covered() -> TestResult {
    let oracle = oracle()?;
    let categories: BTreeSet<String> = array(&oracle, "roundtrip_categories")?
        .iter()
        .map(|category| string(category, "tag").map(str::to_string))
        .collect::<TestResult<_>>()?;

    let mut entry_ids = BTreeSet::new();
    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();

    for entry in array(&oracle, "roundtrip_entries")? {
        let entry_id = string(entry, "entry_id")?;
        assert!(
            entry_id.starts_with(ENTRY_PREFIX),
            "entry ids must be grep-able and namespaced: {entry_id}"
        );
        assert!(
            entry_ids.insert(entry_id.to_string()),
            "duplicate entry id {entry_id}"
        );

        let category = string(entry, "category")?;
        assert!(
            categories.contains(category),
            "{entry_id} references undefined category {category}"
        );
        *category_counts.entry(category.to_string()).or_insert(0) += 1;

        assert!(!string(entry, "encoder")?.is_empty());
        assert!(!string(entry, "decoder")?.is_empty());
        assert!(!string(entry, "equality_oracle")?.is_empty());
        assert!(!string(entry, "proof_surface")?.is_empty());
        assert!(
            !string_vec(entry, "risk_focus")?.is_empty(),
            "{entry_id} must name at least one risk focus"
        );

        let source_paths = string_vec(entry, "source_paths")?;
        assert!(!source_paths.is_empty(), "{entry_id} must cite sources");
        let source_texts: TestResult<Vec<String>> = source_paths
            .iter()
            .map(|path| {
                assert!(
                    !path.starts_with('/'),
                    "{entry_id} path must be repo-relative: {path}"
                );
                assert!(
                    repo_path(path).is_file(),
                    "{entry_id} missing source path {path}"
                );
                read_repo_file(path)
            })
            .collect();
        let source_texts = source_texts?;

        for marker in string_vec(entry, "markers")? {
            assert!(
                source_texts.iter().any(|source| source.contains(&marker)),
                "{entry_id} marker {marker:?} was not found in any source path"
            );
        }
    }

    for category in categories {
        assert!(
            category_counts.get(&category).copied().unwrap_or_default() > 0,
            "{category} must have at least one cataloged roundtrip"
        );
    }
    Ok(())
}

#[test]
fn required_runtime_roundtrips_are_cataloged() -> TestResult {
    let oracle = oracle()?;
    let actual_ids: BTreeSet<String> = array(&oracle, "roundtrip_entries")?
        .iter()
        .map(|entry| string(entry, "entry_id").map(str::to_string))
        .collect::<TestResult<_>>()?;

    for required in string_vec(&oracle, "required_entry_ids")? {
        assert!(
            actual_ids.contains(&required),
            "missing required roundtrip entry {required}"
        );
    }

    for required in [
        "roundtrip.types.ids_serde_json",
        "roundtrip.distributed.region_snapshot_binary",
        "roundtrip.trace.event_json",
        "roundtrip.codec.grpc_message_frame",
        "roundtrip.raptorq.rfc6330_encode_decode",
        "roundtrip.tla.trace_export_projection",
    ] {
        assert!(
            actual_ids.contains(required),
            "missing critical roundtrip {required}"
        );
    }
    Ok(())
}
