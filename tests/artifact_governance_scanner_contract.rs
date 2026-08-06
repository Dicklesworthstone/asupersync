#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const SCANNER_PATH: &str = "artifacts/artifact_governance_scanner_v1.json";
const REPORT_PATH: &str = "docs/proof/artifact_governance_scanner.md";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.2";

const PATH_ALIAS_MEMBERS: &[&str] = &[
    "artifacts/base64_capability_inventory_v1.json",
    "artifacts/dependency_capability_baseline_v1.json",
    "artifacts/dependency_phase1_aggregate_signoff_v1.json",
    "artifacts/hex_capability_inventory_v1.json",
];

const PATH_ALIAS_EDGES: &[(&str, &str)] = &[
    (
        "artifacts/base64_capability_inventory_v1.json",
        "artifacts/dependency_capability_baseline_v1.json",
    ),
    (
        "artifacts/dependency_capability_baseline_v1.json",
        "artifacts/base64_capability_inventory_v1.json",
    ),
    (
        "artifacts/dependency_capability_baseline_v1.json",
        "artifacts/dependency_phase1_aggregate_signoff_v1.json",
    ),
    (
        "artifacts/dependency_capability_baseline_v1.json",
        "artifacts/hex_capability_inventory_v1.json",
    ),
    (
        "artifacts/dependency_phase1_aggregate_signoff_v1.json",
        "artifacts/dependency_capability_baseline_v1.json",
    ),
    (
        "artifacts/hex_capability_inventory_v1.json",
        "artifacts/dependency_capability_baseline_v1.json",
    ),
];

const HISTORICAL_BASELINE_SHA256: &str =
    "88575b016105828ce8c1792492355fd34e8a3687ef6be2509e0412dee949cda8";
const HISTORICAL_BASELINE_COMMIT: &str = "7390d33f4ac297cd28138c8e1ece38f60b278660";
const HISTORICAL_BASELINE_BLOB_OID: &str = "4e56ad4bc05dbd1614583f8cdf8586a0d1f88cc7";

const REQUIRED_CATEGORIES: &[&str] = &[
    "exact_ownership",
    "inferred_ownership",
    "orphan",
    "ambiguous",
    "stale",
    "excluded",
];

const REQUIRED_CONFIDENCE_KINDS: &[&str] = &[
    "exact_bead_id_field",
    "domain_specific_owner_field",
    "proof_manifest_source_path",
    "proof_status_lane_mapping",
    "readme_agents_reference",
    "test_constant_path",
    "manual_ledger_override",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn scanner() -> Value {
    serde_json::from_str(&read_repo_file(SCANNER_PATH))
        .unwrap_or_else(|error| panic!("parse {SCANNER_PATH}: {error}"))
}

fn repo_json(path: &str) -> Result<Value, String> {
    serde_json::from_str(&read_repo_file(path)).map_err(|error| format!("parse {path}: {error}"))
}

fn json_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text == needle,
        Value::Array(entries) => entries
            .iter()
            .any(|entry| json_contains_string(entry, needle)),
        Value::Object(fields) => fields
            .values()
            .any(|entry| json_contains_string(entry, needle)),
        _ => false,
    }
}

fn ledger_path_by_row_id() -> Result<BTreeMap<String, String>, String> {
    let ledger = repo_json(LEDGER_PATH)?;
    let mut rows = BTreeMap::new();
    for row in array(&ledger, "rows")? {
        let row_id = string(row, "artifact_id")?.to_owned();
        let path = string(row, "path")?.to_owned();
        if rows.insert(row_id.clone(), path).is_some() {
            return Err(format!("duplicate ledger row {row_id}"));
        }
    }
    Ok(rows)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))?;
    if text.trim().is_empty() {
        return Err(format!("{key} must be nonempty"));
    }
    Ok(text)
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match value.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(Some(text)),
        Some(Value::String(_)) => Err(format!("{key} must be nonempty when set")),
        Some(_) => Err(format!("{key} must be null or string")),
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a bool"))
}

fn u64_field(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be a u64"))
}

fn optional_u64(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(number) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be null or u64")),
    }
}

fn string_set(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    array(value, key)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{key} entries must be nonempty strings"))
        })
        .collect()
}

fn assert_repo_file_exists(path: &str) -> Result<(), String> {
    if repo_path(path).is_file() {
        Ok(())
    } else {
        Err(format!("referenced repo file must exist: {path}"))
    }
}

fn live_file_pin(path: &str) -> Result<(String, u64), String> {
    let bytes = std::fs::read(repo_path(path)).map_err(|error| format!("read {path}: {error}"))?;
    let text = std::str::from_utf8(&bytes).map_err(|error| format!("utf8 {path}: {error}"))?;
    Ok((
        format!("{:x}", Sha256::digest(&bytes)),
        text.lines().count() as u64,
    ))
}

fn collect_member_pin_rows(
    source: &str,
    value: &Value,
    members: &BTreeSet<String>,
    edges: &mut BTreeMap<(String, String), (String, Option<u64>)>,
) -> Result<(), String> {
    match value {
        Value::Array(entries) => {
            for entry in entries {
                collect_member_pin_rows(source, entry, members, edges)?;
            }
        }
        Value::Object(fields) => {
            if let (Some(target), Some(stored_sha256)) = (
                fields.get("path").and_then(Value::as_str),
                fields.get("sha256").and_then(Value::as_str),
            ) {
                if members.contains(target) {
                    let key = (source.to_owned(), target.to_owned());
                    let line_count = match fields.get("line_count") {
                        Some(Value::Null) | None => None,
                        Some(value) => Some(value.as_u64().ok_or_else(|| {
                            format!("{source} -> {target}: line_count must be u64")
                        })?),
                    };
                    if edges
                        .insert(key.clone(), (stored_sha256.to_owned(), line_count))
                        .is_some()
                    {
                        return Err(format!(
                            "duplicate full-file hash edge {} -> {}",
                            key.0, key.1
                        ));
                    }
                }
            }
            for entry in fields.values() {
                collect_member_pin_rows(source, entry, members, edges)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reachable_members(start: &str, edges: &BTreeSet<(String, String)>) -> BTreeSet<String> {
    let mut reachable = BTreeSet::from([start.to_owned()]);
    let mut frontier = vec![start.to_owned()];
    while let Some(source) = frontier.pop() {
        for (_, target) in edges.iter().filter(|(candidate, _)| candidate == &source) {
            if reachable.insert(target.clone()) {
                frontier.push(target.clone());
            }
        }
    }
    reachable
}

fn validate_reference_integrity(scan: &Value) -> Result<(), String> {
    let audit = object(scan, "artifact_reference_integrity")?;
    let audit_value = Value::Object(audit.clone());
    if string(&audit_value, "audit_id")? != "artifact-full-file-hash-versioned-topology-2026-08-05"
    {
        return Err("unexpected reference-integrity audit_id".to_owned());
    }
    if bool_field(&audit_value, "full_artifact_corpus_claim")? {
        return Err("reference audit must not claim full artifact corpus coverage".to_owned());
    }
    if string(&audit_value, "finding_state")?
        != "PASS_NO_CONTENT_ADDRESSED_CYCLE_WITH_PATH_ALIAS_WARNING"
    {
        return Err("reference audit must distinguish path aliases from content cycles".to_owned());
    }

    let graph_model = object(&audit_value, "graph_model")?;
    let graph_model_value = Value::Object(graph_model.clone());
    for (field, required) in [
        ("path_collapsed_node_identity", "path"),
        ("content_addressed_node_identity", "SHA-256"),
        ("edge_origin_identity", "source artifact SHA-256"),
        (
            "historical_target_rule",
            "immutable commit and blob receipt",
        ),
        ("active_cycle_rule", "content-addressed nodes"),
    ] {
        if !string(&graph_model_value, field)?.contains(required) {
            return Err(format!(
                "reference graph model {field} must mention {required}"
            ));
        }
    }

    let receipt = object(&audit_value, "discovery_receipt")?;
    let receipt_value = Value::Object(receipt.clone());
    if string(&receipt_value, "capture_commit")? != "15391290dce5d259bf491e676d35f3d46564935a"
        || string(&receipt_value, "execution_state")? != "STATIC_READ_ONLY"
        || u64_field(&receipt_value, "tracked_json_document_count")? != 354
        || u64_field(&receipt_value, "parse_failure_count")? != 0
        || u64_field(&receipt_value, "unique_full_file_hash_edge_count")? != 199
        || u64_field(&receipt_value, "unique_reference_path_count")? != 105
        || u64_field(&receipt_value, "path_collapsed_cyclic_component_count")? != 1
        || u64_field(&receipt_value, "content_addressed_cyclic_component_count")? != 0
    {
        return Err("reference-integrity discovery receipt drifted".to_owned());
    }

    let members = string_set(&audit_value, "path_collapsed_component_members")?;
    let expected_members = PATH_ALIAS_MEMBERS
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<BTreeSet<_>>();
    if members != expected_members {
        return Err("path-collapsed reference member set drifted".to_owned());
    }

    let mut discovered = BTreeMap::new();
    for source in &members {
        let source_json = repo_json(source)?;
        collect_member_pin_rows(source, &source_json, &members, &mut discovered)?;
    }
    let expected_edges = PATH_ALIAS_EDGES
        .iter()
        .map(|(source, target)| ((*source).to_owned(), (*target).to_owned()))
        .collect::<BTreeSet<_>>();
    let discovered_edges = discovered.keys().cloned().collect::<BTreeSet<_>>();
    if discovered_edges != expected_edges {
        return Err("versioned reference edge set drifted".to_owned());
    }

    let mut declared_edges = BTreeSet::new();
    let mut path_alias_edges: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    let mut content_edges = BTreeSet::new();
    let mut historical_edge_count = 0_u64;
    let mut current_edge_count = 0_u64;
    for edge in array(&audit_value, "edges")? {
        let source = string(edge, "source_artifact")?.to_owned();
        let target = string(edge, "target_artifact")?.to_owned();
        let key = (source.clone(), target.clone());
        if !declared_edges.insert(key.clone()) {
            return Err(format!(
                "duplicate declared reference edge {source} -> {target}"
            ));
        }
        let (stored_sha256, stored_line_count) = discovered
            .get(&key)
            .ok_or_else(|| format!("undeclared source pin {source} -> {target}"))?;
        if string(edge, "stored_target_sha256")? != stored_sha256.as_str()
            || optional_u64(edge, "stored_target_line_count")? != *stored_line_count
        {
            return Err(format!("{source} -> {target}: stored pin drifted"));
        }

        let (live_source_sha256, _) = live_file_pin(&source)?;
        if string(edge, "source_artifact_sha256")? != live_source_sha256.as_str() {
            return Err(format!(
                "{source} -> {target}: live source identity drifted"
            ));
        }
        let (live_sha256, live_line_count) = live_file_pin(&target)?;
        if string(edge, "live_target_sha256")? != live_sha256.as_str()
            || u64_field(edge, "live_target_line_count")? != live_line_count
        {
            return Err(format!("{source} -> {target}: live target pin drifted"));
        }
        let expected_state = if stored_sha256 == &live_sha256 {
            "current"
        } else {
            "historical"
        };
        if string(edge, "pin_state_at_capture")? != expected_state {
            return Err(format!("{source} -> {target}: pin state drifted"));
        }

        let expected_classification = if expected_state == "current" {
            current_edge_count += 1;
            "current_forward_reference"
        } else {
            historical_edge_count += 1;
            "historical_back_reference"
        };
        if string(edge, "edge_classification")? != expected_classification {
            return Err(format!("{source} -> {target}: edge classification drifted"));
        }

        let source_node = format!("{source}@{live_source_sha256}");
        let target_node = format!("{target}@{stored_sha256}");
        if string(edge, "source_node")? != source_node.as_str()
            || string(edge, "target_node")? != target_node.as_str()
        {
            return Err(format!("{source} -> {target}: content identity drifted"));
        }
        content_edges.insert((source_node, target_node));
        path_alias_edges
            .entry(string(edge, "path_alias_id")?.to_owned())
            .or_default()
            .insert(key);
    }
    if declared_edges != expected_edges
        || u64_field(&audit_value, "path_collapsed_component_edge_count")?
            != declared_edges.len() as u64
    {
        return Err("versioned reference edge set drifted".to_owned());
    }
    if u64_field(&audit_value, "path_collapsed_simple_two_edge_cycle_count")? != 3
        || path_alias_edges.len() != 3
    {
        return Err("path-collapsed alias count drifted".to_owned());
    }
    for (alias_id, pairs) in path_alias_edges {
        if pairs.len() != 2
            || !pairs
                .iter()
                .all(|(source, target)| pairs.contains(&(target.clone(), source.clone())))
        {
            return Err(format!("{alias_id}: expected one reciprocal path alias"));
        }
    }
    for member in &members {
        if reachable_members(member, &declared_edges) != members {
            return Err(format!(
                "{member}: path-collapsed component is not strongly connected"
            ));
        }
    }

    let content_nodes = content_edges
        .iter()
        .flat_map(|(source, target)| [source.clone(), target.clone()])
        .collect::<BTreeSet<_>>();
    if u64_field(&audit_value, "content_addressed_node_count")? != content_nodes.len() as u64
        || u64_field(&audit_value, "content_addressed_edge_count")? != content_edges.len() as u64
        || historical_edge_count != 3
        || current_edge_count != 3
    {
        return Err("content-addressed topology count drifted".to_owned());
    }
    if content_edges
        .iter()
        .any(|(source, target)| reachable_members(target, &content_edges).contains(source))
    {
        return Err("content-addressed reference graph must remain acyclic".to_owned());
    }

    let historical = object(&audit_value, "historical_target_receipt")?;
    let historical_value = Value::Object(historical.clone());
    if string(&historical_value, "target_artifact")?
        != "artifacts/dependency_capability_baseline_v1.json"
        || string(&historical_value, "target_sha256")? != HISTORICAL_BASELINE_SHA256
        || u64_field(&historical_value, "target_line_count")? != 1357
        || string(&historical_value, "commit")? != HISTORICAL_BASELINE_COMMIT
        || string(&historical_value, "blob_oid")? != HISTORICAL_BASELINE_BLOB_OID
        || string(&historical_value, "verification_state")? != "STATIC_GIT_OBJECT_RESOLVED"
    {
        return Err("historical baseline object receipt drifted".to_owned());
    }

    let resolution = object(&audit_value, "resolution")?;
    let resolution_value = Value::Object(resolution.clone());
    if string(&resolution_value, "resolution_state")?
        != "HISTORICAL_BACK_REFERENCES_RESOLVED_TO_IMMUTABLE_GIT_OBJECT"
        || u64_field(&resolution_value, "minimum_full_file_edges_to_replace")? != 0
        || string(&resolution_value, "resolved_by")? != "immutable_commit_or_blob_provenance"
    {
        return Err("versioned-reference resolution drifted".to_owned());
    }
    let rule = string(&resolution_value, "operator_rule")?;
    for required in [
        "historical back-references",
        "do not refresh",
        "content-addressed",
    ] {
        if !rule.contains(required) {
            return Err(format!(
                "versioned-reference operator rule must mention {required}"
            ));
        }
    }
    let boundaries = string_set(&audit_value, "no_claim_boundaries")?;
    for required in [
        "does_not_prove_full_corpus_coverage",
        "does_not_make_historical_pins_current",
        "does_not_authorize_blind_hash_refresh",
        "does_not_prove_git_history_is_available_in_every_checkout",
        "does_not_prove_executable_contract_pass",
    ] {
        if !boundaries.contains(required) {
            return Err(format!("missing reference-integrity boundary {required}"));
        }
    }

    Ok(())
}

fn validate_source_match(source: &Value) -> Result<(String, String), String> {
    let kind = string(source, "kind")?;
    let path = string(source, "path")?;
    let needle = string(source, "match")?;
    assert_repo_file_exists(path)?;
    let haystack = read_repo_file(path);
    if !haystack.contains(needle) {
        return Err(format!("{path} does not contain scanner match {needle}"));
    }
    Ok((kind.to_owned(), path.to_owned()))
}

fn validate_scanner(scan: &Value) -> Result<(), String> {
    if scan.get("schema_version").and_then(Value::as_str) != Some("artifact-governance-scanner-v1")
    {
        return Err("unexpected schema_version".to_owned());
    }
    if scan.get("bead_id").and_then(Value::as_str) != Some(BEAD_ID) {
        return Err("unexpected bead_id".to_owned());
    }

    for path in object(scan, "source_of_truth")?.values().map(|value| {
        value
            .as_str()
            .ok_or("source_of_truth values must be strings")
    }) {
        assert_repo_file_exists(path.map_err(str::to_owned)?)?;
    }

    let coverage = object(scan, "coverage_policy")?;
    if bool_field(&Value::Object(coverage.clone()), "full_corpus_claim")? {
        return Err("scanner must not claim full corpus coverage".to_owned());
    }
    if !bool_field(&Value::Object(coverage.clone()), "non_destructive")? {
        return Err("scanner must be non-destructive".to_owned());
    }
    let parser_policy = string(&Value::Object(coverage.clone()), "parser_policy")?.to_owned();
    for required in ["JSON", "does not rewrite", "delete"] {
        if !parser_policy.contains(required) {
            return Err(format!("parser_policy must mention {required}"));
        }
    }

    validate_reference_integrity(scan)?;

    let confidence_catalog = object(scan, "confidence_catalog")?;
    let confidence_keys = confidence_catalog
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_confidence = REQUIRED_CONFIDENCE_KINDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if confidence_keys != expected_confidence {
        return Err("confidence catalog drifted".to_owned());
    }
    let mut ranks = BTreeSet::new();
    for kind in REQUIRED_CONFIDENCE_KINDS {
        let entry = object(&scan["confidence_catalog"], kind)?;
        string(&Value::Object(entry.clone()), "meaning")?;
        string(&Value::Object(entry.clone()), "false_positive_boundary")?;
        let rank = entry
            .get("rank")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{kind} rank must be u64"))?;
        if !ranks.insert(rank) {
            return Err(format!("duplicate confidence rank {rank}"));
        }
    }

    let category_catalog = object(scan, "category_catalog")?;
    let categories = category_catalog
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_categories = REQUIRED_CATEGORIES.iter().copied().collect::<BTreeSet<_>>();
    if categories != expected_categories {
        return Err("category catalog drifted".to_owned());
    }
    for category in REQUIRED_CATEGORIES {
        let entry = object(&scan["category_catalog"], category)?;
        string(&Value::Object(entry.clone()), "meaning")?;
        string(&Value::Object(entry.clone()), "scanner_rule")?;
        for boundary in string_set(&Value::Object(entry.clone()), "no_claim_boundaries")? {
            if !boundary.starts_with("does_not_") {
                return Err(format!(
                    "{category}: no-claim boundary must be does_not token"
                ));
            }
        }
    }

    let rows = array(scan, "rows")?;
    let ledger_paths = ledger_path_by_row_id()?;
    let mut last_sort_key = String::new();
    let mut paths = BTreeSet::new();
    let mut category_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut confidence_seen = BTreeSet::new();

    for row in rows {
        let path = string(row, "artifact_path")?;
        let category = string(row, "category")?;
        if !category_catalog.contains_key(category) {
            return Err(format!("{path}: unknown category {category}"));
        }
        let sort_key = format!("{path}\0{category}");
        if !last_sort_key.is_empty() && sort_key <= last_sort_key {
            return Err(format!("{path}: rows must use stable bytewise order"));
        }
        last_sort_key = sort_key;
        if !paths.insert(path.to_owned()) {
            return Err(format!("duplicate artifact_path {path}"));
        }

        if category == "excluded" {
            if optional_string(row, "exclusion_reason")?.is_none() {
                return Err(format!("{path}: excluded row needs exclusion_reason"));
            }
        } else {
            assert_repo_file_exists(path)?;
            if optional_string(row, "exclusion_reason")?.is_some() {
                return Err(format!(
                    "{path}: non-excluded row must not carry exclusion_reason"
                ));
            }
        }

        let ownership = object(row, "ownership")?;
        let ownership_value = Value::Object(ownership.clone());
        let bead_ids = string_set(&ownership_value, "bead_ids")?;
        if bead_ids.is_empty() {
            return Err(format!("{path}: ownership bead_ids must not be empty"));
        }
        let confidence_level = string(&ownership_value, "confidence_level")?;
        if !confidence_catalog.contains_key(confidence_level) {
            return Err(format!(
                "{path}: unknown confidence level {confidence_level}"
            ));
        }
        for source in array(&ownership_value, "confidence_sources")? {
            let (kind, source_path) = validate_source_match(source)?;
            if !confidence_catalog.contains_key(&kind) {
                return Err(format!("{path}: unknown confidence source kind {kind}"));
            }
            match kind.as_str() {
                "exact_bead_id_field" => {
                    let source_json = repo_json(&source_path)?;
                    let source_bead = string(&source_json, "bead_id")?;
                    if !bead_ids.contains(source_bead) {
                        return Err(format!(
                            "{path}: exact bead_id {source_bead} not listed in ownership"
                        ));
                    }
                }
                "domain_specific_owner_field" => {
                    let source_json = repo_json(&source_path)?;
                    let source_bead = string(&source_json, "track_bead_id")?;
                    if !bead_ids.contains(source_bead) {
                        return Err(format!(
                            "{path}: track_bead_id {source_bead} not listed in ownership"
                        ));
                    }
                }
                "proof_manifest_source_path" => {
                    let manifest = repo_json(&source_path)?;
                    if !json_contains_string(&manifest, path) {
                        return Err(format!(
                            "{path}: proof manifest source does not contain artifact path"
                        ));
                    }
                }
                "manual_ledger_override" if array(row, "ledger_rows")?.is_empty() => {
                    return Err(format!(
                        "{path}: manual ledger override requires ledger_rows"
                    ));
                }
                _ => {}
            }
            confidence_seen.insert(kind);
        }

        for ledger_row in array(row, "ledger_rows")? {
            let ledger_row = ledger_row
                .as_str()
                .ok_or_else(|| format!("{path}: ledger_rows entries must be strings"))?;
            let ledger_path = ledger_paths
                .get(ledger_row)
                .ok_or_else(|| format!("{path}: unknown ledger row {ledger_row}"))?;
            if ledger_path != path {
                return Err(format!(
                    "{path}: ledger row {ledger_row} points to {ledger_path}"
                ));
            }
        }

        for test_path in array(row, "checked_by_tests")? {
            assert_repo_file_exists(
                test_path
                    .as_str()
                    .ok_or("checked_by_tests entries must be strings")?,
            )?;
        }
        for doc_path in array(row, "docs_references")? {
            assert_repo_file_exists(
                doc_path
                    .as_str()
                    .ok_or("docs_references entries must be strings")?,
            )?;
        }
        for boundary in string_set(row, "no_claim_boundaries")? {
            if !boundary.starts_with("does_not_") {
                return Err(format!("{path}: no-claim boundary must be does_not token"));
            }
        }

        match category {
            "orphan" => {
                if !array(row, "ledger_rows")?.is_empty()
                    || !array(row, "proof_manifest_rows")?.is_empty()
                    || !array(row, "proof_status_rows")?.is_empty()
                {
                    return Err(format!(
                        "{path}: orphan rows must not have governance mappings"
                    ));
                }
            }
            "ambiguous" => {
                if bead_ids.len() < 2 {
                    return Err(format!("{path}: ambiguous rows need conflicting owners"));
                }
            }
            "stale" => {
                let successor = optional_string(row, "superseded_by")?
                    .ok_or_else(|| format!("{path}: stale rows need superseded_by"))?;
                if successor == path || !repo_path(successor).is_file() {
                    return Err(format!(
                        "{path}: supersession target must be a different file"
                    ));
                }
                string(row, "stale_reason")?;
            }
            _ => {
                if optional_string(row, "superseded_by")?.is_some() {
                    return Err(format!("{path}: only stale rows may carry superseded_by"));
                }
            }
        }

        *category_counts.entry(category.to_owned()).or_default() += 1;
    }

    let summary = object(scan, "summary")?;
    if summary.get("row_count").and_then(Value::as_u64) != Some(rows.len() as u64) {
        return Err("summary row_count drifted".to_owned());
    }
    for category in REQUIRED_CATEGORIES {
        if !category_counts.contains_key(*category) {
            return Err(format!("missing required category {category}"));
        }
        let expected = summary["category_counts"][*category]
            .as_u64()
            .ok_or_else(|| format!("summary missing category {category}"))?;
        if category_counts[*category] != expected {
            return Err(format!("summary count drifted for {category}"));
        }
    }
    for kind in REQUIRED_CONFIDENCE_KINDS {
        if !confidence_seen.contains(*kind) {
            return Err(format!("missing confidence source kind {kind}"));
        }
    }

    Ok(())
}

#[test]
fn scanner_artifact_schema_and_links_are_valid() {
    let scan = scanner();
    validate_scanner(&scan).expect("scanner artifact must satisfy A2 contract");
}

#[test]
fn scanner_report_is_concise_and_matches_artifact_boundaries() {
    let report = read_repo_file(REPORT_PATH);
    for required in [
        SCANNER_PATH,
        BEAD_ID,
        "does not claim full-corpus coverage",
        "never rewrites, moves, or deletes artifacts",
        "orphan",
        "ambiguous",
        "stale",
        "excluded",
        "PASS_NO_CONTENT_ADDRESSED_CYCLE_WITH_PATH_ALIAS_WARNING",
        "content-addressed graph",
        "immutable provenance",
        "does not authorize blind hash refresh",
    ] {
        assert!(
            report.contains(required),
            "scanner report must contain {required}"
        );
    }
}

#[test]
fn scanner_is_registered_in_the_governance_ledger() {
    let ledger: Value = serde_json::from_str(&read_repo_file(LEDGER_PATH)).expect("parse ledger");
    let rows = ledger["rows"].as_array().expect("ledger rows");
    let row = rows
        .iter()
        .find(|row| row["artifact_id"].as_str() == Some("artifact-governance-scanner"))
        .expect("ledger row for scanner");

    assert_eq!(row["path"].as_str(), Some(SCANNER_PATH));
    assert_eq!(row["owning_bead"].as_str(), Some(BEAD_ID));
    assert_eq!(row["artifact_family"].as_str(), Some("artifact_governance"));
    assert_eq!(row["citeability_class"].as_str(), Some("proof-bearing"));
}

#[test]
fn malformed_json_fixture_is_rejected() {
    let error = serde_json::from_str::<Value>("{ not valid json")
        .expect_err("malformed scanner JSON must fail to parse");
    assert!(
        error.to_string().contains("expected")
            || error.to_string().contains("key")
            || error.to_string().contains("EOF"),
        "malformed-json diagnostic should be explicit: {error}"
    );
}

#[test]
fn missing_owner_field_fixture_is_rejected() {
    let mut scan = scanner();
    let first_row = scan["rows"][0]
        .as_object_mut()
        .expect("row object for fixture mutation");
    first_row.remove("ownership");

    let error = validate_scanner(&scan).expect_err("missing ownership should fail");
    assert!(error.contains("ownership"), "unexpected error: {error}");
}

#[test]
fn duplicate_artifact_path_fixture_is_rejected() {
    let mut scan = scanner();
    let duplicate = scan["rows"][0].clone();
    scan["rows"]
        .as_array_mut()
        .expect("rows array")
        .insert(1, duplicate);

    let error = validate_scanner(&scan).expect_err("duplicate path should fail");
    assert!(
        error.contains("duplicate artifact_path") || error.contains("stable bytewise order"),
        "unexpected error: {error}"
    );
}

#[test]
fn self_supersession_fixture_is_rejected() {
    let mut scan = scanner();
    let stale = scan["rows"]
        .as_array_mut()
        .expect("rows array")
        .iter_mut()
        .find(|row| row["category"].as_str() == Some("stale"))
        .expect("stale fixture row");
    let path = stale["artifact_path"].clone();
    stale["superseded_by"] = path;

    let error = validate_scanner(&scan).expect_err("self-supersession should fail");
    assert!(error.contains("supersession"), "unexpected error: {error}");
}

#[test]
fn missing_versioned_reference_edge_fixture_is_rejected() {
    let mut scan = scanner();
    scan["artifact_reference_integrity"]["edges"]
        .as_array_mut()
        .expect("reference edges array")
        .pop();

    let error = validate_scanner(&scan).expect_err("missing reference edge should fail");
    assert!(
        error.contains("versioned reference edge set"),
        "unexpected error: {error}"
    );
}
