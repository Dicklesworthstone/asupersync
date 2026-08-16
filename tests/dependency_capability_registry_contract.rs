//! Fail-closed capability-preservation contract for dependency sovereignty.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.5.1
//! Scenario: dependency_capability_registry_contract_v1
//! Fixture: artifacts/dependency_capability_registry_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.5.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const API_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const CUTOVER_POLICY_PATH: &str = "artifacts/dependency_cutover_policy_v1.json";
const ERROR_REGISTRY_PATH: &str = "docs/error_codes/registry.json";
const DOC_PATH: &str = "docs/dependency_capability_registry.md";
const MANIFEST_PATH: &str = "Cargo.toml";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const GENERATED_BEGIN: &str = "<!-- BEGIN GENERATED CAPABILITY SUMMARY -->";
const GENERATED_END: &str = "<!-- END GENERATED CAPABILITY SUMMARY -->";
const SCENARIO_ID: &str = "dependency_capability_registry_contract_v1";
const CAP_A4_BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.5.4";
const AUTHORITY_MARKER: &str = "REV-4 CAPABILITY AUTHORITY";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\"${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_capability_registry\" cargo test -p asupersync --test dependency_capability_registry_contract -- --nocapture";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn registry() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    let nested = value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"));
    assert!(nested.is_object(), "{key} must be an object");
    nested
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn nonempty_string(value: &Value, key: &str, errors: &mut Vec<String>, context: &str) {
    if value
        .get(key)
        .and_then(Value::as_str)
        .is_none_or(|text| text.trim().is_empty())
    {
        errors.push(format!("{context}: {key} must be a nonempty string"));
    }
}

fn nonempty_string_array(value: &Value, key: &str, errors: &mut Vec<String>, context: &str) {
    let Some(entries) = value.get(key).and_then(Value::as_array) else {
        errors.push(format!("{context}: {key} must be an array"));
        return;
    };
    if entries.is_empty()
        || entries
            .iter()
            .any(|entry| entry.as_str().is_none_or(|text| text.trim().is_empty()))
    {
        errors.push(format!("{context}: {key} must contain nonempty strings"));
    }
}

fn capability_ids(registry: &Value) -> BTreeSet<String> {
    array(registry, "capabilities")
        .iter()
        .map(|row| string(row, "capability_id").to_owned())
        .collect()
}

fn tracker_issues() -> Vec<Value> {
    read_repo_file(TRACKER_PATH)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{TRACKER_PATH} contains invalid JSONL: {error}"))
        })
        .collect()
}

fn tracker_ids() -> BTreeSet<String> {
    tracker_issues()
        .iter()
        .map(|issue| string(issue, "id").to_owned())
        .collect()
}

fn issue_has_label(issue: &Value, wanted: &str) -> bool {
    issue
        .get("labels")
        .and_then(Value::as_array)
        .is_some_and(|labels| labels.iter().any(|label| label.as_str() == Some(wanted)))
}

fn path_exists(path: &str) -> bool {
    if Path::new(path).is_absolute() {
        Path::new(path).exists()
    } else {
        repo_root().join(path).exists()
    }
}

/// Package names resolved by `Cargo.lock`. A `dependency_owners` entry that is
/// neither one of these nor a declared non-crate owner does not exist.
fn locked_package_names() -> BTreeSet<String> {
    read_repo_file("Cargo.lock")
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

/// Cargo package names differ from crate paths by `-` vs `_`; accept either.
fn resolves_to_package(owner: &str, packages: &BTreeSet<String>) -> bool {
    packages.contains(owner)
        || packages.contains(&owner.replace('_', "-"))
        || packages.contains(&owner.replace('-', "_"))
}

/// Whole-token search for a crate's use sites: `foo::` or `use foo`. Matching
/// the bare word would let a comment or an unrelated identifier satisfy the
/// attribution check, which is the failure mode this exists to catch.
fn references_crate(source: &str, krate: &str) -> bool {
    let token = krate.replace('-', "_");
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0usize;
    while let Some(offset) = source[from..].find(&token) {
        let start = from + offset;
        let end = start + token.len();
        let before_ok = start == 0 || !source[..start].chars().next_back().is_some_and(is_ident);
        if before_ok {
            let after = source[end..].trim_start();
            let preceded_by_use = source[..start]
                .trim_end()
                .rsplit(['\n', ';'])
                .next()
                .is_some_and(|segment| segment.trim() == "use");
            if after.starts_with("::") || preceded_by_use {
                return true;
            }
        }
        from = start + 1;
    }
    false
}

/// Capability ids exempted from the source-owner attribution check, with the
/// reason. An exemption is only legitimate for a genuinely cross-cutting
/// dependency where no short file list would be true.
fn attribution_exemptions(registry: &Value) -> BTreeMap<String, String> {
    array(registry, "source_owner_attribution_exemptions")
        .iter()
        .map(|row| {
            (
                string(row, "capability_id").to_owned(),
                string(row, "reason").to_owned(),
            )
        })
        .collect()
}

/// Declared non-crate `dependency_owners` — sentinels, external tools, bundled
/// native libraries and std. Declaring them keeps the resolution check
/// fail-closed for everything else.
fn declared_non_crate_owners(registry: &Value) -> BTreeMap<String, String> {
    array(registry, "allowed_non_crate_dependency_owners")
        .iter()
        .map(|row| {
            (
                string(row, "owner").to_owned(),
                string(row, "reason").to_owned(),
            )
        })
        .collect()
}

/// True when the row names at least one real crate and at least one `.rs`
/// source owner, but no named source file actually references any of those
/// crates. This is the check that catches a row naming a `mod.rs` facade, or
/// the wrong one of two same-named files.
fn source_owner_attribution_fails(
    row: &Value,
    packages: &BTreeSet<String>,
    non_crate: &BTreeMap<String, String>,
) -> bool {
    let crates: Vec<String> = strings(row, "dependency_owners")
        .into_iter()
        .filter(|owner| !non_crate.contains_key(owner) && resolves_to_package(owner, packages))
        .collect();
    let sources: Vec<String> = strings(row, "source_owners")
        .into_iter()
        .filter(|source| {
            Path::new(source)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        })
        .collect();
    if crates.is_empty() || sources.is_empty() {
        return false;
    }
    !sources.iter().any(|source| {
        std::fs::read_to_string(repo_root().join(source)).is_ok_and(|text| {
            crates
                .iter()
                .any(|krate| references_crate(&text, krate.as_str()))
        })
    })
}

fn validate_capability_row(
    registry: &Value,
    row: &Value,
    known_features: &BTreeSet<String>,
    known_beads: &BTreeSet<String>,
) -> Vec<String> {
    let capability_id = row
        .get("capability_id")
        .and_then(Value::as_str)
        .unwrap_or("<missing-capability-id>");
    let mut errors = Vec::new();

    for field in array(registry, "required_capability_fields") {
        let field = field
            .as_str()
            .expect("required_capability_fields entries must be strings");
        if row.get(field).is_none() {
            errors.push(format!("{capability_id}: missing required field {field}"));
        }
    }
    if !errors.is_empty() {
        return errors;
    }

    for key in [
        "capability_id",
        "title",
        "category",
        "input_semantics",
        "output_semantics",
        "error_semantics",
        "resource_semantics",
        "disposition",
        "evidence_state",
        "cutover_state",
        "unit_test_owner",
        "e2e_owner",
        "no_claim_boundary",
    ] {
        nonempty_string(row, key, &mut errors, capability_id);
    }
    for key in [
        "dependency_owners",
        "source_owners",
        "exposure",
        "platforms",
        "features",
        "security_invariants",
        "cancellation_invariants",
        "downstream_consumers",
        "replacement_bead_ids",
        "scenario_ids",
    ] {
        nonempty_string_array(row, key, &mut errors, capability_id);
    }
    if !errors.is_empty() {
        return errors;
    }

    let dispositions = string_set(registry, "allowed_dispositions");
    let disposition = string(row, "disposition");
    if !dispositions.contains(disposition) {
        errors.push(format!(
            "{capability_id}: unsupported or destructive disposition {disposition}"
        ));
    }
    if disposition.contains("REMOVE") || disposition.contains("DROP") {
        errors.push(format!(
            "{capability_id}: destructive disposition is forbidden"
        ));
    }

    let evidence_states = string_set(registry, "allowed_evidence_states");
    let evidence_state = string(row, "evidence_state");
    if !evidence_states.contains(evidence_state) {
        errors.push(format!(
            "{capability_id}: unsupported evidence_state {evidence_state}"
        ));
    }
    let cutover_states = string_set(registry, "allowed_cutover_states");
    let cutover_state = string(row, "cutover_state");
    if !cutover_states.contains(cutover_state) {
        errors.push(format!(
            "{capability_id}: unsupported cutover_state {cutover_state}"
        ));
    }
    if evidence_state == "UNKNOWN_BLOCKING" && cutover_state != "BLOCKED_PENDING_EVIDENCE" {
        errors.push(format!(
            "{capability_id}: UNKNOWN evidence must block cutover"
        ));
    }
    match disposition {
        "PRESERVE_AND_REPLACE_IF_PARITY" | "RELOCATE_IF_PARITY"
            if cutover_state != "BLOCKED_PENDING_EVIDENCE" =>
        {
            errors.push(format!(
                "{capability_id}: conditional replacement must remain blocked"
            ));
        }
        "KEEP_UNTIL_PARITY" | "EXPERIMENT_ONLY" if cutover_state != "KEEP_INCUMBENT" => {
            errors.push(format!(
                "{capability_id}: incumbent must remain until parity"
            ));
        }
        _ => {}
    }

    for feature in strings(row, "features") {
        if !known_features.contains(&feature) {
            errors.push(format!(
                "{capability_id}: unknown Cargo feature coordinate {feature}"
            ));
        }
    }
    for source in strings(row, "source_owners") {
        if !path_exists(&source) {
            errors.push(format!(
                "{capability_id}: source owner does not exist: {source}"
            ));
        }
    }

    let baseline = object(row, "baseline");
    for key in ["state", "owner_bead", "fixture", "command"] {
        if baseline
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(|text| text.trim().is_empty())
        {
            errors.push(format!(
                "{capability_id}: baseline.{key} must be a nonempty string"
            ));
        }
    }
    let baseline_state = baseline
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(baseline_state, "existing" | "planned" | "blocked") {
        errors.push(format!(
            "{capability_id}: unsupported baseline state {baseline_state}"
        ));
    }

    for key in ["unit_test_owner", "e2e_owner"] {
        let bead = string(row, key);
        if !known_beads.contains(bead) {
            errors.push(format!(
                "{capability_id}: {key} references unknown bead {bead}"
            ));
        }
    }
    if let Some(bead) = baseline.get("owner_bead").and_then(Value::as_str)
        && !known_beads.contains(bead)
    {
        errors.push(format!(
            "{capability_id}: baseline owner references unknown bead {bead}"
        ));
    }
    for bead in strings(row, "replacement_bead_ids") {
        if !known_beads.contains(&bead) {
            errors.push(format!(
                "{capability_id}: replacement references unknown bead {bead}"
            ));
        }
    }

    errors
}

fn validate_registry(registry: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let known_features = cargo_feature_ids();
    let known_beads = tracker_ids();
    let rows = array(registry, "capabilities");
    let mut seen = BTreeSet::new();

    for row in rows {
        let capability_id = row
            .get("capability_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing-capability-id>");
        if !seen.insert(capability_id.to_owned()) {
            errors.push(format!("duplicate capability ID {capability_id}"));
        }
        errors.extend(validate_capability_row(
            registry,
            row,
            &known_features,
            &known_beads,
        ));
    }
    errors
}

fn set_value(row: &mut Value, key: &str, value: Value) {
    row.as_object_mut()
        .expect("row must be an object")
        .insert(key.to_owned(), value);
}

fn capability_row_mut<'a>(registry: &'a mut Value, capability_id: &str) -> &'a mut Value {
    registry
        .get_mut("capabilities")
        .and_then(Value::as_array_mut)
        .expect("capabilities must be an array")
        .iter_mut()
        .find(|row| string(row, "capability_id") == capability_id)
        .unwrap_or_else(|| panic!("missing mutable capability {capability_id}"))
}

fn cargo_feature_ids() -> BTreeSet<String> {
    let manifest = read_repo_file(MANIFEST_PATH);
    let mut in_features = false;
    let mut features = BTreeSet::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[features]" {
            in_features = true;
            continue;
        }
        if in_features && trimmed.starts_with('[') {
            break;
        }
        if !in_features
            || line.chars().next().is_some_and(char::is_whitespace)
            || trimmed.is_empty()
            || trimmed.starts_with('#')
        {
            continue;
        }
        if let Some((key, _)) = trimmed.split_once('=') {
            features.insert(key.trim().to_owned());
        }
    }
    features
}

fn source_binary_ids() -> BTreeMap<String, String> {
    let mut binaries = BTreeMap::new();
    let source_dir = repo_root().join("src/bin");
    for entry in std::fs::read_dir(&source_dir).expect("src/bin must be readable") {
        let entry = entry.expect("src/bin entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("binary source stem must be UTF-8")
            .to_owned();
        binaries.insert(
            name,
            format!("src/bin/{}.rs", string_from_os(path.file_stem())),
        );
    }

    let manifest = read_repo_file(MANIFEST_PATH);
    let mut in_bin = false;
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;
    let flush = |name: &mut Option<String>,
                 path: &mut Option<String>,
                 binaries: &mut BTreeMap<String, String>| {
        if let (Some(name), Some(path)) = (name.take(), path.take()) {
            binaries.insert(name, path);
        }
    };
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[[bin]]" {
            flush(&mut name, &mut path, &mut binaries);
            in_bin = true;
            continue;
        }
        if in_bin && trimmed.starts_with('[') {
            flush(&mut name, &mut path, &mut binaries);
            in_bin = false;
        }
        if !in_bin {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("name = ") {
            name = Some(unquote(value).to_owned());
        } else if let Some(value) = trimmed.strip_prefix("path = ") {
            path = Some(unquote(value).to_owned());
        }
    }
    flush(&mut name, &mut path, &mut binaries);
    binaries
}

fn string_from_os(value: Option<&std::ffi::OsStr>) -> String {
    value
        .and_then(std::ffi::OsStr::to_str)
        .expect("path component must be UTF-8")
        .to_owned()
}

fn unquote(value: &str) -> &str {
    value
        .trim()
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or_else(|| panic!("expected quoted TOML string, got {value}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn api_semantic_projection(api_map: &Value) -> String {
    let mut projection = String::new();
    for export in array(api_map, "root_exports") {
        let features = strings(export, "feature_flags").join(",");
        let cfg = export.get("cfg").and_then(Value::as_str).unwrap_or("");
        projection.push_str(string(export, "kind"));
        projection.push('\t');
        projection.push_str(string(export, "name"));
        projection.push('\t');
        projection.push_str(&features);
        projection.push('\t');
        projection.push_str(cfg);
        projection.push('\n');
    }
    projection
}

fn selector_matches(selector: &Value, export: &Value) -> bool {
    string(selector, "kind") == string(export, "kind")
        && string(export, "name").starts_with(string(selector, "name_prefix"))
}

fn mapped_capability_ids(registry: &Value) -> BTreeSet<String> {
    let mut mapped = BTreeSet::new();
    for section in [
        "feature_inventory",
        "binary_inventory",
        "format_inventory",
        "journey_inventory",
        "taxonomy_mapping",
        "downstream_consumers",
        "bead_mapping_rules",
    ] {
        for row in array(registry, section) {
            mapped.extend(strings(row, "capability_ids"));
        }
    }
    for selector in array(object(registry, "api_surface_snapshot"), "selectors") {
        mapped.extend(strings(selector, "capability_ids"));
    }
    mapped.extend(strings(
        object(registry, "diagnostic_inventory"),
        "capability_ids",
    ));
    mapped
}

fn render_generated_summary(registry: &Value) -> String {
    let mut category_counts = BTreeMap::<String, usize>::new();
    let mut disposition_counts = BTreeMap::<String, usize>::new();
    let mut evidence_counts = BTreeMap::<String, usize>::new();
    let mut cutover_counts = BTreeMap::<String, usize>::new();
    for row in array(registry, "capabilities") {
        *category_counts
            .entry(string(row, "category").to_owned())
            .or_default() += 1;
        *disposition_counts
            .entry(string(row, "disposition").to_owned())
            .or_default() += 1;
        *evidence_counts
            .entry(string(row, "evidence_state").to_owned())
            .or_default() += 1;
        *cutover_counts
            .entry(string(row, "cutover_state").to_owned())
            .or_default() += 1;
    }

    let counts = |map: &BTreeMap<String, usize>| {
        map.iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut output = String::new();
    output.push_str(GENERATED_BEGIN);
    output.push('\n');
    output.push_str(&format!(
        "- Artifact: `{}` (schema {})\n",
        string(registry, "artifact_id"),
        registry["schema_version"]
    ));
    output.push_str(&format!(
        "- Inventories: {} capabilities; {} Cargo features; {} binaries; {} formats; {} journeys; {} taxonomy candidates; {} downstream consumers; {} bead mapping rules.\n",
        array(registry, "capabilities").len(),
        array(registry, "feature_inventory").len(),
        array(registry, "binary_inventory").len(),
        array(registry, "format_inventory").len(),
        array(registry, "journey_inventory").len(),
        array(registry, "taxonomy_mapping").len(),
        array(registry, "downstream_consumers").len(),
        array(registry, "bead_mapping_rules").len(),
    ));
    output.push_str(&format!("- Categories: {}.\n", counts(&category_counts)));
    output.push_str(&format!(
        "- Dispositions: {}.\n",
        counts(&disposition_counts)
    ));
    output.push_str(&format!(
        "- Evidence states: {}.\n",
        counts(&evidence_counts)
    ));
    output.push_str(&format!(
        "- Cutover states: {}.\n\n",
        counts(&cutover_counts)
    ));
    output
        .push_str("| Capability ID | Category | Disposition | Evidence | Cutover | E2E owner |\n");
    output.push_str("|---|---|---|---|---|---|\n");
    let mut rows = array(registry, "capabilities").iter().collect::<Vec<_>>();
    rows.sort_by_key(|row| string(row, "capability_id"));
    for row in rows {
        output.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | `{}` |\n",
            string(row, "capability_id"),
            string(row, "category"),
            string(row, "disposition"),
            string(row, "evidence_state"),
            string(row, "cutover_state"),
            string(row, "e2e_owner"),
        ));
    }
    output.push_str(GENERATED_END);
    output
}

fn generated_doc_block(doc: &str) -> &str {
    let start = doc
        .find(GENERATED_BEGIN)
        .unwrap_or_else(|| panic!("{DOC_PATH} lacks generated summary start marker"));
    let end = doc
        .find(GENERATED_END)
        .unwrap_or_else(|| panic!("{DOC_PATH} lacks generated summary end marker"))
        + GENERATED_END.len();
    &doc[start..end]
}

#[test]
fn metadata_and_policy_are_fail_closed() {
    let registry = registry();
    assert_eq!(registry["schema_version"], 1);
    assert_eq!(
        string(&registry, "artifact_id"),
        "dependency-capability-registry-v1"
    );
    assert_eq!(string(&registry, "program_id"), PROGRAM_ID);
    assert_eq!(string(&registry, "bead_id"), BEAD_ID);
    assert_eq!(
        string(object(&registry, "policy"), "unknown_rule"),
        "Missing or inconclusive evidence is UNKNOWN_BLOCKING. It may not be interpreted as unused, unsupported, equivalent, or safe to remove."
    );
    assert!(
        string(object(&registry, "policy"), "preservation_rule")
            .contains("Every accepted public API")
    );
    assert!(
        string(object(&registry, "policy"), "test_rule")
            .contains("cancellation, race, shutdown, leak, and quiescence")
    );
    assert!(string(object(&registry, "policy"), "e2e_rule").contains("real no-mock scenario"));
    assert_eq!(
        string(object(&registry, "validation"), "focused_proof_command"),
        PROOF_COMMAND
    );
    assert_eq!(SCENARIO_ID, "dependency_capability_registry_contract_v1");

    let required = [
        "capability_id",
        "title",
        "category",
        "dependency_owners",
        "source_owners",
        "exposure",
        "platforms",
        "features",
        "input_semantics",
        "output_semantics",
        "error_semantics",
        "resource_semantics",
        "security_invariants",
        "cancellation_invariants",
        "downstream_consumers",
        "baseline",
        "replacement_bead_ids",
        "disposition",
        "evidence_state",
        "cutover_state",
        "unit_test_owner",
        "e2e_owner",
        "scenario_ids",
        "no_claim_boundary",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        string_set(&registry, "required_capability_fields"),
        required
    );
}

#[test]
fn every_capability_row_is_complete_and_safe() {
    let registry = registry();
    let errors = validate_registry(&registry);
    assert!(
        errors.is_empty(),
        "capability registry validation failed:\n{}",
        errors.join("\n")
    );

    let ids = capability_ids(&registry);
    assert_eq!(
        ids.len(),
        array(&registry, "capabilities").len(),
        "capability IDs must be unique"
    );
    assert!(
        ids.len() >= 45,
        "the registry must stay granular; found only {} capability families",
        ids.len()
    );

    let generic_extension_capabilities = [
        ("CAP-SERDE-GENERIC", "generic-extension"),
        ("CAP-PROTOBUF-GENERIC", "generic-extension"),
        ("CAP-OTLP-ECOSYSTEM", "third-party-ecosystem"),
        ("CAP-REGEX-PRIVACY", "configuration"),
    ];
    for (id, exposure) in generic_extension_capabilities {
        let row = array(&registry, "capabilities")
            .iter()
            .find(|row| string(row, "capability_id") == id)
            .unwrap_or_else(|| panic!("missing required generic extension capability {id}"));
        assert!(
            string_set(row, "exposure").contains(exposure),
            "{id} must expose {exposure}"
        );
        assert_eq!(
            string(row, "cutover_state"),
            "KEEP_INCUMBENT",
            "{id} must keep its incumbent until full parity"
        );
    }
}

#[test]
fn negative_duplicate_capability_is_rejected() {
    let mut registry = registry();
    let duplicate = array(&registry, "capabilities")[0].clone();
    registry["capabilities"]
        .as_array_mut()
        .expect("capabilities must be mutable")
        .push(duplicate);
    assert!(
        validate_registry(&registry)
            .iter()
            .any(|error| error.contains("duplicate capability ID"))
    );
}

#[test]
fn negative_missing_owner_coordinate_and_baseline_are_rejected() {
    let mut registry = registry();
    set_value(
        capability_row_mut(&mut registry, "CAP-HEX-CODEC"),
        "dependency_owners",
        Value::Array(Vec::new()),
    );
    set_value(
        capability_row_mut(&mut registry, "CAP-BASE64-CODEC"),
        "platforms",
        Value::Array(Vec::new()),
    );
    set_value(
        capability_row_mut(&mut registry, "CAP-TEMP-ARTIFACTS"),
        "features",
        Value::Array(Vec::new()),
    );
    capability_row_mut(&mut registry, "CAP-HASH-MAPS")
        .as_object_mut()
        .expect("capability row must be an object")
        .remove("baseline");

    let errors = validate_registry(&registry).join("\n");
    assert!(errors.contains("dependency_owners"));
    assert!(errors.contains("platforms"));
    assert!(errors.contains("features"));
    assert!(errors.contains("missing required field baseline"));
}

#[test]
fn negative_destructive_disposition_and_unknown_cutover_are_rejected() {
    let mut registry = registry();
    let row = capability_row_mut(&mut registry, "CAP-BASE64-CODEC");
    set_value(row, "disposition", Value::String("REMOVE".to_owned()));
    set_value(
        row,
        "evidence_state",
        Value::String("UNKNOWN_BLOCKING".to_owned()),
    );
    set_value(
        row,
        "cutover_state",
        Value::String("NOT_A_CUTOVER".to_owned()),
    );

    let errors = validate_registry(&registry).join("\n");
    assert!(errors.contains("unsupported or destructive disposition REMOVE"));
    assert!(errors.contains("destructive disposition is forbidden"));
    assert!(errors.contains("UNKNOWN evidence must block cutover"));
}

#[test]
fn cargo_features_are_exhaustive_and_mapped() {
    let registry = registry();
    let source_features = cargo_feature_ids();
    let rows = array(&registry, "feature_inventory");
    let mut artifact_features = BTreeSet::new();
    let known_capabilities = capability_ids(&registry);

    for row in rows {
        let feature = string(row, "feature_id");
        assert!(
            artifact_features.insert(feature.to_owned()),
            "duplicate feature inventory row {feature}"
        );
        nonempty_feature_row(row, &known_capabilities);
    }

    assert_eq!(
        artifact_features, source_features,
        "Cargo feature inventory drifted; update the capability registry before cutover work"
    );
    assert_eq!(artifact_features.len(), 57);
}

fn nonempty_feature_row(row: &Value, known_capabilities: &BTreeSet<String>) {
    let feature = string(row, "feature_id");
    assert!(
        !string(row, "support_class").is_empty(),
        "{feature}: support_class must be nonempty"
    );
    assert!(
        !strings(row, "platforms").is_empty(),
        "{feature}: platforms must be nonempty"
    );
    let capability_ids = strings(row, "capability_ids");
    assert!(
        !capability_ids.is_empty(),
        "{feature}: capability_ids must be nonempty"
    );
    for capability_id in capability_ids {
        assert!(
            known_capabilities.contains(&capability_id),
            "{feature}: unknown capability {capability_id}"
        );
    }
}

#[test]
fn binaries_are_exhaustive_and_source_checked() {
    let registry = registry();
    let source_binaries = source_binary_ids();
    let known_capabilities = capability_ids(&registry);
    let mut artifact_binaries = BTreeMap::new();

    for row in array(&registry, "binary_inventory") {
        let binary_id = string(row, "binary_id");
        let source_path = string(row, "source_path");
        assert!(
            artifact_binaries
                .insert(binary_id.to_owned(), source_path.to_owned())
                .is_none(),
            "duplicate binary inventory row {binary_id}"
        );
        assert!(
            path_exists(source_path),
            "{binary_id}: source path does not exist: {source_path}"
        );
        assert!(
            !string(row, "audience").is_empty(),
            "{binary_id}: audience must be nonempty"
        );
        for feature in strings(row, "required_features") {
            assert!(
                cargo_feature_ids().contains(&feature),
                "{binary_id}: unknown required feature {feature}"
            );
        }
        for capability_id in strings(row, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "{binary_id}: unknown capability {capability_id}"
            );
        }
    }

    assert_eq!(
        artifact_binaries, source_binaries,
        "binary inventory drifted; user and internal tools must all be mapped"
    );
    assert_eq!(artifact_binaries.len(), 15);
    for user_binary in ["asupersync", "atp", "atpd", "offline_tuner"] {
        assert!(artifact_binaries.contains_key(user_binary));
    }
}

#[test]
fn cli_surface_snapshot_covers_commands_options_environment_help_and_exits() {
    let registry = registry();
    let inventory = object(&registry, "cli_surface_inventory");
    let known_capabilities = capability_ids(&registry);
    assert_eq!(
        string(inventory, "snapshot_kind"),
        "full-source-fail-closed"
    );
    assert!(
        string(inventory, "snapshot_rule").contains("exhaustive option, alias, default, value")
    );
    assert_eq!(
        string(inventory, "cutover_baseline_owner"),
        "asupersync-5z2scg.7.1"
    );
    assert_eq!(
        string(inventory, "installed_e2e_owner"),
        "asupersync-5z2scg.7.11"
    );

    let mut snapshot_paths = BTreeSet::new();
    let mut combined_source = String::new();
    for row in array(inventory, "snapshot_files") {
        let source_path = string(row, "source_path");
        assert!(
            snapshot_paths.insert(source_path.to_owned()),
            "duplicate CLI snapshot path {source_path}"
        );
        let source = read_repo_file(source_path);
        assert_eq!(
            source.lines().count() as u64,
            row["line_count"]
                .as_u64()
                .expect("CLI line_count must be an integer"),
            "{source_path}: line-count drift"
        );
        assert_eq!(
            sha256_hex(source.as_bytes()),
            string(row, "sha256"),
            "{source_path}: full-source CLI surface drift"
        );
        combined_source.push_str(&source);
        for capability_id in strings(row, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "{source_path}: unknown capability {capability_id}"
            );
        }
    }
    assert_eq!(snapshot_paths.len(), 7);

    let mut surface_ids = BTreeSet::new();
    for row in array(inventory, "command_roots") {
        let surface_id = string(row, "surface_id");
        assert!(
            surface_ids.insert(surface_id.to_owned()),
            "duplicate CLI command surface {surface_id}"
        );
        let commands = strings(row, "commands");
        assert!(
            !commands.is_empty(),
            "{surface_id}: commands must be nonempty"
        );
        assert_eq!(
            commands.iter().collect::<BTreeSet<_>>().len(),
            commands.len(),
            "{surface_id}: duplicate command"
        );
        for capability_id in strings(row, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "{surface_id}: unknown capability {capability_id}"
            );
        }
    }

    let mut environment = BTreeSet::new();
    for row in array(inventory, "environment_variables") {
        let name = string(row, "name");
        assert!(
            environment.insert(name.to_owned()),
            "duplicate CLI environment variable {name}"
        );
        assert!(
            combined_source.contains(name),
            "CLI environment variable {name} no longer appears in snapshotted sources"
        );
        assert!(
            !string(row, "semantics").is_empty(),
            "{name}: semantics must be nonempty"
        );
    }
    assert_eq!(environment.len(), 10);

    let exit_source = read_repo_file("src/cli/exit.rs");
    let mut source_exits = BTreeMap::new();
    for line in exit_source.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": i32 = ") else {
            continue;
        };
        if matches!(name, "MIN_VALID" | "MAX_VALID") {
            continue;
        }
        let value = value
            .trim_end_matches(';')
            .parse::<i64>()
            .unwrap_or_else(|error| panic!("invalid exit constant {name}: {error}"));
        source_exits.insert(name.to_owned(), value);
    }
    let artifact_exits = array(inventory, "exit_codes")
        .iter()
        .map(|row| {
            (
                string(row, "name").to_owned(),
                row["code"].as_i64().expect("exit code must be an integer"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(artifact_exits, source_exits, "CLI exit registry drifted");
    assert!(string(inventory, "help_contract").contains("shell/OsString"));
}

#[test]
fn public_api_snapshot_and_selectors_are_exhaustive() {
    let registry = registry();
    let api_map = parse_repo_json(API_MAP_PATH);
    let snapshot = object(&registry, "api_surface_snapshot");
    let projection = api_semantic_projection(&api_map);
    let known_capabilities = capability_ids(&registry);

    assert_eq!(
        array(&api_map, "root_exports").len() as u64,
        snapshot["root_export_count"]
            .as_u64()
            .expect("root_export_count must be an integer")
    );
    assert_eq!(
        array(&api_map, "entry_points").len() as u64,
        snapshot["entry_point_count"]
            .as_u64()
            .expect("entry_point_count must be an integer")
    );
    assert_eq!(
        sha256_hex(projection.as_bytes()),
        string(snapshot, "semantic_sha256"),
        "root public export semantics drifted"
    );

    let mut selector_ids = BTreeSet::new();
    for selector in array(snapshot, "selectors") {
        assert!(
            selector_ids.insert(string(selector, "selector_id").to_owned()),
            "duplicate API selector {}",
            string(selector, "selector_id")
        );
        for capability_id in strings(selector, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "API selector references unknown capability {capability_id}"
            );
        }
    }

    for export in array(&api_map, "root_exports") {
        let matches = array(snapshot, "selectors")
            .iter()
            .filter(|selector| selector_matches(selector, export))
            .count();
        assert!(
            matches > 0,
            "unmapped root export {} {}",
            string(export, "kind"),
            string(export, "name")
        );
    }
}

#[test]
fn documented_api_entry_points_have_exact_journey_owners() {
    let registry = registry();
    let api_map = parse_repo_json(API_MAP_PATH);
    let source_use_cases = array(&api_map, "entry_points")
        .iter()
        .map(|entry| string(entry, "use_case").to_owned())
        .collect::<BTreeSet<_>>();
    let mut journey_use_cases = BTreeSet::new();
    let mut journey_ids = BTreeSet::new();
    let known_capabilities = capability_ids(&registry);
    let known_beads = tracker_ids();

    for journey in array(&registry, "journey_inventory") {
        let journey_id = string(journey, "journey_id");
        assert!(
            journey_ids.insert(journey_id.to_owned()),
            "duplicate journey ID {journey_id}"
        );
        assert!(
            path_exists(string(journey, "source_path")),
            "{journey_id}: source_path does not exist"
        );
        for key in ["baseline_owner", "e2e_owner"] {
            assert!(
                known_beads.contains(string(journey, key)),
                "{journey_id}: {key} is not a live tracker ID"
            );
        }
        for capability_id in strings(journey, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "{journey_id}: unknown capability {capability_id}"
            );
        }
        if let Some(use_case) = journey.get("api_use_case").and_then(Value::as_str) {
            assert!(
                journey_use_cases.insert(use_case.to_owned()),
                "API use case {use_case} has multiple journey rows"
            );
        }
    }

    assert_eq!(
        journey_use_cases, source_use_cases,
        "api_surface_map entry-point journeys drifted"
    );
    assert_eq!(source_use_cases.len(), 19);
    assert!(
        journey_ids.len() >= 30,
        "dependency-specific user journeys must remain explicit"
    );
}

#[test]
fn formats_include_every_no_loss_protocol_and_artifact_family() {
    let registry = registry();
    let known_capabilities = capability_ids(&registry);
    let mut formats = BTreeSet::new();
    for row in array(&registry, "format_inventory") {
        let format_id = string(row, "format_id");
        assert!(
            formats.insert(format_id.to_owned()),
            "duplicate format ID {format_id}"
        );
        assert!(
            !strings(row, "exposure").is_empty(),
            "{format_id}: exposure must be nonempty"
        );
        for capability_id in strings(row, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "{format_id}: unknown capability {capability_id}"
            );
        }
    }
    let required = [
        "json",
        "toml",
        "yaml",
        "bincode",
        "messagepack",
        "protobuf",
        "otlp",
        "snapshot",
        "trace",
        "atp-manifest-and-journal",
        "nkey",
        "x509-der-pem",
        "kafka-recordbatch",
        "rfc3339",
        "base64-rfc4648",
        "hex",
        "lz4-block-frame",
        "deflate-zlib-gzip",
        "brotli-rfc7932",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(formats, required);
}

#[test]
fn every_safety_taxonomy_candidate_is_capability_mapped() {
    let registry = registry();
    let taxonomy = parse_repo_json(TAXONOMY_PATH);
    let source_candidates = array(&taxonomy, "classifications")
        .iter()
        .map(|row| string(row, "candidate_id").to_owned())
        .collect::<BTreeSet<_>>();
    let known_capabilities = capability_ids(&registry);
    let mut mapped_candidates = BTreeSet::new();

    for row in array(&registry, "taxonomy_mapping") {
        let candidate_id = string(row, "candidate_id");
        assert!(
            mapped_candidates.insert(candidate_id.to_owned()),
            "duplicate taxonomy mapping {candidate_id}"
        );
        let capability_ids = strings(row, "capability_ids");
        assert!(
            !capability_ids.is_empty(),
            "{candidate_id}: capability mapping must be nonempty"
        );
        for capability_id in capability_ids {
            assert!(
                known_capabilities.contains(&capability_id),
                "{candidate_id}: unknown capability {capability_id}"
            );
        }
    }

    assert_eq!(
        mapped_candidates, source_candidates,
        "safety taxonomy candidate mapping drifted"
    );
    assert_eq!(source_candidates.len(), 33);
}

fn bead_rule_matches(rule: &Value, bead_id: &str) -> bool {
    match string(rule, "scope") {
        "exact" => bead_id == string(rule, "bead_id"),
        "prefix" => bead_id.starts_with(string(rule, "bead_id")),
        other => panic!("unsupported bead rule scope {other}"),
    }
}

fn effective_bead_rule<'a>(rules: &'a [Value], bead_id: &str) -> Result<&'a Value, String> {
    let matches = rules
        .iter()
        .filter(|rule| bead_rule_matches(rule, bead_id))
        .collect::<Vec<_>>();
    let exact = matches
        .iter()
        .copied()
        .filter(|rule| string(rule, "scope") == "exact")
        .collect::<Vec<_>>();
    if exact.len() == 1 {
        return Ok(exact[0]);
    }
    if exact.len() > 1 {
        return Err(format!(
            "{bead_id}: ambiguous mapping: {} exact rules",
            exact.len()
        ));
    }

    let Some(longest) = matches
        .iter()
        .map(|rule| string(rule, "bead_id").len())
        .max()
    else {
        return Err(format!("{bead_id}: unmapped dep-plan bead"));
    };
    let longest_matches = matches
        .into_iter()
        .filter(|rule| string(rule, "bead_id").len() == longest)
        .collect::<Vec<_>>();
    if longest_matches.len() != 1 {
        return Err(format!(
            "{bead_id}: ambiguous mapping: {} equal-precedence prefix rules",
            longest_matches.len()
        ));
    }
    Ok(longest_matches[0])
}

fn authority_capability_ids(issue: &Value) -> BTreeSet<String> {
    let mut capabilities = BTreeSet::new();
    for comment in issue
        .get("comments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(text) = comment.get("text").and_then(Value::as_str) else {
            continue;
        };
        if !text.contains(AUTHORITY_MARKER) {
            continue;
        }
        let authority_segment = text.split("Role =").next().unwrap_or(text);
        for token in authority_segment.split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ',' | ';' | '.' | '`')
        }) {
            let candidate = token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '-'
            });
            if candidate.starts_with("CAP-")
                && candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                capabilities.insert(candidate.to_owned());
            }
        }
    }
    capabilities
}

fn issue_contract_text(issue: &Value) -> String {
    [
        issue.get("title").and_then(Value::as_str).unwrap_or(""),
        issue
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or(""),
        issue
            .get("acceptance_criteria")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ]
    .join(" ")
    .to_ascii_lowercase()
}

fn loss_authorization_errors(registry: &Value, text: &str) -> Vec<String> {
    let normalized = text.to_ascii_lowercase();
    array(registry, "known_loss_fixtures")
        .iter()
        .filter_map(|fixture| {
            let prohibited = string(fixture, "prohibited_text").to_ascii_lowercase();
            normalized
                .contains(&prohibited)
                .then(|| string(fixture, "expected_error").to_owned())
        })
        .collect()
}

fn is_superseded_duplicate(issue: &Value) -> bool {
    issue.get("status").and_then(Value::as_str) == Some("closed")
        && issue
            .get("close_reason")
            .and_then(Value::as_str)
            .is_some_and(|reason| {
                let reason = reason.to_ascii_lowercase();
                reason.contains("superseded") && reason.contains("duplicate")
            })
}

fn has_parent_edge(issue: &Value, parent_id: &str) -> bool {
    issue
        .get("dependencies")
        .and_then(Value::as_array)
        .is_some_and(|dependencies| {
            dependencies.iter().any(|dependency| {
                dependency.get("type").and_then(Value::as_str) == Some("parent-child")
                    && dependency.get("depends_on_id").and_then(Value::as_str) == Some(parent_id)
            })
        })
}

fn graph_signoff_errors(registry: &Value, issues: &[Value], cutover: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let report = object(registry, "graph_signoff_report");
    let rules = array(registry, "bead_mapping_rules");
    let known_capabilities = capability_ids(registry);
    let excluded_superseded_duplicates = issues
        .iter()
        .filter(|issue| issue_has_label(issue, "dep-plan") && is_superseded_duplicate(issue))
        .map(|issue| string(issue, "id").to_owned())
        .collect::<BTreeSet<_>>();
    let dep_plan_issues = issues
        .iter()
        .filter(|issue| issue_has_label(issue, "dep-plan") && !is_superseded_duplicate(issue))
        .collect::<Vec<_>>();
    let issue_by_id = issues
        .iter()
        .map(|issue| (string(issue, "id").to_owned(), issue))
        .collect::<BTreeMap<_, _>>();

    let expected_counts = [
        ("dep_plan_issue_count", dep_plan_issues.len()),
        (
            "non_epic_work_count",
            dep_plan_issues
                .iter()
                .filter(|issue| issue.get("issue_type").and_then(Value::as_str) != Some("epic"))
                .count(),
        ),
        ("capability_count", known_capabilities.len()),
        ("mapping_rule_count", rules.len()),
    ];
    for (key, expected) in expected_counts {
        if report.get(key).and_then(Value::as_u64) != Some(expected as u64) {
            errors.push(format!("graph signoff {key} drifted: expected {expected}"));
        }
    }
    if string(report, "signoff_bead_id") != CAP_A4_BEAD_ID {
        errors.push("graph signoff references the wrong CAP A4 bead".to_owned());
    }
    if string(report, "status") != "PASS_SCOPED" {
        errors.push("graph signoff status must be PASS_SCOPED".to_owned());
    }
    if string_set(report, "excluded_superseded_duplicate_ids") != excluded_superseded_duplicates {
        errors.push(
            "graph signoff excluded_superseded_duplicate_ids drifted from explicit tracker closures"
                .to_owned(),
        );
    }

    let mut unmapped = BTreeSet::new();
    let mut ambiguous = BTreeSet::new();
    let mut authority_mismatches = BTreeSet::new();
    let mut loss_authorizations = BTreeSet::new();
    for issue in &dep_plan_issues {
        let bead_id = string(issue, "id");
        match effective_bead_rule(rules, bead_id) {
            Ok(rule) => {
                let mapped = string_set(rule, "capability_ids");
                for capability_id in &mapped {
                    if !known_capabilities.contains(capability_id) {
                        errors.push(format!(
                            "{bead_id}: mapping references unknown capability {capability_id}"
                        ));
                    }
                }
                let authority = authority_capability_ids(issue);
                if !authority.is_empty() && authority != mapped {
                    authority_mismatches.insert(bead_id.to_owned());
                }
            }
            Err(error) if error.contains("unmapped") => {
                unmapped.insert(bead_id.to_owned());
            }
            Err(_) => {
                ambiguous.insert(bead_id.to_owned());
            }
        }
        if !loss_authorization_errors(registry, &issue_contract_text(issue)).is_empty() {
            loss_authorizations.insert(bead_id.to_owned());
        }
    }

    let reported_findings = [
        ("unmapped_bead_ids", &unmapped),
        ("ambiguous_bead_ids", &ambiguous),
        ("authority_mismatch_bead_ids", &authority_mismatches),
        ("loss_authorization_bead_ids", &loss_authorizations),
    ];
    for (key, actual) in reported_findings {
        if string_set(report, key) != *actual {
            errors.push(format!("graph signoff {key} does not match live findings"));
        }
        if !actual.is_empty() {
            errors.push(format!("graph signoff {key} must be empty: {actual:?}"));
        }
    }

    for bead_id in strings(report, "exact_aggregate_ids") {
        let Some(issue) = issue_by_id.get(&bead_id) else {
            errors.push(format!("missing exact aggregate tracker issue {bead_id}"));
            continue;
        };
        match effective_bead_rule(rules, &bead_id) {
            Ok(rule) => {
                if string(rule, "scope") != "exact" {
                    errors.push(format!("{bead_id}: aggregate must use an exact rule"));
                }
                if string_set(rule, "capability_ids") != authority_capability_ids(issue) {
                    errors.push(format!(
                        "{bead_id}: exact aggregate mapping differs from tracker authority"
                    ));
                }
            }
            Err(error) => errors.push(error),
        }
    }

    let mut stale_owner_ids = BTreeSet::new();
    for row in array(registry, "capabilities") {
        for key in ["unit_test_owner", "e2e_owner"] {
            let owner = string(row, key);
            match issue_by_id.get(owner) {
                Some(issue) if issue.get("issue_type").and_then(Value::as_str) != Some("epic") => {}
                _ => {
                    stale_owner_ids.insert(owner.to_owned());
                }
            }
        }
    }
    for remap in array(report, "terminal_owner_remaps") {
        let capability_id = string(remap, "capability_id");
        let owner_key = match string(remap, "owner_kind") {
            "unit" => "unit_test_owner",
            "e2e" => "e2e_owner",
            other => {
                errors.push(format!("{capability_id}: unsupported owner kind {other}"));
                continue;
            }
        };
        let Some(capability) = array(registry, "capabilities")
            .iter()
            .find(|row| string(row, "capability_id") == capability_id)
        else {
            errors.push(format!("terminal owner remap references {capability_id}"));
            continue;
        };
        let epic_id = string(remap, "superseded_epic_id");
        let terminal_id = string(remap, "terminal_owner_id");
        if string(capability, owner_key) != terminal_id {
            errors.push(format!(
                "{capability_id}: {owner_key} must resolve to terminal {terminal_id}"
            ));
        }
        if issue_by_id
            .get(epic_id)
            .and_then(|issue| issue.get("issue_type"))
            .and_then(Value::as_str)
            != Some("epic")
        {
            errors.push(format!("{epic_id}: superseded owner must remain an epic"));
        }
        match issue_by_id.get(terminal_id) {
            Some(issue)
                if issue.get("issue_type").and_then(Value::as_str) != Some("epic")
                    && has_parent_edge(issue, epic_id) => {}
            _ => errors.push(format!(
                "{terminal_id}: terminal owner must be a non-epic child of {epic_id}"
            )),
        }
    }
    if string_set(report, "stale_terminal_owner_ids") != stale_owner_ids {
        errors.push("graph signoff stale_terminal_owner_ids drifted".to_owned());
    }
    if !stale_owner_ids.is_empty() {
        errors.push(format!(
            "capability evidence owners must be terminal leaves: {stale_owner_ids:?}"
        ));
    }

    for conversion in array(report, "converted_epic_terminals") {
        let epic_id = string(conversion, "epic_id");
        if issue_by_id
            .get(epic_id)
            .and_then(|issue| issue.get("issue_type"))
            .and_then(Value::as_str)
            != Some("epic")
        {
            errors.push(format!("{epic_id}: converted parent must be an epic"));
        }
        for terminal_id in strings(conversion, "terminal_ids") {
            match issue_by_id.get(&terminal_id) {
                Some(issue)
                    if issue.get("issue_type").and_then(Value::as_str) != Some("epic")
                        && has_parent_edge(issue, epic_id) => {}
                _ => errors.push(format!(
                    "{terminal_id}: converted terminal must be a non-epic child of {epic_id}"
                )),
            }
        }
    }

    let bindings = array(cutover, "capability_bindings");
    let cutover_targets = bindings
        .iter()
        .filter(|binding| string(binding, "binding_role") == "CUTOVER_TARGET")
        .count();
    let guard_only = bindings.len() - cutover_targets;
    if report.get("cutover_target_count").and_then(Value::as_u64) != Some(cutover_targets as u64) {
        errors.push("graph signoff cutover_target_count drifted".to_owned());
    }
    if report
        .get("cross_cutting_guard_count")
        .and_then(Value::as_u64)
        != Some(guard_only as u64)
    {
        errors.push("graph signoff cross_cutting_guard_count drifted".to_owned());
    }
    if string_set(report, "required_cutover_gate_ids") != string_set(cutover, "global_gate_ids") {
        errors.push("graph signoff must retain every global cutover gate".to_owned());
    }

    let mut evidence_bypass = BTreeSet::new();
    for binding in bindings {
        if string(binding, "binding_role") != "CUTOVER_TARGET" {
            continue;
        }
        let capability_id = string(binding, "capability_id");
        let Some(capability) = array(registry, "capabilities")
            .iter()
            .find(|row| string(row, "capability_id") == capability_id)
        else {
            evidence_bypass.insert(capability_id.to_owned());
            continue;
        };
        let owners_are_terminal = ["unit_test_owner", "e2e_owner"].into_iter().all(|key| {
            issue_by_id
                .get(string(capability, key))
                .is_some_and(|issue| {
                    issue.get("issue_type").and_then(Value::as_str) != Some("epic")
                })
        });
        if binding
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
            || !owners_are_terminal
        {
            evidence_bypass.insert(capability_id.to_owned());
        }
    }
    if string_set(report, "evidence_bypass_capability_ids") != evidence_bypass {
        errors.push("graph signoff evidence_bypass_capability_ids drifted".to_owned());
    }
    if !evidence_bypass.is_empty() {
        errors.push(format!(
            "cutover bindings bypass required evidence: {evidence_bypass:?}"
        ));
    }

    let unknown_at_cutover = array(registry, "capabilities")
        .iter()
        .filter(|row| {
            string(row, "evidence_state") == "UNKNOWN_BLOCKING"
                && string(row, "cutover_state") != "BLOCKED_PENDING_EVIDENCE"
        })
        .map(|row| string(row, "capability_id").to_owned())
        .collect::<BTreeSet<_>>();
    if string_set(report, "unknown_at_cutover_capability_ids") != unknown_at_cutover {
        errors.push("graph signoff unknown_at_cutover_capability_ids drifted".to_owned());
    }
    if !unknown_at_cutover.is_empty() {
        errors.push(format!(
            "UNKNOWN capability evidence reached cutover: {unknown_at_cutover:?}"
        ));
    }

    errors
}

#[test]
fn every_dep_plan_bead_has_one_unambiguous_effective_rule() {
    let registry = registry();
    let rules = array(&registry, "bead_mapping_rules");
    let known_capabilities = capability_ids(&registry);
    let dep_plan_issues = tracker_issues()
        .into_iter()
        .filter(|issue| issue_has_label(issue, "dep-plan") && !is_superseded_duplicate(issue))
        .collect::<Vec<_>>();
    assert!(
        dep_plan_issues.len() >= 270,
        "unexpectedly small dep-plan graph: {}",
        dep_plan_issues.len()
    );

    for rule in rules {
        assert!(
            matches!(string(rule, "scope"), "exact" | "prefix"),
            "unsupported rule scope"
        );
        for capability_id in strings(rule, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "bead rule references unknown capability {capability_id}"
            );
        }
        assert!(
            dep_plan_issues
                .iter()
                .any(|issue| bead_rule_matches(rule, string(issue, "id"))),
            "dead bead mapping rule {} {}",
            string(rule, "scope"),
            string(rule, "bead_id")
        );
    }

    for issue in dep_plan_issues {
        let bead_id = string(&issue, "id");
        let rule = effective_bead_rule(rules, bead_id)
            .unwrap_or_else(|error| panic!("effective rule resolution failed: {error}"));
        assert!(
            !strings(rule, "capability_ids").is_empty(),
            "{bead_id}: effective mapping must not be empty"
        );
    }
}

#[test]
fn graph_wide_no_loss_signoff_is_current() {
    let registry = registry();
    let issues = tracker_issues();
    let cutover = parse_repo_json(CUTOVER_POLICY_PATH);
    let errors = graph_signoff_errors(&registry, &issues, &cutover);
    assert!(
        errors.is_empty(),
        "CAP A4 graph signoff failed:\n{}",
        errors.join("\n")
    );
}

#[test]
fn negative_unmapped_and_ambiguous_rules_fail_closed() {
    let mut missing_registry = registry();
    let issues = tracker_issues();
    let cutover = parse_repo_json(CUTOVER_POLICY_PATH);
    missing_registry["bead_mapping_rules"]
        .as_array_mut()
        .expect("bead_mapping_rules")
        .retain(|rule| string(rule, "bead_id") != "asupersync-d24mms.13");
    let errors = graph_signoff_errors(&missing_registry, &issues, &cutover).join("\n");
    assert!(errors.contains("unmapped_bead_ids"));

    let mut ambiguous_registry = registry();
    let duplicate = array(&ambiguous_registry, "bead_mapping_rules")
        .iter()
        .find(|rule| string(rule, "bead_id") == "asupersync-d24mms.13")
        .expect("exact aggregate rule")
        .clone();
    ambiguous_registry["bead_mapping_rules"]
        .as_array_mut()
        .expect("bead_mapping_rules")
        .push(duplicate);
    let errors = graph_signoff_errors(&ambiguous_registry, &issues, &cutover).join("\n");
    assert!(errors.contains("ambiguous_bead_ids"));
}

#[test]
fn negative_authority_and_terminal_owner_drift_fail_closed() {
    let issues = tracker_issues();
    let cutover = parse_repo_json(CUTOVER_POLICY_PATH);
    let mut authority_registry = registry();
    let exact = authority_registry["bead_mapping_rules"]
        .as_array_mut()
        .expect("bead_mapping_rules")
        .iter_mut()
        .find(|rule| string(rule, "bead_id") == "asupersync-3u3tej.5")
        .expect("platform aggregate rule");
    exact["capability_ids"] = serde_json::json!(["CAP-SIGNALS"]);
    let errors = graph_signoff_errors(&authority_registry, &issues, &cutover).join("\n");
    assert!(errors.contains("authority_mismatch_bead_ids"));
    assert!(errors.contains("exact aggregate mapping differs"));

    let mut owner_registry = registry();
    set_value(
        capability_row_mut(&mut owner_registry, "CAP-KAFKA"),
        "e2e_owner",
        Value::String("asupersync-dep-p7-kafka-removal-sarszu.2.13".to_owned()),
    );
    let errors = graph_signoff_errors(&owner_registry, &issues, &cutover).join("\n");
    assert!(errors.contains("capability evidence owners must be terminal leaves"));
    assert!(errors.contains("e2e_owner must resolve to terminal"));
}

#[test]
fn all_named_feature_loss_fixtures_fail_for_the_intended_reason() {
    let registry = registry();
    assert_eq!(array(&registry, "known_loss_fixtures").len(), 8);
    for fixture in array(&registry, "known_loss_fixtures") {
        let errors = loss_authorization_errors(&registry, string(fixture, "prohibited_text"));
        assert_eq!(
            errors,
            [string(fixture, "expected_error").to_owned()],
            "{} must fail for its intended reason",
            string(fixture, "fixture_id")
        );
    }
    assert!(
        loss_authorization_errors(
            &registry,
            "KEEP Kafka, Brotli, generic Serde, TOML, regex, OTLP logs, and SQLite until parity"
        )
        .is_empty(),
        "explicit preservation language must remain accepted"
    );
}

#[test]
fn negative_cutover_gate_bypass_fails_closed() {
    let registry = registry();
    let issues = tracker_issues();
    let mut cutover = parse_repo_json(CUTOVER_POLICY_PATH);
    cutover["global_gate_ids"]
        .as_array_mut()
        .expect("global_gate_ids")
        .retain(|gate| gate.as_str() != Some("GATE-E2E"));
    let errors = graph_signoff_errors(&registry, &issues, &cutover).join("\n");
    assert!(errors.contains("must retain every global cutover gate"));

    let mut cutover = parse_repo_json(CUTOVER_POLICY_PATH);
    let binding = cutover["capability_bindings"]
        .as_array_mut()
        .expect("capability_bindings")
        .iter_mut()
        .find(|binding| string(binding, "capability_id") == "CAP-KAFKA")
        .expect("Kafka cutover binding");
    binding["dependency_exit_allowed"] = Value::Bool(true);
    let errors = graph_signoff_errors(&registry, &issues, &cutover).join("\n");
    assert!(errors.contains("bypass required evidence"));
}

#[test]
fn diagnostics_are_stable_and_fully_mapped() {
    let registry = registry();
    let diagnostics = object(&registry, "diagnostic_inventory");
    let error_registry = parse_repo_json(ERROR_REGISTRY_PATH);
    let mut projection = String::new();
    let mut codes = BTreeSet::new();
    for row in array(&error_registry, "codes") {
        let code = string(row, "code");
        assert!(codes.insert(code.to_owned()), "duplicate error code {code}");
        projection.push_str(code);
        projection.push('\n');
    }
    assert_eq!(
        codes.len() as u64,
        diagnostics["expected_code_count"]
            .as_u64()
            .expect("expected_code_count must be an integer")
    );
    assert_eq!(
        sha256_hex(projection.as_bytes()),
        string(diagnostics, "code_projection_sha256"),
        "ASUP diagnostic code inventory drifted"
    );
    // 44 = the 43-code zxqaqs.2 seed plus ASUP-E404 (deterministic
    // snapshot artifact versioning, br-asupersync-5z2scg.3.3, 065615aa1 —
    // which landed without updating this pin; red at HEAD 07-26..07-29).
    assert_eq!(codes.len(), 44);
    assert_eq!(
        strings(diagnostics, "capability_ids"),
        ["CAP-DIAGNOSTICS".to_owned()]
    );
}

fn nested_manifest_references_asupersync(repo_path: &Path, primary_manifest: &Path) -> bool {
    let mut pending = vec![repo_path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if !matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some(".git" | "target" | "node_modules")
                ) {
                    pending.push(path);
                }
            } else if file_type.is_file()
                && path != primary_manifest
                && path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml")
                && std::fs::read_to_string(&path)
                    .is_ok_and(|manifest| manifest.contains("asupersync"))
            {
                return true;
            }
        }
    }
    false
}

#[test]
fn downstream_consumers_are_real_cycle_aware_manifests() {
    let registry = registry();
    let known_capabilities = capability_ids(&registry);
    let probe_policy = object(&registry, "downstream_probe_policy");
    assert_eq!(
        string(probe_policy, "remote_absence_state"),
        "BLOCKED_EXTERNAL"
    );
    assert_eq!(
        string(probe_policy, "executable_baseline_owner"),
        "asupersync-dep-p1-foundations-upksjk.5.2"
    );
    assert!(string(probe_policy, "remote_absence_rule").contains("may not claim downstream"));
    let portfolio_root = Path::new(string(probe_policy, "portfolio_root"));
    let mut unavailable_manifests = Vec::new();
    let mut consumer_ids = BTreeSet::new();
    for row in array(&registry, "downstream_consumers") {
        let consumer_id = string(row, "consumer_id");
        assert!(
            consumer_ids.insert(consumer_id.to_owned()),
            "duplicate downstream consumer {consumer_id}"
        );
        let repo_path = string(row, "repo_path");
        let manifest_path = string(row, "manifest_path");
        if Path::new(manifest_path).is_file() {
            assert!(Path::new(repo_path).is_dir(), "{consumer_id}: missing repo");
            let manifest = std::fs::read_to_string(manifest_path)
                .unwrap_or_else(|error| panic!("{consumer_id}: cannot read manifest: {error}"));
            assert!(
                manifest.contains("asupersync")
                    || nested_manifest_references_asupersync(
                        Path::new(repo_path),
                        Path::new(manifest_path),
                    ),
                "{consumer_id}: neither the root manifest nor a workspace member references asupersync"
            );
        } else {
            unavailable_manifests.push(manifest_path.to_owned());
            assert!(
                Path::new(repo_path).starts_with(portfolio_root)
                    && Path::new(manifest_path).starts_with(portfolio_root),
                "{consumer_id}: unavailable portfolio path must remain under {}",
                portfolio_root.display()
            );
        }
        assert!(
            !strings(row, "feature_profiles").is_empty(),
            "{consumer_id}: feature profiles must be explicit"
        );
        for capability_id in strings(row, "capability_ids") {
            assert!(
                known_capabilities.contains(&capability_id),
                "{consumer_id}: unknown capability {capability_id}"
            );
        }
    }
    assert!(
        consumer_ids.contains("frankensqlite"),
        "reverse-dependency cycle owner must remain explicit"
    );
    assert!(
        consumer_ids.len() >= 15,
        "portfolio inventory unexpectedly narrowed"
    );
    if !unavailable_manifests.is_empty() {
        assert_eq!(
            string(probe_policy, "remote_absence_state"),
            "BLOCKED_EXTERNAL"
        );
        eprintln!(
            "[{SCENARIO_ID}] downstream portfolio BLOCKED_EXTERNAL because {} is incomplete or unavailable; unavailable manifests: {}",
            portfolio_root.display(),
            unavailable_manifests.join(",")
        );
    }
}

#[test]
fn every_capability_is_referenced_by_a_drift_checked_inventory() {
    let registry = registry();
    let all = capability_ids(&registry);
    let mapped = mapped_capability_ids(&registry);
    let orphaned = all.difference(&mapped).cloned().collect::<Vec<_>>();
    assert!(
        orphaned.is_empty(),
        "capabilities with no feature/binary/format/journey/taxonomy/consumer/bead/API mapping: {orphaned:?}"
    );
}

#[test]
fn human_summary_is_deterministic_and_current() {
    let registry = registry();
    let expected = render_generated_summary(&registry);
    let doc = read_repo_file(DOC_PATH);
    assert_eq!(
        generated_doc_block(&doc),
        expected,
        "generated human summary drifted; update it from the canonical artifact"
    );
    assert!(doc.contains("UNKNOWN_BLOCKING"));
    assert!(doc.contains("No feature loss"));
    assert!(doc.contains("scripts/run_all_e2e.sh --suite dependency-sovereignty"));
    assert!(doc.contains("FrankenSQLite"));
}

/// Every `dependency_owners` entry must name something real: a package that
/// `Cargo.lock` resolves, or an explicitly declared non-crate owner.
///
/// This is what catches invented crates. `CAP-NKEY-AUTH` listed `base32` and
/// `crc16` as if they were dependencies; neither exists anywhere in the graph
/// (base32 is `data-encoding`, and CRC-16/XMODEM lives inside `nkeys`). An SBOM
/// or marginal-cost calculation built from that field would have referenced
/// packages that are not in the build.
#[test]
fn every_dependency_owner_resolves_to_a_package_or_a_declared_non_crate_owner() {
    let registry = registry();
    let packages = locked_package_names();
    let non_crate = declared_non_crate_owners(&registry);
    assert!(
        !non_crate.is_empty(),
        "allowed_non_crate_dependency_owners must declare the sentinel vocabulary"
    );
    for (owner, reason) in &non_crate {
        assert!(
            !reason.trim().is_empty(),
            "non-crate dependency owner {owner} must carry a reason"
        );
    }

    let mut unresolved = Vec::new();
    for row in array(&registry, "capabilities") {
        let capability_id = string(row, "capability_id");
        for owner in strings(row, "dependency_owners") {
            if non_crate.contains_key(&owner) || resolves_to_package(&owner, &packages) {
                continue;
            }
            unresolved.push(format!("{capability_id}: {owner}"));
        }
    }
    assert!(
        unresolved.is_empty(),
        "these dependency_owners resolve to no Cargo.lock package and are not declared \
         non-crate owners: {unresolved:#?}"
    );
}

/// A `source_owners` file must actually reference one of the row's crate
/// dependencies. Asserting only that the path exists is far too weak.
///
/// The registry named `src/web/compress.rs` for `CAP-HTTP-COMPRESSION`. That
/// file exists — so the path check passed — but it contains no compression
/// crate at all; the real owner is `src/http/compress.rs`. Two files share a
/// name and the registry named the wrong one. The same class of error credited
/// the RaptorQ pipeline with two serialization capabilities and pointed the
/// regex capability at a module with zero regex references.
#[test]
fn every_source_owner_row_attributes_to_its_dependency() {
    let registry = registry();
    let packages = locked_package_names();
    let non_crate = declared_non_crate_owners(&registry);
    let exemptions = attribution_exemptions(&registry);

    let mut unattributed = Vec::new();
    for row in array(&registry, "capabilities") {
        let capability_id = string(row, "capability_id");
        if exemptions.contains_key(capability_id) {
            continue;
        }
        if source_owner_attribution_fails(row, &packages, &non_crate) {
            unattributed.push(format!(
                "{capability_id}: source_owners {:?} reference none of {:?}",
                strings(row, "source_owners"),
                strings(row, "dependency_owners")
            ));
        }
    }
    assert!(
        unattributed.is_empty(),
        "these capability rows name source owners that do not implement the capability: {unattributed:#?}"
    );
}

/// An exemption must still be earned. If a row is corrected so that it now
/// attributes cleanly, its exemption has to go — otherwise the exemption list
/// becomes a place where defects hide after they stop being defects.
#[test]
fn no_attribution_exemption_is_stale() {
    let registry = registry();
    let packages = locked_package_names();
    let non_crate = declared_non_crate_owners(&registry);
    let exemptions = attribution_exemptions(&registry);
    let known = capability_ids(&registry);

    let mut stale = Vec::new();
    for (capability_id, reason) in &exemptions {
        assert!(
            known.contains(capability_id),
            "attribution exemption names unknown capability {capability_id}"
        );
        assert!(
            !reason.trim().is_empty(),
            "attribution exemption for {capability_id} must carry a reason"
        );
        let row = array(&registry, "capabilities")
            .iter()
            .find(|row| string(row, "capability_id") == capability_id)
            .expect("capability row must exist");
        if !source_owner_attribution_fails(row, &packages, &non_crate) {
            stale.push(capability_id.clone());
        }
    }
    assert!(
        stale.is_empty(),
        "these rows now attribute cleanly and must drop their exemption: {stale:?}"
    );
}
