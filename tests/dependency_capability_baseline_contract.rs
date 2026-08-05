//! Fail-closed executable-baseline contract for dependency sovereignty.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.5.2
//! Scenario: dependency_capability_baseline_contract_v1
//! Fixture: artifacts/dependency_capability_baseline_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.5.2";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const DOC_PATH: &str = "docs/dependency_capability_baseline.md";
const RUNNER_PATH: &str = "scripts/run_dependency_capability_baseline.sh";
const CONSUMER_MANIFEST: &str = "tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml";
const CONSUMER_LOCK: &str = "tests/fixtures/dependency-capability-baseline-consumer/Cargo.lock";
const CONSUMER_SOURCE: &str = "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const GENERATED_BEGIN: &str = "<!-- BEGIN GENERATED BASELINE SUMMARY -->";
const GENERATED_END: &str = "<!-- END GENERATED BASELINE SUMMARY -->";
const HOST_METADATA_BEAD_ID: &str = "asupersync-d24mms.2";
const HOST_METADATA_AUDIT_ID: &str = "CAP-HOST-BENCH-METADATA-STATIC-AUDIT-V1";
const NUM_CPUS_CALL: &str = concat!("num_cpus", "::get()");
const WHOAMI_CALL: &str = concat!("whoami", "::distro()");

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

fn parse_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_json(ARTIFACT_PATH)
}

fn registry() -> Value {
    parse_json(REGISTRY_PATH)
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

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn unsigned(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn count_occurrences(source: &str, token: &str) -> u64 {
    u64::try_from(source.matches(token).count()).expect("source token count fits u64")
}

fn path_exists(path: &str) -> bool {
    let path = Path::new(path);
    if path.is_absolute() {
        path.exists()
    } else {
        repo_root().join(path).exists()
    }
}

fn tracker_ids() -> BTreeSet<String> {
    read_repo_file(TRACKER_PATH)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let issue: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{TRACKER_PATH} contains invalid JSONL: {error}"));
            string(&issue, "id").to_owned()
        })
        .collect()
}

fn registry_rows() -> BTreeMap<String, Value> {
    array(&registry(), "capabilities")
        .iter()
        .map(|row| (string(row, "capability_id").to_owned(), row.clone()))
        .collect()
}

fn evidence_rows(value: &Value) -> BTreeMap<String, Value> {
    array(value, "evidence_catalog")
        .iter()
        .filter_map(|row| {
            row.get("evidence_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), row.clone()))
        })
        .collect()
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

fn validate_baseline(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let required_cases = string_set(value, "case_classes");
    let parity_modes = string_set(value, "parity_modes");
    let baseline_states = string_set(value, "baseline_states");
    let case_dispositions = string_set(value, "case_dispositions");
    let known_beads = tracker_ids();
    let registry = registry_rows();

    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        errors.push("schema_version must be 1".to_owned());
    }
    if string(value, "artifact_id") != "dependency-capability-baseline-v1" {
        errors.push("artifact_id must be dependency-capability-baseline-v1".to_owned());
    }
    if string(value, "program_id") != PROGRAM_ID {
        errors.push(format!("program_id must be {PROGRAM_ID}"));
    }
    if string(value, "bead_id") != BEAD_ID {
        errors.push(format!("bead_id must be {BEAD_ID}"));
    }
    if string(value, "registry_artifact") != REGISTRY_PATH {
        errors.push(format!("registry_artifact must be {REGISTRY_PATH}"));
    }
    nonempty_string(value, "purpose", &mut errors, "artifact");
    nonempty_string(value, "captured_at_utc", &mut errors, "artifact");
    let revision = string(value, "baseline_source_revision");
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        errors.push("baseline_source_revision must be a full 40-hex Git revision".to_owned());
    }
    if required_cases
        != BTreeSet::from([
            "cancellation_cleanup".to_owned(),
            "empty_boundary".to_owned(),
            "malformed_error".to_owned(),
            "positive".to_owned(),
            "recovery".to_owned(),
            "resource_limit".to_owned(),
        ])
    {
        errors.push("case_classes must preserve the canonical six-case taxonomy".to_owned());
    }
    if parity_modes
        != BTreeSet::from([
            "ERROR_CONTRACT".to_owned(),
            "EXACT_BYTES".to_owned(),
            "LIFECYCLE".to_owned(),
            "OPERATOR_UX".to_owned(),
            "PLATFORM_MATRIX".to_owned(),
            "PUBLIC_COMPILE".to_owned(),
            "RESOURCE_ENVELOPE".to_owned(),
            "SECURITY_POLICY".to_owned(),
            "SEMANTIC".to_owned(),
            "SERVICE_INTEROP".to_owned(),
        ])
    {
        errors.push("parity_modes must preserve all ten independent contracts".to_owned());
    }
    if baseline_states
        != BTreeSet::from([
            "BLOCKED_EXTERNAL".to_owned(),
            "BLOCKED_OWNER".to_owned(),
            "BLOCKED_PLATFORM".to_owned(),
            "EXECUTABLE_COMPLETE".to_owned(),
            "EXECUTABLE_PARTIAL_BLOCKING".to_owned(),
        ])
    {
        errors.push("baseline_states must preserve the canonical state taxonomy".to_owned());
    }
    if case_dispositions
        != BTreeSet::from([
            "BLOCKED_EXTERNAL".to_owned(),
            "BLOCKED_OWNER".to_owned(),
            "BLOCKED_PLATFORM".to_owned(),
            "EVIDENCE".to_owned(),
            "NOT_APPLICABLE".to_owned(),
        ])
    {
        errors
            .push("case_dispositions must preserve the canonical disposition taxonomy".to_owned());
    }

    let evidence_catalog = array(value, "evidence_catalog");
    let evidence = evidence_rows(value);
    if evidence.len() != evidence_catalog.len() {
        errors.push("evidence_id values must be unique".to_owned());
    }
    for row in evidence_catalog {
        let evidence_id = row
            .get("evidence_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing-evidence-id>");
        for key in ["evidence_id", "feature_profile", "target", "replay_command"] {
            nonempty_string(row, key, &mut errors, evidence_id);
        }
        let Some(paths) = row.get("fixture_paths").and_then(Value::as_array) else {
            errors.push(format!("{evidence_id}: fixture_paths must be an array"));
            continue;
        };
        if paths.is_empty() {
            errors.push(format!("{evidence_id}: fixture_paths must not be empty"));
        }
        for path in paths {
            let Some(path) = path.as_str() else {
                errors.push(format!("{evidence_id}: fixture path must be a string"));
                continue;
            };
            if path.starts_with("planned://") {
                errors.push(format!(
                    "{evidence_id}: planned placeholder is not evidence"
                ));
            } else if !path_exists(path) {
                errors.push(format!(
                    "{evidence_id}: fixture path does not exist: {path}"
                ));
            }
        }

        let command = row
            .get("replay_command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- ") {
            errors.push(format!(
                "{evidence_id}: replay command must require remote RCH"
            ));
        }
        for token in [
            "CARGO_TARGET_DIR=",
            "CARGO_INCREMENTAL=0",
            "CARGO_PROFILE_TEST_DEBUG=0",
            "RUSTFLAGS='-D warnings -C debuginfo=0'",
            "cargo ",
        ] {
            if !command.contains(token) {
                errors.push(format!(
                    "{evidence_id}: replay command missing required token {token}"
                ));
            }
        }
        if command.contains("planned://") {
            errors.push(format!(
                "{evidence_id}: replay command contains planned placeholder"
            ));
        }
        if evidence_id.starts_with("EVD-CONSUMER-") && !command.contains("--locked") {
            errors.push(format!(
                "{evidence_id}: standalone consumer replay must use --locked"
            ));
        }

        let catalog_cases: BTreeSet<_> = row
            .get("case_classes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if catalog_cases.is_empty() || !catalog_cases.is_subset(&required_cases) {
            errors.push(format!(
                "{evidence_id}: case_classes must be a nonempty allowed subset"
            ));
        }
        let minimum_tests = row
            .get("expected")
            .and_then(|expected| expected.get("minimum_tests"))
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if minimum_tests == 0 {
            errors.push(format!(
                "{evidence_id}: expected.minimum_tests must reject zero-test success"
            ));
        }
        let observables = row
            .get("expected")
            .and_then(|expected| expected.get("observables"))
            .and_then(Value::as_array);
        if observables.is_none_or(|entries| entries.is_empty()) {
            errors.push(format!(
                "{evidence_id}: expected.observables must be nonempty"
            ));
        }
    }

    let profiles = array(value, "consumer_profiles");
    let profile_ids: BTreeSet<_> = profiles
        .iter()
        .filter_map(|profile| profile.get("profile_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    if profile_ids != BTreeSet::from(["consumer-default".to_owned(), "consumer-full".to_owned()]) {
        errors.push("consumer profiles must be exactly consumer-default and consumer-full".into());
    }
    for profile in profiles {
        let profile_id = profile
            .get("profile_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing-profile-id>");
        if profile.get("manifest").and_then(Value::as_str) != Some(CONSUMER_MANIFEST) {
            errors.push(format!(
                "{profile_id}: manifest must name the standalone consumer"
            ));
        }
        let expected_minimum = if profile_id == "consumer-full" { 9 } else { 7 };
        if profile.get("minimum_tests").and_then(Value::as_u64) != Some(expected_minimum) {
            errors.push(format!(
                "{profile_id}: minimum_tests must be exactly {expected_minimum}"
            ));
        }
        if profile.get("lockfile").and_then(Value::as_str) != Some(CONSUMER_LOCK) {
            errors.push(format!(
                "{profile_id}: lockfile must pin the standalone resolution"
            ));
        }
        let expected_features = if profile_id == "consumer-full" {
            BTreeSet::from(["full-profile".to_owned()])
        } else {
            BTreeSet::new()
        };
        if string_set(profile, "features") != expected_features {
            errors.push(format!(
                "{profile_id}: feature set must remain explicit and canonical"
            ));
        }
        if array(profile, "surfaces").is_empty() {
            errors.push(format!(
                "{profile_id}: surfaces must name the downstream contract"
            ));
        }
    }

    let baselines = array(value, "capability_baselines");
    let baseline_ids: BTreeSet<_> = baselines
        .iter()
        .filter_map(|row| row.get("capability_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let registry_ids: BTreeSet<_> = registry.keys().cloned().collect();
    if baseline_ids.len() != baselines.len() {
        errors.push("capability_id values must be unique".to_owned());
    }
    if baseline_ids != registry_ids {
        errors.push("capability baselines must exactly cover CAP A1 registry IDs".to_owned());
    }

    for row in baselines {
        let capability_id = row
            .get("capability_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing-capability-id>");
        for key in ["capability_id", "baseline_state", "no_claim_boundary"] {
            nonempty_string(row, key, &mut errors, capability_id);
        }
        let state = row
            .get("baseline_state")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !baseline_states.contains(state) {
            errors.push(format!(
                "{capability_id}: unsupported baseline_state {state}"
            ));
        }
        if row.get("cutover_eligible").and_then(Value::as_bool) != Some(false) {
            errors.push(format!(
                "{capability_id}: baseline evidence may never authorize cutover"
            ));
        }

        let row_modes: BTreeSet<_> = row
            .get("parity_modes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if row_modes.is_empty() || !row_modes.is_subset(&parity_modes) {
            errors.push(format!(
                "{capability_id}: parity_modes must be a nonempty allowed subset"
            ));
        }

        let row_evidence: BTreeSet<_> = row
            .get("evidence_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if row_evidence.is_empty() {
            errors.push(format!("{capability_id}: evidence_ids must not be empty"));
        }
        for evidence_id in &row_evidence {
            if !evidence.contains_key(evidence_id) {
                errors.push(format!(
                    "{capability_id}: unknown evidence_id {evidence_id}"
                ));
            }
        }

        for profile_id in row
            .get("downstream_profiles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !profile_ids.contains(profile_id) {
                errors.push(format!(
                    "{capability_id}: unknown downstream profile {profile_id}"
                ));
            }
        }

        if let Some(registry_row) = registry.get(capability_id) {
            let registry_scenarios: BTreeSet<_> = array(registry_row, "scenario_ids")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let baseline_scenarios: BTreeSet<_> = row
                .get("scenario_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            if baseline_scenarios != registry_scenarios {
                errors.push(format!(
                    "{capability_id}: scenario_ids must exactly match CAP A1"
                ));
            }
        }

        let Some(cases) = row.get("cases").and_then(Value::as_object) else {
            errors.push(format!("{capability_id}: cases must be an object"));
            continue;
        };
        let case_names: BTreeSet<_> = cases.keys().cloned().collect();
        if case_names != required_cases {
            errors.push(format!(
                "{capability_id}: every required case must be classified exactly once"
            ));
        }

        let mut blocker_dispositions = BTreeSet::new();
        for (case_name, case) in cases {
            let disposition = case
                .get("disposition")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !case_dispositions.contains(disposition) {
                errors.push(format!(
                    "{capability_id}/{case_name}: unsupported disposition {disposition}"
                ));
                continue;
            }
            match disposition {
                "EVIDENCE" => {
                    let evidence_id = case
                        .get("evidence_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !row_evidence.contains(evidence_id) {
                        errors.push(format!(
                            "{capability_id}/{case_name}: evidence must be listed on the row"
                        ));
                    }
                    let supports_case = evidence.get(evidence_id).is_some_and(|evidence_row| {
                        evidence_row
                            .get("case_classes")
                            .and_then(Value::as_array)
                            .is_some_and(|classes| {
                                classes
                                    .iter()
                                    .any(|entry| entry.as_str() == Some(case_name.as_str()))
                            })
                    });
                    if !supports_case {
                        errors.push(format!(
                            "{capability_id}/{case_name}: evidence {evidence_id} does not declare this case class"
                        ));
                    }
                }
                "BLOCKED_EXTERNAL" | "BLOCKED_PLATFORM" | "BLOCKED_OWNER" => {
                    blocker_dispositions.insert(disposition.to_owned());
                    let owner = case
                        .get("owner_bead")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !known_beads.contains(owner) {
                        errors.push(format!(
                            "{capability_id}/{case_name}: blocker owner bead must exist"
                        ));
                    }
                    nonempty_string(
                        case,
                        "reason",
                        &mut errors,
                        &format!("{capability_id}/{case_name}"),
                    );
                }
                "NOT_APPLICABLE" => nonempty_string(
                    case,
                    "reason",
                    &mut errors,
                    &format!("{capability_id}/{case_name}"),
                ),
                _ => {}
            }
        }

        match state {
            "EXECUTABLE_COMPLETE" if !blocker_dispositions.is_empty() => errors.push(format!(
                "{capability_id}: EXECUTABLE_COMPLETE may not contain blockers"
            )),
            "EXECUTABLE_PARTIAL_BLOCKING" if blocker_dispositions.is_empty() => errors.push(
                format!("{capability_id}: partial state must contain a typed blocker"),
            ),
            "BLOCKED_EXTERNAL" if !blocker_dispositions.contains("BLOCKED_EXTERNAL") => errors
                .push(format!(
                    "{capability_id}: BLOCKED_EXTERNAL state needs an external blocker"
                )),
            "BLOCKED_PLATFORM" if !blocker_dispositions.contains("BLOCKED_PLATFORM") => errors
                .push(format!(
                    "{capability_id}: BLOCKED_PLATFORM state needs a platform blocker"
                )),
            "BLOCKED_OWNER" if !blocker_dispositions.contains("BLOCKED_OWNER") => errors.push(
                format!("{capability_id}: BLOCKED_OWNER state needs an owner blocker"),
            ),
            _ => {}
        }
    }

    let runner = value
        .get("runner_contract")
        .unwrap_or_else(|| panic!("runner_contract must be present"));
    if runner.get("script").and_then(Value::as_str) != Some(RUNNER_PATH) {
        errors.push(format!("runner_contract.script must be {RUNNER_PATH}"));
    }
    for key in [
        "scenarios",
        "required_files",
        "required_provenance",
        "required_outcomes",
    ] {
        if runner
            .get(key)
            .and_then(Value::as_array)
            .is_none_or(|entries| entries.is_empty())
        {
            errors.push(format!("runner_contract.{key} must be nonempty"));
        }
    }
    for required in ["summary.json", "events.ndjson", "stdout.log", "stderr.log"] {
        if !string_set(runner, "required_files").contains(required) {
            errors.push(format!("runner_contract missing required file {required}"));
        }
    }
    if string_set(runner, "scenarios")
        != BTreeSet::from([
            "catalog".to_owned(),
            "consumer-default".to_owned(),
            "consumer-full".to_owned(),
            "contract".to_owned(),
        ])
    {
        errors.push("runner_contract scenarios must preserve all four focused lanes".to_owned());
    }
    for (scenario, minimum) in [
        ("contract", 26),
        ("consumer-default", 7),
        ("consumer-full", 9),
        ("catalog", 1),
    ] {
        if runner
            .get("scenario_minimum_tests")
            .and_then(|floors| floors.get(scenario))
            .and_then(Value::as_u64)
            != Some(minimum)
        {
            errors.push(format!(
                "runner_contract minimum for {scenario} must remain {minimum}"
            ));
        }
    }
    for required in [
        "source_revision",
        "baseline_revision",
        "rustc",
        "cargo",
        "command",
        "features",
        "fixture_id",
        "fixture_digest",
        "fixture_manifest",
        "target",
        "host",
        "execution_tree",
        "controller_dirty_paths",
        "rch_worker",
        "scenario_id",
        "step_id",
    ] {
        if !string_set(runner, "required_provenance").contains(required) {
            errors.push(format!(
                "runner_contract missing required provenance field {required}"
            ));
        }
    }
    for required in [
        "PASS",
        "FAIL",
        "BLOCKED_EXTERNAL",
        "BLOCKED_PLATFORM",
        "BLOCKED_OWNER",
        "UNSUPPORTED",
    ] {
        if !string_set(runner, "required_outcomes").contains(required) {
            errors.push(format!(
                "runner_contract missing required outcome {required}"
            ));
        }
    }

    if array(value, "no_claim_boundaries").len() < 5 {
        errors.push("no_claim_boundaries must remain comprehensive".to_owned());
    }
    errors
}

fn assert_invalid(mutated: Value, expected_fragment: &str) {
    let errors = validate_baseline(&mutated);
    assert!(
        errors.iter().any(|error| error.contains(expected_fragment)),
        "expected error containing {expected_fragment:?}, got {errors:#?}"
    );
}

fn capability_index(value: &Value, capability_id: &str) -> usize {
    array(value, "capability_baselines")
        .iter()
        .position(|row| row.get("capability_id").and_then(Value::as_str) == Some(capability_id))
        .unwrap_or_else(|| panic!("missing capability {capability_id}"))
}

fn evidence_index(value: &Value, evidence_id: &str) -> usize {
    array(value, "evidence_catalog")
        .iter()
        .position(|row| row.get("evidence_id").and_then(Value::as_str) == Some(evidence_id))
        .unwrap_or_else(|| panic!("missing evidence {evidence_id}"))
}

fn render_summary(value: &Value) -> String {
    let mut states = BTreeMap::<String, usize>::new();
    let mut rows = Vec::new();
    for row in array(value, "capability_baselines") {
        *states
            .entry(string(row, "baseline_state").to_owned())
            .or_default() += 1;
        let blocked = row
            .get("cases")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, case)| {
                case.get("disposition")
                    .and_then(Value::as_str)
                    .is_some_and(|disposition| disposition.starts_with("BLOCKED_"))
            })
            .count();
        rows.push((
            string(row, "capability_id").to_owned(),
            string(row, "baseline_state").to_owned(),
            blocked,
            array(row, "evidence_ids").len(),
        ));
    }
    rows.sort();

    let state_summary = states
        .iter()
        .map(|(state, count)| format!("{state}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut output = format!(
        "- Artifact: `dependency-capability-baseline-v1` (schema 1)\n- Coverage: {} capabilities; {} evidence entries; {} consumer profiles.\n- States: {state_summary}.\n\n| Capability ID | Baseline state | Evidence | Blocked cases |\n|---|---|---:|---:|\n",
        rows.len(),
        array(value, "evidence_catalog").len(),
        array(value, "consumer_profiles").len()
    );
    for (capability_id, state, blocked, evidence_count) in rows {
        output.push_str(&format!(
            "| `{capability_id}` | {state} | {evidence_count} | {blocked} |\n"
        ));
    }
    output
}

#[test]
fn canonical_baseline_is_complete_and_fail_closed() {
    let errors = validate_baseline(&artifact());
    assert!(
        errors.is_empty(),
        "baseline validation failed:\n{errors:#?}"
    );
}

#[test]
fn standalone_consumer_is_public_only_and_feature_explicit() {
    let manifest_source = read_repo_file(CONSUMER_MANIFEST);
    let manifest: toml::Value =
        toml::from_str(&manifest_source).expect("standalone consumer manifest must parse");
    let lock = read_repo_file(CONSUMER_LOCK);
    let source = read_repo_file(CONSUMER_SOURCE);
    assert!(manifest.get("workspace").is_some());
    assert!(manifest["features"].get("full-profile").is_some());
    assert_eq!(manifest["dependencies"]["prost"].as_str(), Some("=0.14.4"));
    assert_eq!(
        manifest["dependencies"]["serde"]["version"].as_str(),
        Some("=1.0.229")
    );
    assert_eq!(
        manifest["dependencies"]["tower"]["version"].as_str(),
        Some("=0.5.3")
    );
    assert!(
        manifest["features"]
            .as_table()
            .expect("features table")
            .values()
            .flat_map(|value| value.as_array().into_iter().flatten())
            .all(|feature| feature.as_str() != Some("asupersync/test-internals")),
        "standalone profiles must never enable asupersync/test-internals"
    );
    assert!(
        manifest["dependencies"]["asupersync"]
            .get("features")
            .and_then(toml::Value::as_array)
            .is_none_or(|features| features
                .iter()
                .all(|feature| feature.as_str() != Some("test-internals"))),
        "standalone dependency must never enable test-internals directly"
    );
    assert!(
        manifest["dependencies"]["asupersync"]
            .get("workspace")
            .is_none(),
        "standalone dependency must not inherit root workspace settings"
    );
    assert!(lock.starts_with("# This file is automatically @generated by Cargo."));
    assert!(lock.contains("name = \"prost\"\nversion = \"0.14.4\""));
    assert!(lock.contains("name = \"serde\"\nversion = \"1.0.229\""));
    assert!(lock.contains("name = \"tower\"\nversion = \"0.5.3\""));
    assert!(!source.contains("Cx::new()"));
    assert!(source.contains("ConsumerRecord"));
    assert!(source.contains("ConsumerProto"));
    assert!(source.contains("DownstreamStream"));
    assert!(source.contains("InMemoryExporter"));
    assert!(source.contains("TowerService"));
}

#[test]
fn runner_and_docs_expose_replay_logging_and_no_claim_boundaries() {
    let runner = read_repo_file(RUNNER_PATH);
    let docs = read_repo_file(DOC_PATH);
    for required in [
        "summary.json",
        "events.ndjson",
        "stdout.log",
        "stderr.log",
        "provenance.json",
        "replay.sh",
        "BLOCKED_EXTERNAL",
        "BLOCKED_PLATFORM",
        "minimum_tests",
        "MINIMUM_TESTS=26",
        "COMMAND_DISPLAY",
        "FIXTURE_ID",
        "FIXTURE_MANIFEST",
        "sha256_stream",
        "sha256sum",
        "shasum",
        "generated_paths",
        "redact_stream",
        "CAP_A2_LOG_REDACTION_CANARY",
        "provenance failure",
        "--base HEAD",
        "--clean-overlay",
        "--no-overlay",
    ] {
        assert!(
            runner.contains(required),
            "runner missing required contract token {required}"
        );
    }
    for required in [
        "not cutover evidence",
        "zero tests",
        "No feature loss",
        "consumer-default",
        "consumer-full",
        HOST_METADATA_AUDIT_ID,
        HOST_METADATA_BEAD_ID,
        "STATIC_SOURCE_PINNED_NOT_EXECUTED",
        "NO_PLATFORM_OR_PROFILE_MATRIX_EXECUTED",
        "KEEP_INCUMBENT",
        "dependency_exit_allowed=false",
        GENERATED_BEGIN,
        GENERATED_END,
    ] {
        assert!(
            docs.contains(required),
            "documentation missing required contract token {required}"
        );
    }
}

#[test]
fn host_benchmark_metadata_static_audit_is_source_pinned_and_fail_closed() {
    let value = artifact();
    let audit = object(&value, "host_benchmark_metadata_static_audit");
    assert_eq!(string(audit, "audit_id"), HOST_METADATA_AUDIT_ID);
    assert_eq!(string(audit, "bead_id"), HOST_METADATA_BEAD_ID);
    assert_eq!(
        string_set(audit, "capability_ids"),
        BTreeSet::from([
            "CAP-HOST-BENCH-METADATA".to_owned(),
            "CAP-HOST-INTROSPECTION".to_owned(),
        ])
    );
    assert_eq!(
        string(audit, "audit_state"),
        "STATIC_SOURCE_PINNED_NOT_EXECUTED"
    );
    assert_eq!(
        string(audit, "execution_state"),
        "NO_PLATFORM_OR_PROFILE_MATRIX_EXECUTED"
    );
    assert_eq!(string(audit, "observed_at_revision").len(), 40);

    let decision = object(audit, "decision");
    assert_eq!(
        string_set(decision, "dependencies"),
        BTreeSet::from(["num_cpus".to_owned(), "whoami".to_owned()])
    );
    assert_eq!(string(decision, "disposition"), "KEEP_INCUMBENT");
    assert!(!boolean(decision, "dependency_exit_allowed"));
    assert!(!boolean(decision, "manifest_or_lockfile_edit_allowed"));
    assert!(!boolean(decision, "source_behavior_change_allowed"));

    let pins = array(audit, "source_pins");
    assert_eq!(pins.len(), 11);
    let pinned_paths = pins
        .iter()
        .map(|pin| string(pin, "path"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        pinned_paths,
        BTreeSet::from([
            "Cargo.lock",
            "Cargo.toml",
            "artifacts/dependency_capability_registry_v1.json",
            "scripts/run_all_e2e.sh",
            "scripts/run_dependency_sovereignty_e2e.sh",
            "src/atp/benchmark/adapters.rs",
            "src/atp/benchmark/mod.rs",
            "src/atp/benchmark/profiles.rs",
            "src/atp/benchmark/reports.rs",
            "src/atp/mod.rs",
            "tests/atp_benchmark_integration.rs",
        ])
    );
    for pin in pins {
        let path = string(pin, "path");
        let source = read_repo_file(path);
        assert_eq!(
            sha256_hex(&read_repo_bytes(path)),
            string(pin, "sha256"),
            "source pin drift for {path}"
        );
        assert_eq!(
            u64::try_from(source.lines().count()).expect("line count fits u64"),
            unsigned(pin, "line_count"),
            "line-count drift for {path}"
        );
        assert!(!string(pin, "role").trim().is_empty());
    }

    let inventory = object(audit, "call_site_inventory");
    assert_eq!(string(inventory, "state"), "STATIC_COMPLETE_TWO_OF_TWO");
    assert_eq!(unsigned(inventory, "total_dependency_call_sites"), 2);
    let rows = array(inventory, "rows");
    assert_eq!(rows.len(), 2);
    let by_dependency = rows
        .iter()
        .map(|row| (string(row, "dependency"), row))
        .collect::<BTreeMap<_, _>>();
    let num_cpus = by_dependency
        .get("num_cpus")
        .copied()
        .expect("num_cpus row");
    assert_eq!(string(num_cpus, "locked_version"), "1.17.0");
    assert_eq!(string(num_cpus, "path"), "src/atp/benchmark/mod.rs");
    assert_eq!(string(num_cpus, "expression"), NUM_CPUS_CALL);
    assert_eq!(string(num_cpus, "output_field"), "cpu_info");
    assert_eq!(
        string(num_cpus, "candidate"),
        "std::thread::available_parallelism"
    );
    let whoami = by_dependency
        .get("whoami")
        .copied()
        .expect("whoami row");
    assert_eq!(string(whoami, "locked_version"), "2.1.2");
    assert_eq!(string(whoami, "path"), "src/atp/benchmark/mod.rs");
    assert_eq!(string(whoami, "expression"), WHOAMI_CALL);
    assert_eq!(string(whoami, "output_field"), "os_info");

    let benchmark = read_repo_file("src/atp/benchmark/mod.rs");
    assert_eq!(count_occurrences(&benchmark, NUM_CPUS_CALL), 1);
    assert_eq!(count_occurrences(&benchmark, WHOAMI_CALL), 1);
    assert!(benchmark.contains("unwrap_or_else(|_| \"unknown\".to_string())"));
    assert!(benchmark.contains("format!(\"{}x {}\""));
    let lock = read_repo_file("Cargo.lock");
    assert!(lock.contains("name = \"num_cpus\"\nversion = \"1.17.0\""));
    assert!(lock.contains("name = \"whoami\"\nversion = \"2.1.2\""));

    let feature = object(audit, "feature_and_schema_contract");
    assert_eq!(
        string(feature, "module_gate"),
        "cfg(feature = benchmark-adapters)"
    );
    assert_eq!(
        string_set(feature, "default_features"),
        BTreeSet::from([
            "nightly-outcome-try".to_owned(),
            "proc-macros".to_owned(),
        ])
    );
    assert!(!boolean(feature, "default_profile_reaches_benchmark_module"));
    assert_eq!(
        string_set(feature, "benchmark_adapters_dependency_edges"),
        BTreeSet::from(["dep:num_cpus".to_owned(), "dep:whoami".to_owned()])
    );
    assert_eq!(
        string_set(feature, "benchmark_environment_fields"),
        BTreeSet::from([
            "cpu_info".to_owned(),
            "env_vars".to_owned(),
            "memory_info".to_owned(),
            "network_info".to_owned(),
            "os_info".to_owned(),
            "timestamp".to_owned(),
        ])
    );
    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("default = [\"proc-macros\", \"nightly-outcome-try\"]"));
    assert!(manifest.contains("\"dep:num_cpus\""));
    assert!(manifest.contains("\"dep:whoami\""));
    let atp_module = read_repo_file("src/atp/mod.rs");
    assert!(
        atp_module.contains("#[cfg(feature = \"benchmark-adapters\")]\npub mod benchmark;")
    );

    let adapters = read_repo_file("src/atp/benchmark/adapters.rs");
    let profiles = read_repo_file("src/atp/benchmark/profiles.rs");
    let reports = read_repo_file("src/atp/benchmark/reports.rs");
    assert_eq!(
        count_occurrences(&adapters, "BenchmarkEnvironment::collect()?"),
        4
    );
    assert_eq!(
        count_occurrences(&profiles, "BenchmarkEnvironment::collect()?"),
        1
    );
    assert_eq!(
        count_occurrences(&benchmark, "BenchmarkEnvironment::collect().unwrap()"),
        1
    );
    assert_eq!(
        count_occurrences(&reports, "BenchmarkEnvironment::collect().unwrap()"),
        3
    );
    assert_eq!(unsigned(feature, "production_collection_call_count"), 5);
    assert_eq!(unsigned(feature, "unit_only_collection_call_count"), 4);
    assert_eq!(
        unsigned(feature, "integration_host_metadata_assertion_count"),
        0
    );
    let integration = read_repo_file("tests/atp_benchmark_integration.rs");
    for absent in ["BenchmarkEnvironment", "os_info", "cpu_info"] {
        assert!(
            !integration.contains(absent),
            "integration surface unexpectedly contains {absent}"
        );
    }

    let evidence = object(audit, "existing_evidence_assessment");
    assert_eq!(string(evidence, "evidence_id"), "EVD-HOST-TOPOLOGY");
    assert_eq!(
        string(evidence, "coverage_state"),
        "ADJACENT_NOT_BENCHMARK_CALLSITE_PARITY"
    );
    assert_eq!(
        string(evidence, "dependency_sovereignty_runner_state"),
        "SCENARIO_NOT_IMPLEMENTED"
    );
    assert!(!boolean(evidence, "execution_receipt_present"));
    let dependency_runner = read_repo_file("scripts/run_dependency_sovereignty_e2e.sh");
    assert!(!dependency_runner.contains("host_benchmark_metadata"));

    let matrix = object(audit, "required_evidence_matrix");
    assert_eq!(string(matrix, "status"), "MISSING_NOT_RUN");
    assert_eq!(unsigned(matrix, "captured_case_count"), 0);
    assert!(array(matrix, "captured_cases").is_empty());
    assert_eq!(array(matrix, "platform_cells").len(), 3);
    assert_eq!(array(matrix, "profile_cells").len(), 3);
    assert_eq!(array(matrix, "host_contexts").len(), 4);
    assert_eq!(array(matrix, "required_semantics").len(), 6);
    assert_eq!(array(matrix, "required_record_fields").len(), 14);

    let gate = object(audit, "cutover_gate");
    assert_eq!(string(gate, "required_state"), "SAME_OR_BETTER");
    let gate_rows = array(gate, "rows");
    assert_eq!(gate_rows.len(), 8);
    assert_eq!(
        gate_rows
            .iter()
            .filter(|row| string(row, "state") == "STATIC_COMPLETE")
            .count(),
        1
    );
    assert_eq!(
        gate_rows
            .iter()
            .filter(|row| string(row, "state") == "MISSING")
            .count(),
        7
    );
    assert_eq!(
        string(gate, "on_any_missing_or_regressed_row"),
        "KEEP_INCUMBENT"
    );
    assert!(!boolean(gate, "num_cpus_exit_allowed"));
    assert!(!boolean(gate, "whoami_exit_allowed"));
    assert!(!boolean(gate, "tracker_closure_allowed"));

    let no_claims = array(audit, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "No benchmark adapter",
        "do not prove",
        "not a benchmark-adapters replacement receipt",
        "future evidence obligation",
        "does not authorize num_cpus or whoami removal",
    ] {
        assert!(no_claims.contains(required), "missing no-claim: {required}");
    }
}

#[test]
fn documentation_generated_summary_matches_canonical_artifact() {
    let docs = read_repo_file(DOC_PATH);
    let start = docs
        .find(GENERATED_BEGIN)
        .expect("generated summary begin marker")
        + GENERATED_BEGIN.len();
    let end = docs
        .find(GENERATED_END)
        .expect("generated summary end marker");
    assert_eq!(docs[start..end].trim(), render_summary(&artifact()).trim());
}

#[test]
fn artifact_contains_no_secret_fixture_material() {
    let text = read_repo_file(ARTIFACT_PATH);
    for forbidden in [
        "-----BEGIN PRIVATE KEY-----",
        "Authorization: Bearer ",
        "NKEY-SEED-SU",
        "AWS_SECRET_ACCESS_KEY=",
        "planned://",
    ] {
        assert!(
            !text.contains(forbidden),
            "artifact contains forbidden secret/placeholder marker {forbidden}"
        );
    }
}

#[test]
fn missing_capability_is_rejected() {
    let mut value = artifact();
    value["capability_baselines"]
        .as_array_mut()
        .expect("array")
        .pop();
    assert_invalid(value, "exactly cover CAP A1");
}

#[test]
fn schema_and_taxonomy_drift_are_rejected() {
    let mut value = artifact();
    value["schema_version"] = Value::from(2);
    assert_invalid(value, "schema_version must be 1");

    let mut value = artifact();
    value["case_classes"]
        .as_array_mut()
        .expect("case classes")
        .retain(|entry| entry.as_str() != Some("recovery"));
    assert_invalid(value, "canonical six-case taxonomy");

    let mut value = artifact();
    value["parity_modes"]
        .as_array_mut()
        .expect("parity modes")
        .retain(|entry| entry.as_str() != Some("SECURITY_POLICY"));
    assert_invalid(value, "all ten independent contracts");
}

#[test]
fn malformed_baseline_revision_is_rejected() {
    let mut value = artifact();
    value["baseline_source_revision"] = Value::String("HEAD".to_owned());
    assert_invalid(value, "full 40-hex Git revision");
}

#[test]
fn duplicate_evidence_id_is_rejected() {
    let mut value = artifact();
    let duplicate = value["evidence_catalog"][0].clone();
    value["evidence_catalog"]
        .as_array_mut()
        .expect("array")
        .push(duplicate);
    assert_invalid(value, "evidence_id values must be unique");
}

#[test]
fn planned_placeholder_is_rejected() {
    let mut value = artifact();
    value["evidence_catalog"][0]["fixture_paths"][0] =
        Value::String("planned://future-fixture".to_owned());
    assert_invalid(value, "planned placeholder");
}

#[test]
fn bare_cargo_replay_is_rejected() {
    let mut value = artifact();
    value["evidence_catalog"][0]["replay_command"] =
        Value::String("cargo test -p asupersync".to_owned());
    assert_invalid(value, "must require remote RCH");
}

#[test]
fn missing_fixture_path_is_rejected() {
    let mut value = artifact();
    value["evidence_catalog"][0]["fixture_paths"][0] =
        Value::String("tests/fixtures/does-not-exist-cap-a2".to_owned());
    assert_invalid(value, "fixture path does not exist");
}

#[test]
fn zero_test_expectation_is_rejected() {
    let mut value = artifact();
    value["evidence_catalog"][0]["expected"]["minimum_tests"] = Value::from(0);
    assert_invalid(value, "must reject zero-test success");
}

#[test]
fn missing_case_classification_is_rejected() {
    let mut value = artifact();
    let index = capability_index(&value, "CAP-PUBLIC-API-TOPOLOGY");
    value["capability_baselines"][index]["cases"]
        .as_object_mut()
        .expect("cases")
        .remove("recovery");
    assert_invalid(value, "every required case");
}

#[test]
fn evidence_must_declare_the_case_it_supports() {
    let mut value = artifact();
    let index = evidence_index(&value, "EVD-API-SURFACE");
    value["evidence_catalog"][index]["case_classes"] = serde_json::json!(["positive"]);
    assert_invalid(value, "does not declare this case class");
}

#[test]
fn unknown_blocker_owner_is_rejected() {
    let mut value = artifact();
    let index = capability_index(&value, "CAP-PUBLIC-API-TOPOLOGY");
    value["capability_baselines"][index]["cases"]["recovery"]["owner_bead"] =
        Value::String("asupersync-does-not-exist".to_owned());
    assert_invalid(value, "blocker owner bead must exist");
}

#[test]
fn cutover_authorization_is_rejected() {
    let mut value = artifact();
    value["capability_baselines"][0]["cutover_eligible"] = Value::Bool(true);
    assert_invalid(value, "may never authorize cutover");
}

#[test]
fn complete_state_with_blocker_is_rejected() {
    let mut value = artifact();
    let index = capability_index(&value, "CAP-PUBLIC-API-TOPOLOGY");
    value["capability_baselines"][index]["baseline_state"] =
        Value::String("EXECUTABLE_COMPLETE".to_owned());
    assert_invalid(value, "EXECUTABLE_COMPLETE may not contain blockers");
}

#[test]
fn scenario_drift_from_registry_is_rejected() {
    let mut value = artifact();
    value["capability_baselines"][0]["scenario_ids"] = serde_json::json!(["renamed"]);
    assert_invalid(value, "scenario_ids must exactly match CAP A1");
}

#[test]
fn unknown_downstream_profile_is_rejected() {
    let mut value = artifact();
    value["capability_baselines"][0]["downstream_profiles"] =
        serde_json::json!(["ambient-portfolio"]);
    assert_invalid(value, "unknown downstream profile");
}

#[test]
fn consumer_minimum_test_floor_is_rejected_when_weakened() {
    let mut value = artifact();
    value["consumer_profiles"][0]["minimum_tests"] = Value::from(1);
    assert_invalid(value, "minimum_tests must be exactly 7");
}

#[test]
fn consumer_feature_profile_drift_is_rejected() {
    let mut value = artifact();
    let full = array(&value, "consumer_profiles")
        .iter()
        .position(|profile| {
            profile.get("profile_id").and_then(Value::as_str) == Some("consumer-full")
        })
        .expect("consumer-full profile");
    value["consumer_profiles"][full]["features"] = Value::Array(Vec::new());
    assert_invalid(value, "feature set must remain explicit and canonical");
}

#[test]
fn runner_scenario_and_provenance_drift_are_rejected() {
    let mut value = artifact();
    value["runner_contract"]["scenarios"]
        .as_array_mut()
        .expect("runner scenarios")
        .retain(|entry| entry.as_str() != Some("consumer-full"));
    assert_invalid(value, "preserve all four focused lanes");

    let mut value = artifact();
    value["runner_contract"]["required_provenance"]
        .as_array_mut()
        .expect("required provenance")
        .retain(|entry| entry.as_str() != Some("rch_worker"));
    assert_invalid(value, "missing required provenance field rch_worker");

    let mut value = artifact();
    value["runner_contract"]["scenario_minimum_tests"]["contract"] = Value::from(1);
    assert_invalid(value, "minimum for contract must remain 26");
}

#[test]
fn cli_capabilities_all_retain_executable_cli_goldens() {
    let value = artifact();
    for capability_id in [
        "CAP-CLI-ASUPERSYNC",
        "CAP-CLI-ATP",
        "CAP-CLI-ATPD",
        "CAP-CLI-OFFLINE-TUNER",
    ] {
        let index = capability_index(&value, capability_id);
        let evidence: BTreeSet<_> = array(&value["capability_baselines"][index], "evidence_ids")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            evidence.contains("EVD-CLI-GOLDENS"),
            "{capability_id} lost CLI golden evidence"
        );
    }
}

#[test]
fn external_service_rows_remain_explicitly_blocked() {
    let value = artifact();
    for capability_id in [
        "CAP-KAFKA",
        "CAP-NATS-MESSAGING",
        "CAP-DATABASE-WIRE",
        "CAP-REAL-SERVICE-E2E",
    ] {
        let index = capability_index(&value, capability_id);
        assert_eq!(
            value["capability_baselines"][index]["baseline_state"], "BLOCKED_EXTERNAL",
            "{capability_id} must not pretend local fixtures prove service parity"
        );
    }
}

#[test]
fn sqlite_cycle_policy_remains_visible() {
    let value = artifact();
    let index = capability_index(&value, "CAP-SQLITE");
    let boundary = string(&value["capability_baselines"][index], "no_claim_boundary");
    assert!(boundary.contains("reverse dependency"));
    assert!(boundary.contains("may not enter asupersync's graph"));
}
