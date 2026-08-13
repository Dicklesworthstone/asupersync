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
const HASH_MAP_BEAD_ID: &str = "asupersync-d24mms.1";
const HASH_MAP_AUDIT_ID: &str = "CAP-HASH-MAPS-STATIC-AUDIT-V1";
const HASHBROWN_PATH_TOKEN: &str = concat!("hash", "brown::");
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const HOST_METADATA_BEAD_ID: &str = "asupersync-d24mms.2";
const HOST_METADATA_AUDIT_ID: &str = "CAP-HOST-BENCH-METADATA-STATIC-AUDIT-V1";
const HOST_METADATA_CHECKPOINT_BASE_REVISION: &str = "706bde7ee34caa356ef675359b2e611dfae3e700";
const HOST_METADATA_INTEGRATION_PATH: &str = "tests/atp_benchmark_integration.rs";
const HOST_METADATA_INTEGRATION_SHA256: &str =
    "db199620f29ae31d6ef9f6e58c1b2e737cb7a0ce17c8412a7e4eade48e990a80";
const HOST_METADATA_INTEGRATION_LINES: u64 = 467;
const HOST_METADATA_INTEGRATION_TEST: &str =
    "benchmark_environment_host_metadata_candidate_contract";
const NUM_CPUS_CALL: &str = concat!("num_cpus", "::get()");
const WHOAMI_CALL: &str = concat!("whoami", "::distro()");
const TEMPFILE_BEAD_ID: &str = "asupersync-d24mms.5";
const TEMPFILE_CHECKPOINT_ID: &str = "CAP-TEMP-ARTIFACTS-CLAIM-TIME-STATIC-CHECKPOINT-V1";
const TEMPFILE_CHECKPOINT_BASE_REVISION: &str = "869664efc07f7be8a3e3803d48a786f76151a08d";
const VISIBILITY_BEAD_ID: &str = "asupersync-d24mms.7";
const VISIBILITY_AUDIT_ID: &str = "CAP-VISIBILITY-MACRO-STATIC-AUDIT-V1";
const VISIBILITY_MAKE_TOKEN: &str = concat!("visibility", "::make(pub)");
const SLAB_BEAD_ID: &str = "asupersync-d24mms.8";
const SLAB_AUDIT_ID: &str = "CAP-TOKEN-SLAB-STATIC-AUDIT-V1";
const SLAB_PATH_TOKEN: &str = concat!("sl", "ab::");
const SLAB_BASELINE_FIXTURE: &str = "tests/memory_tier_slab_pool_contract.rs";
const PHASE2_SIGNOFF_BEAD_ID: &str = "asupersync-d24mms.13";
const PHASE2_READINESS_AUDIT_ID: &str = "CAP-PHASE2-TERMINAL-READINESS-STATIC-AUDIT-V1";
const PHASE1_SIGNOFF_PATH: &str = "artifacts/dependency_phase1_aggregate_signoff_v1.json";
const CLI_INVENTORY_PATH: &str = "artifacts/cli_clap_surface_inventory_v1.json";
const UTC_FOUNDATION_PATH: &str = "artifacts/time_utc_rfc3339_foundation_v1.json";
const FUTURES_INVENTORY_PATH: &str = "artifacts/futures_lite_capability_inventory_v1.json";
const HEX_INVENTORY_PATH: &str = "artifacts/hex_capability_inventory_v1.json";
const BASE64_INVENTORY_PATH: &str = "artifacts/base64_capability_inventory_v1.json";
const DORMANT_E2E_INVENTORY_PATH: &str = "artifacts/dormant_e2e_inventory_v1.json";
const ATP_ARTIFACT_SOURCE: &str = "src/net/atp/chunk/artifact.rs";

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
    hex::encode(Sha256::digest(bytes))
}

fn count_occurrences(source: &str, token: &str) -> u64 {
    u64::try_from(source.matches(token).count()).expect("source token count fits u64")
}

fn count_trimmed_lines(source: &str, marker: &str) -> u64 {
    u64::try_from(source.lines().filter(|line| line.trim() == marker).count())
        .expect("source line count fits u64")
}

fn simple_toml_dependency_requirement<'a>(section: &'a str, dependency: &str) -> &'a str {
    let prefix = format!("{dependency} = ");
    let declaration = section
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing {dependency} declaration"));
    assert!(!declaration.contains("optional"));
    declaration
        .split_once('=')
        .map(|(_, requirement)| requirement.trim())
        .expect("dependency requirement")
}

fn production_before_test_module(source: &str) -> &str {
    source
        .split_once("\n#[cfg(test)]\nmod tests")
        .map(|(production, _)| production)
        .expect("source must have a top-level cfg(test) module boundary")
}

fn rust_paths_under_with_token(relative_root: &str, token: &str) -> BTreeSet<String> {
    let root = repo_root();
    let mut pending = vec![root.join(relative_root)];
    let mut matches = BTreeSet::new();

    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("failed to inspect {}: {error}", directory.display())
            });
            let path = entry.path();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("failed to stat {}: {error}", path.display()));
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            if source.contains(token) {
                let relative = path
                    .strip_prefix(&root)
                    .expect("source path must remain under repository root")
                    .to_string_lossy()
                    .replace('\\', "/");
                matches.insert(relative);
            }
        }
    }

    matches
}

fn rust_source_paths_with_token(token: &str) -> BTreeSet<String> {
    rust_paths_under_with_token("src", token)
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

fn tracker_issues() -> BTreeMap<String, Value> {
    read_repo_file(TRACKER_PATH)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let issue: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{TRACKER_PATH} contains invalid JSONL: {error}"));
            (string(&issue, "id").to_owned(), issue)
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
        HASH_MAP_AUDIT_ID,
        HASH_MAP_BEAD_ID,
        "NO_REPLACEMENT_OR_BENCHMARK_MATRIX_EXECUTED",
        "hashbrown_exit_allowed=false",
        HOST_METADATA_AUDIT_ID,
        HOST_METADATA_BEAD_ID,
        "STATIC_SOURCE_PINNED_NOT_EXECUTED",
        "NO_PLATFORM_OR_PROFILE_MATRIX_EXECUTED",
        "KEEP_INCUMBENT",
        "dependency_exit_allowed=false",
        TEMPFILE_CHECKPOINT_ID,
        TEMPFILE_BEAD_ID,
        "SOURCE_AUTHORED_NOT_EXECUTED",
        "normal_dependency_optionalization_allowed=false",
        VISIBILITY_AUDIT_ID,
        VISIBILITY_BEAD_ID,
        "NO_MACRO_REPLACEMENT_OR_COMPILE_MATRIX_EXECUTED",
        "visibility_exit_allowed=false",
        SLAB_AUDIT_ID,
        SLAB_BEAD_ID,
        "NO_REPLACEMENT_OR_CONSUMER_MATRIX_EXECUTED",
        "slab_exit_allowed=false",
        PHASE2_READINESS_AUDIT_ID,
        PHASE2_SIGNOFF_BEAD_ID,
        "BLOCKED_12_OF_13_PREREQUISITES_NOT_TERMINAL",
        "phase2_terminal_signoff_allowed=false",
        "ALL_13_PREREQUISITES_TERMINAL_AND_REPLAYED_WITH_ZERO_UNKNOWN",
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
fn hash_map_static_audit_is_source_pinned_and_fail_closed() {
    let value = artifact();
    let audit = object(&value, "hash_map_static_audit");
    assert_eq!(string(audit, "audit_id"), HASH_MAP_AUDIT_ID);
    assert_eq!(string(audit, "bead_id"), HASH_MAP_BEAD_ID);
    assert_eq!(string(audit, "capability_id"), "CAP-HASH-MAPS");
    assert_eq!(
        string(audit, "audit_state"),
        "STATIC_SOURCE_PINNED_NOT_EXECUTED"
    );
    assert_eq!(
        string(audit, "execution_state"),
        "NO_REPLACEMENT_OR_BENCHMARK_MATRIX_EXECUTED"
    );
    assert_eq!(
        string(audit, "observed_at_revision"),
        "4d5748b3de2c15985af55e3dfe3c35626d6be543"
    );

    let decision = object(audit, "decision");
    assert_eq!(string(decision, "dependency"), "hashbrown");
    assert_eq!(string(decision, "candidate"), "std::collections");
    assert_eq!(string(decision, "disposition"), "KEEP_INCUMBENT");
    assert!(!boolean(decision, "dependency_exit_allowed"));
    assert!(!boolean(decision, "manifest_or_lockfile_edit_allowed"));
    assert!(!boolean(decision, "source_behavior_change_allowed"));
    assert!(!boolean(decision, "tracker_closure_allowed"));

    let dependency = object(audit, "dependency_contract");
    assert_eq!(
        string(dependency, "manifest_kind"),
        "unconditional normal dependency"
    );
    assert_eq!(string(dependency, "manifest_requirement"), "0.17");
    assert_eq!(string(dependency, "direct_locked_version"), "0.17.1");
    assert_eq!(
        string_set(dependency, "coexisting_locked_versions"),
        BTreeSet::from(["0.16.1".to_owned(), "0.17.1".to_owned()])
    );
    assert_eq!(string(dependency, "root_direct_edge"), "normal:hashbrown");
    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("hashbrown = \"0.17\""));
    let lock = read_repo_file("Cargo.lock");
    assert!(lock.contains("\"hashbrown 0.17.1\""));
    assert!(lock.contains("name = \"hashbrown\"\nversion = \"0.16.1\""));
    assert!(lock.contains("name = \"hashbrown\"\nversion = \"0.17.1\""));

    let pins = array(audit, "source_pins");
    assert_eq!(pins.len(), 13);
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
            "artifacts/dependency_marginal_ledger_v1.json",
            "docs/benchmarking.md",
            "scripts/run_dependency_sovereignty_e2e.sh",
            "src/runtime/reactor/epoll.rs",
            "src/runtime/reactor/mod.rs",
            "src/runtime/scheduler/local_queue.rs",
            "src/runtime/scheduler/mod.rs",
            "tests/conformance/reactor_conformance.rs",
            "tests/e2e_reactor_optin.rs",
            "tests/metamorphic/local_queue.rs",
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

    assert_eq!(
        rust_source_paths_with_token(HASHBROWN_PATH_TOKEN),
        BTreeSet::from([
            "src/runtime/reactor/epoll.rs".to_owned(),
            "src/runtime/scheduler/local_queue.rs".to_owned(),
        ])
    );

    let inventory = object(audit, "call_site_inventory");
    assert_eq!(
        string(inventory, "state"),
        "STATIC_COMPLETE_TWO_PRODUCTION_FILES"
    );
    assert_eq!(unsigned(inventory, "production_file_count"), 2);
    assert_eq!(unsigned(inventory, "dependency_import_count"), 3);
    assert_eq!(unsigned(inventory, "public_type_exposure_count"), 0);
    assert_eq!(
        unsigned(inventory, "observable_collection_iteration_count"),
        0
    );
    let files = array(inventory, "files");
    assert_eq!(files.len(), 2);
    let by_path = files
        .iter()
        .map(|row| (string(row, "path"), row))
        .collect::<BTreeMap<_, _>>();

    let local = by_path
        .get("src/runtime/scheduler/local_queue.rs")
        .copied()
        .expect("local queue row");
    assert_eq!(
        string_set(local, "imports"),
        BTreeSet::from([format!("{HASHBROWN_PATH_TOKEN}HashSet")])
    );
    assert_eq!(array(local, "collection_roles").len(), 1);
    let local_operations = object(local, "operation_counts");
    assert_eq!(unsigned(local_operations, "presence_insert"), 5);
    assert_eq!(unsigned(local_operations, "presence_remove"), 3);
    assert_eq!(unsigned(local_operations, "presence_reserve"), 1);
    assert_eq!(unsigned(local_operations, "default_initialization"), 1);
    assert_eq!(unsigned(local_operations, "collection_iteration"), 0);
    let local_source = read_repo_file("src/runtime/scheduler/local_queue.rs");
    assert!(local_source.contains(&format!("use {HASHBROWN_PATH_TOKEN}HashSet;")));
    assert_eq!(count_occurrences(&local_source, "presence.insert"), 5);
    assert_eq!(count_occurrences(&local_source, "presence.remove"), 3);
    assert_eq!(count_occurrences(&local_source, "presence.reserve"), 1);
    assert!(!local_source.contains("presence.iter"));
    let scheduler_module = read_repo_file("src/runtime/scheduler/mod.rs");
    assert!(scheduler_module.contains("pub mod local_queue;"));
    assert!(scheduler_module.contains("pub use local_queue::LocalQueue;"));

    let epoll = by_path
        .get("src/runtime/reactor/epoll.rs")
        .copied()
        .expect("epoll row");
    assert_eq!(
        string_set(epoll, "imports"),
        BTreeSet::from([
            format!("{HASHBROWN_PATH_TOKEN}HashMap"),
            format!("{HASHBROWN_PATH_TOKEN}hash_map::Entry"),
        ])
    );
    assert_eq!(array(epoll, "collection_roles").len(), 2);
    let epoll_operations = object(epoll, "operation_counts");
    for (operation, expected) in [
        ("with_capacity", 2),
        ("contains_key", 2),
        ("insert", 2),
        ("get", 2),
        ("entry", 1),
        ("entry_remove", 1),
        ("entry_into_mut", 1),
        ("remove", 5),
        ("collection_iteration", 0),
    ] {
        assert_eq!(unsigned(epoll_operations, operation), expected);
    }
    let epoll_source = read_repo_file("src/runtime/reactor/epoll.rs");
    assert!(epoll_source.contains(&format!("use {HASHBROWN_PATH_TOKEN}HashMap;")));
    assert!(epoll_source.contains(&format!("use {HASHBROWN_PATH_TOKEN}hash_map::Entry;")));
    let epoll_production = epoll_source
        .split_once("\n#[cfg(test)]")
        .map(|(production, _)| production)
        .expect("epoll source must separate production and tests");
    assert_eq!(
        count_occurrences(epoll_production, "HashMap::with_capacity"),
        2
    );
    assert_eq!(count_occurrences(epoll_production, ".contains_key"), 2);
    assert_eq!(count_occurrences(epoll_production, ".tokens.insert"), 1);
    assert_eq!(count_occurrences(epoll_production, ".fds.insert"), 1);
    assert_eq!(count_occurrences(epoll_production, "tokens.entry"), 1);
    assert_eq!(count_occurrences(epoll_production, "state.tokens.get"), 2);
    assert_eq!(
        count_occurrences(epoll_production, "state.tokens.remove"),
        2
    );
    assert_eq!(count_occurrences(epoll_production, "fds.remove"), 3);
    assert_eq!(count_occurrences(epoll_production, "entry.remove()"), 1);
    assert_eq!(count_occurrences(epoll_production, "entry.into_mut()"), 1);
    assert!(!epoll_production.contains("tokens.iter"));
    assert!(!epoll_production.contains("fds.iter"));
    let reactor_module = read_repo_file("src/runtime/reactor/mod.rs");
    assert!(reactor_module.contains("#[cfg(any(target_os = \"linux\", target_os = \"android\"))]"));
    assert!(reactor_module.contains("pub mod epoll;"));

    let registry = registry_rows();
    let capability = registry.get("CAP-HASH-MAPS").expect("hash-map capability");
    assert_eq!(
        string_set(capability, "exposure"),
        BTreeSet::from(["internal-runtime".to_owned()])
    );
    assert_eq!(
        string_set(capability, "source_owners"),
        BTreeSet::from([
            "Cargo.toml".to_owned(),
            "src/runtime/reactor/epoll.rs".to_owned(),
            "src/runtime/scheduler/local_queue.rs".to_owned(),
        ])
    );
    assert_eq!(
        string_set(capability, "replacement_bead_ids"),
        BTreeSet::from([HASH_MAP_BEAD_ID.to_owned()])
    );
    assert_eq!(
        string(capability, "cutover_state"),
        "BLOCKED_PENDING_EVIDENCE"
    );
    let baseline_index = capability_index(&value, "CAP-HASH-MAPS");
    let baseline = &value["capability_baselines"][baseline_index];
    assert!(!boolean(baseline, "cutover_eligible"));
    assert_eq!(
        string_set(baseline, "evidence_ids"),
        BTreeSet::from(["EVD-REACTOR-REGISTRATION".to_owned()])
    );

    let evidence = object(audit, "existing_evidence_assessment");
    let declared_counts = object(evidence, "source_declared_test_counts");
    assert_eq!(
        count_trimmed_lines(&local_source, "#[test]"),
        unsigned(declared_counts, "local_queue_unit_tests")
    );
    assert_eq!(
        count_trimmed_lines(&epoll_source, "#[test]"),
        unsigned(declared_counts, "epoll_unit_tests")
    );
    let metamorphic = read_repo_file("tests/metamorphic/local_queue.rs");
    assert_eq!(
        count_trimmed_lines(&metamorphic, "#[test]"),
        unsigned(declared_counts, "local_queue_metamorphic_test_attributes")
    );
    assert_eq!(
        count_trimmed_lines(&metamorphic, "proptest! {"),
        unsigned(declared_counts, "local_queue_proptest_blocks")
    );
    let conformance = read_repo_file("tests/conformance/reactor_conformance.rs");
    assert_eq!(
        count_trimmed_lines(&conformance, "#[test]"),
        unsigned(declared_counts, "reactor_mock_conformance_tests")
    );
    let reactor_e2e = read_repo_file("tests/e2e_reactor_optin.rs");
    assert_eq!(
        count_trimmed_lines(&reactor_e2e, "#[test]"),
        unsigned(declared_counts, "reactor_e2e_tests")
    );
    assert_eq!(
        string(evidence, "coverage_state"),
        "ADJACENT_PARTIAL_NOT_REPLACEMENT_PARITY"
    );
    assert_eq!(
        string(evidence, "dependency_sovereignty_runner_state"),
        "SCENARIO_NOT_IMPLEMENTED"
    );
    assert!(!boolean(evidence, "execution_receipt_present"));
    let catalog = evidence_rows(&value);
    let baseline_evidence = catalog
        .get("EVD-REACTOR-REGISTRATION")
        .expect("reactor baseline evidence");
    assert_eq!(
        string_set(baseline_evidence, "fixture_paths"),
        BTreeSet::from([
            "tests/conformance/reactor_conformance.rs".to_owned(),
            "tests/e2e_reactor_optin.rs".to_owned(),
        ])
    );
    let dependency_runner = read_repo_file("scripts/run_dependency_sovereignty_e2e.sh");
    assert!(!dependency_runner.contains("reactor_registration_churn"));

    let ledger_assessment = object(audit, "marginal_ledger_assessment");
    let ledger = parse_json(MARGINAL_LEDGER_PATH);
    assert_eq!(
        string(&ledger, "source_commit"),
        string(ledger_assessment, "ledger_source_commit")
    );
    assert!(!boolean(
        ledger_assessment,
        "source_commit_matches_observed_revision"
    ));
    assert!(!boolean(ledger_assessment, "fresh_for_cutover"));
    assert!(!boolean(ledger_assessment, "favorable_cutover_verdict"));
    let hashbrown_rows = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| {
            row.get("direct_root_edge").and_then(Value::as_str) == Some("normal:hashbrown")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        u64::try_from(hashbrown_rows.len()).expect("ledger row count fits u64"),
        unsigned(ledger_assessment, "hashbrown_measurement_row_count")
    );
    assert_eq!(hashbrown_rows.len(), 52);
    let ledger_profiles = hashbrown_rows
        .iter()
        .map(|row| string(row, "feature_profile").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ledger_profiles,
        string_set(ledger_assessment, "feature_profiles")
    );
    let ledger_targets = hashbrown_rows
        .iter()
        .map(|row| string(row, "target_triple").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ledger_targets,
        string_set(ledger_assessment, "target_triples")
    );
    let mut actual_distribution = BTreeMap::<u64, u64>::new();
    for row in &hashbrown_rows {
        *actual_distribution
            .entry(unsigned(row, "marginal_package_version_count"))
            .or_default() += 1;
        assert_eq!(
            string(row, "unsafe_exposure_class"),
            "unclassified-fail-closed"
        );
        assert_eq!(
            string(object(row, "marginal_native_code"), "status"),
            "none"
        );
        assert!(array(row, "build_scripts").is_empty());
        assert!(array(row, "proc_macros").is_empty());
    }
    let expected_distribution = array(
        ledger_assessment,
        "marginal_package_version_count_distribution",
    )
    .iter()
    .map(|row| {
        (
            unsigned(row, "marginal_package_version_count"),
            unsigned(row, "row_count"),
        )
    })
    .collect::<BTreeMap<_, _>>();
    assert_eq!(actual_distribution, expected_distribution);
    assert_eq!(
        actual_distribution,
        BTreeMap::from([(0, 4), (2, 12), (4, 36)])
    );
    let historical_benchmarking = read_repo_file("docs/benchmarking.md");
    assert!(historical_benchmarking.contains("hashbrown::raw::RawTable::reserve_rehash"));

    let matrix = object(audit, "required_evidence_matrix");
    assert_eq!(string(matrix, "status"), "MISSING_NOT_RUN");
    assert_eq!(unsigned(matrix, "captured_case_count"), 0);
    assert!(array(matrix, "captured_cases").is_empty());
    assert_eq!(array(matrix, "platform_cells").len(), 6);
    assert_eq!(array(matrix, "profile_cells").len(), 5);
    assert_eq!(array(matrix, "workload_cells").len(), 8);
    assert_eq!(array(matrix, "required_metrics").len(), 8);
    assert_eq!(array(matrix, "required_record_fields").len(), 14);

    let gate = object(audit, "cutover_gate");
    assert_eq!(string(gate, "required_state"), "SAME_OR_BETTER");
    let gate_rows = array(gate, "rows");
    assert_eq!(gate_rows.len(), 9);
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
        8
    );
    assert_eq!(
        string(gate, "on_any_missing_or_regressed_row"),
        "KEEP_INCUMBENT"
    );
    assert!(!boolean(gate, "hashbrown_exit_allowed"));
    assert!(!boolean(gate, "tracker_closure_allowed"));

    let no_claims = array(audit, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "No hash-map replacement",
        "does not prove scheduler or reactor semantic parity",
        "not current replacement execution receipts",
        "not a same-source hashbrown-versus-std comparison",
        "does not authorize cutover",
        "does not authorize hashbrown removal",
    ] {
        assert!(no_claims.contains(required), "missing no-claim: {required}");
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
    assert_eq!(
        string(audit, "observed_at_revision"),
        "efab658ab3966f68f005b02ba0c5710467523d51"
    );

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
        if path == HOST_METADATA_INTEGRATION_PATH {
            assert_eq!(
                string(pin, "sha256"),
                "db199620f29ae31d6ef9f6e58c1b2e737cb7a0ce17c8412a7e4eade48e990a80"
            );
            assert_eq!(unsigned(pin, "line_count"), 467);
            assert!(!string(pin, "role").trim().is_empty());
            continue;
        }
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
    let whoami = by_dependency.get("whoami").copied().expect("whoami row");
    assert_eq!(string(whoami, "locked_version"), "2.1.2");
    assert_eq!(string(whoami, "path"), "src/atp/benchmark/mod.rs");
    assert_eq!(string(whoami, "expression"), WHOAMI_CALL);
    assert_eq!(string(whoami, "output_field"), "os_info");

    let benchmark = read_repo_file("src/atp/benchmark/mod.rs");
    assert_eq!(count_occurrences(&benchmark, NUM_CPUS_CALL), 1);
    assert_eq!(count_occurrences(&benchmark, WHOAMI_CALL), 1);
    assert!(!benchmark.contains("std::thread::available_parallelism"));
    assert!(!benchmark.contains("sysinfo::System::long_os_version"));
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
        BTreeSet::from(["nightly-outcome-try".to_owned(), "proc-macros".to_owned(),])
    );
    assert!(!boolean(
        feature,
        "default_profile_reaches_benchmark_module"
    ));
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
    assert!(atp_module.contains("#[cfg(feature = \"benchmark-adapters\")]\npub mod benchmark;"));

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
    let integration = read_repo_file(HOST_METADATA_INTEGRATION_PATH);
    assert_eq!(
        sha256_hex(&read_repo_bytes(HOST_METADATA_INTEGRATION_PATH)),
        HOST_METADATA_INTEGRATION_SHA256
    );
    assert_eq!(
        u64::try_from(integration.lines().count()).expect("line count fits u64"),
        HOST_METADATA_INTEGRATION_LINES
    );
    assert_eq!(
        count_occurrences(
            &integration,
            &format!("fn {HOST_METADATA_INTEGRATION_TEST}()")
        ),
        1
    );
    for required in [
        "BenchmarkEnvironment::collect()?",
        "std::thread::available_parallelism()",
        "sysinfo::System::long_os_version()",
        "unwrap_or(1)",
        "unwrap_or_else(|| \"unknown\".to_owned())",
        "cpu_info must retain the '<count>x <ARCH>' shape",
        "candidate cpu_info must retain the '<count>x <ARCH>' shape",
        "BenchmarkEnvironment must serialize as an object",
    ] {
        assert!(
            integration.contains(required),
            "host-metadata checkpoint is missing: {required}"
        );
    }
    let docs = read_repo_file(DOC_PATH);
    for required in [
        HOST_METADATA_CHECKPOINT_BASE_REVISION,
        HOST_METADATA_INTEGRATION_TEST,
        "SOURCE_AUTHORED_NOT_EXECUTED",
        "candidate APIs are compile/smoke anchors",
    ] {
        assert!(
            docs.contains(required),
            "missing host checkpoint doc: {required}"
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
fn tempfile_claim_time_profile_checkpoint_is_source_pinned_and_fail_closed() {
    let expected_pins = BTreeMap::from([
        (
            "Cargo.lock",
            (
                "620579cbaad5dd73da0e70aa21d3a3bf928126ac2920077802e7a3058c522821",
                4666_u64,
            ),
        ),
        (
            "Cargo.toml",
            (
                "fee2c185ab94fd33867a800f7faa8857b8d6204dba7e16eefe510a31fc691c04",
                1057_u64,
            ),
        ),
        (
            "artifacts/dependency_capability_baseline_v1.json",
            (
                "1b51f8fa7d091201f48eb24196cbfc84f868f39fb42a89d153995750f61da0a6",
                3210_u64,
            ),
        ),
        (
            "artifacts/dependency_capability_registry_v1.json",
            (
                "d255864fdd4f314d309e3f749c782a79f8ae4ac70bf63baa57edb14b14b6a6ea",
                6929_u64,
            ),
        ),
        (
            "artifacts/dependency_marginal_ledger_v1.json",
            (
                "4e36ca29d7187e3237cfd9f422b2661009a608e93bb5761c7d511d412d66a047",
                188_447_u64,
            ),
        ),
        (
            "src/atp/benchmark/suite.rs",
            (
                "4c53f1453815ab28acd88ceff677cc837200044bf65a5739f464d1120b7f11a9",
                341_u64,
            ),
        ),
        (
            "src/atp/mod.rs",
            (
                "098e4acd9abc7df0a9b6e3ba484b07e4eade44235166b98c43bad9a4cb3b327a",
                172_u64,
            ),
        ),
        (
            "src/bin/asupersync.rs",
            (
                "39719e72f1c00122ec4730aab2e2404086292ac46ced4e9290bb206a3b618ec7",
                16_791_u64,
            ),
        ),
        (
            "src/lib.rs",
            (
                "22ce17632d6a98843ebd6b9f855a430aef3ea6da07a6657e3311ad87b78c1b7f",
                468_u64,
            ),
        ),
        (
            "src/net/atp/mod.rs",
            (
                "fff6f36cd57f83fc949b9f5a11ad67382367aeb79152a0b6bd62d36b274fb058",
                67_u64,
            ),
        ),
        (
            "src/net/atp/transport_quic/mod.rs",
            (
                "01282192055de1910eab74c3c78b77493c9f2254848027152a50194c8e1d3796",
                17_212_u64,
            ),
        ),
        (
            "src/net/atp/transport_rq/mod.rs",
            (
                "2d3f3123d15124a972b9172be3bcd5a9e8010cfde176e723fb2abb215e28ee86",
                15_242_u64,
            ),
        ),
        (
            "src/net/mod.rs",
            (
                "a0652a2a243499570d274c670dc3c45125584f65909141a36e97fd585e05761e",
                118_u64,
            ),
        ),
        (
            "src/test_logging.rs",
            (
                "85bb7979d1fa1e63c54b230f55b68c8e0f6deea57e6068365b6f91db04cf8848",
                5919_u64,
            ),
        ),
    ]);
    for (path, (expected_sha, expected_lines)) in expected_pins {
        let source = read_repo_file(path);
        assert_eq!(
            sha256_hex(source.as_bytes()),
            expected_sha,
            "tempfile checkpoint source drifted: {path}"
        );
        assert_eq!(
            u64::try_from(source.lines().count()).expect("line count fits u64"),
            expected_lines,
            "tempfile checkpoint line count drifted: {path}"
        );
    }

    let manifest = read_repo_file("Cargo.toml");
    let normal_dependencies = manifest
        .split_once("\n[dependencies]\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n[target.").map(|(section, _)| section))
        .expect("root normal dependencies section");
    let dev_dependencies = manifest
        .split_once("\n[dev-dependencies]\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n[target.").map(|(section, _)| section))
        .expect("root dev dependencies section");
    assert_eq!(
        simple_toml_dependency_requirement(normal_dependencies, "tempfile"),
        simple_toml_dependency_requirement(dev_dependencies, "tempfile")
    );
    assert_eq!(count_occurrences(&manifest, "dep:tempfile"), 0);
    assert!(manifest.contains(
        "name = \"asupersync\"\npath = \"src/bin/asupersync.rs\"\nrequired-features = [\"cli\"]"
    ));
    let lock = read_repo_file("Cargo.lock");
    let tempfile_packages = lock
        .split("\n[[package]]\n")
        .filter(|package| package.starts_with("name = \"tempfile\"\n"))
        .collect::<Vec<_>>();
    assert_eq!(tempfile_packages.len(), 1);
    assert!(tempfile_packages[0].contains("\nversion = \""));
    assert!(tempfile_packages[0].contains("\nsource = \"registry+"));

    let net = read_repo_file("src/net/mod.rs");
    assert!(net.contains("#[cfg(not(target_arch = \"wasm32\"))]\npub mod atp;"));
    let net_atp = read_repo_file("src/net/atp/mod.rs");
    assert!(net_atp.contains("pub mod transport_quic;\npub mod transport_rq;"));

    let rq = read_repo_file("src/net/atp/transport_rq/mod.rs");
    let rq_production = rq
        .split_once("\n#[cfg(test)]\n#[path = \"transport_rq_tests.rs\"]")
        .map(|(production, _)| production)
        .expect("RQ source must retain its external cfg(test) module boundary");
    assert_eq!(count_occurrences(rq_production, "tempfile::"), 4);
    for required in [
        "Option<tempfile::TempDir>",
        "tempfile::Builder::new()",
        "_pack_tempdir: Option<tempfile::TempDir>",
    ] {
        assert!(
            rq_production.contains(required),
            "RQ packing lost {required}"
        );
    }

    let quic = read_repo_file("src/net/atp/transport_quic/mod.rs");
    let quic_production = production_before_test_module(&quic);
    assert_eq!(count_occurrences(quic_production, "tempfile::"), 3);
    for required in [
        "pack_tempdir: Option<std::sync::Arc<tempfile::TempDir>>",
        "let mut pack_tempdir: Option<tempfile::TempDir> = None;",
        "let dir = tempfile::Builder::new()",
    ] {
        assert!(
            quic_production.contains(required),
            "QUIC packing lost {required}"
        );
    }

    let cli = read_repo_file("src/bin/asupersync.rs");
    let cli_production = production_before_test_module(&cli);
    assert_eq!(count_occurrences(cli_production, "tempfile::"), 1);
    assert!(cli_production.contains("tempfile::NamedTempFile::new_in(parent)"));

    let atp_module = read_repo_file("src/atp/mod.rs");
    assert!(atp_module.contains("#[cfg(feature = \"benchmark-adapters\")]\npub mod benchmark;"));
    let benchmark = read_repo_file("src/atp/benchmark/suite.rs");
    assert_eq!(
        count_occurrences(production_before_test_module(&benchmark), "tempfile::"),
        1
    );
    assert!(benchmark.contains("let work_dir = TempDir::new()"));

    let lib = read_repo_file("src/lib.rs");
    assert!(lib.contains("#[cfg(any(test, feature = \"test-internals\"))]\npub mod test_logging;"));
    let test_logging = read_repo_file("src/test_logging.rs");
    let test_logging_production = test_logging
        .split_once("\n#[cfg(test)]\n#[allow(unsafe_code)]\nmod tests")
        .map(|(production, _)| production)
        .expect("test logging must retain its cfg(test) module boundary");
    assert_eq!(count_occurrences(test_logging_production, "tempfile::"), 4);

    let source_paths = rust_source_paths_with_token("tempfile::");
    assert_eq!(source_paths.len(), 80);
    for required in [
        "src/atp/benchmark/suite.rs",
        "src/bin/asupersync.rs",
        "src/net/atp/transport_quic/mod.rs",
        "src/net/atp/transport_rq/mod.rs",
        "src/test_logging.rs",
    ] {
        assert!(
            source_paths.contains(required),
            "missing tempfile path {required}"
        );
    }
    let source_token_count = source_paths
        .iter()
        .map(|path| count_occurrences(&read_repo_file(path), "tempfile::"))
        .sum::<u64>();
    assert_eq!(source_token_count, 277);
    assert_eq!(rust_paths_under_with_token("tests", "tempfile::").len(), 94);
    assert_eq!(
        rust_paths_under_with_token("benches", "tempfile::").len(),
        2
    );
    assert_eq!(
        rust_paths_under_with_token("examples", "tempfile::").len(),
        1
    );

    let baseline = artifact();
    let phase2 = object(&baseline, "phase2_terminal_readiness_static_audit");
    let tempfile_row = array(phase2, "prerequisite_rows")
        .iter()
        .find(|row| string(row, "prerequisite_id") == TEMPFILE_BEAD_ID)
        .expect("historical Phase-2 snapshot must retain the tempfile row");
    assert_eq!(
        string(tempfile_row, "readiness_state"),
        "NO_DEDICATED_RECEIPT"
    );
    assert!(!boolean(tempfile_row, "terminal_ready"));

    let docs = read_repo_file(DOC_PATH);
    for required in [
        TEMPFILE_CHECKPOINT_ID,
        TEMPFILE_CHECKPOINT_BASE_REVISION,
        TEMPFILE_BEAD_ID,
        "SOURCE_AUTHORED_NOT_EXECUTED",
        "KEEP_INCUMBENT",
        "normal_dependency_optionalization_allowed=false",
        "default-native ATP RaptorQ and QUIC pack-materialization paths",
        "historical `NO_DEDICATED_RECEIPT` row remains unchanged",
    ] {
        assert!(
            docs.contains(required),
            "missing tempfile checkpoint doc: {required}"
        );
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

#[test]
fn visibility_macro_static_audit_is_source_pinned_and_fail_closed() {
    let value = artifact();
    let audit = object(&value, "visibility_macro_static_audit");
    assert_eq!(string(audit, "audit_id"), VISIBILITY_AUDIT_ID);
    assert_eq!(string(audit, "bead_id"), VISIBILITY_BEAD_ID);
    assert_eq!(string(audit, "capability_id"), "CAP-VISIBILITY-MACRO");
    assert_eq!(
        string(audit, "audit_state"),
        "STATIC_SOURCE_PINNED_NOT_EXECUTED"
    );
    assert_eq!(
        string(audit, "execution_state"),
        "NO_MACRO_REPLACEMENT_OR_COMPILE_MATRIX_EXECUTED"
    );
    assert_eq!(
        string(audit, "observed_at_revision"),
        "42a66e7f4e6733c28c59405c052c68f7a32ea0d7"
    );

    let decision = object(audit, "decision");
    assert_eq!(string(decision, "dependency"), "visibility");
    assert_eq!(
        string(decision, "candidate"),
        "owned exact-scope attribute in asupersync-macros"
    );
    assert_eq!(string(decision, "disposition"), "KEEP_INCUMBENT");
    assert!(!boolean(decision, "dependency_exit_allowed"));
    assert!(!boolean(decision, "manifest_or_lockfile_edit_allowed"));
    assert!(!boolean(
        decision,
        "macro_or_source_behavior_change_allowed"
    ));
    assert!(!boolean(decision, "tracker_closure_allowed"));

    let dependency = object(audit, "dependency_contract");
    assert_eq!(
        string(dependency, "manifest_kind"),
        "optional normal dependency"
    );
    assert_eq!(string(dependency, "manifest_requirement"), "0.1");
    assert_eq!(string(dependency, "direct_locked_version"), "0.1.1");
    assert_eq!(string(dependency, "root_direct_edge"), "normal:visibility");
    assert_eq!(string(dependency, "enabling_feature"), "test-internals");
    assert_eq!(
        string_set(dependency, "locked_dependencies"),
        BTreeSet::from([
            "proc-macro2".to_owned(),
            "quote".to_owned(),
            "syn 2.0.119".to_owned(),
        ])
    );
    assert_eq!(
        string(dependency, "security_requirement"),
        "macro emits no unsafe"
    );

    let pins = array(audit, "source_pins");
    assert_eq!(pins.len(), 14);
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
            "artifacts/dependency_marginal_ledger_v1.json",
            "asupersync-macros/Cargo.toml",
            "asupersync-macros/src/lib.rs",
            "asupersync-macros/tests/compile_fail_tests.rs",
            "scripts/run_dependency_capability_baseline.sh",
            "src/cx/cx.rs",
            "src/cx/scope.rs",
            "src/net/tcp/stream.rs",
            "src/types/id.rs",
            "tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml",
            "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs",
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

    assert_eq!(
        rust_source_paths_with_token(VISIBILITY_MAKE_TOKEN),
        BTreeSet::from([
            "src/cx/cx.rs".to_owned(),
            "src/cx/scope.rs".to_owned(),
            "src/net/tcp/stream.rs".to_owned(),
            "src/types/id.rs".to_owned(),
        ])
    );
    let inventory = object(audit, "attribute_inventory");
    assert_eq!(
        string(inventory, "state"),
        "STATIC_COMPLETE_TWELVE_OCCURRENCES_FOUR_FILES"
    );
    assert_eq!(
        string(inventory, "exact_source_token"),
        VISIBILITY_MAKE_TOKEN
    );
    assert_eq!(unsigned(inventory, "occurrence_count"), 12);
    assert_eq!(unsigned(inventory, "production_file_count"), 4);
    assert_eq!(unsigned(inventory, "pub_crate_item_count"), 11);
    assert_eq!(unsigned(inventory, "already_public_item_count"), 1);

    let shapes = object(inventory, "item_shape_counts");
    assert_eq!(unsigned(shapes, "inherent_associated_const_fn"), 2);
    assert_eq!(unsigned(shapes, "inherent_associated_fn"), 8);
    assert_eq!(unsigned(shapes, "inherent_receiver_method"), 1);
    assert_eq!(unsigned(shapes, "public_struct"), 1);

    let files = array(inventory, "files");
    assert_eq!(files.len(), 4);
    let by_path = files
        .iter()
        .map(|row| (string(row, "path"), row))
        .collect::<BTreeMap<_, _>>();
    for (path, occurrence_count, generic_impl_context_count, item_count) in [
        ("src/types/id.rs", 2, 0, 2),
        ("src/cx/cx.rs", 6, 5, 6),
        ("src/cx/scope.rs", 3, 3, 3),
        ("src/net/tcp/stream.rs", 1, 0, 1),
    ] {
        let row = by_path.get(path).copied().expect("inventory file row");
        assert_eq!(unsigned(row, "occurrence_count"), occurrence_count);
        assert_eq!(
            unsigned(row, "generic_impl_context_count"),
            generic_impl_context_count
        );
        assert_eq!(array(row, "items").len(), item_count);
        assert_eq!(
            count_occurrences(&read_repo_file(path), VISIBILITY_MAKE_TOKEN),
            occurrence_count
        );
    }

    let id_source = read_repo_file("src/types/id.rs");
    assert_eq!(
        count_occurrences(&id_source, "pub(crate) const fn from_arena"),
        3
    );
    let cx_source = read_repo_file("src/cx/cx.rs");
    assert!(cx_source.contains("pub struct CurrentCxGuard"));
    assert!(cx_source.contains("pub(crate) fn new_with_drivers("));
    assert!(cx_source.contains("pub(crate) fn io_driver_handle(&self)"));
    let scope_source = read_repo_file("src/cx/scope.rs");
    assert!(scope_source.contains("impl<P: Policy> Scope<'_, P>"));
    assert!(scope_source.contains("pub(crate) fn with_pending_spawn_counter("));
    let tcp_source = read_repo_file("src/net/tcp/stream.rs");
    assert!(tcp_source.contains("pub(crate) fn from_std(stream: net::TcpStream)"));
    assert!(tcp_source.contains("#[cfg(target_arch = \"wasm32\")]"));

    let features = object(audit, "feature_path_inventory");
    assert_eq!(
        string_set(features, "default_features"),
        BTreeSet::from(["nightly-outcome-try".to_owned(), "proc-macros".to_owned(),])
    );
    assert_eq!(
        string_set(features, "proc_macros_feature_edges"),
        BTreeSet::from(["dep:asupersync-macros".to_owned()])
    );
    assert_eq!(
        string_set(features, "test_internals_feature_edges"),
        BTreeSet::from([
            "dep:tracing".to_owned(),
            "dep:tracing-log".to_owned(),
            "dep:tracing-subscriber".to_owned(),
            "dep:visibility".to_owned(),
        ])
    );
    assert!(!boolean(
        features,
        "test_internals_currently_enables_owned_macro"
    ));
    assert!(boolean(
        features,
        "sparse_no_default_test_internals_currently_uses_visibility"
    ));
    assert!(boolean(
        features,
        "candidate_requires_explicit_owned_macro_edge"
    ));

    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("default = [\"proc-macros\", \"nightly-outcome-try\"]"));
    assert!(manifest.contains("proc-macros = [\"dep:asupersync-macros\"]"));
    assert!(manifest.contains("visibility = { version = \"0.1\", optional = true }"));
    let test_internals = manifest
        .split_once("test-internals = [")
        .expect("test-internals feature starts")
        .1
        .split_once("\n]")
        .expect("test-internals feature ends")
        .0;
    assert!(test_internals.contains("\"dep:visibility\""));
    assert!(!test_internals.contains("dep:asupersync-macros"));

    let lock = read_repo_file("Cargo.lock");
    assert!(lock.contains("name = \"visibility\"\nversion = \"0.1.1\""));
    assert!(lock.contains("\"syn 2.0.119\""));
    let topology = object(audit, "owned_macro_topology_assessment");
    assert_eq!(string(topology, "owned_crate"), "asupersync-macros");
    assert_eq!(string(topology, "existing_parser_major"), "syn 3");
    assert!(!boolean(topology, "new_parser_dependency_allowed"));
    assert_eq!(
        string(topology, "cycle_risk_state"),
        "UNRESOLVED_REQUIRES_SPARSE_COMPILE_PROOF"
    );
    assert!(!boolean(topology, "published_macro_present"));
    assert!(!boolean(
        topology,
        "visibility_specific_unit_or_trybuild_fixture_present"
    ));
    let macro_manifest = read_repo_file("asupersync-macros/Cargo.toml");
    assert!(macro_manifest.contains(
        "asupersync = { path = \"..\", default-features = false, features = [\"test-internals\"] }"
    ));
    assert!(macro_manifest.contains("trybuild = \"1.0\""));
    assert!(!read_repo_file("asupersync-macros/src/lib.rs").contains(VISIBILITY_MAKE_TOKEN));
    let visibility_fixture_count =
        std::fs::read_dir(repo_root().join("asupersync-macros/tests/compile_fail"))
            .expect("compile-fail fixture directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("visibility"))
            .count();
    assert_eq!(visibility_fixture_count, 0);

    let registry = registry_rows();
    let capability = registry
        .get("CAP-VISIBILITY-MACRO")
        .expect("visibility capability");
    assert_eq!(
        string_set(capability, "dependency_owners"),
        BTreeSet::from(["asupersync-macros".to_owned(), "visibility".to_owned(),])
    );
    assert_eq!(
        string_set(capability, "features"),
        BTreeSet::from(["test-internals".to_owned()])
    );
    assert_eq!(
        string_set(capability, "replacement_bead_ids"),
        BTreeSet::from([VISIBILITY_BEAD_ID.to_owned()])
    );
    assert_eq!(
        string(capability, "cutover_state"),
        "BLOCKED_PENDING_EVIDENCE"
    );
    let baseline_index = capability_index(&value, "CAP-VISIBILITY-MACRO");
    let baseline = &value["capability_baselines"][baseline_index];
    assert_eq!(
        string_set(baseline, "scenario_ids"),
        BTreeSet::from(["test_internals_consumer".to_owned()])
    );
    assert_eq!(
        string_set(baseline, "evidence_ids"),
        BTreeSet::from(["EVD-PROC-MACROS".to_owned()])
    );
    assert!(!boolean(baseline, "cutover_eligible"));

    let evidence = object(audit, "existing_evidence_assessment");
    assert_eq!(string(evidence, "baseline_evidence_id"), "EVD-PROC-MACROS");
    assert_eq!(
        string(evidence, "dependency_capability_runner_state"),
        "SCENARIO_NOT_IMPLEMENTED"
    );
    assert_eq!(
        unsigned(evidence, "visibility_specific_trybuild_fixture_count"),
        0
    );
    assert!(!boolean(evidence, "execution_receipt_present"));
    let runner = read_repo_file(RUNNER_PATH);
    assert!(!runner.contains("test_internals_consumer"));
    let consumer_manifest =
        read_repo_file("tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml");
    let consumer_source =
        read_repo_file("tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs");
    assert!(!consumer_manifest.contains("features = [\"test-internals\"]"));
    assert!(!consumer_manifest.contains("asupersync/test-internals"));
    assert!(!consumer_source.contains(VISIBILITY_MAKE_TOKEN));

    let downstream = object(audit, "downstream_use_assessment");
    assert_eq!(
        string(downstream, "state"),
        "PARTIAL_STATIC_TOKEN_SEARCH_NOT_SEMANTICALLY_CLASSIFIED"
    );
    assert!(!boolean(
        downstream,
        "complete_downstream_inventory_present"
    ));

    let marginal = object(audit, "marginal_ledger_assessment");
    assert_eq!(unsigned(marginal, "visibility_measurement_row_count"), 4);
    assert!(!boolean(
        marginal,
        "source_commit_matches_observed_revision"
    ));
    assert!(!boolean(marginal, "fresh_for_cutover"));
    assert!(!boolean(marginal, "favorable_cutover_verdict"));
    let ledger = parse_json(MARGINAL_LEDGER_PATH);
    assert_eq!(
        string(&ledger, "source_commit"),
        string(marginal, "ledger_source_commit")
    );
    let rows = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("dependency_name").and_then(Value::as_str) == Some("visibility"))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows.iter()
            .map(|row| string(row, "feature_profile").to_owned())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["workspace-dev-build-audit".to_owned()])
    );
    assert_eq!(
        rows.iter()
            .map(|row| string(row, "target_triple").to_owned())
            .collect::<BTreeSet<_>>(),
        string_set(marginal, "target_triples")
    );
    for row in rows {
        assert_eq!(string(row, "direct_root_edge"), "normal:visibility");
        assert_eq!(unsigned(row, "marginal_package_version_count"), 1);
        assert_eq!(string(row, "unsafe_exposure_class"), "SAFE-OWN");
        assert!(array(row, "build_scripts").is_empty());
        assert_eq!(array(row, "proc_macros").len(), 1);
        assert_eq!(
            string(object(row, "marginal_native_code"), "status"),
            "none"
        );
    }

    let matrix = object(audit, "required_evidence_matrix");
    assert_eq!(string(matrix, "status"), "MISSING_NOT_RUN");
    assert_eq!(unsigned(matrix, "captured_case_count"), 0);
    assert!(array(matrix, "captured_cases").is_empty());
    assert_eq!(array(matrix, "item_shape_cells").len(), 8);
    assert_eq!(array(matrix, "profile_cells").len(), 5);
    assert_eq!(array(matrix, "target_cells").len(), 4);
    assert_eq!(array(matrix, "diagnostic_cells").len(), 6);

    let gate = object(audit, "cutover_gate");
    assert_eq!(string(gate, "required_state"), "SAME_OR_BETTER");
    let gate_rows = array(gate, "rows");
    assert_eq!(gate_rows.len(), 9);
    assert_eq!(
        gate_rows
            .iter()
            .filter(|row| row.get("state").and_then(Value::as_str) == Some("STATIC_COMPLETE"))
            .count(),
        1
    );
    assert_eq!(
        gate_rows
            .iter()
            .filter(|row| row.get("state").and_then(Value::as_str) == Some("MISSING"))
            .count(),
        8
    );
    assert_eq!(
        string(gate, "on_any_missing_or_regressed_row"),
        "KEEP_INCUMBENT"
    );
    assert!(!boolean(gate, "visibility_exit_allowed"));
    assert!(!boolean(gate, "tracker_closure_allowed"));

    let no_claims = array(audit, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "No owned visibility macro",
        "does not prove expansion",
        "not a visibility replacement receipt",
        "does not authorize cutover",
        "does not authorize visibility removal",
    ] {
        assert!(no_claims.contains(required), "missing no-claim: {required}");
    }
}

#[test]
fn slab_static_audit_is_source_pinned_and_rejects_misbound_evidence() {
    let value = artifact();
    let audit = object(&value, "slab_static_audit");
    assert_eq!(string(audit, "audit_id"), SLAB_AUDIT_ID);
    assert_eq!(string(audit, "bead_id"), SLAB_BEAD_ID);
    assert_eq!(string(audit, "capability_id"), "CAP-TOKEN-SLAB");
    assert_eq!(
        string(audit, "audit_state"),
        "STATIC_SOURCE_PINNED_NOT_EXECUTED"
    );
    assert_eq!(
        string(audit, "execution_state"),
        "NO_REPLACEMENT_OR_CONSUMER_MATRIX_EXECUTED"
    );
    assert_eq!(
        string(audit, "observed_at_revision"),
        "341ac3656a98e8b07749207d2996914b23042fcf"
    );

    let decision = object(audit, "decision");
    assert_eq!(string(decision, "dependency"), "slab");
    assert_eq!(
        string(decision, "candidate"),
        "minimal owned safe free-list slab"
    );
    assert_eq!(string(decision, "disposition"), "KEEP_INCUMBENT");
    assert!(!boolean(decision, "dependency_exit_allowed"));
    assert!(!boolean(decision, "manifest_or_lockfile_edit_allowed"));
    assert!(!boolean(decision, "source_behavior_change_allowed"));
    assert!(!boolean(decision, "tracker_closure_allowed"));

    let dependency = object(audit, "dependency_contract");
    assert_eq!(
        string(dependency, "manifest_kind"),
        "unconditional normal dependency"
    );
    assert_eq!(string(dependency, "manifest_requirement"), "0.4");
    assert_eq!(string(dependency, "direct_locked_version"), "0.4.12");
    assert_eq!(string(dependency, "root_direct_edge"), "normal:slab");
    assert!(boolean(dependency, "default_profile_reachable"));
    assert_eq!(unsigned(dependency, "external_production_file_count"), 4);
    assert_eq!(unsigned(dependency, "public_type_exposure_count"), 0);
    assert_eq!(array(dependency, "security_requirements").len(), 2);
    assert_eq!(array(dependency, "lifecycle_requirements").len(), 2);

    let pins = array(audit, "source_pins");
    assert_eq!(pins.len(), 14);
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
            "artifacts/dependency_marginal_ledger_v1.json",
            "scripts/run_all_e2e.sh",
            "scripts/run_dependency_sovereignty_e2e.sh",
            "src/service/mod.rs",
            "src/service/rate_limit.rs",
            "src/sync/mod.rs",
            "src/sync/semaphore.rs",
            "src/sync/waiter.rs",
            "src/time/mod.rs",
            "src/time/wheel.rs",
            SLAB_BASELINE_FIXTURE,
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

    assert_eq!(
        rust_source_paths_with_token(SLAB_PATH_TOKEN),
        BTreeSet::from([
            "src/service/rate_limit.rs".to_owned(),
            "src/sync/semaphore.rs".to_owned(),
            "src/sync/waiter.rs".to_owned(),
            "src/time/wheel.rs".to_owned(),
        ])
    );
    let inventory = object(audit, "call_site_inventory");
    assert_eq!(
        string(inventory, "state"),
        "STATIC_COMPLETE_FOUR_PRODUCTION_FILES"
    );
    assert_eq!(string(inventory, "exact_source_token"), SLAB_PATH_TOKEN);
    assert_eq!(unsigned(inventory, "production_file_count"), 4);
    assert_eq!(unsigned(inventory, "dependency_import_count"), 3);
    assert_eq!(
        unsigned(inventory, "qualified_type_or_constructor_count"),
        2
    );
    assert_eq!(unsigned(inventory, "public_type_exposure_count"), 0);

    let roles = array(inventory, "consumer_roles");
    assert_eq!(roles.len(), 4);
    let by_path = roles
        .iter()
        .map(|row| (string(row, "path"), row))
        .collect::<BTreeMap<_, _>>();

    let rate = by_path
        .get("src/service/rate_limit.rs")
        .copied()
        .expect("rate-limit consumer row");
    assert_eq!(string(rate, "role"), "RateLimitWaiter registry");
    let rate_operations = object(rate, "operation_counts");
    for (operation, expected) in [
        ("new", 6),
        ("get", 1),
        ("get_mut", 1),
        ("try_remove", 1),
        ("reserve", 1),
        ("insert", 1),
        ("mem_take", 3),
        ("consuming_iteration", 1),
    ] {
        assert_eq!(unsigned(rate_operations, operation), expected);
    }
    let rate_source = read_repo_file("src/service/rate_limit.rs");
    let rate_production = production_before_test_module(&rate_source);
    assert_eq!(count_occurrences(rate_production, "Slab::new()"), 6);
    assert_eq!(count_occurrences(rate_production, "state.waiters.get("), 1);
    assert_eq!(
        count_occurrences(rate_production, ".get_mut(handle.slot)"),
        1
    );
    assert_eq!(
        count_occurrences(rate_production, "try_remove(handle.slot)"),
        1
    );
    assert_eq!(
        count_occurrences(rate_production, "state.waiters.reserve("),
        1
    );
    assert_eq!(
        count_occurrences(rate_production, "state.waiters.insert("),
        1
    );
    assert_eq!(
        count_occurrences(rate_production, "std::mem::take(&mut state.waiters)"),
        3
    );
    assert_eq!(
        count_occurrences(rate_production, "for (_, waiter) in waiters"),
        1
    );
    assert!(rate_production.contains("(waiter.id == handle.id).then_some(waiter)"));

    let semaphore = by_path
        .get("src/sync/semaphore.rs")
        .copied()
        .expect("semaphore consumer row");
    assert_eq!(
        string(semaphore, "role"),
        "SemaphoreState FIFO waiter registry"
    );
    let semaphore_operations = object(semaphore, "operation_counts");
    for (operation, expected) in [
        ("with_capacity", 1),
        ("get", 3),
        ("get_mut", 1),
        ("insert", 1),
        ("index_mutation", 3),
        ("remove", 1),
        ("len", 1),
        ("reserve", 2),
        ("mem_take", 1),
    ] {
        assert_eq!(unsigned(semaphore_operations, operation), expected);
    }
    let semaphore_source = read_repo_file("src/sync/semaphore.rs");
    let semaphore_production = production_before_test_module(&semaphore_source);
    assert_eq!(
        count_occurrences(semaphore_production, "Slab::with_capacity(4)"),
        1
    );
    assert_eq!(
        count_occurrences(semaphore_production, "state.waiters.get("),
        3
    );
    assert_eq!(
        count_occurrences(semaphore_production, "state.waiters.get_mut("),
        1
    );
    assert_eq!(
        count_occurrences(semaphore_production, "state.waiters.insert("),
        1
    );
    assert_eq!(count_occurrences(semaphore_production, "state.waiters["), 3);
    assert_eq!(
        count_occurrences(semaphore_production, "state.waiters.remove("),
        1
    );
    assert_eq!(
        count_occurrences(semaphore_production, "state.waiters.len()"),
        1
    );
    assert_eq!(
        count_occurrences(semaphore_production, "state.waiters.reserve("),
        2
    );
    assert_eq!(
        count_occurrences(semaphore_production, "std::mem::take(&mut state.waiters)"),
        1
    );
    assert!(semaphore_production.contains("(waiter.id == handle.id).then_some(waiter)"));

    let waiter = by_path
        .get("src/sync/waiter.rs")
        .copied()
        .expect("waiter consumer row");
    assert_eq!(string(waiter, "role"), "WaiterChain reusable slot store");
    let waiter_operations = object(waiter, "operation_counts");
    for (operation, expected) in [
        ("new", 1),
        ("len", 1),
        ("vacant_key", 2),
        ("insert", 2),
        ("remove", 2),
        ("get_mut", 2),
        ("get", 1),
        ("index_access", 11),
    ] {
        assert_eq!(unsigned(waiter_operations, operation), expected);
    }
    let waiter_source = read_repo_file("src/sync/waiter.rs");
    let waiter_production = production_before_test_module(&waiter_source);
    for (token, expected) in [
        ("Slab::new()", 1),
        ("self.slots.len()", 1),
        ("self.slots.vacant_key()", 2),
        ("self.slots.insert(", 2),
        ("self.slots.remove(", 2),
        ("self.slots.get_mut(", 2),
        ("self.slots.get(", 1),
        ("self.slots[", 11),
    ] {
        assert_eq!(count_occurrences(waiter_production, token), expected);
    }
    assert_eq!(
        count_occurrences(waiter_production, "debug_assert_eq!(inserted, index)"),
        2
    );
    assert!(waiter_production.contains("WaiterChain exhausted its stable waiter ID space"));

    let wheel = by_path
        .get("src/time/wheel.rs")
        .copied()
        .expect("timer-wheel consumer row");
    assert_eq!(string(wheel, "role"), "TimerActivityMap generation store");
    let wheel_operations = object(wheel, "operation_counts");
    for (operation, expected) in [
        ("with_capacity", 1),
        ("len", 1),
        ("is_empty", 4),
        ("clear", 1),
        ("insert", 1),
        ("get", 2),
        ("remove", 2),
    ] {
        assert_eq!(unsigned(wheel_operations, operation), expected);
    }
    let wheel_source = read_repo_file("src/time/wheel.rs");
    let wheel_production = production_before_test_module(&wheel_source);
    for (token, expected) in [
        ("slab::Slab::with_capacity(64)", 1),
        ("self.active.len()", 1),
        ("self.active.is_empty()", 4),
        ("self.active.clear()", 1),
        ("self.active.insert(", 1),
        ("self.active.remove(", 2),
    ] {
        assert_eq!(count_occurrences(wheel_production, token), expected);
    }
    assert!(wheel_production.contains(".active\n            .get(id_usize)"));
    assert!(wheel_production.contains("self.active\n            .get(entry.id as usize)"));
    assert!(wheel_production.contains("|&g| g == handle.generation"));
    assert!(wheel_production.contains("*generation == entry.generation"));

    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("slab = \"0.4\""));
    let lock = read_repo_file("Cargo.lock");
    assert!(lock.contains("name = \"slab\"\nversion = \"0.4.12\""));
    assert!(read_repo_file("src/service/mod.rs").contains("pub mod rate_limit;"));
    let sync_module = read_repo_file("src/sync/mod.rs");
    assert!(sync_module.contains("pub mod semaphore;"));
    assert!(sync_module.contains("mod waiter;"));
    assert!(read_repo_file("src/time/mod.rs").contains("mod wheel;"));

    let registry = registry_rows();
    let capability = registry
        .get("CAP-TOKEN-SLAB")
        .expect("token-slab capability");
    assert_eq!(
        string_set(capability, "source_owners"),
        BTreeSet::from([
            "src/service/rate_limit.rs".to_owned(),
            "src/sync/semaphore.rs".to_owned(),
            "src/sync/waiter.rs".to_owned(),
            "src/time/wheel.rs".to_owned(),
        ])
    );
    assert_eq!(
        string_set(capability, "features"),
        BTreeSet::from(["default".to_owned()])
    );
    assert_eq!(
        string_set(capability, "replacement_bead_ids"),
        BTreeSet::from([SLAB_BEAD_ID.to_owned()])
    );
    assert_eq!(
        string_set(capability, "scenario_ids"),
        BTreeSet::from([
            "token_slab_cancel_cleanup".to_owned(),
            "token_slab_churn".to_owned(),
        ])
    );
    assert_eq!(
        string(capability, "cutover_state"),
        "BLOCKED_PENDING_EVIDENCE"
    );

    let baseline_index = capability_index(&value, "CAP-TOKEN-SLAB");
    let baseline = &value["capability_baselines"][baseline_index];
    assert_eq!(string(baseline, "baseline_state"), "EXECUTABLE_COMPLETE");
    assert_eq!(
        string_set(baseline, "evidence_ids"),
        BTreeSet::from(["EVD-TOKEN-SLAB".to_owned()])
    );
    assert!(!boolean(baseline, "cutover_eligible"));

    let assessment = object(audit, "existing_evidence_assessment");
    assert_eq!(
        string(assessment, "binding_state"),
        "MISBOUND_ADJACENT_EVIDENCE_NOT_REPLACEMENT_PARITY"
    );
    assert_eq!(
        string(assessment, "baseline_fixture_path"),
        SLAB_BASELINE_FIXTURE
    );
    assert_eq!(unsigned(assessment, "fixture_external_slab_token_count"), 0);
    assert_eq!(unsigned(assessment, "fixture_util_arena_token_count"), 5);
    assert_eq!(unsigned(assessment, "fixture_declared_test_count"), 12);
    assert!(!boolean(
        assessment,
        "replacement_execution_receipt_present"
    ));

    let catalog = evidence_rows(&value);
    let catalogued = catalog
        .get("EVD-TOKEN-SLAB")
        .expect("catalogued token-slab evidence");
    assert_eq!(
        string_set(catalogued, "fixture_paths"),
        BTreeSet::from([SLAB_BASELINE_FIXTURE.to_owned()])
    );
    let fixture = read_repo_file(SLAB_BASELINE_FIXTURE);
    assert_eq!(count_occurrences(&fixture, SLAB_PATH_TOKEN), 0);
    let arena_token_count = count_occurrences(&fixture, "use asupersync::util::Arena;")
        + count_occurrences(&fixture, "Arena::with_capacity")
        + count_occurrences(&fixture, "Arena::<");
    assert_eq!(arena_token_count, 5);
    assert_eq!(count_trimmed_lines(&fixture, "#[test]"), 12);
    for absent in ["RateLimit", "SemaphoreState", "WaiterChain", "TimerWheel"] {
        assert!(
            !fixture.contains(absent),
            "misbound fixture contains {absent}"
        );
    }

    let declared_counts = object(assessment, "source_declared_test_counts");
    assert_eq!(
        count_trimmed_lines(&rate_source, "#[test]"),
        unsigned(declared_counts, "rate_limit")
    );
    assert_eq!(
        count_trimmed_lines(&semaphore_source, "#[test]"),
        unsigned(declared_counts, "semaphore")
    );
    assert_eq!(
        count_trimmed_lines(&waiter_source, "#[test]"),
        unsigned(declared_counts, "waiter")
    );
    assert_eq!(
        count_trimmed_lines(&wheel_source, "#[test]"),
        unsigned(declared_counts, "timer_wheel")
    );
    assert!(waiter_source.contains("popped_waiter_id_cannot_remove_reused_slab_slot"));
    assert!(wheel_source.contains("wheel_cancel_rejects_generation_mismatch_without_removing"));
    assert!(semaphore_source.contains("metamorphic_fifo_order_under_cancellation"));
    assert!(rate_source.contains("panicking_waiter_does_not_suppress_other_refund_wakes"));

    let dependency_runner = read_repo_file("scripts/run_dependency_sovereignty_e2e.sh");
    let aggregate_runner = read_repo_file("scripts/run_all_e2e.sh");
    for absent in ["token_slab_churn", "token_slab_cancel_cleanup"] {
        assert!(!dependency_runner.contains(absent));
        assert!(!aggregate_runner.contains(absent));
    }

    let marginal = object(audit, "marginal_ledger_assessment");
    assert_eq!(unsigned(marginal, "slab_measurement_row_count"), 52);
    assert_eq!(unsigned(marginal, "feature_profile_count"), 13);
    assert_eq!(unsigned(marginal, "target_triple_count"), 4);
    assert!(!boolean(
        marginal,
        "source_commit_matches_observed_revision"
    ));
    assert!(!boolean(marginal, "fresh_for_cutover"));
    assert!(!boolean(marginal, "favorable_cutover_verdict"));
    let ledger = parse_json(MARGINAL_LEDGER_PATH);
    assert_eq!(
        string(&ledger, "source_commit"),
        string(marginal, "ledger_source_commit")
    );
    let rows = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("dependency_name").and_then(Value::as_str) == Some("slab"))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 52);
    assert_eq!(
        rows.iter()
            .map(|row| string(row, "feature_profile").to_owned())
            .collect::<BTreeSet<_>>(),
        string_set(marginal, "feature_profiles")
    );
    assert_eq!(
        rows.iter()
            .map(|row| string(row, "target_triple").to_owned())
            .collect::<BTreeSet<_>>(),
        string_set(marginal, "target_triples")
    );
    let mut package_count_distribution = BTreeMap::new();
    for row in rows {
        assert_eq!(string(row, "direct_root_edge"), "normal:slab");
        assert_eq!(string(row, "unsafe_exposure_class"), "SAFE-OWN");
        assert!(array(row, "build_scripts").is_empty());
        assert!(array(row, "proc_macros").is_empty());
        assert_eq!(
            string(object(row, "marginal_native_code"), "status"),
            "none"
        );
        let package_count = unsigned(row, "marginal_package_version_count");
        *package_count_distribution
            .entry(package_count)
            .or_insert(0usize) += 1;
        if package_count == 0 {
            assert!(array(row, "marginal_package_versions").is_empty());
        } else {
            assert_eq!(package_count, 1);
            assert_eq!(array(row, "marginal_package_versions").len(), 1);
        }
    }
    assert_eq!(
        package_count_distribution,
        BTreeMap::from([(0, 25usize), (1, 27usize)])
    );

    let matrix = object(audit, "required_evidence_matrix");
    assert_eq!(string(matrix, "status"), "MISSING_NOT_RUN");
    assert_eq!(unsigned(matrix, "captured_case_count"), 0);
    assert!(array(matrix, "captured_cases").is_empty());
    assert_eq!(array(matrix, "consumer_cells").len(), 4);
    assert_eq!(array(matrix, "collection_cells").len(), 8);
    assert_eq!(array(matrix, "profile_cells").len(), 6);
    assert_eq!(array(matrix, "target_cells").len(), 4);
    assert_eq!(array(matrix, "required_metrics").len(), 8);

    let gate = object(audit, "cutover_gate");
    assert_eq!(string(gate, "required_state"), "SAME_OR_BETTER");
    let gate_rows = array(gate, "rows");
    assert_eq!(gate_rows.len(), 10);
    assert_eq!(
        gate_rows
            .iter()
            .filter(|row| row.get("state").and_then(Value::as_str) == Some("STATIC_COMPLETE"))
            .count(),
        1
    );
    assert_eq!(
        gate_rows
            .iter()
            .filter(|row| row.get("state").and_then(Value::as_str) == Some("MISSING"))
            .count(),
        9
    );
    assert_eq!(
        string(gate, "on_any_missing_or_regressed_row"),
        "KEEP_INCUMBENT"
    );
    assert!(!boolean(gate, "slab_exit_allowed"));
    assert!(!boolean(gate, "tracker_closure_allowed"));

    let no_claims = array(audit, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "No slab replacement",
        "do not prove candidate behavior",
        "misbound adjacent util::Arena evidence",
        "does not authorize cutover",
        "does not authorize slab removal",
    ] {
        assert!(no_claims.contains(required), "missing no-claim: {required}");
    }
}

#[test]
fn phase2_terminal_readiness_frontier_is_exact_and_fail_closed() {
    let value = artifact();
    let audit = object(&value, "phase2_terminal_readiness_static_audit");
    assert_eq!(string(audit, "audit_id"), PHASE2_READINESS_AUDIT_ID);
    assert_eq!(string(audit, "bead_id"), PHASE2_SIGNOFF_BEAD_ID);
    assert_eq!(
        string(audit, "observed_at_revision"),
        "33f94643ced8f5415ad3c1f0a30cd42ddcb738c9"
    );
    assert_eq!(
        string(audit, "audit_state"),
        "STATIC_GIT_ARTIFACT_AND_TRACKER_TOPOLOGY_PINNED_NOT_EXECUTED"
    );
    assert_eq!(
        string(audit, "execution_state"),
        "NO_CHILD_OR_AGGREGATE_EXECUTION_REPLAYED"
    );

    let expected_capabilities = BTreeSet::from([
        "CAP-ATP-VERSION-SCANNER".to_owned(),
        "CAP-AUTH-CREDENTIALS".to_owned(),
        "CAP-BASE64-CODEC".to_owned(),
        "CAP-CLI-OFFLINE-TUNER".to_owned(),
        "CAP-DIAGNOSTICS".to_owned(),
        "CAP-FUTURES-STREAMS".to_owned(),
        "CAP-HASH-MAPS".to_owned(),
        "CAP-HEX-CODEC".to_owned(),
        "CAP-HOST-BENCH-METADATA".to_owned(),
        "CAP-HOST-INTROSPECTION".to_owned(),
        "CAP-REAL-SERVICE-E2E".to_owned(),
        "CAP-TEMP-ARTIFACTS".to_owned(),
        "CAP-TIME-UTC-RFC3339".to_owned(),
        "CAP-TOKEN-SLAB".to_owned(),
        "CAP-VERIFICATION-PROFILES".to_owned(),
        "CAP-VISIBILITY-MACRO".to_owned(),
    ]);
    let binding = object(audit, "registry_binding");
    assert_eq!(string(binding, "state"), "EXACT_PRESENT");
    assert_eq!(string(binding, "registry_path"), REGISTRY_PATH);
    assert_eq!(string_set(binding, "capability_ids"), expected_capabilities);

    let registry = registry();
    let registry_rule = array(&registry, "bead_mapping_rules")
        .iter()
        .find(|rule| rule.get("bead_id").and_then(Value::as_str) == Some(PHASE2_SIGNOFF_BEAD_ID))
        .expect("Phase-2 signoff must have an exact registry rule");
    assert_eq!(string(registry_rule, "scope"), "exact");
    assert_eq!(
        string_set(registry_rule, "capability_ids"),
        string_set(binding, "capability_ids")
    );

    let tracker_snapshot = object(audit, "tracker_snapshot");
    assert_eq!(string(tracker_snapshot, "path"), TRACKER_PATH);
    assert_eq!(string(tracker_snapshot, "sha256").len(), 64);
    assert!(unsigned(tracker_snapshot, "line_count") > 0);
    assert!(!boolean(tracker_snapshot, "completion_authority"));
    assert!(!boolean(tracker_snapshot, "write_allowed"));
    assert!(string(tracker_snapshot, "role").contains("read-only"));

    let expected_pins = BTreeMap::from([
        (
            REGISTRY_PATH,
            (
                "d255864fdd4f314d309e3f749c782a79f8ae4ac70bf63baa57edb14b14b6a6ea",
                6929_u64,
            ),
        ),
        (
            PHASE1_SIGNOFF_PATH,
            (
                "f99bb9e88291d122b1f075c43480436ed1a94c0389174a472c9684d9b2ebf3c4",
                327_u64,
            ),
        ),
        (
            CLI_INVENTORY_PATH,
            (
                "6e75eaffa3b3a8e64feb38631d7f4d1e65a9126b9338780303e639168687bb55",
                7443_u64,
            ),
        ),
        (
            UTC_FOUNDATION_PATH,
            (
                "b141bca2ef0238eab6541d903ad02d61dc9c7801acdf7609606fd75a5e1cc599",
                91_u64,
            ),
        ),
        (
            FUTURES_INVENTORY_PATH,
            (
                "cea3d2d4c0874b0ee002f98d7730ce5ef67e82c24a0f7412bb96ee49552514fe",
                894_u64,
            ),
        ),
        (
            HEX_INVENTORY_PATH,
            (
                "971385dfaf02570e6a02d52b494bc231e089ab8281bbcde812ff529727c10478",
                960_u64,
            ),
        ),
        (
            BASE64_INVENTORY_PATH,
            (
                "28171082ff529b93cbe951b9de84db9423b8922fde531c82aa21051b933c83eb",
                417_u64,
            ),
        ),
        (
            ATP_ARTIFACT_SOURCE,
            (
                "21b5131f5c5c2502b96bd61363a3bc21072062a0b9473bd602ab478a6b77cea9",
                1597_u64,
            ),
        ),
        (
            "scripts/run_dependency_sovereignty_e2e.sh",
            (
                "388af46854549b837e7de602fbb84f99d26dcf2fef6b7e4f8575f1f6478d33a0",
                1276_u64,
            ),
        ),
        (
            DORMANT_E2E_INVENTORY_PATH,
            (
                "9a28fef1a5e304d371b2c4e0b0538085ad304ce0bdc54828e7709c029a42edbd",
                552_u64,
            ),
        ),
        (
            TRACKER_PATH,
            (
                "54331bf1da49d041ab0b92e89cf81037a3808de1e7d13ef4810dafc1315256bf",
                12444_u64,
            ),
        ),
    ]);
    let source_pins = array(audit, "source_pins");
    assert_eq!(source_pins.len(), expected_pins.len());
    let actual_pin_paths = source_pins
        .iter()
        .map(|pin| string(pin, "path").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_pin_paths,
        expected_pins
            .keys()
            .map(|path| (*path).to_owned())
            .collect()
    );
    for pin in source_pins {
        let path = string(pin, "path");
        let (expected_sha, expected_lines) = expected_pins
            .get(path)
            .unwrap_or_else(|| panic!("unexpected Phase-2 source pin {path}"));
        assert_eq!(
            string(pin, "sha256"),
            *expected_sha,
            "stored SHA for {path}"
        );
        assert_eq!(
            unsigned(pin, "line_count"),
            *expected_lines,
            "stored line count for {path}"
        );
        assert!(!string(pin, "role").is_empty());
    }

    let expected_prerequisites = BTreeSet::from([
        "asupersync-dep-p1-foundations-upksjk.4".to_owned(),
        "asupersync-d24mms.1".to_owned(),
        "asupersync-d24mms.10.6".to_owned(),
        "asupersync-d24mms.11".to_owned(),
        "asupersync-d24mms.12.5".to_owned(),
        "asupersync-d24mms.2".to_owned(),
        "asupersync-d24mms.3".to_owned(),
        "asupersync-d24mms.4".to_owned(),
        "asupersync-d24mms.5".to_owned(),
        "asupersync-d24mms.6.10".to_owned(),
        "asupersync-d24mms.7".to_owned(),
        "asupersync-d24mms.8".to_owned(),
        "asupersync-d24mms.9.5".to_owned(),
    ]);
    let issues = tracker_issues();
    let signoff_issue = issues
        .get(PHASE2_SIGNOFF_BEAD_ID)
        .expect("tracker snapshot must contain Phase-2 signoff");
    let tracker_prerequisites = array(signoff_issue, "dependencies")
        .iter()
        .filter(|dependency| dependency.get("type").and_then(Value::as_str) == Some("blocks"))
        .map(|dependency| string(dependency, "depends_on_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(tracker_prerequisites, expected_prerequisites);

    let prerequisite_rows = array(audit, "prerequisite_rows");
    assert_eq!(prerequisite_rows.len(), 13);
    let row_ids = prerequisite_rows
        .iter()
        .map(|row| string(row, "prerequisite_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(row_ids, expected_prerequisites);

    let mut state_counts = BTreeMap::<String, u64>::new();
    let mut terminal_ready = BTreeSet::new();
    let mut landing_commits = BTreeSet::new();
    for row in prerequisite_rows {
        *state_counts
            .entry(string(row, "readiness_state").to_owned())
            .or_default() += 1;
        assert!(!array(row, "evidence_refs").is_empty());
        assert!(!string(row, "landed_scope").is_empty());
        if boolean(row, "terminal_ready") {
            terminal_ready.insert(string(row, "prerequisite_id").to_owned());
            assert!(array(row, "missing_terminal_evidence").is_empty());
        } else {
            assert!(!array(row, "missing_terminal_evidence").is_empty());
        }
        for commit in array(row, "landing_commits") {
            let commit = commit.as_str().expect("landing commit must be text");
            assert_eq!(commit.len(), 40);
            assert!(commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(
                landing_commits.insert(commit.to_owned()),
                "duplicate landing commit"
            );
        }
    }
    assert_eq!(
        state_counts,
        BTreeMap::from([
            ("CAMPAIGN_PARTIAL_BLOCKED".to_owned(), 4),
            ("CHECKPOINT_LANDED_BLOCKED".to_owned(), 2),
            ("FOUNDATION_SCOPED_PASS".to_owned(), 1),
            ("NO_DEDICATED_RECEIPT".to_owned(), 1),
            ("STATIC_KEEP_GATE_LANDED_BLOCKED".to_owned(), 5),
        ])
    );
    assert_eq!(
        terminal_ready,
        BTreeSet::from(["asupersync-dep-p1-foundations-upksjk.4".to_owned()])
    );
    assert_eq!(
        landing_commits,
        BTreeSet::from([
            "03ae793105ce744c10b878d78d4d0723d23aa81f".to_owned(),
            "1472b388e365460c2dc067b57f084291e6d8d407".to_owned(),
            "2ddb3c79f33119f5e13001ca9c2547c2117b8627".to_owned(),
            "33f94643ced8f5415ad3c1f0a30cd42ddcb738c9".to_owned(),
            "341ac3656a98e8b07749207d2996914b23042fcf".to_owned(),
            "42a66e7f4e6733c28c59405c052c68f7a32ea0d7".to_owned(),
            "4d5748b3de2c15985af55e3dfe3c35626d6be543".to_owned(),
            "51543c21a171e2708d3892776c8979fdf2d9fd01".to_owned(),
            "66e7b73f10fad35292485ea2b3ff1d3a2bb9fff4".to_owned(),
            "8793ef7097f23622b2bdea1cd9a60afbb11517f1".to_owned(),
            "90b367053a81ddb436aca6641fc6307fc2b2f1b3".to_owned(),
            "982d1ae6f76c57c7f7f73aff915aa4c33bfb3e8b".to_owned(),
            "da9b1b40fcc1bf19ba92f445ed338bb51b638ee0".to_owned(),
            "efab658ab3966f68f005b02ba0c5710467523d51".to_owned(),
            "f89fa209b9a1612deab458734030ffcacd908037".to_owned(),
            "f8c96d5e9641928d5d37ed990aaa16805b95620a".to_owned(),
        ])
    );

    let summary = object(audit, "readiness_summary");
    assert_eq!(unsigned(summary, "required_prerequisite_count"), 13);
    assert_eq!(unsigned(summary, "terminal_ready_count"), 1);
    assert_eq!(unsigned(summary, "blocked_count"), 12);
    let declared_state_counts = array(summary, "state_counts")
        .iter()
        .map(|row| (string(row, "state").to_owned(), unsigned(row, "count")))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(declared_state_counts, state_counts);

    for (key, bead_id) in [
        ("hash_map_static_audit", HASH_MAP_BEAD_ID),
        (
            "host_benchmark_metadata_static_audit",
            HOST_METADATA_BEAD_ID,
        ),
        ("visibility_macro_static_audit", VISIBILITY_BEAD_ID),
        ("slab_static_audit", SLAB_BEAD_ID),
    ] {
        let leaf = object(&value, key);
        assert_eq!(string(leaf, "bead_id"), bead_id);
        assert!(!boolean(
            object(leaf, "cutover_gate"),
            "tracker_closure_allowed"
        ));
    }

    let cli = parse_json(CLI_INVENTORY_PATH);
    let env_logger = object(&cli, "env_logger_static_audit");
    assert_eq!(string(env_logger, "bead_id"), "asupersync-d24mms.3");
    assert!(!boolean(
        object(env_logger, "cutover_gate"),
        "tracker_closure_allowed"
    ));
    let phase1 = parse_json(PHASE1_SIGNOFF_PATH);
    assert_eq!(
        string(object(&phase1, "verdict"), "outcome"),
        "PASS_SCOPED_FOUNDATIONS_ONLY"
    );
    let utc = parse_json(UTC_FOUNDATION_PATH);
    assert!(!boolean(object(&utc, "decision"), "close_bead_allowed"));
    assert_eq!(
        string(&parse_json(FUTURES_INVENTORY_PATH), "bead_id"),
        "asupersync-d24mms.6.1"
    );
    assert_eq!(
        string(&parse_json(HEX_INVENTORY_PATH), "bead_id"),
        "asupersync-d24mms.9.1"
    );
    assert_eq!(
        string(&parse_json(BASE64_INVENTORY_PATH), "bead_id"),
        "asupersync-d24mms.10.1"
    );
    assert_eq!(
        string(&parse_json(DORMANT_E2E_INVENTORY_PATH), "bead_id"),
        "asupersync-d24mms.12.1"
    );
    let scanner = read_repo_file(ATP_ARTIFACT_SOURCE);
    assert!(scanner.contains("const MAX_VERSION_TOKEN_BYTES: usize = 64;"));
    assert!(!scanner.contains("mod regex"));
    let runner = read_repo_file("scripts/run_dependency_sovereignty_e2e.sh");
    assert!(runner.contains("atp_version_artifacts"));
    assert!(runner.contains("dep-sovereignty-asupersync_d24mms_11_d22341de8339"));

    let decision = object(audit, "readiness_decision");
    assert_eq!(
        string(decision, "status"),
        "BLOCKED_12_OF_13_PREREQUISITES_NOT_TERMINAL"
    );
    assert!(!boolean(decision, "phase2_terminal_signoff_allowed"));
    assert!(!boolean(decision, "dependency_exit_allowed"));
    assert!(!boolean(decision, "manifest_or_lockfile_edit_allowed"));
    assert!(!boolean(decision, "tracker_closure_allowed"));
    assert_eq!(
        string(decision, "required_next_state"),
        "ALL_13_PREREQUISITES_TERMINAL_AND_REPLAYED_WITH_ZERO_UNKNOWN"
    );
    assert_eq!(
        string(decision, "on_missing_stale_unreplayed_or_regressed_row"),
        "BLOCK_PHASE2_SIGNOFF_AND_KEEP_INCUMBENTS"
    );

    let no_claims = array(audit, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "No Cargo, RCH",
        "do not prove that any child terminal",
        "topology context only",
        "do not authorize their tracker closure",
        "does not authorize Phase-2 signoff",
        "deletion of any file",
    ] {
        assert!(no_claims.contains(required), "missing no-claim: {required}");
    }
}
