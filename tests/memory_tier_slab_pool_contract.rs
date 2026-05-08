//! Contract ratchets for memory-tier aware slab/pool certification.

use asupersync::record::{ObligationRecord, RegionRecord, TaskRecord};
use asupersync::runtime::config::{MEMORY_TIER_SLAB_POOL_CERTIFICATIONS, RuntimeCapacityHints};
use asupersync::util::Arena;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const CONTRACT_PATH: &str = "artifacts/memory_tier_slab_pool_contract_v1.json";
const NUMA_LOCALITY_CONTRACT_PATH: &str = "artifacts/numa_arena_locality_smoke_contract_v1.json";
const RELEASE_PROOF_PACK_CONTRACT_PATH: &str = "artifacts/release_proof_pack_contract_v1.json";
const SOURCE_DECLARATIONS_PATH: &str = "src/runtime/config.rs";
const TEST_PATH: &str = "tests/memory_tier_slab_pool_contract.rs";

fn load_contract() -> Value {
    serde_json::from_str(&fs::read_to_string(CONTRACT_PATH).expect("read memory tier contract"))
        .expect("parse memory tier contract")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value[key]
        .as_object()
        .unwrap_or_else(|| panic!("{key} object"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string array entry").to_string())
        .collect()
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string array entry").to_string())
        .collect()
}

fn tier_rows(contract: &Value) -> Vec<&Value> {
    array(contract, "tier_rows").iter().collect()
}

fn rows_by_id(contract: &Value) -> BTreeMap<String, &Value> {
    tier_rows(contract)
        .into_iter()
        .map(|row| (string_field(row, "row_id").to_string(), row))
        .collect()
}

fn validation_commands(contract: &Value) -> BTreeSet<String> {
    string_set(contract, "validation_commands")
}

fn render_markdown(contract: &Value) -> Vec<String> {
    let mut rows = vec![
        "| Row | Domain | Tier | Verdict | Proofs |".to_string(),
        "| --- | --- | --- | --- | --- |".to_string(),
    ];

    for row in tier_rows(contract) {
        rows.push(format!(
            "| {} | {} | {} | {} | {} |",
            string_field(row, "row_id"),
            string_field(row, "runtime_domain"),
            string_field(row, "memory_tier"),
            string_field(row, "operator_verdict"),
            array(row, "proof_commands").len()
        ));
    }

    rows
}

fn usize_field(value: &Value, key: &str) -> usize {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} unsigned integer")) as usize
}

#[derive(Debug, Clone, Copy)]
struct StressArenaProbe {
    initial_capacity: usize,
    final_capacity: usize,
    growth_events: usize,
}

fn stress_arena(initial_capacity: usize, inserts: usize) -> StressArenaProbe {
    let mut arena = Arena::with_capacity(initial_capacity);
    let initial_capacity = arena.capacity();
    let mut last_capacity = initial_capacity;
    let mut growth_events = 0usize;

    for index in 0..inserts {
        arena.insert(index as u64);
        let current_capacity = arena.capacity();
        if current_capacity != last_capacity {
            growth_events += 1;
            last_capacity = current_capacity;
        }
    }

    StressArenaProbe {
        initial_capacity,
        final_capacity: arena.capacity(),
        growth_events,
    }
}

fn bytes_to_mib(bytes: usize) -> f64 {
    bytes as f64 / 1_048_576.0
}

fn reserved_record_bytes(hints: RuntimeCapacityHints) -> usize {
    Arena::<TaskRecord>::estimated_bytes_for_capacity(hints.task_capacity)
        + Arena::<RegionRecord>::estimated_bytes_for_capacity(hints.region_capacity)
        + Arena::<ObligationRecord>::estimated_bytes_for_capacity(hints.obligation_capacity)
}

#[test]
fn contract_declares_the_memory_tier_coverage_surface() {
    let contract = load_contract();
    assert_eq!(
        string_field(&contract, "contract_version"),
        "memory-tier-slab-pool-contract-v1"
    );
    assert_eq!(string_field(&contract, "bead_id"), "asupersync-h6pjqb");
    assert_eq!(string_field(&contract, "status"), "contract_guarded");

    let requirements = object(&contract, "coverage_requirements");
    let required_domains = string_set(
        &Value::Object(requirements.clone()),
        "required_runtime_domains",
    );
    for domain in [
        "task_records",
        "region_records",
        "obligation_records",
        "trace_evidence",
        "proof_artifacts",
    ] {
        assert!(
            required_domains.contains(domain),
            "missing required runtime domain {domain}"
        );
    }

    let required_tiers = string_set(
        &Value::Object(requirements.clone()),
        "required_memory_tiers",
    );
    for tier in [
        "hot_runtime_records",
        "warm_capacity_and_locality_plans",
        "cold_evidence_artifacts",
        "safe_heap_fallback",
    ] {
        assert!(required_tiers.contains(tier), "missing memory tier {tier}");
    }
}

#[test]
fn stress_frontier_presizes_hot_records_and_keeps_fallback_visible() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    let frontier = Value::Object(object(&contract, "stress_frontier").clone());
    assert_eq!(
        string_field(&frontier, "scenario_id"),
        "memory-tier-high-count-frontier-v1"
    );

    for row_id in string_vec(&frontier, "required_rows") {
        assert!(
            rows.contains_key(&row_id),
            "stress frontier required row {row_id} must exist"
        );
    }

    let counts = Value::Object(object(&frontier, "record_counts").clone());
    let task_records = usize_field(&counts, "task_records");
    let region_records = usize_field(&counts, "region_records");
    let obligation_records = usize_field(&counts, "obligation_records");
    let hints = RuntimeCapacityHints::from_expected_concurrent_tasks(usize_field(
        &frontier,
        "expected_concurrent_tasks",
    ));
    assert!(
        hints.task_capacity >= task_records,
        "task capacity must cover the task-record frontier"
    );
    assert!(
        hints.region_capacity >= region_records,
        "region capacity must cover the region-record frontier"
    );
    assert!(
        hints.obligation_capacity >= obligation_records,
        "obligation capacity must cover the obligation-record frontier"
    );

    let hinted_task = stress_arena(hints.task_capacity, task_records);
    let hinted_region = stress_arena(hints.region_capacity, region_records);
    let hinted_obligation = stress_arena(hints.obligation_capacity, obligation_records);
    let hinted_growth =
        hinted_task.growth_events + hinted_region.growth_events + hinted_obligation.growth_events;
    assert_eq!(
        hinted_growth,
        usize_field(&frontier, "max_growth_events_after_presize"),
        "pre-sized hot arenas must not grow during the frontier burst"
    );
    assert_eq!(hinted_task.initial_capacity, hints.task_capacity);
    assert_eq!(hinted_region.initial_capacity, hints.region_capacity);
    assert_eq!(
        hinted_obligation.initial_capacity,
        hints.obligation_capacity
    );
    assert!(hinted_task.final_capacity >= task_records);
    assert!(hinted_region.final_capacity >= region_records);
    assert!(hinted_obligation.final_capacity >= obligation_records);

    let default_hints = RuntimeCapacityHints::default();
    let baseline_growth = stress_arena(default_hints.task_capacity, task_records).growth_events
        + stress_arena(default_hints.region_capacity, region_records).growth_events
        + stress_arena(default_hints.obligation_capacity, obligation_records).growth_events;
    assert!(
        baseline_growth >= usize_field(&frontier, "min_growth_events_without_hints"),
        "unhinted baseline must still show the growth churn this frontier protects against"
    );

    let hinted_reserved_mib = bytes_to_mib(reserved_record_bytes(hints));
    let max_reserved_mib = frontier["max_reserved_mib_after_presize"]
        .as_f64()
        .expect("max_reserved_mib_after_presize f64");
    assert!(
        hinted_reserved_mib <= max_reserved_mib,
        "frontier reserves {hinted_reserved_mib:.4} MiB, exceeding {max_reserved_mib:.4} MiB"
    );

    let fallback = rows
        .get("safe_heap_fallback")
        .expect("safe heap fallback row must remain visible");
    assert_eq!(
        string_field(fallback, "status"),
        string_field(&frontier, "required_safe_fallback_status"),
        "stress frontier must not hide the safe fallback row"
    );
}

#[test]
fn source_declarations_match_contract_rows() {
    let contract = load_contract();
    let policy = object(&contract, "source_declaration_policy");
    assert_eq!(
        string_field(&Value::Object(policy.clone()), "declaration_table"),
        "MEMORY_TIER_SLAB_POOL_CERTIFICATIONS"
    );
    assert_eq!(
        string_field(&Value::Object(policy.clone()), "source_path"),
        SOURCE_DECLARATIONS_PATH
    );
    assert_eq!(
        policy["matrix_rows_must_match_source_declarations"].as_bool(),
        Some(true)
    );

    for field in [
        "row_id",
        "runtime_domain",
        "memory_tier",
        "operator_verdict",
        "status",
        "source_files",
        "existing_contracts",
        "proof_commands",
    ] {
        assert!(
            string_set(&Value::Object(policy.clone()), "declared_fields").contains(field),
            "source declaration policy must require {field}"
        );
    }

    let rows_by_id = rows_by_id(&contract);
    let declared_ids = MEMORY_TIER_SLAB_POOL_CERTIFICATIONS
        .iter()
        .map(|declaration| declaration.row_id.to_string())
        .collect::<BTreeSet<_>>();
    let contract_ids = rows_by_id.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        contract_ids, declared_ids,
        "memory-tier contract rows must match source declarations"
    );

    for declaration in MEMORY_TIER_SLAB_POOL_CERTIFICATIONS {
        let row = rows_by_id
            .get(declaration.row_id)
            .unwrap_or_else(|| panic!("missing contract row {}", declaration.row_id));
        assert_eq!(
            string_field(row, "runtime_domain"),
            declaration.runtime_domain.as_str()
        );
        assert_eq!(
            string_field(row, "memory_tier"),
            declaration.memory_tier.as_str()
        );
        assert_eq!(
            string_field(row, "operator_verdict"),
            declaration.operator_verdict.as_str()
        );
        assert_eq!(string_field(row, "status"), declaration.status.as_str());
        assert_eq!(
            string_vec(row, "source_files"),
            declaration
                .source_files
                .iter()
                .map(|entry| (*entry).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            string_vec(row, "existing_contracts"),
            declaration
                .existing_contracts
                .iter()
                .map(|entry| (*entry).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            string_vec(row, "proof_commands"),
            declaration
                .proof_commands
                .iter()
                .map(|entry| (*entry).to_string())
                .collect::<Vec<_>>()
        );
    }

    let source = fs::read_to_string(SOURCE_DECLARATIONS_PATH).expect("read source declarations");
    assert!(source.contains("pub const MEMORY_TIER_SLAB_POOL_CERTIFICATIONS"));
    assert!(source.contains("MemoryTierSlabPoolCertification"));
}

#[test]
fn warm_numa_locality_row_is_backed_by_live_accounting_contract() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    let row = rows
        .get("warm_numa_arena_locality")
        .expect("warm NUMA locality row must exist");
    assert_eq!(
        string_field(row, "operator_verdict"),
        "implemented_verified"
    );
    assert_eq!(string_field(row, "status"), "implemented_verified");
    assert!(
        string_vec(row, "existing_contracts")
            .iter()
            .any(|contract| contract == "numa-arena-locality-smoke-contract-v1"),
        "warm NUMA row must compose the live NUMA locality smoke contract"
    );

    let required_accounting = string_vec(row, "required_accounting");
    for required in [
        "worker_cohort_fingerprint",
        "topology_fixture_hash",
        "selected_remote_touch_count",
        "remote_touch_reduction_ratio",
        "ownership_preserved",
    ] {
        assert!(
            required_accounting.iter().any(|field| field == required),
            "warm NUMA row must require {required}"
        );
    }

    let numa_contract: Value = serde_json::from_str(
        &fs::read_to_string(NUMA_LOCALITY_CONTRACT_PATH)
            .expect("read NUMA locality smoke contract"),
    )
    .expect("parse NUMA locality smoke contract");
    assert_eq!(
        string_field(&numa_contract, "contract_version"),
        "numa-arena-locality-smoke-contract-v1"
    );

    let mut saw_remote_touch_win = false;
    let mut saw_safe_fallback = false;
    let mut saw_template = false;
    for scenario in array(&numa_contract, "smoke_scenarios") {
        let scenario_id = string_field(scenario, "scenario_id");
        let projection = object(scenario, "expected_report_projection");
        for field in &required_accounting {
            assert!(
                projection.contains_key(field),
                "{scenario_id} projection missing required accounting field {field}"
            );
        }
        assert_eq!(
            projection
                .get("ownership_preserved")
                .and_then(Value::as_bool),
            Some(true),
            "{scenario_id} must preserve logical ownership"
        );

        let baseline_remote = projection
            .get("baseline_remote_touch_count")
            .and_then(Value::as_u64)
            .expect("baseline remote touch count");
        let selected_remote = projection
            .get("selected_remote_touch_count")
            .and_then(Value::as_u64)
            .expect("selected remote touch count");
        let reduction_ratio = projection
            .get("remote_touch_reduction_ratio")
            .and_then(Value::as_f64)
            .expect("remote touch reduction ratio");
        let verdict = projection
            .get("operator_verdict")
            .and_then(Value::as_str)
            .expect("operator verdict");
        let used_safe_fallback = projection
            .get("used_safe_fallback")
            .and_then(Value::as_bool)
            .expect("used safe fallback");

        if verdict == "ready_for_rch" {
            saw_remote_touch_win = true;
            assert!(
                selected_remote < baseline_remote,
                "{scenario_id} must reduce remote touches before it can be a win"
            );
            assert!(
                reduction_ratio > 0.0,
                "{scenario_id} must report a positive remote-touch reduction"
            );
            assert!(
                !used_safe_fallback,
                "{scenario_id} must not use fallback when locality wins"
            );
        }
        if verdict == "fallback_only" {
            saw_safe_fallback = true;
            assert!(
                used_safe_fallback,
                "{scenario_id} fallback row must keep safe fallback visible"
            );
            assert!(
                !array(&Value::Object(projection.clone()), "fallback_reason_codes").is_empty(),
                "{scenario_id} fallback row must expose a reason code"
            );
        }
        if string_field(scenario, "topology_mode") == "host_template_optional" {
            saw_template = true;
            assert_eq!(
                projection
                    .get("worker_cohort_fingerprint")
                    .and_then(Value::as_u64),
                Some(0),
                "{scenario_id} template must not fabricate worker evidence"
            );
            assert!(
                projection
                    .get("topology_fixture_hash")
                    .is_some_and(Value::is_null),
                "{scenario_id} template must not fabricate topology evidence"
            );
        }
    }

    assert!(saw_remote_touch_win, "missing locality win scenario");
    assert!(saw_safe_fallback, "missing safe-fallback scenario");
    assert!(saw_template, "missing host-template scenario");
}

#[test]
fn cold_proof_artifact_retention_row_is_backed_by_release_pack_output() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    let row = rows
        .get("cold_proof_artifact_retention")
        .expect("cold proof artifact retention row must exist");
    assert_eq!(
        string_field(row, "operator_verdict"),
        "implemented_verified"
    );
    assert_eq!(string_field(row, "status"), "implemented_verified");
    assert!(
        string_vec(row, "existing_contracts")
            .iter()
            .any(|contract| contract == "release-proof-pack-v1"),
        "cold proof row must compose the live release proof pack contract"
    );

    let required_accounting = string_vec(row, "required_accounting");
    for required in [
        "source_artifact_sha256",
        "source_artifact_byte_count",
        "proof_command_count",
        "raw_tracker_rows_omitted",
    ] {
        assert!(
            required_accounting.iter().any(|field| field == required),
            "cold proof row must require {required}"
        );
    }

    let release_contract: Value = serde_json::from_str(
        &fs::read_to_string(RELEASE_PROOF_PACK_CONTRACT_PATH)
            .expect("read release proof pack contract"),
    )
    .expect("parse release proof pack contract");
    assert_eq!(
        string_field(&release_contract, "contract_version"),
        "release-proof-pack-contract-v1"
    );

    let required_index_fields = string_set(&release_contract, "required_index_fields");
    for field in [
        "source_artifacts",
        "proof_commands",
        "summaries.tracker",
        "verdict",
    ] {
        assert!(
            required_index_fields.contains(field),
            "release proof pack contract must require {field}"
        );
    }
    let fail_closed_rules = string_vec(&release_contract, "fail_closed_rules").join("\n");
    assert!(fail_closed_rules.contains("missing source artifacts set verdict to fail_closed"));
    assert!(
        fail_closed_rules
            .contains("tracker summary includes counts and hashes only, not raw issue rows")
    );

    let output = Command::new("python3")
        .args([
            "scripts/proof_runner.py",
            "--release-proof-pack",
            "--release-proof-pack-generated-at",
            "2026-05-08T00:00:00Z",
            "--output",
            "json",
        ])
        .output()
        .expect("run release proof pack generator");
    assert!(
        output.status.success(),
        "release proof pack generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let generated: Value =
        serde_json::from_slice(&output.stdout).expect("parse release proof pack generator output");
    let pack = generated
        .get("proof_pack")
        .expect("generator output contains proof_pack");
    assert_eq!(
        pack["schema_version"].as_str(),
        Some("release-proof-pack-v1")
    );
    assert_eq!(pack["verdict"].as_str(), Some("pass"));

    let source_artifacts = array(pack, "source_artifacts");
    assert!(
        !source_artifacts.is_empty(),
        "release proof pack must include source artifact rows"
    );
    let mut saw_hash = false;
    let mut saw_byte_count = false;
    for artifact in source_artifacts {
        let sha256 = artifact["sha256"].as_str().expect("source artifact sha256");
        assert!(
            sha256.starts_with("sha256:"),
            "source artifact hashes must be sha256 tagged"
        );
        saw_hash = true;

        let byte_count = artifact["bytes"]
            .as_u64()
            .expect("source artifact byte count");
        assert!(
            byte_count > 0,
            "included source artifacts must report nonzero bytes"
        );
        saw_byte_count = true;
    }
    assert!(saw_hash, "missing source artifact sha256 accounting");
    assert!(
        saw_byte_count,
        "missing source artifact byte-count accounting"
    );

    let proof_commands = array(pack, "proof_commands");
    assert!(
        !proof_commands.is_empty(),
        "release proof pack must include proof commands"
    );
    let summary = object(pack, "summary");
    assert_eq!(
        summary.get("source_artifact_count").and_then(Value::as_u64),
        Some(u64::try_from(source_artifacts.len()).expect("artifact count fits u64"))
    );
    assert_eq!(
        summary.get("proof_command_count").and_then(Value::as_u64),
        Some(u64::try_from(proof_commands.len()).expect("proof command count fits u64"))
    );
    assert_eq!(
        pack["summaries"]["tracker"]["raw_issue_rows_embedded"].as_bool(),
        Some(false),
        "proof packs must retain tracker counts and hashes, not raw issue rows"
    );
}

#[test]
fn every_tier_row_is_source_owned_and_has_a_proof_lane() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    for row_id in [
        "hot_task_record_pool",
        "warm_runtime_capacity_hints",
        "warm_numa_arena_locality",
        "cold_trace_evidence_tiers",
        "cold_proof_artifact_retention",
        "safe_heap_fallback",
    ] {
        assert!(rows.contains_key(row_id), "missing row {row_id}");
    }

    for row in rows.values() {
        let row_id = string_field(row, "row_id");
        let source_files = array(row, "source_files");
        assert!(!source_files.is_empty(), "{row_id} has no source files");
        for source in source_files {
            let path = source.as_str().expect("source file string");
            assert!(Path::new(path).exists(), "{row_id} source {path} missing");
        }

        let proof_commands = array(row, "proof_commands");
        assert!(!proof_commands.is_empty(), "{row_id} has no proof commands");
        for command in proof_commands {
            let command = command.as_str().expect("proof command string");
            if command.contains("cargo ") || command.contains("rustfmt") {
                assert!(
                    command.starts_with("rch exec -- "),
                    "{row_id} CPU-heavy proof must be rch-routed: {command}"
                );
            }
            if command.contains("cargo test") {
                assert!(
                    command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_"),
                    "{row_id} cargo proof must use an isolated target dir: {command}"
                );
            }
        }
    }
}

#[test]
fn fail_closed_rows_cannot_render_as_green_or_unbounded() {
    let contract = load_contract();
    let allowed_states = string_set(
        &Value::Object(object(&contract, "coverage_requirements").clone()),
        "required_fail_closed_states",
    );
    let forbidden = string_set(
        &Value::Object(object(&contract, "coverage_requirements").clone()),
        "forbidden_green_without_live_proof",
    );
    let rendered = render_markdown(&contract).join("\n");

    for row in tier_rows(&contract) {
        let row_id = string_field(row, "row_id");
        let verdict = string_field(row, "operator_verdict");
        assert!(
            allowed_states.contains(verdict),
            "{row_id} uses non fail-closed verdict {verdict}"
        );
        assert_ne!(
            verdict, "ready_for_rch",
            "{row_id} renders a stale green verdict"
        );
        assert_ne!(verdict, "pass", "{row_id} renders a stale green verdict");
    }

    for forbidden_claim in forbidden {
        assert!(
            !rendered.contains(&forbidden_claim),
            "rendered matrix contains stale unsupported claim {forbidden_claim:?}"
        );
    }
}

#[test]
fn validation_commands_cover_this_contract_test() {
    let contract = load_contract();
    let policy = object(&contract, "validation_policy");
    assert_eq!(
        policy["contract_test_target"].as_str(),
        Some("memory_tier_slab_pool_contract")
    );
    assert_eq!(
        policy["cargo_proofs_must_be_rch_routed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        policy["cargo_proofs_must_use_isolated_target_dir"].as_bool(),
        Some(true)
    );

    let required_flags = string_set(&Value::Object(policy.clone()), "required_feature_flags");
    assert!(required_flags.contains("test-internals"));

    let commands_must_cover = string_set(&Value::Object(policy.clone()), "commands_must_cover");
    for required in ["json_syntax", "contract_rustfmt", "contract_cargo_test"] {
        assert!(
            commands_must_cover.contains(required),
            "validation policy omits {required}"
        );
    }

    let commands = validation_commands(&contract);
    assert!(commands.iter().any(|command| {
        command
            == "python3 -m json.tool artifacts/memory_tier_slab_pool_contract_v1.json >/dev/null"
    }));
    assert!(commands.iter().any(|command| {
        command.starts_with("git diff --check --")
            && command.contains(SOURCE_DECLARATIONS_PATH)
            && command.contains(CONTRACT_PATH)
            && command.contains(TEST_PATH)
    }));
    assert!(commands.iter().any(|command| {
        command.starts_with("rch exec -- rustfmt")
            && command.contains("--edition 2024")
            && command.contains(SOURCE_DECLARATIONS_PATH)
            && command.contains(TEST_PATH)
    }));
    assert!(commands.iter().any(|command| {
        command.starts_with("rch exec -- ")
            && command.contains(
                "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_tier_slab_pool_contract",
            )
            && command.contains("cargo test -p asupersync --test memory_tier_slab_pool_contract")
            && command.contains("--features test-internals")
    }));
}

#[test]
fn markdown_projection_is_stable() {
    let contract = load_contract();
    let rendered = render_markdown(&contract);
    let golden: Vec<String> = array(&contract, "markdown_golden")
        .iter()
        .map(|line| line.as_str().expect("markdown line string").to_string())
        .collect();

    assert_eq!(
        rendered, golden,
        "memory-tier certification matrix projection must stay reviewed"
    );
}
