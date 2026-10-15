//! Contract ratchets for memory-tier aware slab/pool certification.

use asupersync::record::{ObligationRecord, RegionRecord, TaskRecord};
use asupersync::runtime::config::{
    ArenaLocalityAccessModel, ArenaLocalityPolicy, ArenaTemperatureFallbackReason,
    ArenaTemperaturePolicy, MEMORY_TIER_SLAB_POOL_CERTIFICATIONS, RuntimeCapacityHints,
    RuntimeConfig, TraceStorageProfile, WorkerCohortMapping,
};
use asupersync::util::Arena;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const CONTRACT_PATH: &str = "artifacts/memory_tier_slab_pool_contract_v1.json";
const HOT_COLD_ARENA_TIERS_CONTRACT_PATH: &str =
    "artifacts/hot_cold_arena_tiers_smoke_contract_v1.json";
const NUMA_LOCALITY_CONTRACT_PATH: &str = "artifacts/numa_arena_locality_smoke_contract_v1.json";
const OPERATOR_PROOF_BACKLOG_SIGNOFF_CONTRACT_PATH: &str =
    "artifacts/operator_proof_backlog_signoff_contract_v1.json";
const RELEASE_PROOF_PACK_CONTRACT_PATH: &str = "artifacts/release_proof_pack_contract_v1.json";
const RUNTIME_LATENCY_BUDGET_CERTIFICATE_PATH: &str =
    "artifacts/runtime_latency_budget_certificate_v1.json";
const SCHEDULER_P999_BASELINE_RECEIPT_PATH: &str =
    "tests/artifacts/perf/asupersync-xeh8m0.3/three_lane_decision_baseline_v1.json";
const SCHEDULER_P999_COMPLETE_RECEIPT_PATH: &str =
    "tests/artifacts/perf/asupersync-h6pjqb/scheduler_p999_latency_receipt_v1.json";
const SOURCE_DECLARATIONS_PATH: &str = "src/runtime/config.rs";
const TASK_RECORD_POOL_CONTRACT_PATH: &str = "artifacts/task_record_pool_smoke_contract_v1.json";
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

fn scenario_by_id<'a>(contract: &'a Value, scenario_id: &str) -> &'a Value {
    array(contract, "smoke_scenarios")
        .iter()
        .find(|scenario| string_field(scenario, "scenario_id") == scenario_id)
        .unwrap_or_else(|| panic!("missing scenario {scenario_id}"))
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
fn safe_heap_fallback_row_is_backed_by_task_pool_and_hot_cold_fallbacks() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    let row = rows
        .get("safe_heap_fallback")
        .expect("safe heap fallback row must exist");
    let frontier = Value::Object(object(&contract, "safe_heap_fallback_frontier").clone());

    assert_eq!(
        string_field(&frontier, "scenario_id"),
        "memory-tier-safe-heap-fallback-frontier-v1"
    );
    assert_eq!(
        string_field(&frontier, "required_row"),
        "safe_heap_fallback"
    );
    assert_eq!(
        string_field(row, "operator_verdict"),
        string_field(&frontier, "required_row_status"),
        "safe fallback must not render as an optimized runtime win"
    );
    assert_eq!(
        string_field(row, "status"),
        string_field(&frontier, "required_row_status")
    );

    let existing_contracts = string_set(row, "existing_contracts");
    for required in string_vec(&frontier, "required_existing_contracts") {
        assert!(
            existing_contracts.contains(&required),
            "safe fallback row must compose {required}"
        );
    }

    let required_accounting = string_set(row, "required_accounting");
    for field in string_vec(&frontier, "required_accounting_fields") {
        assert!(
            required_accounting.contains(&field),
            "safe fallback row must require {field}"
        );
    }

    assert_eq!(
        string_field(&frontier, "task_record_pool_contract_path"),
        TASK_RECORD_POOL_CONTRACT_PATH
    );
    let task_record_pool_contract: Value = serde_json::from_str(
        &fs::read_to_string(TASK_RECORD_POOL_CONTRACT_PATH)
            .expect("read task record pool smoke contract"),
    )
    .expect("parse task record pool smoke contract");
    assert_eq!(
        string_field(&task_record_pool_contract, "contract_version"),
        "task-record-pool-smoke-contract-v1"
    );
    let task_pool_scenario = scenario_by_id(
        &task_record_pool_contract,
        string_field(&frontier, "required_task_pool_scenario"),
    );
    assert_eq!(
        string_field(task_pool_scenario, "operator_verdict"),
        "fallback_only"
    );
    let task_pool_projection =
        Value::Object(object(task_pool_scenario, "expected_report_projection").clone());
    let required_projection =
        Value::Object(object(&frontier, "required_task_pool_projection").clone());
    for field in [
        "operator_verdict",
        "safe_fallback_profile",
        "used_safe_fallback",
        "no_win_trigger",
    ] {
        assert_eq!(
            task_pool_projection.get(field),
            required_projection.get(field),
            "task-pool fallback projection must preserve {field}"
        );
    }
    assert_eq!(
        string_set(&task_pool_projection, "fallback_reason_codes"),
        string_set(&required_projection, "fallback_reason_codes"),
        "task-pool fallback must keep the exact no-win reason set"
    );
    for field in &required_accounting {
        assert!(
            task_pool_projection.get(field).is_some(),
            "task-pool fallback projection missing {field}"
        );
    }

    assert_eq!(
        string_field(&frontier, "hot_cold_contract_path"),
        HOT_COLD_ARENA_TIERS_CONTRACT_PATH
    );
    let hot_cold_contract: Value = serde_json::from_str(
        &fs::read_to_string(HOT_COLD_ARENA_TIERS_CONTRACT_PATH)
            .expect("read hot/cold arena smoke contract"),
    )
    .expect("parse hot/cold arena smoke contract");
    assert_eq!(
        string_field(&hot_cold_contract, "contract_version"),
        "hot-cold-arena-tiers-smoke-contract-v1"
    );
    for scenario_id in string_vec(&frontier, "required_hot_cold_fallback_scenarios") {
        let scenario = scenario_by_id(&hot_cold_contract, &scenario_id);
        let workload = Value::Object(object(scenario, "workload_model").clone());
        assert_eq!(
            string_field(&workload, "default_safe_fallback_profile"),
            string_field(&frontier, "required_hot_cold_fallback_policy"),
            "{scenario_id} must name the conservative allocation fallback"
        );
        let notes = Value::Object(object(scenario, "operator_notes").clone());
        assert_eq!(
            string_field(&notes, "fallback_policy"),
            string_field(&frontier, "required_hot_cold_fallback_policy"),
            "{scenario_id} must expose the operator fallback policy"
        );
        assert!(
            scenario
                .get("expected_report_projection")
                .is_some_and(Value::is_null),
            "{scenario_id} must keep unexecuted fallback projections explicit"
        );
    }

    for forbidden in string_vec(&frontier, "forbidden_operator_verdicts") {
        assert_ne!(
            string_field(row, "operator_verdict"),
            forbidden,
            "safe fallback must not claim {forbidden}"
        );
        assert_ne!(
            string_field(row, "status"),
            forbidden,
            "safe fallback status must not claim {forbidden}"
        );
    }
    let rendered = render_markdown(&contract).join("\n");
    assert!(
        rendered.contains(
            "| safe_heap_fallback | task_records | safe_heap_fallback | fallback_only | 1 |"
        ),
        "markdown golden must keep safe fallback visible"
    );
    assert!(
        !rendered
            .contains("| safe_heap_fallback | task_records | safe_heap_fallback | ready_for_rch |"),
        "safe fallback must not render green"
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
fn cold_trace_evidence_tiers_row_is_backed_by_hot_cold_arena_contract() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    let row = rows
        .get("cold_trace_evidence_tiers")
        .expect("cold trace evidence row must exist");
    assert_eq!(
        string_field(row, "operator_verdict"),
        "implemented_verified"
    );
    assert_eq!(string_field(row, "status"), "implemented_verified");
    assert!(
        string_vec(row, "existing_contracts")
            .iter()
            .any(|contract| contract == "hot-cold-arena-tiers-smoke-contract-v1"),
        "cold trace row must compose the live hot/cold arena smoke contract"
    );

    let required_accounting = string_vec(row, "required_accounting");
    for required in [
        "trace_storage_profile",
        "hot_metadata_bytes",
        "cold_evidence_bytes",
        "retained_evidence_budget_bytes",
        "fallback_reason_codes",
    ] {
        assert!(
            required_accounting.iter().any(|field| field == required),
            "cold trace row must require {required}"
        );
    }

    let hot_cold_contract: Value = serde_json::from_str(
        &fs::read_to_string(HOT_COLD_ARENA_TIERS_CONTRACT_PATH)
            .expect("read hot/cold arena smoke contract"),
    )
    .expect("parse hot/cold arena smoke contract");
    assert_eq!(
        string_field(&hot_cold_contract, "contract_version"),
        "hot-cold-arena-tiers-smoke-contract-v1"
    );

    for field in [
        "expected_report_projection",
        "actual_report_projection",
        "actual_report_projection_repeat_2",
    ] {
        assert!(
            string_set(&hot_cold_contract, "required_run_report_fields").contains(field),
            "hot/cold run report must retain {field}"
        );
        assert!(
            string_set(&hot_cold_contract, "required_bundle_fields").contains(field),
            "hot/cold bundle must retain {field}"
        );
    }

    let mut saw_tiered_retention = false;
    let mut saw_large_page_fallback = false;
    let mut saw_locality_no_win = false;
    let mut saw_real_host_template = false;
    for scenario in array(&hot_cold_contract, "smoke_scenarios") {
        let scenario_id = string_field(scenario, "scenario_id");
        assert_eq!(
            string_field(scenario, "trace_storage_profile"),
            "large_memory_256g",
            "{scenario_id} must exercise the large-memory trace profile"
        );
        assert!(
            scenario.get("expected_report_projection").is_some(),
            "{scenario_id} must keep the projection slot explicit"
        );

        let workload = scenario
            .get("workload_model")
            .expect("scenario workload model");
        assert_eq!(
            string_field(workload, "default_safe_fallback_profile"),
            "unified",
            "{scenario_id} must name the safe fallback profile"
        );
        let capacity_hints = object(workload, "capacity_hints");
        for field in ["task_capacity", "region_capacity", "obligation_capacity"] {
            assert!(
                capacity_hints
                    .get(field)
                    .and_then(Value::as_u64)
                    .is_some_and(|value| value > 0),
                "{scenario_id} must keep nonzero {field}"
            );
        }

        let requested_policy = string_field(scenario, "requested_policy");
        if requested_policy == "tiered_cold_evidence" && scenario_id.contains("TIERED-RETENTION") {
            saw_tiered_retention = true;
        }
        if requested_policy == "tiered_cold_evidence_large_pages" {
            saw_large_page_fallback = workload
                .get("large_page_cold_slabs_supported")
                .and_then(Value::as_bool)
                == Some(false);
        }
        if scenario_id.contains("NO-WIN") {
            saw_locality_no_win = true;
            assert_eq!(requested_policy, "tiered_cold_evidence");
        }
        if scenario_id.contains("REAL-HOST-TEMPLATE") {
            saw_real_host_template = true;
            assert!(
                workload["locality_profile_input"]["worker_to_cohort_map"].is_null(),
                "real-host template must not fabricate locality evidence"
            );
        }
    }
    assert!(saw_tiered_retention, "missing tiered-retention scenario");
    assert!(
        saw_large_page_fallback,
        "missing unsupported large-page fallback scenario"
    );
    assert!(saw_locality_no_win, "missing locality no-win scenario");
    assert!(
        saw_real_host_template,
        "missing real-host template scenario"
    );

    let capacity_hints = RuntimeCapacityHints::new(4096, 1024, 2048);
    let worker_cohort_map = (0..64).map(|worker| worker / 8).collect::<Vec<_>>();
    let winning_locality = RuntimeConfig {
        worker_threads: 64,
        worker_cohort_map: Some(WorkerCohortMapping::new(worker_cohort_map)),
        capacity_hints: Some(capacity_hints),
        ..RuntimeConfig::default()
    }
    .arena_locality_report(
        ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: 6500,
            accounting_epoch: 11,
        },
        Some(91),
        &ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        },
    );
    let tiered_config = RuntimeConfig {
        worker_threads: 64,
        capacity_hints: Some(capacity_hints),
        arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
        trace_storage_profile: TraceStorageProfile::LargeMemory256G,
        ..RuntimeConfig::default()
    };
    let tiered_report =
        tiered_config.arena_temperature_report_with_locality(false, Some(&winning_locality), false);
    assert_eq!(tiered_report.fallback_reason, None);
    assert_eq!(
        tiered_report.cold_evidence_bytes,
        tiered_report.retained_evidence_bytes
    );
    assert_eq!(
        tiered_report.retained_evidence_bytes,
        TraceStorageProfile::LargeMemory256G
            .budget()
            .estimated_cold_bytes()
    );
    assert!(tiered_report.estimated_hot_bytes() > 0);
    let rendered_fields = tiered_report
        .render_report_fields()
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<BTreeMap<_, _>>();
    for field in [
        "estimated_hot_bytes",
        "cold_evidence_bytes",
        "retained_evidence_bytes",
        "fallback_reason",
    ] {
        assert!(
            rendered_fields.contains_key(field),
            "live arena report must render {field}"
        );
    }

    let large_page_report = RuntimeConfig {
        arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
        trace_storage_profile: TraceStorageProfile::LargeMemory256G,
        ..RuntimeConfig::default()
    }
    .arena_temperature_report_with_locality(false, Some(&winning_locality), false);
    assert_eq!(
        large_page_report.fallback_reason,
        Some(ArenaTemperatureFallbackReason::LargePagesUnsupported)
    );
    assert!(
        !large_page_report.large_page_cold_slabs_active,
        "unsupported large-page requests must fail closed"
    );

    let missing_locality_report = RuntimeConfig {
        arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
        trace_storage_profile: TraceStorageProfile::LargeMemory256G,
        ..RuntimeConfig::default()
    }
    .arena_temperature_report_with_locality(false, None, false);
    assert_eq!(
        missing_locality_report.fallback_reason,
        Some(ArenaTemperatureFallbackReason::LocalityProfileMissing)
    );
    assert_eq!(missing_locality_report.cold_evidence_bytes, 0);
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
fn scheduler_p999_latency_receipt_is_backed_by_complete_same_host_receipt() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    let row = rows
        .get("scheduler_p999_latency_receipt")
        .expect("scheduler p999 row must exist");
    assert_eq!(
        string_field(row, "operator_verdict"),
        "implemented_verified"
    );
    assert_eq!(string_field(row, "status"), "implemented_verified");
    for lower_contract in [
        "operator-proof-backlog-signoff-contract-v1",
        "runtime-latency-budget-certificate-v1",
        "asupersync-h6pjqb-scheduler-p999-latency-receipt-v1",
    ] {
        assert!(
            string_vec(row, "existing_contracts")
                .iter()
                .any(|contract| contract == lower_contract),
            "scheduler p999 row must compose {lower_contract}"
        );
    }

    let required_accounting = string_vec(row, "required_accounting");
    for required in [
        "p50_latency_ns",
        "p95_latency_ns",
        "p999_latency_ns",
        "sample_count",
        "previous_runtime_blocker_non_reproduction",
    ] {
        assert!(
            required_accounting.iter().any(|field| field == required),
            "scheduler p999 row must require {required}"
        );
    }
    assert!(
        string_vec(row, "source_files")
            .iter()
            .any(|path| path == SCHEDULER_P999_COMPLETE_RECEIPT_PATH),
        "scheduler p999 row must point at the complete checked-in receipt"
    );

    let latency_frontier = Value::Object(object(&contract, "latency_frontier").clone());
    assert_eq!(
        string_field(&latency_frontier, "scenario_id"),
        "memory-tier-scheduler-p999-frontier-v1"
    );
    assert_eq!(
        string_field(&latency_frontier, "required_row"),
        "scheduler_p999_latency_receipt"
    );
    assert_eq!(
        string_field(&latency_frontier, "signoff_contract_path"),
        OPERATOR_PROOF_BACKLOG_SIGNOFF_CONTRACT_PATH
    );
    assert_eq!(
        string_field(&latency_frontier, "latency_certificate_path"),
        RUNTIME_LATENCY_BUDGET_CERTIFICATE_PATH
    );
    assert_eq!(
        string_field(&latency_frontier, "baseline_receipt_path"),
        SCHEDULER_P999_BASELINE_RECEIPT_PATH
    );
    assert_eq!(
        string_field(&latency_frontier, "complete_receipt_path"),
        SCHEDULER_P999_COMPLETE_RECEIPT_PATH
    );

    let signoff: Value = serde_json::from_str(
        &fs::read_to_string(OPERATOR_PROOF_BACKLOG_SIGNOFF_CONTRACT_PATH)
            .expect("read operator proof backlog signoff contract"),
    )
    .expect("parse operator proof backlog signoff contract");
    assert_eq!(
        string_field(&signoff, "contract_version"),
        "operator-proof-backlog-signoff-contract-v1"
    );
    assert_eq!(
        string_field(&signoff, "final_operator_verdict"),
        string_field(&latency_frontier, "required_signoff_verdict")
    );
    assert_eq!(
        string_field(&signoff, "broad_readiness_claim"),
        string_field(&latency_frontier, "required_broad_readiness_claim")
    );
    assert!(
        string_field(&signoff, "operator_note").contains("p50/p95/p999"),
        "signoff note must keep the missing quantile receipt visible"
    );

    let scheduler_child = array(&signoff, "child_receipts")
        .iter()
        .find(|receipt| receipt["bead_id"].as_str() == Some("asupersync-xeh8m0.3"))
        .expect("scheduler evidence child receipt");
    assert_eq!(
        string_field(scheduler_child, "operator_verdict"),
        string_field(&latency_frontier, "required_child_verdict")
    );
    assert_eq!(
        scheduler_child["remote_exit_status"].as_u64(),
        Some(101),
        "runtime blocker must remain visible"
    );
    assert!(
        string_field(scheduler_child, "fallback_no_win_reason").contains("p50/p95/p999"),
        "child receipt must refuse broad p999 claims"
    );
    assert!(
        array(scheduler_child, "artifact_paths")
            .iter()
            .any(|path| path.as_str() == Some(SCHEDULER_P999_BASELINE_RECEIPT_PATH)),
        "child receipt must point at the checked-in scheduler baseline receipt"
    );

    let baseline: Value = serde_json::from_str(
        &fs::read_to_string(SCHEDULER_P999_BASELINE_RECEIPT_PATH)
            .expect("read scheduler p999 baseline receipt"),
    )
    .expect("parse scheduler p999 baseline receipt");
    assert_eq!(string_field(&baseline, "verdict"), "no_win");
    assert_eq!(
        baseline["proof_lane_executed_through_rch"].as_bool(),
        Some(true)
    );
    let metrics = object(&baseline, "metrics");
    assert_eq!(
        metrics.get("metrics_state").and_then(Value::as_str),
        Some("required_quantiles_not_collected_runtime_failed_before_full_scenario")
    );
    for metric in ["p50", "p95", "p999", "sample_count"] {
        assert!(
            metrics.get(metric).is_some_and(serde_json::Value::is_null),
            "baseline metric {metric} must remain null until the complete receipt exists"
        );
    }
    let claims = object(&baseline, "claims");
    assert_eq!(
        claims["scheduler_speedup"].as_str(),
        Some("not_claimed"),
        "no memory-tier speedup can be claimed from a no-win receipt"
    );
    assert_eq!(
        claims["baseline_latency"].as_str(),
        Some("not_claimed"),
        "baseline latency must stay unclaimed until quantiles exist"
    );
    let next_required_action = claims["next_required_action"]
        .as_str()
        .expect("next required action");
    for needle in [
        "Fix or isolate",
        "rerun the same rch cargo bench lane",
        "p50/p95/p999",
    ] {
        assert!(
            next_required_action.contains(needle),
            "next required action must contain {needle:?}"
        );
    }

    let complete_receipt: Value = serde_json::from_str(
        &fs::read_to_string(SCHEDULER_P999_COMPLETE_RECEIPT_PATH)
            .expect("read scheduler p999 complete receipt"),
    )
    .expect("parse scheduler p999 complete receipt");
    assert_eq!(
        string_field(&complete_receipt, "schema_version"),
        string_field(&latency_frontier, "required_complete_receipt_schema")
    );
    assert_eq!(
        string_field(&complete_receipt, "verdict"),
        string_field(&latency_frontier, "required_complete_receipt_verdict")
    );
    assert_eq!(
        string_field(&complete_receipt, "operator_verdict"),
        string_field(&latency_frontier, "required_complete_operator_verdict")
    );
    assert_eq!(
        complete_receipt["proof_lane_executed_through_rch"].as_bool(),
        Some(true),
        "complete receipt must be rch-routed"
    );
    assert_eq!(
        string_field(
            &Value::Object(object(&complete_receipt, "host_class").clone()),
            "verdict"
        ),
        string_field(&latency_frontier, "required_same_host_verdict")
    );
    assert_eq!(
        object(&complete_receipt, "rch_history")["remote_exit"].as_u64(),
        Some(0),
        "complete receipt must come from a successful rch run"
    );
    assert_eq!(
        object(&complete_receipt, "previous_blocker")["reproduced_in_this_run"].as_bool(),
        latency_frontier["previous_blocker_must_be_non_reproduced"]
            .as_bool()
            .map(|must_be_non_reproduced| !must_be_non_reproduced),
        "previous os-thread-local blocker must be explicitly non-reproduced"
    );
    let complete_claims = object(&complete_receipt, "claims");
    assert_eq!(
        string_field(&Value::Object(complete_claims.clone()), "baseline_latency"),
        string_field(&latency_frontier, "required_baseline_latency_claim")
    );
    assert_eq!(
        string_field(&Value::Object(complete_claims.clone()), "scheduler_speedup"),
        string_field(&latency_frontier, "required_scheduler_speedup_claim")
    );

    let required_quantiles = string_vec(&latency_frontier, "required_quantiles");
    let required_sample_count = latency_frontier["required_sample_count"]
        .as_u64()
        .expect("required sample count");
    let benchmarks = array(&complete_receipt, "benchmarks");
    assert_eq!(
        benchmarks.len(),
        6,
        "complete receipt must include every three-lane decision case"
    );
    for benchmark in benchmarks {
        let case = string_field(benchmark, "case");
        assert_eq!(
            benchmark["samples"].as_u64(),
            Some(required_sample_count),
            "{case} must use the required sample count"
        );
        for quantile in &required_quantiles {
            assert!(
                benchmark[quantile]
                    .as_f64()
                    .is_some_and(|value| value > 0.0),
                "{case} must report positive {quantile}"
            );
        }
        let p50 = benchmark["p50_ns"].as_f64().expect("p50");
        let p95 = benchmark["p95_ns"].as_f64().expect("p95");
        let p999 = benchmark["p999_ns"].as_f64().expect("p999");
        assert!(
            p50 <= p95 && p95 <= p999,
            "{case} quantiles must be monotonic"
        );
    }

    let latency_certificate: Value = serde_json::from_str(
        &fs::read_to_string(RUNTIME_LATENCY_BUDGET_CERTIFICATE_PATH)
            .expect("read runtime latency budget certificate"),
    )
    .expect("parse runtime latency budget certificate");
    assert_eq!(
        string_field(&latency_certificate, "contract_version"),
        "runtime-latency-budget-certificate-v1"
    );
    let verdicts = array(&latency_certificate, "verdicts")
        .iter()
        .map(|verdict| string_field(verdict, "verdict").to_string())
        .collect::<BTreeSet<_>>();
    for verdict in ["pass", "no_win", "fail_closed"] {
        assert!(
            verdicts.contains(verdict),
            "latency certificate must define {verdict}"
        );
    }
    let required_inputs = string_set(&latency_certificate, "required_inputs");
    for input in ["p999_latency_ns", "sample_count", "replay_command"] {
        assert!(
            required_inputs.contains(input),
            "latency certificate must require {input}"
        );
    }
    let fail_closed_rules = string_set(&latency_certificate, "fail_closed_rules");
    assert!(
        fail_closed_rules.contains("missing_quantiles_mean_only_evidence"),
        "mean-only evidence must fail closed"
    );
    let no_win_rules = string_set(&latency_certificate, "no_win_rules");
    assert!(
        no_win_rules.contains("p999_budget_exceeded"),
        "p999 over-budget evidence must remain no-win"
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
        "scheduler_p999_latency_receipt",
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
