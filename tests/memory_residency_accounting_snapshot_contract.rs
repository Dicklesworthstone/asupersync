//! Contract tests for memory-residency accounting snapshots.

#![allow(missing_docs)]

use asupersync::runtime::config::{
    ArenaLocalityAccessModel, ArenaLocalityPolicy, ArenaTemperaturePolicy, RuntimeCapacityHints,
    RuntimeConfig, TraceStorageProfile, WorkerCohortMapping,
};
use asupersync::runtime::{
    ArtifactMemoryPressureSnapshot, MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT,
    MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION, MemoryResidencyAccountingSnapshot,
    MemoryResidencyAccountingStatus, MemoryResidencyAggregationKind, MemoryResidencyLiveTaskAction,
    MemoryResidencyPolicy, MemoryResidencyPolicyInput, MemoryResidencyReasonCode,
    MemoryResidencyRecordPoolCounters, MemoryResidencyTier, RuntimeSnapshot,
};
use asupersync::web::debug::{DebugServer, DebugServerConfig, SnapshotFn};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

const CONTRACT_PATH: &str = "artifacts/memory_residency_accounting_snapshot_v1.json";
const DOCS_PATH: &str = "docs/proof/memory_residency_accounting_snapshot.md";
const SNAPSHOT_SOURCE_PATH: &str = "src/runtime/memory_residency.rs";
const DEBUG_SOURCE_PATH: &str = "src/web/debug.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    let path = repo_root().join(path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn load_contract() -> Value {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH)).expect("parse accounting contract")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string array entry").to_string())
        .collect()
}

fn large_host_worker_cohort_map() -> WorkerCohortMapping {
    WorkerCohortMapping::new(vec![
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
        3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7,
        7, 7, 7, 7,
    ])
}

fn skewed_access_model() -> ArenaLocalityAccessModel {
    ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
        obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
        task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
    }
}

fn locality_report(
    access_model: &ArenaLocalityAccessModel,
    budget_bps: u16,
) -> asupersync::runtime::config::ArenaLocalityReport {
    RuntimeConfig {
        worker_threads: 64,
        worker_cohort_map: Some(large_host_worker_cohort_map()),
        capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
        ..RuntimeConfig::default()
    }
    .arena_locality_report(
        ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: budget_bps,
            accounting_epoch: 17,
        },
        Some(95),
        access_model,
    )
}

fn cache_snapshot() -> ArtifactMemoryPressureSnapshot {
    ArtifactMemoryPressureSnapshot {
        resident_bytes: 128 * 1024 * 1024,
        max_resident_bytes: 8 * 1024 * 1024 * 1024,
        hot_resident_bytes: 96 * 1024 * 1024,
        cold_resident_bytes: 32 * 1024 * 1024,
        spill_eligible_bytes: 2 * 1024 * 1024 * 1024,
        remote_numa_bytes: 0,
        pressure_bps: 1_500,
        high_pressure: false,
        duplicate_bytes_avoided: 0,
        artifact_count: 12,
    }
}

fn base_input<'a>(
    locality: &'a asupersync::runtime::config::ArenaLocalityReport,
    cache: &'a ArtifactMemoryPressureSnapshot,
) -> MemoryResidencyPolicyInput<'a> {
    MemoryResidencyPolicyInput::new(
        RuntimeCapacityHints::from_expected_concurrent_tasks(4096),
        TraceStorageProfile::LargeMemory256G,
        ArenaTemperaturePolicy::TieredColdEvidence,
    )
    .with_locality_report(locality, 30)
    .with_artifact_cache_pressure(cache)
}

fn counters() -> MemoryResidencyRecordPoolCounters {
    MemoryResidencyRecordPoolCounters {
        task_hits: 11,
        task_misses: 2,
        task_recycles: 3,
        region_hits: 5,
        region_misses: 1,
        region_recycles: 2,
        obligation_hits: 7,
        obligation_misses: 4,
        obligation_recycles: 6,
    }
}

fn test_runtime_snapshot() -> RuntimeSnapshot {
    RuntimeSnapshot {
        timestamp: 123,
        regions: vec![],
        tasks: vec![],
        obligations: vec![],
        recent_events: vec![],
        finalizer_history: vec![],
        loser_drain_history: vec![],
    }
}

fn get_debug_response(server: &DebugServer, path: &str) -> String {
    let addr = server
        .local_addr()
        .expect("debug server should expose local addr in tests");
    let mut stream = TcpStream::connect(addr).expect("connect debug server");
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write request");
    stream.flush().expect("flush request");

    let mut response = String::new();
    let mut reader = BufReader::new(&stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => response.push_str(&line),
        }
    }
    response
}

#[test]
fn contract_artifact_and_docs_pin_schema_debug_endpoint_and_no_claims() {
    let contract = load_contract();
    assert_eq!(
        string_field(&contract, "schema_version"),
        "memory-residency-accounting-snapshot-contract-v1"
    );
    assert_eq!(
        string_field(&contract, "bead_id"),
        "asupersync-memory-residency-control-ho2itz.3"
    );
    assert_eq!(string_field(&contract, "status"), "contract_guarded");

    for path in [
        string_field(&contract["source_of_truth"], "snapshot_source"),
        string_field(&contract["source_of_truth"], "runtime_export"),
        string_field(&contract["source_of_truth"], "debug_server_source"),
        string_field(&contract["source_of_truth"], "contract_test"),
        string_field(&contract["source_of_truth"], "docs"),
        string_field(&contract["source_of_truth"], "upstream_policy_contract"),
    ] {
        assert!(repo_root().join(path).exists(), "{path} must exist");
    }

    assert_eq!(
        string_field(&contract["snapshot_schema"], "runtime_schema"),
        MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION
    );
    assert_eq!(
        string_field(&contract["snapshot_schema"], "debug_server_endpoint"),
        MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT
    );
    assert_eq!(
        string_vec(&contract["snapshot_schema"], "tier_order"),
        ["hot", "warm", "cold", "fallback", "no_win"]
    );
    assert_eq!(
        string_vec(&contract["snapshot_schema"], "aggregation_order"),
        [
            "runtime_total",
            "task_records",
            "region_records",
            "obligation_records",
            "retained_evidence",
            "artifact_cache"
        ]
    );

    let command = string_field(&contract["proof_lane"], "command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_"));
    assert!(
        command.contains(
            "cargo test -p asupersync --test memory_residency_accounting_snapshot_contract"
        )
    );

    let consumers: BTreeSet<_> = string_vec(&contract, "consumers").into_iter().collect();
    assert!(consumers.contains("debug-server GET /debug/memory-residency"));
    assert!(
        consumers
            .iter()
            .any(|consumer| consumer.contains("runtime-inspector"))
    );

    let non_consumers: BTreeSet<_> = string_vec(&contract, "non_consumers").into_iter().collect();
    assert!(non_consumers.contains("RuntimeBuilder default configuration"));
    assert!(non_consumers.contains("task cancellation or migration paths"));

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(CONTRACT_PATH));
    assert!(docs.contains(SNAPSHOT_SOURCE_PATH));
    assert!(docs.contains(DEBUG_SOURCE_PATH));
    assert!(docs.contains(MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT));
    assert!(docs.contains("Non-consumers"));
    assert!(docs.contains("release readiness"));
}

#[test]
fn default_policy_snapshot_is_disabled_and_has_no_continuous_loop() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = cache_snapshot();
    let input = base_input(&locality, &cache);
    let snapshot = MemoryResidencyAccountingSnapshot::from_policy_input(
        &MemoryResidencyPolicy::default(),
        &input,
        9,
        None,
    );

    assert_eq!(
        snapshot.schema_version,
        MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION
    );
    assert_eq!(
        snapshot.debug_server_endpoint,
        MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT
    );
    assert_eq!(snapshot.status, MemoryResidencyAccountingStatus::Disabled);
    assert!(!snapshot.policy_enabled);
    assert_eq!(snapshot.selected_tier, MemoryResidencyTier::Fallback);
    assert_eq!(
        snapshot.live_task_action,
        MemoryResidencyLiveTaskAction::RecommendOnly
    );
    assert!(!snapshot.continuous_accounting_loop);
    assert!(!snapshot.record_pool_counters_available);
    assert!(
        snapshot
            .reason_codes
            .contains(&MemoryResidencyReasonCode::PolicyDisabled)
    );
}

#[test]
fn fresh_snapshot_has_stable_tier_and_aggregation_order() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = cache_snapshot();
    let input = base_input(&locality, &cache);
    let snapshot = MemoryResidencyAccountingSnapshot::from_policy_input(
        &MemoryResidencyPolicy::experimental_opt_in(),
        &input,
        42,
        Some(counters()),
    );

    assert_eq!(snapshot.status, MemoryResidencyAccountingStatus::Fresh);
    assert_eq!(snapshot.selected_tier, MemoryResidencyTier::Warm);
    assert_eq!(
        snapshot
            .tier_rows
            .iter()
            .map(|row| row.tier)
            .collect::<Vec<_>>(),
        [
            MemoryResidencyTier::Hot,
            MemoryResidencyTier::Warm,
            MemoryResidencyTier::Cold,
            MemoryResidencyTier::Fallback,
            MemoryResidencyTier::NoWin
        ]
    );
    assert_eq!(
        snapshot
            .aggregation_rows
            .iter()
            .map(|row| row.kind)
            .collect::<Vec<_>>(),
        [
            MemoryResidencyAggregationKind::RuntimeTotal,
            MemoryResidencyAggregationKind::TaskRecords,
            MemoryResidencyAggregationKind::RegionRecords,
            MemoryResidencyAggregationKind::ObligationRecords,
            MemoryResidencyAggregationKind::RetainedEvidence,
            MemoryResidencyAggregationKind::ArtifactCache
        ]
    );
    assert!(snapshot.capacity.estimated_hot_runtime_record_bytes > 0);
    assert!(snapshot.capacity.estimated_hot_trace_bytes > 0);
    assert!(snapshot.capacity.candidate_cold_evidence_bytes > 0);
    assert_eq!(snapshot.record_pool_counters.total_hits(), 23);
    assert_eq!(snapshot.record_pool_counters.total_misses(), 7);
    assert_eq!(snapshot.record_pool_counters.total_recycles(), 11);
    assert!(
        snapshot
            .stable_report_lines()
            .contains(&"aggregation=artifact_cache row_count=12 estimated_bytes=134217728 status=fresh source=artifact_cache_pressure".to_string())
    );
}

#[test]
fn snapshot_json_is_byte_stable_for_repeated_fixed_inputs() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = cache_snapshot();
    let input = base_input(&locality, &cache);
    let first = MemoryResidencyAccountingSnapshot::from_policy_input(
        &MemoryResidencyPolicy::experimental_opt_in(),
        &input,
        99,
        Some(counters()),
    );
    let second = MemoryResidencyAccountingSnapshot::from_policy_input(
        &MemoryResidencyPolicy::experimental_opt_in(),
        &input,
        99,
        Some(counters()),
    );

    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
}

#[test]
fn unavailable_debug_provider_fails_closed_unknown() {
    let snapshot = MemoryResidencyAccountingSnapshot::unavailable(7);
    assert_eq!(snapshot.status, MemoryResidencyAccountingStatus::Unknown);
    assert_eq!(snapshot.selected_tier, MemoryResidencyTier::Fallback);
    assert!(!snapshot.policy_enabled);
    assert!(!snapshot.continuous_accounting_loop);
    assert!(
        snapshot
            .reason_codes
            .contains(&MemoryResidencyReasonCode::RuntimePressureUnknown)
    );
    assert!(
        snapshot
            .aggregation_rows
            .iter()
            .all(|row| row.status == MemoryResidencyAccountingStatus::Unknown)
    );
}

#[test]
fn stale_topology_snapshot_fails_closed_stale() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = cache_snapshot();
    let input = base_input(&locality, &cache).with_locality_report(&locality, 9_999);
    let snapshot = MemoryResidencyAccountingSnapshot::from_policy_input(
        &MemoryResidencyPolicy::experimental_opt_in(),
        &input,
        42,
        Some(counters()),
    );

    assert_eq!(snapshot.status, MemoryResidencyAccountingStatus::Stale);
    assert_eq!(snapshot.selected_tier, MemoryResidencyTier::Fallback);
    assert!(
        snapshot
            .reason_codes
            .contains(&MemoryResidencyReasonCode::StaleTopology)
    );
}

#[test]
fn missing_record_pool_counters_fail_closed_unknown() {
    let locality = locality_report(&skewed_access_model(), 6500);
    let cache = cache_snapshot();
    let input = base_input(&locality, &cache);
    let snapshot = MemoryResidencyAccountingSnapshot::from_policy_input(
        &MemoryResidencyPolicy::experimental_opt_in(),
        &input,
        42,
        None,
    );

    assert_eq!(snapshot.status, MemoryResidencyAccountingStatus::Unknown);
    assert!(!snapshot.record_pool_counters_available);
    for kind in [
        MemoryResidencyAggregationKind::TaskRecords,
        MemoryResidencyAggregationKind::RegionRecords,
        MemoryResidencyAggregationKind::ObligationRecords,
    ] {
        let row = snapshot
            .aggregation_rows
            .iter()
            .find(|row| row.kind == kind)
            .expect("counter row");
        assert_eq!(row.status, MemoryResidencyAccountingStatus::Unknown);
    }
}

#[test]
fn debug_server_endpoint_is_additive_and_schema_versioned() {
    let snapshot_fn: SnapshotFn = Arc::new(test_runtime_snapshot);
    let mut server = DebugServer::with_config(
        0,
        snapshot_fn,
        DebugServerConfig {
            print_url: false,
            ..Default::default()
        },
    );
    server.start().expect("debug server starts");

    let runtime_response = get_debug_response(&server, "/debug/snapshot");
    assert!(runtime_response.contains("200 OK"));
    assert!(runtime_response.contains("\"timestamp\": 123"));

    let residency_response =
        get_debug_response(&server, MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT);
    assert!(residency_response.contains("200 OK"));
    assert!(residency_response.contains(MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION));
    assert!(residency_response.contains("\"status\": \"unknown\""));
    assert!(residency_response.contains("\"continuous_accounting_loop\": false"));

    server.stop();
}
