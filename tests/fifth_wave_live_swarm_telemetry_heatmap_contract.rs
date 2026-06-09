#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION, SwarmContentionHeatmapInput,
    SwarmContentionHeatmapLedger, SwarmContentionHeatmapVerdict, SwarmContentionLockMetric,
    SwarmContentionSchedulerLaneMetric, SwarmContentionSeverity, SwarmReplayAdmissionDecision,
    SwarmReplayScenario, build_swarm_contention_heatmap, render_swarm_contention_heatmap_text,
    run_swarm_replay_scenario, summarize_swarm_replay_trace,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/fifth_wave_live_swarm_telemetry_heatmap_v1.json";
const ATLAS_PATH: &str = "artifacts/fifth_wave_swarm_control_plane_atlas_v1.json";
const BEAD_ID: &str = "asupersync-live-swarm-telemetry-heatmap-wt9b4r";
const LANE_ID: &str = "fifth-wave-live-swarm-telemetry-heatmap";
const PROOF_COMMAND_ID: &str = "fifth-wave-live-swarm-telemetry-heatmap-contract";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_fifth_wave_live_swarm_telemetry_heatmap";
const TEST_PATH: &str = "tests/fifth_wave_live_swarm_telemetry_heatmap_contract.rs";

const REQUIRED_LEDGER_FIELDS: &[&str] = &[
    "schema_version",
    "ledger_id",
    "scenario_id",
    "baseline_id",
    "stale_baseline",
    "verdict",
    "max_severity",
    "required_fields_present",
    "missing_required_fields",
    "source_trace_ids",
    "proof_command",
    "lock_hotspots",
    "scheduler_lane_hotspots",
    "region_hotspots",
    "queue_hotspots",
    "top_hotspots",
    "routing_hints",
];

const REQUIRED_HOTSPOT_FIELDS: &[&str] = &[
    "key",
    "kind",
    "severity",
    "impact_score",
    "p50_wait_ns",
    "p95_wait_ns",
    "p99_wait_ns",
    "queue_depth_p95",
    "queue_depth_p99",
    "contentions",
    "region_or_scope",
    "evidence",
    "owner_surface",
    "owner_bead_hint",
];

const REQUIRED_NON_CLAIMS: &[&str] = &[
    "does not prove live RCH fleet availability",
    "does not implement a production dashboard",
    "does not prove broad observability correctness",
    "does not prove broad workspace health",
    "does not prove performance improvement",
    "does not prove no regression",
    "does not authorize local Cargo fallback",
    "does not create branches, worktrees, scratch clones, or non-main refs",
    "does not modify runtime scheduler policy",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn artifact() -> Value {
    read_json(ARTIFACT_PATH)
}

fn atlas() -> Value {
    read_json(ATLAS_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, key)
        .iter()
        .map(|row| (string(row, id_key).to_string(), row))
        .collect()
}

fn serde_text<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("serialize enum")
        .as_str()
        .expect("serialized enum should be a string")
        .to_string()
}

fn proof_command() -> String {
    format!(
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR={TARGET_DIR} CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test fifth_wave_live_swarm_telemetry_heatmap_contract -- --nocapture"
    )
}

fn assert_remote_required_cargo_command(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "proof command must route Cargo through RCH: {command}"
    );
    for required in [
        TARGET_DIR,
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "--test fifth_wave_live_swarm_telemetry_heatmap_contract",
        "-- --nocapture",
    ] {
        assert!(
            command.contains(required),
            "proof command missing {required}: {command}"
        );
    }
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "local fallback",
        "executing locally",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

fn scenario(
    scenario_id: &str,
    task_count: usize,
    cancel_after_steps: Option<u64>,
) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: scenario_id.to_string(),
        seed: 0x5A11_0000 ^ task_count as u64,
        worker_count: 3,
        cohort_count: 1,
        region_count: 1,
        tasks_per_region: task_count,
        yields_per_task: 2,
        yield_jitter: 1,
        channel_capacity: 16,
        messages_per_task: 1,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 1,
        timer_ticks_per_task: 1,
        cancellation_tree_depth: 2,
        artifact_bytes_per_task: 64,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps,
        max_steps: 10_000,
    }
}

fn trace_summary(
    scenario_id: &str,
    task_count: usize,
    cancel_after_steps: Option<u64>,
) -> asupersync::lab::SwarmPressureTraceSummary {
    let replay = run_swarm_replay_scenario(&scenario(scenario_id, task_count, cancel_after_steps))
        .expect("swarm replay scenario should run");
    summarize_swarm_replay_trace(&replay)
}

fn lock_metric(name: &str, p95_wait_ns: u64, p99_wait_ns: u64) -> SwarmContentionLockMetric {
    SwarmContentionLockMetric {
        name: name.to_string(),
        acquisitions: 64,
        contentions: if p95_wait_ns >= 100_000 { 12 } else { 0 },
        wait_ns: p95_wait_ns.saturating_mul(64),
        hold_ns: 8_000,
        max_wait_ns: p99_wait_ns,
        max_hold_ns: 5_000,
        p50_wait_ns: p95_wait_ns / 4,
        p95_wait_ns,
        p99_wait_ns,
        p95_hold_ns: 2_000,
        p99_hold_ns: 5_000,
        instrumentation_mode: "fifth_wave_fixture".to_string(),
    }
}

fn lane_metric(
    lane_id: &str,
    p95_wait_ns: u64,
    p99_wait_ns: u64,
    queue_depth_p95: u64,
    queue_depth_p99: u64,
) -> SwarmContentionSchedulerLaneMetric {
    SwarmContentionSchedulerLaneMetric {
        lane_id: lane_id.to_string(),
        dispatched_tasks: 128,
        p50_wait_ns: p95_wait_ns / 4,
        p95_wait_ns,
        p99_wait_ns,
        queue_depth_p50: queue_depth_p95 / 4,
        queue_depth_p95,
        queue_depth_p99,
        steal_attempts: 2,
        fairness_yields: if queue_depth_p99 >= 64 { 3 } else { 0 },
    }
}

fn heatmap_input(fixture_id: &str) -> SwarmContentionHeatmapInput {
    match fixture_id {
        "quiet-baseline" => SwarmContentionHeatmapInput {
            ledger_id: "quiet-baseline-ledger".to_string(),
            baseline_id: Some("main-baseline-2026-06-09".to_string()),
            baseline_age_secs: 60,
            max_baseline_age_secs: 86_400,
            trace_summary: Some(trace_summary("heatmap-quiet-baseline", 1, None)),
            lock_metrics: vec![lock_metric("runtime_state", 8_000, 16_000)],
            scheduler_lanes: vec![lane_metric("ready", 8_000, 16_000, 1, 2)],
            source_trace_ids: vec!["trace-heatmap-quiet".to_string()],
            proof_command: Some(proof_command()),
        },
        "saturated-scheduler-lane" => SwarmContentionHeatmapInput {
            ledger_id: "saturated-scheduler-ledger".to_string(),
            baseline_id: Some("main-baseline-2026-06-09".to_string()),
            baseline_age_secs: 60,
            max_baseline_age_secs: 86_400,
            trace_summary: Some(trace_summary("heatmap-saturated-scheduler", 8, None)),
            lock_metrics: vec![
                lock_metric("runtime_state", 500_000, 1_000_000),
                lock_metric("obligation_table", 120_000, 300_000),
            ],
            scheduler_lanes: vec![
                lane_metric("ready", 200_000, 350_000, 96, 192),
                lane_metric("cancel-drain", 25_000, 50_000, 8, 16),
            ],
            source_trace_ids: vec!["trace-heatmap-saturated".to_string()],
            proof_command: Some(proof_command()),
        },
        "cancellation-storm-drain" => SwarmContentionHeatmapInput {
            ledger_id: "cancellation-storm-ledger".to_string(),
            baseline_id: Some("main-baseline-2026-06-09".to_string()),
            baseline_age_secs: 60,
            max_baseline_age_secs: 86_400,
            trace_summary: Some(trace_summary("heatmap-cancellation-storm", 8, Some(1))),
            lock_metrics: vec![lock_metric("cancel_registry", 120_000, 300_000)],
            scheduler_lanes: vec![lane_metric("cancel-drain", 100_000, 250_000, 32, 64)],
            source_trace_ids: vec!["trace-heatmap-cancel-storm".to_string()],
            proof_command: Some(proof_command()),
        },
        "proof-stalled-stale-baseline" => SwarmContentionHeatmapInput {
            ledger_id: "stale-baseline-ledger".to_string(),
            baseline_id: Some("main-baseline-2026-06-01".to_string()),
            baseline_age_secs: 172_800,
            max_baseline_age_secs: 86_400,
            trace_summary: Some(trace_summary("heatmap-stale-baseline", 1, None)),
            lock_metrics: vec![lock_metric("runtime_state", 8_000, 16_000)],
            scheduler_lanes: vec![lane_metric("ready", 8_000, 16_000, 1, 2)],
            source_trace_ids: vec!["trace-heatmap-stale".to_string()],
            proof_command: Some(proof_command()),
        },
        other => panic!("unknown fixture {other}"),
    }
}

fn build_fixture(fixture_id: &str) -> SwarmContentionHeatmapLedger {
    build_swarm_contention_heatmap(&heatmap_input(fixture_id))
}

fn assert_no_forbidden_tokens(value: &str, forbidden_tokens: &BTreeSet<String>) {
    let normalized = value.to_ascii_lowercase();
    for token in forbidden_tokens {
        assert!(
            !normalized.contains(&token.to_ascii_lowercase()),
            "unredacted token {token} found in {value}"
        );
    }
}

#[test]
fn artifact_declares_sources_atlas_alignment_and_remote_proof_lane() {
    let artifact = artifact();
    assert_eq!(
        string(&artifact, "schema_version"),
        "fifth-wave-live-swarm-telemetry-heatmap-v1"
    );
    assert_eq!(string(&artifact, "bead_id"), BEAD_ID);

    let source = object(&artifact, "source_of_truth");
    for (key, expected) in [
        ("atlas_artifact", ATLAS_PATH),
        (
            "operator_cockpit_contract",
            "artifacts/swarm_operator_cockpit_report_contract_v1.json",
        ),
        (
            "rch_freshness_broker",
            "artifacts/fifth_wave_rch_proof_freshness_broker_v1.json",
        ),
        ("runtime_heatmap_source", "src/lab/swarm_replay.rs"),
        ("contract_test", TEST_PATH),
        ("agent_instructions", "AGENTS.md"),
        ("readme", "README.md"),
    ] {
        assert_eq!(
            source
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("source_of_truth.{key}")),
            expected
        );
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path must exist: {expected}"
        );
    }

    let lane = &artifact["proof_lane"];
    assert_eq!(string(lane, "lane_id"), LANE_ID);
    assert_eq!(string(lane, "owner_bead"), BEAD_ID);
    assert_eq!(string(lane, "proof_command_id"), PROOF_COMMAND_ID);
    assert_eq!(string(lane, "target_dir"), TARGET_DIR);
    assert!(bool_field(lane, "remote_required"));
    assert!(!bool_field(lane, "local_fallback_allowed"));
    assert_remote_required_cargo_command(string(lane, "proof_command"));

    let atlas = atlas();
    let atlas_lanes = rows_by_id(&atlas, "child_lanes", "owner_bead");
    let atlas_lane = atlas_lanes.get(BEAD_ID).expect("atlas heatmap child lane");
    assert_eq!(string(atlas_lane, "lane_id"), string(lane, "lane_id"));
    assert_eq!(
        string(atlas_lane, "proof_command_id"),
        string(lane, "proof_command_id")
    );
    assert_eq!(
        string(atlas_lane, "proof_command"),
        string(lane, "proof_command")
    );
}

#[test]
fn snapshot_schema_matches_live_heatmap_builder_fields() {
    let artifact = artifact();
    let schema = &artifact["snapshot_schema"];
    assert_eq!(
        string(schema, "runtime_schema_version"),
        SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(u64_field(schema, "max_top_hotspots"), 8);
    assert_eq!(u64_field(schema, "agent_mail_text_max_bytes"), 2500);

    let required_fields = string_set(schema, "required_heatmap_fields");
    for field in REQUIRED_LEDGER_FIELDS {
        assert!(required_fields.contains(*field), "missing field {field}");
    }

    let ledger = build_fixture("saturated-scheduler-lane");
    let ledger_json = serde_json::to_value(&ledger).expect("serialize ledger");
    let ledger_object = ledger_json.as_object().expect("ledger object");
    for field in REQUIRED_LEDGER_FIELDS {
        assert!(
            ledger_object.contains_key(*field),
            "live ledger missing required artifact field {field}"
        );
    }

    let hotspot_fields = string_set(schema, "required_hotspot_fields");
    for field in REQUIRED_HOTSPOT_FIELDS {
        assert!(
            hotspot_fields.contains(*field),
            "missing hotspot field {field}"
        );
    }
    let first_hotspot = serde_json::to_value(
        ledger
            .top_hotspots
            .first()
            .expect("saturated fixture should rank hotspots"),
    )
    .expect("serialize hotspot");
    let hotspot_object = first_hotspot.as_object().expect("hotspot object");
    for field in REQUIRED_HOTSPOT_FIELDS {
        assert!(
            hotspot_object.contains_key(*field),
            "live hotspot missing required artifact field {field}"
        );
    }

    let verdicts = string_set(schema, "verdicts");
    for verdict in [
        SwarmContentionHeatmapVerdict::Pass,
        SwarmContentionHeatmapVerdict::Degraded,
        SwarmContentionHeatmapVerdict::Incomplete,
        SwarmContentionHeatmapVerdict::StaleEvidence,
    ] {
        assert!(
            verdicts.contains(&serde_text(verdict)),
            "artifact missing verdict {verdict:?}"
        );
    }

    let severities = string_set(schema, "severities");
    for severity in [
        SwarmContentionSeverity::Nominal,
        SwarmContentionSeverity::Watch,
        SwarmContentionSeverity::Warning,
        SwarmContentionSeverity::Critical,
    ] {
        assert!(
            severities.contains(&serde_text(severity)),
            "artifact missing severity {severity:?}"
        );
    }
}

#[test]
fn fixture_catalog_exercises_pass_degraded_cancellation_and_stale_mapping() {
    let artifact = artifact();
    let fixtures = rows_by_id(&artifact, "fixture_catalog", "fixture_id");
    let forbidden_tokens = string_set(&artifact["redaction_boundary"], "forbidden_tokens");
    for fixture_id in [
        "quiet-baseline",
        "saturated-scheduler-lane",
        "cancellation-storm-drain",
        "proof-stalled-stale-baseline",
    ] {
        let row = fixtures
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing fixture {fixture_id}"));
        assert_eq!(
            string(row, "requires_redaction_policy"),
            "agent-mail-safe-redaction-v1"
        );

        let ledger = build_fixture(fixture_id);
        let rendered = render_swarm_contention_heatmap_text(&ledger);
        let expected_verdict = string(row, "expected_verdict");
        assert_eq!(serde_text(ledger.verdict), expected_verdict);
        assert!(
            ledger.top_hotspots.len() <= u64_field(row, "max_top_hotspots") as usize,
            "{fixture_id} exceeded hotspot cap"
        );
        assert!(
            ledger.source_trace_ids.len() >= u64_field(row, "minimum_source_trace_ids") as usize,
            "{fixture_id} missing source trace ids"
        );
        assert!(
            rendered.len()
                <= u64_field(&artifact["snapshot_schema"], "agent_mail_text_max_bytes") as usize,
            "{fixture_id} rendered text too large: {}",
            rendered.len()
        );
        assert!(rendered.contains("Swarm Contention Heatmap Ledger"));
        assert!(rendered.contains("top_hotspots:"));
        assert_no_forbidden_tokens(&rendered, &forbidden_tokens);
        for hint in &ledger.routing_hints {
            assert_no_forbidden_tokens(hint, &forbidden_tokens);
        }

        if let Some(expected) = row.get("expected_max_severity").and_then(Value::as_str) {
            assert_eq!(serde_text(ledger.max_severity), expected);
        }
        if let Some(expected) = row
            .get("expected_max_severity_at_least")
            .and_then(Value::as_str)
        {
            let expected_rank = match expected {
                "nominal" => SwarmContentionSeverity::Nominal,
                "watch" => SwarmContentionSeverity::Watch,
                "warning" => SwarmContentionSeverity::Warning,
                "critical" => SwarmContentionSeverity::Critical,
                other => panic!("unknown expected severity {other}"),
            };
            assert!(
                ledger.max_severity >= expected_rank,
                "{fixture_id} severity {:?} below {expected_rank:?}",
                ledger.max_severity
            );
        }
        if let Some(expected) = row.get("expected_stale_baseline").and_then(Value::as_bool) {
            assert_eq!(ledger.stale_baseline, expected);
        }
    }
}

#[test]
fn failure_fixtures_and_non_claims_fail_closed() {
    let artifact = artifact();
    let failure_fixtures = rows_by_id(&artifact, "failure_fixtures", "case_id");
    for case_id in [
        "missing-trace-summary",
        "missing-lock-metrics",
        "missing-scheduler-lanes",
        "local-fallback-authorized",
        "unredacted-operator-token",
        "broad-dashboard-claim",
    ] {
        assert!(
            failure_fixtures.contains_key(case_id),
            "missing failure fixture {case_id}"
        );
    }

    let mut missing_trace = heatmap_input("quiet-baseline");
    missing_trace.trace_summary = None;
    let missing_trace_ledger = build_swarm_contention_heatmap(&missing_trace);
    assert_eq!(
        missing_trace_ledger.verdict,
        SwarmContentionHeatmapVerdict::Incomplete
    );
    assert!(
        missing_trace_ledger
            .missing_required_fields
            .contains(&"trace_summary".to_string())
    );

    let mut missing_locks = heatmap_input("quiet-baseline");
    missing_locks.lock_metrics.clear();
    let missing_locks_ledger = build_swarm_contention_heatmap(&missing_locks);
    assert_eq!(
        missing_locks_ledger.verdict,
        SwarmContentionHeatmapVerdict::Incomplete
    );
    assert!(
        missing_locks_ledger
            .missing_required_fields
            .contains(&"lock_metrics".to_string())
    );

    let mut missing_lanes = heatmap_input("quiet-baseline");
    missing_lanes.scheduler_lanes.clear();
    let missing_lanes_ledger = build_swarm_contention_heatmap(&missing_lanes);
    assert_eq!(
        missing_lanes_ledger.verdict,
        SwarmContentionHeatmapVerdict::Incomplete
    );
    assert!(
        missing_lanes_ledger
            .missing_required_fields
            .contains(&"scheduler_lanes".to_string())
    );

    assert!(bool_field(&artifact["proof_lane"], "remote_required"));
    assert!(!bool_field(
        &artifact["proof_lane"],
        "local_fallback_allowed"
    ));
    assert_remote_required_cargo_command(string(&artifact["proof_lane"], "proof_command"));

    let non_claims = string_set(&artifact, "non_claims");
    for required in REQUIRED_NON_CLAIMS {
        assert!(
            non_claims.contains(*required),
            "missing non-claim {required}"
        );
    }
    for claim in string_set(&artifact["proof_lane"], "does_not_cover") {
        assert!(
            claim.to_ascii_lowercase().starts_with("does not "),
            "proof lane no-claim must be explicit: {claim}"
        );
    }

    assert!(!bool_field(
        &artifact["redaction_boundary"],
        "destructive_cleanup_required"
    ));
    assert!(!bool_field(
        &artifact["redaction_boundary"],
        "branch_or_worktree_required"
    ));
    for requirement in array(&artifact, "closeout_requirements") {
        let text = requirement
            .as_str()
            .expect("closeout_requirements entries must be strings");
        assert!(!text.trim().is_empty(), "closeout requirement is empty");
    }
}
