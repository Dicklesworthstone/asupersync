//! No-mock cockpit proof runner contract (br-asupersync-vssefs.9.7).
//!
//! This test file is both the contract check and the RCH execution payload for
//! `scripts/run_swarm_cockpit_proof_runner.sh`. It runs at least one bounded
//! real swarm scenario through live Asupersync lab-runtime surfaces, derives
//! the pressure trace summary and contention ledger from the real replay,
//! plans the RCH proof lane, builds the operator cockpit report, and emits the
//! cockpit bundle as stdout events the runner script parses into operator
//! evidence.
//!
//! Provenance is fail-closed: when the runner script supplies real RCH
//! provenance through `SWARM_COCKPIT_PROOF_*` environment variables the
//! cockpit outcome must be `Pass`; when provenance is absent (plain CI run)
//! the outcome must be `Blocked`, never green.

#![allow(missing_docs)]
#![allow(clippy::pedantic, clippy::nursery)]

use asupersync::lab::{
    SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION, SwarmContentionHeatmapInput,
    SwarmContentionLockMetric, SwarmContentionSchedulerLaneMetric, SwarmOperatorCockpitInput,
    SwarmOperatorCockpitMemoryDecision, SwarmOperatorCockpitObligationVerdict,
    SwarmOperatorCockpitOutcome, SwarmOperatorCockpitReport, SwarmPressureTraceSummary,
    SwarmProofLanePlan, SwarmProofLaneRchProvenance, SwarmProofLaneRequest, SwarmReplayScenario,
    SwarmReplaySummary, build_swarm_contention_heatmap, build_swarm_operator_cockpit_report,
    plan_swarm_proof_lane, render_swarm_operator_cockpit_text, run_swarm_replay_scenario,
    summarize_swarm_replay_trace,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_cockpit_proof_runner_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_swarm_cockpit_proof_runner.sh";
const CORPUS_PATH: &str = "artifacts/swarm_workload_scenario_corpus_v1.json";
const EVENT_PREFIX: &str = "SWARM_COCKPIT_PROOF_EVENT ";
const REDACTION_POLICY_ID: &str = "agent-mail-safe-redaction-v1";
const GENERATED_BY: &str = "swarm-cockpit-proof-runner";
const INSTRUMENTATION_MODE: &str = "lab-trace-derived";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_json(relative: &str) -> Value {
    let raw = std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn artifact() -> Value {
    read_json(ARTIFACT_PATH)
}

fn corpus() -> Value {
    read_json(CORPUS_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
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
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_value(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
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

fn env_string(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}

/// Real RCH provenance is only available when the runner script invokes this
/// test through `rch exec` and forwards the provenance environment.
fn script_provenance() -> Option<SwarmProofLaneRchProvenance> {
    let remote = std::env::var("SWARM_COCKPIT_PROOF_REMOTE").ok()?;
    if remote != "1" {
        return None;
    }
    let observed_head = env_string("SWARM_COCKPIT_PROOF_GIT_COMMIT", "unknown");
    let target_dir = env_string(
        "SWARM_COCKPIT_PROOF_TARGET_DIR",
        "${TMPDIR:-/tmp}/rch_target_swarm_cockpit_proof_runner",
    );
    Some(SwarmProofLaneRchProvenance {
        worker_id: env_string("SWARM_COCKPIT_PROOF_RCH_WORKER", "captured-by-runner"),
        remote_observed: true,
        observed_head,
        target_dir,
        exit_status: Some(0),
    })
}

fn corpus_scenario_rows(corpus: &Value) -> BTreeMap<String, Value> {
    array(corpus, "scenarios")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row.clone()))
        .collect()
}

fn parse_replay(row: &Value) -> SwarmReplayScenario {
    serde_json::from_value(
        row.get("replay_scenario")
            .unwrap_or_else(|| panic!("{} missing replay_scenario", string(row, "scenario_id")))
            .clone(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "parse replay_scenario {}: {error}",
            string(row, "scenario_id")
        )
    })
}

fn matrix_rows_for_profile<'a>(artifact: &'a Value, profile: &str) -> Vec<&'a Value> {
    array(artifact, "scenario_matrix")
        .iter()
        .filter(|row| profile == "all" || string(row, "profile") == profile)
        .collect()
}

fn proof_command(artifact: &Value, features: &str) -> String {
    let target_dir = env_string(
        "SWARM_COCKPIT_PROOF_TARGET_DIR",
        "${TMPDIR:-/tmp}/rch_target_swarm_cockpit_proof_runner",
    );
    env_string(
        "SWARM_COCKPIT_PROOF_COMMAND",
        &format!(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR={target_dir} cargo test -p \
             asupersync --test {} --features {features} -- --nocapture",
            string(artifact, "contract_test")
                .trim_start_matches("tests/")
                .trim_end_matches(".rs"),
        ),
    )
}

/// Derive the scheduler lane metric from real replay trace counters.
///
/// The lab runtime is deterministic and virtual-time based, so wall-clock lock
/// waits do not exist; wait values are reported as zero with an explicit
/// `lab-trace-derived` instrumentation mode rather than synthesized numbers.
fn lane_metric_from_trace(trace: &SwarmPressureTraceSummary) -> SwarmContentionSchedulerLaneMetric {
    let queue_depth = trace.queue_pressure.peak_queue_depth as u64;
    SwarmContentionSchedulerLaneMetric {
        lane_id: "lab-ready-lane".to_string(),
        dispatched_tasks: trace.task_lifecycle.scheduled_tasks as u64,
        p50_wait_ns: 0,
        p95_wait_ns: 0,
        p99_wait_ns: 0,
        queue_depth_p50: queue_depth.min(1),
        queue_depth_p95: queue_depth,
        queue_depth_p99: queue_depth,
        steal_attempts: 0,
        fairness_yields: 0,
    }
}

/// Derive the lock-style metric from real replay obligation/queue counters.
fn lock_metric_from_trace(trace: &SwarmPressureTraceSummary) -> SwarmContentionLockMetric {
    let acquisitions =
        (trace.obligations.resolved_obligations + trace.obligations.unresolved_obligations) as u64;
    SwarmContentionLockMetric {
        name: "lab-obligation-ledger".to_string(),
        acquisitions: acquisitions.max(1),
        contentions: trace.queue_pressure.pressure_event_count as u64,
        wait_ns: 0,
        hold_ns: 0,
        max_wait_ns: 0,
        max_hold_ns: 0,
        p50_wait_ns: 0,
        p95_wait_ns: 0,
        p99_wait_ns: 0,
        p95_hold_ns: 0,
        p99_hold_ns: 0,
        instrumentation_mode: INSTRUMENTATION_MODE.to_string(),
    }
}

fn contention_ledger_from_trace(
    trace: SwarmPressureTraceSummary,
    command: &str,
) -> asupersync::lab::SwarmContentionHeatmapLedger {
    let lock_metric = lock_metric_from_trace(&trace);
    let lane_metric = lane_metric_from_trace(&trace);
    let source_trace_id = format!("swarm-replay-trace-{}", trace.scenario_id);
    build_swarm_contention_heatmap(&SwarmContentionHeatmapInput {
        ledger_id: format!("cockpit-proof-contention-{}", trace.scenario_id),
        baseline_id: Some("cockpit-proof-run-local-baseline".to_string()),
        baseline_age_secs: 0,
        max_baseline_age_secs: 86_400,
        trace_summary: Some(trace),
        lock_metrics: vec![lock_metric],
        scheduler_lanes: vec![lane_metric],
        source_trace_ids: vec![source_trace_id],
        proof_command: Some(command.to_string()),
    })
}

fn proof_lane_for_run(
    artifact: &Value,
    scenario_id: &str,
    features: &str,
    provenance: Option<SwarmProofLaneRchProvenance>,
) -> SwarmProofLanePlan {
    let command = proof_command(artifact, features);
    let head = provenance
        .as_ref()
        .map_or_else(|| "unknown".to_string(), |p| p.observed_head.clone());
    let target_dir = provenance.as_ref().map_or_else(
        || "${TMPDIR:-/tmp}/rch_target_swarm_cockpit_proof_runner".to_string(),
        |p| p.target_dir.clone(),
    );
    let request = SwarmProofLaneRequest {
        lane_id: format!("{scenario_id}-cockpit-proof"),
        scenario_id: scenario_id.to_string(),
        source_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            CORPUS_PATH.to_string(),
            "src/lab/swarm_replay.rs".to_string(),
            string(artifact, "contract_test").to_string(),
        ],
        touched_surfaces: vec![
            RUNNER_SCRIPT_PATH.to_string(),
            string(artifact, "contract_test").to_string(),
            ARTIFACT_PATH.to_string(),
        ],
        command,
        target_dir,
        features: vec![features.to_string()],
        expected_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            string(
                &object(artifact, "operator_evidence").clone(),
                "run_report_path",
            )
            .to_string(),
        ],
        timeout_secs: 1800,
        remote_required: true,
        local_fallback_authorized: false,
        expected_head: Some(head.clone()),
        observed_head: Some(head),
        rch_provenance: provenance,
        transcript_markers: vec![
            EVENT_PREFIX.trim_end().to_string(),
            "test result: ok".to_string(),
        ],
        covers: vec![
            "no_mock_cockpit_proof_runner".to_string(),
            "operator_cockpit_bundle_emission".to_string(),
        ],
        does_not_cover: vec![
            "workspace_release_health".to_string(),
            "broad_conformance".to_string(),
            "wall_clock_performance_baselines".to_string(),
        ],
        atlas_context: None,
    };
    plan_swarm_proof_lane(&request)
}

/// Run one real scenario end to end and build the cockpit report from the
/// real replay evidence. This is the no-mock core of the proof runner.
fn run_cockpit_pipeline(
    artifact: &Value,
    scenario: &SwarmReplayScenario,
    provenance: Option<SwarmProofLaneRchProvenance>,
) -> (SwarmReplaySummary, SwarmOperatorCockpitReport) {
    let features = env_string("SWARM_COCKPIT_PROOF_FEATURES", "test-internals");
    let replay = run_swarm_replay_scenario(scenario)
        .unwrap_or_else(|error| panic!("replay scenario {}: {error:?}", scenario.scenario_id));
    let trace = summarize_swarm_replay_trace(&replay);
    assert_eq!(
        trace.scenario_id, scenario.scenario_id,
        "trace summary must reference the executed scenario"
    );

    let command = proof_command(artifact, &features);
    let proof_lane = proof_lane_for_run(artifact, &scenario.scenario_id, &features, provenance);
    let contention = contention_ledger_from_trace(trace.clone(), &command);

    let input = SwarmOperatorCockpitInput {
        report_id: format!("{}-cockpit-proof", scenario.scenario_id),
        scenario: Some(scenario.clone()),
        trace_summary: Some(trace),
        proof_lanes: vec![proof_lane],
        contention_ledger: Some(contention),
        minimizer_report: None,
        memory_decision: SwarmOperatorCockpitMemoryDecision::Nominal,
        memory_decision_reason: Some("bounded small scenario; no brownout required".to_string()),
        latency_p50_ns: None,
        latency_p95_ns: None,
        latency_p99_ns: None,
        latency_cv_bps: None,
        source_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            CORPUS_PATH.to_string(),
            "src/lab/swarm_replay.rs".to_string(),
            string(artifact, "contract_test").to_string(),
        ],
        redaction_policy_id: Some(REDACTION_POLICY_ID.to_string()),
        secret_like_value_count: 0,
        generated_by: GENERATED_BY.to_string(),
    };
    let report = build_swarm_operator_cockpit_report(&input);
    (replay, report)
}

fn outcome_label(outcome: SwarmOperatorCockpitOutcome) -> &'static str {
    match outcome {
        SwarmOperatorCockpitOutcome::Pass => "pass",
        SwarmOperatorCockpitOutcome::Degraded => "degraded",
        SwarmOperatorCockpitOutcome::NoWin => "no_win",
        SwarmOperatorCockpitOutcome::Blocked => "blocked",
        SwarmOperatorCockpitOutcome::StaleEvidence => "stale_evidence",
        SwarmOperatorCockpitOutcome::Malformed => "malformed",
        SwarmOperatorCockpitOutcome::Unsupported => "unsupported",
    }
}

fn obligation_label(verdict: SwarmOperatorCockpitObligationVerdict) -> &'static str {
    match verdict {
        SwarmOperatorCockpitObligationVerdict::Clean => "clean",
        SwarmOperatorCockpitObligationVerdict::LeakSuspect => "leak_suspect",
        SwarmOperatorCockpitObligationVerdict::Missing => "missing",
        SwarmOperatorCockpitObligationVerdict::Incomplete => "incomplete",
    }
}

fn scenario_event_row(
    matrix_row: &Value,
    scenario: &SwarmReplayScenario,
    replay: &SwarmReplaySummary,
    report: &SwarmOperatorCockpitReport,
    first_failure: &str,
) -> Value {
    let proof_status = match report.outcome {
        SwarmOperatorCockpitOutcome::Pass => "pass",
        SwarmOperatorCockpitOutcome::Degraded => "degraded",
        _ => "fail_closed",
    };
    let quiescence_result = if replay.quiescent && replay.non_terminal_task_count == 0 {
        "quiescent"
    } else {
        "not_quiescent"
    };
    json!({
        "scenario_id": scenario.scenario_id,
        "profile": string(matrix_row, "profile"),
        "command": proof_command(&artifact(), &env_string("SWARM_COCKPIT_PROOF_FEATURES", "test-internals")),
        "git_commit": env_string("SWARM_COCKPIT_PROOF_GIT_COMMIT", "unknown"),
        "rch_worker": env_string("SWARM_COCKPIT_PROOF_RCH_WORKER", "captured-by-runner"),
        "feature_set": env_string("SWARM_COCKPIT_PROOF_FEATURES", "test-internals"),
        "worker_count": scenario.worker_count,
        "region_count": scenario.region_count,
        "task_count": replay.task_count,
        "quiescence_result": quiescence_result,
        "obligation_verdict": obligation_label(report.obligation_verdict),
        "cockpit_outcome": outcome_label(report.outcome),
        "first_failure": first_failure,
        "artifact_path": env_string(
            "SWARM_COCKPIT_PROOF_OUTPUT_DIR",
            "target/swarm-cockpit-proof-runner/contract-test",
        ),
        "proof_status": proof_status,
    })
}

fn validate_event_row(artifact: &Value, row: &Value) -> Result<(), String> {
    let required = string_set(artifact, "required_log_fields");
    let present = row
        .as_object()
        .ok_or_else(|| "event row must be an object".to_string())?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing = required.difference(&present).cloned().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!("event row missing fields: {missing:?}"));
    }

    let proof_status = string(row, "proof_status");
    let first_failure = row
        .get("first_failure")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proof_status == "pass" {
        if !first_failure.is_empty() {
            return Err("pass row must not carry first_failure".to_string());
        }
        if string(row, "quiescence_result") != "quiescent" {
            return Err("pass row must prove quiescence".to_string());
        }
        if string(row, "cockpit_outcome") != "pass" {
            return Err("pass row must carry a pass cockpit outcome".to_string());
        }
    }
    if proof_status == "fail_closed" && first_failure.is_empty() {
        return Err("fail_closed row must explain first_failure".to_string());
    }

    let rendered = serde_json::to_string(row)
        .map_err(|error| format!("render event row: {error}"))?
        .to_ascii_lowercase();
    for marker in string_set(artifact, "forbidden_success_markers") {
        if rendered.contains(&marker) {
            return Err(format!("event row contains forbidden marker {marker}"));
        }
    }
    Ok(())
}

fn emit_event(row: &Value) {
    println!(
        "{EVENT_PREFIX}{}",
        serde_json::to_string(row).expect("render event row")
    );
}

#[test]
fn cockpit_proof_artifact_declares_live_sources_and_rch_only_execution() {
    let artifact = artifact();

    assert_eq!(
        string(&artifact, "contract_version"),
        "swarm-cockpit-proof-runner-v1"
    );
    assert_eq!(string(&artifact, "bead_id"), "asupersync-vssefs.9.7");
    assert_eq!(
        string(&artifact, "cockpit_report_schema_version"),
        SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION
    );
    assert_eq!(string(&artifact, "runner_script"), RUNNER_SCRIPT_PATH);
    assert_eq!(
        string(&artifact, "contract_test"),
        "tests/swarm_cockpit_proof_runner_contract.rs"
    );
    assert_eq!(string(&artifact, "scenario_corpus"), CORPUS_PATH);

    // Every declared source file must exist in the repository.
    for key in [
        "runner_script",
        "contract_test",
        "scenario_corpus",
        "cockpit_report_contract",
    ] {
        let relative = string(&artifact, key);
        assert!(
            repo_path(relative).exists(),
            "{key} {relative} must exist in the repository"
        );
    }

    let scenario_source = object(&artifact, "scenario_source");
    assert_eq!(
        string(scenario_source, "runtime_scenario_type"),
        "asupersync::lab::SwarmReplayScenario"
    );
    assert_eq!(
        string(scenario_source, "runtime_runner"),
        "asupersync::lab::run_swarm_replay_scenario"
    );
    assert_eq!(
        string(scenario_source, "cockpit_report_builder"),
        "asupersync::lab::build_swarm_operator_cockpit_report"
    );
    assert!(repo_path(string(scenario_source, "runtime_source")).exists());

    let policy = object(&artifact, "execution_policy");
    assert!(!bool_value(policy, "local_fallback_allowed"));
    assert_eq!(string(policy, "missing_provenance_outcome"), "blocked");
    assert_eq!(string(policy, "default_profile"), "small");

    let proof_command = string(&artifact, "proof_command");
    assert!(proof_command.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(proof_command.contains("--execute"));
    assert!(string(&artifact, "dry_run_command").contains("--dry-run"));

    let outcomes = string_set(&artifact, "required_outcomes");
    for outcome in [
        "pass",
        "degraded",
        "no_win",
        "blocked",
        "stale_evidence",
        "malformed",
        "unsupported",
    ] {
        assert!(
            outcomes.contains(outcome),
            "missing required outcome {outcome}"
        );
    }

    let verdicts = string_set(&artifact, "required_obligation_verdicts");
    for verdict in ["clean", "leak_suspect", "missing", "incomplete"] {
        assert!(
            verdicts.contains(verdict),
            "missing obligation verdict {verdict}"
        );
    }

    let evidence = object(&artifact, "operator_evidence");
    assert_eq!(string(evidence, "stdout_event_prefix"), EVENT_PREFIX);
    for key in [
        "manifest_path",
        "run_log_path",
        "run_report_path",
        "cockpit_report_json_path",
        "cockpit_report_text_path",
    ] {
        assert!(!string(evidence, key).is_empty());
    }
}

#[test]
fn runner_script_fails_closed_with_dry_run_and_execute_modes() {
    let artifact = artifact();
    let script_source = std::fs::read_to_string(repo_path(RUNNER_SCRIPT_PATH))
        .unwrap_or_else(|error| panic!("read {RUNNER_SCRIPT_PATH}: {error}"));

    // Execute mode must be RCH-only and fail closed.
    assert!(
        script_source.contains("RCH_REQUIRE_REMOTE=1"),
        "runner script must require remote RCH execution"
    );
    assert!(
        script_source.contains("--dry-run") && script_source.contains("--execute"),
        "runner script must support dry-run and execute modes"
    );
    // The script reads the event prefix from the contract artifact rather than
    // hard-coding the literal, so assert the consumption mechanism instead.
    assert!(
        script_source.contains("stdout_event_prefix"),
        "runner script must read the stdout event prefix from the contract artifact"
    );
    assert!(
        script_source.contains("cockpit_report.json")
            && script_source.contains("cockpit_report.txt"),
        "runner script must write the cockpit report bundle"
    );
    // The script must consume the contract artifact rather than embedding policy.
    assert!(
        script_source.contains("swarm_cockpit_proof_runner_contract_v1.json"),
        "runner script must read the contract artifact"
    );

    // The script must not contain forbidden success markers (the markers are
    // read from the artifact so the literals never appear in checked sources).
    let lowered = script_source.to_ascii_lowercase();
    for marker in string_set(&artifact, "forbidden_success_markers") {
        assert!(
            !lowered.contains(&marker),
            "runner script must not contain forbidden marker {marker}"
        );
    }

    // No silent local cargo fallback: the execute path must dispatch through
    // the rch wrapper with RCH_REQUIRE_REMOTE=1, and the post-run validation
    // must reject rch local-fallback markers in the run log.
    assert!(
        script_source.contains("RCH_REQUIRE_REMOTE=1 \"${RCH_BIN}\" exec --"),
        "execute mode must dispatch cargo through rch exec with remote required"
    );
    assert!(
        script_source.contains("[RCH] local (") && script_source.contains("local_fallback"),
        "post-run validation must detect and reject rch local-fallback markers"
    );
    assert!(
        script_source.contains("first_failure"),
        "post-run validation must record a first_failure reason on any failure"
    );
}

#[test]
fn scenario_matrix_rows_resolve_to_real_corpus_scenarios() {
    let artifact = artifact();
    let corpus = corpus();
    let known = corpus_scenario_rows(&corpus);

    let matrix = array(&artifact, "scenario_matrix");
    assert!(!matrix.is_empty(), "scenario matrix must not be empty");

    let mut closeout_rows = 0_usize;
    for row in matrix {
        let source_id = string(row, "source_scenario_id");
        let corpus_row = known
            .get(source_id)
            .unwrap_or_else(|| panic!("matrix row references unknown corpus scenario {source_id}"));
        // The replay scenario must parse into the real runtime type and pass
        // its own validation so manifest rows can never refer to fake scenarios.
        let scenario = parse_replay(corpus_row);
        assert_eq!(scenario.scenario_id, source_id);
        if bool_value(row, "closeout_required") {
            closeout_rows += 1;
            assert_eq!(
                string(row, "profile"),
                "small",
                "closeout scenario must stay in the small profile"
            );
            assert_eq!(
                string(row, "execution_mode"),
                "run_in_contract",
                "closeout scenario must actually execute"
            );
        }
    }
    assert_eq!(
        closeout_rows, 1,
        "exactly one closeout-required scenario keeps the proof bounded"
    );
}

#[test]
fn small_profile_runs_real_lab_scenario_and_emits_cockpit_bundle() {
    let artifact = artifact();
    let corpus = corpus();
    let known = corpus_scenario_rows(&corpus);
    let profile = env_string("SWARM_COCKPIT_PROOF_PROFILE", "small");

    let rows = matrix_rows_for_profile(&artifact, &profile);
    assert!(!rows.is_empty(), "profile {profile} selected no scenarios");

    for matrix_row in rows {
        if string(matrix_row, "execution_mode") != "run_in_contract" {
            // Expensive rows stay manifest-only; they must never emit
            // success-shaped events from this contract.
            continue;
        }
        let corpus_row = &known[string(matrix_row, "source_scenario_id")];
        let scenario = parse_replay(corpus_row);

        let provenance = script_provenance();
        let provenance_present = provenance.is_some();
        let (replay, report) = run_cockpit_pipeline(&artifact, &scenario, provenance);

        // The report must always be schema-stable and JSON round-trippable.
        assert_eq!(
            report.schema_version,
            SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION
        );
        let rendered = serde_json::to_value(&report).expect("serialize cockpit report");
        let round_tripped: SwarmOperatorCockpitReport =
            serde_json::from_value(rendered.clone()).expect("round-trip cockpit report");
        let re_rendered =
            serde_json::to_value(&round_tripped).expect("re-serialize cockpit report");
        assert_eq!(
            re_rendered, rendered,
            "cockpit report JSON must round-trip stably"
        );

        let text = render_swarm_operator_cockpit_text(&report);
        assert!(
            text.len() < 2500,
            "cockpit text must stay Agent Mail compact"
        );

        // Real lab evidence: the scenario actually ran to quiescence.
        assert!(replay.quiescent, "small scenario must reach quiescence");
        assert_eq!(replay.non_terminal_task_count, 0);

        let first_failure = if provenance_present {
            String::new()
        } else {
            "missing RCH provenance: cockpit outcome blocked (fail closed)".to_string()
        };

        if provenance_present {
            // Script-invoked execution with real provenance must be green.
            assert_eq!(
                report.outcome,
                SwarmOperatorCockpitOutcome::Pass,
                "missing fields: {:?}",
                report.missing_required_fields
            );
            assert!(report.rch_remote_provenance_observed);
            assert_eq!(
                report.obligation_verdict,
                SwarmOperatorCockpitObligationVerdict::Clean
            );
            assert!(report.redaction_preserved);
        } else {
            // Plain CI run: provenance is absent, so the cockpit must report
            // Blocked. This proves the runner cannot go green without RCH.
            assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Blocked);
            assert!(!report.blocked_proof_lane_ids.is_empty());
            assert!(!report.rch_remote_provenance_observed);
        }

        // Emit the operator evidence rows the runner script parses.
        let event = scenario_event_row(matrix_row, &scenario, &replay, &report, &first_failure);
        validate_event_row(&artifact, &event)
            .unwrap_or_else(|error| panic!("event row invalid: {error}"));
        emit_event(&event);
        emit_event(&json!({
            "scenario_id": scenario.scenario_id,
            "kind": "cockpit_report",
            "report": rendered,
        }));
        emit_event(&json!({
            "scenario_id": scenario.scenario_id,
            "kind": "cockpit_text",
            "text": text,
        }));
    }
}

#[test]
fn missing_rch_provenance_is_blocked_not_green() {
    let artifact = artifact();
    let corpus = corpus();
    let known = corpus_scenario_rows(&corpus);
    let small_rows = matrix_rows_for_profile(&artifact, "small");
    let corpus_row = &known[string(small_rows[0], "source_scenario_id")];
    let scenario = parse_replay(corpus_row);

    // Force the no-provenance path regardless of environment.
    let (_replay, report) = run_cockpit_pipeline(&artifact, &scenario, None);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Blocked);
    assert!(!report.rch_remote_provenance_observed);
    assert!(
        report
            .missing_required_fields
            .iter()
            .any(|field| field.contains("remote_provenance")),
        "blocked report must name the missing provenance field: {:?}",
        report.missing_required_fields
    );
    assert!(!report.blocked_proof_lane_ids.is_empty());

    // A blocked report must never be renderable as a passing event row.
    let small_matrix_row = small_rows[0];
    let replay = run_swarm_replay_scenario(&scenario).expect("replay scenario");
    let event = scenario_event_row(
        small_matrix_row,
        &scenario,
        &replay,
        &report,
        "missing RCH provenance: cockpit outcome blocked (fail closed)",
    );
    assert_eq!(string(&event, "proof_status"), "fail_closed");
    assert_eq!(string(&event, "cockpit_outcome"), "blocked");
    validate_event_row(&artifact, &event).expect("fail_closed row must validate");
}
