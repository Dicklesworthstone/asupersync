#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::path::{Path, PathBuf};

const README_PATH: &str = "README.md";
const WORKFLOW_PATH: &str = ".github/workflows/methodology-gates.yml";
const CONTRACT_PATH: &str = "artifacts/phase6_methodology_gate_enforcement_contract_v1.json";
const METHODOLOGY_BENCH_PATH: &str = "benches/methodology_baselines.rs";
const GOLDEN_BENCH_PATH: &str = "benches/golden_output.rs";
const GOLDEN_REGISTRY_PATH: &str = "benches/golden_registry.rs";
const CARGO_TOML_PATH: &str = "Cargo.toml";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn contract() -> JsonValue {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH))
        .expect("parse phase6 methodology gate contract")
}

fn nonempty_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn string_array(value: &JsonValue, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn local_gate<'a>(contract: &'a JsonValue, gate_id: &str) -> &'a JsonValue {
    contract
        .get("direct_main_local_gates")
        .and_then(JsonValue::as_array)
        .expect("direct_main_local_gates array")
        .iter()
        .find(|gate| gate.get("gate_id").and_then(JsonValue::as_str) == Some(gate_id))
        .unwrap_or_else(|| panic!("missing direct-main gate {gate_id}"))
}

fn cargo_bench_stanza<'a>(cargo_toml: &'a str, bench_name: &str) -> &'a str {
    let marker = format!("name = \"{bench_name}\"");
    let start = cargo_toml
        .find(&marker)
        .unwrap_or_else(|| panic!("Cargo.toml must declare bench {bench_name}"));
    let tail = &cargo_toml[start..];
    let end = tail.find("\n[[").unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn phase6_contract_records_main_only_enforcement_split() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("phase6-methodology-gate-enforcement-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rckg8s")
    );

    let workflow = contract
        .get("repository_workflow")
        .expect("repository_workflow object");
    assert_eq!(
        workflow.get("branch_model").and_then(JsonValue::as_str),
        Some("main_only")
    );
    assert_eq!(
        workflow
            .get("normal_agent_landing")
            .and_then(JsonValue::as_str),
        Some("direct_main_commit")
    );
    assert_eq!(
        workflow
            .get("pull_requests_required_for_agents")
            .and_then(JsonValue::as_bool),
        Some(false)
    );

    let signoff = contract.get("final_signoff").expect("final_signoff object");
    assert_eq!(
        signoff.get("pr_only").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        signoff.get("push_enforced").and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(
        signoff.get("local_enforced").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        signoff.get("release_only").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn local_gate_commands_are_rch_backed_and_scoped() {
    let contract = contract();
    let gates = contract
        .get("direct_main_local_gates")
        .and_then(JsonValue::as_array)
        .expect("direct_main_local_gates array");
    assert_eq!(gates.len(), 5, "expected five direct-main local gates");

    for gate in gates {
        let gate_id = nonempty_string(gate, "gate_id");
        let command = nonempty_string(gate, "rch_command");
        assert!(
            command.starts_with("rch exec -- ")
                || command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- ")
                || command
                    .starts_with("RCH_BUILD_TIMEOUT_SEC=5400 RCH_REQUIRE_REMOTE=1 rch exec -- "),
            "{gate_id}: command must be rch-backed: {command}"
        );
        assert!(
            !command.starts_with("rch exec -- cargo "),
            "{gate_id}: cargo command must declare env before cargo: {command}"
        );

        if command.contains(" cargo ") {
            assert!(
                command.contains("CARGO_TARGET_DIR="),
                "{gate_id}: cargo command must use an explicit target dir: {command}"
            );
        }

        if command.contains(" cargo bench ")
            || command.contains(" cargo test ")
            || command.contains(" cargo flamegraph ")
        {
            assert!(
                command.contains("-p asupersync") || command.contains("--package asupersync"),
                "{gate_id}: cargo command must stay scoped to the asupersync crate: {command}"
            );
        }

        let artifacts = gate
            .get("artifact_locations")
            .and_then(JsonValue::as_array)
            .unwrap_or_else(|| panic!("{gate_id}: artifact_locations must be an array"));
        assert!(
            !artifacts.is_empty(),
            "{gate_id}: must name at least one artifact location"
        );
        assert!(
            artifacts.iter().all(|item| item
                .as_str()
                .is_some_and(|path| path.starts_with("artifacts/")
                    || path.starts_with("target/")
                    || path.starts_with("tests/"))),
            "{gate_id}: artifact locations must stay in repo artifact/test surfaces"
        );
    }
}

#[test]
fn direct_main_benchmark_commands_and_comparator_are_executable_and_fail_closed() {
    let contract = contract();
    assert_eq!(
        contract.get("repair_bead_id").and_then(JsonValue::as_str),
        Some("asupersync-phase6-direct-main-benchmark-gate-drift-3kn86z")
    );

    let baseline = local_gate(&contract, "baseline-benchmarks");
    let baseline_command = nonempty_string(baseline, "rch_command");
    for required in [
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "RCH_BUILD_TIMEOUT_SEC=5400",
        "CARGO_TARGET_DIR=",
        "ASUPERSYNC_PHASE6_BASELINE=artifacts/baseline.json",
        "ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT=5",
        "cargo bench -p asupersync --bench methodology_baselines",
        "--features test-internals,criterion-benches",
    ] {
        assert!(
            baseline_command.contains(required),
            "baseline command must contain {required:?}: {baseline_command}"
        );
    }

    let comparison = baseline
        .get("comparison_contract")
        .expect("baseline comparison_contract");
    assert_eq!(
        nonempty_string(comparison, "runner"),
        "benches/methodology_baselines.rs post-benchmark gate"
    );
    assert_eq!(
        nonempty_string(comparison, "tracked_baseline"),
        "artifacts/baseline.json"
    );
    assert_eq!(
        nonempty_string(comparison, "candidate_metric"),
        "median.point_estimate"
    );
    assert_eq!(nonempty_string(comparison, "tracked_metric"), "p50_ns");
    assert_eq!(
        comparison
            .get("max_regression_pct")
            .and_then(JsonValue::as_u64),
        Some(5)
    );
    assert_eq!(
        nonempty_string(comparison, "threshold_semantics"),
        "fail_when_strictly_greater"
    );
    assert_eq!(
        nonempty_string(comparison, "missing_tracked_candidate_row"),
        "fail_closed"
    );
    assert_eq!(
        nonempty_string(comparison, "duplicate_or_invalid_row"),
        "fail_closed"
    );
    assert_eq!(
        nonempty_string(comparison, "untracked_candidate_row"),
        "ignore_until_tracked"
    );
    assert_eq!(
        comparison
            .get("no_local_fallback")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    for gate_id in ["golden-checksums-bench", "flamegraph"] {
        let command = nonempty_string(local_gate(&contract, gate_id), "rch_command");
        assert!(
            command.contains("RCH_REQUIRE_REMOTE=1 rch exec -- "),
            "{gate_id} must require remote RCH execution"
        );
        assert!(
            command.contains("--features test-internals,criterion-benches"),
            "{gate_id} must enable every Cargo-required benchmark feature"
        );
    }

    let golden_test_command = nonempty_string(
        local_gate(&contract, "golden-checksums-test"),
        "rch_command",
    );
    assert!(
        golden_test_command.contains("cargo test -j 4 "),
        "golden-checksums-test must fit the pinned-nightly RCH worker capacity"
    );
    assert!(
        golden_test_command.contains("RCH_REQUIRE_REMOTE=1 rch exec -- "),
        "golden-checksums-test must require remote RCH execution"
    );

    let cargo_toml = read_repo_file(CARGO_TOML_PATH);
    for bench_name in ["methodology_baselines", "golden_output"] {
        let stanza = cargo_bench_stanza(&cargo_toml, bench_name);
        assert!(
            stanza.contains("required-features = [\"test-internals\", \"criterion-benches\"]"),
            "{bench_name} must retain the feature requirements checked by direct-main commands"
        );
    }

    let runner = read_repo_file(METHODOLOGY_BENCH_PATH);
    for required in [
        "PHASE6_BASELINE_ENV",
        "PHASE6_THRESHOLD_ENV",
        "criterion_home()",
        "operation.replacen('/', \"_\", 1)",
        "baseline.baselines",
        "new/estimates.json",
        "delta_pct > PHASE6_MAX_REGRESSION_PCT",
        "std::process::exit(2)",
    ] {
        assert!(
            runner.contains(required),
            "Phase 6 baseline runner must preserve {required:?}"
        );
    }

    let readme = read_repo_file(README_PATH);
    for gate_id in [
        "baseline-benchmarks",
        "golden-checksums-bench",
        "golden-checksums-test",
        "flamegraph",
    ] {
        let command = nonempty_string(local_gate(&contract, gate_id), "rch_command");
        assert!(
            readme.contains(command),
            "README must publish the checked {gate_id} command verbatim"
        );
    }
}

#[test]
fn golden_registry_and_reviewed_update_flow_fail_closed() {
    let contract = contract();
    assert_eq!(
        contract
            .get("golden_registry_repair_bead_id")
            .and_then(JsonValue::as_str),
        Some("asupersync-golden-registry-fail-closed-provenance-xzv2c4")
    );

    let gate = local_gate(&contract, "golden-checksums-bench");
    let normal = gate
        .get("normal_mode_contract")
        .expect("golden normal_mode_contract");
    assert_eq!(
        normal
            .get("tracked_registry_required")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        normal.get("scenario_set").and_then(JsonValue::as_str),
        Some("exact")
    );
    for field in [
        "duplicate_scenario",
        "missing_scenario",
        "extra_scenario",
        "generate_sentinel",
        "malformed_hash_or_provenance",
    ] {
        assert_eq!(
            normal.get(field).and_then(JsonValue::as_str),
            Some("fail_closed"),
            "{field} must fail closed"
        );
    }

    let update = gate
        .get("reviewed_update_contract")
        .expect("golden reviewed_update_contract");
    let update_command = nonempty_string(update, "rch_command");
    for required in [
        "RCH_BUILD_TIMEOUT_SEC=5400 RCH_REQUIRE_REMOTE=1 rch exec",
        "--base HEAD --clean-overlay --no-overlay",
        "-- env GOLDEN_UPDATE=1 GOLDEN_REVIEWED_GIT_SHA=$(git rev-parse HEAD)",
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_phase6_golden_update",
        "cargo bench -p asupersync --bench golden_output",
        "--features test-internals,criterion-benches",
    ] {
        assert!(
            update_command.contains(required),
            "reviewed update command must contain {required:?}: {update_command}"
        );
    }
    for boolean in [
        "requires_clean_tracked_tree",
        "requires_reviewed_sha_equal_to_head",
        "candidate_contains_only_fresh_exact_scenario_set",
        "promotion_requires_separate_reviewed_commit",
    ] {
        assert_eq!(
            update.get(boolean).and_then(JsonValue::as_bool),
            Some(true),
            "{boolean} must be true"
        );
    }
    assert_eq!(
        update
            .get("tracked_registry_mutated_by_benchmark")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(nonempty_string(update, "write_mode"), "atomic_candidate");
    assert_eq!(
        nonempty_string(update, "candidate_location"),
        "${TMPDIR:-/tmp}/rch_target_asupersync_phase6_golden_update/criterion/golden-update/golden_checksums.json"
    );

    let registry = read_repo_file(GOLDEN_REGISTRY_PATH);
    for required in [
        "const GOLDEN_SCENARIOS: [&str; 14]",
        "load_golden_registry_from_path",
        "duplicate golden checksum scenario",
        "git_sha: String",
        "generated_at: String",
        "build_update_candidate",
    ] {
        assert!(
            registry.contains(required),
            "golden registry must preserve fail-closed anchor {required:?}"
        );
    }

    let cargo_toml = read_repo_file(CARGO_TOML_PATH);
    assert!(
        cargo_toml.contains("autobenches = false"),
        "bench support modules must not be auto-discovered as standalone bench targets"
    );

    let bench = read_repo_file(GOLDEN_BENCH_PATH);
    for required in [
        "mod golden_registry;",
        "GOLDEN_REVIEWED_GIT_SHA",
        "write_json_atomically",
        "finalize_golden_run",
    ] {
        assert!(
            bench.contains(required),
            "golden bench must preserve fail-closed anchor {required:?}"
        );
    }
    for forbidden in [
        "fn inline_registry()",
        "expected == \"GENERATE\"",
        "std::fs::write(GOLDEN_CHECKSUMS_PATH",
    ] {
        assert!(
            !bench.contains(forbidden) && !registry.contains(forbidden),
            "golden bench/registry must not restore stale behavior {forbidden:?}"
        );
    }

    let readme = read_repo_file(README_PATH);
    assert!(
        readme.contains("-- env GOLDEN_UPDATE=1 GOLDEN_REVIEWED_GIT_SHA=${GOLDEN_REVIEWED_SHA}"),
        "README must place reviewed update controls inside the remote environment"
    );
    assert!(
        readme.contains("criterion/golden-update/golden_checksums.json"),
        "README must name the retrieved candidate"
    );
}

#[test]
fn flamegraph_gate_records_pressure_control_attribution() {
    let contract = contract();
    let gates = contract
        .get("direct_main_local_gates")
        .and_then(JsonValue::as_array)
        .expect("direct_main_local_gates array");
    let flamegraph = gates
        .iter()
        .find(|gate| gate.get("gate_id").and_then(JsonValue::as_str) == Some("flamegraph"))
        .expect("flamegraph gate");
    let attribution = flamegraph
        .get("pressure_control_attribution")
        .expect("flamegraph pressure_control_attribution object");

    assert_eq!(
        nonempty_string(attribution, "contract"),
        "artifacts/runtime_pressure_control_evidence_contract_v1.json"
    );
    assert_eq!(
        nonempty_string(attribution, "contract_test"),
        "tests/runtime_pressure_control_evidence_contract.rs"
    );
    assert_eq!(
        nonempty_string(attribution, "operator_runbook"),
        "docs/runtime_pressure_triage_runbook.md"
    );
    assert_eq!(
        nonempty_string(attribution, "signal"),
        "scheduler_tail_pressure"
    );
    assert_eq!(
        nonempty_string(attribution, "lab_scenario_family"),
        "cpu_lane_pressure"
    );
    assert_eq!(
        nonempty_string(attribution, "benchmark_surface"),
        "methodology_baselines"
    );
    assert_eq!(
        string_array(attribution, "benchmark_rows"),
        vec![
            "methodology/task_spawn/inject_ready_global_queue".to_string(),
            "methodology/task_spawn/local_queue_push".to_string(),
            "methodology/task_spawn/local_queue_spawn_batch/1000".to_string(),
        ]
    );
    let non_claim = nonempty_string(attribution, "non_claim").to_ascii_lowercase();
    for required in ["does not prove", "throughput", "performance improvement"] {
        assert!(
            non_claim.contains(required),
            "flamegraph pressure attribution must preserve non-claim phrase {required:?}"
        );
    }
}

#[test]
fn workflow_parses_and_is_explicitly_pr_only() {
    let workflow_text = read_repo_file(WORKFLOW_PATH);
    let workflow: YamlValue =
        serde_yaml::from_str(&workflow_text).expect("methodology workflow must parse as YAML");
    let mapping = workflow
        .as_mapping()
        .expect("methodology workflow must be a YAML mapping");

    let on_key = YamlValue::String("on".to_string());
    let on = mapping
        .get(&on_key)
        .expect("workflow must declare triggers");
    let on_mapping = on.as_mapping().expect("workflow on: must be a mapping");
    assert!(
        on_mapping.contains_key(YamlValue::String("pull_request".to_string())),
        "methodology workflow must keep its PR trigger explicit"
    );
    assert!(
        !on_mapping.contains_key(YamlValue::String("push".to_string())),
        "contract currently records no push-on-main enforcement"
    );

    assert!(
        workflow_text.contains("${{ github.event.pull_request.number }}"),
        "PR artifact names must remain visibly PR-number based"
    );

    let jobs = mapping
        .get(YamlValue::String("jobs".to_string()))
        .and_then(YamlValue::as_mapping)
        .expect("workflow must contain jobs mapping");
    for required_job in [
        "baseline-gate",
        "flamegraph-gate",
        "golden-checksum-gate",
        "proof-note-gate",
        "summary",
    ] {
        assert!(
            jobs.contains_key(YamlValue::String(required_job.to_string())),
            "workflow must contain job {required_job}"
        );
    }
}

#[test]
fn readme_describes_direct_main_lane_and_no_longer_claims_pr_only_enforcement() {
    let readme = read_repo_file(README_PATH);
    for required in [
        "direct commits on `main`",
        "Direct-main agent lane",
        "PR/release-review lane",
        "artifacts/phase6_methodology_gate_enforcement_contract_v1.json",
        "tests/phase6_methodology_gate_contract.rs",
        "rch exec -- env CARGO_INCREMENTAL=0",
        "Push-on-main GitHub enforcement is not currently enabled",
    ] {
        assert!(
            readme.contains(required),
            "README Phase 6 policy gates section must contain `{required}`"
        );
    }

    for stale in [
        "The methodology bar is enforced at PR review time",
        "runs on every pull request targeting `main`. There are no advisory-only gates",
        "All four gates are **live today** on `pull_request` events targeting `main`",
        "before opening the PR",
    ] {
        assert!(
            !readme.contains(stale),
            "README must not preserve stale PR-only claim `{stale}`"
        );
    }
}
