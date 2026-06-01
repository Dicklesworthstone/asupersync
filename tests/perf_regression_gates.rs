#![allow(warnings)]
#![allow(clippy::all)]
//! Perf regression gate tests and helpers (bd-274qo).
//!
//! Validates the regression gate mechanism used in CI to prevent performance
//! regressions from landing. Tests exercise:
//!
//! - Baseline JSON parsing and schema validation
//! - Regression threshold logic (mean 1.10x, p95 1.15x, p99 1.25x)
//! - Smoke tests with synthetic baselines to verify gate behavior
//! - Edge cases: missing baselines, empty baselines, NaN/Inf values
//!
//! These tests do NOT run actual benchmarks — they validate the gate logic
//! itself using synthetic data so CI stays fast and deterministic.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// =========================================================================
// Baseline JSON schema (matches capture_baseline.sh output)
// =========================================================================

/// A single benchmark entry in the baseline JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineBenchmark {
    name: String,
    mean_ns: f64,
    median_ns: f64,
    #[serde(default)]
    std_dev_ns: f64,
    #[serde(default)]
    cv_pct: Option<f64>,
    #[serde(default)]
    p95_ns: Option<f64>,
    #[serde(default)]
    p99_ns: Option<f64>,
    #[serde(default)]
    sample_count: Option<usize>,
}

/// Root structure of baseline JSON files.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineReport {
    #[serde(default)]
    schema_version: Option<String>,
    generated_at: String,
    #[serde(default)]
    cv_pct_flake_threshold: Option<f64>,
    #[serde(default)]
    flaky_benches: Vec<String>,
    benchmarks: Vec<BaselineBenchmark>,
}

// =========================================================================
// Regression gate logic (mirrors capture_baseline.sh --compare)
// =========================================================================

/// Thresholds for regression detection, matching docs/benchmarking.md.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone)]
struct RegressionThresholds {
    mean_ratio: f64,
    p95_ratio: f64,
    p99_ratio: f64,
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            mean_ratio: 1.10,
            p95_ratio: 1.15,
            p99_ratio: 1.25,
        }
    }
}

/// Result of checking a single metric for regression.
#[derive(Debug, Clone)]
struct MetricCheck {
    metric_name: String,
    baseline_ns: f64,
    current_ns: f64,
    ratio: f64,
    threshold: f64,
    passed: bool,
}

impl MetricCheck {
    fn new(metric_name: &str, baseline_ns: f64, current_ns: f64, threshold: f64) -> Self {
        let ratio = if baseline_ns <= 0.0 {
            if current_ns <= 0.0 {
                1.0
            } else {
                f64::INFINITY
            }
        } else {
            current_ns / baseline_ns
        };
        let passed = ratio.is_finite() && ratio <= threshold;
        Self {
            metric_name: metric_name.to_string(),
            baseline_ns,
            current_ns,
            ratio,
            threshold,
            passed,
        }
    }
}

/// Full regression check for a benchmark against a baseline.
#[derive(Debug)]
struct BenchmarkRegressionResult {
    benchmark_name: String,
    checks: Vec<MetricCheck>,
    passed: bool,
}

/// Compare a current benchmark against a baseline entry.
fn check_regression(
    baseline: &BaselineBenchmark,
    current: &BaselineBenchmark,
    thresholds: &RegressionThresholds,
) -> BenchmarkRegressionResult {
    let mut checks = Vec::new();

    checks.push(MetricCheck::new(
        "mean_ns",
        baseline.mean_ns,
        current.mean_ns,
        thresholds.mean_ratio,
    ));

    if let (Some(bp95), Some(cp95)) = (baseline.p95_ns, current.p95_ns) {
        checks.push(MetricCheck::new("p95_ns", bp95, cp95, thresholds.p95_ratio));
    }

    if let (Some(bp99), Some(cp99)) = (baseline.p99_ns, current.p99_ns) {
        checks.push(MetricCheck::new("p99_ns", bp99, cp99, thresholds.p99_ratio));
    }

    let passed = checks.iter().all(|c| c.passed);
    BenchmarkRegressionResult {
        benchmark_name: baseline.name.clone(),
        checks,
        passed,
    }
}

/// Run regression checks across all matching benchmarks.
fn run_regression_gate(
    baseline: &BaselineReport,
    current: &BaselineReport,
    thresholds: &RegressionThresholds,
) -> Vec<BenchmarkRegressionResult> {
    let baseline_map: std::collections::HashMap<&str, &BaselineBenchmark> = baseline
        .benchmarks
        .iter()
        .map(|b| (b.name.as_str(), b))
        .collect();

    current
        .benchmarks
        .iter()
        .filter_map(|cur| {
            baseline_map
                .get(cur.name.as_str())
                .map(|base| check_regression(base, cur, thresholds))
        })
        .collect()
}

/// Generate a human-readable regression report.
fn format_regression_report(results: &[BenchmarkRegressionResult]) -> String {
    let mut report = String::new();
    let failures: Vec<&BenchmarkRegressionResult> = results.iter().filter(|r| !r.passed).collect();

    if failures.is_empty() {
        report.push_str("All regression checks passed.\n");
    } else {
        let _ = writeln!(
            report,
            "REGRESSION DETECTED: {} benchmark(s) exceeded thresholds\n",
            failures.len()
        );
        for fail in &failures {
            let _ = writeln!(report, "  {}:", fail.benchmark_name);
            for check in &fail.checks {
                if !check.passed {
                    let _ = writeln!(
                        report,
                        "    {} {:.2}x > {:.2}x (baseline={:.1}ns, current={:.1}ns)\n",
                        check.metric_name,
                        check.ratio,
                        check.threshold,
                        check.baseline_ns,
                        check.current_ns,
                    );
                }
            }
        }
    }

    report
}

// =========================================================================
// Helper: create synthetic baseline/current reports
// =========================================================================

fn make_benchmark(name: &str, mean_ns: f64, median_ns: f64) -> BaselineBenchmark {
    BaselineBenchmark {
        name: name.to_string(),
        mean_ns,
        median_ns,
        std_dev_ns: mean_ns * 0.1,
        cv_pct: Some(10.0),
        p95_ns: Some(mean_ns * 1.3),
        p99_ns: Some(mean_ns * 1.8),
        sample_count: Some(100),
    }
}

fn make_report(benchmarks: Vec<BaselineBenchmark>) -> BaselineReport {
    BaselineReport {
        schema_version: Some("asupersync.baseline.v2".to_string()),
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        cv_pct_flake_threshold: Some(5.0),
        flaky_benches: vec![],
        benchmarks,
    }
}

fn write_criterion_benchmark(
    root: &Path,
    bench_path: &str,
    mean_ns: f64,
    median_ns: f64,
    std_dev_ns: f64,
    iters: &[u64],
    times: &[u64],
) {
    let bench_dir = root.join("criterion").join(bench_path).join("new");
    fs::create_dir_all(&bench_dir).expect("create criterion fixture directories");
    let estimates = serde_json::json!({
        "mean": {"point_estimate": mean_ns},
        "median": {"point_estimate": median_ns},
        "std_dev": {"point_estimate": std_dev_ns},
    });
    let sample = serde_json::json!({
        "iters": iters,
        "times": times,
    });
    fs::write(
        bench_dir.join("estimates.json"),
        serde_json::to_vec(&estimates).expect("serialize estimates"),
    )
    .expect("write estimates.json");
    fs::write(
        bench_dir.join("sample.json"),
        serde_json::to_vec(&sample).expect("serialize sample"),
    )
    .expect("write sample.json");
}

fn write_minimal_criterion_output(root: &Path) {
    write_criterion_benchmark(root, "bench", 1.0, 1.0, 0.0, &[1], &[1]);
}

fn write_criterion_benchmark_without_samples(
    root: &Path,
    bench_path: &str,
    mean_ns: f64,
    median_ns: f64,
    std_dev_ns: f64,
) {
    let bench_dir = root.join("criterion").join(bench_path).join("new");
    fs::create_dir_all(&bench_dir).expect("create criterion fixture directories");
    let estimates = serde_json::json!({
        "mean": {"point_estimate": mean_ns},
        "median": {"point_estimate": median_ns},
        "std_dev": {"point_estimate": std_dev_ns},
    });
    fs::write(
        bench_dir.join("estimates.json"),
        serde_json::to_vec(&estimates).expect("serialize estimates"),
    )
    .expect("write estimates.json");
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn write_executable_script(path: &Path, body: &str) {
    fs::write(path, body).expect("write executable script");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("script metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod script");
    }
}

fn run_capture_baseline_with_command(arg_name: &str, arg_value: &str) -> std::process::Output {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());
    let script = repo_root().join("scripts/capture_baseline.sh");
    Command::new("bash")
        .arg(script)
        .arg("--run")
        .arg(arg_name)
        .arg(arg_value)
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .output()
        .expect("run capture_baseline.sh")
}

fn add_valid_swarm_ledger_env(command: &mut Command) -> &mut Command {
    command
        .env("RCH_REQUIRE_REMOTE", "1")
        .env("SWARM_LEDGER_RCH_WORKER_ID", "vmi-ledger-test")
        .env("SWARM_LEDGER_RCH_BUILD_ID", "29863361030127999")
        .env(
            "SWARM_LEDGER_RCH_COMMAND",
            "rch exec -- cargo bench --bench phase0_baseline",
        )
        .env("SWARM_LEDGER_MEMORY_ENVELOPE_BYTES", "1073741824")
        .env("SWARM_LEDGER_QUIESCENCE_VERDICT", "pass")
}

// =========================================================================
// Tests: baseline JSON parsing
// =========================================================================

#[test]
fn parse_baseline_json_from_disk() {
    let baseline_path = Path::new("baselines/baseline_latest.json");
    if !baseline_path.exists() {
        // No baseline on disk — skip gracefully (CI may not have run benches).
        eprintln!("SKIP: no baseline at {}", baseline_path.display());
        return;
    }
    let data = fs::read_to_string(baseline_path).expect("read baseline file");
    let report: BaselineReport = serde_json::from_str(&data).expect("parse baseline JSON");

    assert!(!report.generated_at.is_empty(), "generated_at must be set");
    assert!(
        !report.benchmarks.is_empty(),
        "baseline must contain benchmarks"
    );

    for bench in &report.benchmarks {
        assert!(!bench.name.is_empty(), "benchmark name must not be empty");
        assert!(
            bench.mean_ns.is_finite() && bench.mean_ns >= 0.0,
            "mean_ns must be finite and non-negative for {}",
            bench.name
        );
        assert!(
            bench.median_ns.is_finite() && bench.median_ns >= 0.0,
            "median_ns must be finite and non-negative for {}",
            bench.name
        );
    }
}

#[test]
fn capture_baseline_preserves_quoted_commands_and_emits_valid_run_events() {
    let command = "printf '%s\\n' 'alpha beta'";
    let encoded = BASE64_STANDARD.encode(command);

    for (arg_name, arg_value) in [("--cmd", command), ("--cmd-b64", encoded.as_str())] {
        let output = run_capture_baseline_with_command(arg_name, arg_value);
        assert!(
            output.status.success(),
            "capture_baseline should succeed for {arg_name}: status={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
        assert!(
            stdout.contains("\nalpha beta\n"),
            "quoted argument should survive wrapper transport for {arg_name}: {stdout}"
        );
        assert!(
            !stdout.contains("\"\"alpha") && !stdout.contains("\"\"beta"),
            "wrapper transport must not split quoted command output for {arg_name}: {stdout}"
        );

        let start_line = stdout
            .lines()
            .find(|line| line.contains("\"profiling_run_start\""))
            .expect("start event line");
        let end_line = stdout
            .lines()
            .find(|line| line.contains("\"profiling_run_end\""))
            .expect("end event line");

        let start: serde_json::Value =
            serde_json::from_str(start_line).expect("start event must be valid json");
        let end: serde_json::Value =
            serde_json::from_str(end_line).expect("end event must be valid json");

        assert_eq!(start["command"], command, "start event command");
        assert_eq!(end["command"], command, "end event command");
    }
}

#[test]
fn capture_baseline_quoted_command_runner_ignores_login_shell_profiles() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());
    fs::write(
        temp.path().join(".bash_profile"),
        "printf 'LOGIN_SHELL_NOISE\\n'\n",
    )
    .expect("write .bash_profile");

    let script = repo_root().join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--run")
        .arg("--cmd")
        .arg("printf '%s\\n' 'alpha beta'")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("HOME", temp.path())
        .output()
        .expect("run capture_baseline.sh");

    assert!(
        output.status.success(),
        "capture_baseline should succeed when HOME contains a noisy login profile: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(
        !stdout.contains("LOGIN_SHELL_NOISE"),
        "quoted command runner must not source login-shell startup files: {stdout}"
    );
    assert!(
        stdout.contains("\nalpha beta\n"),
        "command output should still be present without login-shell noise: {stdout}"
    );
}

#[test]
fn capture_baseline_default_run_requires_rch() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());
    let missing_rch = temp.path().join("missing-rch");
    let script = repo_root().join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--run")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("RCH_BIN", &missing_rch)
        .output()
        .expect("run capture_baseline.sh");

    assert!(
        !output.status.success(),
        "capture_baseline should fail closed without rch"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("RCH_BIN"),
        "stderr should name the missing rch contract: {stderr}"
    );
    assert!(
        stderr.contains("refusing local cargo bench fallback"),
        "stderr should explain the fail-closed benchmark policy: {stderr}"
    );
}

#[test]
fn capture_baseline_default_run_uses_rch_override() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());
    let rch_argv_log = temp.path().join("rch-shim-argv.log");
    let rch_shim = temp.path().join("rch-shim");
    let save_dir = temp.path().join("baselines");
    write_executable_script(
        &rch_shim,
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > {}\n",
            rch_argv_log.display()
        ),
    );

    let script = repo_root().join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--smoke")
        .arg("--save")
        .arg(&save_dir)
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("RCH_BIN", &rch_shim)
        .output()
        .expect("run capture_baseline.sh");

    assert!(
        output.status.success(),
        "capture_baseline should succeed with scripted rch shim: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let argv = fs::read_to_string(&rch_argv_log).expect("read rch argv log");
    for token in [
        "exec",
        "--",
        "env",
        "RUSTFLAGS=-C force-frame-pointers=yes",
        "CARGO_TARGET_DIR=",
        "cargo",
        "bench",
        "--profile",
        "release-perf",
        "--bench",
        "phase0_baseline",
    ] {
        assert!(
            argv.contains(token),
            "default run path must invoke rch-wrapped bench token `{token}`: {argv}"
        );
    }

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let start_line = stdout
        .lines()
        .find(|line| line.contains("\"profiling_run_start\""))
        .expect("start event line");
    let end_line = stdout
        .lines()
        .find(|line| line.contains("\"profiling_run_end\""))
        .expect("end event line");
    let start: serde_json::Value =
        serde_json::from_str(start_line).expect("start event must be valid json");
    let end: serde_json::Value =
        serde_json::from_str(end_line).expect("end event must be valid json");

    for event in [&start, &end] {
        let command = event["command"]
            .as_str()
            .expect("command field should be present");
        assert!(
            command.contains("exec -- env RUSTFLAGS=-C force-frame-pointers=yes CARGO_TARGET_DIR=")
                && command.contains(" cargo bench --profile release-perf")
                && command.contains(" --features criterion-benches")
                && command.contains(" --bench phase0_baseline"),
            "run events must record the isolated rch-wrapped bench command: {command}"
        );
    }

    let smoke_report = fs::read_dir(&save_dir)
        .expect("read save dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("smoke_report_") && name.ends_with(".json"))
        })
        .expect("smoke report path");
    let smoke_report_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(smoke_report).expect("read smoke report"))
            .expect("parse smoke report");
    let smoke_command = smoke_report_json["command"]
        .as_str()
        .expect("smoke report command field should be present");
    assert!(
        smoke_command
            .contains("exec -- env RUSTFLAGS=-C force-frame-pointers=yes CARGO_TARGET_DIR=")
            && smoke_command.contains(" cargo bench --profile release-perf")
            && smoke_command.contains(" --features criterion-benches")
            && smoke_command.contains(" --bench phase0_baseline"),
        "smoke report must record the isolated rch-wrapped bench command: {smoke_command}"
    );
    assert_eq!(
        smoke_report_json["config"]["cargo_profile"], "release-perf",
        "smoke report should record the Cargo benchmark profile"
    );
    assert_eq!(
        smoke_report_json["config"]["bench_rustflags"], "-C force-frame-pointers=yes",
        "smoke report should record benchmark RUSTFLAGS"
    );
}

#[test]
fn run_perf_e2e_list_succeeds_without_rch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing_rch = temp.path().join("missing-rch");
    let script = repo_root().join("scripts/run_perf_e2e.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--list")
        .env("RCH_BIN", &missing_rch)
        .output()
        .expect("run run_perf_e2e.sh --list");

    assert!(
        output.status.success(),
        "run_perf_e2e --list should not require rch: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout.contains("phase0_baseline") && stdout.contains("scheduler_benchmark"),
        "list output should still enumerate benchmark suites: {stdout}"
    );
}

#[test]
fn run_perf_e2e_requires_rch_for_benchmark_execution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing_rch = temp.path().join("missing-rch");
    let script = repo_root().join("scripts/run_perf_e2e.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--bench")
        .arg("phase0_baseline")
        .arg("--no-compare")
        .env("RCH_BIN", &missing_rch)
        .output()
        .expect("run run_perf_e2e.sh");

    assert!(
        !output.status.success(),
        "run_perf_e2e should fail closed without rch"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("RCH_BIN"),
        "stderr should name the missing rch contract: {stderr}"
    );
    assert!(
        stderr.contains("refusing local cargo bench fallback"),
        "stderr should explain the fail-closed benchmark policy: {stderr}"
    );
}

#[test]
fn run_perf_e2e_and_ci_route_benches_through_release_perf_profile() {
    let repo = repo_root();
    let run_perf =
        fs::read_to_string(repo.join("scripts/run_perf_e2e.sh")).expect("read run_perf_e2e.sh");
    let workflow = fs::read_to_string(repo.join(".github/workflows/benchmarks.yml"))
        .expect("read benchmarks workflow");

    for (label, text) in [
        ("run_perf_e2e.sh", run_perf.as_str()),
        ("benchmarks.yml", workflow.as_str()),
    ] {
        assert!(
            text.contains("BENCH_CARGO_PROFILE") && text.contains("release-perf"),
            "{label} should expose release-perf as the benchmark Cargo profile"
        );
        assert!(
            text.contains("BENCH_RUSTFLAGS") && text.contains("-C force-frame-pointers=yes"),
            "{label} should force frame pointers for benchmark profiles"
        );
        assert!(
            text.contains("cargo bench --profile"),
            "{label} should invoke cargo bench with an explicit profile"
        );
    }

    assert!(
        !workflow.contains("cargo bench --all-features -- --noplot")
            && !workflow.contains("cargo bench --all-features --bench"),
        "workflow cargo bench calls must not silently use Cargo's default bench profile"
    );
    assert!(
        run_perf.contains("BASELINE_TMP_PATH=\"$BASELINE_CURRENT\" ./scripts/capture_baseline.sh"),
        "run_perf_e2e should preserve captured baseline JSON after capture_baseline stopped using a fixed /tmp path"
    );
}

#[test]
fn parse_synthetic_baseline_roundtrip() {
    let report = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("scheduler/priority", 250.0, 248.0),
    ]);

    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let parsed: BaselineReport = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(parsed.benchmarks.len(), 2);
    assert_eq!(parsed.benchmarks[0].name, "arena/insert");
    assert!((parsed.benchmarks[0].mean_ns - 14.0).abs() < 0.001);
}

#[test]
fn parse_baseline_without_percentiles() {
    let json = r#"{
        "generated_at": "2026-01-01T00:00:00Z",
        "benchmarks": [
            {"name": "test/bench", "mean_ns": 100.0, "median_ns": 95.0, "std_dev_ns": 10.0}
        ]
    }"#;
    let report: BaselineReport = serde_json::from_str(json).expect("parse");
    assert_eq!(report.benchmarks.len(), 1);
    assert!(report.benchmarks[0].p95_ns.is_none());
    assert!(report.benchmarks[0].p99_ns.is_none());
}

#[test]
fn capture_baseline_emits_cv_pct_and_flaky_bench_quarantine() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_criterion_benchmark(
        temp.path(),
        "stable/bench",
        1_000.0,
        950.0,
        40.0,
        &[1, 1, 1],
        &[900, 1_000, 1_100],
    );
    write_criterion_benchmark(
        temp.path(),
        "noisy/bench",
        1_000.0,
        960.0,
        75.0,
        &[1, 1, 1],
        &[900, 1_000, 1_200],
    );

    let script = repo_root().join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--cv-pct-flake-threshold")
        .arg("5.0")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .current_dir(temp.path())
        .output()
        .expect("run capture_baseline.sh");

    eprintln!(
        "capture_baseline cv_pct status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "capture_baseline should succeed against synthetic Criterion output"
    );

    let report: BaselineReport =
        serde_json::from_slice(&output.stdout).expect("stdout must stay pure baseline JSON");
    assert_eq!(
        report.schema_version.as_deref(),
        Some("asupersync.baseline.v2"),
        "baseline schema version should be explicit"
    );
    assert_eq!(
        report.cv_pct_flake_threshold,
        Some(5.0),
        "flake threshold should be recorded in the baseline"
    );
    assert_eq!(
        report.flaky_benches,
        vec!["noisy/bench".to_string()],
        "only benches above the cv_pct threshold should be quarantined"
    );

    let by_name: std::collections::HashMap<&str, &BaselineBenchmark> = report
        .benchmarks
        .iter()
        .map(|bench| (bench.name.as_str(), bench))
        .collect();
    let stable = by_name.get("stable/bench").expect("stable bench present");
    let noisy = by_name.get("noisy/bench").expect("noisy bench present");
    assert!(
        (stable.cv_pct.expect("stable cv_pct") - 4.0).abs() < 0.000_001,
        "stable bench cv_pct should be std_dev/mean*100"
    );
    assert!(
        (noisy.cv_pct.expect("noisy cv_pct") - 7.5).abs() < 0.000_001,
        "noisy bench cv_pct should be std_dev/mean*100"
    );
    assert!(
        !temp.path().join(".bench-history").exists(),
        "plain capture must not mutate .bench-history without --bench-history"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(".bench-history updated"),
        "history logging should be absent when history writes are disabled"
    );
}

#[test]
fn capture_baseline_bench_history_is_opt_in_and_appends_runs_log() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_criterion_benchmark(
        temp.path(),
        "history/bench_a",
        2_000.0,
        1_900.0,
        50.0,
        &[1, 1, 1],
        &[1_800, 2_000, 2_200],
    );

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let history_dir = temp.path().join("bench-history");

    for run_idx in 0..2 {
        let output = Command::new("bash")
            .arg(&script)
            .arg("--bench-history")
            .arg("--bench-history-dir")
            .arg(&history_dir)
            .arg("--profile")
            .arg("release-perf")
            .env("CRITERION_DIR", temp.path().join("criterion"))
            .current_dir(&repo)
            .output()
            .expect("run capture_baseline.sh");

        eprintln!(
            "capture_baseline bench-history run {run_idx} status={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(
            output.status.success(),
            "bench-history run {run_idx} should succeed"
        );
        let report: BaselineReport =
            serde_json::from_slice(&output.stdout).expect("stdout must remain baseline JSON");
        assert_eq!(report.benchmarks.len(), 1, "one synthetic bench captured");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(".bench-history updated"),
            "bench-history update receipt should be logged to stderr"
        );
    }

    let latest_path = history_dir.join("history__bench_a.latest.json");
    let latest: serde_json::Value = serde_json::from_slice(
        &fs::read(&latest_path)
            .unwrap_or_else(|err| panic!("read latest history {}: {err}", latest_path.display())),
    )
    .expect("latest history JSON should parse");
    assert_eq!(latest["name"], "history/bench_a");
    assert_eq!(latest["profile"], "release-perf");
    assert_eq!(latest["mean_ns"], 2_000.0);
    assert_eq!(latest["median_ns"], 1_900.0);
    assert_eq!(latest["std_dev_ns"], 50.0);
    assert_eq!(latest["cv_pct"], 2.5);
    assert!(
        latest["git_sha"].as_str().is_some_and(|sha| sha.len() >= 7),
        "history records should carry git SHA attribution: {latest}"
    );

    let runs_path = history_dir.join("runs.jsonl");
    let runs = fs::read_to_string(&runs_path)
        .unwrap_or_else(|err| panic!("read runs log {}: {err}", runs_path.display()));
    let records: Vec<serde_json::Value> = runs
        .lines()
        .map(|line| serde_json::from_str(line).expect("runs.jsonl line should parse"))
        .collect();
    assert_eq!(
        records.len(),
        2,
        "runs.jsonl should append one record per capture invocation: {runs}"
    );
    for record in records {
        assert_eq!(record["name"], "history/bench_a");
        assert_eq!(record["profile"], "release-perf");
        assert_eq!(record["cv_pct"], 2.5);
    }
}

#[test]
fn capture_baseline_swarm_ledger_is_opt_in_and_appends_rich_records() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_criterion_benchmark(
        temp.path(),
        "swarm/pressure",
        2_000.0,
        1_900.0,
        50.0,
        &[1, 1, 1, 1, 1],
        &[1_800, 1_900, 2_000, 2_100, 2_200],
    );

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let ledger_dir = temp.path().join("swarm-ledger");

    let output = Command::new("bash")
        .arg(&script)
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("SWARM_LEDGER_DIR", &ledger_dir)
        .current_dir(&repo)
        .output()
        .expect("run capture_baseline.sh without swarm ledger");
    assert!(
        output.status.success(),
        "plain capture should succeed before ledger opt-in: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !ledger_dir.exists(),
        "plain capture must not create swarm ledger artifacts without --swarm-ledger"
    );

    let mut command = Command::new("bash");
    command
        .arg(&script)
        .arg("--swarm-ledger")
        .arg("--swarm-ledger-dir")
        .arg(&ledger_dir)
        .arg("--scenario-id")
        .arg("scheduler-global-queue")
        .arg("--profile")
        .arg("release-perf")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("BENCH_FEATURES", "messaging-fabric,cli,benchmark-adapters")
        .current_dir(&repo);
    let output = add_valid_swarm_ledger_env(&mut command)
        .output()
        .expect("run capture_baseline.sh with swarm ledger");

    eprintln!(
        "capture_baseline swarm-ledger status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "swarm ledger capture should succeed with complete provenance"
    );
    let report: BaselineReport =
        serde_json::from_slice(&output.stdout).expect("stdout must remain baseline JSON");
    let bench = report
        .benchmarks
        .iter()
        .find(|bench| bench.name == "swarm/pressure")
        .expect("captured swarm benchmark");
    assert_eq!(
        bench.sample_count,
        Some(5),
        "baseline records should expose sample_count for ledger consumers"
    );

    let ledger_path = ledger_dir.join("ledger.jsonl");
    let ledger = fs::read_to_string(&ledger_path)
        .unwrap_or_else(|err| panic!("read ledger {}: {err}", ledger_path.display()));
    let records: Vec<serde_json::Value> = ledger
        .lines()
        .map(|line| serde_json::from_str(line).expect("ledger line should parse"))
        .collect();
    assert_eq!(
        records.len(),
        1,
        "ledger should append one record for the synthetic benchmark: {ledger}"
    );
    let record = &records[0];
    assert_eq!(
        record["schema_version"],
        "asupersync.swarm-performance-ledger.v1"
    );
    assert_eq!(record["scenario_id"], "scheduler-global-queue");
    assert_eq!(record["benchmark_name"], "swarm/pressure");
    assert_eq!(record["sample_count"], 5);
    assert_eq!(record["latency_ns"]["p50"], 1_900.0);
    assert_eq!(record["latency_ns"]["p95"], 2_180.0);
    assert_eq!(record["latency_ns"]["p99"], 2_196.0);
    assert_eq!(record["cv_pct"], 2.5);
    assert_eq!(record["cargo_profile"], "release-perf");
    assert_eq!(
        record["cargo_features"],
        "messaging-fabric,cli,benchmark-adapters"
    );
    assert_eq!(record["rch"]["worker_id"], "vmi-ledger-test");
    assert_eq!(record["rch"]["build_id"], "29863361030127999");
    assert_eq!(record["rch"]["remote_required"], true);
    assert_eq!(record["memory"]["memory_envelope_bytes"], 1_073_741_824);
    assert_eq!(record["quiescence"]["verdict"], "pass");
    assert_eq!(record["verdict"], "pass");
    assert!(
        record["git_sha"].as_str().is_some_and(|sha| sha.len() >= 7),
        "ledger records should carry current git SHA attribution: {record}"
    );
    assert!(
        record["throughput_ops_per_sec"]
            .as_f64()
            .is_some_and(|throughput| throughput > 0.0),
        "ledger should derive positive throughput from p50 latency: {record}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("swarm performance ledger updated"),
        "ledger update receipt should be logged to stderr"
    );
}

#[test]
fn capture_baseline_swarm_ledger_derives_rch_provenance_from_run_log() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());

    let run_log = temp.path().join("rch-run.log");
    fs::write(
        &run_log,
        "\
2026-05-30T06:18:34Z INFO Selected worker: vmi-log-ledger at ubuntu@example
2026-05-30T06:19:27Z INFO Rewriting CARGO_TARGET_DIR for remote execution (worker-scoped path): /tmp/x -> /data/projects/asupersync/.rch-target-vmi-log-ledger-job-29863361030127998-1780121916439450732-0
",
    )
    .expect("write rch provenance run log");

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let ledger_dir = temp.path().join("swarm-ledger");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--swarm-ledger")
        .arg("--swarm-ledger-dir")
        .arg(&ledger_dir)
        .arg("--scenario-id")
        .arg("scheduler-log-derived-rch")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("RUN_OUTPUT_LOG", &run_log)
        .env(
            "RUN_COMMAND_DISPLAY",
            "rch exec -- cargo bench --bench phase0_baseline",
        )
        .env("RCH_REQUIRE_REMOTE", "1")
        .env("SWARM_LEDGER_MEMORY_ENVELOPE_BYTES", "4096")
        .env("SWARM_LEDGER_QUIESCENCE_VERDICT", "not_applicable")
        .current_dir(&repo)
        .output()
        .expect("run capture_baseline.sh with RCH log-derived provenance");

    assert!(
        output.status.success(),
        "swarm ledger should accept provenance derived from RUN_OUTPUT_LOG: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let ledger_path = ledger_dir.join("ledger.jsonl");
    let ledger = fs::read_to_string(&ledger_path)
        .unwrap_or_else(|err| panic!("read ledger {}: {err}", ledger_path.display()));
    let record: serde_json::Value =
        serde_json::from_str(ledger.trim()).expect("single ledger row should parse");
    assert_eq!(record["rch"]["worker_id"], "vmi-log-ledger");
    assert_eq!(record["rch"]["build_id"], "29863361030127998");
    assert_eq!(
        record["rch"]["command"],
        "rch exec -- cargo bench --bench phase0_baseline"
    );
}

#[test]
fn capture_baseline_swarm_ledger_rejects_missing_tail_metrics() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_criterion_benchmark_without_samples(
        temp.path(),
        "swarm/missing-tail",
        1_000.0,
        950.0,
        10.0,
    );

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let ledger_dir = temp.path().join("swarm-ledger");
    let mut command = Command::new("bash");
    command
        .arg(&script)
        .arg("--swarm-ledger")
        .arg("--swarm-ledger-dir")
        .arg(&ledger_dir)
        .arg("--scenario-id")
        .arg("scheduler-missing-tail")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .current_dir(&repo);
    let output = add_valid_swarm_ledger_env(&mut command)
        .output()
        .expect("run capture_baseline.sh with missing sample data");

    assert!(
        !output.status.success(),
        "swarm ledger should reject records without p95/p99 samples"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("missing finite p95_ns") || stderr.contains("missing finite p99_ns"),
        "tail metric failure should be explicit: {stderr}"
    );
    assert!(
        !ledger_dir.join("ledger.jsonl").exists(),
        "invalid records must not create an append-only ledger file"
    );
}

#[test]
fn capture_baseline_swarm_ledger_rejects_stale_commit_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let mut command = Command::new("bash");
    command
        .arg(&script)
        .arg("--swarm-ledger")
        .arg("--swarm-ledger-dir")
        .arg(temp.path().join("swarm-ledger"))
        .arg("--scenario-id")
        .arg("scheduler-stale-sha")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env(
            "SWARM_LEDGER_EXPECT_GIT_SHA",
            "0000000000000000000000000000000000000000",
        )
        .current_dir(&repo);
    let output = add_valid_swarm_ledger_env(&mut command)
        .output()
        .expect("run capture_baseline.sh with stale commit metadata");

    assert!(
        !output.status.success(),
        "swarm ledger should reject stale expected git metadata"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("stale commit metadata"),
        "stale git metadata failure should be explicit: {stderr}"
    );
}

#[test]
fn capture_baseline_swarm_ledger_rejects_malformed_rch_provenance() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--swarm-ledger")
        .arg("--swarm-ledger-dir")
        .arg(temp.path().join("swarm-ledger"))
        .arg("--scenario-id")
        .arg("scheduler-bad-rch")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .env("SWARM_LEDGER_RCH_WORKER_ID", "bad worker id")
        .env("SWARM_LEDGER_RCH_BUILD_ID", "not-a-number")
        .env("SWARM_LEDGER_MEMORY_ENVELOPE_BYTES", "1024")
        .current_dir(&repo)
        .output()
        .expect("run capture_baseline.sh with malformed RCH provenance");

    assert!(
        !output.status.success(),
        "swarm ledger should reject malformed RCH provenance"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("valid RCH worker id") || stderr.contains("numeric RCH build id"),
        "malformed RCH provenance failure should be explicit: {stderr}"
    );
}

#[test]
fn capture_baseline_swarm_ledger_rejects_non_monotonic_history_timestamps() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_criterion_output(temp.path());

    let ledger_dir = temp.path().join("swarm-ledger");
    fs::create_dir_all(&ledger_dir).expect("create ledger dir");
    fs::write(
        ledger_dir.join("ledger.jsonl"),
        r#"{"generated_at":"9999-01-01T00:00:00Z"}"#,
    )
    .expect("write future ledger row");

    let repo = repo_root();
    let script = repo.join("scripts/capture_baseline.sh");
    let mut command = Command::new("bash");
    command
        .arg(&script)
        .arg("--swarm-ledger")
        .arg("--swarm-ledger-dir")
        .arg(&ledger_dir)
        .arg("--scenario-id")
        .arg("scheduler-nonmonotonic")
        .env("CRITERION_DIR", temp.path().join("criterion"))
        .current_dir(&repo);
    let output = add_valid_swarm_ledger_env(&mut command)
        .output()
        .expect("run capture_baseline.sh with future ledger history");

    assert!(
        !output.status.success(),
        "swarm ledger should reject non-monotonic append timestamps"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("non-monotonic history timestamp"),
        "timestamp regression failure should be explicit: {stderr}"
    );
}

#[test]
fn capture_baseline_help_documents_perf_history_options() {
    let script = repo_root().join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--help")
        .output()
        .expect("run capture_baseline.sh --help");

    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8(output.stdout).expect("help stdout should be utf8");
    for expected in [
        "--profile <name>",
        "--cargo-profile <name>",
        "--bench-rustflags <flags>",
        "--bench-history",
        "--no-bench-history",
        "--bench-history-dir <dir>",
        "--cv-pct-flake-threshold <pct>",
        "--swarm-ledger",
        "--no-swarm-ledger",
        "--swarm-ledger-dir <dir>",
        "--scenario-id <id>",
    ] {
        assert!(
            stdout.contains(expected),
            "help output should document {expected}: {stdout}"
        );
    }
}

#[test]
fn capture_baseline_rejects_missing_perf_option_values_cleanly() {
    let script = repo_root().join("scripts/capture_baseline.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg("--profile")
        .output()
        .expect("run capture_baseline.sh --profile");

    assert!(
        !output.status.success(),
        "missing --profile value should fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("--profile requires a non-empty value"),
        "missing value error should be explicit, not a shell nounset failure: {stderr}"
    );
    assert!(
        !stderr.contains("unbound variable"),
        "missing value path must not expose bash nounset noise: {stderr}"
    );
}

// =========================================================================
// Tests: regression gate logic
// =========================================================================

#[test]
fn gate_passes_on_identical_results() {
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("scheduler/priority", 250.0, 248.0),
    ]);
    let current = baseline.clone();
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|r| r.passed),
        "identical results must pass"
    );
}

#[test]
fn gate_passes_on_improvement() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    // 20% faster
    let current = make_report(vec![make_benchmark("arena/insert", 11.2, 11.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "improvements must pass");
}

#[test]
fn gate_passes_on_small_regression_within_threshold() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // 8% regression — within 10% mean threshold
    let current = make_report(vec![make_benchmark("arena/insert", 108.0, 103.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].passed,
        "8% regression should be within 10% mean threshold"
    );
}

#[test]
fn gate_fails_on_mean_regression() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // 15% regression on mean — exceeds 10% threshold
    let current = make_report(vec![make_benchmark("arena/insert", 115.0, 110.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed, "15% mean regression must fail");

    let failed_checks: Vec<&MetricCheck> = results[0].checks.iter().filter(|c| !c.passed).collect();
    assert!(
        failed_checks.iter().any(|c| c.metric_name == "mean_ns"),
        "mean_ns check must fail"
    );
}

#[test]
fn gate_fails_on_p95_regression() {
    // Construct baselines where mean is fine but p95 exceeds threshold.
    let mut baseline_bench = make_benchmark("scheduler/priority", 100.0, 95.0);
    baseline_bench.p95_ns = Some(130.0);
    let mut current_bench = make_benchmark("scheduler/priority", 105.0, 100.0);
    // p95 grows from 130 to 155 → 1.19x, exceeds 1.15x
    current_bench.p95_ns = Some(155.0);

    let baseline = make_report(vec![baseline_bench]);
    let current = make_report(vec![current_bench]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed, "p95 regression must fail");

    let failed_checks: Vec<&MetricCheck> = results[0].checks.iter().filter(|c| !c.passed).collect();
    assert!(
        failed_checks.iter().any(|c| c.metric_name == "p95_ns"),
        "p95_ns check must fail"
    );
}

#[test]
fn gate_fails_on_p99_regression() {
    let mut baseline_bench = make_benchmark("scheduler/priority", 100.0, 95.0);
    baseline_bench.p99_ns = Some(180.0);
    let mut current_bench = make_benchmark("scheduler/priority", 105.0, 100.0);
    // p99 grows from 180 to 230 → 1.28x, exceeds 1.25x
    current_bench.p99_ns = Some(230.0);

    let baseline = make_report(vec![baseline_bench]);
    let current = make_report(vec![current_bench]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed, "p99 regression must fail");
}

#[test]
fn gate_handles_missing_benchmark_in_current() {
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("arena/get_hit", 1.0, 0.9),
    ]);
    // Current only has one benchmark
    let current = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    // Only matching benchmarks are compared
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn gate_handles_new_benchmark_in_current() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let current = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("arena/new_bench", 5.0, 4.8),
    ]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    // New benchmarks without baselines are skipped
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn gate_handles_empty_baseline() {
    let baseline = make_report(vec![]);
    let current = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert!(results.is_empty(), "no comparisons with empty baseline");
}

#[test]
fn gate_handles_empty_current() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let current = make_report(vec![]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert!(results.is_empty(), "no comparisons with empty current");
}

// =========================================================================
// Tests: edge cases
// =========================================================================

#[test]
fn gate_handles_zero_baseline() {
    let baseline = make_report(vec![make_benchmark("zero/bench", 0.0, 0.0)]);
    let current = make_report(vec![make_benchmark("zero/bench", 5.0, 4.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    // Zero baseline with non-zero current should fail (infinite ratio).
    assert!(!results[0].passed);
}

#[test]
fn gate_handles_zero_both() {
    let baseline = make_report(vec![make_benchmark("zero/bench", 0.0, 0.0)]);
    let current = make_report(vec![make_benchmark("zero/bench", 0.0, 0.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    // 0/0 → ratio 1.0, should pass.
    assert!(results[0].passed);
}

#[test]
fn custom_thresholds_are_respected() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // 4% regression
    let current = make_report(vec![make_benchmark("arena/insert", 104.0, 99.0)]);

    // Strict threshold: 3%
    let strict = RegressionThresholds {
        mean_ratio: 1.03,
        p95_ratio: 1.05,
        p99_ratio: 1.10,
    };
    let results = run_regression_gate(&baseline, &current, &strict);
    assert!(!results[0].passed, "4% regression must fail 3% threshold");

    // Lenient threshold: 5%
    let lenient = RegressionThresholds {
        mean_ratio: 1.05,
        p95_ratio: 1.10,
        p99_ratio: 1.20,
    };
    let results = run_regression_gate(&baseline, &current, &lenient);
    assert!(results[0].passed, "4% regression should pass 5% threshold");
}

#[test]
fn boundary_regression_exactly_at_threshold() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // Exactly 10% regression — at the boundary
    let current = make_report(vec![make_benchmark("arena/insert", 110.0, 104.5)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    // 1.10 <= 1.10 → passes (threshold is inclusive)
    assert!(results[0].passed, "exactly-at-threshold should pass");
}

// =========================================================================
// Tests: report formatting
// =========================================================================

#[test]
fn report_shows_pass_on_clean_run() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let current = baseline.clone();
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    let report = format_regression_report(&results);
    assert!(
        report.contains("All regression checks passed"),
        "clean run report: {report}"
    );
}

#[test]
fn report_shows_failure_details() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    let current = make_report(vec![make_benchmark("arena/insert", 120.0, 115.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    let report = format_regression_report(&results);
    assert!(
        report.contains("REGRESSION DETECTED"),
        "regression report: {report}"
    );
    assert!(
        report.contains("arena/insert"),
        "report must name the benchmark: {report}"
    );
    assert!(
        report.contains("mean_ns"),
        "report must name the metric: {report}"
    );
}

// =========================================================================
// Tests: multiple benchmarks in one gate check
// =========================================================================

#[test]
fn gate_multiple_benchmarks_mixed_results() {
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 100.0, 95.0),
        make_benchmark("arena/get_hit", 1.0, 0.9),
        make_benchmark("scheduler/priority", 250.0, 248.0),
    ]);
    let current = make_report(vec![
        make_benchmark("arena/insert", 120.0, 115.0), // 20% regression → fail
        make_benchmark("arena/get_hit", 0.95, 0.88),  // improvement → pass
        make_benchmark("scheduler/priority", 255.0, 253.0), // 2% → pass
    ]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 3);

    let passed = results.iter().filter(|r| r.passed).count();
    let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();

    assert_eq!(passed, 2, "2 benchmarks should pass");
    assert_eq!(failed.len(), 1, "1 benchmark should fail");
    assert_eq!(failed[0].benchmark_name, "arena/insert");
}

// =========================================================================
// Tests: conformance with on-disk baseline (if available)
// =========================================================================

#[test]
fn gate_on_disk_baseline_self_check() {
    let baseline_path = Path::new("baselines/baseline_latest.json");
    if !baseline_path.exists() {
        eprintln!("SKIP: no baseline at {}", baseline_path.display());
        return;
    }
    let data = fs::read_to_string(baseline_path).expect("read baseline");
    let report: BaselineReport = serde_json::from_str(&data).expect("parse baseline");

    // Self-comparison must always pass.
    let thresholds = RegressionThresholds::default();
    let results = run_regression_gate(&report, &report, &thresholds);

    for result in &results {
        assert!(
            result.passed,
            "self-comparison must pass for {}",
            result.benchmark_name
        );
    }
}

// =========================================================================
// Tests: synthetic regression smoke test (bd-274qo acceptance criteria)
// =========================================================================

#[test]
fn smoke_test_synthetic_regression_detected() {
    // Model a real CI scenario: current run has a regression on one bench.
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("arena/get_hit", 1.0, 0.9),
        make_benchmark("scheduler/local_queue/push_pop", 45.0, 43.0),
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1340.0, 1320.0),
        make_benchmark("budget/combine", 10.0, 10.0),
    ]);

    let current = make_report(vec![
        make_benchmark("arena/insert", 14.2, 14.0), // +1.4% → pass
        make_benchmark("arena/get_hit", 1.02, 0.92), // +2% → pass
        make_benchmark("scheduler/local_queue/push_pop", 55.0, 53.0), // +22% → FAIL
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1360.0, 1340.0), // +1.5% → pass
        make_benchmark("budget/combine", 10.5, 10.3),                                 // +5% → pass
    ]);

    let thresholds = RegressionThresholds::default();
    let results = run_regression_gate(&baseline, &current, &thresholds);

    let all_passed = results.iter().all(|r| r.passed);
    assert!(!all_passed, "gate must detect synthetic regression");

    let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].benchmark_name, "scheduler/local_queue/push_pop");

    let report = format_regression_report(&results);
    assert!(report.contains("REGRESSION DETECTED"));
    assert!(report.contains("scheduler/local_queue/push_pop"));
}

#[test]
fn smoke_test_clean_run_passes_gate() {
    // Model CI with no regressions: small noise remains within tolerance.
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("scheduler/local_queue/push_pop", 45.0, 43.0),
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1340.0, 1320.0),
    ]);

    let current = make_report(vec![
        make_benchmark("arena/insert", 14.5, 14.2), // +3.6%
        make_benchmark("scheduler/local_queue/push_pop", 47.0, 45.5), // +4.4%
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1380.0, 1360.0), // +3.0%
    ]);

    let thresholds = RegressionThresholds::default();
    let results = run_regression_gate(&baseline, &current, &thresholds);

    let all_passed = results.iter().all(|r| r.passed);
    assert!(all_passed, "normal noise should pass the gate");

    let report = format_regression_report(&results);
    assert!(report.contains("All regression checks passed"));
}

// =========================================================================
// Tests: JSON serialization of regression results (for CI artifacts)
// =========================================================================

#[derive(Debug, Serialize, Deserialize)]
struct GateReport {
    passed: bool,
    total_benchmarks: usize,
    regressions: Vec<RegressionDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegressionDetail {
    benchmark: String,
    metric: String,
    ratio: f64,
    threshold: f64,
    baseline_ns: f64,
    current_ns: f64,
}

fn build_gate_report(results: &[BenchmarkRegressionResult]) -> GateReport {
    let mut regressions = Vec::new();
    for result in results {
        for check in &result.checks {
            if !check.passed {
                regressions.push(RegressionDetail {
                    benchmark: result.benchmark_name.clone(),
                    metric: check.metric_name.clone(),
                    ratio: check.ratio,
                    threshold: check.threshold,
                    baseline_ns: check.baseline_ns,
                    current_ns: check.current_ns,
                });
            }
        }
    }
    let passed = regressions.is_empty();
    GateReport {
        passed,
        total_benchmarks: results.len(),
        regressions,
    }
}

#[test]
fn gate_report_json_roundtrip() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    let current = make_report(vec![make_benchmark("arena/insert", 115.0, 110.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    let gate_report = build_gate_report(&results);

    assert!(!gate_report.passed);
    assert_eq!(gate_report.total_benchmarks, 1);
    assert_eq!(gate_report.regressions.len(), 1);

    let json = serde_json::to_string_pretty(&gate_report).expect("serialize gate report");
    let parsed: GateReport = serde_json::from_str(&json).expect("deserialize gate report");
    assert!(!parsed.passed);
    assert_eq!(parsed.regressions[0].benchmark, "arena/insert");
}

// =========================================================================
// apply_perf_ratchet.py two-sided flake quarantine (br-asupersync-4j4h32)
// =========================================================================

/// Write a synthetic `asupersync.baseline.v2` JSON with the given
/// (name, median_ns, cv_pct) rows.
fn write_ratchet_fixture(path: &Path, rows: &[(&str, f64, f64)]) {
    let benchmarks: Vec<serde_json::Value> = rows
        .iter()
        .map(|(name, median, cv)| {
            serde_json::json!({
                "name": name,
                "mean_ns": median,
                "median_ns": median,
                "std_dev_ns": median * cv / 100.0,
                "cv_pct": cv,
                "p95_ns": median * 1.1,
                "p99_ns": median * 1.2,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "schema_version": "asupersync.baseline.v2",
        "generated_at": "2026-06-01T00:00:00Z",
        "cv_pct_flake_threshold": 5.0,
        "flaky_benches": [],
        "benchmarks": benchmarks,
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&doc).expect("serialize ratchet fixture"),
    )
    .expect("write ratchet fixture");
}

/// Run apply_perf_ratchet.py against a candidate/baseline fixture pair and
/// return (exit_code, parsed JSON report).
fn run_perf_ratchet(candidate: &Path, baseline: &Path) -> (i32, serde_json::Value) {
    let script = repo_root().join("scripts/apply_perf_ratchet.py");
    let output = Command::new("python3")
        .arg(&script)
        .arg("--candidate")
        .arg(candidate)
        .arg("--baseline")
        .arg(baseline)
        .arg("--json")
        .output()
        .expect("run apply_perf_ratchet.py");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "ratchet emitted invalid JSON: {e}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap_or(-1), report)
}

/// The core two-sided protection: a flaky committed baseline must be
/// QUARANTINED, not scored, even when the candidate looks like a huge
/// regression against it. Before br-asupersync-4j4h32 this produced a
/// phantom Block.
#[test]
fn ratchet_quarantines_flaky_baseline_instead_of_phantom_blocking() {
    let temp = tempfile::tempdir().expect("tempdir");
    let baseline_path = temp.path().join("baseline.json");
    let candidate_path = temp.path().join("candidate.json");

    // Baseline captured under contention: a/noisy is flake (cv 24.5%).
    write_ratchet_fixture(
        &baseline_path,
        &[("a/noisy", 100.0, 24.5), ("a/stable", 200.0, 1.0)],
    );
    // Candidate is clean but appears +50% regressed vs. the noisy baseline row.
    write_ratchet_fixture(
        &candidate_path,
        &[("a/noisy", 150.0, 1.0), ("a/stable", 201.0, 1.0)],
    );

    let (code, report) = run_perf_ratchet(&candidate_path, &baseline_path);

    assert_eq!(
        report["verdict"], "Allow",
        "flaky baseline must not phantom-block: {report}"
    );
    assert_eq!(code, 0);
    assert_eq!(report["scored_count"], 1, "only the stable bench is scored");
    let quarantined = report["quarantined"].as_array().expect("quarantined array");
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0]["name"], "a/noisy");
    assert_eq!(
        quarantined[0]["side"], "baseline",
        "quarantine must attribute the flake to the baseline side"
    );
    assert!(
        report["blocked"]
            .as_array()
            .expect("blocked array")
            .is_empty()
    );
}

/// Candidate-side flake quarantine still works (pre-existing behavior must
/// not regress), and the record is attributed to the candidate side.
#[test]
fn ratchet_still_quarantines_flaky_candidate_side() {
    let temp = tempfile::tempdir().expect("tempdir");
    let baseline_path = temp.path().join("baseline.json");
    let candidate_path = temp.path().join("candidate.json");

    write_ratchet_fixture(&baseline_path, &[("b/x", 100.0, 1.0), ("b/y", 100.0, 1.0)]);
    write_ratchet_fixture(&candidate_path, &[("b/x", 100.0, 9.9), ("b/y", 101.0, 1.0)]);

    let (code, report) = run_perf_ratchet(&candidate_path, &baseline_path);

    assert_eq!(report["verdict"], "Allow");
    assert_eq!(code, 0);
    let quarantined = report["quarantined"].as_array().expect("quarantined array");
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0]["name"], "b/x");
    assert_eq!(quarantined[0]["side"], "candidate");
}

/// Real regressions on stable benches must still Block (the two-sided check
/// must not weaken the gate).
#[test]
fn ratchet_still_blocks_real_regression_on_stable_benches() {
    let temp = tempfile::tempdir().expect("tempdir");
    let baseline_path = temp.path().join("baseline.json");
    let candidate_path = temp.path().join("candidate.json");

    write_ratchet_fixture(&baseline_path, &[("b/x", 100.0, 1.0), ("b/y", 100.0, 1.0)]);
    write_ratchet_fixture(&candidate_path, &[("b/x", 100.0, 1.0), ("b/y", 150.0, 1.0)]);

    let (code, report) = run_perf_ratchet(&candidate_path, &baseline_path);

    assert_eq!(report["verdict"], "Block");
    assert_eq!(code, 2);
    let blocked = report["blocked"].as_array().expect("blocked array");
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0]["name"], "b/y");
}

/// When every bench is flaky on the baseline side, the verdict is
/// Quarantine (exit 3), not Allow and not Block.
#[test]
fn ratchet_all_flaky_baseline_yields_quarantine_verdict() {
    let temp = tempfile::tempdir().expect("tempdir");
    let baseline_path = temp.path().join("baseline.json");
    let candidate_path = temp.path().join("candidate.json");

    write_ratchet_fixture(
        &baseline_path,
        &[("c/x", 100.0, 30.0), ("c/y", 100.0, 15.0)],
    );
    write_ratchet_fixture(&candidate_path, &[("c/x", 100.0, 1.0), ("c/y", 100.0, 1.0)]);

    let (code, report) = run_perf_ratchet(&candidate_path, &baseline_path);

    assert_eq!(report["verdict"], "Quarantine");
    assert_eq!(code, 3);
    assert_eq!(report["scored_count"], 0);
    assert_eq!(
        report["quarantined"]
            .as_array()
            .expect("quarantined array")
            .len(),
        2
    );
}
