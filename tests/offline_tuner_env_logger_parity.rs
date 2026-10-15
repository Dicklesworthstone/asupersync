//! Black-box logging and verbosity contract for the `offline_tuner` binary.
//!
//! The matrix deliberately executes the real release-profile binary. In
//! particular, `optimize` runs the production benchmark path rather than a
//! reduced test-only mode. Each cell emits one redacted NDJSON receipt with
//! byte-exact stdout/stderr and generated-artifact hashes so the canonical
//! dependency-sovereignty runner can retain and replay the evidence.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CANARY: &str = "OFFLINE_TUNER_SECRET_CANARY_DO_NOT_RETAIN";
const REPLAY: &str = "RCH_REQUIRE_REMOTE=1 bash scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario offline-tuner-logging-parity";

#[derive(Clone, Copy)]
enum RustLogCell {
    Unset,
    Off,
    Trace,
    InvalidCanary,
}

impl RustLogCell {
    const ALL: [Self; 3] = [Self::Unset, Self::Off, Self::Trace];

    const fn label(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::Off => "off",
            Self::Trace => "trace",
            Self::InvalidCanary => "invalid_canary",
        }
    }

    fn apply(self, command: &mut Command) {
        match self {
            Self::Unset => {
                command.env_remove("RUST_LOG");
            }
            Self::Off => {
                command.env("RUST_LOG", "off");
            }
            Self::Trace => {
                command.env("RUST_LOG", "trace");
            }
            Self::InvalidCanary => {
                command.env("RUST_LOG", format!("offline_tuner={CANARY}"));
            }
        }
    }
}

struct SuccessCase {
    args: Vec<OsString>,
    artifacts: Vec<PathBuf>,
    verbose_marker: &'static str,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture JSON should serialize"),
    )
    .expect("fixture JSON should be writable");
}

fn write_fixtures(root: &Path) -> (PathBuf, PathBuf) {
    let tuning_results = root.join("tuning-results-fixture.json");
    write_json(
        &tuning_results,
        &json!({
            "target_architecture": "GenericScalar",
            "optimization_criteria": {
                "latency_weight": 0.5,
                "throughput_weight": 0.3,
                "bandwidth_weight": 0.2,
                "min_improvement_threshold": 5.0
            },
            "selected_candidate": {
                "candidate_id": "genericscalar-t8-u1-pf0-split-v1",
                "architecture_class": "GenericScalar",
                "tile_bytes": 8,
                "unroll": 1,
                "prefetch_distance": 0,
                "fusion_shape": "Split",
                "optimization_flags": []
            }
        }),
    );

    let scheduler_evidence = root.join("scheduler-evidence-fixture.json");
    write_json(
        &scheduler_evidence,
        &json!({
            "schema_version": "asupersync.scheduler-evidence.v1",
            "run_label": "offline-tuner-logging-parity",
            "workload_class": "mixed_burst",
            "topology": {
                "worker_threads": 64,
                "cohort_count": 2,
                "memory_budget_gib": 256
            },
            "current_knobs": {
                "worker_threads": 64,
                "steal_batch_size": 8,
                "cancel_streak_limit": 16,
                "global_queue_limit": 0,
                "parking_enabled": true
            },
            "metrics": {
                "wake_to_run_p50_ns": 8_000,
                "wake_to_run_p95_ns": 90_000,
                "wake_to_run_p99_ns": 220_000,
                "queue_residency_p50_ns": 16_000,
                "queue_residency_p95_ns": 200_000,
                "queue_residency_p99_ns": 520_000,
                "ready_backlog_p95": 192,
                "ready_backlog_p99": 320,
                "cancel_debt_p95": 48,
                "cancel_debt_p99": 128,
                "remote_steal_ratio_pct": 42,
                "cross_cohort_wake_p99_ns": 180_000
            },
            "notes": ["deterministic_fixture"]
        }),
    );

    (tuning_results, scheduler_evidence)
}

fn success_case(
    command_id: &str,
    cell_dir: &Path,
    tuning_results: &Path,
    scheduler_evidence: &Path,
) -> SuccessCase {
    match command_id {
        "optimize" => SuccessCase {
            args: ["optimize", "--arch", "scalar"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            artifacts: vec![
                cell_dir.join("tuning_results_GenericScalar.json"),
                cell_dir.join("optimized_profile_GenericScalar.json"),
            ],
            verbose_marker: "Candidates:\n",
        },
        "candidates" => SuccessCase {
            args: ["candidates", "--arch", "scalar"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            artifacts: vec![cell_dir.join("candidates_GenericScalar.json")],
            verbose_marker: "1. genericscalar-",
        },
        "emit-profile" => {
            let output = cell_dir.join("emitted-profile.json");
            SuccessCase {
                args: vec![
                    OsString::from("emit-profile"),
                    OsString::from("--results-file"),
                    tuning_results.as_os_str().to_owned(),
                    OsString::from("--output-file"),
                    output.as_os_str().to_owned(),
                ],
                artifacts: vec![output],
                verbose_marker: "Selected candidate: genericscalar-",
            }
        }
        "validate" => SuccessCase {
            args: ["validate", "--arch", "scalar"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            artifacts: Vec::new(),
            verbose_marker: "PASSED: mul_slice for scenario single_byte",
        },
        "scheduler-recommend" => {
            let output = cell_dir.join("scheduler-report.json");
            SuccessCase {
                args: vec![
                    OsString::from("scheduler-recommend"),
                    OsString::from("--evidence-file"),
                    scheduler_evidence.as_os_str().to_owned(),
                    OsString::from("--output-file"),
                    output.as_os_str().to_owned(),
                ],
                artifacts: vec![output],
                verbose_marker: "Run label: offline-tuner-logging-parity",
            }
        }
        _ => panic!("unknown success command fixture: {command_id}"),
    }
}

fn run_binary(
    output_dir: &Path,
    args: &[OsString],
    verbose: bool,
    rust_log: RustLogCell,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_offline_tuner"));
    command.arg("--output-dir").arg(output_dir);
    if verbose {
        command.arg("--verbose");
    }
    command.args(args);
    command.env("ASUPERSYNC_OFFLINE_TUNER_SECRET_CANARY", CANARY);
    rust_log.apply(&mut command);
    command.output().expect("offline_tuner should start")
}

fn artifact_receipts(paths: &[PathBuf]) -> Vec<Value> {
    paths
        .iter()
        .map(|path| {
            let bytes = fs::read(path)
                .unwrap_or_else(|error| panic!("expected artifact {}: {error}", path.display()));
            json!({
                "name": path.file_name().expect("artifact file name").to_string_lossy(),
                "size_bytes": bytes.len(),
                "sha256": sha256_hex(&bytes)
            })
        })
        .collect()
}

fn assert_no_secret_or_panic(output: &Output, cell_id: &str) {
    assert!(
        output.status.code().is_some(),
        "{cell_id}: process terminated by signal"
    );
    assert!(
        !output
            .stdout
            .windows(CANARY.len())
            .any(|window| window == CANARY.as_bytes()),
        "{cell_id}: stdout leaked the canary"
    );
    assert!(
        !output
            .stderr
            .windows(CANARY.len())
            .any(|window| window == CANARY.as_bytes()),
        "{cell_id}: stderr leaked the canary"
    );
}

#[test]
fn all_subcommands_preserve_logging_verbosity_and_exit_behavior() {
    let temp = tempfile::tempdir().expect("matrix tempdir");
    let (tuning_results, scheduler_evidence) = write_fixtures(temp.path());
    let command_ids = [
        "optimize",
        "candidates",
        "emit-profile",
        "validate",
        "scheduler-recommend",
    ];
    let mut nominal_cells = 0usize;

    for command_id in command_ids {
        for verbose in [false, true] {
            for rust_log in RustLogCell::ALL {
                nominal_cells += 1;
                let cell_id = format!(
                    "{command_id}__{}__rust_log_{}",
                    if verbose { "verbose" } else { "concise" },
                    rust_log.label()
                );
                let cell_dir = temp.path().join(&cell_id);
                let case =
                    success_case(command_id, &cell_dir, &tuning_results, &scheduler_evidence);
                let output = run_binary(&cell_dir, &case.args, verbose, rust_log);
                assert_no_secret_or_panic(&output, &cell_id);
                assert_eq!(output.status.code(), Some(0), "{cell_id}");
                assert!(
                    output.stderr.is_empty(),
                    "{cell_id}: env_logger emitted observable stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );

                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout.contains(case.verbose_marker) == verbose,
                    "{cell_id}: explicit --verbose stdout contract drifted"
                );

                println!(
                    "{}",
                    json!({
                        "schema_version": "offline-tuner-logging-parity-cell-v1",
                        "cell_id": cell_id,
                        "command_id": command_id,
                        "verbose": verbose,
                        "rust_log": rust_log.label(),
                        "exit_code": output.status.code(),
                        "stdout_hex": hex::encode(&output.stdout),
                        "stderr_hex": hex::encode(&output.stderr),
                        "artifacts": artifact_receipts(&case.artifacts),
                        "redaction_canary_absent": true,
                        "replay": REPLAY
                    })
                );
            }
        }
    }

    assert_eq!(nominal_cells, 30, "the full 5 x 2 x 3 matrix must run");
}

#[test]
fn malformed_input_and_filesystem_failures_stay_reported_without_panics() {
    let temp = tempfile::tempdir().expect("negative-case tempdir");
    let missing_results = temp.path().join("missing-results.json");
    let malformed_results = temp.path().join("malformed-results.json");
    fs::write(&malformed_results, b"{not-json").expect("malformed fixture");
    let output_dir_file = temp.path().join("output-dir-is-a-file");
    fs::write(&output_dir_file, b"not a directory").expect("output-dir fixture");

    let cases = [
        (
            "missing_optimize_arch",
            temp.path().join("missing-optimize-arch"),
            vec![OsString::from("optimize")],
            false,
            RustLogCell::Unset,
            1,
            "Must specify --arch or --auto-detect",
        ),
        (
            "missing_results_file",
            temp.path().join("missing-results-output"),
            vec![
                OsString::from("emit-profile"),
                OsString::from("--results-file"),
                missing_results.as_os_str().to_owned(),
            ],
            true,
            RustLogCell::Trace,
            1,
            "No such file or directory",
        ),
        (
            "malformed_results_json",
            temp.path().join("malformed-results-output"),
            vec![
                OsString::from("emit-profile"),
                OsString::from("--results-file"),
                malformed_results.as_os_str().to_owned(),
            ],
            false,
            RustLogCell::Off,
            1,
            "key must be a string",
        ),
        (
            "output_directory_is_file",
            output_dir_file,
            vec![
                OsString::from("candidates"),
                OsString::from("--arch"),
                OsString::from("scalar"),
            ],
            false,
            RustLogCell::Trace,
            1,
            "Failed to create output directory",
        ),
        (
            "invalid_architecture",
            temp.path().join("invalid-architecture"),
            vec![
                OsString::from("validate"),
                OsString::from("--arch"),
                OsString::from("not-an-architecture"),
            ],
            true,
            RustLogCell::Off,
            2,
            "invalid value 'not-an-architecture'",
        ),
    ];

    for (cell_id, output_dir, args, verbose, rust_log, expected_exit, expected_stderr) in cases {
        let output = run_binary(&output_dir, &args, verbose, rust_log);
        assert_no_secret_or_panic(&output, cell_id);
        assert_eq!(output.status.code(), Some(expected_exit), "{cell_id}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_stderr),
            "{cell_id}: missing diagnostic {expected_stderr:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!(
            "{}",
            json!({
                "schema_version": "offline-tuner-logging-parity-negative-v1",
                "cell_id": cell_id,
                "verbose": verbose,
                "rust_log": rust_log.label(),
                "exit_code": output.status.code(),
                "stdout_hex": hex::encode(&output.stdout),
                "stderr_hex": hex::encode(&output.stderr),
                "panic_observed": false,
                "redaction_canary_absent": true,
                "replay": REPLAY
            })
        );
    }

    println!(
        "{}",
        json!({
            "schema_version": "offline-tuner-logging-parity-panic-disposition-v1",
            "safe_reachable_panic_case": null,
            "disposition": "NO_SAFE_REACHABLE_PANIC_PATH_IDENTIFIED",
            "covered_nonpanic_failures": 5,
            "replay": REPLAY
        })
    );
}

#[test]
fn invalid_rust_log_never_echoes_a_secret_after_cutover() {
    let temp = tempfile::tempdir().expect("invalid-filter tempdir");
    let output = run_binary(
        &temp.path().join("invalid-filter-output"),
        &[
            OsString::from("candidates"),
            OsString::from("--arch"),
            OsString::from("scalar"),
        ],
        false,
        RustLogCell::InvalidCanary,
    );
    assert_eq!(output.status.code(), Some(0));

    let incumbent_canary_echo = output
        .stderr
        .windows(CANARY.len())
        .any(|window| window == CANARY.as_bytes());
    let incumbent_baseline = std::env::var_os("ASUPERSYNC_EXPECT_INCUMBENT_ENV_LOGGER").is_some();
    if incumbent_baseline {
        assert!(
            incumbent_canary_echo,
            "incumbent baseline no longer demonstrates the expected env_filter echo"
        );
    } else {
        assert!(
            !incumbent_canary_echo,
            "invalid RUST_LOG echoed secret material to stderr"
        );
        assert!(
            output.stderr.is_empty(),
            "post-cutover invalid RUST_LOG must not create an orphan diagnostic channel"
        );
    }

    let redacted_stderr = String::from_utf8_lossy(&output.stderr)
        .replace(CANARY, "[REDACTED_CANARY]")
        .into_bytes();
    println!(
        "{}",
        json!({
            "schema_version": "offline-tuner-invalid-rust-log-v1",
            "cell_id": "candidates__concise__rust_log_invalid_canary",
            "incumbent_baseline": incumbent_baseline,
            "incumbent_canary_echo_observed": incumbent_canary_echo,
            "exit_code": output.status.code(),
            "stdout_hex": hex::encode(&output.stdout),
            "redacted_stderr_hex": hex::encode(redacted_stderr),
            "raw_secret_retained": false,
            "replay": REPLAY
        })
    );
}
