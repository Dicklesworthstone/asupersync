//! Contract tests for the ARQ/QUIC H2/H5 E2E script surfaces.
//!
//! These tests intentionally exercise offline validation and structure paths.
//! The full loopback transfer is run through `scripts/run_arq_quic_loopback_e2e.sh`
//! via RCH for H5 closeout evidence.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "arq_quic_scripts_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn unique_artifact_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    repo_root().join("artifacts/arq_quic_e2e").join(format!(
        "{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write file");
}

fn write_fixture(dir: &Path, sha_match: bool) {
    let event_lines = [
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:00Z","stage":"setup","status":"started","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:01Z","stage":"receiver_ready","status":"passed","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:02Z","stage":"sender_transfer","status":"passed","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:03Z","stage":"sha256_verify","status":"passed","message":"fixture"}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:04Z","stage":"summary","status":"passed","message":"fixture","details":{"transport_counters":{"no_claim":"fixture no-claim"}}}"#,
        r#"{"schema_version":"arq-quic-e2e-event-v1","ts":"2026-06-17T00:00:04Z","stage":"offline_validation","status":"passed","message":"fixture"}"#,
    ];
    write_file(
        &dir.join("events.ndjson"),
        &format!("{}\n", event_lines.join("\n")),
    );

    let summary = format!(
        r#"{{
  "schema_version": "arq-quic-loopback-e2e-summary-v1",
  "status": "passed",
  "transport": "quic",
  "bytes_sent": 8192,
  "bytes_received": 8192,
  "sender": {{"event":"atp_send","transport":"quic","committed":true,"bytes_sent":8192}},
  "receiver": {{"event":"atp_receive","transport":"quic","committed":true,"bytes_received":8192}},
  "sha256_match": {sha_match},
  "metrics": {{
    "sender_max_rss_kb": 12345,
    "receiver_max_rss_kb": 23456,
    "peak_max_rss_kb": 23456,
    "sender_elapsed_raw":"0:00.01",
    "receiver_elapsed_raw":"0:00.02",
    "sender_elapsed_seconds": 0.01,
    "receiver_elapsed_seconds": 0.02,
    "transfer_elapsed_seconds": 0.01,
    "goodput_bytes_per_second": 819200.0,
    "goodput_bits_per_second": 6553600.0,
    "symbol_loss_rate": 0.0,
    "feedback_rounds_total": 0,
    "decode_time_per_block_micros": 25.0
  }},
  "transport_counters": {{
    "source":"atp-cli-json",
    "symbols_sent": 64,
    "symbols_accepted": 64,
    "feedback_rounds_sender": 0,
    "feedback_rounds_receiver": 0,
    "decode_count": 1,
    "decode_micros": 25,
    "symbols_sent_available": true,
    "symbols_accepted_available": true,
    "feedback_rounds_available": true,
    "decode_count_available": true,
    "decode_micros_available": true,
    "no_claim": "fixture decode metrics no-claim"
  }},
  "artifacts": {{"events_ndjson":"events.ndjson"}}
}}"#
    );
    write_file(&dir.join("summary.json"), &summary);
}

fn read_lossy(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| format!("<unavailable: {err}>"))
}

fn real_loopback_debug_dump(root: &Path) -> String {
    [
        ("events.ndjson", root.join("events.ndjson")),
        ("summary.json", root.join("summary.json")),
        ("sender.json", root.join("sender.json")),
        ("receiver.json", root.join("receiver.json")),
        ("sender.stderr", root.join("sender.stderr")),
        ("receiver.stderr", root.join("receiver.stderr")),
        ("sender.time.txt", root.join("sender.time.txt")),
        ("receiver.time.txt", root.join("receiver.time.txt")),
        ("certs.log", root.join("certs.log")),
    ]
    .into_iter()
    .map(|(label, path)| format!("--- {label} ---\n{}", read_lossy(&path)))
    .collect::<Vec<_>>()
    .join("\n")
}

#[test]
fn loopback_from_output_accepts_valid_retained_artifacts() {
    let root = unique_tmp("valid");
    write_fixture(&root, true);

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        output.status.success(),
        "validator rejected valid fixture; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_corrupted_summary() {
    let root = unique_tmp("corrupt");
    write_fixture(&root, false);

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted corrupted fixture; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_missing_counter_values_even_when_flags_claim_available() {
    let root = unique_tmp("missing_counter");
    write_fixture(&root, true);

    let summary_path = root.join("summary.json");
    let summary = std::fs::read_to_string(&summary_path).expect("read summary fixture");
    write_file(
        &summary_path,
        &summary.replace(
            r#""feedback_rounds_receiver": 0"#,
            r#""feedback_rounds_receiver": null"#,
        ),
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted unavailable feedback counter hidden by availability flag; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_missing_receiver_rss_metric() {
    let root = unique_tmp("missing_receiver_rss");
    write_fixture(&root, true);

    let summary_path = root.join("summary.json");
    let summary = std::fs::read_to_string(&summary_path).expect("read summary fixture");
    write_file(
        &summary_path,
        &summary.replace(
            r#""receiver_max_rss_kb": 23456"#,
            r#""receiver_max_rss_kb": null"#,
        ),
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted missing receiver RSS metric; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_missing_goodput_metric() {
    let root = unique_tmp("missing_goodput");
    write_fixture(&root, true);

    let summary_path = root.join("summary.json");
    let summary = std::fs::read_to_string(&summary_path).expect("read summary fixture");
    write_file(
        &summary_path,
        &summary.replace(
            r#""goodput_bytes_per_second": 819200.0"#,
            r#""goodput_bytes_per_second": null"#,
        ),
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted missing goodput metric; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_out_of_range_symbol_loss_metric() {
    let root = unique_tmp("bad_symbol_loss");
    write_fixture(&root, true);

    let summary_path = root.join("summary.json");
    let summary = std::fs::read_to_string(&summary_path).expect("read summary fixture");
    write_file(
        &summary_path,
        &summary.replace(r#""symbol_loss_rate": 0.0"#, r#""symbol_loss_rate": 1.25"#),
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted out-of-range symbol-loss metric; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loopback_from_output_rejects_missing_decode_time_metric() {
    let root = unique_tmp("missing_decode_time");
    write_fixture(&root, true);

    let summary_path = root.join("summary.json");
    let summary = std::fs::read_to_string(&summary_path).expect("read summary fixture");
    write_file(
        &summary_path,
        &summary.replace(
            r#""decode_time_per_block_micros": 25.0"#,
            r#""decode_time_per_block_micros": null"#,
        ),
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("run loopback from-output validator");

    assert!(
        !output.status.success(),
        "validator accepted missing decode-time metric; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lossy_quic_script_no_longer_xfails_f1_data_loss_floor() {
    let script =
        std::fs::read_to_string(repo_root().join("scripts/atp_e2e_lossy.sh")).expect("read script");

    for eps in ["0.01", "0.05", "0.10"] {
        let key = format!("quic:{eps}=");
        assert!(
            !script.contains(&key),
            "F1-fixed data-loss eps={eps} must be a real PASS/FAIL gate, not a default XFAIL"
        );
    }
    assert!(
        script.contains("quic:0.20=G4.2/F6:extreme-loss-control-recovery-budget"),
        "the only default data-loss XFAIL should be the extreme F6/control-budget follow-up"
    );
    assert!(
        !script.contains("no-loss-repair-until-receiver-decode-on-arrival"),
        "stale F1-not-landed wording must not remain in the lossy QUIC gate"
    );
}

#[test]
fn fleet_script_structure_validation_is_no_claim_and_deterministic() {
    let script_path = repo_root().join("scripts/run_arq_quic_fleet_e2e.sh");
    let script = std::fs::read_to_string(&script_path).expect("read fleet script");
    let bench_script_path = repo_root().join("scripts/atp_quic_vs_rsync_benchmark.sh");
    let bench_script =
        std::fs::read_to_string(&bench_script_path).expect("read fleet bench script");
    assert!(
        script.contains(r#"export METHODS="atpquic""#),
        "fleet wrapper must force the H5-owned atpquic method instead of inheriting METHODS"
    );
    assert!(
        bench_script.contains("RUN_ID"),
        "fleet bench script must scope normal runs under a retained unique run id"
    );
    assert!(
        bench_script.contains("artifacts/arq_quic_e2e"),
        "fleet bench script must default local artifacts under artifacts/arq_quic_e2e"
    );
    assert!(
        bench_script.contains("tcpdump"),
        "G1 fleet runs must retain packet evidence when tcpdump is available"
    );
    assert!(
        !bench_script.contains("-delete"),
        "fleet bench script must not delete remote work-dir contents during normal runs"
    );
    assert!(
        !bench_script.contains("rm -f"),
        "fleet bench script must not remove prior receiver artifacts during normal runs"
    );
    assert!(
        !bench_script.contains("rmdir "),
        "fleet bench script must retain destination directories for inspection"
    );
    assert!(
        !bench_script.contains("pkill -f"),
        "fleet bench script must not terminate unrelated receiver processes to make a port clean"
    );

    let output = Command::new(repo_root().join("scripts/run_arq_quic_fleet_e2e.sh"))
        .arg("--validate-structure")
        .output()
        .expect("run fleet structure validator");

    assert!(
        output.status.success(),
        "fleet structure validation failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""schema_version": "arq-quic-fleet-e2e-structure-v1""#));
    assert!(stdout.contains(r#""forced_methods": "atpquic""#));
    assert!(stdout.contains(r#""local_default_root": "#));
    assert!(stdout.contains(r#""remote_default_root": "/tmp/atp_bench/runs/<RUN_ID>""#));
    assert!(stdout.contains(r#""packet_evidence": "#));
    assert!(stdout.contains(r#""retained_remote_dst""#));
    assert!(stdout.contains(r#""tcpdump_status""#));
    assert!(stdout.contains("destination directories are retained"));
    assert!(stdout.contains("G1/G2 own two-machine evidence"));
}

#[test]
fn atp_bench_resource_guard_is_first_class_report_artifact() {
    let root = unique_tmp("bench_resource_guard");
    let results = root.join("results.jsonl");
    let conditions = root.join("conditions.json");
    write_file(
        &conditions,
        r#"{
  "date": "2026-06-17T00:00:00Z",
  "sender": "fixture-sender",
  "receiver": "fixture-receiver",
  "rtt": "fixture",
  "sender_cores": 4,
  "receiver_cores": 4,
  "runs": 2,
  "max_load_per_core": 1.5,
  "max_sender_rss_mb": 64,
  "max_receiver_rss_mb": 64
}"#,
    );
    write_file(
        &results,
        r#"{"tool":"atp-quic","payload":"10m","run":1,"verify_ok":true,"sender":{"wall_s":2.0,"bytes":10485760,"max_rss_kb":32768,"user_s":0.5,"sys_s":0.25,"cycles":1000000000,"instructions":2000000000,"avg_core_util_pct":55,"load1_start":1.0,"load1_end":1.2},"receiver_sampler":{"peak_rss_kb":40960,"avg_rss_kb":30000,"peak_cpu_pct":40,"avg_cpu_pct":25,"peak_load1":1.4},"receiver_time":{"max_rss_kb":42000},"resource_guard":{"schema_version":"atp-bench-resource-guard-v1","ok":true,"checks":[{"name":"sender_load1","observed":1.2,"limit":6.0,"unit":"loadavg","passed":true},{"name":"receiver_load1","observed":1.4,"limit":6.0,"unit":"loadavg","passed":true},{"name":"sender_peak_rss","observed":32.0,"limit":64.0,"unit":"MiB","passed":true},{"name":"receiver_peak_rss","observed":41.0,"limit":64.0,"unit":"MiB","passed":true}],"configured":{"max_load_per_core":1.5,"max_sender_rss_mb":64,"max_receiver_rss_mb":64}}}
{"tool":"atp-quic","payload":"10m","run":2,"verify_ok":true,"sender":{"wall_s":2.2,"bytes":10485760,"max_rss_kb":32768,"user_s":0.55,"sys_s":0.25,"cycles":1000000000,"instructions":2000000000,"avg_core_util_pct":58,"load1_start":1.0,"load1_end":1.2},"receiver_sampler":{"peak_rss_kb":90112,"avg_rss_kb":50000,"peak_cpu_pct":40,"avg_cpu_pct":25,"peak_load1":7.2},"receiver_time":{"max_rss_kb":90112},"resource_guard":{"schema_version":"atp-bench-resource-guard-v1","ok":false,"checks":[{"name":"sender_load1","observed":1.2,"limit":6.0,"unit":"loadavg","passed":true},{"name":"receiver_load1","observed":7.2,"limit":6.0,"unit":"loadavg","passed":false},{"name":"sender_peak_rss","observed":32.0,"limit":64.0,"unit":"MiB","passed":true},{"name":"receiver_peak_rss","observed":88.0,"limit":64.0,"unit":"MiB","passed":false}],"configured":{"max_load_per_core":1.5,"max_sender_rss_mb":64,"max_receiver_rss_mb":64}}}
"#,
    );

    let output = Command::new("python3")
        .arg(repo_root().join("scripts/atp_bench/report.py"))
        .arg(&results)
        .arg(&conditions)
        .output()
        .expect("run atp bench report");

    assert!(
        output.status.success(),
        "report rejected resource guard fixture; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("## Resource Guard"));
    assert!(stdout.contains("load1 <= 1.5x cores"));
    assert!(stdout.contains("| 10m | atp-quic | 1/2 |"));
    assert!(stdout.contains("receiver_peak_rss"));
    assert!(stdout.contains("| FAIL |"));
    assert!(stdout.contains("FAILED the RSS/load resource guard"));

    let run_bench = std::fs::read_to_string(repo_root().join("scripts/atp_bench/run_bench.sh"))
        .expect("read atp bench runner");
    for required in [
        "--max-load-per-core",
        "--max-sender-rss-mb",
        "--max-receiver-rss-mb",
        "atp-bench-resource-guard-v1",
        r#"\"resource_guard\":$resource_guard"#,
    ] {
        assert!(
            run_bench.contains(required),
            "run_bench must contain {required}"
        );
    }
}

#[test]
#[ignore = "runs the real atp QUIC loopback; invoke explicitly through RCH"]
fn loopback_script_runs_real_atp_binary() {
    let atp_bin = std::env::var_os("CARGO_BIN_EXE_atp")
        .map(PathBuf::from)
        .expect("CARGO_BIN_EXE_atp must be available; run with --features atp-cli,tls");
    let root = unique_artifact_dir("h5_loopback");

    let output = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .env("ATP_BIN", &atp_bin)
        .env("ARQ_QUIC_OUTPUT_DIR", &root)
        .env("ARQ_QUIC_PAYLOAD_BYTES", "8192")
        .output()
        .expect("run real loopback script");

    assert!(
        output.status.success(),
        "real loopback script failed at {}; stdout: {}; stderr: {}\n{}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        real_loopback_debug_dump(&root)
    );

    let validate = Command::new(repo_root().join("scripts/run_arq_quic_loopback_e2e.sh"))
        .args(["--from-output", root.to_str().unwrap()])
        .output()
        .expect("validate retained real loopback artifacts");

    assert!(
        validate.status.success(),
        "retained real loopback artifacts failed validation; stdout: {}; stderr: {}\n{}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr),
        real_loopback_debug_dump(&root)
    );

    let summary = std::fs::read_to_string(root.join("summary.json")).expect("read summary");
    let events = std::fs::read_to_string(root.join("events.ndjson")).expect("read events");

    assert!(summary.contains(r#""schema_version": "arq-quic-loopback-e2e-summary-v1""#));
    assert!(summary.contains(r#""transport": "quic""#));
    assert!(summary.contains(r#""sha256_match": true"#));
    assert!(summary.contains(r#""sender_max_rss_kb":"#));
    assert!(summary.contains(r#""receiver_max_rss_kb":"#));
    assert!(summary.contains(r#""peak_max_rss_kb":"#));
    assert!(summary.contains(r#""symbols_sent_available": true"#));
    assert!(summary.contains(r#""symbols_accepted_available": true"#));
    assert!(summary.contains(r#""feedback_rounds_available": true"#));
    assert!(summary.contains(r#""decode_count_available": true"#));
    assert!(summary.contains(r#""decode_micros_available": true"#));
    assert!(events.contains(r#""stage":"receiver_ready","status":"passed""#));
    assert!(events.contains(r#""stage":"sender_transfer","status":"passed""#));
    assert!(events.contains(r#""stage":"sha256_verify","status":"passed""#));
}
