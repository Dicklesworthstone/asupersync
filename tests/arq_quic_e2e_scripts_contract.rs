//! Contract tests for the ARQ/QUIC H2/H5 E2E script surfaces.
//!
//! These tests intentionally exercise offline validation and structure paths.
//! The full loopback transfer is run through `scripts/run_arq_quic_loopback_e2e.sh`
//! via RCH for H5 closeout evidence.

#![allow(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

#[cfg(unix)]
#[test]
fn atp_bench_rq_auth_keys_use_protected_stdin_only() {
    let scripts = repo_root().join("scripts/atp_bench");
    let run_bench_path = scripts.join("run_bench.sh");
    let run_bench =
        std::fs::read_to_string(&run_bench_path).expect("read atp fleet benchmark runner");
    let run_matrix = std::fs::read_to_string(scripts.join("run_matrix_cell.sh"))
        .expect("read atp matrix cell runner");
    let matrix_plan =
        std::fs::read_to_string(scripts.join("matrix_bench.sh")).expect("read atp matrix planner");
    let run_one_path = scripts.join("run_one.sh");
    let run_one = std::fs::read_to_string(&run_one_path).expect("read sender run helper");
    let score_matrix_path = scripts.join("score_matrix.py");
    let score_matrix =
        std::fs::read_to_string(&score_matrix_path).expect("read matrix scorecard generator");
    let readme = std::fs::read_to_string(scripts.join("README.md")).expect("read benchmark README");
    let matrix_doc =
        std::fs::read_to_string(scripts.join("MATRIX.md")).expect("read matrix runbook");
    let agents = std::fs::read_to_string(repo_root().join("AGENTS.md")).expect("read AGENTS");
    let matrix_spec = std::fs::read_to_string(repo_root().join("docs/atp_bench_matrix_spec.md"))
        .expect("read matrix specification");

    for (name, script) in [
        ("run_bench", &run_bench),
        ("run_matrix", &run_matrix),
        ("matrix_plan", &matrix_plan),
    ] {
        for forbidden in [
            "--rq-auth-key-hex",
            "ATP_RQ_AUTH_KEY_HEX=",
            "ATP_RQ_AUTH_KEY_HEX='",
            "env ATP_RQ_AUTH_KEY_HEX=",
        ] {
            assert!(
                !script.contains(forbidden),
                "{name} must not contain secret-bearing command pattern {forbidden}"
            );
        }
        for line in script.lines().filter(|line| line.contains("/usr/bin/time")) {
            assert!(
                !line.contains("$RQ_AUTH_SECRET"),
                "{name} time command must not interpolate the RQ key: {line}"
            );
        }
    }

    assert!(!run_bench.contains("--atp-rq-auth-key-hex"));
    assert!(run_bench.contains("--atp-rq-auth-key-stdin"));
    assert!(run_bench.contains("ATP_RQ_AUTH_KEY_HEX is forbidden"));
    assert!(run_bench.contains("RQ_AUTH_KEY_HEX is forbidden"));
    assert!(run_bench.contains("[[ ! -t 0 ]]"));
    assert!(run_bench.contains("data = sys.stdin.buffer.read(66)"));
    assert!(run_bench.contains("len(data) == 65"));
    assert!(run_bench.contains("all(byte in b\"0123456789abcdefABCDEF\""));
    let protected_read = run_bench
        .find("RQ_AUTH_SECRET=$(/usr/bin/python3 -c")
        .expect("bounded raw protected input read");
    let dated_defaults = run_bench
        .find("OUT=\"${OUT:-artifacts/atp_bench/$(date")
        .expect("dated defaults after argument parsing");
    assert!(
        protected_read < dated_defaults,
        "no external default helper may inherit protected stdin before it is drained"
    );
    assert!(run_bench.contains("SSH_S_OPTS=(-T -x"));
    assert!(run_bench.contains("SSH_R_OPTS=(-T -x"));
    assert!(run_bench.contains("SSH_S=(ssh \"${SSH_S_OPTS[@]}\" -- \"$SENDER\")"));
    assert!(run_bench.contains("SSH_R=(ssh \"${SSH_R_OPTS[@]}\" -- \"$RECEIVER\")"));
    for safe_option in [
        "BatchMode=yes",
        "StdinNull=no",
        "ForkAfterAuthentication=no",
        "SessionType=default",
        "PermitLocalCommand=no",
        "LocalCommand=none",
        "RemoteCommand=none",
        "KnownHostsCommand=none",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
    ] {
        assert_eq!(
            run_bench.matches(safe_option).count(),
            2,
            "both fleet SSH commands must force {safe_option}"
        );
    }
    assert_eq!(run_bench.matches("-S none").count(), 2);
    assert!(run_bench.contains("SSH_STDIN_CONFIG_CANARY_PATH=/__atp_ssh_stdin_preflight_canary__"));
    assert!(run_bench.contains("ssh \"${options_ref[@]}\" -G -- \"$host\" \"$remote_command\""));
    assert!(run_bench.contains("ssh_secret_stdin_preflight SSH_R_OPTS"));
    assert!(run_bench.contains("ssh_secret_stdin_preflight SSH_S_OPTS"));
    let early_sender_preflight = run_bench
        .find("ssh_secret_stdin_preflight SSH_S_OPTS \"$SENDER\" \"true\"")
        .expect("early sender SSH config gate");
    let early_receiver_preflight = run_bench
        .find("ssh_secret_stdin_preflight SSH_R_OPTS \"$RECEIVER\" \"true\"")
        .expect("early receiver SSH config gate");
    let early_preflight_guard = run_bench
        .find("if ((HAS_ATP_RQ)); then")
        .expect("RQ-only early SSH config gate");
    assert!(early_preflight_guard < early_sender_preflight);
    assert!(run_bench.contains("receiver_host_is_safe \"$RECEIVER_IP\""));
    let receiver_validation = run_bench
        .find("receiver_host_is_safe \"$RECEIVER_IP\"")
        .expect("derived receiver HostName validation");
    let first_local_write = run_bench
        .find("mkdir -p \"$OUT\"")
        .expect("first local output write");
    assert!(
        receiver_validation < first_local_write,
        "derived receiver HostName must fail closed before deployment or local output writes"
    );
    let first_fleet_contact = run_bench
        .find("\"${SSH_S[@]}\" \"mkdir -p")
        .expect("first fleet-mutating SSH command");
    assert!(
        early_sender_preflight < first_local_write
            && early_receiver_preflight < first_local_write
            && early_sender_preflight < first_fleet_contact
            && early_receiver_preflight < first_fleet_contact,
        "both effective SSH configs must pass before any local output or fleet mutation"
    );
    let tool_validation = run_bench
        .find("for tool in \"${TOOL_LIST[@]}\"; do")
        .expect("tool allowlist loop");
    assert!(
        tool_validation < first_local_write,
        "tool names must be allowlisted before entering any remote path"
    );
    let byte_count_guard = run_bench
        .find("[[ \"$bytes\" =~ ^[0-9]+$ ]]")
        .expect("remote payload byte-count guard");
    let secret_sender_command = run_bench
        .find("sender_command=\"env -u ATP_RQ_AUTH_KEY_HEX")
        .expect("secret-bearing sender command");
    assert!(
        byte_count_guard < secret_sender_command,
        "remote byte count must be validated before shell command construction"
    );
    let exact_receiver_preflight = run_bench
        .find("ssh_secret_stdin_preflight SSH_R_OPTS \"$RECEIVER\" \"$receiver_command\"")
        .expect("exact receiver command preflight");
    let exact_sender_preflight = run_bench
        .find("ssh_secret_stdin_preflight SSH_S_OPTS \"$SENDER\" \"$sender_command\"")
        .expect("exact sender command preflight");
    let first_secret_delivery = run_bench
        .find("send_rq_auth_secret | \"${SSH_R[@]}\"")
        .expect("receiver secret delivery");
    assert!(
        exact_receiver_preflight < first_secret_delivery
            && exact_sender_preflight < first_secret_delivery,
        "both exact commands must pass preflight before either secret-bearing session starts"
    );
    for dangerous_effective_config in [
        "forkafterauthentication",
        "sessiontype",
        "localcommand|remotecommand",
        "proxycommand",
        "identityfile|certificatefile|revokedhostkeys",
        "userknownhostsfile|globalknownhostsfile",
        "revokedhostkeys|pkcs11provider|securitykeyprovider|xauthlocation",
        "^/(dev|proc)(/[^/]+)*/fd/0$",
        "[[ \"$path\" == *%* ]]",
        "/usr/bin/readlink -fz -- \"$path\" /dev/stdin",
        "ssh_path_list_targets_protected_stdin",
        "consumed the public stdin canary",
    ] {
        assert!(
            run_bench.contains(dangerous_effective_config),
            "effective-config preflight must cover {dangerous_effective_config}"
        );
    }
    assert!(run_bench.contains("unset ATP_RQ_AUTH_KEY_HEX RQ_AUTH_SECRET"));
    assert!(run_bench.contains("env -u ATP_RQ_AUTH_KEY_HEX"));
    assert!(run_bench.contains("--rq-auth-key-stdin <&0"));
    assert_eq!(
        run_bench.matches("send_rq_auth_secret |").count(),
        2,
        "fleet runner must feed exactly the RQ receiver and sender"
    );
    for line in run_bench
        .lines()
        .filter(|line| line.contains("${SSH_S[@]}") || line.contains("${SSH_R[@]}"))
    {
        assert!(
            !line.contains("$RQ_AUTH_SECRET"),
            "SSH command text must not interpolate the RQ key: {line}"
        );
    }

    assert!(run_matrix.contains("RQ_AUTH_KEY_HEX is forbidden"));
    assert!(run_matrix.contains("ATP_RQ_AUTH_KEY_HEX is forbidden"));
    assert!(run_matrix.contains("RQ_AUTH_SECRET=$(env -u ATP_RQ_AUTH_KEY_HEX"));
    assert!(run_matrix.contains("auth_recv=(--rq-auth-key-stdin)"));
    assert!(run_matrix.contains("auth_send=(--rq-auth-key-stdin)"));
    assert!(run_matrix.contains("atp-quic-tls13)         run_atp tls quic"));
    assert!(!run_matrix.contains("atp-quic-tls13-xauth"));
    assert!(!matrix_plan.contains("encrypted-xauth"));
    assert!(matrix_plan.contains("ATP_RQ_AUTH_KEY_HEX is forbidden"));
    assert!(matrix_plan.contains("RQ_AUTH_KEY_HEX is forbidden"));
    assert!(matrix_plan.contains("expected_auth_posture"));
    assert!(matrix_plan.contains("row.get(\"auth_posture\") == expected_auth_posture"));
    assert!(run_matrix.contains("ROW_AUTH=\"$AUTH_POSTURE\""));
    assert!(run_matrix.contains("\"auth_posture\": e(\"ROW_AUTH\", \"\")"));
    let planner_guard = matrix_plan
        .find("ATP_RQ_AUTH_KEY_HEX is forbidden")
        .expect("planner legacy environment guard");
    let planner_helpers = matrix_plan
        .find("SCRIPT_DIR=\"")
        .expect("planner command substitutions");
    assert!(
        planner_guard < planner_helpers,
        "matrix planner must reject secret environments before spawning helpers"
    );
    assert!(
        !run_matrix.contains("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        run_matrix.matches("send_rq_auth_secret |").count(),
        2,
        "matrix runner must feed exactly the authenticated RQ receiver and sender"
    );

    assert!(run_one.contains("mpstat -P ALL 1 </dev/null"));
    assert!(run_one.contains("perf stat -e task-clock true </dev/null"));
    for (name, doc) in [
        ("README", &readme),
        ("MATRIX", &matrix_doc),
        ("AGENTS", &agents),
        ("matrix spec", &matrix_spec),
    ] {
        assert!(
            !doc.contains("--rq-auth-key-hex"),
            "{name} must not advertise the legacy secret argv flag"
        );
    }
    assert!(readme.contains("--atp-rq-auth-key-stdin"));
    assert!(matrix_doc.contains("fresh key over protected stdin"));
    assert!(matrix_doc.contains("The old `RQ_AUTH_KEY_HEX`"));
    assert!(matrix_doc.contains("environment inputs are rejected"));
    assert!(readme.contains("neither rewrites nor deletes existing artifacts"));
    assert!(matrix_doc.contains("does not rewrite or delete old artifacts"));
    assert!(matrix_doc.contains("resume key now includes an explicit auth-posture gate"));
    assert!(matrix_doc.contains("older rows without that field"));
    for legacy_name in [
        "send.time",
        "recv.time",
        "recv_time.txt",
        "atp_bench_one.*/time.txt",
    ] {
        assert!(
            readme.contains(legacy_name) || matrix_doc.contains(legacy_name),
            "retention guidance must name legacy artifact {legacy_name}"
        );
    }
    assert!(score_matrix.contains("auth_posture_exclusion_reason"));
    assert!(score_matrix.contains("QUIC_TLS13_AUTH_POSTURE"));
    assert!(score_matrix.contains("Auth-posture exclusions"));

    let reject_input = |input: &[u8]| {
        let mut child = Command::new(&run_bench_path)
            .args([
                "--sender",
                "unused-sender.invalid",
                "--receiver",
                "unused-receiver.invalid",
                "--tools",
                "atp-rq",
                "--atp-rq-auth-key-stdin",
            ])
            .env_remove("ATP_RQ_AUTH_KEY_HEX")
            .env_remove("RQ_AUTH_KEY_HEX")
            .env_remove("RQ_AUTH_SECRET")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fleet runner fail-fast input fixture");
        child
            .stdin
            .take()
            .expect("fixture stdin")
            .write_all(input)
            .expect("write fixture input");
        let output = child.wait_with_output().expect("wait for input rejection");
        assert!(!output.status.success());
        assert_eq!(output.status.code(), Some(2));
        output
    };

    let malformed =
        reject_input(b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeefg\n");
    assert!(
        String::from_utf8_lossy(&malformed.stderr)
            .contains("ATP RQ auth stdin must contain exactly one 64-hex line")
    );
    let missing_newline =
        reject_input(b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    assert!(
        String::from_utf8_lossy(&missing_newline.stderr)
            .contains("ATP RQ auth stdin must contain exactly one 64-hex line")
    );
    let trailing =
        reject_input(b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\nX");
    assert!(
        String::from_utf8_lossy(&trailing.stderr)
            .contains("ATP RQ auth stdin must contain exactly one 64-hex line")
    );
    let trailing_nul =
        reject_input(b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\0");
    assert!(
        String::from_utf8_lossy(&trailing_nul.stderr)
            .contains("ATP RQ auth stdin must contain exactly one 64-hex line")
    );

    let valid_secret = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
    let reject_unsafe_arg_for_tools = |tools: &str, flag: &str, value: &str| {
        let mut child = Command::new("/bin/bash")
            .arg(&run_bench_path)
            .args([
                "--sender",
                "unused-sender.invalid",
                "--receiver",
                "unused-receiver.invalid",
                "--tools",
                tools,
                "--atp-rq-auth-key-stdin",
                flag,
                value,
            ])
            .env("PATH", "/definitely-not-a-command-path")
            .env_remove("ATP_RQ_AUTH_KEY_HEX")
            .env_remove("RQ_AUTH_KEY_HEX")
            .env_remove("RQ_AUTH_SECRET")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fail-fast CLI validation fixture");
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(valid_secret);
        }
        let output = child
            .wait_with_output()
            .expect("wait for CLI validation rejection");
        assert_eq!(output.status.code(), Some(2));
        let mut diagnostics = output.stdout;
        diagnostics.extend_from_slice(&output.stderr);
        assert!(
            !diagnostics
                .windows(valid_secret.len() - 1)
                .any(|window| window == &valid_secret[..valid_secret.len() - 1])
        );
        diagnostics
    };
    let reject_unsafe_arg =
        |flag: &str, value: &str| reject_unsafe_arg_for_tools("atp-rq", flag, value);
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--base", "/root/bench;unexpected"))
            .contains("--base must be an absolute shell-safe path")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg(
            "--atp-rq-symbol-size",
            "1024$(unexpected)"
        ))
        .contains("--atp-rq-symbol-size must be an integer from 1 through 65535")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--atp-rq-max-block-size", "auto'broken"))
            .contains("--atp-rq-max-block-size must be auto or a 64-bit byte count")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--atp-rq-symbol-size", "65536"))
            .contains("--atp-rq-symbol-size must be an integer from 1 through 65535")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg(
            "--atp-rq-streams",
            "18446744073709551616"
        ))
        .contains("--atp-rq-streams must fit a positive 64-bit usize")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg(
            "--atp-rq-tail-drain-ms",
            "18446744073709551616"
        ))
        .contains("--atp-rq-tail-drain-ms must fit an unsigned 64-bit integer")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--atp-quic-handshake-timeout-ms", "0"))
            .contains(
                "--atp-quic-handshake-timeout-ms must fit a positive unsigned 64-bit integer"
            )
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg_for_tools(
            "atp-rq,atp-quic",
            "--atp-rq-symbol-size",
            "1145"
        ))
        .contains("--atp-rq-symbol-size must be no larger than 1144 when atp-quic is selected")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg(
            "--atp-rq-max-block-size",
            "17179869184G"
        ))
        .contains("--atp-rq-max-block-size must be auto or a 64-bit byte count")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--atp-rq-repair-overhead", "0.9"))
            .contains("--atp-rq-repair-overhead must be a finite decimal at least 1.0")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--run-id", ".."))
            .contains("invalid --run-id; use a non-traversing")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--tools", "unknown;unexpected"))
            .contains("--tools contains an unknown method")
    );
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--atp-binary", "-unexpected"))
            .contains("--atp-binary must be a shell-safe local path")
    );
    let huge_decimal = "9".repeat(400);
    assert!(
        String::from_utf8_lossy(&reject_unsafe_arg("--max-load-per-core", &huge_decimal))
            .contains("--max-load-per-core must be a finite nonnegative decimal")
    );

    let numeric_probe = Command::new("bash")
        .arg("-c")
        .arg(
            r#"
set -euo pipefail
source <(awk '/^is_uint\(\)/,/^while \[\[ \$# -gt 0 \]\]/ {
    if ($0 ~ /^while \[\[ \$# -gt 0 \]\]/) exit
    print
}' "$RUN_BENCH_PATH")
[[ "$(canonical_uint 0008)" == 8 ]]
positive_uint_le 65535 65535
! positive_uint_le 65536 65535
uint_le 0 18446744073709551615
uint_le 18446744073709551615 18446744073709551615
! uint_le 18446744073709551616 18446744073709551615
for value in auto AUTO 0 1K 2kb 3KiB 4M 5MiB 6G 7GiB; do
    is_valid_max_block_size "$value"
done
! is_valid_max_block_size 17179869184G
is_finite_decimal_at_least_one 1.0
! is_finite_decimal_at_least_one 0.9
"#,
        )
        .env("RUN_BENCH_PATH", &run_bench_path)
        .output()
        .expect("run bounded numeric parser fixtures");
    assert!(
        numeric_probe.status.success(),
        "bounded numeric parser fixtures failed: {}",
        String::from_utf8_lossy(&numeric_probe.stderr)
    );

    let safe_ssh_config = unique_tmp("ssh safe proxyjump config");
    write_file(
        &safe_ssh_config,
        "Host fixture-bastion\n    HostName bastion.example\n    User fixture\n\
         Host fixture-safe\n    HostName receiver.example\n    User fixture\n\
             IdentityFile %d/.ssh/id_ed25519\n    ProxyJump fixture-bastion\n",
    );
    let spaced_stdin_alias = unique_tmp("ssh stdin alias with spaces");
    std::os::unix::fs::symlink("/dev/stdin", &spaced_stdin_alias)
        .expect("create spaced protected-stdin alias");
    let spaced_identity_config = unique_tmp("ssh spaced identity config");
    write_file(
        &spaced_identity_config,
        &format!(
            "Host *\n    IdentityFile \"{}\"\n",
            spaced_stdin_alias.display()
        ),
    );
    let spaced_known_hosts_config = unique_tmp("ssh spaced known hosts config");
    write_file(
        &spaced_known_hosts_config,
        &format!(
            "Host *\n    UserKnownHostsFile \"{}\" /tmp/fixture-known-hosts\n",
            spaced_stdin_alias.display()
        ),
    );
    let ambiguous_stdin_alias = unique_tmp("ssh stdin  alias with  repeated spaces");
    std::os::unix::fs::symlink("/dev/stdin", &ambiguous_stdin_alias)
        .expect("create ambiguous protected-stdin alias");
    let ambiguous_known_hosts_config = unique_tmp("ssh ambiguous known hosts config");
    write_file(
        &ambiguous_known_hosts_config,
        &format!(
            "Host *\n    UserKnownHostsFile \"{}\" /tmp/fixture-known-hosts\n",
            ambiguous_stdin_alias.display()
        ),
    );
    let leading_path_dir = unique_tmp("ssh leading path cwd");
    std::fs::create_dir_all(&leading_path_dir).expect("create leading-path fixture directory");
    let leading_stdin_alias = leading_path_dir.join(" fd0-alias");
    std::os::unix::fs::symlink("/dev/stdin", &leading_stdin_alias)
        .expect("create leading-space protected-stdin alias");
    let leading_identity_config = unique_tmp("ssh leading identity config");
    write_file(
        &leading_identity_config,
        "Host *\n    IdentityFile \" fd0-alias\"\n",
    );

    let preflight_probe = Command::new("bash")
        .arg("-c")
        .arg(
            r#"
set -euo pipefail
source <(awk '
    /^ssh_path_targets_protected_stdin\(\)/ { emit = 1 }
    /^# Reject any effective-config collision/ { exit }
    emit { print }
' "$RUN_BENCH_PATH")
SSH_STDIN_CONFIG_CANARY_PATH=/__atp_ssh_stdin_preflight_canary__
ssh_path_targets_protected_stdin '/tmp/literal\backslash' /tmp
ssh_path_targets_protected_stdin '/tmp/literal"quote' /tmp
BASE_OPTS=(-T -x
    -o BatchMode=yes -o StdinNull=no -o RequestTTY=no
    -o ForkAfterAuthentication=no -o SessionType=default
    -o PermitLocalCommand=no -o LocalCommand=none -o RemoteCommand=none
    -o KnownHostsCommand=none
    -o ControlMaster=no -o ControlPath=none -o ControlPersist=no
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -S none)
SAFE_OPTS=("${BASE_OPTS[@]}" -F "$SAFE_SSH_CONFIG")
ISOLATED_OPTS=("${BASE_OPTS[@]}" -F /dev/null)
ssh_secret_stdin_preflight SAFE_OPTS fixture-safe "printf ready"
expect_reject() {
    local expected="$1"
    shift
    local output
    if output=$(ssh_secret_stdin_preflight "$@" 2>&1); then
        echo "fixture unexpectedly accepted: $expected" >&2
        return 1
    fi
    if [[ "$output" != *"$expected"* ]]; then
        echo "fixture rejected for the wrong reason: expected=$expected output=$output" >&2
        return 1
    fi
}
PROXY_OPTS=("${ISOLATED_OPTS[@]}" -o ProxyCommand=-)
expect_reject proxycommand PROXY_OPTS unused-proxy.invalid "printf ready"
SESSION_OPTS=(-T -x
    -F /dev/null
    -o BatchMode=yes -o StdinNull=no -o RequestTTY=no
    -o ForkAfterAuthentication=no -o SessionType=none
    -o PermitLocalCommand=no -o LocalCommand=none -o RemoteCommand=none
    -o KnownHostsCommand=none
    -o ControlMaster=no -o ControlPath=none -o ControlPersist=no
    -o ForwardAgent=no -o ForwardX11=no -S none)
expect_reject sessiontype SESSION_OPTS unused-session.invalid "printf ready"
IDENTITY_OPTS=("${ISOLATED_OPTS[@]}" -o IdentityFile=/dev/./fd/0)
expect_reject identityfile IDENTITY_OPTS unused-identity.invalid "printf ready"
PROC_ROOT_OPTS=("${ISOLATED_OPTS[@]}" -o IdentityFile=/proc/self/root/dev/stdin)
expect_reject identityfile PROC_ROOT_OPTS unused-proc-root.invalid "printf ready"
THREAD_ROOT_OPTS=("${ISOLATED_OPTS[@]}" -o IdentityFile=/proc/thread-self/root/dev/stdin)
expect_reject identityfile THREAD_ROOT_OPTS unused-thread-root.invalid "printf ready"
SPACED_IDENTITY_OPTS=("${BASE_OPTS[@]}" -F "$SPACED_IDENTITY_CONFIG")
expect_reject identityfile SPACED_IDENTITY_OPTS unused-spaced-identity.invalid "printf ready"
LEADING_IDENTITY_OPTS=("${BASE_OPTS[@]}" -F "$LEADING_IDENTITY_CONFIG")
expect_reject identityfile LEADING_IDENTITY_OPTS unused-leading-identity.invalid "printf ready"
SPACED_KNOWN_OPTS=("${BASE_OPTS[@]}" -F "$SPACED_KNOWN_CONFIG")
expect_reject userknownhostsfile SPACED_KNOWN_OPTS unused-spaced-known.invalid "printf ready"
AMBIGUOUS_KNOWN_OPTS=("${BASE_OPTS[@]}" -F "$AMBIGUOUS_KNOWN_CONFIG")
expect_reject userknownhostsfile AMBIGUOUS_KNOWN_OPTS unused-ambiguous-known.invalid "printf ready"
TOKEN_IDENTITY_OPTS=("${ISOLATED_OPTS[@]}" -o 'IdentityFile=%d/../../dev/stdin')
expect_reject identityfile TOKEN_IDENTITY_OPTS unused-token.invalid "printf ready"
ENV_IDENTITY_OPTS=("${ISOLATED_OPTS[@]}" -o 'IdentityFile=${HOME}/../../dev/stdin')
expect_reject identityfile ENV_IDENTITY_OPTS unused-env.invalid "printf ready"
TILDE_IDENTITY_OPTS=("${ISOLATED_OPTS[@]}" -o 'IdentityFile=~root/../../dev/stdin')
expect_reject identityfile TILDE_IDENTITY_OPTS unused-tilde.invalid "printf ready"
original_home="$HOME"
HOME=/a/b/c
HOSTILE_HOME_D_OPTS=("${ISOLATED_OPTS[@]}" -o 'IdentityFile=%d/../../dev/stdin')
expect_reject identityfile HOSTILE_HOME_D_OPTS unused-hostile-home-d.invalid "printf ready"
HOSTILE_HOME_TILDE_OPTS=("${ISOLATED_OPTS[@]}" -o 'IdentityFile=~/../../dev/stdin')
expect_reject identityfile HOSTILE_HOME_TILDE_OPTS unused-hostile-home-tilde.invalid "printf ready"
HOME="$original_home"
HOST_TOKEN_OPTS=("${ISOLATED_OPTS[@]}"
    -o HostName=/dev/stdin -o IdentityFile=%h -o 'ProxyCommand=nc localhost 22')
expect_reject identityfile HOST_TOKEN_OPTS unused-host-token.invalid "printf ready"
HOST_DERIVE_OPTS=(-F /dev/null -o 'HostName=127.0.0.1;cat<&0;#' -o 'ProxyCommand=nc localhost 22')
derived_host=$(ssh "${HOST_DERIVE_OPTS[@]}" -G -- unused-derived-host.invalid \
    | awk '$1 == "hostname" { print $2; exit }')
if receiver_host_is_safe "$derived_host"; then
    echo "hostile effective HostName passed shell-safe validation" >&2
    exit 1
fi
for safe_host in receiver.example 192.0.2.10 2001:db8::10 fe80::1%eth0; do
    receiver_host_is_safe "$safe_host"
done
INCLUDE_OPTS=("${BASE_OPTS[@]}" -F /dev/stdin)
expect_reject "stdin canary" INCLUDE_OPTS unused-include.invalid "printf ready"
"#,
        )
        .current_dir(&leading_path_dir)
        .env("RUN_BENCH_PATH", &run_bench_path)
        .env("SAFE_SSH_CONFIG", &safe_ssh_config)
        .env("SPACED_IDENTITY_CONFIG", &spaced_identity_config)
        .env("SPACED_KNOWN_CONFIG", &spaced_known_hosts_config)
        .env("AMBIGUOUS_KNOWN_CONFIG", &ambiguous_known_hosts_config)
        .env("LEADING_IDENTITY_CONFIG", &leading_identity_config)
        .output()
        .expect("run effective SSH config preflight fixtures");
    assert!(
        preflight_probe.status.success(),
        "SSH config preflight fixtures failed: {}",
        String::from_utf8_lossy(&preflight_probe.stderr)
    );

    let mut run_one_stdin_probe = Command::new(&run_one_path)
        .args([
            "protected-stdin-fixture",
            "0",
            "--",
            "/bin/sh",
            "-c",
            "IFS= read -r line && [ \"$line\" = stdin-line-fixture-4f2d ]",
        ])
        .env_remove("ATP_RQ_AUTH_KEY_HEX")
        .env_remove("RQ_AUTH_KEY_HEX")
        .env_remove("RQ_AUTH_SECRET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn run_one protected-stdin probe");
    run_one_stdin_probe
        .stdin
        .take()
        .expect("run_one fixture stdin")
        .write_all(b"stdin-line-fixture-4f2d\n")
        .expect("write run_one protected-stdin fixture");
    let run_one_stdin_probe = run_one_stdin_probe
        .wait_with_output()
        .expect("wait for run_one protected-stdin probe");
    let mut run_one_diagnostics = run_one_stdin_probe.stdout.clone();
    run_one_diagnostics.extend_from_slice(&run_one_stdin_probe.stderr);
    assert!(
        run_one_stdin_probe.status.success()
            && String::from_utf8_lossy(&run_one_stdin_probe.stdout).contains("\"status\":0"),
        "run_one did not preserve command stdin: {}",
        String::from_utf8_lossy(&run_one_diagnostics)
    );
    assert!(
        !String::from_utf8_lossy(&run_one_diagnostics).contains("stdin-line-fixture-4f2d"),
        "run_one echoed the protected stdin line"
    );

    let legacy_resume_fixture = unique_tmp("auth_posture_resume_legacy").with_extension("jsonl");
    write_file(
        &legacy_resume_fixture,
        r#"{"workload":"500K","regime":"perfect","crypto_tier":"encrypted","method":"atp-quic-tls13","rep":1,"status":"ok"}
"#,
    );
    let current_resume_fixture = unique_tmp("auth_posture_resume_current").with_extension("jsonl");
    write_file(
        &current_resume_fixture,
        r#"{"workload":"500K","regime":"perfect","crypto_tier":"encrypted","method":"atp-quic-tls13","auth_posture":"quic-tls13-transport-aead-v1","rep":1,"status":"ok"}
"#,
    );
    let run_resume_probe = |results_jsonl: &Path| {
        Command::new("bash")
            .arg("-c")
            .arg(
                r#"
set -euo pipefail
source <(awk '/^cell_done\(\)/,/^write_plan_row\(\)/ {
    if ($0 ~ /^write_plan_row/) exit
    print
}' "$MATRIX_PLAN_PATH")
cell_done 500K perfect encrypted atp-quic-tls13 1 1
"#,
            )
            .env("MATRIX_PLAN_PATH", scripts.join("matrix_bench.sh"))
            .env("RESULTS_JSONL", results_jsonl)
            .output()
            .expect("run matrix auth-posture resume fixture")
    };
    let legacy_resume_probe = run_resume_probe(&legacy_resume_fixture);
    assert_eq!(
        legacy_resume_probe.status.code(),
        Some(1),
        "legacy QUIC row bypassed auth-posture resume gate: {}",
        String::from_utf8_lossy(&legacy_resume_probe.stderr)
    );
    let current_resume_probe = run_resume_probe(&current_resume_fixture);
    assert!(
        current_resume_probe.status.success(),
        "current matrix auth-posture resume fixture failed: {}",
        String::from_utf8_lossy(&current_resume_probe.stderr)
    );

    let mixed_score_fixture = unique_tmp("auth_posture_mixed_score").with_extension("jsonl");
    write_file(
        &mixed_score_fixture,
        concat!(
            "{\"workload\":\"500K\",\"regime\":\"perfect\",\"crypto_tier\":\"encrypted\",\"method\":\"atp-quic-tls13\",\"rep\":1,\"wall_s\":100.0,\"sha_ok\":true,\"status\":\"ok\"}\n",
            "{\"workload\":\"500K\",\"regime\":\"perfect\",\"crypto_tier\":\"encrypted\",\"method\":\"atp-quic-tls13\",\"auth_posture\":\"quic-tls13-transport-aead-v1\",\"rep\":2,\"wall_s\":10.0,\"sha_ok\":true,\"status\":\"ok\"}\n",
            "{\"workload\":\"500K\",\"regime\":\"perfect\",\"crypto_tier\":\"encrypted\",\"method\":\"rsync-ssh-aes128gcm\",\"auth_posture\":\"ssh-aes128-gcm-v1\",\"rep\":1,\"wall_s\":20.0,\"sha_ok\":true,\"status\":\"ok\"}\n",
        ),
    );
    let mixed_score_probe = Command::new("python3")
        .arg(&score_matrix_path)
        .arg(&mixed_score_fixture)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("score mixed legacy/current auth-posture fixture");
    let mixed_scorecard = String::from_utf8_lossy(&mixed_score_probe.stdout);
    assert!(
        mixed_score_probe.status.success(),
        "mixed auth-posture scoring fixture failed: {}",
        String::from_utf8_lossy(&mixed_score_probe.stderr)
    );
    assert!(
        mixed_scorecard.contains("| 0.500 | 2.000 |")
            && mixed_scorecard.contains("(missing)")
            && mixed_scorecard.contains("quic-tls13-transport-aead-v1")
            && !mixed_scorecard.contains("| 2.750 |"),
        "legacy QUIC row was not quarantined before scoring: {mixed_scorecard}"
    );
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
