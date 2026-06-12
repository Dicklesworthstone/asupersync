#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::lab::LabRuntime;
use asupersync::record::ObligationKind;
use asupersync::types::Budget;
use asupersync_macros::lab_test;
use std::path::Path;
use std::process::Command;

#[lab_test]
fn runtime_form_gets_seed_zero(lab: &mut LabRuntime) {
    assert_eq!(lab.config().seed, 0);
}

#[lab_test(seeds = 2..5)]
fn seed_matrix_runs_every_seed(lab: &mut LabRuntime) {
    assert!((2..5).contains(&lab.config().seed));
}

#[lab_test(seeds = 7..8, chaos)]
fn chaos_uses_light_profile(lab: &mut LabRuntime) {
    assert_eq!(lab.config().seed, 7);
    assert!(lab.has_chaos());
}

#[lab_test]
async fn async_cx_form_gets_current_cx(cx: &Cx) {
    assert_eq!(
        cx.region_id(),
        Cx::current().expect("current Cx").region_id()
    );
}

#[should_panic(expected = "seed 3")]
#[lab_test(seeds = 2..5)]
fn seed_matrix_failure_reports_seed(lab: &mut LabRuntime) {
    assert_ne!(lab.config().seed, 3, "intentional seed failure");
}

#[should_panic(expected = "obligation leak")]
#[lab_test]
fn obligation_leak_fails_after_body(lab: &mut LabRuntime) {
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task_id, _handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    lab.state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create obligation");
    lab.scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);
}

#[ignore]
#[lab_test(seeds = 11..12)]
fn ignored_failure_for_deterministic_crashpack(lab: &mut LabRuntime) {
    assert_ne!(lab.config().seed, 11, "deterministic crashpack failure");
}

#[ignore]
#[lab_test(seeds = 13..14)]
fn ignored_failure_for_panic_tail(lab: &mut LabRuntime) {
    assert_ne!(lab.config().seed, 13, "panic tail crashpack failure");
}

#[test]
fn failing_lab_test_writes_deterministic_crashpack() {
    let first_panic = capture_panic(ignored_failure_for_deterministic_crashpack);
    let first_path = crashpack_path(&first_panic);
    let first_bytes = std::fs::read(&first_path).expect("read first crashpack");

    let second_panic = capture_panic(ignored_failure_for_deterministic_crashpack);
    let second_path = crashpack_path(&second_panic);
    let second_bytes = std::fs::read(&second_path).expect("read second crashpack");

    assert_eq!(first_path, second_path);
    assert_eq!(first_bytes, second_bytes);
    assert!(Path::new(&first_path).is_file());

    let json = String::from_utf8(first_bytes).expect("crashpack is utf-8 json");
    assert!(json.contains("\"seed\": 11"));
    assert!(json.contains("\"config_hash\""));
    assert!(json.contains("\"canonical_prefix\""));
    assert!(json.contains("\"oracle_violations\""));
    assert!(json.contains("\"replay\""));
    assert!(json.contains("deterministic crashpack failure"));
}

#[test]
fn failing_lab_test_panic_prints_crashpack_and_replay_last_lines() {
    let panic = capture_panic(ignored_failure_for_panic_tail);
    let path = crashpack_path(&panic);
    let mut lines = panic.lines().rev();
    let replay = lines.next().expect("replay line");
    let crashpack = lines.next().expect("crashpack line");

    assert_eq!(crashpack, format!("crashpack: {path}"));
    assert!(replay.starts_with("replay: "));
    assert!(replay.contains(&path));
}

#[test]
fn auto_crashpack_env_zero_disables_failure_artifact_tail() {
    let output = Command::new(std::env::current_exe().expect("current test exe"))
        .arg("--ignored")
        .arg("ignored_failure_for_panic_tail")
        .arg("--exact")
        .arg("--nocapture")
        .env("ASUPERSYNC_AUTO_ARTIFACTS", "0")
        .output()
        .expect("run ignored failure in subprocess");

    assert!(!output.status.success());
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    assert!(combined.contains("panic tail crashpack failure"));
    assert!(!combined.contains("crashpack: "));
    assert!(!combined.contains("replay: "));
}

fn capture_panic(test: fn()) -> String {
    let payload = std::panic::catch_unwind(test).expect_err("test should panic");
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

fn crashpack_path(message: &str) -> String {
    let path = message
        .lines()
        .find_map(|line| line.strip_prefix("crashpack: "))
        .expect("panic should include crashpack path");
    assert!(
        path.contains("target/test-artifacts"),
        "unexpected crashpack path: {path}"
    );
    path.to_string()
}
