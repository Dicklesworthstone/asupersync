//! Contract for `scripts/main_watchdog.py` (asupersync-bi2462.147).
//!
//! Drives the watchdog's `evaluate` mode (the dry run) with synthetic commits and
//! raw lane logs. Nothing runs through RCH, git or the tracker here: the point is
//! that the engine files exactly the right P0 payload for a planted red, never
//! re-files a known red, and never reads a lane as green without evidence.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const WEB_API: &str = "35050222+Dicklesworthstone@users.noreply.github.com";

fn sha(n: u8) -> String {
    format!("{n:02x}").repeat(20)
}

fn commit(n: u8, email: &str, subject: &str) -> Value {
    json!({
        "sha": sha(n),
        "author_name": "author",
        "author_email": email,
        "committed_at": "2026-09-23T00:00:00+00:00",
        "subject": subject,
        "message": subject,
        "paths": ["src/lib.rs"],
        "beads": [],
        "unsafe_paths": [],
    })
}

fn build_green() -> String {
    "  INFO rch::hook: Selected worker: hz3 at ubuntu@host\n    Finished `dev` profile [unoptimized] target(s) in 1m\n  Remote command finished: exit=0 in 60000ms\n".to_owned()
}

fn build_red(targets: &[&str]) -> String {
    let mut log = String::from("  INFO rch::hook: Selected worker: hz4 at ubuntu@host\n");
    for (index, target) in targets.iter().enumerate() {
        log.push_str(&format!(
            "tests/{target}.rs:{line}:5: error[E0599]: no method named `frob` found\n",
            line = 10 + index
        ));
        log.push_str(&format!(
            "error: could not compile `asupersync` (test \"{target}\") due to 1 previous error\n"
        ));
    }
    log.push_str("  Remote command finished: exit=101 in 60000ms\n");
    log
}

fn test_green(target: &str, passed: usize) -> String {
    format!(
        "     Running tests/{target}.rs (target/debug/deps/{target}-abc)\nrunning {passed} tests\ntest result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n  Remote command finished: exit=0 in 1000ms\n"
    )
}

fn lanes() -> Value {
    json!([
        {"id": "check-default", "kind": "build", "argv": ["cargo", "check", "--all-targets"]},
        {"id": "targeted-tests[default]", "kind": "test", "argv": ["cargo", "test", "--test", "alpha_native"],
         "expected_targets": ["alpha_native"]},
    ])
}

fn evaluate(scenario: &Value) -> Value {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let path: PathBuf = std::env::temp_dir().join(format!(
        "main_watchdog_contract_{}_{}.json",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(scenario).expect("serialize scenario"),
    )
    .expect("write scenario");
    let output = Command::new("python3")
        .arg("scripts/main_watchdog.py")
        .arg("evaluate")
        .arg("--scenario")
        .arg(&path)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("python3 must run the watchdog");
    assert!(
        output.status.success(),
        "watchdog evaluate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("watchdog prints JSON")
}

fn receipt<'a>(result: &'a Value, lane: &str) -> &'a Value {
    result["receipts"]
        .as_array()
        .expect("receipts array")
        .iter()
        .find(|r| r["lane"] == lane)
        .unwrap_or_else(|| panic!("no receipt for {lane}: {result:#}"))
}

/// Tracker writes run as `br --no-db <args>` so they reach issues.jsonl even when the
/// checkout's beads.db is stale (87cd61b9d); returns `<args>`.
fn br_args(call: &[String]) -> &[String] {
    assert_eq!(
        call[..2],
        ["br", "--no-db"],
        "tracker write bypasses the DB: {call:?}"
    );
    &call[2..]
}

/// Five commits; the web/API commit 3 breaks `alpha_native`; the head is 5.
fn planted_red_scenario(state: Value, head_targets: &[&str]) -> Value {
    let commits = vec![
        commit(1, "dev@example.com", "one"),
        commit(2, "dev@example.com", "two"),
        commit(
            3,
            WEB_API,
            "three: Tests have NOT been compiled or executed",
        ),
        commit(4, "dev@example.com", "four"),
        commit(5, "dev@example.com", "five"),
    ];
    let mut check = serde_json::Map::new();
    for n in 1..=5u8 {
        let log = match n {
            1 | 2 => build_green(),
            5 => build_red(head_targets),
            _ => build_red(&["alpha_native"]),
        };
        check.insert(sha(n), json!({"log": log}));
    }
    json!({
        "plan": {"commits": commits, "lanes": lanes()},
        "state": state,
        "now": "2026-09-23T12:00:00+00:00",
        "lane_logs": {
            "check-default": check,
            "targeted-tests[default]": {sha(5): {"log": test_green("alpha_native", 3)}},
        },
    })
}

#[test]
fn planted_red_is_bisected_to_its_commit_and_files_one_p0() {
    let result = evaluate(&planted_red_scenario(
        json!({"known_reds": {}}),
        &["alpha_native"],
    ));
    let payloads = result["bead_payloads"].as_array().expect("payload array");
    assert_eq!(payloads.len(), 1, "exactly one new red: {result:#}");
    let payload = &payloads[0];
    let culprit = sha(3);
    let title = payload["title"].as_str().expect("title");
    assert!(
        title.starts_with(&format!(
            "[main-watchdog] RED check-default at {}",
            &culprit[..9]
        )),
        "{title}"
    );
    assert!(
        title.contains("asupersync (test \"alpha_native\")"),
        "{title}"
    );
    assert!(
        title.contains("error[E0599]"),
        "first error in title: {title}"
    );
    assert!(title.contains(WEB_API), "author identity in title: {title}");
    assert_eq!(payload["priority"], 0);
    assert_eq!(payload["type"], "bug");
    assert_eq!(payload["parent"], "asupersync-bi2462.147");
    assert_eq!(payload["culprit"], culprit);
    let description = payload["description"].as_str().expect("description");
    assert!(
        description.contains("GitHub web/API identity"),
        "{description}"
    );
    assert!(
        description.contains("declares not compiled/executed: True"),
        "{description}"
    );
    assert!(description.contains("Worker: hz4"), "{description}");
    assert!(
        description.contains("does not revert or"),
        "no auto-revert: {description}"
    );

    let check = receipt(&result, "check-default");
    assert_eq!(check["verdict"], "red");
    assert_eq!(check["culprit"], culprit);
    assert_eq!(check["culprit_exact"], true);
    let probes: Vec<&str> = check["bisect_probes"]
        .as_array()
        .expect("probes")
        .iter()
        .map(|p| p["sha"].as_str().expect("probe sha"))
        .collect();
    assert_eq!(
        probes,
        vec![sha(3).as_str(), sha(2).as_str()],
        "binary search path"
    );
    assert_eq!(
        receipt(&result, "targeted-tests[default]")["verdict"],
        "green"
    );
    assert!(
        result["state"].get("last_green").is_none(),
        "a red batch is not green"
    );
    assert_eq!(
        result["state"]["last_covered"],
        sha(5),
        "decisive lanes cover the batch"
    );
}

#[test]
fn red_already_present_at_the_batch_base_blames_no_commit() {
    let mut scenario = planted_red_scenario(json!({"known_reds": {}}), &["alpha_native"]);
    for n in 1..=5u8 {
        scenario["lane_logs"]["check-default"][sha(n)] =
            json!({"log": build_red(&["alpha_native"])});
    }
    let base = sha(0xee);
    scenario["plan"]["since"] = json!(base.clone());
    scenario["lane_logs"]["check-default"][base.clone()] =
        json!({"log": build_red(&["alpha_native"])});
    let result = evaluate(&scenario);
    let payloads = result["bead_payloads"].as_array().expect("array");
    assert_eq!(payloads.len(), 1, "{result:#}");
    assert!(
        payloads[0]["culprit"].is_null(),
        "pre-existing red names no culprit: {result:#}"
    );
    let title = payloads[0]["title"].as_str().expect("title");
    assert!(
        title.contains(&format!("already red at batch base {}", &base[..9])),
        "{title}"
    );
    let check = receipt(&result, "check-default");
    assert_eq!(check["pre_existing"], true);
    assert!(check["culprit"].is_null());

    // Green base: the first commit of the batch really is the culprit.
    scenario["lane_logs"]["check-default"][base] = json!({"log": build_green()});
    let result = evaluate(&scenario);
    assert_eq!(result["bead_payloads"][0]["culprit"], sha(1));
    assert_eq!(receipt(&result, "check-default")["culprit_exact"], true);
}

#[test]
fn known_red_is_not_refiled_but_a_new_target_is() {
    let known = json!({"known_reds": {"check-default": {
        "asupersync (test \"alpha_native\")": {"bead": "asupersync-known1", "culprit": sha(3)}
    }}});
    let same = evaluate(&planted_red_scenario(known.clone(), &["alpha_native"]));
    assert!(
        same["bead_payloads"].as_array().expect("array").is_empty(),
        "{same:#}"
    );
    assert_eq!(
        receipt(&same, "check-default")["still_red"]["asupersync (test \"alpha_native\")"],
        "asupersync-known1"
    );

    let grown = evaluate(&planted_red_scenario(
        known,
        &["alpha_native", "beta_native"],
    ));
    let payloads = grown["bead_payloads"].as_array().expect("array");
    assert_eq!(payloads.len(), 1, "only the new target is filed: {grown:#}");
    assert_eq!(
        payloads[0]["new_targets"],
        json!(["asupersync (test \"beta_native\")"])
    );
    // beta_native is red only at the head, so the bisect lands on commit 5.
    assert_eq!(payloads[0]["culprit"], sha(5));
}

#[test]
fn a_green_head_heals_known_reds() {
    let mut scenario = planted_red_scenario(
        json!({"known_reds": {"check-default": {"asupersync (test \"alpha_native\")": {"bead": "asupersync-known1"}}}}),
        &[],
    );
    scenario["lane_logs"]["check-default"][sha(5)] = json!({"log": build_green()});
    let result = evaluate(&scenario);
    assert_eq!(
        receipt(&result, "check-default")["healed"],
        json!(["asupersync (test \"alpha_native\")"])
    );
    assert!(result["state"]["known_reds"].get("check-default").is_none());
    assert_eq!(result["state"]["last_green"], sha(5));
}

#[test]
fn nothing_reads_green_without_evidence() {
    let head = sha(9);
    let one = |id: &str, kind: &str, expected: Value| json!({"id": id, "kind": kind, "argv": ["cargo"], "expected_targets": expected});
    let scenario = json!({
        "plan": {
            "commits": [commit(9, "dev@example.com", "nine")],
            "lanes": [
                one("admission", "build", json!([])),
                one("false-green", "build", json!([])),
                one("no-finished", "build", json!([])),
                one("zero-tests", "test", json!(["alpha_native"])),
                one("missing-target", "test", json!(["alpha_native", "gamma_native"])),
                one("client-143-after-remote-0", "build", json!([])),
            ],
        },
        "lane_logs": {
            "admission": {head.clone(): {"log": "[RCH] refusing local fallback ([RCH-I003] ...)\n", "client_exit": 103}},
            "false-green": {head.clone(): {"log": "RCH-E412 dependency preflight unknown source_entrypoint\n", "client_exit": 0}},
            "no-finished": {head.clone(): {"log": "  Remote command finished: exit=0 in 1ms\n"}},
            "zero-tests": {head.clone(): {"log": test_green("alpha_native", 0)}},
            "missing-target": {head.clone(): {"log": test_green("alpha_native", 2)}},
            "client-143-after-remote-0": {head.clone(): {"log": build_green(), "client_exit": 143}},
        },
    });
    let result = evaluate(&scenario);
    assert_eq!(receipt(&result, "admission")["verdict"], "deferred");
    for lane in ["false-green", "no-finished", "zero-tests", "missing-target"] {
        assert_eq!(
            receipt(&result, lane)["verdict"],
            "no-evidence",
            "{lane}: {result:#}"
        );
    }
    assert!(
        receipt(&result, "missing-target")["reason"]
            .as_str()
            .expect("reason")
            .contains("gamma_native")
    );
    // The remote result is authoritative when the client dies after it (E309 class).
    assert_eq!(
        receipt(&result, "client-143-after-remote-0")["verdict"],
        "green"
    );
    assert!(
        result["bead_payloads"]
            .as_array()
            .expect("array")
            .is_empty()
    );
    assert!(
        result["state"].get("last_covered").is_none(),
        "undecided lanes do not cover the batch"
    );
}

/// The worker killed rustc (out of memory); `before` is logged ahead of the kill.
fn compiler_killed(before: &str) -> String {
    format!(
        "  INFO rch::hook: Selected worker: vmi1149989 at ubuntu@host\n{before}error: could not compile `asupersync` (lib test)\n\nCaused by:\n  process didn't exit successfully: `/root/.rustup/toolchains/nightly-2026-08-31-x86_64-unknown-linux-gnu/bin/rustc --crate-name asupersync --edition=2024 src/lib.rs --test -C debuginfo=2` (signal: 9, SIGKILL: kill)\n  Remote command finished: exit=101 in 1363895ms\n"
    )
}

#[test]
fn a_dependency_preflight_refusal_is_no_evidence_not_a_retry() {
    // rch 2.1.0 refuses a base whose own Cargo manifests fail its preflight (RCH-E413),
    // on every attempt. Deferring it would retry a lane that can never run.
    let head = sha(9);
    let refusal = "  WARN rch::hook: Dependency preflight blocked remote execution [RCH-E413]: Clean-overlay requires selected Cargo inputs.\n[RCH] remote required; refusing local fallback (dependency preflight failed: policy_violation selected_cargo_sources)\n";
    let admission = "[RCH] remote required; refusing local fallback ([RCH-I001] requested worker set refused (selection error: queue_timeout))\n";
    let lane = |id: &str| json!({"id": id, "kind": "build", "argv": ["cargo"], "expected_targets": []});
    let scenario = json!({
        "plan": {
            "commits": [commit(9, "dev@example.com", "nine")],
            "lanes": [lane("preflight-refused"), lane("admission-refused")],
        },
        "lane_logs": {
            "preflight-refused": {head.clone(): {"log": refusal, "client_exit": 103}},
            "admission-refused": {head.clone(): {"log": admission, "client_exit": 103}},
        },
    });
    let result = evaluate(&scenario);
    let refused = receipt(&result, "preflight-refused");
    assert_eq!(refused["verdict"], "no-evidence", "{result:#}");
    assert!(
        refused["reason"].as_str().expect("reason").contains("RCH-E413"),
        "{refused:#}"
    );
    // An ordinary admission refusal is still deferred for a later run.
    assert_eq!(receipt(&result, "admission-refused")["verdict"], "deferred", "{result:#}");
}

#[test]
fn a_preflight_refused_head_moves_the_next_batch_past_it() {
    // The refusal repeats on every attempt, so a batch that keeps the same head never
    // covers anything again (09-27: stuck on 1d9799819 for a day).
    let head = sha(9);
    let refusal = "  WARN rch::hook: Dependency preflight blocked remote execution [RCH-E413]: Clean-overlay requires selected Cargo inputs.\n";
    let lane = json!({"id": "check-default", "kind": "build", "argv": ["cargo"], "expected_targets": []});
    let refused = evaluate(&json!({
        "plan": {"commits": [commit(9, "dev@example.com", "nine")], "lanes": [lane.clone()]},
        "lane_logs": {"check-default": {head.clone(): {"log": refusal, "client_exit": 103}}},
        "state": {"known_reds": {}, "last_covered": sha(8)},
    }));
    assert_eq!(refused["state"]["preflight_refused_head"], head, "{refused:#}");
    assert_eq!(refused["state"]["last_covered"], sha(8), "nothing was covered: {refused:#}");

    // The next batch runs a full batch past the refused head; without a refusal, or
    // once the refused head is already covered, it is the ordinary batch.
    let shas: Vec<String> = (1..=50).map(sha).collect();
    let refused_state = json!({"preflight_refused_head": sha(20)});
    let probed = evaluate(&json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"select_batch": [
            {"shas": shas, "max_batch": 20, "state": refused_state},
            {"shas": shas, "max_batch": 20, "state": {}},
            {"shas": shas[25..].to_vec(), "max_batch": 20, "state": refused_state},
        ]},
    }));
    let batches = probed["probe_results"]["select_batch"].as_array().expect("batches");
    assert_eq!(batches[0], json!(shas[..40]), "{probed:#}");
    assert_eq!(batches[1], json!(shas[..20]), "{probed:#}");
    assert_eq!(batches[2], json!(shas[25..45]), "{probed:#}");

    // A decisive head releases the refusal.
    let released = evaluate(&json!({
        "plan": {"commits": [commit(9, "dev@example.com", "nine")], "lanes": [lane]},
        "lane_logs": {"check-default": {head.clone(): {"log": build_green()}}},
        "state": {"known_reds": {}, "preflight_refused_head": sha(7)},
    }));
    assert!(released["state"].get("preflight_refused_head").is_none(), "{released:#}");
    assert_eq!(released["state"]["last_covered"], head, "{released:#}");
}

/// Under clippy the kernel kills `clippy-driver <path>/rustc ...`. That OOM was
/// once read as red and bisected onto an innocent commit (bi2462.147.65).
#[test]
fn a_clippy_driver_killed_on_the_worker_is_undecided() {
    let head = sha(9);
    let log = "  INFO rch::hook: Selected worker: vmi1264463 at root@host\nerror: could not compile `asupersync` (lib test)\n\nCaused by:\n  process didn't exit successfully: `/root/.rustup/toolchains/nightly-2026-08-31-x86_64-unknown-linux-gnu/bin/clippy-driver /root/.rustup/toolchains/nightly-2026-08-31-x86_64-unknown-linux-gnu/bin/rustc --crate-name asupersync --edition=2024 src/lib.rs --test` (signal: 9, SIGKILL: kill)\n  Remote command finished: exit=101 in 1363895ms\n";
    let scenario = json!({
        "plan": {
            "commits": [commit(9, "dev@example.com", "nine")],
            "lanes": [{"id": "clippy-default", "kind": "build", "argv": ["cargo"], "expected_targets": []}],
        },
        "lane_logs": {"clippy-default": {head.clone(): {"log": log}}},
    });
    let result = evaluate(&scenario);
    let outcome = receipt(&result, "clippy-default");
    assert_eq!(outcome["verdict"], "no-evidence", "{result:#}");
    assert!(
        result["bead_payloads"]
            .as_array()
            .expect("array")
            .is_empty(),
        "a killed clippy-driver must never file a bead: {result:#}"
    );
}

#[test]
fn a_compiler_killed_on_the_worker_is_undecided_unless_a_real_failure_sits_beside_it() {
    let head = sha(9);
    let one = |id: &str, kind: &str| json!({"id": id, "kind": kind, "argv": ["cargo"], "expected_targets": []});
    let failed_test = "     Running tests/alpha_native.rs (target/debug/deps/alpha_native-abc)\nrunning 1 test\ntest boom ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
    let scenario = json!({
        "plan": {
            "commits": [commit(9, "dev@example.com", "nine")],
            "lanes": [
                one("killed-build", "build"),
                one("killed-test", "test"),
                one("killed-beside-real-error", "build"),
                one("killed-beside-failed-test", "test"),
                one("test-binary-killed", "test"),
            ],
        },
        "lane_logs": {
            "killed-build": {head.clone(): {"log": compiler_killed("")}},
            "killed-test": {head.clone(): {"log": compiler_killed("")}},
            "killed-beside-real-error": {head.clone(): {"log": compiler_killed(
                "src/lib.rs:10:5: error[E0599]: no method named `frob` found\n"
            )}},
            "killed-beside-failed-test": {head.clone(): {"log": compiler_killed(failed_test)}},
            "test-binary-killed": {head.clone(): {"log": "     Running tests/alpha_native.rs (target/debug/deps/alpha_native-abc)\nrunning 2 tests\nerror: test failed, to rerun pass `--test alpha_native`\n\nCaused by:\n  process didn't exit successfully: `/data/tmp/rch/x/target/debug/deps/alpha_native-abc` (signal: 9, SIGKILL: kill)\n  Remote command finished: exit=101 in 1000ms\n"}},
        },
    });
    let result = evaluate(&scenario);
    for lane in ["killed-build", "killed-test"] {
        let outcome = receipt(&result, lane);
        assert_eq!(outcome["verdict"], "no-evidence", "{lane}: {result:#}");
        assert!(
            outcome["reason"]
                .as_str()
                .expect("reason")
                .contains("signal 9"),
            "{lane}: {outcome:#}"
        );
    }
    // A real diagnostic, a failed test, or a killed test binary (which the code under
    // test can cause) is still red.
    for lane in [
        "killed-beside-real-error",
        "killed-beside-failed-test",
        "test-binary-killed",
    ] {
        assert_eq!(
            receipt(&result, lane)["verdict"],
            "red",
            "{lane}: {result:#}"
        );
    }
    let filed: Vec<&str> = result["bead_payloads"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|payload| payload["lane"].as_str())
        .collect();
    assert!(
        !filed.contains(&"killed-build") && !filed.contains(&"killed-test"),
        "a killed compiler must never file a bead: {filed:?}"
    );
    assert!(
        result["state"].get("last_covered").is_none(),
        "an undecided lane does not cover the batch"
    );
}

/// A dependency build that failed because the worker lost its files (hz4, 2026-09-28:
/// the registry cache was pruned under running builds); `extra` is appended as is.
fn dependency_fault(extra: &str) -> String {
    format!(
        "  INFO rch::hook: Selected worker: hz4 at ubuntu@host\n   Compiling proptest v1.11.0\nerror: could not compile `proptest` (lib)\n\nCaused by:\n  could not execute process `rustc --crate-name proptest --edition=2021 /data/tmp/rch-cargo-cache-hz4/registry/src/index.crates.io-1949cf8c6b5b557f/proptest-1.11.0/src/lib.rs` (never executed)\n\nCaused by:\n  No such file or directory (os error 2)\n{extra}  Remote command finished: exit=101 in 182237ms\n"
    )
}

#[test]
fn a_dependency_the_worker_could_not_build_is_undecided_unless_a_workspace_crate_fails() {
    let head = sha(9);
    let one = |id: &str, kind: &str| json!({"id": id, "kind": kind, "argv": ["cargo"], "expected_targets": []});
    let missing_source = "  INFO rch::hook: Selected worker: hz4 at ubuntu@host\nerror[E0583]: file not found for module `scalar`\nerror: couldn't read `/data/tmp/rch-cargo-cache-hz4/registry/src/index.crates.io-1949cf8c6b5b557f/curve25519-dalek-4.1.3/src/../README.md`: No such file or directory (os error 2)\nerror: could not compile `curve25519-dalek` (lib) due to 10 previous errors\n  Remote command finished: exit=101 in 71717ms\n";
    // A dependency that fails on its own diagnostics can be caused by a manifest or
    // lockfile change in the commit under test.
    let dependency_error = "  INFO rch::hook: Selected worker: hz3 at ubuntu@host\nerror[E0277]: the trait bound `T: Send` is not satisfied\nerror: could not compile `serde` (lib) due to 1 previous error\n  Remote command finished: exit=101 in 1000ms\n";
    // The check-wasm32 lane on a worker without the rustup target: every crate fails
    // on a missing `core` before any code of this repository is reached.
    let missing_target = "  INFO rch::hook: Selected worker: hz2 at ubuntu@host\n    Checking cfg-if v1.0.4\nerror[E0463]: can't find crate for `core`\n  |\n  = note: the `wasm32-unknown-unknown` target may not be installed\n  = help: consider downloading the target with `rustup target add wasm32-unknown-unknown`\nerror: could not compile `cfg-if` (lib) due to 1 previous error\n  Remote command finished: exit=101 in 900ms\n";
    // The same fault under --message-format=short: rustc prints no note (check-wasm32 on
    // ovh-a, 2026-10-01: filed as the false P0 bi2462.147.71).
    let missing_target_short = "  INFO rch::hook: Selected worker: ovh-a at ubuntu@host\n    Checking cfg-if v1.0.5\nerror[E0463]: can't find crate for `core`\nerror: could not compile `cfg-if` (lib) due to 1 previous error\n    Checking typenum v1.20.1\nerror: could not compile `typenum` (lib) due to 1 previous error\n  Remote command finished: exit=101 in 900ms\n";
    // A dep-info fault can stop cargo before any crate reports `could not compile`
    // (hz4, 2026-09-29: filed as the false P0 bi2462.147.66).
    let dep_info_only = "  INFO rch::hook: Selected worker: hz4 at ubuntu@host\n   Compiling syn v2.0.119\nerror: could not parse/generate dep info at: /data/tmp/rch/asupersync/08eb264dca0e0e69/.rch-target-hz4-job-1/debug/build/syn/0f39f05953ee3969/out/syn-0f39f05953ee3969.d\n\nCaused by:\n  No such file or directory (os error 2)\n  Remote command finished: exit=101 in 7561ms\n";
    let scenario = json!({
        "plan": {
            "commits": [commit(9, "dev@example.com", "nine")],
            "lanes": [
                one("fault-build", "build"),
                one("fault-test", "test"),
                one("fault-missing-source", "build"),
                one("fault-missing-target", "build"),
                one("fault-missing-target-short", "build"),
                one("fault-dep-info-only", "test"),
                one("fault-beside-workspace-error", "build"),
                one("fault-beside-member-error", "build"),
                one("dependency-error", "build"),
            ],
        },
        "lane_logs": {
            "fault-build": {head.clone(): {"log": dependency_fault("")}},
            "fault-test": {head.clone(): {"log": dependency_fault("")}},
            "fault-missing-source": {head.clone(): {"log": missing_source}},
            "fault-missing-target": {head.clone(): {"log": missing_target}},
            "fault-missing-target-short": {head.clone(): {"log": missing_target_short}},
            "fault-dep-info-only": {head.clone(): {"log": dep_info_only}},
            "fault-beside-workspace-error": {head.clone(): {"log": dependency_fault(
                "src/lib.rs:10:5: error[E0599]: no method named `frob` found\nerror: could not compile `asupersync` (lib) due to 1 previous error\n"
            )}},
            // A workspace member whose package name is not asupersync-*: its local path
            // on the Checking line marks it as this repository's code.
            "fault-beside-member-error": {head.clone(): {"log": dependency_fault(
                "    Checking franken-kernel v0.1.0 (/data/tmp/rch/asupersync/0123abcd/franken_kernel)\nfranken_kernel/src/lib.rs:3:5: error[E0425]: cannot find value `x` in this scope\nerror: could not compile `franken-kernel` (lib) due to 1 previous error\n"
            )}},
            "dependency-error": {head.clone(): {"log": dependency_error}},
        },
    });
    let result = evaluate(&scenario);
    for lane in [
        "fault-build",
        "fault-test",
        "fault-missing-source",
        "fault-missing-target",
        "fault-missing-target-short",
        "fault-dep-info-only",
    ] {
        let outcome = receipt(&result, lane);
        assert_eq!(outcome["verdict"], "no-evidence", "{lane}: {result:#}");
        assert!(
            outcome["reason"]
                .as_str()
                .expect("reason")
                .contains("third-party dependency"),
            "{lane}: {outcome:#}"
        );
    }
    for lane in ["fault-beside-workspace-error", "fault-beside-member-error", "dependency-error"] {
        assert_eq!(
            receipt(&result, lane)["verdict"],
            "red",
            "{lane}: {result:#}"
        );
    }
    let filed: Vec<&str> = result["bead_payloads"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|payload| payload["lane"].as_str())
        .collect();
    for lane in [
        "fault-build",
        "fault-test",
        "fault-missing-source",
        "fault-missing-target",
        "fault-missing-target-short",
        "fault-dep-info-only",
    ] {
        assert!(!filed.contains(&lane), "a worker fault must never file a bead: {filed:?}");
    }
    assert!(
        result["state"].get("last_covered").is_none(),
        "an undecided lane does not cover the batch"
    );
}

fn test_red(target: &str, test: &str) -> String {
    format!(
        "     Running tests/{target}.rs (target/debug/deps/{target}-abc)\nrunning 1 test\ntest {test} ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n  Remote command finished: exit=101 in 1000ms\n"
    )
}

#[test]
fn a_probe_where_the_red_test_did_not_compile_names_a_range_not_a_culprit() {
    // alpha_native's `boom` fails at the head. At commit 3 the target does not
    // compile, so its tests never ran there; commit 4 is the first where it
    // compiles (and fails). Reading commit 3 as clear would blame commit 4
    // exactly, the commit that merely made the test compile.
    let lane = json!({"id": "targeted-tests[default]", "kind": "test",
        "argv": ["cargo", "test", "--test", "alpha_native"], "expected_targets": ["alpha_native"]});
    let commits: Vec<Value> = (1..=5u8)
        .map(|n| commit(n, "dev@example.com", "change"))
        .collect();
    let mut logs = serde_json::Map::new();
    logs.insert(sha(3), json!({"log": build_red(&["alpha_native"])}));
    for n in [4u8, 5] {
        logs.insert(sha(n), json!({"log": test_red("alpha_native", "boom")}));
    }
    let result = evaluate(&json!({
        "plan": {"commits": commits, "lanes": [lane]},
        "state": {"known_reds": {}},
        "now": "2026-09-26T12:00:00+00:00",
        "lane_logs": {"targeted-tests[default]": logs},
    }));
    let outcome = receipt(&result, "targeted-tests[default]");
    assert_eq!(outcome["verdict"], "red", "{result:#}");
    assert_eq!(
        outcome["culprit_exact"], false,
        "an uncompiled probe decides nothing: {outcome:#}"
    );
    assert_ne!(outcome["culprit"], sha(4), "{outcome:#}");
    let probes = outcome["bisect_probes"].as_array().expect("probes");
    assert_eq!(probes.len(), 1, "the search stops at the undecided probe");
    assert_eq!(probes[0]["sha"], sha(3));
}

#[test]
fn predicates_match_real_phrasings_and_reject_look_alikes() {
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {
            "declares_not_compiled": [
                "Tests have NOT been compiled or executed",
                "Rust/Cargo/RCH are unavailable; compilation and Rust tests have NOT run",
                "Rust compilation, rustfmt and runtime tests remain NOT RUN: rustc missing",
                "stopped before execution: rch not found, exit 127",
                "native compilation and test execution remain unverified because of shared load",
                "compilation, runtime tests and rustfmt are NOT RUN: rustc, Cargo, rustfmt absent",
                // Describing someone else's code is not a self-declaration.
                "Test targets that had never compiled were repaired",
                "authors lacked compile access (\"rch was not found (exit 127)\")",
                "ledger_recovery.rs (landed uncompiled in 8f08a9631) uses the nightly API",
                "Keep handler execution inside the branch",
                "recompiled cleanly on hz3",
                "the first version missed \"compilation, runtime tests and rustfmt are NOT RUN\"",
                "The first plan flagged the watchdog's own commit as declaring it was not compiled.",
            ],
            "known_ids": ["asupersync-bi2462.158", "asupersync-qoir1r"],
            "bead_ids": [
                "fix(macros): asupersync-macros race (br-asupersync-bi2462.158)",
                "see asupersync-qoir1r and asupersync-notreal1",
            ],
            "file_cfg_features": [
                "#![cfg(feature = \"tls\")]\nuse x;",
                "#![cfg(all(feature = \"tls\", feature = \"http3\", not(target_arch = \"wasm32\")))]",
                "#![cfg(not(target_arch = \"wasm32\"))]\n",
                "#![cfg(any(feature = \"a\", feature = \"b\"))]",
                // The multi-line form 23 test files use; a line regex saw no features here.
                "//! doc\n#![cfg(all(\n    feature = \"tls\",\n    feature = \"test-internals\",\n    not(target_arch = \"wasm32\")\n))]\nuse x;",
                "#![cfg(target_arch = \"wasm32\")]",
            ],
            "lib_filter_for": [
                "src/distributed/consensus/pbft.rs",
                "src/grpc/native_stream/mod.rs",
                "src/lib.rs",
                "src/bin/atp.rs",
                "tests/x.rs",
            ],
        },
    });
    let probes = &evaluate(&scenario)["probe_results"];
    assert_eq!(
        probes["declares_not_compiled"],
        json!([
            true, true, true, true, true, true, false, false, false, false, false, false, false
        ])
    );
    assert_eq!(
        probes["bead_ids"],
        json!([["asupersync-bi2462.158"], ["asupersync-qoir1r"]])
    );
    assert_eq!(
        probes["file_cfg_features"],
        json!([
            [["tls"], true],
            [["http3", "tls"], true],
            [[], true],
            [["a"], true],
            [["test-internals", "tls"], true],
            [[], false]
        ])
    );
    assert_eq!(
        probes["lib_filter_for"],
        json!([
            "distributed::consensus::pbft",
            "grpc::native_stream",
            null,
            null,
            null
        ])
    );
}

/// A changed `src/` file is checked with the features its module chain needs, under
/// the module path it really has. Line-based mapping ran feature-gated modules
/// without their feature, so their tests compiled to nothing and still read green.
#[test]
fn feature_gated_modules_map_to_their_features_and_real_module_paths() {
    let sources = json!({
        "src/lib.rs": "//! crate\n#![allow(dead_code)]\npub mod plain;\n#[cfg(any(feature = \"mysql\", feature = \"postgres\"))]\npub mod database;\n#[cfg(all(\n    feature = \"tls\",\n    not(target_arch = \"wasm32\")\n))]\n// a comment between the attribute and the item\npub mod tls;\n#[cfg(target_arch = \"wasm32\")]\npub mod wasm_only;\n",
        "src/plain.rs": "#[cfg(test)]\n#[path = \"plain_tests.rs\"]\nmod tests;\n",
        "src/plain_tests.rs": "",
        "src/database/mod.rs": "#[cfg(feature = \"postgres\")]\npub mod postgres;\n",
        "src/database/postgres.rs": "#[cfg(test)]\ninclude!(\"postgres_tests.rs\");\n",
        "src/database/postgres_tests.rs": "",
        "src/tls.rs": "pub mod types;\n",
        "src/tls/types.rs": "",
        "src/wasm_only.rs": "",
        "src/orphan.rs": "",
    });
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {
            "defaults": ["proc-macros"],
            "cfg_requirement": [
                "feature = \"tls\"",
                "all(feature = \"tls\", not(target_arch = \"wasm32\"))",
                "feature = \"proc-macros\"",
                "not(feature = \"proc-macros\")",
                "any(feature = \"mysql\", feature = \"postgres\")",
                "target_os = \"windows\"",
                "all(unix, test)",
                "panic = \"abort\"",
                "all(feature = \"a\"",
            ],
            "module_tree": {"sources": sources, "roots": ["src/lib.rs"]},
        },
    });
    let probes = &evaluate(&scenario)["probe_results"];
    assert_eq!(
        probes["cfg_requirement"],
        json!([
            ["tls"],
            ["tls"],
            [],
            "never",
            ["mysql"],
            "never",
            [],
            null,
            null
        ])
    );
    assert_eq!(
        probes["module_tree"],
        json!({
            "src/lib.rs": ["", []],
            "src/plain.rs": ["plain", []],
            "src/plain_tests.rs": ["plain::tests", []],
            "src/database/mod.rs": ["database", ["mysql"]],
            // Not mysql+postgres: the `any` on `database` is resolved against the whole chain.
            "src/database/postgres.rs": ["database::postgres", ["postgres"]],
            "src/database/postgres_tests.rs": ["database::postgres", ["postgres"]],
            "src/tls.rs": ["tls", ["tls"]],
            "src/tls/types.rs": ["tls::types", ["tls"]],
            "src/wasm_only.rs": ["wasm_only", "never"],
        }),
        "src/orphan.rs is absent: nothing compiles it"
    );
}

#[test]
fn parallel_head_lanes_change_nothing_but_wall_clock() {
    let serial = evaluate(&planted_red_scenario(
        json!({"known_reds": {}}),
        &["alpha_native"],
    ));
    let mut scenario = planted_red_scenario(json!({"known_reds": {}}), &["alpha_native"]);
    scenario["parallel"] = json!(4);
    let parallel = evaluate(&scenario);
    for key in ["receipts", "bead_payloads", "state", "notes"] {
        assert_eq!(serial[key], parallel[key], "{key} differs under --parallel");
    }
    assert_eq!(receipt(&parallel, "check-default")["culprit"], sha(3));
}

#[test]
fn a_lib_filter_that_ran_no_test_is_reported_not_hidden() {
    let lane = json!({
        "id": "targeted-lib", "kind": "test", "argv": ["cargo", "test", "--lib"],
        "expected_targets": [], "lib_filters": ["database::postgres", "trace::capture"],
    });
    let log = "     Running unittests src/lib.rs (target/debug/deps/asupersync-abc)\nrunning 2 tests\ntest trace::capture::tests::records_poll ... ok\ntest trace::capture::tests::records_wake ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 900 filtered out; finished in 0.01s\n  Remote command finished: exit=0 in 1000ms\n";
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": [lane]},
        "lane_logs": {"targeted-lib": {sha(1): {"log": log}}},
    });
    let lib = receipt(&evaluate(&scenario), "targeted-lib").clone();
    assert_eq!(lib["verdict"], "green", "{lib:#}");
    assert_eq!(lib["unexercised_filters"], json!(["database::postgres"]));
}

/// Only this lane runs the rustdoc examples, the README's included (br-asupersync-69l7je).
/// It runs when a batch touches crate source or the README. One `Doc-tests` header owns
/// two libtest blocks (merged, then standalone doctests), so a failure is keyed by cargo's
/// `--doc` and names the doctest, spaces and all.
#[test]
fn doctests_run_for_source_or_readme_changes_and_a_failure_names_the_doctest() {
    let probed = evaluate(&json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"touches_rustdoc": [
            ["src/lib.rs"], ["README.md"], ["src/net/tcp/mod.rs", "docs/x.md"],
            ["tests/a.rs", "Cargo.toml"], ["docs/README.md", "scripts/x.py"],
        ]},
    }));
    assert_eq!(
        probed["probe_results"]["touches_rustdoc"],
        json!([true, true, true, false, false]),
        "{probed:#}"
    );

    let lane = json!({
        "id": "doctests", "kind": "test", "argv": ["cargo", "test", "--doc"],
        "expected_targets": ["doc"],
    });
    let green = "   Doc-tests asupersync\nrunning 3 tests\ntest src/a.rs - a (line 3) ... ok\ntest src/b.rs - b (line 9) - compile ... ok\ntest src/c.rs - c (line 1) ... ignored\ntest result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\nrunning 1 test\ntest src/d.rs - d (line 5) ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n  Remote command finished: exit=0 in 1000ms\n";
    let red = "   Doc-tests asupersync\nrunning 2 tests\ntest src/a.rs - a (line 3) ... ok\ntest src/stream/mod.rs - stream::StreamExt::try_buffered (line 450) ... FAILED\n\nfailures:\n\nfailures:\n    src/stream/mod.rs - stream::StreamExt::try_buffered (line 450)\n\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\nerror: doctest failed, to rerun pass `-p asupersync --doc`\n  Remote command finished: exit=101 in 1000ms\n";
    for (log, verdict, failing) in [
        (green, "green", json!([])),
        (
            red,
            "red",
            json!(["doc::src/stream/mod.rs - stream::StreamExt::try_buffered (line 450)"]),
        ),
    ] {
        let result = evaluate(&json!({
            "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": [lane.clone()]},
            "lane_logs": {"doctests": {sha(1): {"log": log, "client_exit": if verdict == "red" { 101 } else { 0 }}}},
        }));
        let doc = receipt(&result, "doctests");
        assert_eq!(doc["verdict"], verdict, "{doc:#}");
        assert_eq!(
            doc["failing_targets"].as_array().cloned().unwrap_or_default(),
            failing.as_array().cloned().unwrap_or_default(),
            "{doc:#}"
        );
    }
}

/// A batch that touches Cargo.toml or a top-level integration test runs the test
/// registration contract (bi2462.87): a commit that never ran `cargo test` can
/// still add a feature-gated test without its `[[test]]` required-features.
#[test]
fn manifest_or_top_level_test_changes_run_the_registration_contract() {
    let probed = evaluate(&json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"touches_test_registration": [
            ["Cargo.toml"],
            ["tests/new_native.rs"],
            ["src/lib.rs", "tests/atp/helper.rs"],
            ["src/lib.rs", "docs/x.md"],
            ["fuzz/Cargo.toml", "tests/fixtures/x.rs"],
        ]},
    }));
    assert_eq!(
        probed["probe_results"]["touches_test_registration"],
        json!([true, true, false, false, false]),
        "{probed:#}"
    );
}

/// The rotation (execution debt, br-asupersync-kh02d2) walks every default-feature
/// integration target in turn, gated and non-test entries aside. A decisive run
/// advances the cursor and an admission refusal does not. A new red is filed once,
/// a failed filing is retried by later runs, a red that persists gets no second
/// bead, and a later green run heals it.
#[test]
fn rotation_walks_default_targets_and_files_each_new_red_once() {
    let ok = |t: &str| {
        format!(
            "     Running tests/{t}.rs (x)\nrunning 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
    };
    let red = |t: &str| {
        format!(
            "     Running tests/{t}.rs (x)\nrunning 1 test\ntest pins ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
    };
    let fin = |code: u32| format!("  Remote command finished: exit={code} in 1ms\n");
    let probed = evaluate(&json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"rotation": [{
            "root_paths": [
                "tests/alpha.rs", "tests/beta.rs", "tests/gamma.rs", "tests/gated.rs",
                "tests/common", "tests/renamed_file.rs",
            ],
            "registry": {
                "tests/gated.rs": {"name": "gated", "features": ["cli"]},
                "tests/renamed_file.rs": {"name": "delta", "features": []},
            },
            "count": 2,
            "runs": [
                {"sha": "a1", "log": ok("alpha") + &red("beta") + &fin(101), "client_exit": 101, "file_as": null},
                {"sha": "a2", "log": "", "client_exit": 103},
                {"sha": "a3", "log": ok("delta") + &ok("gamma") + &fin(0), "file_as": "asupersync-rot1"},
                {"sha": "a4", "log": ok("alpha") + &red("beta") + &fin(101), "client_exit": 101, "file_as": "asupersync-dup"},
                {"sha": "a5", "log": ok("delta") + &ok("gamma") + &fin(0)},
                {"sha": "a6", "log": ok("alpha") + &ok("beta") + &fin(0)},
            ],
        }]},
    }));
    let rotation = &probed["probe_results"]["rotation"][0];
    assert_eq!(
        rotation["names"],
        json!(["alpha", "beta", "delta", "gamma"]),
        "{probed:#}"
    );
    let rounds = rotation["rounds"].as_array().expect("rounds");
    let summary: Vec<Value> = rounds
        .iter()
        .map(|r| {
            json!([
                r["picked"],
                r["verdict"],
                r["cursor"],
                r["new_red"],
                r["healed"],
                r["filed"],
                r["pending"]
            ])
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            json!([["alpha", "beta"], "red", 2, ["beta"], [], [], 1]),
            json!([["delta", "gamma"], "deferred", 2, [], [], [], 1]),
            json!([
                ["delta", "gamma"],
                "green",
                0,
                [],
                [],
                ["asupersync-rot1"],
                0
            ]),
            json!([["alpha", "beta"], "red", 2, [], [], [], 0]),
            json!([["delta", "gamma"], "green", 0, [], [], [], 0]),
            json!([["alpha", "beta"], "green", 2, [], ["beta"], [], 0]),
        ],
        "{probed:#}"
    );
    assert_eq!(
        rounds[3]["results"]["beta"],
        json!(["red", "asupersync-rot1"])
    );
    let filings = rotation["filings"].as_array().expect("filings");
    assert_eq!(
        filings.len(),
        3,
        "one payload, two failed attempts, then filed: {probed:#}"
    );
    for filing in filings {
        assert_eq!(filing["title"], "[main-watchdog] ROTATION RED at a1: beta");
        assert_eq!(filing["priority"], 1);
        assert_eq!(filing["new_targets"], json!(["beta::pins"]));
    }
}

/// RCH delivers cargo's stderr (the `Running` headers) apart from libtest's stdout
/// (the result blocks); the runner concatenates them. Reading "the last header
/// seen" filed rotation failures under the wrong target and recorded the failing
/// ones green (2026-09-29: api_surface_map_contract and
/// artifact_governance_scanner_contract). The k-th libtest block belongs to the
/// k-th header. A target at a nested path is named by its binary, not its file stem
/// (atp_per_module_logging_redaction_contract kept the rotation cursor stuck). When
/// blocks and headers do not pair up, only cargo's own list of failed binaries
/// names a target, and nothing is recorded green.
#[test]
fn rotation_attributes_each_failure_to_the_binary_that_printed_it() {
    let nested = "atp_per_module_logging_redaction_contract";
    let ok = |n: usize| {
        format!("running {n} tests\ntest result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
    };
    let headers = format!(
        "     Running tests/alpha.rs (target/debug/deps/alpha-0123abcd)\n     Running tests/atp/per_module/logging_redaction_contract.rs (target/debug/deps/{nested}-4567ef01)\n     Running tests/beta.rs (target/debug/deps/beta-89abcdef)\n"
    );
    // stdout first, then stderr: every header sits below every block.
    let paired = ok(3)
        + "running 1 test\ntest pins ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        + &ok(2)
        + &headers
        + &format!("error: 1 target failed:\n    `-p asupersync --test {nested}`\n  Remote command finished: exit=101 in 1ms\n");
    // A failing test's captured output echoes a libtest header: four blocks, three
    // headers. cargo names two failed binaries, so neither test can be placed.
    let unpaired = String::from(
        "running 1 test\ntest one ... FAILED\n\nfailures:\n\n---- one stdout ----\nrunning 1 test\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
    ) + &ok(3)
        + "running 2 tests\ntest two ... FAILED\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        + &headers
        + "error: 2 targets failed:\n    `-p asupersync --test alpha`\n    `-p asupersync --test beta`\n  Remote command finished: exit=101 in 1ms\n";
    let probed = evaluate(&json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"rotation": [{
            "root_paths": ["tests/alpha.rs", "tests/beta.rs", "tests/atp"],
            "registry": {
                "tests/atp/per_module/logging_redaction_contract.rs": {"name": nested, "features": []},
            },
            "count": 3,
            "runs": [
                {"sha": "b1", "log": paired, "client_exit": 101, "file_as": "asupersync-rota"},
                {"sha": "b2", "log": unpaired, "client_exit": 101, "file_as": "asupersync-rotb"},
            ],
        }]},
    }));
    let rotation = &probed["probe_results"]["rotation"][0];
    let rounds = rotation["rounds"].as_array().expect("rounds");
    assert_eq!(rounds[0]["verdict"], "red", "{probed:#}");
    assert_eq!(rounds[0]["new_red"], json!([nested]), "{probed:#}");
    assert_eq!(
        rounds[0]["results"],
        json!({"alpha": ["green", null], nested: ["red", "asupersync-rota"], "beta": ["green", null]}),
        "{probed:#}"
    );
    assert_eq!(
        rotation["filings"][0]["new_targets"],
        json!([format!("{nested}::pins")]),
        "{probed:#}"
    );
    // Unpaired: cargo's list still marks alpha and beta red; the nested target, which
    // may well have passed, is not healed on this evidence.
    assert_eq!(rounds[1]["new_red"], json!(["alpha", "beta"]), "{probed:#}");
    assert_eq!(rounds[1]["healed"], json!([]), "{probed:#}");
    assert_eq!(
        rounds[1]["results"][nested],
        json!(["red", "asupersync-rota"]),
        "{probed:#}"
    );
}

/// The browser SDK's Node suites run on the watchdog host (Node, not Cargo), one
/// `=== node-suite <path> exit=<code>` marker after each suite's output (bi2462.135).
/// A failing test is keyed by suite and test name. The file-level entry, which names
/// the suite by its path in a per-run temporary snapshot, never becomes a key, so a
/// persisting red is not refiled every run. A missing fake-indexeddb reference is the
/// host's gap: undecided, never green and never red.
#[test]
fn node_suites_are_keyed_by_suite_and_test_and_a_missing_reference_proves_nothing() {
    let head = sha(9);
    let node = |id: &str| json!({"id": id, "kind": "node", "argv": ["node"], "suites": ["scripts/test_browser_a.mjs", "scripts/test_browser_b.mjs"]});
    let stats = |pass: u32, fail: u32| format!("ℹ tests {}\nℹ pass {pass}\nℹ fail {fail}\n", pass + fail);
    let green = format!(
        "✔ one (1.0ms)\n{}=== node-suite scripts/test_browser_a.mjs exit=0\n{}=== node-suite scripts/test_browser_b.mjs exit=0\n",
        stats(3, 0),
        stats(2, 0)
    );
    let red = format!(
        "{}=== node-suite scripts/test_browser_a.mjs exit=0\n✖ fails on purpose (1.04ms)\n{}✖ failing tests:\n✖ fails on purpose (1.04ms)\n✖ /tmp/asupersync_watchdog_node_x1/scripts/test_browser_b.mjs (5.1ms)\n=== node-suite scripts/test_browser_b.mjs exit=1\n",
        stats(3, 0),
        stats(1, 1)
    );
    let timed_out = format!("{}=== node-suite scripts/test_browser_a.mjs exit=0\n=== node-suite scripts/test_browser_b.mjs exit=timeout\n", stats(3, 0));
    let no_reference = format!(
        "{}=== node-suite scripts/test_browser_a.mjs exit=0\nError: Artifact transaction tests require fake-indexeddb 6.2.5.\n{}=== node-suite scripts/test_browser_b.mjs exit=1\n",
        stats(3, 0),
        stats(0, 1)
    );
    let absent = "=== node-suite scripts/test_browser_a.mjs exit=absent\n=== node-suite scripts/test_browser_b.mjs exit=absent\n";
    let no_node = "=== node-suite scripts/test_browser_a.mjs exit=no-node\n=== node-suite scripts/test_browser_b.mjs exit=no-node\n";
    let scenario = json!({
        "plan": {
            "commits": [commit(9, "dev@example.com", "nine")],
            "lanes": [node("green"), node("red"), node("timed-out"), node("no-reference"), node("absent"), node("no-node")],
        },
        "lane_logs": {
            "green": {head.clone(): {"log": green}},
            "red": {head.clone(): {"log": red}},
            "timed-out": {head.clone(): {"log": timed_out}},
            "no-reference": {head.clone(): {"log": no_reference}},
            "absent": {head.clone(): {"log": absent}},
            "no-node": {head.clone(): {"log": no_node}},
        },
    });
    let result = evaluate(&scenario);
    let green = receipt(&result, "green");
    assert_eq!(green["verdict"], "green", "{result:#}");
    assert_eq!(green["counts"]["passed"], 5);
    let red = receipt(&result, "red");
    assert_eq!(red["verdict"], "red", "{result:#}");
    assert_eq!(
        red["failing_targets"],
        json!(["scripts/test_browser_b.mjs::fails on purpose"]),
        "{result:#}"
    );
    assert_eq!(
        receipt(&result, "timed-out")["failing_targets"],
        json!(["scripts/test_browser_b.mjs::(suite failed, exit timeout)"]),
        "{result:#}"
    );
    for lane in ["no-reference", "absent", "no-node"] {
        assert_eq!(
            receipt(&result, lane)["verdict"],
            "no-evidence",
            "{lane}: {result:#}"
        );
    }
    assert!(
        receipt(&result, "no-reference")["reason"]
            .as_str()
            .expect("reason")
            .contains("WATCHDOG_FAKE_INDEXEDDB_SOURCE"),
        "{result:#}"
    );
}

/// The feature-gated rotation (br-asupersync-kh02d2.1) runs what the test build compiles
/// out. The test build has the defaults plus what a path dev-dependency unifies in (here
/// `extra`, which turns on `implied`), so a target that needs only those belongs to the
/// default rotation. Any other target is a row keyed by the features its code needs:
/// its required-features plus every manifest feature a cfg names (not a comment or a
/// string; an undefined name would make `--features` fail the run). An exempt feature
/// drops the target, and one pick never spans two feature sets.
#[test]
fn feature_rotation_runs_what_the_test_build_compiles_out_one_feature_set_at_a_time() {
    let probed = evaluate(&json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"feature_rotation": [{
            "manifest": {
                "package": {"name": "asupersync"},
                "features": {
                    "default": ["core"], "core": [], "extra": ["implied", "dep:serde"],
                    "implied": [], "tls": ["dep:rustls"], "cli": ["tls"], "tower": [],
                    "loom-tests": [],
                },
                "dev-dependencies": {
                    "conformance": {"package": "asupersync-conformance", "path": "conformance"},
                    "serde_json": "1",
                },
            },
            "members": {"conformance": {"dependencies": {
                "asupersync": {"path": "..", "default-features": false, "features": ["extra"]},
            }}},
            "registry": {
                "tests/cli_a.rs": {"name": "cli_a", "features": ["cli"]},
                "tests/nested/tls_b.rs": {"name": "tls_b", "features": ["tls"]},
                "tests/tls_d.rs": {"name": "tls_d", "features": ["implied", "tls"]},
                "tests/implied_only.rs": {"name": "implied_only", "features": ["implied"]},
                "tests/loom.rs": {"name": "loom", "features": ["loom-tests"]},
            },
            "sources": {
                "tests/cli_a.rs": "",
                "tests/nested/tls_b.rs": "",
                "tests/tls_d.rs": "",
                "tests/implied_only.rs": "",
                "tests/loom.rs": "",
                "tests/plain.rs": "#[test]\nfn t() {}\n",
                "tests/inner.rs": "#[cfg(feature = \"tower\")]\nmod tower_tests {}\n#[cfg(all(feature = \"extra\", not(feature = \"tls\")))]\nmod x {}\n#[cfg(feature = \"no-such-feature\")]\nmod y {}\n",
                "tests/mentions.rs": "// cfg(feature = \"tls\") in a comment\nconst S: &str = \"#[cfg(feature = \\\"cli\\\")]\";\nconst Q: char = '\"';\n",
                "tests/tls_c.rs": "#[cfg_attr(feature = \"tls\", ignore)]\n#[test]\nfn t() {}\n",
                "tests/common/mod.rs": "#[cfg(feature = \"tls\")]\npub fn helper() {}\n",
            },
            "count": 2,
            "picks": 4,
        }]},
    }));
    let result = &probed["probe_results"]["feature_rotation"][0];
    assert_eq!(
        result["test_build"],
        json!(["core", "extra", "implied"]),
        "{probed:#}"
    );
    assert_eq!(
        result["rows"],
        json!([
            ["cli", "cli_a"],
            ["tls", "tls_b"],
            ["tls", "tls_c"],
            ["tls", "tls_d"],
            ["tls,tower", "inner"]
        ]),
        "{probed:#}"
    );
    // `tls_d` shares the `tls` build (it needs `implied` too, which the test build has),
    // and its pick still names `implied`: cargo checks required-features as written.
    assert_eq!(
        result["picks"],
        json!([
            {"features": "cli", "picked": ["cli_a"], "cursor": 1},
            {"features": "tls", "picked": ["tls_b", "tls_c"], "cursor": 3},
            {"features": "implied,tls", "picked": ["tls_d"], "cursor": 4},
            {"features": "tls,tower", "picked": ["inner"], "cursor": 0},
        ]),
        "{probed:#}"
    );
}

fn hedge_log(with_newer: bool) -> String {
    let mut log = String::from(
        "     Running tests/hedge_native.rs (x)\nrunning 2 tests\ntest cancel_test ... FAILED\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s\n",
    );
    if with_newer {
        log.push_str("     Running tests/newer_contract.rs (x)\nrunning 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n");
    }
    log.push_str("  Remote command finished: exit=101 in 1000ms\n");
    log
}

/// The first real run's failure shape (bi2462.147.2): a targeted lane at the batch
/// head names a target (`newer_contract`) that only the head commit added, and the
/// red target (`hedge_native`) appeared at commit 3.
fn new_target_mid_batch_scenario(disable_filter: bool) -> Value {
    let lane = json!({
        "id": "targeted-tests[default]", "kind": "test",
        "argv": ["cargo", "test", "--test", "hedge_native", "--test", "newer_contract"],
        "expected_targets": ["hedge_native", "newer_contract"],
    });
    json!({
        "plan": {
            "commits": (1..=5u8).map(|n| commit(n, "dev@example.com", "c")).collect::<Vec<_>>(),
            "lanes": [lane],
        },
        "state": {"known_reds": {}},
        "disable_target_filter": disable_filter,
        "absent_targets": {
            sha(1): ["hedge_native", "newer_contract"],
            sha(2): ["hedge_native", "newer_contract"],
            sha(3): ["newer_contract"],
            sha(4): ["newer_contract"],
        },
        "lane_logs": {"targeted-tests[default]": {
            sha(3): {"log": hedge_log(false)},
            sha(4): {"log": hedge_log(false)},
            sha(5): {"log": hedge_log(true)},
        }},
    })
}

#[test]
fn bisect_probes_only_request_targets_that_exist_at_the_probed_commit() {
    let result = evaluate(&new_target_mid_batch_scenario(false));
    let lane = receipt(&result, "targeted-tests[default]");
    assert_eq!(lane["verdict"], "red");
    assert_eq!(lane["new_red"], json!(["hedge_native::cancel_test"]));
    assert_eq!(lane["culprit"], sha(3), "{result:#}");
    assert_eq!(lane["culprit_exact"], true);
    let probes = lane["bisect_probes"].as_array().expect("probes");
    assert_eq!(probes[0]["sha"], sha(3));
    assert_eq!(probes[0]["verdict"], "red");
    assert_eq!(probes[1]["sha"], sha(2));
    assert_eq!(
        probes[1]["verdict"], "target-absent",
        "a commit without the failing target cannot hold its red and is not run"
    );

    // Without the filter, cargo refuses the probe's target list. That must read as
    // undecided (a range), never as a confident culprit.
    let unfiltered = evaluate(&new_target_mid_batch_scenario(true));
    let lane = receipt(&unfiltered, "targeted-tests[default]");
    assert_eq!(lane["culprit_exact"], false, "{unfiltered:#}");
    assert_eq!(lane["bisect_probes"][0]["verdict"], "no-evidence");
}

#[test]
fn a_targeted_green_heals_only_the_targets_it_ran() {
    let lane = json!({
        "id": "targeted-tests[default]", "kind": "test",
        "argv": ["cargo", "test", "--test", "alpha_native"],
        "expected_targets": ["alpha_native"],
    });
    let known = json!({"known_reds": {"targeted-tests[default]": {
        "hedge_native::cancel_test": {"bead": "asupersync-bi2462.165"},
        "alpha_native::old_red": {"bead": "asupersync-known2"},
    }}});
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "c")], "lanes": [lane]},
        "state": known,
        "lane_logs": {"targeted-tests[default]": {sha(1): {"log": test_green("alpha_native", 4)}}},
    });
    let result = evaluate(&scenario);
    assert_eq!(
        receipt(&result, "targeted-tests[default]")["healed"],
        json!(["alpha_native::old_red"])
    );
    assert_eq!(
        result["state"]["known_reds"]["targeted-tests[default]"],
        json!({"hedge_native::cancel_test": {"bead": "asupersync-bi2462.165"}}),
        "a run that never executed hedge_native cannot heal it"
    );
}

#[test]
fn a_healed_red_is_reported_on_its_bead_and_closes_it_only_when_nothing_it_tracks_is_red() {
    let lane = |id: &str, target: &str| json!({"id": id, "kind": "test", "argv": ["cargo", "test", "--test", target], "expected_targets": [target]});
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "c")],
                 "lanes": [lane("a", "alpha_native"), lane("b", "beta_native")]},
        "state": {
            "known_reds": {
                "a": {
                    "alpha_native::shared": {"bead": "asupersync-shared"},
                    "alpha_native::solo": {"bead": "asupersync-solo"},
                    "alpha_native::owned": {"bead": "asupersync-owned"},
                    "alpha_native::queued": {"bead": null},
                },
                // Lane b never runs gamma_native, so this red cannot heal here.
                "b": {"gamma_native::other": {"bead": "asupersync-shared"}},
            },
            "pending_beads": [
                {"lane": "a", "new_targets": ["alpha_native::queued"], "title": "healed before filing"},
                {"lane": "b", "new_targets": ["gamma_native::x"], "title": "still red"},
            ],
        },
        "lane_logs": {
            "a": {sha(1): {"log": test_green("alpha_native", 4)}},
            "b": {sha(1): {"log": test_green("beta_native", 2)}},
        },
        "open_issues": [
            {"id": "asupersync-shared", "status": "open"},
            {"id": "asupersync-solo", "status": "open"},
            {"id": "asupersync-owned", "status": "in_progress", "assignee": "SomeAgent"},
        ],
    });
    let result = evaluate(&scenario);
    let argv: Vec<Vec<String>> =
        serde_json::from_value(result["heal_calls"].clone()).expect("recorded br calls");
    let calls: Vec<&[String]> = argv.iter().map(|call| br_args(call)).collect();
    let commented: Vec<&str> = calls
        .iter()
        .filter(|call| call[0] == "comments")
        .map(|call| call[2].as_str())
        .collect();
    let closed: Vec<&str> = calls
        .iter()
        .filter(|call| call[0] == "close")
        .map(|call| call[1].as_str())
        .collect();
    assert_eq!(
        commented,
        ["asupersync-owned", "asupersync-shared", "asupersync-solo"],
        "every filed bead with a heal gets the receipt: {calls:?}"
    );
    assert_eq!(
        closed,
        ["asupersync-solo"],
        "closed only when open, unassigned and nothing it tracks is red: {calls:?}"
    );
    let shared_note = calls
        .iter()
        .find(|call| call[0] == "comments" && call[2] == "asupersync-shared")
        .expect("shared comment");
    assert!(shared_note[4].contains("stays open"), "{shared_note:?}");
    let pending: Vec<&str> = result["state"]["pending_beads"]
        .as_array()
        .expect("pending")
        .iter()
        .map(|payload| payload["title"].as_str().expect("title"))
        .collect();
    assert_eq!(
        pending,
        ["still red"],
        "a queued filing for a healed red is dropped"
    );
}

#[test]
fn an_already_tracked_red_is_not_filed_again() {
    let hedge = "hedge_factory_native::cancellation_during_backup_delay_stops_primary_and_never_launches_backup";
    let tracked = json!({
        "id": "asupersync-bi2462.165",
        "title": "Owner cancellation never reaches parked branches",
        "description": "tests/hedge_factory_native.rs::cancellation_during_backup_delay_stops_primary_and_never_launches_backup",
    });
    let unrelated =
        json!({"id": "asupersync-x1", "title": "cancellation_during_backup", "description": ""});
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"existing_bead_for": [
            {"new_targets": [hedge], "open_issues": [unrelated.clone(), tracked.clone()]},
            {"new_targets": [hedge, "hedge_factory_native::other_test"], "open_issues": [tracked.clone()]},
            {"new_targets": ["remote exit 101"], "open_issues": [tracked]},
            {"new_targets": [hedge], "open_issues": [unrelated]},
        ]},
    });
    assert_eq!(
        evaluate(&scenario)["probe_results"]["existing_bead_for"],
        json!(["asupersync-bi2462.165", null, null, null]),
        "whole-word match on every new test; a partial name or an error-keyed red never matches"
    );
}

#[test]
fn a_failed_bead_filing_is_queued_and_retried_not_lost() {
    // A red enters known_reds on first sight, so its payload is never produced
    // again. On 2026-09-25 the tracker refused every write for hours; a filing
    // that failed then must survive until a later run can file it.
    let lane = "targeted-tests[default]";
    let payload =
        |title: &str, target: &str| json!({"title": title, "lane": lane, "new_targets": [target]});
    let tracked = json!({"id": "asupersync-x9", "title": "t2 is broken",
                         "description": "beta_native::t2 fails"});
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"file_or_queue": [{
            "state": {"known_reds": {lane: {
                "alpha_native::t1": {"bead": null}, "beta_native::t2": {"bead": null}}}},
            "rounds": [
                {"payloads": [payload("RED t1", "alpha_native::t1")], "fail_titles": ["RED t1"]},
                {"payloads": [payload("RED t2", "beta_native::t2")],
                 "fail_titles": ["RED t1", "RED t2"]},
                {"payloads": [], "open_issues": [tracked]},
                {"payloads": []},
            ],
        }]},
    });
    let rounds = &evaluate(&scenario)["probe_results"]["file_or_queue"][0];
    let pending = |i: usize| rounds[i]["pending"].clone();
    assert_eq!(pending(0), json!(["RED t1"]), "a failed filing is queued");
    assert_eq!(
        pending(1),
        json!(["RED t1", "RED t2"]),
        "retried, still failing"
    );
    assert_eq!(
        pending(2),
        json!([]),
        "the recovered tracker drains the queue"
    );
    assert_eq!(
        rounds[2]["beads"][lane],
        json!({"alpha_native::t1": "filed:RED t1", "beta_native::t2": "asupersync-x9"}),
        "the queued red is filed; one that gained an open bead meanwhile is recorded, not refiled"
    );
    assert_eq!(pending(3), json!([]));
}

/// A commit for the rule-3 ledger (bi2462.147.1): `hh:mm` on 2026-09-24 UTC.
fn ledger_commit(n: u8, email: &str, at: &str, message: &str, path: &str) -> Value {
    let mut c = commit(n, email, message);
    c["committed_at"] = json!(format!("2026-09-24T{at}:00+00:00"));
    c["paths"] = json!([path]);
    c["is_merge"] = json!(false);
    c
}

fn run_receipt(head: u8, at: &str, verdict: &str, culprit: Option<u8>) -> Value {
    json!({
        "sha": sha(head),
        "recorded_at": format!("2026-09-24T{at}:00+00:00"),
        "lane": "check-default",
        "verdict": verdict,
        "culprit": culprit.map(sha),
    })
}

fn ledger_probe(receipts: Vec<Value>) -> Value {
    ledger_probe_with(receipts, json!({}), json!([]))
}

/// `filed` maps escalated commits to their beads; `open_issues` is the tracker.
fn ledger_probe_with(receipts: Vec<Value>, filed: Value, open_issues: Value) -> Value {
    let commits = vec![
        ledger_commit(1, WEB_API, "00:00", "one", "src/a.rs"),
        ledger_commit(2, "dev@example.com", "00:30", "two", "src/a.rs"),
        ledger_commit(3, WEB_API, "04:00", "three", "src/a.rs"),
        ledger_commit(4, WEB_API, "04:30", "four", "src/a.rs"),
        ledger_commit(5, WEB_API, "05:00", "five", "src/a.rs"),
        ledger_commit(
            6,
            "dev@example.com",
            "07:00",
            "six: Tests have NOT been compiled or executed",
            "src/b.rs",
        ),
        ledger_commit(7, WEB_API, "11:00", "seven", "src/a.rs"),
        ledger_commit(8, WEB_API, "11:30", "eight", "docs/x.md"),
    ];
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"receipt_ledger": [{
            "commits": commits, "receipts": receipts, "now": "2026-09-24T12:00:00+00:00",
            "filed": filed, "open_issues": open_issues,
        }]},
    });
    evaluate(&scenario)["probe_results"]["receipt_ledger"][0].clone()
}

/// Validation Path rule 3: a no-compile-path commit gets a receipt within 2 h, and no
/// green receipt after 6 h means one P0 naming it. A red elsewhere blocks instead of
/// multiplying P0s; the red's own bead covers it.
#[test]
fn rule3_ledger_lists_overdue_commits_and_escalates_after_six_hours() {
    let probe = ledger_probe(vec![
        run_receipt(2, "01:00", "green", None),
        run_receipt(4, "09:00", "red", Some(4)),
    ]);
    let ledger = &probe["ledger"];
    let statuses: Vec<(String, String)> = ledger["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            (
                r["sha"].as_str().expect("sha")[..2].to_owned(),
                r["status"].as_str().expect("status").to_owned(),
            )
        })
        .collect();
    let expected: Vec<(String, String)> = [
        ("01", "green"),
        ("03", "blocked"),
        ("04", "red"),
        ("05", "escalate"),
        ("06", "overdue"),
        ("07", "pending"),
    ]
    .into_iter()
    .map(|(s, st)| (s.to_owned(), st.to_owned()))
    .collect();
    assert_eq!(statuses, expected, "{ledger:#}");
    assert_eq!(
        ledger["owed"], 6,
        "a plain dev commit and a docs-only commit owe nothing"
    );
    assert_eq!(ledger["green_within_2h"], 1);
    assert_eq!(ledger["rows"][0]["latency_h"], 1.0);
    assert_eq!(ledger["rows"][1]["blocked_by"], json!([sha(4)]));
    assert_eq!(ledger["overdue"], json!([sha(6)]));
    assert_eq!(ledger["escalate"], json!([sha(5)]));
    let payloads = probe["payloads"].as_array().expect("payloads");
    assert_eq!(payloads.len(), 1);
    let title = payloads[0]["title"].as_str().expect("title");
    assert!(
        title.starts_with(&format!(
            "[main-watchdog] NO GREEN RECEIPT after 6 h: {}",
            &sha(5)[..9]
        )),
        "{title}"
    );
    assert!(title.contains(WEB_API), "{title}");
    assert_eq!(payloads[0]["priority"], 0);
    assert_eq!(payloads[0]["parent"], "asupersync-bi2462.147");

    // Negative twin: a later all-green run covers everything, so nothing is owed.
    let healed = ledger_probe(vec![
        run_receipt(2, "01:00", "green", None),
        run_receipt(4, "09:00", "red", Some(4)),
        run_receipt(8, "11:45", "green", None),
    ]);
    assert_eq!(healed["ledger"]["escalate"], json!([]));
    assert_eq!(healed["ledger"]["overdue"], json!([]));
    assert_eq!(healed["payloads"], json!([]));
    assert!(
        healed["ledger"]["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .all(|r| r["status"] == "green"),
        "{healed:#}"
    );
}

/// One chronic known red must not keep every later commit escalated forever: a run
/// whose red lanes fail only through known reds (each with its own bead) covers its
/// commits. A new red or a lane without evidence does not. A covered escalation gets
/// its receipt once, and only an open, unassigned bead is closed.
#[test]
fn a_run_red_only_through_known_reds_covers_and_closes_its_escalations() {
    let known_red_only = || {
        let mut lane = run_receipt(8, "11:45", "red", None);
        lane["lane"] = json!("targeted-lib");
        lane["still_red"] = json!({"asupersync (lib test)": "asupersync-bi2462.147.4"});
        lane
    };
    // .92 is already closed, so it is not among the open issues.
    let mut filed = json!({});
    filed[sha(3)] = json!("asupersync-bi2462.147.91");
    filed[sha(5)] = json!("asupersync-bi2462.147.90");
    filed[sha(7)] = json!("asupersync-bi2462.147.92");
    let open_issues = json!([
        {"id": "asupersync-bi2462.147.90", "status": "open"},
        {"id": "asupersync-bi2462.147.91", "status": "in_progress", "assignee": "SomeAgent"},
    ]);
    let probe = |extra: Option<Value>| {
        let mut receipts = vec![
            run_receipt(2, "01:00", "green", None),
            run_receipt(4, "09:00", "red", Some(4)),
            run_receipt(8, "11:45", "green", None),
            known_red_only(),
        ];
        receipts.extend(extra);
        ledger_probe_with(receipts, filed.clone(), open_issues.clone())
    };
    let greens = |probe: &Value| {
        probe["ledger"]["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .filter(|r| r["status"] == "green")
            .count()
    };

    let covered = probe(None);
    assert_eq!(greens(&covered), 6, "{covered:#}");
    assert_eq!(covered["ledger"]["rows"][3]["receipt_head"], json!(sha(8)));
    let closures = &covered["closures"];
    assert_eq!(
        closures["reported"],
        json!([
            {"bead": "asupersync-bi2462.147.91", "sha": sha(3), "closed": false},
            {"bead": "asupersync-bi2462.147.90", "sha": sha(5), "closed": true},
        ]),
        "{closures:#}"
    );
    let argv: Vec<Vec<String>> =
        serde_json::from_value(closures["commands"].clone()).expect("commands");
    let commands: Vec<&[String]> = argv.iter().map(|call| br_args(call)).collect();
    let verbs: Vec<(&str, &str)> = commands
        .iter()
        .map(|c| (c[0].as_str(), c[1].as_str()))
        .collect();
    assert_eq!(
        verbs,
        [
            ("comments", "add"),
            ("comments", "add"),
            ("close", "asupersync-bi2462.147.90"),
        ],
        "{closures:#}"
    );
    assert_eq!(commands[0][2], "asupersync-bi2462.147.91");
    assert_eq!(
        commands[2][3],
        format!("covered at {} (main watchdog)", &sha(8)[..9])
    );
    assert_eq!(
        closures["filed"],
        json!({}),
        "covered commits are reported once; an already closed bead is only forgotten"
    );

    let mut new_red = run_receipt(8, "11:45", "red", Some(7));
    new_red["new_red"] = json!(["asupersync (test \"alpha_native\")"]);
    let mut no_evidence = run_receipt(8, "11:45", "no-evidence", None);
    no_evidence["lane"] = json!("clippy-default");
    for (name, extra) in [("new red", new_red), ("no evidence", no_evidence)] {
        let uncovered = probe(Some(extra));
        assert_eq!(greens(&uncovered), 1, "{name}: {uncovered:#}");
        assert_eq!(uncovered["closures"]["reported"], json!([]), "{name}");
        assert_eq!(uncovered["closures"]["commands"], json!([]), "{name}");
        assert_eq!(uncovered["closures"]["filed"], filed, "{name}");
    }
}

#[test]
fn first_run_ledger_names_targets_no_lane_has_executed() {
    // A target that ran zero tests is not executed; one that ran tests is.
    let lane = json!({
        "id": "targeted-tests[default]", "kind": "test", "argv": ["cargo", "test"],
        "expected_targets": ["alpha_native", "beta_native"],
    });
    let log = format!(
        "{}     Running tests/beta_native.rs (x)\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
        test_green("alpha_native", 2).replace("  Remote command finished: exit=0 in 1000ms\n", "")
    ) + "  Remote command finished: exit=0 in 1000ms\n";
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": [lane]},
        "lane_logs": {"targeted-tests[default]": {sha(1): {"log": log}}},
        "probes": {"first_run_ledger": [
            {"added": ["alpha_native", "beta_native"], "receipts": [{"targets_executed": ["alpha_native"]}]},
            {"added": ["alpha_native"], "receipts": [{"targets_executed": ["alpha_native"]}]},
        ]},
    });
    let result = evaluate(&scenario);
    assert_eq!(
        receipt(&result, "targeted-tests[default]")["targets_executed"],
        json!(["alpha_native"])
    );
    assert_eq!(
        result["probe_results"]["first_run_ledger"],
        json!([
            {"added": 2, "never_run": ["beta_native"]},
            {"added": 1, "never_run": []}
        ])
    );
}

#[test]
fn stranded_work_and_duplicate_fixes_alert_only_past_their_thresholds() {
    let now = "2026-09-24T12:00:00+00:00";
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {
            "stranded": [
                {"now": now, "tree": {"ahead": 2, "oldest_unpushed_at": "2026-09-24T09:00:00+00:00",
                                      "oldest_unpushed_beads": ["asupersync-x1"], "behind": 0}},
                {"now": now, "tree": {"ahead": 2, "oldest_unpushed_at": "2026-09-24T11:00:00+00:00",
                                      "oldest_unpushed_beads": [], "behind": 5}},
                {"now": now, "tree": {"ahead": 0, "landed_elsewhere": 4, "behind": 6}},
            ],
            "duplicate_fixes": [
                {"origin": [{"id": "o1", "beads": ["asupersync-fix1", "asupersync-bi2462.162"],
                             "hunks": {"src/a.rs": [[10, 20]]}}],
                 "local": [
                     {"id": "same-bead", "beads": ["asupersync-fix1"], "hunks": {}},
                     {"id": "process-bead-disjoint", "beads": ["asupersync-bi2462.162"],
                      "hunks": {"src/a.rs": [[30, 40]]}},
                     {"id": "overlap", "beads": [], "hunks": {"src/a.rs": [[18, 25]]}},
                 ]},
            ],
            "diff_hunks": [
                "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -10,3 +10,4 @@ fn x\n-a\n@@ -40 +41,2 @@\n+b\n@@ -50,0 +52 @@\n+c\n",
            ],
        },
    });
    let probes = &evaluate(&scenario)["probe_results"];
    let stranded = probes["stranded_alerts"].as_array().expect("stranded");
    let first = stranded[0].as_array().expect("case 0");
    assert_eq!(first.len(), 1, "{stranded:?}");
    assert!(
        first[0]
            .as_str()
            .expect("alert")
            .starts_with("stranded: main is 2 commit(s) ahead")
            && first[0].as_str().expect("alert").contains("asupersync-x1"),
        "{first:?}"
    );
    assert_eq!(
        stranded[1],
        json!([]),
        "1 h unpushed and 5 behind stay silent"
    );
    let third: Vec<&str> = stranded[2]
        .as_array()
        .expect("case 2")
        .iter()
        .map(|a| a.as_str().expect("alert"))
        .collect();
    assert!(
        third.len() == 2
            && third[0].starts_with("stale: 4 commit(s)")
            && third[1].starts_with("behind: main is 6"),
        "{third:?}"
    );
    assert_eq!(
        probes["duplicate_fixes"],
        json!([[
            {"origin": "o1", "local": "same-bead", "beads": ["asupersync-fix1"], "overlapping_files": []},
            {"origin": "o1", "local": "overlap", "beads": [], "overlapping_files": ["src/a.rs"]}
        ]]),
        "a shared process bead and disjoint lines are not a duplicate"
    );
    assert_eq!(
        probes["diff_hunks"],
        json!([{"src/a.rs": [[10, 12], [40, 40], [50, 50]]}])
    );
}

/// A failing lib unit test is keyed `lib::<test>`. The lib target exists wherever
/// src/lib.rs does; looking for tests/lib.rs made every bisect probe read
/// target-absent, so run2 blamed its batch head (bi2462.147.4).
#[test]
fn lib_unit_test_target_exists_through_src_lib() {
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"target_root_paths": [
            {"name": "lib"},
            {"name": "alpha_native"},
            {"name": "beta", "registry": {"tests/b/main.rs": {"name": "beta", "features": []}}},
        ]},
    });
    assert_eq!(
        evaluate(&scenario)["probe_results"]["target_root_paths"],
        json!([
            ["src/lib.rs"],
            ["tests/alpha_native.rs"],
            ["tests/b/main.rs"]
        ])
    );
}

/// bi2462.147.1 item 5: an owner decision recorded in a bead comment with no later commit
/// citing the bead is listed after 48 h. A passing mention of the phrase is not a decision.
#[test]
fn decision_ledger_lists_owner_decisions_nothing_has_implemented() {
    let decision =
        |at: &str| json!({"created_at": at, "text": "OWNER DECISION, recorded verbatim: ship it."});
    let scenario = json!({
        "plan": {"commits": [commit(1, "dev@example.com", "x")], "lanes": []},
        "lane_logs": {},
        "probes": {"decision_ledger": [{
            "now": "2026-09-24T12:00:00+00:00",
            "issues": [
                {"id": "asupersync-done", "status": "open", "comments": [decision("2026-09-20T00:00:00Z")]},
                {"id": "asupersync-stale", "status": "open", "comments": [decision("2026-09-21T00:00:00Z")]},
                {"id": "asupersync-young", "status": "open", "comments": [decision("2026-09-24T00:00:00Z")]},
                {"id": "asupersync-settled", "status": "closed", "comments": [decision("2026-09-20T00:00:00Z")]},
                {"id": "asupersync-mention", "status": "open", "comments": [
                    {"created_at": "2026-09-20T00:00:00Z", "text": "this remains the owner decision to make"}
                ]},
            ],
            "commits": [
                // Before the decision: does not count as implementing it.
                {"sha": sha(1), "committed_at": "2026-09-19T00:00:00+00:00", "beads": ["asupersync-stale"]},
                {"sha": sha(2), "committed_at": "2026-09-21T00:00:00+00:00", "beads": ["asupersync-done"]},
            ],
        }]},
    });
    let rows = evaluate(&scenario)["probe_results"]["decision_ledger"][0].clone();
    let statuses: Vec<(String, String)> = rows
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            (
                r["bead"].as_str().expect("bead").to_owned(),
                r["status"].as_str().expect("status").to_owned(),
            )
        })
        .collect();
    let expected: Vec<(String, String)> = [
        ("asupersync-done", "implemented"),
        ("asupersync-settled", "closed"),
        ("asupersync-stale", "stale"),
        ("asupersync-young", "pending"),
    ]
    .into_iter()
    .map(|(b, s)| (b.to_owned(), s.to_owned()))
    .collect();
    assert_eq!(statuses, expected, "{rows:#}");
    assert_eq!(rows[0]["implemented_by"], sha(2));
}

#[test]
fn script_documents_its_non_claims() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/main_watchdog.py"),
    )
    .expect("read watchdog");
    for marker in [
        "asupersync-bi2462.147",
        "It never\nreverts, edits, or pushes anyone's code.",
        "--clean-overlay",
        "never green",
    ] {
        assert!(
            source.contains(marker),
            "watchdog docstring lost: {marker:?}"
        );
    }
}
