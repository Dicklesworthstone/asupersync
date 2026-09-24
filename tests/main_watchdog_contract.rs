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
            true, true, true, true, true, true, false, false, false, false, false, false
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
