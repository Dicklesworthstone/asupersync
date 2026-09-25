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
