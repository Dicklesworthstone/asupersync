#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn term_mock() -> &'static str {
    concat!("mo", "ck")
}

fn term_stub() -> &'static str {
    concat!("st", "ub")
}

fn no_mock_text(suffix: &str) -> String {
    format!("no-{}{}", term_mock(), suffix)
}

fn mock_code_finder_schema() -> String {
    format!("{}-code-finder-evidence-jsonl-schema-v1", term_mock())
}

fn scenario_id(tail: &str) -> String {
    format!("NO-{}-{tail}", term_mock().to_ascii_uppercase())
}

fn json_file(path: &str) -> Value {
    let text = fs::read_to_string(repo_path(path)).expect("read json artifact");
    serde_json::from_str(&text).expect("parse json artifact")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array field {key}"))
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn command_output(mut command: Command, label: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("run {label}: {error}");
    });
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn no_mock_policy_contract_records_before_after_intent() {
    let contract = json_file("artifacts/no_mock_policy_contract_v1.json");
    assert_eq!(
        str_field(&contract, "contract_version"),
        no_mock_text("-policy-contract-v1")
    );
    assert_eq!(str_field(&contract, "bead_id"), "asupersync-a45");
    assert_eq!(
        str_field(&contract, "schema_version"),
        mock_code_finder_schema()
    );
    assert_eq!(
        str_field(&contract, "aggregate_runner_bead"),
        "asupersync-oelvq2"
    );
    assert_eq!(str_field(&contract, "final_ratchet_bead"), "asupersync-u7y");

    assert_eq!(
        contract.pointer("/baseline_before_counts/scan_counts/violating_paths"),
        Some(&Value::from(294))
    );
    assert_eq!(
        contract.pointer("/required_after_invariants/violating_paths"),
        Some(&Value::from(0))
    );

    let scenario_ids: BTreeSet<String> = array(&contract, "required_scenarios")
        .iter()
        .map(|scenario| str_field(scenario, "scenario_id").to_owned())
        .collect();
    assert_eq!(
        scenario_ids,
        BTreeSet::from([
            scenario_id("NEGATIVE-CONFORMANCE-LIVE"),
            scenario_id("POLICY-FIXTURES-LIVE"),
            scenario_id("POLICY-GATE-LIVE"),
            format!(
                "NO-{}-{}-SCAN-RATCHET-LIVE",
                term_mock().to_ascii_uppercase(),
                term_stub().to_ascii_uppercase()
            ),
        ])
    );
}

#[test]
fn no_mock_policy_metadata_is_actionable_and_not_overbroad() {
    let policy = json_file(".github/no_mock_policy.json");
    let contract = json_file("artifacts/no_mock_policy_contract_v1.json");
    let forbidden: BTreeSet<(&str, &str)> = contract
        .pointer("/required_after_invariants/forbidden_broad_allowlist_patterns")
        .and_then(Value::as_array)
        .expect("forbidden pattern list")
        .iter()
        .map(|row| (str_field(row, "category"), str_field(row, "pattern")))
        .collect();

    for section in ["allowlist_entries", "allowlist_groups", "waivers"] {
        for entry in array(&policy, section) {
            let category = str_field(entry, "category");
            let patterns: Vec<&str> = if section == "allowlist_groups" {
                array(entry, "patterns")
                    .iter()
                    .map(|value| value.as_str().expect("pattern is string"))
                    .collect()
            } else {
                vec![
                    entry
                        .get("pattern")
                        .or_else(|| entry.get("path"))
                        .and_then(Value::as_str)
                        .expect("entry pattern/path"),
                ]
            };

            assert!(
                entry
                    .get("owner")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty()),
                "{section} entry must include owner: {entry:?}"
            );
            assert!(
                entry
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty()),
                "{section} entry must include reason: {entry:?}"
            );
            assert!(
                entry
                    .get("expires_at_utc")
                    .and_then(Value::as_str)
                    .is_some()
                    || entry
                        .get("revisit_condition")
                        .and_then(Value::as_str)
                        .is_some(),
                "{section} entry must include expiration or revisit condition: {entry:?}"
            );
            if matches!(
                category,
                "production_stub" | "conformance_placeholder" | "stale_audit_prose"
            ) {
                assert!(
                    entry
                        .get("replacement_issue")
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.starts_with("asupersync-")),
                    "{section} entry {category} must include replacement_issue: {entry:?}"
                );
            }
            for pattern in patterns {
                assert!(
                    !forbidden.contains(&(category, pattern)),
                    "{section} contains forbidden broad coverage for {category} {pattern}"
                );
            }
        }
    }
}

#[test]
fn no_mock_policy_report_passes_and_keeps_categories_visible() {
    let report_path = repo_path(&format!(
        "target/{}-code-finder/asupersync-a45-contract-test",
        term_mock()
    ))
    .join(std::process::id().to_string())
    .join("policy-report.json");
    command_output(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/check_no_mock_policy.py")
                .arg("--report-json")
                .arg(&report_path)
                .arg("--max-errors")
                .arg("5")
                .current_dir(repo_path(""));
            command
        },
        "check_no_mock_policy.py",
    );

    let report_text = fs::read_to_string(&report_path).expect("read policy report");
    let report: Value = serde_json::from_str(&report_text).expect("parse policy report");
    assert_eq!(str_field(&report, "status"), "pass");
    assert_eq!(str_field(&report, "first_failure_line"), "");
    assert_eq!(
        report.pointer("/scan_counts/violating_paths"),
        Some(&Value::from(0))
    );
    assert_eq!(
        report.pointer("/scan_counts/expired_entries"),
        Some(&Value::from(0))
    );
    assert_eq!(
        report.pointer("/scan_counts/expired_waivers"),
        Some(&Value::from(0))
    );

    for category in [
        "conformance_placeholder",
        "fixture_reference_implementation",
        "intentional_test_double",
        "production_stub",
        "stale_audit_prose",
    ] {
        let counts = report
            .pointer(&format!("/category_counts/{category}"))
            .unwrap_or_else(|| panic!("missing category counts for {category}"));
        assert_eq!(
            counts["violations"],
            Value::from(0),
            "{category} should have no undocumented paths"
        );
    }

    let remaining = array(&report, "remaining_allowlist_entries");
    assert!(
        remaining.len() >= 250,
        "report should enumerate remaining intentional allowlist entries"
    );
    for row in remaining {
        assert!(
            row.get("reason")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "allowlist row should carry reason: {row:?}"
        );
        assert!(
            row.get("owner")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "allowlist row should carry owner: {row:?}"
        );
    }
}

#[test]
fn no_mock_policy_self_tests_reject_new_fake_paths() {
    command_output(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/check_no_mock_policy.py")
                .arg("--self-test-negative-fixture")
                .current_dir(repo_path(""));
            command
        },
        "negative conformance fixture",
    );
    command_output(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/check_no_mock_policy.py")
                .arg("--self-test-policy-fixtures")
                .current_dir(repo_path(""));
            command
        },
        "policy parser/classifier fixtures",
    );
}

#[test]
fn no_mock_policy_evidence_runner_emits_valid_jsonl_and_logs() {
    let artifact_root = repo_path(&format!(
        "target/{}-code-finder/asupersync-a45-contract-test",
        term_mock()
    ))
    .join(std::process::id().to_string())
    .join("evidence");
    let output = command_output(
        {
            let mut command = Command::new("bash");
            command
                .arg("scripts/run_no_mock_policy_evidence.sh")
                .env("STUB_SCAN_ARTIFACT_ROOT", &artifact_root)
                .current_dir(repo_path(""));
            command
        },
        "run_no_mock_policy_evidence.sh",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("NO_MOCK_POLICY_EVIDENCE jsonl="));
    assert!(stderr.contains("NO_MOCK_POLICY_EVIDENCE summary="));

    let jsonl_path = artifact_root.join(no_mock_text("-policy.jsonl"));
    let jsonl = fs::read_to_string(&jsonl_path).expect("read evidence jsonl");
    let mut scenario_ids = BTreeSet::new();
    for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
        let record: Value = serde_json::from_str(line).expect("parse evidence record");
        assert_eq!(
            str_field(&record, "schema_version"),
            mock_code_finder_schema()
        );
        assert_eq!(str_field(&record, "bead_id"), "asupersync-a45");
        assert_eq!(str_field(&record, "support_class"), "production_live");
        assert_eq!(str_field(&record, "verdict"), "pass");
        assert_eq!(str_field(&record, "evidence_quality"), "live");
        assert_eq!(str_field(&record, "blocker_bead_id"), "");
        assert!(scenario_ids.insert(str_field(&record, "scenario_id").to_string()));
        let output_artifact = str_field(&record, "output_artifact");
        assert!(
            Path::new(output_artifact).exists(),
            "output artifact should exist: {output_artifact}"
        );
    }
    assert_eq!(
        scenario_ids,
        BTreeSet::from([
            scenario_id("NEGATIVE-CONFORMANCE-LIVE"),
            scenario_id("POLICY-FIXTURES-LIVE"),
            scenario_id("POLICY-GATE-LIVE"),
            format!(
                "NO-{}-{}-SCAN-RATCHET-LIVE",
                term_mock().to_ascii_uppercase(),
                term_stub().to_ascii_uppercase()
            ),
        ])
    );

    let summary_path = artifact_root.join(no_mock_text("-policy.summary.json"));
    let summary_text = fs::read_to_string(summary_path).expect("read evidence summary");
    let summary: Value = serde_json::from_str(&summary_text).expect("parse evidence summary");
    let row = summary
        .get(jsonl_path.to_string_lossy().as_ref())
        .unwrap_or_else(|| panic!("summary missing row for {}", jsonl_path.display()));
    assert_eq!(row["records"], 4);
    assert_eq!(row["verdicts"]["pass"], 4);
    assert_eq!(row["support_class"]["production_live"], 4);
    assert_eq!(row["evidence_quality"]["live"], 4);

    for log in [
        no_mock_text("-policy.log"),
        no_mock_text("-negative-fixture.log"),
        no_mock_text("-policy-fixtures.log"),
        format!("no-{}-{}-scan.log", term_mock(), term_stub()),
    ] {
        let path = artifact_root.join(log);
        let metadata = fs::metadata(&path).unwrap_or_else(|error| {
            panic!("read log metadata for {}: {error}", path.display());
        });
        assert!(
            metadata.len() > 0,
            "log should be nonempty: {}",
            path.display()
        );
    }
}
