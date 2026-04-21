#![allow(clippy::all)]
//! Contract tests for TOKIO-REPLACE parity dashboard generator (2oh2u.1.4.1).
//!
//! Validates deterministic machine-readable and human-readable outputs sourced
//! from repo truth (`.beads/issues.jsonl` + inventory/evidence artifacts).

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const SCRIPT_PATH: &str = "scripts/generate_tokio_parity_dashboard.py";
const WORKFLOW_PATH: &str = ".github/workflows/tokio_parity_dashboard_drift.yml";
const FIXED_TIMESTAMP: &str = "2026-03-03T00:00:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn make_temp_dir(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be monotonic for test temp dirs")
        .as_nanos();
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("asupersync_{test_name}_{pid}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("must create temp output dir");
    dir
}

fn run_generator(json_out: &Path, md_out: &Path) {
    let status = Command::new("python3")
        .arg(SCRIPT_PATH)
        .arg("--repo-root")
        .arg(repo_root())
        .arg("--json-out")
        .arg(json_out)
        .arg("--md-out")
        .arg(md_out)
        .arg("--generated-at")
        .arg(FIXED_TIMESTAMP)
        .status()
        .expect("failed to execute parity dashboard generator");
    assert!(status.success(), "generator command must exit successfully");
}

fn parse_json(path: &Path) -> Value {
    let raw = std::fs::read_to_string(path).expect("must read generated json");
    serde_json::from_str(&raw).expect("generated json must parse")
}

#[test]
fn generator_script_exists_with_python_shebang_and_required_flags() {
    let script_path = repo_root().join(SCRIPT_PATH);
    assert!(script_path.exists(), "generator script must exist");

    let script = std::fs::read_to_string(script_path).expect("must read generator script");
    assert!(
        script.starts_with("#!/usr/bin/env python3"),
        "generator must use python3 shebang"
    );

    for flag in [
        "--repo-root",
        "--issues",
        "--inventory-doc",
        "--json-out",
        "--md-out",
        "--generated-at",
    ] {
        assert!(
            script.contains(flag),
            "script must expose required CLI flag: {flag}"
        );
    }
}

#[test]
fn generator_emits_machine_and_human_artifacts() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_emit");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");

    run_generator(&json_out, &md_out);

    assert!(json_out.exists(), "json dashboard output must exist");
    assert!(md_out.exists(), "markdown dashboard output must exist");

    let md = std::fs::read_to_string(&md_out).expect("must read markdown dashboard");
    assert!(
        md.len() > 4000,
        "markdown dashboard should be substantial, got {} bytes",
        md.len()
    );
}

#[test]
fn json_dashboard_has_required_schema_and_identity_fields() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_schema");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let payload = parse_json(&json_out);
    assert_eq!(
        payload["schema_version"].as_str(),
        Some("tokio-parity-dashboard-v1"),
        "schema_version must match dashboard contract"
    );
    assert_eq!(
        payload["bead_id"].as_str(),
        Some("asupersync-2oh2u.1.4.1"),
        "bead_id must match T1.4.a"
    );
    assert_eq!(
        payload["program_id"].as_str(),
        Some("asupersync-2oh2u"),
        "program_id must match TOKIO-REPLACE epic id"
    );
    assert_eq!(
        payload["generated_at"].as_str(),
        Some(FIXED_TIMESTAMP),
        "generated_at must reflect explicit override"
    );

    let policy = payload["ci_policy"]
        .as_object()
        .expect("ci_policy must be object");
    for field in [
        "policy_id",
        "hard_fail_conditions",
        "promotion_criteria",
        "rollback_or_exception_criteria",
        "ownership",
    ] {
        assert!(
            policy.get(field).is_some(),
            "ci_policy missing required field: {field}"
        );
    }

    let routing = payload["drift_routing"]
        .as_object()
        .expect("drift_routing must be object");
    for field in [
        "policy_id",
        "generated_at",
        "owner_roles",
        "alert_count",
        "alerts",
    ] {
        assert!(
            routing.get(field).is_some(),
            "drift_routing missing required field: {field}"
        );
    }

    let alerts = payload["drift_routing"]["alerts"]
        .as_array()
        .expect("drift_routing.alerts must be array");
    assert_eq!(
        payload["drift_routing"]["alert_count"].as_u64(),
        Some(alerts.len() as u64),
        "drift_routing.alert_count must match alerts length"
    );
}

#[test]
fn json_dashboard_includes_all_tracks_t1_through_t9() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_tracks");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let payload = parse_json(&json_out);
    let tracks = payload["tracks"]
        .as_array()
        .expect("tracks must be an array");
    assert_eq!(tracks.len(), 9, "dashboard must include exactly 9 tracks");

    let observed: BTreeSet<String> = tracks
        .iter()
        .map(|row| {
            row["track"]
                .as_str()
                .expect("track id must be string")
                .to_string()
        })
        .collect();
    let expected: BTreeSet<String> = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(observed, expected, "must include all expected track ids");
}

#[test]
fn json_dashboard_track_rows_include_status_progress_evidence_and_blockers() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_track_rows");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let payload = parse_json(&json_out);
    let tracks = payload["tracks"]
        .as_array()
        .expect("tracks must be an array");

    for row in tracks {
        for field in [
            "track",
            "name",
            "root_bead_id",
            "root_status",
            "children_total",
            "children_closed",
            "completion_ratio",
            "evidence",
            "unresolved_blocker_count",
        ] {
            assert!(
                row.get(field).is_some(),
                "track row missing required field: {field}"
            );
        }

        let evidence = row["evidence"]
            .as_object()
            .expect("track evidence must be object");
        for field in [
            "required_count",
            "present_count",
            "completeness_ratio",
            "artifacts",
        ] {
            assert!(
                evidence.get(field).is_some(),
                "track evidence missing field: {field}"
            );
        }

        let required = evidence["required_count"]
            .as_u64()
            .expect("required_count must be u64");
        let present = evidence["present_count"]
            .as_u64()
            .expect("present_count must be u64");
        assert!(
            present <= required,
            "present evidence count cannot exceed required count"
        );
    }
}

#[test]
fn json_dashboard_includes_capability_family_snapshot_and_summary() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_capability");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let payload = parse_json(&json_out);
    let families = payload["capability_families"]
        .as_array()
        .expect("capability_families must be array");
    assert!(
        families.len() >= 28,
        "must include at least 28 capability families from inventory"
    );

    for family in families {
        for field in ["family_id", "title", "parity", "maturity", "determinism"] {
            assert!(
                family.get(field).is_some(),
                "capability family missing field: {field}"
            );
        }
    }

    let summary = payload["summary"]
        .as_object()
        .expect("summary must be object");
    for field in [
        "program_id",
        "program_issue_count",
        "status_counts",
        "track_count",
        "capability_family_count",
        "capability_parity_counts",
        "unresolved_blocker_count",
    ] {
        assert!(
            summary.get(field).is_some(),
            "summary missing field: {field}"
        );
    }
}

#[test]
fn blocker_chains_have_required_shape_when_present() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_blockers");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let payload = parse_json(&json_out);
    let chains = payload["blocker_chains"]
        .as_array()
        .expect("blocker_chains must be array");
    for chain in chains {
        for field in [
            "issue_id",
            "status",
            "direct_unresolved_dependencies",
            "chain",
            "chain_length",
            "cycle_detected",
        ] {
            assert!(
                chain.get(field).is_some(),
                "blocker chain row missing field: {field}"
            );
        }

        let chain_ids = chain["chain"]
            .as_array()
            .expect("chain must be array of issue ids");
        assert!(
            !chain_ids.is_empty(),
            "chain entry must include at least one issue id"
        );
        assert_eq!(
            chain_ids[0].as_str(),
            chain["issue_id"].as_str(),
            "chain must start with issue_id"
        );
    }
}

#[test]
fn drift_routing_alerts_include_beads_and_agent_mail_templates() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_drift_routing");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let payload = parse_json(&json_out);
    let alerts = payload["drift_routing"]["alerts"]
        .as_array()
        .expect("drift_routing.alerts must be array");

    for alert in alerts {
        for field in [
            "alert_id",
            "condition",
            "severity",
            "affected_issue_ids",
            "bead_actions",
            "agent_mail",
        ] {
            assert!(
                alert.get(field).is_some(),
                "drift alert missing required field: {field}"
            );
        }

        let actions = alert["bead_actions"]
            .as_object()
            .expect("bead_actions must be object");
        for field in ["status_flag_command", "follow_up_template_command"] {
            assert!(
                actions.get(field).is_some(),
                "bead_actions missing field: {field}"
            );
        }

        let agent_mail = alert["agent_mail"]
            .as_object()
            .expect("agent_mail must be object");
        for field in [
            "thread_id",
            "subject",
            "recipient_roles",
            "message_template",
            "send_message_template",
        ] {
            assert!(
                agent_mail.get(field).is_some(),
                "agent_mail missing field: {field}"
            );
        }
    }
}

#[test]
fn markdown_dashboard_contains_required_sections_and_tokens() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_markdown");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");
    run_generator(&json_out, &md_out);

    let md = std::fs::read_to_string(md_out).expect("must read markdown dashboard");
    for token in [
        "asupersync-2oh2u.1.4.1",
        "Track Parity Dashboard",
        "Evidence Completeness by Track",
        "Unresolved Blocker Chains",
        "Capability Family Parity Snapshot",
        "Drift-Detection Rules",
        "CI/Nightly Drift Enforcement Policy",
        "Drift Alert Routing",
        "tokio_parity_dashboard_drift.yml",
        "Deterministic Regeneration",
        "| T1 |",
        "| T9 |",
    ] {
        assert!(
            md.contains(token),
            "markdown missing required token: {token}"
        );
    }
}

#[test]
fn workflow_exists_and_enforces_hard_fail_drift_policy() {
    let workflow_path = repo_root().join(WORKFLOW_PATH);
    assert!(
        workflow_path.exists(),
        "parity dashboard CI/nightly workflow must exist"
    );

    let workflow =
        std::fs::read_to_string(workflow_path).expect("must read parity dashboard workflow");
    for token in [
        "schedule:",
        "workflow_dispatch:",
        "pull_request:",
        "python3 scripts/generate_tokio_parity_dashboard.py",
        "git diff --exit-code -- docs/tokio_parity_dashboard.json docs/tokio_parity_dashboard.md",
        "Enforce hard-fail drift policy",
        "closed_with_missing_evidence",
        "closed_with_unresolved_blockers",
        "closed_with_incomplete_children",
        "dependency_cycle_detected",
        "Suggested drift routing actions:",
        "status_flag_command:",
        "agent_mail_thread:",
        "cargo test --test tokio_parity_dashboard -- --nocapture",
    ] {
        assert!(
            workflow.contains(token),
            "workflow missing required hard-fail token: {token}"
        );
    }
}

#[test]
fn fixed_timestamp_generation_is_stable_across_repeated_runs() {
    let out_dir = make_temp_dir("tokio_parity_dashboard_determinism");
    let json_out = out_dir.join("tokio_parity_dashboard.json");
    let md_out = out_dir.join("tokio_parity_dashboard.md");

    run_generator(&json_out, &md_out);
    let json_first = std::fs::read_to_string(&json_out).expect("must read first json output");
    let md_first = std::fs::read_to_string(&md_out).expect("must read first markdown output");

    run_generator(&json_out, &md_out);
    let json_second = std::fs::read_to_string(&json_out).expect("must read second json output");
    let md_second = std::fs::read_to_string(&md_out).expect("must read second markdown output");

    assert_eq!(
        json_first, json_second,
        "json output must be stable across repeated fixed-timestamp runs"
    );
    assert_eq!(
        md_first, md_second,
        "markdown output must be stable across repeated fixed-timestamp runs"
    );
}
