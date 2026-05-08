//! Contract test for operator proof lane dashboard
//!
//! Validates that scripts/operator_proof_lane_dashboard.py correctly ingests
//! artifacts/proof_lane_manifest_v1.json and artifacts/proof_status_snapshot_v1.json
//! to produce a machine-readable status model with required categories.

use serde_json::Value;
use std::process::{Command, Stdio};
use std::str;

const DASHBOARD_TABLE_GOLDEN: &str =
    "tests/fixtures/operator_proof_lane_dashboard/table_scrubbed_expected.md";

fn scrub_dashboard_table_timestamp(stdout: &str) -> String {
    let mut lines = stdout
        .trim_end()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        !lines.is_empty(),
        "dashboard table output must not be empty"
    );

    let header_prefix = "# Asupersync Proof Lane Dashboard - ";
    assert!(
        lines[0].starts_with(header_prefix),
        "dashboard table header must include timestamp"
    );
    lines[0] = format!("{header_prefix}[TIMESTAMP]");

    let mut scrubbed = lines.join("\n");
    scrubbed.push('\n');
    scrubbed
}

#[test]
fn dashboard_script_exists_and_executable() {
    let script_path = std::path::Path::new("scripts/operator_proof_lane_dashboard.py");
    assert!(script_path.exists(), "Dashboard script must exist");

    let metadata = std::fs::metadata(script_path).unwrap();
    let permissions = metadata.permissions();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = permissions.mode();
        assert!(mode & 0o111 != 0, "Dashboard script must be executable");
    }
}

#[test]
fn dashboard_produces_valid_json_output() {
    let output = Command::new("python3")
        .args(["scripts/operator_proof_lane_dashboard.py", "--format=json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
        panic!("Dashboard script failed: {}", stderr);
    }

    let stdout = str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");
    let dashboard: Value =
        serde_json::from_str(stdout).expect("Dashboard should produce valid JSON");

    // Validate required top-level fields
    assert!(
        dashboard.get("timestamp").is_some(),
        "Dashboard must include timestamp"
    );
    assert!(
        dashboard.get("manifest_version").is_some(),
        "Dashboard must include manifest_version"
    );
    assert!(
        dashboard.get("snapshot_version").is_some(),
        "Dashboard must include snapshot_version"
    );
    assert!(
        dashboard.get("summary").is_some(),
        "Dashboard must include summary"
    );
    assert!(
        dashboard.get("production_graph_proofs").is_some(),
        "Dashboard must include production_graph_proofs"
    );
    assert!(
        dashboard.get("fuzz_smoke_evidence").is_some(),
        "Dashboard must include fuzz_smoke_evidence"
    );
    assert!(
        dashboard.get("rustdoc_frontier").is_some(),
        "Dashboard must include rustdoc_frontier"
    );
    assert!(
        dashboard.get("formal_proof_evidence").is_some(),
        "Dashboard must include formal_proof_evidence"
    );
    assert!(
        dashboard.get("quality_gates").is_some(),
        "Dashboard must include quality_gates"
    );
    assert!(
        dashboard.get("known_blockers").is_some(),
        "Dashboard must include known_blockers"
    );
    assert!(
        dashboard.get("guarantees").is_some(),
        "Dashboard must include guarantees"
    );
    assert!(
        dashboard.get("lane_coverage").is_some(),
        "Dashboard must include lane_coverage"
    );

    // Validate summary structure
    let summary = dashboard.get("summary").unwrap().as_object().unwrap();
    assert!(
        summary.contains_key("total_lanes"),
        "Summary must include total_lanes"
    );
    assert!(
        summary.contains_key("green"),
        "Summary must include green count"
    );
    assert!(
        summary.contains_key("yellow_frontier"),
        "Summary must include yellow_frontier count"
    );
    assert!(
        summary.contains_key("red_blocked"),
        "Summary must include red_blocked count"
    );
    assert!(
        summary.contains_key("total_guarantees"),
        "Summary must include total_guarantees"
    );
}

#[test]
fn dashboard_table_output_readable() {
    let output = Command::new("python3")
        .args(["scripts/operator_proof_lane_dashboard.py", "--format=table"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
        panic!("Dashboard script failed: {}", stderr);
    }

    let stdout = str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");

    // Validate table format contains expected sections
    assert!(
        stdout.contains("# Asupersync Proof Lane Dashboard"),
        "Table must include header"
    );
    assert!(
        stdout.contains("## Summary"),
        "Table must include summary section"
    );
    assert!(
        stdout.contains("Total lanes:"),
        "Table must include lane counts"
    );
    assert!(
        stdout.contains("Total guarantees:"),
        "Table must include guarantee counts"
    );

    // Validate required category sections appear
    assert!(
        stdout.contains("Production Graph Proofs") || stdout.contains("## Production"),
        "Table must distinguish production graph proofs"
    );
    assert!(
        stdout.contains("Fuzz Smoke Evidence") || stdout.contains("## Fuzz"),
        "Table must distinguish fuzz smoke evidence"
    );
    assert!(
        stdout.contains("Rustdoc Frontier") || stdout.contains("## Rustdoc"),
        "Table must distinguish rustdoc frontier"
    );
    assert!(
        stdout.contains("Formal Proof Evidence") || stdout.contains("## Formal"),
        "Table must distinguish formal proof evidence"
    );
    assert!(
        stdout.contains("Quality Gates") || stdout.contains("quality"),
        "Table must distinguish quality gates"
    );
}

#[test]
fn dashboard_table_output_matches_scrubbed_golden() {
    let output = Command::new("python3")
        .args(["scripts/operator_proof_lane_dashboard.py", "--format=table"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
        panic!("Dashboard script failed: {}", stderr);
    }

    let stdout = str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");
    let scrubbed = scrub_dashboard_table_timestamp(stdout);
    let expected = std::fs::read_to_string(DASHBOARD_TABLE_GOLDEN)
        .expect("read proof-lane dashboard table golden");

    assert_eq!(
        scrubbed, expected,
        "dashboard table output must match the scrubbed golden"
    );
}

#[test]
fn dashboard_summary_output_concise() {
    let output = Command::new("python3")
        .args([
            "scripts/operator_proof_lane_dashboard.py",
            "--format=summary",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
        panic!("Dashboard script failed: {}", stderr);
    }

    let stdout = str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");
    let line_count = stdout.trim().lines().count();

    // Validate concise summary format
    assert!(line_count <= 6, "Summary should be concise (≤6 lines)");
    assert!(
        stdout.contains("Asupersync Proof Status:"),
        "Summary must include overall status"
    );
    assert!(
        stdout.contains("Lanes:"),
        "Summary must include lane breakdown"
    );
    assert!(
        stdout.contains("Guarantees:"),
        "Summary must include guarantee status"
    );
    assert!(
        stdout.contains("Updated:"),
        "Summary must include timestamp"
    );

    // Validate status indicators
    assert!(
        stdout.contains("🟢") || stdout.contains("🟡") || stdout.contains("🔴"),
        "Summary must include status indicator"
    );
}

#[test]
fn dashboard_category_filtering_works() {
    let categories = ["production", "fuzz", "rustdoc", "formal", "quality"];

    for category in &categories {
        let output = Command::new("python3")
            .args([
                "scripts/operator_proof_lane_dashboard.py",
                "--format=table",
                &format!("--category={}", category),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to execute dashboard script");

        if !output.status.success() {
            let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
            panic!(
                "Dashboard script failed for category {}: {}",
                category, stderr
            );
        }

        let stdout =
            str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");
        assert!(
            stdout.contains("## Summary"),
            "Category filtering must preserve summary"
        );
    }
}

#[test]
fn dashboard_validates_required_artifacts() {
    // Test that dashboard script properly validates required input files exist
    let script_path = std::fs::canonicalize("scripts/operator_proof_lane_dashboard.py")
        .expect("canonicalize dashboard script");
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    let output = Command::new("python3")
        .arg(script_path)
        .args(["--format=json"])
        .current_dir(temp_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    // Should fail when artifacts are missing
    assert!(
        !output.status.success(),
        "Dashboard should fail when required artifacts are missing"
    );

    let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
    assert!(
        stderr.contains("not found") || stderr.contains("FileNotFoundError"),
        "Should report missing file error"
    );
}

#[test]
fn dashboard_lane_coverage_complete() {
    let output = Command::new("python3")
        .args(["scripts/operator_proof_lane_dashboard.py", "--format=json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
        panic!("Dashboard script failed: {}", stderr);
    }

    let stdout = str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");
    let dashboard: Value =
        serde_json::from_str(stdout).expect("Dashboard should produce valid JSON");

    // Load manifest to validate coverage completeness
    let manifest_content = std::fs::read_to_string("artifacts/proof_lane_manifest_v1.json")
        .expect("Should be able to read proof lane manifest");
    let manifest: Value =
        serde_json::from_str(&manifest_content).expect("Manifest should be valid JSON");

    let manifest_lanes = manifest.get("lanes").unwrap().as_array().unwrap();
    let dashboard_coverage = dashboard.get("lane_coverage").unwrap().as_object().unwrap();

    // Every manifest lane should appear in dashboard coverage
    for lane in manifest_lanes {
        let lane_id = lane.get("lane_id").unwrap().as_str().unwrap();
        assert!(
            dashboard_coverage.contains_key(lane_id),
            "Dashboard lane_coverage must include all manifest lanes: {}",
            lane_id
        );

        let dashboard_lane = dashboard_coverage
            .get(lane_id)
            .unwrap()
            .as_object()
            .unwrap();
        assert!(
            dashboard_lane.contains_key("status"),
            "Lane must have status"
        );
        assert!(
            dashboard_lane.contains_key("command"),
            "Lane must have command"
        );
        assert!(dashboard_lane.contains_key("kind"), "Lane must have kind");
    }
}

#[test]
fn dashboard_guarantee_status_aggregation_correct() {
    let output = Command::new("python3")
        .args(["scripts/operator_proof_lane_dashboard.py", "--format=json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute dashboard script");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid UTF-8>");
        panic!("Dashboard script failed: {}", stderr);
    }

    let stdout = str::from_utf8(&output.stdout).expect("Dashboard output should be valid UTF-8");
    let dashboard: Value =
        serde_json::from_str(stdout).expect("Dashboard should produce valid JSON");

    let guarantees = dashboard.get("guarantees").unwrap().as_array().unwrap();

    // Validate guarantee status aggregation logic
    for guarantee in guarantees {
        let guarantee_obj = guarantee.as_object().unwrap();
        let status = guarantee_obj.get("status").unwrap().as_str().unwrap();
        let lane_statuses = guarantee_obj
            .get("lane_statuses")
            .unwrap()
            .as_array()
            .unwrap();

        // Guarantee status should follow aggregation rules:
        // - green if all lanes green
        // - red if any lane red
        // - yellow if any lane yellow and no red
        let has_red = lane_statuses
            .iter()
            .any(|s| s.as_str().unwrap().contains("red"));
        let has_yellow = lane_statuses
            .iter()
            .any(|s| s.as_str().unwrap().contains("yellow"));
        let all_green = lane_statuses.iter().all(|s| s.as_str().unwrap() == "green");

        if all_green {
            assert_eq!(status, "green", "All-green guarantee should be green");
        } else if has_red {
            assert_eq!(
                status, "red_blocked_external",
                "Red-containing guarantee should be red"
            );
        } else if has_yellow {
            assert_eq!(
                status, "yellow_frontier",
                "Yellow-containing guarantee should be yellow"
            );
        }
    }
}
