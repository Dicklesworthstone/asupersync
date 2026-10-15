//! Browser Edition execution-ladder contract checks.
//!
//! Focused follow-up: stale lane-health state must not mask a current hard
//! prerequisite failure in candidate diagnostics.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    let full_path = repo_root().join(path);
    std::fs::read_to_string(&full_path)
        .unwrap_or_else(|_| panic!("missing {}", full_path.display()))
}

fn repo_file_exists(path: &str) -> bool {
    repo_root().join(path).exists()
}

fn assert_markers_in_order(text: &str, markers: &[&str], failure_context: &str) {
    let mut search_start = 0usize;
    for marker in markers {
        let relative_index = text[search_start..]
            .find(marker)
            .unwrap_or_else(|| panic!("{failure_context}: missing marker {marker:?}"));
        search_start += relative_index + marker.len();
    }
}

#[test]
fn execution_ladder_artifacts_preserve_health_vs_prerequisite_precedence() {
    let stale_ungated_lane_unhealthy =
        "const laneUnhealthy = directLaneForHost === laneId && laneHealth.status === \"demoted\"";

    let mut artifacts = vec![("browser source", "packages/browser/src/index.ts")];
    if repo_file_exists("packages/browser/dist/index.js") {
        artifacts.push(("browser dist bundle", "packages/browser/dist/index.js"));
    }

    for (label, path) in artifacts {
        let content = read_repo_file(path);

        assert_markers_in_order(
            &content,
            &[
                "const laneUnhealthy",
                "selectedReasonCode === \"demote_due_to_lane_health\"",
                "directLaneForHost === laneId",
                "laneHealth.status === \"demoted\"",
            ],
            &format!(
                "{label} must gate lane-unhealthy candidate diagnostics to live health demotions"
            ),
        );
        assert_markers_in_order(
            &content,
            &[
                "const prerequisiteMissing",
                "selectedReasonCode !== \"demote_due_to_lane_health\"",
                "\"candidate_prerequisite_missing\"",
            ],
            &format!(
                "{label} must preserve prerequisite-missing diagnostics for non-health downgrades"
            ),
        );
        assert!(
            !content.contains(stale_ungated_lane_unhealthy),
            "{label} must not regress to the stale ungated lane-unhealthy predicate",
        );
    }
}
