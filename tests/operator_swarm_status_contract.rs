//! Contract tests for the ASW operator swarm-status surface.

use asupersync::cli::doctor::{
    agent_swarm_status_contract, parse_git_short_status, run_agent_swarm_status_smoke,
    validate_agent_swarm_status_contract,
};

#[test]
fn swarm_status_contract_validates_and_smoke_is_deterministic() {
    let contract = agent_swarm_status_contract();
    validate_agent_swarm_status_contract(&contract).expect("valid ASW status contract");

    let first = run_agent_swarm_status_smoke(&contract).expect("first swarm status");
    let second = run_agent_swarm_status_smoke(&contract).expect("second swarm status");
    assert_eq!(first, second);
    assert_eq!(first.schema_version, "doctor-agent-swarm-status-v1");
    assert_eq!(first.health_status, "critical");
    assert_eq!(first.readiness_score, 20);
    assert_eq!(first.reservation_conflict_count, 1);
    assert_eq!(first.proof_frontier_blocker_count, 1);
    assert!(
        first
            .recommendations
            .iter()
            .any(|recommendation| recommendation.action == "fix_first_proof_blocker")
    );
}

#[test]
fn swarm_status_git_parser_tracks_dirty_paths_and_unowned_ahead_commits() {
    let parsed = parse_git_short_status(
        "## main...origin/main [ahead 2, behind 1]\n M src/cli/doctor/mod.rs\n?? tests/operator_swarm_status_contract.rs\n",
        &["def456".to_string(), "abc123".to_string(), "abc123".to_string()],
    )
    .expect("parse git status");

    assert_eq!(parsed.branch, "main");
    assert_eq!(parsed.upstream.as_deref(), Some("origin/main"));
    assert_eq!(parsed.ahead, 2);
    assert_eq!(parsed.behind, 1);
    assert_eq!(
        parsed.dirty_paths,
        vec![
            "src/cli/doctor/mod.rs".to_string(),
            "tests/operator_swarm_status_contract.rs".to_string(),
        ]
    );
    assert_eq!(
        parsed.unowned_ahead_commits,
        vec!["abc123".to_string(), "def456".to_string()]
    );
}
