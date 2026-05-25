//! Integration tests for AgentTaskProofBundle implementation.
//!
//! Tests the ASW-6 requirements for replayable proof bundles:
//! - Bundle schema records all required fields
//! - Redaction policy removes sensitive content
//! - Replay instructions distinguish safety levels
//! - E2E scenarios generate bundles for various failure types

use asupersync::lab::crashpack::agent_proof::{
    AgentTaskProofBundleBuilder, BlockerRecord, CommandRecord, CommitRecord, FileReservationRecord,
    RchRecord, ReplayInstructions, ReplaySafetyLevel, ValidationFrontierRecord,
};
use asupersync::lab::oracle::evidence::{
    BayesFactor, EvidenceEntry, EvidenceLine, EvidenceStrength, LogLikelihoodContributions,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn agent_proof_bundle_records_all_required_fields() {
    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Fix bug in stream handler")
        .with_agent_id("SapphireHill")
        .with_bead_id("asupersync-abc123")
        .with_touched_path("src/stream/handler.rs")
        .with_command("cargo test --lib stream", 0)
        .with_rch_worker("worker-456")
        .with_commit_id("abc123def")
        .with_mail_thread_id("thread-789")
        .with_artifact_path("test_results.json")
        .build()
        .expect("should build valid bundle");

    assert_eq!(bundle.objective, "Fix bug in stream handler");
    assert_eq!(bundle.agent_id, "SapphireHill");
    assert_eq!(bundle.bead_ids, vec!["asupersync-abc123"]);
    assert_eq!(
        bundle.touched_paths,
        vec![PathBuf::from("src/stream/handler.rs")]
    );
    assert_eq!(bundle.commands.len(), 1);
    assert_eq!(bundle.commands[0].command, "cargo test --lib stream");
    assert_eq!(bundle.commands[0].exit_status, 0);
    assert!(bundle.rch_details.is_some());
    assert_eq!(bundle.mail_thread_ids, vec!["thread-789"]);
    assert_eq!(
        bundle.artifact_paths,
        vec![PathBuf::from("test_results.json")]
    );
}

#[test]
fn redaction_policy_removes_sensitive_content() {
    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("test redaction")
        .with_agent_id("TestAgent")
        .with_command("curl --token=secret123 https://api.example.com", 0)
        .with_command("git push --auth=bearer_token_456", 1)
        .with_command("mysql -p supersecretpassword", 2)
        .build()
        .expect("should build with redacted commands");

    assert_eq!(bundle.commands.len(), 3);

    // Check token redaction
    assert!(bundle.commands[0].command.contains("--token=[REDACTED]"));
    assert!(!bundle.commands[0].command.contains("secret123"));

    // Check auth redaction
    assert!(bundle.commands[1].command.contains("--auth=[REDACTED]"));
    assert!(!bundle.commands[1].command.contains("bearer_token_456"));

    // Check password redaction
    assert!(bundle.commands[2].command.contains("-p [REDACTED]"));
    assert!(!bundle.commands[2].command.contains("supersecretpassword"));
}

#[test]
fn replay_instructions_categorize_commands_by_safety() {
    let safe_instructions = ReplayInstructions {
        safety_level: ReplaySafetyLevel::Safe,
        safe_commands: vec!["cargo test".to_string(), "cargo check".to_string()],
        remote_required_commands: vec![],
        approval_required_commands: vec![],
        environment_variables: BTreeMap::new(),
        required_file_state: vec![],
        manual_setup_instructions: vec![],
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("test replay safety")
        .with_agent_id("TestAgent")
        .with_replay_instructions(safe_instructions)
        .build()
        .expect("should build with custom replay instructions");

    assert_eq!(
        bundle.replay_instructions.safety_level,
        ReplaySafetyLevel::Safe
    );
    assert_eq!(bundle.replay_instructions.safe_commands.len(), 2);
    assert!(
        bundle
            .replay_instructions
            .safe_commands
            .contains(&"cargo test".to_string())
    );
}

#[test]
fn e2e_success_scenario_generates_clean_bundle() {
    let evidence = EvidenceEntry {
        invariant: "task_completion".to_string(),
        passed: true,
        bayes_factor: BayesFactor {
            log10_bf: -1.0,
            hypothesis: "task failure".to_string(),
            strength: EvidenceStrength::Against,
        },
        log_likelihoods: LogLikelihoodContributions {
            structural: -0.5,
            detection: -0.5,
            total: -1.0,
        },
        evidence_lines: vec![EvidenceLine {
            equation: "BF = P(evidence | failure) / P(evidence | success)".to_string(),
            substitution: "passed=true, exit_status=0".to_string(),
            intuition: "Task completed successfully with clean exit".to_string(),
        }],
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Successful test run")
        .with_agent_id("TestAgent")
        .with_command("cargo test --lib", 0)
        .with_evidence("task_completion", evidence)
        .build()
        .expect("should build success scenario bundle");

    assert!(bundle.first_blocker.is_none());
    assert_eq!(bundle.evidence_ledger.entries.len(), 1);
    assert!(bundle.evidence_ledger.entries[0].evidence.passed);
}

#[test]
fn e2e_rch_refusal_scenario_records_admission_failure() {
    let rch_record = RchRecord {
        worker_id: None,
        admitted: false,
        refusal_reason: Some("No available workers".to_string()),
        queue_position: Some(15),
        wait_time_ms: Some(30000),
    };

    let blocker = BlockerRecord {
        blocker_type: "rch_refusal".to_string(),
        description: "RCH refused task due to resource exhaustion".to_string(),
        source_location: None,
        concurrent_change: false,
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Task blocked by RCH")
        .with_agent_id("TestAgent")
        .with_rch_details(rch_record)
        .with_first_blocker(blocker)
        .build()
        .expect("should build RCH refusal bundle");

    assert!(bundle.rch_details.is_some());
    let rch = bundle.rch_details.as_ref().unwrap();
    assert!(!rch.admitted);
    assert_eq!(rch.refusal_reason.as_ref().unwrap(), "No available workers");

    assert!(bundle.first_blocker.is_some());
    let blocker = bundle.first_blocker.as_ref().unwrap();
    assert_eq!(blocker.blocker_type, "rch_refusal");
}

#[test]
fn e2e_compile_frontier_scenario_records_validation_state() {
    let frontier = ValidationFrontierRecord {
        main_commit: "def456".to_string(),
        compile_failures: vec![
            "src/stream/handler.rs:42:5 cannot find function `missing_fn`".to_string(),
            "src/net/tcp.rs:100:20 use of moved value".to_string(),
        ],
        test_failures: vec!["test_stream_integration".to_string()],
        production_lib_green: false,
    };

    let blocker = BlockerRecord {
        blocker_type: "compile_error".to_string(),
        description: "Build failed due to unrelated compile frontier".to_string(),
        source_location: Some("src/stream/handler.rs:42:5".to_string()),
        concurrent_change: true,
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Task blocked by compile errors")
        .with_agent_id("TestAgent")
        .with_validation_frontier(frontier)
        .with_first_blocker(blocker)
        .build()
        .expect("should build compile frontier bundle");

    assert!(!bundle.validation_frontier.production_lib_green);
    assert_eq!(bundle.validation_frontier.compile_failures.len(), 2);
    assert!(bundle.validation_frontier.compile_failures[0].contains("missing_fn"));

    assert!(bundle.first_blocker.is_some());
    assert!(bundle.first_blocker.as_ref().unwrap().concurrent_change);
}

#[test]
fn e2e_reservation_conflict_scenario_records_file_contention() {
    let reservation = FileReservationRecord {
        path: PathBuf::from("src/critical_module.rs"),
        holder: "OtherAgent".to_string(),
        reservation_id: "res-12345".to_string(),
        released_cleanly: false,
    };

    let blocker = BlockerRecord {
        blocker_type: "reservation_conflict".to_string(),
        description: "File reserved by concurrent agent".to_string(),
        source_location: Some("src/critical_module.rs".to_string()),
        concurrent_change: true,
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Task blocked by file reservation")
        .with_agent_id("TestAgent")
        .with_file_reservation(reservation)
        .with_first_blocker(blocker)
        .build()
        .expect("should build reservation conflict bundle");

    assert_eq!(bundle.file_reservations.len(), 1);
    assert_eq!(bundle.file_reservations[0].holder, "OtherAgent");
    assert!(!bundle.file_reservations[0].released_cleanly);

    assert!(bundle.first_blocker.is_some());
    assert_eq!(
        bundle.first_blocker.as_ref().unwrap().blocker_type,
        "reservation_conflict"
    );
}

#[test]
fn proof_bundle_emits_complete_artifact_set() {
    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Test artifact emission")
        .with_agent_id("TestAgent")
        .with_command("echo hello", 0)
        .with_command("echo world", 0)
        .build()
        .expect("should build test bundle");

    let temp_dir = TempDir::new().expect("should create temp dir");
    bundle
        .emit_proof_artifacts(temp_dir.path())
        .expect("should emit artifacts");

    // Check all expected artifacts are created
    let expected_files = [
        "agent_proof_bundle.json",
        "evidence_ledger.json",
        "replay.sh",
        "commands.txt",
    ];

    for file in &expected_files {
        let file_path = temp_dir.path().join(file);
        assert!(
            file_path.exists(),
            "Expected artifact {} was not created",
            file
        );

        // Verify files are not empty
        let metadata = std::fs::metadata(&file_path).expect("should read file metadata");
        assert!(metadata.len() > 0, "Artifact {} is empty", file);
    }

    // Verify replay script is executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let replay_path = temp_dir.path().join("replay.sh");
        let perms = std::fs::metadata(&replay_path).expect("should read permissions");
        assert!(
            perms.permissions().mode() & 0o111 != 0,
            "Replay script is not executable"
        );
    }

    // Verify bundle JSON is valid
    let bundle_path = temp_dir.path().join("agent_proof_bundle.json");
    let bundle_content = std::fs::read_to_string(&bundle_path).expect("should read bundle JSON");
    let parsed: serde_json::Value =
        serde_json::from_str(&bundle_content).expect("bundle JSON should be valid");

    assert_eq!(parsed["objective"], "Test artifact emission");
    assert_eq!(parsed["agent_id"], "TestAgent");
}

#[test]
fn concurrent_commit_scenario_captures_git_state() {
    let commit_record = CommitRecord {
        before_commit: "abc123".to_string(),
        after_commit: Some("def456".to_string()),
        dirty_tree_before: false,
        dirty_tree_after: true,
        changed_files: vec![
            PathBuf::from("src/modified.rs"),
            PathBuf::from("tests/new_test.rs"),
        ],
    };

    let blocker = BlockerRecord {
        blocker_type: "concurrent_commit".to_string(),
        description: "Local changes conflict with upstream".to_string(),
        source_location: Some("git merge".to_string()),
        concurrent_change: true,
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Handle merge conflict")
        .with_agent_id("TestAgent")
        .with_commit_record(commit_record)
        .with_first_blocker(blocker)
        .build()
        .expect("should build concurrent commit bundle");

    assert_eq!(bundle.commit_ids.before_commit, "abc123");
    assert_eq!(bundle.commit_ids.after_commit.as_ref().unwrap(), "def456");
    assert!(bundle.commit_ids.dirty_tree_after);
    assert_eq!(bundle.commit_ids.changed_files.len(), 2);

    assert!(bundle.first_blocker.as_ref().unwrap().concurrent_change);
}

#[test]
fn agent_crash_scenario_preserves_partial_evidence() {
    let evidence = EvidenceEntry {
        invariant: "partial_completion".to_string(),
        passed: false,
        bayes_factor: BayesFactor {
            log10_bf: 1.5,
            hypothesis: "agent crash".to_string(),
            strength: EvidenceStrength::Strong,
        },
        log_likelihoods: LogLikelihoodContributions {
            structural: 0.8,
            detection: 0.7,
            total: 1.5,
        },
        evidence_lines: vec![EvidenceLine {
            equation: "BF = P(partial output | crash) / P(partial output | normal)".to_string(),
            substitution: "exit_status=segfault, output_truncated=true".to_string(),
            intuition: "Agent terminated abnormally with partial output".to_string(),
        }],
    };

    let bundle = AgentTaskProofBundleBuilder::new()
        .with_objective("Task interrupted by crash")
        .with_agent_id("TestAgent")
        .with_command("cargo test --lib", 11) // segfault exit code
        .with_evidence("partial_completion", evidence)
        .build()
        .expect("should build crash scenario bundle");

    assert_eq!(bundle.commands[0].exit_status, 11);
    assert_eq!(bundle.evidence_ledger.entries.len(), 1);
    assert!(!bundle.evidence_ledger.entries[0].evidence.passed);

    let summary = bundle.evidence_ledger.evidence_summary();
    assert_eq!(summary.strong, 1);
    assert!(summary.has_strong_violations());
}
