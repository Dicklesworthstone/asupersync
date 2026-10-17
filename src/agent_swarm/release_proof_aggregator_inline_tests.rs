    use super::*;

    #[test]
    fn test_aggregator_creation() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);
        assert!(aggregator.config.require_remote_rch);
    }

    #[test]
    fn test_proof_status_determination_complete() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "test commit".to_string(),
            author: "test".to_string(),
            timestamp: SystemTime::now(),
            pushed: true,
        }];

        let rch_commands = vec![RchCommandRecord {
            command: "cargo check".to_string(),
            exit_code: 0,
            remote_required: true,
            worker: Some("worker1".to_string()),
            duration: Duration::from_secs(10),
            started_at: SystemTime::now(),
            output_summary: "success".to_string(),
        }];

        let pushed_refs = vec![GitRef {
            ref_name: "refs/remotes/origin/main".to_string(),
            commit_hash: "abc123".to_string(),
            pushed: true,
            pushed_at: SystemTime::now(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &rch_commands, None, &handoff_status, &pushed_refs)
            .unwrap();

        assert_eq!(status, ProofStatus::Complete);
    }

    #[test]
    fn test_proof_status_requires_commits_on_main() {
        let mut config = AggregatorConfig::default();
        config.require_remote_rch = false;
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "test commit".to_string(),
            author: "test".to_string(),
            timestamp: SystemTime::now(),
            pushed: true,
        }];

        let pushed_refs = vec![GitRef {
            ref_name: "refs/remotes/origin/topic".to_string(),
            commit_hash: "abc123".to_string(),
            pushed: true,
            pushed_at: SystemTime::now(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &[], None, &handoff_status, &pushed_refs)
            .unwrap();

        assert_eq!(status, ProofStatus::MissingCloseout);
    }

    #[test]
    fn test_proof_status_rejects_unpushed_commits() {
        let mut config = AggregatorConfig::default();
        config.require_remote_rch = false;
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "test commit".to_string(),
            author: "test".to_string(),
            timestamp: SystemTime::now(),
            pushed: false,
        }];

        let pushed_refs = vec![GitRef {
            ref_name: "refs/remotes/origin/main".to_string(),
            commit_hash: "abc123".to_string(),
            pushed: true,
            pushed_at: SystemTime::now(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &[], None, &handoff_status, &pushed_refs)
            .unwrap();

        assert_eq!(status, ProofStatus::MissingCloseout);
    }

    #[test]
    fn test_proof_status_determination_missing_remote() {
        let mut config = AggregatorConfig::default();
        config.require_remote_rch = true;
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![];
        let rch_commands = vec![RchCommandRecord {
            command: "cargo check".to_string(),
            exit_code: 0,
            remote_required: true,
            worker: None, // No worker = local execution
            duration: Duration::from_secs(10),
            started_at: SystemTime::now(),
            output_summary: "success".to_string(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &rch_commands, None, &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::LocalFallback);
    }

    #[test]
    fn test_proof_status_requires_remote_when_no_rch_evidence_exists() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);
        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&[], &[], None, &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::MissingRemoteProof);
    }

    #[test]
    fn test_rch_message_parser_extracts_worker_exit_and_duration() {
        let started_at = SystemTime::now();
        let message = r"
## 2026-05-27T12:43:18.938024Z — HazyRidge → MossyPond

Command:
`rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo check -p asupersync --lib`

2026-05-27T12:43:18Z INFO Selected worker: vmi1167313 at ubuntu@154.12.232.219
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 07s
Remote command finished: exit=0 in 188296ms
[RCH] remote vmi1167313 (234.3s)
";

        let records = ReleaseProofAggregator::extract_rch_records_from_message(message, started_at);

        assert_eq!(records.len(), 1);
        assert!(records[0].command.starts_with("rch exec -- env"));
        assert_eq!(records[0].exit_code, 0);
        assert_eq!(records[0].worker.as_deref(), Some("vmi1167313"));
        assert_eq!(records[0].duration, Duration::from_millis(188_296));
    }

    #[test]
    fn test_proof_status_determination_blocked() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let blocker = Some(BlockerRecord {
            blocker_type: BlockerType::TestFailure,
            description: "Test failed".to_string(),
            encountered_at: SystemTime::now(),
            external: false,
        });

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&[], &[], blocker.as_ref(), &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::Blocked);
    }

    #[test]
    fn test_proof_status_determination_stale() {
        let config = AggregatorConfig {
            max_commit_age: Duration::from_secs(60), // 1 minute
            require_remote_rch: false,
            ..AggregatorConfig::default()
        };
        let aggregator = ReleaseProofAggregator::new(config);

        let old_time = SystemTime::now() - Duration::from_secs(120); // 2 minutes ago
        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "old commit".to_string(),
            author: "test".to_string(),
            timestamp: old_time,
            pushed: true,
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &[], None, &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::Stale);
    }

    #[test]
    fn test_generate_summary() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let record = ReleaseProofRecord {
            bead_id: "test-bead".to_string(),
            agent_name: "test-agent".to_string(),
            reservations: vec![],
            touched_paths: vec![],
            commits: vec![CommitRecord {
                hash: "abc123".to_string(),
                message: "test commit".to_string(),
                author: "test".to_string(),
                timestamp: SystemTime::now(),
                pushed: true,
            }],
            rch_commands: vec![],
            first_blocker: None,
            lease_receipts: vec![],
            handoff_status: HandoffStatus {
                capsule_exists: false,
                decision: None,
                last_updated: SystemTime::now(),
            },
            pushed_refs: vec![],
            generated_at: SystemTime::now(),
            status: ProofStatus::Complete,
        };

        let summary = aggregator.generate_summary(&record);
        assert_eq!(summary.bead_id, "test-bead");
        assert_eq!(summary.status, ProofStatus::Complete);
        assert_eq!(summary.commit_count, 1);
        assert!(!summary.main_pushed);
        assert!(summary.summary.contains("Release ready"));
    }

    #[test]
    fn test_freshness_score_calculation() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let record = ReleaseProofRecord {
            bead_id: "test-bead".to_string(),
            agent_name: "test-agent".to_string(),
            reservations: vec![],
            touched_paths: vec![],
            commits: vec![CommitRecord {
                hash: "abc123".to_string(),
                message: "test commit".to_string(),
                author: "test".to_string(),
                timestamp: SystemTime::now(),
                pushed: true,
            }],
            rch_commands: vec![],
            first_blocker: None,
            lease_receipts: vec![],
            handoff_status: HandoffStatus {
                capsule_exists: false,
                decision: None,
                last_updated: SystemTime::now(),
            },
            pushed_refs: vec![],
            generated_at: SystemTime::now(),
            status: ProofStatus::Complete,
        };

        let score = aggregator.calculate_freshness_score(&record);
        assert!(score > 0.8); // Fresh evidence should have high score
    }

    #[test]
    fn test_bead_id_validation() {
        // Valid bead IDs should pass
        assert!(ReleaseProofAggregator::validate_bead_id("test-bead-123").is_ok());
        assert!(ReleaseProofAggregator::validate_bead_id("abc_def-123").is_ok());
        assert!(ReleaseProofAggregator::validate_bead_id("simple").is_ok());

        // Empty or too long should fail
        assert!(ReleaseProofAggregator::validate_bead_id("").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id(&"x".repeat(65)).is_err());

        // Dangerous characters should fail
        assert!(ReleaseProofAggregator::validate_bead_id("test;rm -rf").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test`cat /etc/passwd`").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test$(whoami)").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test&pwd").is_err());

        // Path traversal patterns should fail
        assert!(ReleaseProofAggregator::validate_bead_id("../../../etc/passwd").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test/../admin").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test/subdir").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test\\windows\\path").is_err());
    }

    #[test]
    fn test_file_path_validation() {
        // Create an isolated directory for testing
        let temp_dir = std::env::temp_dir().join("test_aggregator");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let temp_path = temp_dir.to_str().unwrap();

        // Valid paths within allowed directory should pass
        let valid_file = temp_dir.join("test.json");
        std::fs::write(&valid_file, "test").unwrap();
        assert!(
            ReleaseProofAggregator::validate_file_path(valid_file.to_str().unwrap(), temp_path)
                .is_ok()
        );

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_git_snapshot_capture() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        // Should be able to capture git snapshot (if we're in a git repo)
        let snapshot_result = aggregator.capture_git_snapshot();

        // This will succeed if we're in a git repo, fail otherwise
        // We just want to make sure it doesn't panic or have security issues
        match snapshot_result {
            Ok(hash) => {
                assert!(!hash.is_empty());
                assert!(
                    hash.chars()
                        .all(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
                );
            }
            Err(_) => {
                // Not in a git repo or git not available - that's okay for testing
            }
        }
    }

    #[test]
    fn test_sensitive_information_redaction() {
        let config = AggregatorConfig {
            redact_sensitive: true,
            ..AggregatorConfig::default()
        };
        let aggregator = ReleaseProofAggregator::new(config);

        let record = ReleaseProofRecord {
            bead_id: "test-bead".to_string(),
            agent_name: "sensitive-agent".to_string(),
            reservations: vec![FileReservation {
                agent: "another-agent".to_string(),
                patterns: vec!["src/**".to_string()],
                exclusive: true,
                ttl_seconds: 3600,
                reason: "test".to_string(),
                acquired_at: SystemTime::now(),
                released_at: None,
            }],
            touched_paths: vec![],
            commits: vec![],
            rch_commands: vec![RchCommandRecord {
                command: "cargo check".to_string(),
                exit_code: 0,
                remote_required: false,
                worker: None,
                duration: Duration::from_secs(10),
                started_at: SystemTime::now(),
                output_summary: "a".repeat(200), // Long output to test redaction
            }],
            first_blocker: None,
            lease_receipts: vec![],
            handoff_status: HandoffStatus {
                capsule_exists: false,
                decision: None,
                last_updated: SystemTime::now(),
            },
            pushed_refs: vec![],
            generated_at: SystemTime::now(),
            status: ProofStatus::Complete,
        };

        let redacted = aggregator.redact_sensitive_information(&record);
        assert_eq!(redacted.agent_name, "[redacted]");
        assert_eq!(redacted.reservations[0].agent, "[redacted]");
        assert!(
            redacted.rch_commands[0]
                .output_summary
                .contains("[redacted]")
        );
    }
