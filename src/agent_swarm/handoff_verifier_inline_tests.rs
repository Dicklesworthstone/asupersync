    use super::*;

    fn create_test_capsule() -> HandoffCapsule {
        let mut capsule = HandoffCapsule {
            session_meta: SessionMetadata {
                agent_id: "test-agent".to_string(),
                session_duration: Duration::from_secs(3600),
                last_active: SystemTime::now(),
                session_type: SessionType::Interactive,
                docs_receipts: vec![DocReceipt {
                    doc_path: "AGENTS.md".to_string(),
                    content_hash: "abc123".to_string(),
                    read_at: SystemTime::now(),
                }],
            },
            git_state: GitState {
                current_branch: "main".to_string(),
                main_hash: "deadbeef".to_string(),
                working_tree_clean: true,
                staged_changes: vec![],
                untracked_files: vec![],
                last_remote_sync: Some(SystemTime::now()),
            },
            inbox_state: InboxState {
                unread_count: 0,
                pending_acks: vec![],
                last_check: SystemTime::now(),
                critical_unacked: vec![],
            },
            active_reservations: vec![],
            claimed_beads: vec![],
            dirty_paths: DirtyPathSummary {
                owned_files: BTreeSet::new(),
                peer_modified: BTreeMap::new(),
                potential_conflicts: vec![],
            },
            proof_commands: vec![],
            first_blocker: None,
            pushed_commits: vec![],
            remaining_risks: vec![],
            created_at: SystemTime::now(),
            content_hash: String::new(),
        };
        refresh_content_hash(&mut capsule);
        capsule
    }

    fn refresh_content_hash(capsule: &mut HandoffCapsule) {
        capsule.content_hash = HandoffVerifier::new().compute_content_hash(capsule);
    }

    #[test]
    fn test_fresh_handoff_continues() {
        let verifier = HandoffVerifier::new();
        let capsule = create_test_capsule();

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::Continue => {}
            other => panic!("Expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn test_stale_docs_requires_refresh() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        // Make docs receipt old
        capsule.session_meta.docs_receipts[0].read_at =
            SystemTime::now() - Duration::from_secs(7200); // 2 hours ago
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::NarrowRefreshRequired { refresh_targets } => {
                assert!(refresh_targets.contains(&RefreshTarget::Documentation));
            }
            other => panic!("Expected NarrowRefreshRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_wrong_branch_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.git_state.current_branch = "feature-branch".to_string();
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r.category, ViolationCategory::StaleGitState))
                );
            }
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_critical_messages_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.inbox_state.critical_unacked.push(MessageRef {
            message_id: "critical-msg".to_string(),
            sender: "admin".to_string(),
            priority: MessagePriority::Critical,
            received_at: SystemTime::now(),
        });
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(reasons.iter().any(|r| matches!(
                    r.category,
                    ViolationCategory::CriticalUnacknowledgedMessages
                )));
            }
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_expired_reservations_need_coordination() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.active_reservations.push(FileReservation {
            id: "expired-res".to_string(),
            paths: vec!["src/**".to_string()],
            exclusive: true,
            expires_at: SystemTime::now() - Duration::from_secs(60), // Expired
            reason: "test".to_string(),
        });
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::CoordinateFirst {
                coordination_needed,
            } => {
                assert!(coordination_needed.iter().any(|c| matches!(
                    c.requirement_type,
                    CoordinationType::FileReservationHandoff
                )));
            }
            other => panic!("Expected CoordinateFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_bead_claims_need_coordination() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.claimed_beads.push(BeadClaim {
            bead_id: "asupersync-test-bead".to_string(),
            title: "stale claim".to_string(),
            status: BeadStatus::InProgress,
            claimed_at: SystemTime::now() - Duration::from_secs(3600),
            progress: 0.5,
        });
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::CoordinateFirst {
                coordination_needed,
            } => {
                let bead_coordination = coordination_needed
                    .iter()
                    .find(|c| matches!(c.requirement_type, CoordinationType::BeadTransfer));
                assert!(bead_coordination.is_some());
                assert!(
                    bead_coordination
                        .unwrap()
                        .target_agents
                        .iter()
                        .any(|target| target.contains("stale-claim"))
                );
            }
            other => panic!("Expected CoordinateFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_file_conflicts_need_coordination() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.dirty_paths.potential_conflicts.push(ConflictInfo {
            file_path: "src/conflicted.rs".to_string(),
            competing_agents: vec!["agent1".to_string(), "agent2".to_string()],
            severity: ConflictSeverity::Medium,
        });
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::CoordinateFirst {
                coordination_needed,
            } => {
                assert!(
                    coordination_needed.iter().any(|c| matches!(
                        c.requirement_type,
                        CoordinationType::ConflictResolution
                    ))
                );
            }
            other => panic!("Expected CoordinateFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_missing_content_hash_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.content_hash = String::new();

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r.category, ViolationCategory::IntegrityCheckFailure))
                );
            }
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_content_hash_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        // Set an incorrect hash that won't match the computed hash
        capsule.content_hash = "invalid-hash-that-wont-match".to_string();

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r.category, ViolationCategory::IntegrityCheckFailure))
                );
                // Check that the evidence includes the hash mismatch details
                assert!(
                    reasons
                        .iter()
                        .any(|r| r.evidence.contains("Expected:")
                            && r.evidence.contains("Computed:"))
                );
            }
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_valid_content_hash_continues() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        // Compute the correct hash for the capsule
        let correct_hash = verifier.compute_content_hash(&capsule);
        capsule.content_hash = correct_hash;

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::Continue => {}
            other => panic!("Expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn test_proof_command_timeout_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.proof_commands.push(ProofCommand {
            command_id: "old-proof".to_string(),
            command_line: "cargo test".to_string(),
            started_at: SystemTime::now() - Duration::from_secs(3600), // 1 hour ago
            expected_completion: None,
            command_type: ProofCommandType::Test,
        });
        refresh_content_hash(&mut capsule);

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r.category, ViolationCategory::FailedProofCommands))
                );
            }
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_capsule_serialization() {
        let capsule = create_test_capsule();

        // Test that the capsule can be serialized and deserialized
        let json = serde_json::to_string(&capsule).unwrap();
        let deserialized: HandoffCapsule = serde_json::from_str(&json).unwrap();

        assert_eq!(
            capsule.session_meta.agent_id,
            deserialized.session_meta.agent_id
        );
        assert_eq!(
            capsule.git_state.current_branch,
            deserialized.git_state.current_branch
        );
    }
