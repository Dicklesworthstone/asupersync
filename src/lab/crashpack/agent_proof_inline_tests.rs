    use super::*;

    #[test]
    fn builder_requires_objective_and_agent_id() {
        let result = AgentTaskProofBundleBuilder::new().build();
        assert!(matches!(
            result,
            Err(AgentProofError::MissingField("objective"))
        ));

        let result = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .build();
        assert!(matches!(
            result,
            Err(AgentProofError::MissingField("agent_id"))
        ));

        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .build()
            .expect("should build with required fields");

        assert_eq!(bundle.objective, "test task");
        assert_eq!(bundle.agent_id, "TestAgent");
    }

    #[test]
    fn commands_are_redacted_for_sensitive_content() {
        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_command("curl --token=secret123 https://api.example.com", 0)
            .build()
            .expect("should build");

        assert_eq!(bundle.commands.len(), 1);
        assert!(bundle.commands[0].command.contains("[REDACTED]"));
        assert!(!bundle.commands[0].command.contains("secret123"));
    }

    #[test]
    fn replay_instructions_default_to_approval_required() {
        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_command("cargo test", 0)
            .build()
            .expect("should build");

        assert_eq!(
            bundle.replay_instructions.safety_level,
            ReplaySafetyLevel::ApprovalRequired
        );
        assert_eq!(
            bundle.replay_instructions.approval_required_commands,
            vec!["cargo test"]
        );
    }

    #[test]
    fn touched_paths_are_deduplicated() {
        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_touched_path("src/main.rs")
            .with_touched_path("src/main.rs")
            .with_touched_path("src/lib.rs")
            .build()
            .expect("should build");

        assert_eq!(bundle.touched_paths.len(), 2);
        assert!(bundle.touched_paths.contains(&PathBuf::from("src/main.rs")));
        assert!(bundle.touched_paths.contains(&PathBuf::from("src/lib.rs")));
    }

    #[test]
    fn bundle_validation_rejects_empty_fields() {
        let result = AgentTaskProofBundle {
            schema_version: AGENT_PROOF_BUNDLE_SCHEMA_VERSION,
            objective: String::new(),
            agent_id: "TestAgent".to_string(),
            bead_ids: Vec::new(),
            file_reservations: Vec::new(),
            touched_paths: Vec::new(),
            commands: Vec::new(),
            rch_details: None,
            commit_ids: CommitRecord {
                before_commit: "abc123".to_string(),
                after_commit: None,
                dirty_tree_before: false,
                dirty_tree_after: false,
                changed_files: Vec::new(),
            },
            validation_frontier: ValidationFrontierRecord {
                main_commit: "def456".to_string(),
                compile_failures: Vec::new(),
                test_failures: Vec::new(),
                production_lib_green: true,
            },
            mail_thread_ids: Vec::new(),
            artifact_paths: Vec::new(),
            first_blocker: None,
            replay_instructions: ReplayInstructions {
                safety_level: ReplaySafetyLevel::Safe,
                safe_commands: Vec::new(),
                remote_required_commands: Vec::new(),
                approval_required_commands: Vec::new(),
                environment_variables: BTreeMap::new(),
                required_file_state: Vec::new(),
                manual_setup_instructions: Vec::new(),
            },
            evidence_ledger: AtpEvidenceLedger::new(),
            metadata: BTreeMap::new(),
        };

        assert!(matches!(
            validate_bundle(&result),
            Err(AgentProofError::InvalidBundle(_))
        ));
    }

    #[test]
    fn proof_bundle_can_emit_artifacts() {
        use tempfile::TempDir;

        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_command("echo hello", 0)
            .build()
            .expect("should build");

        let temp_dir = TempDir::new().expect("should create temp dir");
        bundle
            .emit_proof_artifacts(temp_dir.path())
            .expect("should emit artifacts");

        // Check that expected files were created
        assert!(temp_dir.path().join("agent_proof_bundle.json").exists());
        assert!(temp_dir.path().join("evidence_ledger.json").exists());
        assert!(temp_dir.path().join("replay.sh").exists());
        assert!(temp_dir.path().join("commands.txt").exists());

        // Verify replay script is executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(temp_dir.path().join("replay.sh"))
                .expect("should read permissions");
            assert!(perms.permissions().mode() & 0o111 != 0);
        }
    }
