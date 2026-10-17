    use super::*;
    use crate::atp::object::{ContentId, ObjectEdge, ObjectKind, PlatformMetadata};

    fn graph_with_file(name: &str, content: &[u8]) -> (ObjectGraph, ObjectId) {
        let file = Object::file(content.to_vec());
        let file_id = file.id.clone();
        let directory = Object::directory(vec![ObjectEdge::new(file_id, name.to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file object inserts");
        graph.add_root(directory).expect("directory root inserts");
        (graph, root)
    }

    fn allow_policy(root: &str) -> DestinationPolicy {
        DestinationPolicy::AllowListed {
            allowed_roots: BTreeSet::from([PathBuf::from(root)]),
            require_quarantine: true,
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            allow_special_files: false,
            case_sensitive: false,
            max_bytes: Some(1_000),
        }
    }

    fn input<'a>(
        graph: &'a ObjectGraph,
        root: &'a ObjectId,
        policy: DestinationPolicy,
    ) -> ReceivePreflightInput<'a> {
        ReceivePreflightInput {
            sender_identity: "peer-alpha-secret".to_string(),
            grant_id: Some("grant-1".to_string()),
            capability_scope: Some("path:/safe".to_string()),
            manifest_root: root,
            graph,
            destination_policy: policy,
            destination_root: PathBuf::from("/safe"),
            destination_relative_path: PathBuf::from("bundle"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(2_000),
                quota_remaining_bytes: Some(2_000),
                safety_margin_bytes: 10,
            },
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::DaemonAllowRule {
                rule_id: "allow-1".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
            trace_id: Some("trace-1".to_string()),
            replay_pointer: Some("proof://bundle".to_string()),
        }
    }

    #[test]
    fn portable_path_components_reject_windows_aliases_and_forbidden_characters() {
        for component in [
            "NUL",
            "nul.txt",
            "COM1.log",
            "lpt9.tar.gz",
            "CONIN$",
            "trailing.",
            "trailing ",
            "alternate:stream",
            "question?",
            "star*",
            "control\u{1f}",
            ".ASUPERSYNC-ATP-DELTA-V1",
            ".asupersync-atp-delta-package-hostile",
            ".atp-staging-hostile",
            ".atp-rq-staging-hostile",
            ".atp-quic-staging-hostile",
        ] {
            assert!(
                validate_portable_path_component(component).is_err(),
                "portable path component {component:?} must fail closed"
            );
        }

        for component in ["payload.bin", "nested-name", "café.txt"] {
            validate_portable_path_component(component)
                .unwrap_or_else(|error| panic!("safe component {component:?}: {error}"));
        }
    }

    #[test]
    fn portable_relative_paths_and_collision_keys_are_windows_safe() {
        validate_portable_relative_path("nested/payload.bin").expect("safe relative path");
        for path in [
            "",
            "/absolute",
            "../escape",
            "nested/./payload",
            "nested//payload",
            "nested/NUL.txt",
        ] {
            assert!(
                validate_portable_relative_path(path).is_err(),
                "portable relative path {path:?} must fail closed"
            );
        }

        assert_eq!(
            portable_path_collision_key("Docs/Readme.TXT"),
            portable_path_collision_key("docs/README.txt")
        );
        assert_eq!(
            portable_path_collision_key("caf\u{e9}"),
            portable_path_collision_key("cafe\u{301}")
        );

        validate_portable_path_set(["Foo/a", "Foo/b", "Foo/nested/c"])
            .expect("one consistently-cased tree");
        assert!(validate_portable_path_set(["Foo", "foo"]).is_err());
        assert!(validate_portable_path_set(["Foo/a", "foo/b"]).is_err());
        assert!(validate_portable_path_set(["Foo", "foo/pwn"]).is_err());
        assert!(validate_portable_path_set(["Foo", "Foo/pwn"]).is_err());
    }

    /// portable_path_collision_key's ASCII fast path equals the full
    /// NFC / uppercase / NFC fold for every ASCII input (dfdwyt), and
    /// non-ASCII input still takes the full fold.
    #[test]
    fn ascii_collision_keys_match_the_full_unicode_fold() {
        use unicode_normalization::UnicodeNormalization;

        fn full_fold(path: &str) -> String {
            path.nfc()
                .flat_map(char::to_uppercase)
                .collect::<String>()
                .nfc()
                .collect()
        }
        let mut inputs: Vec<String> = (0_u8..128)
            .map(|byte| char::from(byte).to_string())
            .collect();
        let mut state = 0x9e37_79b9_u32;
        for _ in 0..2000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = usize::try_from(state % 24).expect("small length");
            let mut input = String::new();
            for _ in 0..len {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                input.push(char::from(u8::try_from(state >> 25).expect("7-bit value")));
            }
            inputs.push(input);
        }
        for input in &inputs {
            assert!(input.is_ascii());
            assert_eq!(
                portable_path_collision_key(input),
                full_fold(input),
                "{input:?}"
            );
        }
        for input in [
            "caf\u{e9}",
            "cafe\u{301}",
            "\u{df}",
            "Stra\u{df}e",
            "\u{130}x",
            "a\u{345}",
        ] {
            assert_eq!(
                portable_path_collision_key(input),
                full_fold(input),
                "{input:?}"
            );
        }
    }

    #[test]
    fn default_policy_denies_before_materialization() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan = build_receive_plan(input(
            &graph,
            &root,
            DestinationPolicy::conservative_default(),
        ))
        .expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::DestinationPolicyDenied)
        );
        assert_eq!(plan.commit_policy, ReceiveCommitPolicy::DenyFinalCommit);
    }

    #[test]
    fn allow_listed_policy_with_daemon_consent_admits_final_commit() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::AllowFinalCommit);
        assert_eq!(plan.storage.result, StoragePreflightResult::Pass);
        assert!(plan.rejected_reasons.is_empty());
        assert_eq!(plan.object_graph_summary.expected_bytes, 5);
        assert_eq!(
            plan.object_graph_summary.kind_counts[&ObjectKind::FileObject.to_string()],
            1
        );
    }

    #[test]
    fn case_insensitive_allowlist_matches_destination_root_case() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/SAFE"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::AllowFinalCommit);
        assert!(
            !plan
                .rejected_reasons
                .contains(&ReceiveRejectReason::DestinationPolicyDenied)
        );
    }

    #[test]
    fn case_sensitive_allowlist_rejects_destination_root_case_mismatch() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let policy = DestinationPolicy::AllowListed {
            allowed_roots: BTreeSet::from([PathBuf::from("/SAFE")]),
            require_quarantine: true,
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            allow_special_files: false,
            case_sensitive: true,
            max_bytes: Some(1_000),
        };
        let plan = build_receive_plan(input(&graph, &root, policy)).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::DestinationPolicyDenied)
        );
    }

    #[test]
    fn mailbox_consent_keeps_receive_quarantine_only() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.consent_source = ReceiveConsentSource::MailboxPolicy {
            policy_id: "mailbox-only".to_string(),
        };

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::QuarantineOnly);
        assert_eq!(plan.commit_policy, ReceiveCommitPolicy::QuarantineOnly);
    }

    #[test]
    fn path_traversal_fails_closed() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.destination_relative_path = PathBuf::from("../escape");

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::UnsafeDestinationPath(_)))
        );
    }

    #[test]
    fn case_insensitive_object_collision_fails_closed() {
        let file_a = Object::file(b"a".to_vec());
        let file_b = Object::file(b"b".to_vec());
        let directory = Object::directory(vec![
            ObjectEdge::new(file_a.id.clone(), "Readme".to_string()),
            ObjectEdge::new(file_b.id.clone(), "README".to_string()),
        ]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file_a).expect("file a inserts");
        graph.add_object(file_b).expect("file b inserts");
        graph.add_root(directory).expect("directory root inserts");

        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::CaseCollision(_)))
        );
    }

    #[test]
    fn symlink_edges_fail_closed_unless_policy_allows_them() {
        let target = ObjectId::content(ContentId::from_bytes(b"target"));
        let file = Object::file(b"target".to_vec());
        let directory = Object::directory(vec![ObjectEdge::symlink(
            target,
            "link".to_string(),
            PathBuf::from("/etc/passwd"),
        )]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file inserts");
        graph.add_root(directory).expect("directory root inserts");

        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::SymlinkDenied(_)))
        );
    }

    #[test]
    fn executable_bits_fail_closed_under_portable_policy() {
        let mut file = Object::file(b"run".to_vec());
        file.metadata.platform = PlatformMetadata {
            unix_mode: Some(0o100_755),
            ..PlatformMetadata::default()
        };
        let directory =
            Object::directory(vec![ObjectEdge::new(file.id.clone(), "run".to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file inserts");
        graph.add_root(directory).expect("directory root inserts");

        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.object_graph_summary.executable_count, 1);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::ExecutableDenied(_)))
        );
    }

    #[test]
    fn quota_and_free_space_are_checked_with_safety_margin() {
        let (graph, root) = graph_with_file("large.bin", &[0; 32]);
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.storage_evidence = StorageEvidence {
            available_bytes: Some(100),
            quota_remaining_bytes: Some(40),
            safety_margin_bytes: 16,
        };

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.storage.result, StoragePreflightResult::QuotaExceeded);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::StorageDenied(
                    StoragePreflightResult::QuotaExceeded
                ))
        );
    }

    #[test]
    fn existing_destination_requires_explicit_overwrite_policy() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive
            .existing_destination_paths
            .insert(PathBuf::from("/safe/bundle"));

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(
            plan.destructive_actions,
            vec![DestructiveAction::Overwrite(PathBuf::from("/safe/bundle"))]
        );
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::OverwriteDenied(_)))
        );
    }

    #[test]
    fn cli_confirmation_replay_is_plan_bound() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        let wrong_confirmation = String::from("not-bound-to-plan");
        receive.consent_source = ReceiveConsentSource::CliConfirmation {
            token: wrong_confirmation,
        };

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::ConsentTokenMismatch)
        );
    }

    #[test]
    fn quarantine_queue_is_stable_and_recoverable() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.consent_source = ReceiveConsentSource::MailboxPolicy {
            policy_id: "mailbox-only".to_string(),
        };
        let plan = build_receive_plan(receive).expect("plan builds");
        let mut queue = QuarantineQueue::new();

        queue.enqueue(&plan).expect("enqueue succeeds");
        queue
            .mark_materialized(&plan.plan_digest)
            .expect("materialize succeeds");

        let items = queue.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].state, QuarantineQueueState::Materialized);
        assert_eq!(items[0].plan_digest, plan.plan_digest);
    }

    #[test]
    fn human_and_json_output_are_stable() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        let human = plan.stable_human_lines();
        let json = plan.stable_json().expect("known plan serializes to json");

        assert_eq!(human[0], "decision allow_final_commit");
        assert_eq!(json["decision"], "allow_final_commit");
        assert_eq!(json["storage"]["expected_bytes"], 5);
    }
