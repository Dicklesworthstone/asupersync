    use super::*;

    fn path(raw: &str) -> DirectoryPath {
        DirectoryPath::normalize(raw, PathNormalizationRules::default()).expect("path")
    }

    fn file(raw: &str, content_id: &str) -> DirectoryManifestEntry {
        DirectoryManifestEntry::new(
            path(raw),
            DirectoryEntryKind::File,
            Some(content_id.to_string()),
            DirectoryEntryMetadata::with_identity(content_id),
        )
    }

    fn sized_file(raw: &str, content_id: &str, size_bytes: u64) -> DirectoryManifestEntry {
        let mut metadata = DirectoryEntryMetadata::with_identity(content_id);
        metadata.size_bytes = Some(size_bytes);
        DirectoryManifestEntry::new(
            path(raw),
            DirectoryEntryKind::File,
            Some(content_id.to_string()),
            metadata,
        )
    }

    fn manifest(entries: Vec<DirectoryManifestEntry>) -> DirectoryManifest {
        let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
        for entry in entries {
            manifest.insert(entry).expect("insert");
        }
        manifest
    }

    #[test]
    fn path_normalization_rejects_unsafe_paths() {
        assert_eq!(path("a//./b\\c").as_str(), "a/b/c");
        assert!(matches!(
            DirectoryPath::normalize("../secret", PathNormalizationRules::default()),
            Err(DirectorySyncError::ParentTraversal(_))
        ));
        assert!(matches!(
            DirectoryPath::normalize("/tmp/file", PathNormalizationRules::default()),
            Err(DirectorySyncError::AbsolutePath(_))
        ));
    }

    #[test]
    fn case_conflicts_are_classified() {
        let source = manifest(vec![file("Readme.md", "a"), file("README.md", "b")]);
        let plan = plan_directory_sync(
            &source,
            &DirectoryManifest::new(PathNormalizationRules::default()),
            DirectorySyncPolicy::default(),
        );

        assert!(
            plan.decisions
                .iter()
                .any(|decision| decision.reason == "case_conflict")
        );
        assert!(
            plan.proof
                .conflict_decisions
                .iter()
                .any(|item| item.contains("case_conflict"))
        );
    }

    #[test]
    fn rename_detection_uses_stable_identity() {
        let source = manifest(vec![file("new/name.txt", "same")]);
        let destination = manifest(vec![file("old/name.txt", "same")]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::default());

        let rename = plan
            .decisions
            .iter()
            .find(|decision| decision.action == DirectorySyncAction::Rename)
            .expect("rename");
        assert_eq!(
            rename.from_path.as_ref().map(DirectoryPath::as_str),
            Some("old/name.txt")
        );
    }

    #[test]
    fn rename_detection_does_not_plan_old_path_delete() {
        let source = manifest(vec![file("new/name.txt", "same")]);
        let destination = manifest(vec![file("old/name.txt", "same")]);
        let plan = plan_directory_sync(
            &source,
            &destination,
            DirectorySyncPolicy::mirror_with_authorization(
                DestructiveAuthorization::explicit_mirror_apply(),
            ),
        );

        assert_eq!(plan.decisions.len(), 1);
        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Rename);
        assert_eq!(plan.decisions[0].path.as_str(), "new/name.txt");
        assert_eq!(
            plan.decisions[0]
                .from_path
                .as_ref()
                .map(DirectoryPath::as_str),
            Some("old/name.txt")
        );
    }

    #[test]
    fn duplicate_stable_identity_blocks_rename_candidate() {
        let source = manifest(vec![file("new/name.txt", "same")]);
        let destination = manifest(vec![
            file("old/one.txt", "same"),
            file("old/two.txt", "same"),
        ]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::default());

        assert!(
            !plan
                .decisions
                .iter()
                .any(|decision| decision.action == DirectorySyncAction::Rename)
        );
        assert_eq!(
            plan.decisions
                .iter()
                .filter(|decision| decision.reason == "stable_identity_conflict")
                .count(),
            2
        );
    }

    #[test]
    fn symlink_policy_skips_by_default() {
        let mut metadata = DirectoryEntryMetadata::default();
        metadata.symlink_target = Some("target.txt".to_string());
        let source = manifest(vec![DirectoryManifestEntry::new(
            path("link.txt"),
            DirectoryEntryKind::Symlink,
            None,
            metadata,
        )]);
        let plan = plan_directory_sync(
            &source,
            &DirectoryManifest::new(PathNormalizationRules::default()),
            DirectorySyncPolicy::default(),
        );

        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Skip);
        assert_eq!(plan.proof.skipped_paths, vec!["link.txt"]);
    }

    #[test]
    fn permission_changes_require_explicit_policy() {
        let mut source_entry = file("run.sh", "script");
        source_entry.metadata.unix_mode = Some(0o755);
        let mut destination_entry = file("run.sh", "script");
        destination_entry.metadata.unix_mode = Some(0o644);
        let source = manifest(vec![source_entry]);
        let destination = manifest(vec![destination_entry]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::default());

        assert_eq!(
            plan.decisions[0].action,
            DirectorySyncAction::PermissionChange
        );
        assert!(!plan.decisions[0].authorized);
        assert!(!plan.decisions[0].would_apply);
    }

    #[test]
    fn mirror_delete_needs_authorization_and_respects_dry_run() {
        let source = DirectoryManifest::new(PathNormalizationRules::default());
        let destination = manifest(vec![file("stale.txt", "old")]);
        let policy = DirectorySyncPolicy::mirror_with_authorization(DestructiveAuthorization {
            allow_delete: true,
            dry_run: true,
            ..DestructiveAuthorization::default()
        });
        let plan = plan_directory_sync(&source, &destination, policy);

        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Delete);
        assert!(plan.decisions[0].authorized);
        assert!(!plan.decisions[0].would_apply);
        assert!(plan.decisions[0].dry_run_visible);
    }

    #[test]
    fn metadata_round_trip_preserves_caveats() {
        let mut metadata = DirectoryEntryMetadata::with_identity("id");
        metadata.unix_mode = Some(0o600);
        metadata.modified_epoch_micros = Some(1_234);
        metadata.sparse_summary = Some("holes=2".to_string());
        let entry = DirectoryManifestEntry::new(
            path("sparse.img"),
            DirectoryEntryKind::SparseFile,
            Some("cid".to_string()),
            metadata,
        );

        assert!(entry.caveats.contains(&MetadataCaveat::UnixPermissions));
        assert!(entry.caveats.contains(&MetadataCaveat::TimestampResolution));
        assert!(entry.caveats.contains(&MetadataCaveat::SparseMetadata));
        assert_eq!(
            serde_json::from_str::<DirectoryManifestEntry>(
                &serde_json::to_string(&entry).expect("serialize")
            )
            .expect("deserialize"),
            entry
        );
    }

    #[test]
    fn conflict_classification_preserves_local_by_default() {
        let source = manifest(vec![file("same.txt", "new")]);
        let destination = manifest(vec![file("same.txt", "old")]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::send_only());

        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Conflict);
        assert_eq!(plan.decisions[0].reason, "destination_differs");
        assert!(!plan.decisions[0].would_apply);
        assert_eq!(
            plan.proof.conflict_decisions,
            vec!["same.txt:destination_differs"]
        );
    }

    #[test]
    fn directory_early_report_surfaces_metadata_and_verified_small_files() {
        let directory = DirectoryManifestEntry::new(
            path("docs"),
            DirectoryEntryKind::Directory,
            None,
            DirectoryEntryMetadata::default(),
        );
        let source = manifest(vec![
            directory,
            sized_file("docs/README.md", "small-cid", 512),
            sized_file("model.bin", "large-cid", 2 * 1024 * 1024),
        ]);
        let verified_content_ids =
            BTreeSet::from(["small-cid".to_string(), "large-cid".to_string()]);

        let report = source.early_usability_report(
            &verified_content_ids,
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            DirectoryFinalCommitState::Pending,
            "directory-replay:small-files",
        );

        assert_eq!(
            report.usability_state,
            DirectoryEarlyUsabilityState::SmallFilesAvailable
        );
        assert_eq!(
            report.final_commit_state,
            DirectoryFinalCommitState::Pending
        );
        assert_eq!(report.replay_pointer, "directory-replay:small-files");
        assert_eq!(
            report.metadata_paths,
            vec!["docs", "docs/README.md", "model.bin"]
        );
        assert_eq!(report.small_file_paths, vec!["docs/README.md"]);
        assert_eq!(report.withheld_content_paths, vec!["model.bin"]);
        assert_eq!(report.manifest_tree_root, hex::encode(source.tree_root()));
        assert!(report.safety_caveats.contains(
            &"final directory commit not complete; expose early entries separately".to_string()
        ));

        let large = report
            .entries
            .iter()
            .find(|entry| entry.path == "model.bin")
            .expect("large entry");
        assert_eq!(
            large.state,
            DirectoryEarlyEntryState::MetadataOnly,
            "large verified files must not become small-file early content"
        );
        assert_eq!(large.reason, "metadata_only_file_exceeds_small_file_policy");
    }

    #[test]
    fn directory_early_report_withholds_unverified_small_file_content() {
        let source = manifest(vec![sized_file("config.json", "config-cid", 128)]);
        let report = source.early_usability_report(
            &BTreeSet::new(),
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            DirectoryFinalCommitState::Pending,
            "directory-replay:unverified",
        );

        assert_eq!(
            report.usability_state,
            DirectoryEarlyUsabilityState::MetadataAvailable
        );
        assert_eq!(report.metadata_paths, vec!["config.json"]);
        assert!(report.small_file_paths.is_empty());
        assert_eq!(report.withheld_content_paths, vec!["config.json"]);
        assert_eq!(
            report.entries[0].reason,
            "metadata_only_content_not_verified"
        );
        assert!(!report.entries[0].content_visible);
    }

    #[test]
    fn directory_early_report_keeps_final_commit_state_separate() {
        let source = manifest(vec![sized_file("done.txt", "done-cid", 32)]);
        let policy = DirectoryEarlyUsabilityPolicy {
            expose_metadata_before_final: false,
            ..DirectoryEarlyUsabilityPolicy::small_files_up_to(1024)
        };

        let pending = source.early_usability_report(
            &BTreeSet::from(["done-cid".to_string()]),
            policy,
            DirectoryFinalCommitState::Pending,
            "directory-replay:pending",
        );
        assert_eq!(
            pending.usability_state,
            DirectoryEarlyUsabilityState::NoEntries
        );
        assert!(pending.metadata_paths.is_empty());
        assert!(pending.small_file_paths.is_empty());
        assert_eq!(
            pending.entries[0].reason,
            "metadata_withheld_until_final_commit"
        );

        let committed = source.early_usability_report(
            &BTreeSet::from(["done-cid".to_string()]),
            policy,
            DirectoryFinalCommitState::Committed,
            "directory-replay:committed",
        );
        assert_eq!(
            committed.usability_state,
            DirectoryEarlyUsabilityState::FinalCommitted
        );
        assert_eq!(
            committed.final_commit_state,
            DirectoryFinalCommitState::Committed
        );
        assert_eq!(committed.metadata_paths, vec!["done.txt"]);
        assert_eq!(committed.small_file_paths, vec!["done.txt"]);
        assert!(!committed.safety_caveats.contains(
            &"final directory commit not complete; expose early entries separately".to_string()
        ));
    }

    #[test]
    fn explicit_apply_changes_projected_tree_root() {
        let source = manifest(vec![file("same.txt", "new")]);
        let destination = manifest(vec![file("same.txt", "old")]);
        let policy = DirectorySyncPolicy::mirror_with_authorization(
            DestructiveAuthorization::explicit_mirror_apply(),
        );
        let plan = plan_directory_sync(&source, &destination, policy);

        assert!(plan.decisions[0].would_apply);
        assert_eq!(plan.proof.final_tree_root, hex::encode(source.tree_root()));
        assert!(plan.proof.replay_pointer.starts_with("directory-sync:"));
    }
