    use super::*;

    #[cfg(any(unix, windows))]
    #[test]
    fn directory_metadata_capture_includes_root_and_nonempty_directories() {
        let root = tempfile::tempdir().expect("temporary directory");
        let nested = root.path().join("nested");
        let deep = nested.join("deep");
        std::fs::create_dir_all(&deep).expect("create non-empty directory tree");
        std::fs::create_dir(root.path().join("empty")).expect("create explicit empty directory");
        std::fs::write(deep.join("payload.bin"), b"payload").expect("write nested payload");

        let captured = futures_lite::future::block_on(capture_directory_metadata_manifest(
            root.path(),
            &MetadataPolicy::default(),
        ))
        .expect("capture directory metadata");
        assert!(captured.root.is_some());
        assert_eq!(
            captured
                .entries
                .iter()
                .map(|entry| entry.rel_path.as_str())
                .collect::<Vec<_>>(),
            vec!["nested", "nested/deep"]
        );
        assert!(
            captured
                .entries
                .iter()
                .all(|entry| matches!(entry.metadata.file_kind, FileKind::Directory))
        );

        let portable = futures_lite::future::block_on(capture_directory_metadata_manifest(
            root.path(),
            &MetadataPolicy::portable(),
        ))
        .expect("portable capture");
        assert!(portable.is_empty());
    }

    #[test]
    fn windows_reparse_attribute_is_treated_as_link_like() {
        assert!(windows_attributes_contain_reparse_point(
            WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(!windows_attributes_contain_reparse_point(0));
    }

    #[test]
    fn receive_metadata_validation_rejects_noncanonical_wire_values() {
        let mut policy = MetadataPolicy::default();
        policy.preserve_timestamps = true;

        let invalid_mode = EntryMetadata {
            unix_mode: Some(0o10_000),
            ..EntryMetadata::default()
        };
        assert!(
            validate_entry_metadata_for_receive("file", &invalid_mode, &policy)
                .expect_err("noncanonical mode must fail")
                .contains("0o7777")
        );

        let incomplete_owner = EntryMetadata {
            uid: Some(1000),
            ..EntryMetadata::default()
        };
        assert!(
            validate_entry_metadata_for_receive("file", &incomplete_owner, &policy)
                .expect_err("partial owner tuple must fail")
                .contains("both uid and gid")
        );

        for invalid_time in [
            EntryMetadata {
                mtime_nanos: Some(1),
                ..EntryMetadata::default()
            },
            EntryMetadata {
                mtime_unix_secs: Some(1),
                mtime_nanos: Some(1_000_000_000),
                ..EntryMetadata::default()
            },
        ] {
            assert!(
                validate_entry_metadata_for_receive("file", &invalid_time, &policy)
                    .expect_err("invalid time tuple must fail")
                    .contains("modification time")
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlink_identity_keeps_high_64_file_id_bits() {
        let mut first_id = [0u8; 16];
        first_id[0] = 7;
        let mut second_id = first_id;
        second_id[12] = 1;
        let first = HardlinkIdentity::windows(42, first_id);
        let second = HardlinkIdentity::windows(42, second_id);
        assert_ne!(first, second, "ReFS high file-id bits must remain distinct");
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_normalizes_contained_backslash_symlink_target() {
        let root = tempfile::tempdir().expect("temporary directory");
        let target = root.path().join("targets/file.txt");
        std::fs::create_dir_all(target.parent().expect("target parent"))
            .expect("create target directory");
        std::fs::write(&target, b"target").expect("write target");
        let link = root.path().join("link");
        std::os::windows::fs::symlink_file(Path::new(r"targets\file.txt"), &link)
            .expect("create Windows relative symlink");

        let metadata = read_entry_metadata_sync(&link, &MetadataPolicy::default())
            .expect("capture Windows symlink metadata");
        assert_eq!(metadata.symlink_target.as_deref(), Some("targets/file.txt"));
        assert!(matches!(
            metadata.symlink_target_info,
            Some(SymlinkTargetInfo {
                semantics: SymlinkTargetSemantics::PortableRelative,
                ..
            })
        ));
        validate_entry_metadata_for_receive("link", &metadata, &MetadataPolicy::default())
            .expect("normalized target validates for receive");
    }

    #[cfg(unix)]
    #[test]
    fn transactional_symlink_commit_replaces_file_without_temp_leaks() {
        let root = tempfile::tempdir().expect("temporary directory");
        let target = root.path().join("target");
        let link = root.path().join("link");
        std::fs::write(&target, b"target").expect("write target");
        std::fs::write(&link, b"old").expect("write old destination");
        let metadata = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("target".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::File),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            ..EntryMetadata::default()
        };

        futures_lite::future::block_on(commit_symlink_transactionally("link", &link, &metadata))
            .expect("commit symlink");
        assert_eq!(
            std::fs::read_link(&link).expect("read link"),
            Path::new("target")
        );
        assert!(
            std::fs::read_dir(root.path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".atp-sym-"))
        );
    }

    #[test]
    fn transactional_regular_commit_replaces_file_without_temp_leaks() {
        let root = tempfile::tempdir().expect("temporary directory");
        let staging = root.path().join("staging");
        let destination = root.path().join("destination");
        std::fs::write(&staging, b"new").expect("write staged file");
        std::fs::write(&destination, b"old").expect("write destination");

        futures_lite::future::block_on(commit_staged_regular_file_transactionally(
            &staging,
            &destination,
        ))
        .expect("commit staged regular file");
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"new"
        );
        assert!(!staging.exists(), "staging leaf must be consumed");
        assert!(
            std::fs::read_dir(root.path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".atp-sym-backup-"))
        );
    }

    /// br-asupersync-r02ssd: a batch commits each file atomically and records
    /// each distinct parent once, so one `sync` replaces a directory fsync per
    /// file.
    #[test]
    fn deferred_parent_syncs_commit_each_file_and_sync_each_parent_once() {
        let root = tempfile::tempdir().expect("temporary directory");
        let first_dir = root.path().join("a");
        let second_dir = root.path().join("b");
        std::fs::create_dir(&first_dir).expect("create a");
        std::fs::create_dir(&second_dir).expect("create b");
        let mut batch = DeferredParentSyncs::default();
        let destinations = [
            first_dir.join("one"),
            first_dir.join("two"),
            first_dir.join("three"),
            second_dir.join("four"),
        ];
        for (index, destination) in destinations.iter().enumerate() {
            let staging = root.path().join(format!("staging-{index}"));
            std::fs::write(&staging, format!("file {index}")).expect("write staged file");
            futures_lite::future::block_on(batch.commit_staged_regular_file(&staging, destination))
                .expect("commit staged regular file");
            assert!(!staging.exists(), "staging leaf {index} must be consumed");
            assert_eq!(
                std::fs::read_to_string(destination).expect("read destination"),
                format!("file {index}")
            );
        }
        assert_eq!(
            batch.parents.keys().cloned().collect::<Vec<_>>(),
            vec![first_dir.clone(), second_dir.clone()],
            "each distinct parent is recorded once and synced later, not per file"
        );
        futures_lite::future::block_on(batch.sync()).expect("sync recorded parents");
    }

    #[test]
    fn staged_sync_failure_preserves_source_destination_and_parent_batch() {
        let root = tempfile::tempdir().expect("temporary directory");
        let staging = root.path().join("staging");
        let destination = root.path().join("destination");
        std::fs::write(&staging, b"new payload").expect("write staged bytes");
        std::fs::write(&destination, b"old payload").expect("write old bytes");
        let mut batch = DeferredParentSyncs::default();
        let result = futures_lite::future::block_on(async {
            let pending = StagedFileSync::open(&staging).await?;
            let synced = pending
                .sync_with(|file| {
                    assert_eq!(file.metadata()?.len(), 11);
                    assert_eq!(std::fs::read(&destination)?, b"old payload");
                    Err(io::Error::other("planted data-sync failure"))
                })
                .map_err(|error| StreamingError::new(error.to_string()))?;
            batch.commit_synced_regular_file(synced, &destination).await
        });

        let error = result.expect_err("failed sync must prevent publication");
        assert!(error.to_string().contains("planted data-sync failure"));
        assert_eq!(std::fs::read(&staging).unwrap(), b"new payload");
        assert_eq!(std::fs::read(&destination).unwrap(), b"old payload");
        assert!(batch.parents.is_empty(), "no rename was acknowledged");
    }

    /// A real kernel sync refusal distinguishes fsync from a no-op. Procfs
    /// exposes a readable regular file but does not support syncing it. Every
    /// production entry point must report that refusal before trying a rename.
    #[cfg(target_os = "linux")]
    #[test]
    fn regular_commit_paths_propagate_real_sync_failure_before_rename() {
        let root = tempfile::tempdir().expect("temporary directory");
        let staging = Path::new("/proc/self/status");
        assert!(std::fs::symlink_metadata(staging).unwrap().is_file());
        for mode in 0..3 {
            let destination = root.path().join(format!("destination-{mode}"));
            std::fs::write(&destination, b"old payload").expect("write old bytes");
            let mut batch = DeferredParentSyncs::default();
            let result = match mode {
                0 => futures_lite::future::block_on(commit_staged_regular_file_transactionally(
                    staging,
                    &destination,
                )),
                1 => futures_lite::future::block_on(
                    batch.commit_staged_regular_file(staging, &destination),
                ),
                _ => install_staged_regular_file_sync(staging, &destination),
            };
            let error = result.expect_err("procfs cannot sync staged file data");
            assert!(
                error.to_string().contains("sync staged file before commit"),
                "mode {mode} must fail at the data sync, before rename: {error}"
            );
            assert_eq!(std::fs::read(&destination).unwrap(), b"old payload");
            assert!(staging.exists(), "the source must remain untouched");
            assert!(batch.parents.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_sync_handle_preserves_restrictive_metadata_and_final_bytes() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary directory");
        let staging = root.path().join("staging");
        let destination = root.path().join("destination");
        std::fs::write(&destination, b"old").unwrap();
        let mut writer = std::fs::File::create(&staging).unwrap();
        writer.write_all(b"complete payload").unwrap();
        let pending = StagedFileSync::from_file(staging.clone(), writer).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0)).unwrap();
        let synced = pending
            .sync_with(|file| {
                assert_eq!(file.metadata()?.permissions().mode() & 0o7777, 0);
                assert_eq!(file.metadata()?.len(), 16);
                assert_eq!(std::fs::read(&destination)?, b"old");
                file.sync_all()
            })
            .expect("the retained handle can sync mode-000 data");
        let mut batch = DeferredParentSyncs::default();
        futures_lite::future::block_on(batch.commit_synced_regular_file(synced, &destination))
            .expect("publish already synced data without reopening it");
        assert!(!staging.exists());
        assert_eq!(
            std::fs::metadata(&destination).unwrap().permissions().mode() & 0o7777,
            0
        );
        futures_lite::future::block_on(batch.sync()).expect("sync destination directory");
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"complete payload");
    }

    #[cfg(unix)]
    #[test]
    fn transactional_bytes_and_hardlink_keep_mode_zero_without_reopening() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary directory");
        let primary = root.path().join("primary");
        let alias = root.path().join("alias");
        let metadata = EntryMetadata {
            unix_mode: Some(0),
            ..EntryMetadata::default()
        };
        futures_lite::future::block_on(commit_regular_bytes_with_metadata_transactionally(
            &primary,
            b"durable primary",
            Some(&metadata),
        ))
        .expect("original writable handle survives restrictive metadata");
        futures_lite::future::block_on(commit_hardlink_transactionally(&primary, &alias))
            .expect("adding a link does not reopen the primary's bytes");
        assert_eq!(
            inode_key_if_regular_sync(&primary).unwrap(),
            inode_key_if_regular_sync(&alias).unwrap()
        );
        for path in [&primary, &alias] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o7777, 0);
        }
        std::fs::set_permissions(&primary, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&alias).unwrap(), b"durable primary");
    }

    #[cfg(unix)]
    #[test]
    fn data_sync_refuses_fifo_and_symlink_without_opening_them() {
        let root = tempfile::tempdir().expect("temporary directory");
        let fifo = root.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"target").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for path in [fifo, link] {
            let result = StagedFileSync::open_sync(path);
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
        }
    }

    #[test]
    fn transactional_regular_metadata_verifier_refuses_before_publication() {
        fn planted_refusal(
            _staging_path: &Path,
            _metadata: &EntryMetadata,
        ) -> Result<(), StreamingError> {
            Err(StreamingError::new("planted metadata read-back refusal"))
        }

        let root = tempfile::tempdir().expect("temporary directory");
        let destination = root.path().join("destination");
        std::fs::write(&destination, b"old destination").expect("write old destination");
        let metadata = EntryMetadata::default();

        let error = futures_lite::future::block_on(
            commit_regular_bytes_with_metadata_verified_transactionally(
                &destination,
                b"rejected replacement",
                Some(&metadata),
                false,
                planted_refusal,
            ),
        )
        .expect_err("planted metadata refusal must fail the transaction");

        assert!(
            error
                .to_string()
                .contains("planted metadata read-back refusal")
        );
        assert_eq!(
            std::fs::read(&destination).expect("read preserved destination"),
            b"old destination",
            "verifier refusal must happen before final rename"
        );
        assert!(
            std::fs::read_dir(root.path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".atp-sym-file-new-")),
            "rejected staging leaf must be reclaimed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn transactional_fifo_commit_replaces_leaf_without_temp_leaks() {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().expect("temporary directory");
        let destination = root.path().join("destination");
        std::fs::write(&destination, b"old regular destination").expect("write destination");
        let metadata = EntryMetadata {
            file_kind: FileKind::Fifo,
            unix_mode: Some(0o640),
            mtime_unix_secs: Some(1_600_000_789),
            mtime_nanos: Some(123_456_789),
            ..EntryMetadata::default()
        };

        futures_lite::future::block_on(commit_fifo_transactionally(&destination, &metadata))
            .expect("commit FIFO transactionally");
        let committed = std::fs::symlink_metadata(&destination).expect("FIFO metadata");
        assert!(committed.file_type().is_fifo());
        assert_eq!(committed.permissions().mode() & 0o7777, 0o640);
        assert_eq!(
            (committed.mtime(), committed.mtime_nsec()),
            (1_600_000_789, 123_456_789)
        );
        assert!(
            std::fs::read_dir(root.path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".atp-sym-fifo-new-"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn transactional_fifo_commit_failure_preserves_existing_destination() {
        let root = tempfile::tempdir().expect("temporary directory");
        let destination = root.path().join("destination");
        std::fs::create_dir(&destination).expect("create protected destination directory");
        let metadata = EntryMetadata {
            file_kind: FileKind::Fifo,
            unix_mode: Some(0o640),
            ..EntryMetadata::default()
        };

        let error =
            futures_lite::future::block_on(commit_fifo_transactionally(&destination, &metadata))
                .expect_err("FIFO must not replace an existing directory");
        assert!(error.to_string().contains("directory"));
        assert!(
            destination.is_dir(),
            "failed install must preserve destination"
        );
        assert!(
            std::fs::read_dir(root.path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".atp-sym-fifo-new-"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn transactional_regular_commit_replaces_readonly_windows_file() {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        let root = tempfile::tempdir().expect("temporary directory");
        let staging = root.path().join("staging");
        let destination = root.path().join("destination");
        std::fs::write(&staging, b"new").expect("write staged file");
        std::fs::write(&destination, b"old").expect("write destination");
        set_windows_attributes(
            &destination,
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
        )
        .expect("make destination read-only");

        futures_lite::future::block_on(commit_staged_regular_file_transactionally(
            &staging,
            &destination,
        ))
        .expect("replace read-only destination");
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"new"
        );
        let attributes = std::fs::symlink_metadata(&destination)
            .expect("destination metadata")
            .file_attributes();
        assert_eq!(
            attributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
            0
        );
        assert!(!staging.exists(), "staging leaf must be consumed");
    }

    #[cfg(windows)]
    #[test]
    fn transactional_regular_commit_replaces_readonly_windows_symlinks() {
        use std::os::windows::fs::{
            FileTypeExt as _, OpenOptionsExt as _, symlink_dir, symlink_file,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
        };

        fn make_link_readonly(path: &Path) {
            let mut options = std::fs::OpenOptions::new();
            let file = options
                .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
                .expect("open symlink itself");
            let mut permissions = file.metadata().expect("symlink metadata").permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions)
                .expect("make symlink read-only");
            assert!(
                file.metadata()
                    .expect("read-only symlink metadata")
                    .permissions()
                    .readonly()
            );
        }

        let root = tempfile::tempdir().expect("temporary directory");
        let file_target = root.path().join("file-target");
        let directory_target = root.path().join("directory-target");
        std::fs::write(&file_target, b"target").expect("write file target");
        std::fs::create_dir(&directory_target).expect("create directory target");

        for (label, directory_link) in [("file", false), ("directory", true)] {
            let destination = root.path().join(format!("{label}-destination"));
            if directory_link {
                symlink_dir(&directory_target, &destination).expect("create directory symlink");
            } else {
                symlink_file(&file_target, &destination).expect("create file symlink");
            }
            make_link_readonly(&destination);
            let staging = root.path().join(format!("{label}-staging"));
            std::fs::write(&staging, format!("new-{label}")).expect("write staged file");

            futures_lite::future::block_on(commit_staged_regular_file_transactionally(
                &staging,
                &destination,
            ))
            .unwrap_or_else(|error| panic!("replace read-only {label} symlink: {error}"));
            assert_eq!(
                std::fs::read(&destination).expect("read replacement"),
                format!("new-{label}").as_bytes()
            );
            assert!(
                std::fs::symlink_metadata(&destination)
                    .expect("replacement metadata")
                    .file_type()
                    .is_file(),
                "{label} symlink must be replaced by a regular file"
            );
            assert!(
                !std::fs::symlink_metadata(&destination)
                    .expect("replacement metadata")
                    .file_type()
                    .is_symlink_file()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn transactional_bytes_commit_installs_incoming_readonly_attributes() {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        let root = tempfile::tempdir().expect("temporary directory");
        let destination = root.path().join("destination");
        std::fs::write(&destination, b"stale").expect("write stale destination");
        let metadata = EntryMetadata {
            windows_attributes: Some(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
            ..EntryMetadata::default()
        };

        let report =
            futures_lite::future::block_on(commit_regular_bytes_with_metadata_transactionally(
                &destination,
                b"replacement",
                Some(&metadata),
            ))
            .expect("commit bytes with read-only metadata");
        assert!(report.applied.contains(&"windows_attributes"));
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"replacement"
        );
        let attributes = std::fs::symlink_metadata(&destination)
            .expect("destination metadata")
            .file_attributes();
        assert_eq!(
            attributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
        );

        set_windows_attributes(&destination, 0).expect("clear attributes for cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn transactional_hardlink_commit_replaces_readonly_windows_file() {
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        let root = tempfile::tempdir().expect("temporary directory");
        let primary = root.path().join("primary");
        let destination = root.path().join("destination");
        let displaced_alias = root.path().join("displaced-alias");
        std::fs::write(&primary, b"shared").expect("write primary");
        std::fs::write(&destination, b"old").expect("write destination");
        std::fs::hard_link(&destination, &displaced_alias).expect("link displaced destination");
        set_windows_attributes(&primary, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN)
            .expect("make primary read-only");
        set_windows_attributes(&destination, FILE_ATTRIBUTE_READONLY)
            .expect("make destination read-only");

        futures_lite::future::block_on(commit_hardlink_transactionally(&primary, &destination))
            .expect("replace destination with hardlink");
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"shared"
        );
        assert_eq!(
            inode_key_if_regular_sync(&primary).expect("primary identity"),
            inode_key_if_regular_sync(&destination).expect("destination identity")
        );
        use std::os::windows::fs::MetadataExt as _;
        assert_eq!(
            std::fs::symlink_metadata(&primary)
                .expect("primary metadata")
                .file_attributes()
                & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
        );
        assert_eq!(
            std::fs::read(&displaced_alias).expect("read displaced alias"),
            b"old"
        );
        assert_ne!(
            std::fs::symlink_metadata(&displaced_alias)
                .expect("displaced alias metadata")
                .file_attributes()
                & FILE_ATTRIBUTE_READONLY,
            0
        );

        // TempDir cleanup must not be defeated by the intentionally preserved
        // read-only attributes on either hardlink set.
        set_windows_attributes(&primary, 0).expect("clear primary attributes for cleanup");
        set_windows_attributes(&displaced_alias, 0)
            .expect("clear displaced attributes for cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn windows_unix_time_parts_round_trip_before_and_after_epoch() {
        for (seconds, nanos) in [
            (-2_i64, 125_000_000_u32),
            (-1, 0),
            (-1, 1),
            (-1, 999_999_999),
            (0, 0),
            (1, 500_000_000),
        ] {
            let time = unix_parts_to_system_time(seconds, nanos).expect("representable timestamp");
            let platform_nanos = nanos - (nanos % 100);
            assert_eq!(
                system_time_to_unix_parts(time),
                Some((seconds, platform_nanos))
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_applies_pre_epoch_mtime() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("pre-epoch");
        std::fs::write(&path, b"timestamp").expect("write fixture");
        let metadata = EntryMetadata {
            mtime_unix_secs: Some(-315_619_200),
            mtime_nanos: Some(123_456_700),
            ..EntryMetadata::default()
        };

        let report = apply_entry_metadata_sync(&path, &metadata).expect("apply metadata");
        assert!(report.applied.contains(&"mtime"), "report: {report:?}");
        let captured = read_entry_metadata_sync(
            &path,
            &MetadataPolicy {
                preserve_timestamps: true,
                ..MetadataPolicy::portable()
            },
        )
        .expect("capture applied metadata");
        assert_eq!(captured.mtime_unix_secs, metadata.mtime_unix_secs);
        assert_eq!(captured.mtime_nanos, metadata.mtime_nanos);
    }

    #[cfg(windows)]
    #[test]
    fn windows_applies_attributes_beyond_legacy_max_path() {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
        let root = tempfile::tempdir().expect("temporary directory");
        let mut parent = root.path().to_path_buf();
        for index in 0..8 {
            parent.push(format!(
                "segment-{index:02}-0123456789abcdef0123456789abcdef"
            ));
        }
        std::fs::create_dir_all(&parent).expect("create extended-length parent");
        let path = parent.join("payload.bin");
        assert!(
            path.as_os_str().len() > 260,
            "fixture must exceed legacy MAX_PATH: {}",
            path.display()
        );
        std::fs::write(&path, b"long-path").expect("write extended-length file");

        set_windows_attributes(&path, FILE_ATTRIBUTE_HIDDEN)
            .expect("apply attributes through a long-path-safe handle");
        let attributes = std::fs::symlink_metadata(&path)
            .expect("read extended-length metadata")
            .file_attributes();
        assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_distinguishes_file_and_directory_symlinks() {
        let root = tempfile::tempdir().expect("temporary directory");
        std::fs::write(root.path().join("file-target"), b"target").expect("write file target");
        std::fs::create_dir(root.path().join("dir-target")).expect("create dir target");
        let file_link = root.path().join("file-link");
        let dir_link = root.path().join("dir-link");
        std::os::windows::fs::symlink_file("file-target", &file_link)
            .expect("create Windows file symlink");
        std::os::windows::fs::symlink_dir("dir-target", &dir_link)
            .expect("create Windows directory symlink");

        let file = read_entry_metadata_sync(&file_link, &MetadataPolicy::default())
            .expect("capture file link");
        let directory = read_entry_metadata_sync(&dir_link, &MetadataPolicy::default())
            .expect("capture directory link");
        assert_eq!(
            file.symlink_target_info.and_then(|info| info.kind),
            Some(SymlinkTargetKind::File)
        );
        assert_eq!(
            directory.symlink_target_info.and_then(|info| info.kind),
            Some(SymlinkTargetKind::Directory)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlinks_share_the_same_identity() {
        let root = tempfile::tempdir().expect("temporary directory");
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::write(&first, b"same inode").expect("write primary");
        std::fs::hard_link(&first, &second).expect("create hardlink");
        let first_key = inode_key_if_regular_sync(&first)
            .expect("first identity query")
            .expect("first identity available");
        let second_key = inode_key_if_regular_sync(&second)
            .expect("second identity query")
            .expect("second identity available");
        assert_eq!(first_key, second_key);
    }

    fn meta(mode: Option<u32>) -> EntryMetadata {
        EntryMetadata {
            unix_mode: mode,
            ..Default::default()
        }
    }

    fn zero_scan_entry(
        rel_path: &str,
        size_bytes: u64,
        mtime_secs: i64,
        ctime_secs: Option<i64>,
        identity: Option<FileIdentity>,
    ) -> ZeroScanEntry {
        let metadata = EntryMetadata {
            mtime_unix_secs: Some(mtime_secs),
            mtime_nanos: Some(0),
            ..Default::default()
        };
        let mut fingerprint =
            ZeroScanFingerprint::from_entry_metadata(size_bytes, &metadata).with_similarity(
                SimilaritySignature::new(size_bytes.rotate_left(7), Some(size_bytes)),
            );
        if let Some(secs) = ctime_secs {
            fingerprint = fingerprint.with_ctime(secs, 0);
        }
        if let Some(id) = identity {
            fingerprint = fingerprint.with_identity(id);
        }
        ZeroScanEntry::new(rel_path, fingerprint)
    }

    #[test]
    fn zero_scan_prefilter_skips_unchanged_tree() {
        let prior = vec![
            zero_scan_entry("alpha.bin", 10, 1_700_000_000, Some(1_700_000_010), None),
            zero_scan_entry(
                "nested/beta.bin",
                20,
                1_700_000_001,
                Some(1_700_000_011),
                None,
            ),
        ];
        let current = prior.clone();

        let plan = ZeroScanPrefilter::plan(&prior, &current, None, ZeroScanPolicy::default());

        assert_eq!(plan.scheduled_chunk_hashes, 0);
        assert_eq!(plan.skipped_chunk_hashes, 2);
        assert_eq!(plan.skipped_chunk_hash_bytes, 30);
        assert_eq!(plan.estimated_content_bytes_floor, 0);
        assert!(
            plan.decisions
                .iter()
                .all(|decision| matches!(decision, ZeroScanDecision::Unchanged { .. }))
        );
    }

    #[test]
    fn zero_scan_dirty_set_forces_chunk_hashing() {
        let prior = vec![
            zero_scan_entry("alpha.bin", 10, 1_700_000_000, Some(1_700_000_010), None),
            zero_scan_entry(
                "nested/beta.bin",
                20,
                1_700_000_001,
                Some(1_700_000_011),
                None,
            ),
        ];
        let current = prior.clone();
        let dirty = DirtyPathSet::from_paths(["nested/beta.bin"]);

        let plan =
            ZeroScanPrefilter::plan(&prior, &current, Some(&dirty), ZeroScanPolicy::default());

        assert_eq!(plan.skipped_chunk_hashes, 1);
        assert_eq!(plan.scheduled_chunk_hashes, 1);
        assert_eq!(plan.estimated_content_bytes_floor, 20);
        assert!(matches!(
            plan.decisions[1],
            ZeroScanDecision::NeedsChunkHash {
                reason: ZeroScanHashReason::DirtySetHit,
                ..
            }
        ));
    }

    #[test]
    fn zero_scan_detects_rename_without_resending_content() {
        let identity = FileIdentity::new(7, 42);
        let prior = vec![zero_scan_entry(
            "old-name.bin",
            64,
            1_700_000_000,
            Some(1_700_000_010),
            Some(identity),
        )];
        let current = vec![zero_scan_entry(
            "new-name.bin",
            64,
            1_700_000_000,
            Some(1_700_000_010),
            Some(identity),
        )];

        let plan = ZeroScanPrefilter::plan(&prior, &current, None, ZeroScanPolicy::default());

        assert_eq!(plan.scheduled_chunk_hashes, 0);
        assert_eq!(plan.skipped_chunk_hashes, 1);
        assert_eq!(plan.estimated_content_bytes_floor, 0);
        assert_eq!(
            plan.decisions,
            vec![ZeroScanDecision::ReusePriorContent {
                rel_path: "new-name.bin".to_string(),
                prior_rel_path: "old-name.bin".to_string(),
            }]
        );
    }

    #[test]
    fn zero_scan_requires_ctime_by_default() {
        let prior = vec![zero_scan_entry(
            "same-size-mtime.bin",
            64,
            1_700_000_000,
            None,
            None,
        )];
        let current = prior.clone();

        let plan = ZeroScanPrefilter::plan(&prior, &current, None, ZeroScanPolicy::default());

        assert_eq!(plan.scheduled_chunk_hashes, 1);
        assert!(matches!(
            plan.decisions[0],
            ZeroScanDecision::NeedsChunkHash {
                reason: ZeroScanHashReason::StatChanged,
                ..
            }
        ));

        let permissive = ZeroScanPolicy {
            require_ctime: false,
            ..ZeroScanPolicy::default()
        };
        let plan = ZeroScanPrefilter::plan(&prior, &current, None, permissive);
        assert_eq!(plan.scheduled_chunk_hashes, 0);
        assert!(matches!(
            plan.decisions[0],
            ZeroScanDecision::Unchanged { .. }
        ));
    }

    #[test]
    fn bare_metadata_yields_no_commitment() {
        let bare = EntryMetadata::default();
        assert!(bare.is_bare());
        assert_eq!(metadata_commitment(&[("a", &bare), ("b", &bare)]), None);
    }

    #[test]
    fn commitment_is_order_independent_and_64_hex() {
        let a = meta(Some(0o644));
        let b = meta(Some(0o755));
        let r1 = metadata_commitment(&[("a", &a), ("b", &b)]).expect("commitment");
        let r2 = metadata_commitment(&[("b", &b), ("a", &a)]).expect("commitment");
        assert_eq!(r1, r2, "commitment must be order-independent");
        assert_eq!(r1.len(), 64);
        assert!(r1.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn changing_a_mode_changes_the_commitment() {
        // The headline "merkle covers metadata" property: flip one mode bit and
        // the committed root must move.
        let before = metadata_commitment(&[("f", &meta(Some(0o644)))]).expect("c");
        let after = metadata_commitment(&[("f", &meta(Some(0o600)))]).expect("c");
        assert_ne!(before, after, "metadata change must change the commitment");
    }

    #[test]
    fn legacy_v1_symlink_commitment_is_frozen() {
        let legacy = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("../t".to_string()),
            ..EntryMetadata::default()
        };
        assert_eq!(
            metadata_commitment(&[("f", &legacy)]).as_deref(),
            Some("4af5addb7e13dbcad54a31d2b2c2567f17c5954026294388e8051e76a4f4efe0")
        );
    }

    #[test]
    fn v2_commitment_covers_symlink_kind_semantics_and_windows_attributes() {
        let mut file_link = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("target".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::File),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            ..EntryMetadata::default()
        };
        let file_root = metadata_commitment(&[("link", &file_link)]).expect("v2 root");

        file_link.symlink_target_info.as_mut().expect("info").kind =
            Some(SymlinkTargetKind::Directory);
        let directory_root = metadata_commitment(&[("link", &file_link)]).expect("v2 root");
        assert_ne!(file_root, directory_root);

        file_link
            .symlink_target_info
            .as_mut()
            .expect("info")
            .semantics = SymlinkTargetSemantics::Unix;
        let native_root = metadata_commitment(&[("link", &file_link)]).expect("v2 root");
        assert_ne!(directory_root, native_root);

        let attributes = EntryMetadata {
            windows_attributes: Some(0x21),
            ..EntryMetadata::default()
        };
        assert_ne!(
            metadata_commitment(&[("f", &attributes)]),
            metadata_commitment(&[("f", &EntryMetadata::default())])
        );
    }

    #[test]
    fn symlink_target_validation_normalizes_against_manifest_parent() {
        let metadata = EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("../target".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::File),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            ..EntryMetadata::default()
        };
        assert!(validate_symlink_metadata_for_receive("dir/link", &metadata).is_ok());
        assert!(validate_symlink_metadata_for_receive("link", &metadata).is_err());

        for target in ["/rooted", "\\rooted", "C:relative", "dir\\file", "../NUL"] {
            let mut invalid = metadata.clone();
            invalid.symlink_target = Some(target.to_string());
            assert!(
                validate_symlink_metadata_for_receive("dir/link", &invalid).is_err(),
                "target {target:?} must fail closed"
            );
        }
    }

    #[test]
    fn unsafe_windows_attribute_bits_are_rejected() {
        let metadata = EntryMetadata {
            windows_attributes: Some(WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT),
            ..EntryMetadata::default()
        };
        assert!(validate_symlink_metadata_for_receive("file", &metadata).is_err());
    }

    #[test]
    fn changing_mtime_or_symlink_changes_the_commitment() {
        let base = EntryMetadata {
            unix_mode: Some(0o644),
            mtime_unix_secs: Some(1000),
            ..Default::default()
        };
        let mut later = base.clone();
        later.mtime_unix_secs = Some(2000);
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &later)]),
        );
        let mut link = base.clone();
        link.file_kind = FileKind::Symlink;
        link.symlink_target = Some("target.txt".to_string());
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &link)]),
        );
    }

    #[test]
    fn changing_xattrs_changes_the_commitment() {
        let mut base = meta(Some(0o644));
        base.xattrs
            .insert("user.asupersync.alpha".to_string(), b"one".to_vec());
        let mut changed = base.clone();
        changed
            .xattrs
            .insert("user.asupersync.alpha".to_string(), b"two".to_vec());
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &changed)]),
            "xattr value changes must move the metadata commitment"
        );

        let mut renamed = base.clone();
        renamed.xattrs.clear();
        renamed
            .xattrs
            .insert("user.asupersync.beta".to_string(), b"one".to_vec());
        assert_ne!(
            metadata_commitment(&[("f", &base)]),
            metadata_commitment(&[("f", &renamed)]),
            "xattr name changes must move the metadata commitment"
        );
    }

    #[test]
    fn presence_distinguishes_absent_from_zero() {
        let absent = EntryMetadata {
            unix_mode: Some(0o644),
            ..Default::default()
        };
        let zero_uid = EntryMetadata {
            unix_mode: Some(0o644),
            uid: Some(0),
            gid: Some(0),
            ..Default::default()
        };
        assert_ne!(
            metadata_commitment(&[("f", &absent)]),
            metadata_commitment(&[("f", &zero_uid)]),
            "absent uid must hash differently from uid=0",
        );
    }

    #[test]
    fn entry_metadata_json_round_trips() {
        let m = EntryMetadata {
            file_kind: FileKind::Symlink,
            unix_mode: Some(0o777),
            mtime_unix_secs: Some(1_700_000_000),
            mtime_nanos: Some(123),
            uid: Some(1000),
            gid: Some(1000),
            windows_attributes: None,
            symlink_target: Some("../t".to_string()),
            symlink_target_info: Some(SymlinkTargetInfo {
                kind: Some(SymlinkTargetKind::Directory),
                semantics: SymlinkTargetSemantics::PortableRelative,
            }),
            hardlink_target: None,
            xattrs: BTreeMap::from([("user.asupersync.note".to_string(), b"hello".to_vec())]),
        };
        let js = serde_json::to_string(&m).expect("ser");
        let back: EntryMetadata = serde_json::from_str(&js).expect("de");
        assert_eq!(m, back);
    }

    #[cfg(unix)]
    #[test]
    fn apply_metadata_huge_mtime_nanos_carry_does_not_panic() {
        let meta = EntryMetadata {
            mtime_unix_secs: Some(i64::MAX),
            mtime_nanos: Some(1_000_000_000),
            ..Default::default()
        };
        let path = Path::new("/asupersync-metadata-mtime-overflow-regression-missing-file");

        let report = futures_lite::future::block_on(apply_entry_metadata(path, &meta))
            .expect("out-of-range off-wire mtime must degrade into a metadata report");

        assert!(report.applied.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "mtime");
    }

    #[cfg(unix)]
    #[test]
    fn apply_metadata_preserves_pre_epoch_mtime() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("pre-epoch");
        std::fs::write(&path, b"timestamp").expect("write fixture");
        let meta = EntryMetadata {
            mtime_unix_secs: Some(-315_619_200),
            mtime_nanos: Some(123_456_789),
            ..Default::default()
        };

        let report = futures_lite::future::block_on(apply_entry_metadata(&path, &meta))
            .expect("apply pre-epoch mtime");
        assert!(report.applied.contains(&"mtime"), "report: {report:?}");

        let captured = read_entry_metadata_sync(
            &path,
            &MetadataPolicy {
                preserve_timestamps: true,
                ..MetadataPolicy::portable()
            },
        )
        .expect("capture pre-epoch mtime");
        assert_eq!(captured.mtime_unix_secs, meta.mtime_unix_secs);
        assert_eq!(captured.mtime_nanos, meta.mtime_nanos);
    }

    #[cfg(all(unix, not(target_os = "redox")))]
    #[test]
    fn apply_metadata_preserves_fifo_mtime_without_opening_it() {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("events.fifo");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .expect("create FIFO fixture");
        let meta = EntryMetadata {
            file_kind: FileKind::Fifo,
            unix_mode: Some(0o620),
            mtime_unix_secs: Some(1_600_000_789),
            mtime_nanos: Some(123_456_789),
            ..EntryMetadata::default()
        };

        let report = apply_entry_metadata_sync(&path, &meta).expect("apply FIFO metadata");
        assert!(report.applied.contains(&"mtime"), "report: {report:?}");
        assert!(report.applied.contains(&"mode"), "report: {report:?}");

        let observed = std::fs::symlink_metadata(&path).expect("stat FIFO after metadata apply");
        assert!(observed.file_type().is_fifo());
        assert_eq!(observed.permissions().mode() & 0o7777, 0o620);
        assert_eq!(
            (observed.mtime(), observed.mtime_nsec()),
            (1_600_000_789, 123_456_789)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_xattr_apply_does_not_follow_a_swapped_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary directory");
        let target = root.path().join("outside-target");
        let path = root.path().join("events.fifo");
        std::fs::write(&target, b"unchanged").expect("write target fixture");
        symlink(&target, &path).expect("replace FIFO path with symlink fixture");

        let attribute = "user.asupersync-fifo-nofollow";
        let meta = EntryMetadata {
            file_kind: FileKind::Fifo,
            xattrs: std::collections::BTreeMap::from([(
                attribute.to_string(),
                b"must-not-redirect".to_vec(),
            )]),
            ..EntryMetadata::default()
        };

        let _report = apply_entry_metadata_sync(&path, &meta).expect("apply FIFO metadata");
        assert_ne!(
            xattr::get(&target, attribute).expect("read target xattr"),
            Some(b"must-not-redirect".to_vec()),
            "FIFO xattr application followed a swapped symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_metadata_filters_unpermitted_xattr_namespaces() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("xattr-filter-target");
        std::fs::write(&path, b"content").expect("write fixture");

        let meta = EntryMetadata {
            xattrs: std::collections::BTreeMap::from([
                (
                    "security.capability".to_string(),
                    b"\x01\x00\x00\x00".to_vec(),
                ),
                (
                    "system.posix_acl_access".to_string(),
                    b"\x02\x00\x00\x00".to_vec(),
                ),
                ("trusted.overlay".to_string(), b"overlay".to_vec()),
            ]),
            ..EntryMetadata::default()
        };

        let report = apply_entry_metadata_sync(&path, &meta).expect("apply metadata");
        assert!(
            report.applied.is_empty(),
            "privileged xattrs must not be applied"
        );
        assert_eq!(report.skipped.len(), 3);
        for (field, reason) in &report.skipped {
            assert_eq!(*field, "xattr");
            assert!(
                reason.contains("rejected outside permitted xattr namespace"),
                "unexpected skip reason: {reason}"
            );
        }
    }

    #[test]
    fn bare_regular_omits_optional_fields_in_json() {
        let m = EntryMetadata::default();
        let js = serde_json::to_string(&m).expect("ser");
        // Only file_kind survives; optionals are skipped.
        assert!(js.contains("file_kind"));
        assert!(!js.contains("unix_mode"));
        assert!(!js.contains("symlink_target"));
    }

    #[cfg(unix)]
    #[test]
    fn install_staged_regular_file_sync_checks_both_leaves() {
        let root = tempfile::tempdir().expect("temporary directory");
        let out = root.path().join("out.bin");

        let staged_link = root.path().join("staged-link.part");
        std::os::unix::fs::symlink("elsewhere", &staged_link).expect("staged symlink");
        let error = install_staged_regular_file_sync(&staged_link, &out)
            .expect_err("a staged symlink is not a regular file");
        assert!(
            error.to_string().contains("wrong filesystem kind"),
            "{error}"
        );
        assert!(
            std::fs::symlink_metadata(&out).is_err(),
            "nothing installed"
        );

        let staged = root.path().join("staged.part");
        std::fs::write(&staged, b"payload").expect("staged file");
        let out_dir = root.path().join("out-dir");
        std::fs::create_dir(&out_dir).expect("destination directory");
        let error = install_staged_regular_file_sync(&staged, &out_dir)
            .expect_err("a real directory is never replaced");
        assert!(error.to_string().contains("real directory"), "{error}");
        assert!(staged.exists(), "a refused install keeps the staged file");

        std::fs::write(&out, b"old").expect("existing destination");
        install_staged_regular_file_sync(&staged, &out).expect("replace the destination");
        assert_eq!(std::fs::read(&out).expect("installed file"), b"payload");
        assert!(!staged.exists(), "the staged file is renamed into place");
    }
