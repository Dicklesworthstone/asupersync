    use super::*;

    fn keep_set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| (*p).to_string()).collect()
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create directory symlink");
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_dir(target, link).expect("create directory symlink");
    }

    #[cfg(unix)]
    fn create_file_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create file symlink");
    }

    #[cfg(windows)]
    fn create_file_link(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_file(target, link).expect("create file symlink");
    }

    #[test]
    fn expand_keep_adds_all_ancestors() {
        let keep = expand_keep_set(&keep_set(&["a/b/c.txt", "a/d.txt"]));
        assert!(keep.contains("a"));
        assert!(keep.contains("a/b"));
        assert!(keep.contains("a/b/c.txt"));
        assert!(keep.contains("a/d.txt"));
        assert!(!keep.contains("a/b/c.txt/extra"));
    }

    #[test]
    fn expand_keep_ignores_empty_and_slashes() {
        let keep = expand_keep_set(&keep_set(&["", "/", "x//y/"]));
        assert!(keep.contains("x"));
        assert!(keep.contains("x/y"));
        assert_eq!(keep.len(), 2);
    }

    #[test]
    fn depth_counts_components() {
        assert_eq!(depth(""), 0);
        assert_eq!(depth("a"), 1);
        assert_eq!(depth("a/b/c"), 3);
        assert_eq!(depth("a//b"), 2);
    }

    #[test]
    fn mirror_entry_kind_labels() {
        assert_eq!(MirrorEntryKind::File.as_str(), "file");
        assert_eq!(MirrorEntryKind::Dir.as_str(), "dir");
        assert_eq!(MirrorEntryKind::Symlink.as_str(), "symlink");
    }

    #[test]
    fn default_policy_is_dry_run() {
        let p = MirrorPolicy::default();
        assert!(!p.enabled);
        assert!(p.max_delete_fraction > 0.0 && p.max_delete_fraction <= 1.0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_paths_require_a_strict_component_descendant() {
        let wide = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        let root = wide(r"\\?\C:\mirror\root");

        assert!(windows_final_path_is_strict_descendant(
            &root,
            &wide(r"\\?\C:\mirror\root\child.txt")
        ));
        assert!(windows_final_path_is_strict_descendant(
            &wide(r"\\?\C:\mirror\root\"),
            &wide(r"\\?\C:\mirror\root\nested\child.txt")
        ));
        assert!(!windows_final_path_is_strict_descendant(&root, &root));
        assert!(!windows_final_path_is_strict_descendant(
            &root,
            &wide(r"\\?\C:\mirror\root-sibling\child.txt")
        ));
        assert!(!windows_final_path_is_strict_descendant(
            &root,
            &wide(r"\\?\D:\mirror\root\child.txt")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_delete_checks_containment_and_filesystem_kind() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        let outside = temp.path().join("outside.txt");
        let stale_dir = dest.join("stale-dir");
        std::fs::create_dir_all(&stale_dir).expect("create stale directory");
        std::fs::write(&outside, b"outside").expect("write outside file");

        remove_mirror_entry_windows(&dest, &outside, MirrorEntryKind::File)
            .expect_err("outside handle must fail containment proof");
        assert_eq!(
            std::fs::read(&outside).expect("outside file remains"),
            b"outside"
        );

        remove_mirror_entry_windows(&dest, &stale_dir, MirrorEntryKind::File)
            .expect_err("wrong-kind directory handle must fail closed");
        assert!(stale_dir.is_dir());

        remove_mirror_entry_windows(&dest, &stale_dir, MirrorEntryKind::Dir)
            .expect("empty contained directory is deleted by handle");
        assert!(!stale_dir.exists());
    }

    #[test]
    fn destination_keep_matching_preserves_folding_spelling_but_deletes_real_alias() {
        let keep = keep_set(&["Docs/Readme.txt"]);
        let keep_aliases = BTreeMap::from([(
            portable_path_collision_key("Docs/Readme.txt"),
            vec!["Docs/Readme.txt".to_string()],
        )]);

        let folding_destination = keep_set(&["docs/README.TXT"]);
        assert!(destination_entry_is_kept(
            "docs/README.TXT",
            &keep,
            &keep_aliases,
            &folding_destination,
        ));

        let case_sensitive_destination = keep_set(&["Docs/Readme.txt", "docs/README.TXT"]);
        assert!(destination_entry_is_kept(
            "Docs/Readme.txt",
            &keep,
            &keep_aliases,
            &case_sensitive_destination,
        ));
        assert!(!destination_entry_is_kept(
            "docs/README.TXT",
            &keep,
            &keep_aliases,
            &case_sensitive_destination,
        ));
    }

    #[test]
    fn destination_keep_matching_uses_unicode_normalization_and_rejects_unrelated_paths() {
        let composed = "caf\u{e9}.txt";
        let decomposed = "cafe\u{301}.txt";
        let keep = keep_set(&[composed]);
        let keep_aliases = BTreeMap::from([(
            portable_path_collision_key(composed),
            vec![composed.to_string()],
        )]);
        let destination = keep_set(&[decomposed]);

        assert!(destination_entry_is_kept(
            decomposed,
            &keep,
            &keep_aliases,
            &destination,
        ));
        assert!(!destination_entry_is_kept(
            "unrelated.txt",
            &keep,
            &keep_aliases,
            &destination,
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn mirror_ancestor_recheck_rejects_reparse_before_delete() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&dest).expect("create destination");
        std::fs::create_dir_all(&outside).expect("create outside directory");
        let victim = outside.join("victim.txt");
        std::fs::write(&victim, b"outside").expect("write outside victim");
        let pivot = dest.join("pivot");
        create_directory_link(&outside, &pivot);

        let read_error =
            futures_lite::future::block_on(reject_mirror_reparse_ancestors(&dest, &pivot, true))
                .expect_err("reparse directory must be rejected before read_dir");
        assert!(matches!(read_error, MirrorError::ReparseAncestor(_)));

        let error = futures_lite::future::block_on(reject_mirror_reparse_ancestors(
            &dest,
            &pivot.join("victim.txt"),
            false,
        ))
        .expect_err("reparse ancestor must fail closed");
        assert!(matches!(error, MirrorError::ReparseAncestor(_)));
        assert_eq!(
            std::fs::read(&victim).expect("outside victim remains readable"),
            b"outside"
        );

        #[cfg(windows)]
        {
            let error = remove_mirror_entry_windows(
                &dest,
                &pivot.join("victim.txt"),
                MirrorEntryKind::File,
            )
            .expect_err("resolved outside handle must fail containment proof");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(
                std::fs::read(&victim).expect("outside victim survives handle guard"),
                b"outside"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn mirror_deletes_link_leaf_without_touching_outside_target() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        std::fs::create_dir_all(&dest).expect("create destination");
        let outside = temp.path().join("outside.txt");
        std::fs::write(&outside, b"outside").expect("write outside target");
        let link = dest.join("stale-link");
        create_file_link(&outside, &link);

        let report = futures_lite::future::block_on(mirror_dest(
            &cx,
            &dest,
            &BTreeSet::new(),
            MirrorPolicy {
                enabled: true,
                max_delete_fraction: 1.0,
            },
        ))
        .expect("mirror removes only link leaf");
        assert_eq!(report.deleted, 1);
        assert!(!link.exists());
        assert_eq!(
            std::fs::read(&outside).expect("outside target remains readable"),
            b"outside"
        );
    }

    #[cfg(windows)]
    #[test]
    fn mirror_deletes_readonly_name_without_mutating_external_hardlink() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        std::fs::create_dir_all(&dest).expect("create destination");
        let stale = dest.join("stale.txt");
        let external = temp.path().join("external.txt");
        std::fs::write(&stale, b"shared").expect("write stale file");
        std::fs::hard_link(&stale, &external).expect("create external hardlink");
        let mut permissions = std::fs::metadata(&stale)
            .expect("stale metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&stale, permissions).expect("make shared inode read-only");

        let report = futures_lite::future::block_on(mirror_dest(
            &cx,
            &dest,
            &BTreeSet::new(),
            MirrorPolicy {
                enabled: true,
                max_delete_fraction: 1.0,
            },
        ))
        .expect("mirror deletes read-only stale name");
        assert_eq!(report.deleted, 1);
        assert!(!stale.exists());
        assert_eq!(
            std::fs::read(&external).expect("external hardlink remains readable"),
            b"shared"
        );
        assert!(
            std::fs::metadata(&external)
                .expect("external hardlink metadata")
                .permissions()
                .readonly(),
            "mirror must not clear shared READONLY attributes"
        );

        let mut permissions = std::fs::metadata(&external)
            .expect("external cleanup metadata")
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&external, permissions)
            .expect("clear external read-only attribute for cleanup");
    }
