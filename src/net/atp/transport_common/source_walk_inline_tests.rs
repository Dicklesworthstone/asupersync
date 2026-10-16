    use super::*;
    use super::super::streaming::{collect_entries, collect_entries_with_policy};

    #[test]
    fn directory_batches_bound_inspections_and_preserve_every_child() {
        for count in [0, 1, 31, 32, 33, 64, 65, 97] {
            let root = tempfile::tempdir().unwrap();
            for i in (0..count).rev() {
                std::fs::write(root.path().join(format!("file-{i:03}")), b"x").unwrap();
            }
            let mut scan = DirectoryScan::open(root.path().to_path_buf(), true).unwrap();
            let mut batches = 0;
            while scan.inner.is_some() {
                let before = scan.children.len();
                scan = scan.advance().unwrap();
                assert!(scan.children.len() - before <= ENTRIES_PER_BATCH);
                batches += 1;
            }
            // A completely full batch requires another next() to observe EOF.
            assert_eq!(batches, count / ENTRIES_PER_BATCH + 1);
            let actual: Vec<_> = scan.children.iter().map(|c| c.name.clone()).collect();
            let expected: Vec<_> = (0..count).map(|i| format!("file-{i:03}")).collect();
            assert_eq!(actual, expected);
            assert!(scan.children.iter().all(|c| !c.is_dir));
        }
    }

    #[test]
    fn public_walk_preserves_sorted_files_and_only_empty_directory_leaves() {
        let root = tempfile::tempdir().unwrap();
        for dir in ["z-empty", "a/empty", "a/nested", "b"] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        for name in ["c", "b/x", "a/nested/y"] {
            std::fs::write(root.path().join(name), b"payload").unwrap();
        }
        let (_, is_dir, entries) =
            futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert!(is_dir);
        let actual: Vec<_> = entries.iter().map(|e| e.rel_path.as_str()).collect();
        assert_eq!(actual, ["a/empty", "a/nested/y", "b/x", "c", "z-empty"]);
        for entry in entries {
            assert_eq!(entry.abs_path, root.path().join(&entry.rel_path));
        }
    }

    #[test]
    fn public_walk_crosses_multiple_directory_batch_boundaries() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = Vec::new();
        for d in 0..35 {
            let dir = root.path().join(format!("dir-{d:02}"));
            std::fs::create_dir(&dir).unwrap();
            for f in 0..34 {
                let name = format!("file-{f:02}");
                std::fs::write(dir.join(&name), b"x").unwrap();
                expected.push(format!("dir-{d:02}/{name}"));
            }
        }
        let (_, _, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        let actual: Vec<_> = entries.into_iter().map(|e| e.rel_path).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_directory_error_keeps_its_source_path() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let error = futures_lite::future::block_on(read_children(&missing, true)).unwrap_err();
        assert!(error.message().starts_with(&format!("{}: ", missing.display())));
    }

    #[test]
    fn empty_root_and_single_file_keep_existing_shapes() {
        let root = tempfile::tempdir().unwrap();
        let (_, is_dir, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert!(is_dir);
        assert!(entries.is_empty());
        let path = root.path().join("one");
        std::fs::write(&path, b"payload").unwrap();
        let (name, is_dir, entries) = futures_lite::future::block_on(collect_entries(&path)).unwrap();
        assert_eq!(name, "one");
        assert!(!is_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rel_path, "one");
        assert_eq!(entries[0].abs_path, path);
    }

    #[test]
    fn denied_io_refuses_public_walk_and_directory_batches() {
        let root = tempfile::tempdir().unwrap();
        let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
        let error = futures_lite::future::block_on(cx.with_ambient(collect_entries(root.path())))
            .unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
        let error = futures_lite::future::block_on(cx.with_ambient(read_children(root.path(), true)))
            .unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
    }

    #[cfg(unix)]
    #[test]
    fn cycles_broken_links_and_outside_directory_links_are_leaves() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("not-transferred"), b"outside").unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("outside")).unwrap();
        std::os::unix::fs::symlink("missing", root.path().join("broken")).unwrap();
        let (_, _, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.rel_path.as_str()).collect();
        assert_eq!(names, ["broken", "cycle", "outside"]);
        let error = futures_lite::future::block_on(collect_entries_with_policy(
            root.path(), &MetadataPolicy::portable(),
        )).unwrap_err();
        assert!(error.message().contains("metadata policy"));
    }

    #[cfg(unix)]
    #[test]
    fn root_symlink_requires_io_even_when_preserved() {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        let (_, is_dir, entries) = futures_lite::future::block_on(collect_entries(&link)).unwrap();
        assert!(!is_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rel_path, "link");
        let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
        let error = futures_lite::future::block_on(cx.with_ambient(collect_entries(&link))).unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
    }

    #[cfg(unix)]
    #[test]
    fn discovered_directory_cannot_be_followed_as_a_symlink_at_open() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = root.path().join("directory");
        std::fs::create_dir(&path).unwrap();
        let children = futures_lite::future::block_on(read_children(root.path(), true)).unwrap();
        assert!(children[0].is_dir);
        std::fs::rename(&path, root.path().join("original-directory")).unwrap();
        std::os::unix::fs::symlink(outside.path(), &path).unwrap();
        let error = DirectoryScan::open(path, true).unwrap_err();
        assert!(error.message().contains("became a link or reparse point"));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_and_non_portable_child_names_fail_closed() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        for (name, message) in [
            (OsString::from_vec(vec![0xff]), "not valid Unicode"),
            (OsString::from("bad:name"), "not portable"),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join(name), b"x").unwrap();
            let error = futures_lite::future::block_on(collect_entries(root.path())).unwrap_err();
            assert!(error.message().contains(message), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn deep_tree_and_special_leaves_do_not_require_recursive_futures_or_content_opens() {
        let root = tempfile::tempdir().unwrap();
        let mut path = root.path().to_path_buf();
        for _ in 0..128 {
            path.push("d");
            std::fs::create_dir(&path).unwrap();
        }
        let socket = root.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let (_, _, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].abs_path, path);
        assert_eq!(entries[1].abs_path, socket);
    }
