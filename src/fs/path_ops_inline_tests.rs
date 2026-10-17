    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::ffi::OsString;
    use std::fs;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> io::Result<Self> {
            let mut path = std::env::temp_dir();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            path.push(format!("asupersync_{prefix}_{nanos}"));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// The errno io_uring path operations are refused with while a test
    /// forces it (0: none). Process-wide, because the operations run on
    /// blocking threads. A refused operation still completes through the
    /// blocking syscall, so a concurrent test sees the same results.
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    static FORCED_URING_REFUSAL: std::sync::atomic::AtomicI32 =
        std::sync::atomic::AtomicI32::new(0);
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    static BLOCKING_FALLBACKS: AtomicU64 = AtomicU64::new(0);

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    pub(super) fn forced_uring_refusal() -> Option<i32> {
        match FORCED_URING_REFUSAL.load(Ordering::SeqCst) {
            0 => None,
            errno => Some(errno),
        }
    }

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    pub(super) fn note_blocking_fallback() {
        BLOCKING_FALLBACKS.fetch_add(1, Ordering::SeqCst);
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn path_to_cstring_accepts_non_utf8_unix_paths() {
        init_test("path_to_cstring_accepts_non_utf8_unix_paths");
        let raw = vec![b'f', b's', b'_', 0xFE];
        let path = PathBuf::from(OsString::from_vec(raw.clone()));

        let c = path_to_cstring(&path).expect("non-utf8 unix path should be accepted");
        crate::assert_with_log!(
            c.as_bytes() == raw.as_slice(),
            "raw bytes preserved",
            raw.as_slice(),
            c.as_bytes()
        );
        crate::test_complete!("path_to_cstring_accepts_non_utf8_unix_paths");
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn path_to_cstring_rejects_nul_bytes() {
        init_test("path_to_cstring_rejects_nul_bytes");
        let path = PathBuf::from(OsString::from_vec(vec![b'b', b'a', b'd', 0, b'x']));

        let err = path_to_cstring(&path).expect_err("path with nul must be rejected");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "invalid input error",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("path_to_cstring_rejects_nul_bytes");
    }

    #[test]
    fn metadata_basic() {
        init_test("metadata_basic");
        let dir = TempDir::new("meta").unwrap();
        let file_path = dir.path().join("test.txt");

        future::block_on(async {
            write(&file_path, b"hello").await.unwrap();
            let meta = metadata(&file_path).await.unwrap();
            let is_file = meta.is_file();
            crate::assert_with_log!(is_file, "is_file", true, is_file);
            let is_dir = meta.is_dir();
            crate::assert_with_log!(!is_dir, "is_dir false", false, is_dir);
            let len = meta.len();
            crate::assert_with_log!(len == 5, "len", 5, len);
        });
        crate::test_complete!("metadata_basic");
    }

    #[test]
    fn read_write_roundtrip() {
        init_test("read_write_roundtrip");
        let dir = TempDir::new("rw").unwrap();
        let file_path = dir.path().join("read_write.txt");

        future::block_on(async {
            write(&file_path, "hello world").await.unwrap();
            let contents = read_to_string(&file_path).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
            let bytes = read(&file_path).await.unwrap();
            crate::assert_with_log!(bytes == b"hello world", "bytes", b"hello world", bytes);
        });
        crate::test_complete!("read_write_roundtrip");
    }

    #[test]
    fn copy_rename_remove() {
        init_test("copy_rename_remove");
        let dir = TempDir::new("ops").unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        let renamed = dir.path().join("renamed.txt");

        future::block_on(async {
            write(&src, b"copy me").await.unwrap();
            let copied = copy(&src, &dst).await.unwrap();
            crate::assert_with_log!(copied == 7, "copied bytes", 7, copied);
            rename(&dst, &renamed).await.unwrap();
            let exists = dst.exists();
            crate::assert_with_log!(!exists, "dst removed", false, exists);
            let contents = read(&renamed).await.unwrap();
            crate::assert_with_log!(contents == b"copy me", "contents", b"copy me", contents);
            remove_file(&renamed).await.unwrap();
            let exists = renamed.exists();
            crate::assert_with_log!(!exists, "renamed removed", false, exists);
        });
        crate::test_complete!("copy_rename_remove");
    }

    #[test]
    fn hard_link_roundtrip() {
        init_test("hard_link_roundtrip");
        let dir = TempDir::new("hard_link").unwrap();
        let src = dir.path().join("source.txt");
        let link = dir.path().join("link.txt");

        future::block_on(async {
            write(&src, b"same-bytes").await.unwrap();
            hard_link(&src, &link).await.unwrap();

            let source = read(&src).await.unwrap();
            let linked = read(&link).await.unwrap();
            crate::assert_with_log!(
                linked == source,
                "linked bytes match source",
                source,
                linked
            );
        });
        crate::test_complete!("hard_link_roundtrip");
    }

    #[test]
    fn set_permissions_readonly_roundtrip() {
        init_test("set_permissions_readonly_roundtrip");
        let dir = TempDir::new("permissions").unwrap();
        let path = dir.path().join("file.txt");

        future::block_on(async {
            write(&path, b"content").await.unwrap();

            let mut perms = metadata(&path).await.unwrap().permissions();
            perms.set_readonly(true);
            set_permissions(&path, perms).await.unwrap();

            let readonly_after_set = metadata(&path).await.unwrap().permissions().readonly();
            crate::assert_with_log!(readonly_after_set, "readonly set", true, readonly_after_set);

            let mut perms = metadata(&path).await.unwrap().permissions();
            perms.set_readonly(false);
            set_permissions(&path, perms).await.unwrap();

            let readonly_after_clear = metadata(&path).await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly_after_clear,
                "readonly cleared",
                false,
                readonly_after_clear
            );
        });
        crate::test_complete!("set_permissions_readonly_roundtrip");
    }

    #[test]
    fn write_atomic_creates_and_replaces_without_temp_leaks() {
        init_test("write_atomic_creates_and_replaces_without_temp_leaks");
        let dir = TempDir::new("write_atomic").unwrap();
        let path = dir.path().join("target.txt");

        future::block_on(async {
            write_atomic(&path, b"v1").await.unwrap();
            let first = read(&path).await.unwrap();
            crate::assert_with_log!(first == b"v1", "initial write", b"v1", first);

            write_atomic(&path, b"v2").await.unwrap();
            let second = read(&path).await.unwrap();
            crate::assert_with_log!(second == b"v2", "replacement write", b"v2", second);

            let mut leaked_tmp = Vec::new();
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                if name.to_string_lossy().contains(".asupersync-tmp-") {
                    leaked_tmp.push(name.to_string_lossy().to_string());
                }
            }
            crate::assert_with_log!(
                leaked_tmp.is_empty(),
                "no leaked temporary files",
                "[]",
                format!("{leaked_tmp:?}")
            );
        });
        crate::test_complete!("write_atomic_creates_and_replaces_without_temp_leaks");
    }

    #[test]
    fn write_atomic_missing_parent_fails_cleanly() {
        init_test("write_atomic_missing_parent_fails_cleanly");
        let dir = TempDir::new("write_atomic_missing_parent").unwrap();
        let missing_parent = dir.path().join("missing");
        let target = missing_parent.join("target.txt");

        future::block_on(async {
            let err = write_atomic(&target, b"data")
                .await
                .expect_err("missing parent should fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::NotFound,
                "missing parent returns NotFound",
                io::ErrorKind::NotFound,
                err.kind()
            );
            let target_exists = target.exists();
            crate::assert_with_log!(
                !target_exists,
                "target should not be created on failure",
                false,
                target_exists
            );
        });
        crate::test_complete!("write_atomic_missing_parent_fails_cleanly");
    }

    #[test]
    fn write_atomic_preserves_preexisting_stale_temp_files() {
        init_test("write_atomic_preserves_preexisting_stale_temp_files");
        let dir = TempDir::new("write_atomic_stale_temp").unwrap();
        let path = dir.path().join("target.txt");
        let file_name = path.file_name().expect("target file name");
        let start = ATOMIC_WRITE_COUNTER.load(Ordering::Relaxed);

        for offset in 0..8 {
            let counter = start.saturating_add(offset);
            let stale = dir.path().join(format!(
                ".{}.asupersync-tmp-deadbeefdeadbeef-{counter}",
                file_name.to_string_lossy(),
            ));
            fs::write(stale, b"stale-temp").unwrap();
        }

        future::block_on(async {
            write_atomic(&path, b"fresh").await.unwrap();

            let bytes = read(&path).await.unwrap();
            crate::assert_with_log!(bytes == b"fresh", "fresh content written", b"fresh", bytes);

            let stale_count = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".asupersync-tmp-")
                })
                .count();
            crate::assert_with_log!(
                stale_count >= 8,
                "preexisting stale temp files preserved",
                ">= 8",
                stale_count
            );
        });
        crate::test_complete!("write_atomic_preserves_preexisting_stale_temp_files");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_preserves_existing_unix_permissions() {
        init_test("write_atomic_preserves_existing_unix_permissions");
        let dir = TempDir::new("write_atomic_permissions").unwrap();
        let path = dir.path().join("script.sh");

        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        future::block_on(async {
            write_atomic(&path, b"new").await.unwrap();

            let bytes = read(&path).await.unwrap();
            crate::assert_with_log!(bytes == b"new", "new content written", b"new", bytes);

            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            crate::assert_with_log!(mode == 0o700, "existing permissions preserved", 0o700, mode);
        });
        crate::test_complete!("write_atomic_preserves_existing_unix_permissions");
    }

    #[test]
    fn write_atomic_offloaded_creates_and_replaces_without_temp_leaks() {
        init_test("write_atomic_offloaded_creates_and_replaces_without_temp_leaks");
        let dir = TempDir::new("write_atomic_offloaded").unwrap();
        let path = dir.path().join("target.txt");

        future::block_on(async {
            write_atomic_offloaded(&path, b"offloaded_v1")
                .await
                .unwrap();
            let first = read(&path).await.unwrap();
            crate::assert_with_log!(
                first == b"offloaded_v1",
                "initial write",
                b"offloaded_v1",
                first
            );

            write_atomic_offloaded(&path, b"offloaded_v2")
                .await
                .unwrap();
            let second = read(&path).await.unwrap();
            crate::assert_with_log!(
                second == b"offloaded_v2",
                "replacement write",
                b"offloaded_v2",
                second
            );

            let mut leaked_tmp = Vec::new();
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                if name.to_string_lossy().contains(".asupersync-tmp-") {
                    leaked_tmp.push(name.to_string_lossy().to_string());
                }
            }
            crate::assert_with_log!(
                leaked_tmp.is_empty(),
                "no leaked temporary files",
                "[]",
                format!("{leaked_tmp:?}")
            );
        });
        crate::test_complete!("write_atomic_offloaded_creates_and_replaces_without_temp_leaks");
    }

    #[test]
    fn write_atomic_offloaded_missing_parent_fails_cleanly() {
        init_test("write_atomic_offloaded_missing_parent_fails_cleanly");
        let dir = TempDir::new("write_atomic_offloaded_missing_parent").unwrap();
        let missing_parent = dir.path().join("missing");
        let target = missing_parent.join("target.txt");

        future::block_on(async {
            let err = write_atomic_offloaded(&target, b"data")
                .await
                .expect_err("missing parent should fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::NotFound,
                "missing parent returns NotFound",
                io::ErrorKind::NotFound,
                err.kind()
            );
            let target_exists = target.exists();
            crate::assert_with_log!(
                !target_exists,
                "target should not be created on failure",
                false,
                target_exists
            );
        });
        crate::test_complete!("write_atomic_offloaded_missing_parent_fails_cleanly");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_slow_commit_probe_progresses_and_drops() {
        init_test("write_atomic_offloaded_slow_commit_probe_progresses_and_drops");
        let dir = TempDir::new("write_atomic_offloaded_probe").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Case 1: Drop staged write BEFORE commit begins -> leaves target unchanged
            let staged = stage_write_atomic(&path, b"staged_only").await.unwrap();
            drop(staged);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Case 2: While commit_async is parked in rename, another task on the single worker makes progress.
            // When the future is dropped after rename starts on the blocking pool,
            // the target is still replaced cleanly without temp file leaks.
            let probe = Arc::new(FilesystemOperationProbe::new());
            let staged2 = stage_write_atomic(&path, b"replaced_content")
                .await
                .unwrap();

            let mut commit_fut =
                Box::pin(staged2.commit_async_with_probe_for_test(Arc::clone(&probe)));

            // Poll once to launch the blocking task
            assert!(
                futures_lite::future::poll_once(commit_fut.as_mut())
                    .await
                    .is_none(),
                "commit_async must yield while waiting on the blocking task"
            );

            // Wait until the blocking task has started and is parked at the probe
            assert!(
                probe.wait_until_blocked(Duration::from_secs(5)),
                "blocking commit task must reach the probe gate"
            );

            // Verify another task on the SAME single worker can make progress while commit is parked
            let other_handle = runtime.spawn_local(async { 42 });
            assert_eq!(
                other_handle.await.unwrap(),
                42,
                "another task spawned on the worker must make progress"
            );

            // Target is still "original" before probe releases rename
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Drop the commit future while the blocking task is parked
            drop(commit_fut);

            // Now release the probe so the blocking task completes its rename and fsync
            probe.release();
            assert!(
                probe.wait_until_completed(Duration::from_secs(5)),
                "offloaded commit must finish"
            );

            // The target should now be replaced because the offloaded rename ran to completion
            assert_eq!(std::fs::read(&path).unwrap(), b"replaced_content");

            // Verify no leaked temporary files
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".asupersync-tmp-")
                })
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "no leaked temporary files: {leaked_tmp:?}"
            );
        });

        crate::test_complete!("write_atomic_offloaded_slow_commit_probe_progresses_and_drops");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_parks_on_pool_while_worker_progresses() {
        init_test("write_atomic_offloaded_parks_on_pool_while_worker_progresses");
        let dir = TempDir::new("write_atomic_offloaded_t_a").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Stage new content over original
            let staged = stage_write_atomic(&path, b"new").await.unwrap();

            // Occupy the only blocking pool thread with a parked probe
            let gate = Arc::new(FilesystemOperationProbe::new());
            let blocker_path = dir.path().join("blocker.txt");
            let mut blocker =
                Box::pin(write_with_probe_for_test(&blocker_path, b"x", Arc::clone(&gate)));
            assert!(
                futures_lite::future::poll_once(blocker.as_mut())
                    .await
                    .is_none(),
                "blocker must yield pending"
            );
            assert!(
                gate.wait_until_blocked(Duration::from_secs(5)),
                "blocker must reach gate"
            );

            // Now commit_async: must yield None (queued behind blocker on pool)
            let mut commit_fut = Box::pin(staged.commit_async());
            assert!(
                futures_lite::future::poll_once(commit_fut.as_mut())
                    .await
                    .is_none(),
                "commit_async must offload to pool and not run inline"
            );

            // Target remains original while queued on pool
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Release blocker and wait for both to finish
            gate.release();
            blocker.await.unwrap();
            commit_fut.await.unwrap();

            assert_eq!(std::fs::read(&path).unwrap(), b"new");
        });

        crate::test_complete!("write_atomic_offloaded_parks_on_pool_while_worker_progresses");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_drop_before_claim_preserves_target_and_cleans_temp() {
        init_test("write_atomic_offloaded_drop_before_claim_preserves_target_and_cleans_temp");
        let dir = TempDir::new("write_atomic_offloaded_t_b").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .unwrap();

        runtime.block_on(async {
            // 1. Stage before blocking pool is occupied
            let staged = stage_write_atomic(&path, b"new2").await.unwrap();

            // 2. Block the only pool worker
            let gate = Arc::new(FilesystemOperationProbe::new());
            let blocker_path = dir.path().join("blocker.txt");
            let mut blocker =
                Box::pin(write_with_probe_for_test(&blocker_path, b"x", Arc::clone(&gate)));
            assert!(
                futures_lite::future::poll_once(blocker.as_mut())
                    .await
                    .is_none()
            );
            assert!(gate.wait_until_blocked(Duration::from_secs(5)));

            // 3. Queue commit_async behind blocker
            let mut commit_fut = Box::pin(staged.commit_async());
            assert!(
                futures_lite::future::poll_once(commit_fut.as_mut())
                    .await
                    .is_none()
            );

            // Drop commit_fut before pool worker claims it
            drop(commit_fut);

            // 4. Release blocker
            gate.release();
            blocker.await.unwrap();

            // 5. Run one more pool job to ensure cancelled job is dequeued and discarded
            let read_bytes = crate::fs::read(&path).await.unwrap();
            assert_eq!(read_bytes, b"original");

            // 6. Target remains original and no temp files are leaked
            assert_eq!(std::fs::read(&path).unwrap(), b"original");
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".asupersync-tmp-"))
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "no leaked temp files: {leaked_tmp:?}"
            );
        });

        crate::test_complete!(
            "write_atomic_offloaded_drop_before_claim_preserves_target_and_cleans_temp"
        );
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_restricted_cx_capability_denied() {
        init_test("write_atomic_offloaded_restricted_cx_capability_denied");
        let dir = TempDir::new("write_atomic_offloaded_t_c").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Case 1: write_atomic_offloaded under restricted Cx
            let restricted_cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
            let res = restricted_cx
                .with_ambient(write_atomic_offloaded(&path, b"unauthorized"))
                .await;
            assert!(res.is_err());
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Case 2: Stage under full authority, commit_async under restricted authority
            let staged = stage_write_atomic(&path, b"staged_auth").await.unwrap();
            let res2 = restricted_cx.with_ambient(staged.commit_async()).await;
            assert!(res2.is_err());
            assert_eq!(res2.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Temp file must be cleaned up
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".asupersync-tmp-"))
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "temp file must be cleaned up on capability denial"
            );
        });

        crate::test_complete!("write_atomic_offloaded_restricted_cx_capability_denied");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_commit_phase_error_cleanup() {
        init_test("write_atomic_offloaded_commit_phase_error_cleanup");
        let dir = TempDir::new("write_atomic_offloaded_t_d").unwrap();
        let target_dir = dir.path().join("existing_dir");
        std::fs::create_dir(&target_dir).unwrap();
        std::fs::write(target_dir.join("file.txt"), b"keep me").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Staging succeeds; rename over non-empty directory fails in commit phase
            let staged = stage_write_atomic(&target_dir, b"cannot overwrite dir")
                .await
                .unwrap();
            let commit_res = staged.commit_async().await;
            assert!(commit_res.is_err(), "commit over directory must fail");
            assert!(target_dir.is_dir());
            assert!(target_dir.join("file.txt").exists());

            // Temp file must be cleaned up
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".asupersync-tmp-"))
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "temp file must be cleaned up on commit failure: {leaked_tmp:?}"
            );
        });

        crate::test_complete!("write_atomic_offloaded_commit_phase_error_cleanup");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_no_pool_executes_inline() {
        init_test("write_atomic_offloaded_no_pool_executes_inline");
        let dir = TempDir::new("write_atomic_offloaded_t_e").unwrap();
        let path = dir.path().join("target.txt");

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut fut = Box::pin(write_atomic_offloaded(&path, b"inline_val"));
            let poll_res = futures_lite::future::poll_once(fut.as_mut()).await;
            assert!(
                poll_res.is_some(),
                "without blocking pool, executes inline on first poll"
            );
            assert!(poll_res.unwrap().is_ok());
            assert_eq!(std::fs::read(&path).unwrap(), b"inline_val");
        });

        crate::test_complete!("write_atomic_offloaded_no_pool_executes_inline");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_with_probe_for_test_exercises_export() {
        init_test("write_atomic_offloaded_with_probe_for_test_exercises_export");
        let dir = TempDir::new("write_atomic_offloaded_t_f").unwrap();
        let path = dir.path().join("target.txt");
        let probe = Arc::new(FilesystemOperationProbe::new());

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        let probe_clone = Arc::clone(&probe);
        let path_clone = path.clone();
        let writer_thread = std::thread::spawn(move || {
            runtime.block_on(async move {
                write_atomic_offloaded_with_probe_for_test(
                    path_clone,
                    b"probed_val",
                    probe_clone,
                )
                .await
                .unwrap();
            });
        });

        assert!(probe.wait_until_blocked(Duration::from_secs(5)));
        probe.release();
        writer_thread.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"probed_val");

        crate::test_complete!("write_atomic_offloaded_with_probe_for_test_exercises_export");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_metadata_basic() {
        init_test("symlink_metadata_basic");
        let dir = TempDir::new("symlink").unwrap();
        let file_path = dir.path().join("file.txt");
        let link_path = dir.path().join("link");

        future::block_on(async {
            write(&file_path, b"content").await.unwrap();
            symlink(&file_path, &link_path).await.unwrap();

            let meta = metadata(&link_path).await.unwrap();
            let is_file = meta.is_file();
            crate::assert_with_log!(is_file, "is_file", true, is_file);
            let len = meta.len();
            crate::assert_with_log!(len == 7, "len", 7, len);

            let link_meta = symlink_metadata(&link_path).await.unwrap();
            let is_symlink = link_meta.file_type().is_symlink();
            crate::assert_with_log!(is_symlink, "is_symlink", true, is_symlink);
        });
        crate::test_complete!("symlink_metadata_basic");
    }

    /// br-asupersync-pxg07b M2: when io_uring itself is refused, every io_uring
    /// path operation still completes through the blocking syscall. The
    /// refusals are EPERM (a seccomp profile such as Docker's default, or
    /// `kernel.io_uring_disabled`), ENOSYS (gVisor), ENOMEM (locked memory),
    /// and EINVAL or EOPNOTSUPP (an opcode the kernel does not know).
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    #[test]
    fn io_uring_path_operations_fall_back_when_io_uring_is_refused() {
        struct Refusal;
        impl Drop for Refusal {
            fn drop(&mut self) {
                FORCED_URING_REFUSAL.store(0, Ordering::SeqCst);
            }
        }

        init_test("io_uring_path_operations_fall_back_when_io_uring_is_refused");
        let dir = TempDir::new("uring_refused").unwrap();
        for errno in [
            libc::EPERM,
            libc::ENOSYS,
            libc::ENOMEM,
            libc::EINVAL,
            libc::EOPNOTSUPP,
        ] {
            let _refusal = Refusal;
            FORCED_URING_REFUSAL.store(errno, Ordering::SeqCst);
            let fallbacks = BLOCKING_FALLBACKS.load(Ordering::SeqCst);
            let base = dir.path().join(format!("errno_{errno}"));
            let file = base.join("file");
            let renamed = base.join("renamed");
            let link = base.join("link");
            future::block_on(async {
                crate::fs::create_dir(&base).await.expect("create_dir");
                write(&file, b"x").await.unwrap();
                rename(&file, &renamed).await.expect("rename");
                symlink(&renamed, &link).await.expect("symlink");
                let target = fs::read_link(&link).unwrap();
                crate::assert_with_log!(target == renamed, "link target", renamed, target);
                remove_file(&link).await.expect("remove_file (link)");
                remove_file(&renamed).await.expect("remove_file");
                crate::fs::remove_dir(&base).await.expect("remove_dir");
            });
            let removed = !base.exists();
            crate::assert_with_log!(
                removed,
                format!("errno {errno}: directory removed"),
                true,
                removed
            );
            let taken = BLOCKING_FALLBACKS.load(Ordering::SeqCst) - fallbacks;
            crate::assert_with_log!(
                taken >= 6,
                format!("errno {errno}: all six operations took the blocking path"),
                ">= 6",
                taken
            );
        }
        crate::test_complete!("io_uring_path_operations_fall_back_when_io_uring_is_refused");
    }
