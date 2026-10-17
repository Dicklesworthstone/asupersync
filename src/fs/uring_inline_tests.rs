    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    use std::os::fd::IntoRawFd;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn assert_polled_after_completion(err: &io::Error, operation: &str) {
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(
            err.to_string(),
            format!("io_uring {operation} future polled after completion")
        );
    }

    fn assert_poll_fails_closed<T: std::fmt::Debug>(poll: Poll<io::Result<T>>, operation: &str) {
        assert!(
            matches!(&poll, Poll::Ready(Err(_))),
            "expected fail-closed {operation} repoll, got {poll:?}"
        );
        if let Poll::Ready(Err(err)) = poll {
            assert_polled_after_completion(&err, operation);
        }
    }

    #[test]
    fn test_submitted_completion_wait_retries_syscall_errors() {
        init_test("test_submitted_completion_wait_retries_syscall_errors");
        let mut attempts = 0;

        let result = wait_until_submitted_completion(|| {
            attempts += 1;
            match attempts {
                1 => (Err(io::Error::from(io::ErrorKind::Interrupted)), None),
                2 => (Err(io::Error::from(io::ErrorKind::WouldBlock)), None),
                3 => (Err(io::Error::from_raw_os_error(libc::EIO)), None),
                4 => (Ok(1), Some(23)),
                _ => panic!("completion driver retried after terminal CQE"),
            }
        });

        crate::assert_with_log!(result == 23, "terminal CQE result", 23, result);
        crate::assert_with_log!(attempts == 4, "wait attempts", 4, attempts);
        crate::test_complete!("test_submitted_completion_wait_retries_syscall_errors");
    }

    #[test]
    fn test_submitted_completion_is_observed_alongside_wait_error() {
        init_test("test_submitted_completion_is_observed_alongside_wait_error");
        let mut attempts = 0;

        let result = wait_until_submitted_completion(|| {
            attempts += 1;
            (
                Err(io::Error::from(io::ErrorKind::Interrupted)),
                Some(-libc::ECANCELED),
            )
        });

        crate::assert_with_log!(
            result == -libc::ECANCELED,
            "negative matching CQE is terminal",
            -libc::ECANCELED,
            result
        );
        crate::assert_with_log!(attempts == 1, "wait attempts", 1, attempts);
        crate::test_complete!("test_submitted_completion_is_observed_alongside_wait_error");
    }

    #[test]
    fn test_submitted_completion_tracked_drain_survives_unrelated_cqe() {
        init_test("test_submitted_completion_tracked_drain_survives_unrelated_cqe");
        let target = OpKind::Read.encode(41);
        let state = Mutex::new(OpState::Pending {
            user_data: target,
            waker: None,
        });
        let mut script = std::collections::VecDeque::from([
            (Err(io::Error::from_raw_os_error(libc::EIO)), Vec::new()),
            (
                Err(io::Error::from(io::ErrorKind::Interrupted)),
                vec![(UNKNOWN_CQE_USER_DATA, 0)],
            ),
            (
                Err(io::Error::from(io::ErrorKind::Interrupted)),
                vec![(target, -libc::ECANCELED)],
            ),
        ]);
        let mut wait_cycles = 0;
        let mut completion_batches = 0;

        drain_tracked_until_quiescent(
            || state_pending_user_data(&state).is_some(),
            || {
                completion_batches += 1;
                wait_until_submitted_completion(|| {
                    wait_cycles += 1;
                    let (wait_result, completions) = script
                        .pop_front()
                        .expect("tracked drain requested an unexpected wait cycle");
                    let completion = (!completions.is_empty()).then_some(completions);
                    (wait_result, completion)
                })
            },
            |user_data, result| {
                let _ = mark_op_complete(&state, user_data, result);
            },
        );

        let terminal_result = match &*state.lock() {
            OpState::Complete(result) => *result,
            state => panic!("tracked state did not reach completion: {state:?}"),
        };
        crate::assert_with_log!(wait_cycles == 3, "wait cycles", 3, wait_cycles);
        crate::assert_with_log!(
            completion_batches == 2,
            "completion batches",
            2,
            completion_batches
        );
        crate::assert_with_log!(
            terminal_result == -libc::ECANCELED,
            "matching cancellation CQE",
            -libc::ECANCELED,
            terminal_result
        );
        crate::test_complete!("test_submitted_completion_tracked_drain_survives_unrelated_cqe");
    }

    #[cfg(unix)]
    #[test]
    fn test_path_to_cstring_accepts_non_utf8_unix_paths() {
        init_test("test_path_to_cstring_accepts_non_utf8_unix_paths");
        let raw = vec![b'f', b'i', b'l', b'e', b'_', 0xFD];
        let path = std::path::PathBuf::from(OsString::from_vec(raw.clone()));

        let c = path_to_cstring(&path).expect("non-utf8 unix path should be accepted");
        crate::assert_with_log!(
            c.as_bytes() == raw.as_slice(),
            "raw bytes preserved",
            raw.as_slice(),
            c.as_bytes()
        );
        crate::test_complete!("test_path_to_cstring_accepts_non_utf8_unix_paths");
    }

    #[cfg(unix)]
    #[test]
    fn test_path_to_cstring_rejects_nul_bytes() {
        init_test("test_path_to_cstring_rejects_nul_bytes");
        let path = std::path::PathBuf::from(OsString::from_vec(vec![b'b', b'a', b'd', 0, b'x']));

        let err = path_to_cstring(&path).expect_err("path with nul must be rejected");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "invalid input error",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_path_to_cstring_rejects_nul_bytes");
    }

    #[test]
    fn test_uring_file_create_write_read() {
        init_test("test_uring_file_create_write_read");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_test.txt");

            // Create and write
            let file = IoUringFile::create(&path).unwrap();
            let n = file.write(b"hello io_uring").await.unwrap();
            crate::assert_with_log!(n == 14, "bytes written", 14usize, n);
            file.sync_all().await.unwrap();
            drop(file);

            // Read back
            let file = IoUringFile::open(&path).unwrap();
            let mut buf = vec![0u8; 32];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 14, "bytes read", 14usize, n);
            crate::assert_with_log!(
                &buf[..n] == b"hello io_uring",
                "content",
                "hello io_uring",
                String::from_utf8_lossy(&buf[..n])
            );
        });
        crate::test_complete!("test_uring_file_create_write_read");
    }

    #[test]
    fn test_uring_file_drop_drains_pending_read() {
        init_test("test_uring_file_drop_drains_pending_read");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_drop_pending_read.txt");
        std::fs::write(&path, b"hello").unwrap();

        let file = IoUringFile::open(&path).unwrap();

        // Submit a read without waiting for it in user code, then rely on Drop to
        // drain the CQE before tearing down the ring mapping.
        let pending = file.submit_pending_read_for_test(5, 0).unwrap();
        let buf = pending.finish_buffer();

        let read_completed = buf == b"hello";
        let read_cancelled = buf.iter().all(|byte| *byte == 0);
        crate::assert_with_log!(
            read_completed || read_cancelled,
            "drop drained read to completion or cancellation",
            "completed_or_cancelled",
            String::from_utf8_lossy(&buf)
        );
        let file_contents = std::fs::read(&path).unwrap();
        crate::assert_with_log!(
            file_contents == b"hello",
            "drop drained read leaves source file intact",
            "hello",
            String::from_utf8_lossy(&file_contents)
        );
        crate::test_complete!("test_uring_file_drop_drains_pending_read");
    }

    #[test]
    fn test_uring_file_drop_drains_pending_write() {
        init_test("test_uring_file_drop_drains_pending_write");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_drop_pending_write.txt");

        let file = IoUringFile::open_with_flags(
            &path,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
        .unwrap();
        let payload = b"drop-drained-write";

        let pending = file
            .submit_pending_write_for_test(payload.to_vec(), 0)
            .unwrap();
        pending.drain();

        let contents = std::fs::read(&path).unwrap();
        let write_completed = contents.as_slice() == payload;
        let write_cancelled = contents.is_empty();
        crate::assert_with_log!(
            write_completed || write_cancelled,
            "drop drained write to completion or cancellation",
            "completed_or_cancelled",
            String::from_utf8_lossy(&contents)
        );
        crate::test_complete!("test_uring_file_drop_drains_pending_write");
    }

    #[test]
    fn test_uring_file_drop_drains_pending_sync() {
        init_test("test_uring_file_drop_drains_pending_sync");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_drop_pending_sync.txt");
        std::fs::write(&path, b"sync-before-drop").unwrap();

        let file = IoUringFile::open_with_flags(&path, libc::O_RDWR, 0).unwrap();

        let pending = file.submit_pending_sync_for_test(false).unwrap();
        pending.drain();

        let contents = std::fs::read(&path).unwrap();
        crate::assert_with_log!(
            contents.as_slice() == b"sync-before-drop",
            "drop drained sync without corrupting file",
            "sync-before-drop",
            String::from_utf8_lossy(&contents)
        );
        crate::test_complete!("test_uring_file_drop_drains_pending_sync");
    }

    #[test]
    fn test_uring_file_read_at_write_at() {
        init_test("test_uring_file_read_at_write_at");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_offset_test.txt");

            // Create file with content
            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Write at offset 0
            let n = file.write_at(b"AAAAAAAAAA", 0).await.unwrap();
            crate::assert_with_log!(n == 10, "first write", 10usize, n);

            // Write at offset 5 (overwrite middle)
            let n = file.write_at(b"BBBBB", 5).await.unwrap();
            crate::assert_with_log!(n == 5, "second write", 5usize, n);

            file.sync_all().await.unwrap();

            // Read at offset 0
            let mut buf = vec![0u8; 10];
            let n = file.read_at(&mut buf, 0).await.unwrap();
            crate::assert_with_log!(n == 10, "read back", 10usize, n);
            crate::assert_with_log!(
                &buf[..n] == b"AAAAABBBBB",
                "content",
                "AAAAABBBBB",
                String::from_utf8_lossy(&buf[..n])
            );
        });
        crate::test_complete!("test_uring_file_read_at_write_at");
    }

    #[test]
    fn test_uring_completion_attribution_ignores_unrelated_cqe() {
        init_test("test_uring_completion_attribution_ignores_unrelated_cqe");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_unrelated_cqe.txt");
            std::fs::write(&path, b"hello").unwrap();

            let file = IoUringFile::open(&path).unwrap();

            file.submit_unknown_nop_for_test(UNKNOWN_CQE_USER_DATA)
                .unwrap();

            let mut buf = [0u8; 5];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 5, "read length", 5usize, n);
            crate::assert_with_log!(
                &buf == b"hello",
                "read ignores unrelated CQE and returns actual data",
                "hello",
                String::from_utf8_lossy(&buf)
            );
        });
        crate::test_complete!("test_uring_completion_attribution_ignores_unrelated_cqe");
    }

    #[test]
    fn test_uring_completion_attribution_ignores_unrelated_cqe_before_write() {
        init_test("test_uring_completion_attribution_ignores_unrelated_cqe_before_write");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_unrelated_cqe_write.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            file.submit_unknown_nop_for_test(UNKNOWN_CQE_USER_DATA)
                .unwrap();

            let n = file.write(b"hello").await.unwrap();
            crate::assert_with_log!(n == 5, "write length", 5usize, n);
            file.sync_all().await.unwrap();
            drop(file);

            let contents = std::fs::read(&path).unwrap();
            crate::assert_with_log!(
                contents.as_slice() == b"hello",
                "write ignores unrelated CQE and persists actual data",
                "hello",
                String::from_utf8_lossy(&contents)
            );
        });
        crate::test_complete!(
            "test_uring_completion_attribution_ignores_unrelated_cqe_before_write"
        );
    }

    #[test]
    fn test_uring_completion_attribution_ignores_unrelated_cqe_before_sync() {
        init_test("test_uring_completion_attribution_ignores_unrelated_cqe_before_sync");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_unrelated_cqe_sync.txt");
            std::fs::write(&path, b"hello").unwrap();

            let file = IoUringFile::open_with_flags(&path, libc::O_RDWR, 0).unwrap();

            file.submit_unknown_nop_for_test(UNKNOWN_CQE_USER_DATA)
                .unwrap();

            file.sync_all().await.unwrap();
            drop(file);

            let contents = std::fs::read(&path).unwrap();
            crate::assert_with_log!(
                contents.as_slice() == b"hello",
                "sync ignores unrelated CQE and preserves actual data",
                "hello",
                String::from_utf8_lossy(&contents)
            );
        });
        crate::test_complete!(
            "test_uring_completion_attribution_ignores_unrelated_cqe_before_sync"
        );
    }

    #[test]
    fn test_uring_set_len_has_no_async_truncate_completion() {
        init_test("test_uring_set_len_has_no_async_truncate_completion");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_truncate_no_pending.txt");
        std::fs::write(&path, b"truncate-boundary").unwrap();

        let file = IoUringFile::open_with_flags(&path, libc::O_RDWR, 0).unwrap();
        file.set_len(8).unwrap();

        crate::assert_with_log!(
            !any_ops_pending(&file.inner),
            "set_len uses synchronous ftruncate and leaves no io_uring state",
            false,
            any_ops_pending(&file.inner)
        );
        crate::assert_with_log!(
            file.metadata().unwrap().len() == 8,
            "truncated len",
            8u64,
            file.metadata().unwrap().len()
        );
        crate::test_complete!("test_uring_set_len_has_no_async_truncate_completion");
    }

    #[test]
    fn test_uring_sq_full_recovers_by_submitting_and_retrying() {
        init_test("test_uring_sq_full_recovers_by_submitting_and_retrying");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_sq_full_retry.txt");
            std::fs::write(&path, b"hello").unwrap();

            let file = IoUringFile::open(&path).unwrap();

            {
                let mut ring = file.inner.ring.lock();
                let mut next_user_data = 1u64;
                loop {
                    let entry = opcode::Nop::new()
                        .build()
                        .user_data(0xFF00_0000_AA00_0000u64.wrapping_add(next_user_data));
                    // SAFETY: NOP has no external buffer dependencies.
                    let push_result = unsafe { ring.submission().push(&entry) };
                    if push_result.is_err() {
                        break;
                    }
                    next_user_data = next_user_data.saturating_add(1);
                }
            }

            let mut buf = [0u8; 5];
            let n = file.read(&mut buf).await.unwrap();
            assert_eq!(n, 5, "read length after SQ recovery");
            assert_eq!(&buf, b"hello", "read succeeds after SQ-full recovery");
        });
        crate::test_complete!("test_uring_sq_full_recovers_by_submitting_and_retrying");
    }

    #[test]
    fn test_uring_file_position_tracking() {
        init_test("test_uring_file_position_tracking");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_position_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Initial position should be 0
            crate::assert_with_log!(
                file.position() == 0,
                "initial position",
                0u64,
                file.position()
            );

            // Write updates position
            let n = file.write(b"hello").await.unwrap();
            crate::assert_with_log!(n == 5, "write", 5usize, n);
            crate::assert_with_log!(
                file.position() == 5,
                "position after write",
                5u64,
                file.position()
            );

            // write_at does NOT update position
            let n = file.write_at(b"world", 10).await.unwrap();
            crate::assert_with_log!(n == 5, "write_at", 5usize, n);
            crate::assert_with_log!(
                file.position() == 5,
                "position after write_at",
                5u64,
                file.position()
            );

            // Seek updates position
            let pos = file.seek(SeekFrom::Start(0)).unwrap();
            crate::assert_with_log!(pos == 0, "seek result", 0u64, pos);
            crate::assert_with_log!(
                file.position() == 0,
                "position after seek",
                0u64,
                file.position()
            );
        });
        crate::test_complete!("test_uring_file_position_tracking");
    }

    #[test]
    fn test_uring_seek_current_uses_logical_position() {
        init_test("test_uring_seek_current_uses_logical_position");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_seek_current_position.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            let n = file.write(b"abcdef").await.unwrap();
            crate::assert_with_log!(n == 6, "write length", 6usize, n);

            let current = file.seek(SeekFrom::Current(0)).unwrap();
            crate::assert_with_log!(current == 6, "current seek result", 6u64, current);
            crate::assert_with_log!(
                file.position() == 6,
                "position after current seek",
                6u64,
                file.position()
            );

            let current = file.seek(SeekFrom::Current(-2)).unwrap();
            crate::assert_with_log!(current == 4, "rewound seek result", 4u64, current);
            crate::assert_with_log!(
                file.position() == 4,
                "position after rewind",
                4u64,
                file.position()
            );

            let mut tail = [0u8; 2];
            let n = file.read(&mut tail).await.unwrap();
            crate::assert_with_log!(n == 2, "tail read length", 2usize, n);
            crate::assert_with_log!(
                &tail == b"ef",
                "tail read bytes",
                "ef",
                String::from_utf8_lossy(&tail)
            );
        });
        crate::test_complete!("test_uring_seek_current_uses_logical_position");
    }

    #[test]
    fn test_uring_from_raw_fd_preserves_existing_cursor_position() {
        init_test("test_uring_from_raw_fd_preserves_existing_cursor_position");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_from_raw_fd_cursor.txt");

            std::fs::write(&path, b"abcdef").unwrap();
            let mut std_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            std::io::Seek::seek(&mut std_file, SeekFrom::Start(2)).unwrap();

            let raw_fd = std_file.into_raw_fd();
            let file = unsafe { IoUringFile::from_raw_fd(raw_fd) }.unwrap();

            crate::assert_with_log!(
                file.position() == 2,
                "initial logical cursor preserves raw fd offset",
                2u64,
                file.position()
            );
            let current = file.seek(SeekFrom::Current(0)).unwrap();
            crate::assert_with_log!(current == 2, "seek current", 2u64, current);

            let mut buf = [0u8; 2];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 2, "read length", 2usize, n);
            crate::assert_with_log!(
                &buf == b"cd",
                "read starts from transferred cursor",
                "cd",
                String::from_utf8_lossy(&buf)
            );
            crate::assert_with_log!(
                file.position() == 4,
                "position after read from transferred cursor",
                4u64,
                file.position()
            );
        });
        crate::test_complete!("test_uring_from_raw_fd_preserves_existing_cursor_position");
    }

    #[test]
    fn test_uring_from_raw_fd_closes_fd_when_position_probe_fails() {
        init_test("test_uring_from_raw_fd_closes_fd_when_position_probe_fails");

        let mut fds = [0; 2];
        let pipe_result = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe creation should succeed");

        let read_fd = fds[0];
        let write_fd = fds[1];

        let err = unsafe { IoUringFile::from_raw_fd(read_fd) }
            .expect_err("non-seekable fds must fail position probe");
        crate::assert_with_log!(
            err.raw_os_error() == Some(libc::ESPIPE),
            "pipe fd fails with ESPIPE",
            Some(libc::ESPIPE),
            err.raw_os_error()
        );

        // The failed constructor owned `read_fd` and closed it. Probe the pipe, not the
        // number: closing `read_fd` again here can close an fd a concurrent test was just
        // handed (it did on 2026-09-29, and the lib test binary died with SIGBUS right
        // after). With no reader left, a write fails with EPIPE; Rust ignores SIGPIPE.
        let write_result = unsafe { libc::write(write_fd, [0u8].as_ptr().cast(), 1) };
        let write_errno = io::Error::last_os_error().raw_os_error();
        crate::assert_with_log!(
            write_result == -1,
            "failed construction must still consume and close the transferred fd",
            -1,
            write_result
        );
        crate::assert_with_log!(
            write_errno == Some(libc::EPIPE),
            "the pipe has no reader left",
            Some(libc::EPIPE),
            write_errno
        );

        let write_close_result = unsafe { libc::close(write_fd) };
        crate::assert_with_log!(
            write_close_result == 0,
            "write end remains open for explicit cleanup",
            0,
            write_close_result
        );

        crate::test_complete!("test_uring_from_raw_fd_closes_fd_when_position_probe_fails");
    }

    #[test]
    fn test_uring_write_uses_position_at_poll_time() {
        init_test("test_uring_write_uses_position_at_poll_time");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_lazy_write_position.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            let first = file.write(b"abc");
            let second = file.write(b"def");

            let n = first.await.unwrap();
            crate::assert_with_log!(n == 3, "first write length", 3usize, n);
            crate::assert_with_log!(
                file.position() == 3,
                "position after first write",
                3u64,
                file.position()
            );

            let n = second.await.unwrap();
            crate::assert_with_log!(n == 3, "second write length", 3usize, n);
            crate::assert_with_log!(
                file.position() == 6,
                "position after second write",
                6u64,
                file.position()
            );

            file.sync_all().await.unwrap();

            let mut buf = [0u8; 6];
            let n = file.read_at(&mut buf, 0).await.unwrap();
            crate::assert_with_log!(n == 6, "read back length", 6usize, n);
            crate::assert_with_log!(
                &buf == b"abcdef",
                "write futures append in poll order",
                "abcdef",
                String::from_utf8_lossy(&buf)
            );
        });
        crate::test_complete!("test_uring_write_uses_position_at_poll_time");
    }

    #[test]
    fn test_uring_read_uses_position_at_poll_time() {
        init_test("test_uring_read_uses_position_at_poll_time");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_lazy_read_position.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();
            file.write_at(b"abcdef", 0).await.unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            let mut first_buf = [0u8; 3];
            let mut second_buf = [0u8; 3];
            let first = file.read(&mut first_buf);
            let second = file.read(&mut second_buf);

            let n = first.await.unwrap();
            crate::assert_with_log!(n == 3, "first read length", 3usize, n);
            crate::assert_with_log!(
                &first_buf == b"abc",
                "first read bytes",
                "abc",
                String::from_utf8_lossy(&first_buf)
            );
            crate::assert_with_log!(
                file.position() == 3,
                "position after first read",
                3u64,
                file.position()
            );

            let n = second.await.unwrap();
            crate::assert_with_log!(n == 3, "second read length", 3usize, n);
            crate::assert_with_log!(
                &second_buf == b"def",
                "second read bytes",
                "def",
                String::from_utf8_lossy(&second_buf)
            );
            crate::assert_with_log!(
                file.position() == 6,
                "position after second read",
                6u64,
                file.position()
            );
        });
        crate::test_complete!("test_uring_read_uses_position_at_poll_time");
    }

    #[test]
    fn test_uring_file_sync_data() {
        init_test("test_uring_file_sync_data");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_sync_test.txt");

            let file = IoUringFile::create(&path).unwrap();
            file.write(b"sync test data").await.unwrap();

            // sync_data should succeed
            file.sync_data().await.unwrap();

            // sync_all should succeed
            file.sync_all().await.unwrap();
        });
        crate::test_complete!("test_uring_file_sync_data");
    }

    #[test]
    fn test_uring_read_future_second_poll_fails_closed() {
        init_test("test_uring_read_future_second_poll_fails_closed");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_read_repoll.txt");
        std::fs::write(&path, b"hello").unwrap();

        let file = IoUringFile::open(&path).unwrap();
        let mut buf = [0u8; 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        {
            let mut future = file.read(&mut buf);
            let first = Pin::new(&mut future).poll(&mut cx);
            assert!(matches!(first, Poll::Ready(Ok(5))));
            assert_eq!(file.position(), 5);

            assert_poll_fails_closed(Pin::new(&mut future).poll(&mut cx), "read");
        }
        assert_eq!(&buf, b"hello");
        assert_eq!(file.position(), 5);
        crate::test_complete!("test_uring_read_future_second_poll_fails_closed");
    }

    #[test]
    fn test_uring_write_future_second_poll_fails_closed() {
        init_test("test_uring_write_future_second_poll_fails_closed");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_write_repoll.txt");

        let file = IoUringFile::open_with_flags(
            &path,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
        .unwrap();
        let mut future = file.write(b"abc");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(3))));
        assert_eq!(file.position(), 3);

        assert_poll_fails_closed(Pin::new(&mut future).poll(&mut cx), "write");
        assert_eq!(file.position(), 3);

        let mut buf = [0u8; 3];
        let n = futures_lite::future::block_on(file.read_at(&mut buf, 0)).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"abc");
        crate::test_complete!("test_uring_write_future_second_poll_fails_closed");
    }

    #[test]
    fn test_uring_sync_future_second_poll_fails_closed() {
        init_test("test_uring_sync_future_second_poll_fails_closed");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_sync_repoll.txt");

        let file = IoUringFile::create(&path).unwrap();
        let mut future = file.sync_all();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(()))));

        assert_poll_fails_closed(Pin::new(&mut future).poll(&mut cx), "sync");
        crate::test_complete!("test_uring_sync_future_second_poll_fails_closed");
    }

    #[test]
    fn test_uring_error_terminal_still_fails_closed_on_repoll() {
        init_test("test_uring_error_terminal_still_fails_closed_on_repoll");
        let dir = tempdir().unwrap();
        let path = dir.path().join("uring_error_repoll.txt");
        std::fs::write(&path, b"hello").unwrap();

        let file = IoUringFile::open(&path).unwrap();
        let mut future = file.write(b"abc");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(_))));
        assert_eq!(file.position(), 0);

        assert_poll_fails_closed(Pin::new(&mut future).poll(&mut cx), "write");
        assert_eq!(file.position(), 0);
        crate::test_complete!("test_uring_error_terminal_still_fails_closed_on_repoll");
    }

    #[test]
    fn test_uring_file_set_len_truncate() {
        init_test("test_uring_file_set_len_truncate");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_truncate_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Write 20 bytes
            file.write(b"01234567890123456789").await.unwrap();
            file.sync_all().await.unwrap();

            // Truncate to 10
            file.set_len(10).unwrap();

            // Position should be clamped from 19 to 10
            crate::assert_with_log!(
                file.position() <= 10,
                "position clamped after truncate",
                true,
                file.position() <= 10
            );

            // Read back and verify
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = vec![0u8; 32];
            let n = file.read(&mut buf).await.unwrap();
            crate::assert_with_log!(n == 10, "truncated read length", 10usize, n);
            crate::assert_with_log!(
                &buf[..n] == b"0123456789",
                "truncated content",
                "0123456789",
                String::from_utf8_lossy(&buf[..n])
            );
        });
        crate::test_complete!("test_uring_file_set_len_truncate");
    }

    #[test]
    fn test_uring_file_set_len_extend() {
        init_test("test_uring_file_set_len_extend");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_extend_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            file.write(b"hello").await.unwrap();
            file.sync_all().await.unwrap();

            // Extend to 10 bytes (zero-filled beyond 5)
            file.set_len(10).unwrap();

            let meta = file.metadata().unwrap();
            crate::assert_with_log!(meta.len() == 10, "extended length", 10u64, meta.len());

            // Read the extended region
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = vec![0u8; 10];
            let n = file.read_at(&mut buf, 0).await.unwrap();
            crate::assert_with_log!(n == 10, "read length", 10usize, n);
            crate::assert_with_log!(
                &buf[..5] == b"hello",
                "original content preserved",
                "hello",
                String::from_utf8_lossy(&buf[..5])
            );
            crate::assert_with_log!(
                buf[5..] == [0u8; 5],
                "extended bytes are zero",
                true,
                buf[5..] == [0u8; 5]
            );
        });
        crate::test_complete!("test_uring_file_set_len_extend");
    }

    #[test]
    fn test_uring_file_metadata() {
        init_test("test_uring_file_metadata");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_metadata_test.txt");

            let file = IoUringFile::create(&path).unwrap();
            file.write(b"metadata test").await.unwrap();
            file.sync_all().await.unwrap();

            let meta = file.metadata().unwrap();
            crate::assert_with_log!(meta.is_file(), "is_file", true, meta.is_file());
            crate::assert_with_log!(meta.len() == 13, "file length", 13u64, meta.len());
        });
        crate::test_complete!("test_uring_file_metadata");
    }

    #[test]
    fn test_uring_file_metadata_permissions_roundtrip_uses_fs_wrapper() {
        init_test("test_uring_file_metadata_permissions_roundtrip_uses_fs_wrapper");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_metadata_permissions_roundtrip.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            let mut permissions = file.metadata().unwrap().permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions).unwrap();
            let readonly = file.metadata().unwrap().permissions().readonly();
            crate::assert_with_log!(
                readonly,
                "io_uring file permissions set readonly through fs wrapper",
                true,
                readonly
            );

            let mut permissions = file.metadata().unwrap().permissions();
            permissions.set_readonly(false);
            file.set_permissions(permissions).unwrap();
            let readonly = file.metadata().unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly,
                "io_uring file permissions reset through fs wrapper",
                false,
                readonly
            );
        });
        crate::test_complete!("test_uring_file_metadata_permissions_roundtrip_uses_fs_wrapper");
    }

    #[test]
    fn test_uring_file_large_io() {
        init_test("test_uring_file_large_io");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("uring_large_test.txt");

            let file = IoUringFile::open_with_flags(
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
            .unwrap();

            // Write 64KB of data in 4KB chunks
            let data: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
            let mut written = 0usize;
            while written < data.len() {
                let end = std::cmp::min(written + 4096, data.len());
                let n = file
                    .write_at(&data[written..end], written as u64)
                    .await
                    .unwrap();
                written += n;
            }
            file.sync_all().await.unwrap();

            // Read back in one shot and verify
            let mut buf = vec![0u8; 65536];
            let mut read_total = 0usize;
            while read_total < buf.len() {
                let n = file
                    .read_at(&mut buf[read_total..], read_total as u64)
                    .await
                    .unwrap();
                if n == 0 {
                    break;
                }
                read_total += n;
            }
            crate::assert_with_log!(read_total == 65536, "total read", 65536usize, read_total);
            crate::assert_with_log!(buf == data, "data integrity", true, buf == data);
        });
        crate::test_complete!("test_uring_file_large_io");
    }
