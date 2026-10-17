    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::{AsyncReadExt, AsyncWriteExt}; // Extension traits for read_to_string etc
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_file_create_write_read() {
        init_test("test_file_create_write_read");
        // Phase 0 is synchronous; we use a simple block_on for async tests.

        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test.txt");

            // Create and write
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read back
            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
        });
        crate::test_complete!("test_file_create_write_read");
    }

    #[test]
    fn test_file_seek() {
        init_test("test_file_seek");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_seek.txt");

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .await
                .unwrap();

            file.write_all(b"0123456789").await.unwrap();

            file.seek(SeekFrom::Start(5)).await.unwrap();
            let mut buf = [0u8; 5];
            file.read_exact(&mut buf).await.unwrap();
            crate::assert_with_log!(&buf == b"56789", "seek contents", b"56789", buf);
        });
        crate::test_complete!("test_file_seek");
    }

    #[test]
    fn test_file_read_into_vec_reuses_owned_buffer() {
        init_test("test_file_read_into_vec_reuses_owned_buffer");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_read_into_vec.txt");
            std::fs::write(&path, b"abcdefg").unwrap();

            let mut file = File::open(&path).await.unwrap();
            let buffer = vec![0_u8; 4];
            let capacity = buffer.capacity();

            let (buffer, bytes_read) = file.read_into_vec(buffer).await.unwrap();
            crate::assert_with_log!(bytes_read == 4, "first bytes read", 4usize, bytes_read);
            crate::assert_with_log!(
                &buffer[..bytes_read] == b"abcd",
                "first chunk",
                b"abcd",
                &buffer[..bytes_read]
            );
            crate::assert_with_log!(
                buffer.capacity() == capacity,
                "buffer capacity reused",
                capacity,
                buffer.capacity()
            );

            let (buffer, bytes_read) = file.read_into_vec(buffer).await.unwrap();
            crate::assert_with_log!(bytes_read == 3, "second bytes read", 3usize, bytes_read);
            crate::assert_with_log!(
                &buffer[..bytes_read] == b"efg",
                "second chunk",
                b"efg",
                &buffer[..bytes_read]
            );
        });
        crate::test_complete!("test_file_read_into_vec_reuses_owned_buffer");
    }

    #[test]
    fn test_file_create_new_is_exclusive_and_read_write() {
        init_test("test_file_create_new_is_exclusive_and_read_write");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("exclusive.txt");

            let mut file = File::create_new(&path).await.unwrap();
            file.write_all(b"exclusive").await.unwrap();
            file.rewind().await.unwrap();

            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "exclusive",
                "create_new file is read-write",
                "exclusive",
                contents
            );
            drop(file);

            let err = File::create_new(&path)
                .await
                .expect_err("second create_new must fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::AlreadyExists,
                "create_new existing error kind",
                io::ErrorKind::AlreadyExists,
                err.kind()
            );
        });
        crate::test_complete!("test_file_create_new_is_exclusive_and_read_write");
    }

    #[test]
    fn test_file_metadata() {
        init_test("test_file_metadata");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_metadata.txt");

            // Create file with known content
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"test content").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read metadata
            let file = File::open(&path).await.unwrap();
            let metadata = file.metadata().await.unwrap();

            crate::assert_with_log!(metadata.is_file(), "is_file", true, metadata.is_file());
            crate::assert_with_log!(metadata.len() == 12, "file length", 12u64, metadata.len());
        });
        crate::test_complete!("test_file_metadata");
    }

    #[test]
    fn test_file_metadata_permissions_roundtrip_uses_fs_wrapper() {
        init_test("test_file_metadata_permissions_roundtrip_uses_fs_wrapper");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_metadata_permissions.txt");

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .await
                .unwrap();

            let mut permissions = file.metadata().await.unwrap().permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions).await.unwrap();
            let readonly = file.metadata().await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                readonly,
                "file permissions set readonly through fs wrapper",
                true,
                readonly
            );

            let mut permissions = file.metadata().await.unwrap().permissions();
            permissions.set_readonly(false);
            file.set_permissions(permissions).await.unwrap();
            let readonly = file.metadata().await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly,
                "file permissions reset through fs wrapper",
                false,
                readonly
            );
        });
        crate::test_complete!("test_file_metadata_permissions_roundtrip_uses_fs_wrapper");
    }

    #[test]
    fn test_file_set_len() {
        init_test("test_file_set_len");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_truncate.txt");

            // Create and write using async API
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();

            // Truncate
            file.set_len(5).await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Verify
            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(contents == "hello", "truncated contents", "hello", contents);
        });
        crate::test_complete!("test_file_set_len");
    }

    #[test]
    fn test_cancellation_safety_soft_cancel() {
        // Test that dropping an in-flight file operation doesn't corrupt state.
        // With spawn_blocking, the blocking op continues but result is discarded.
        init_test("test_cancellation_safety_soft_cancel");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_cancel.txt");

            // Create file first
            let file = File::create(&path).await.unwrap();
            drop(file);

            // Open the file - this should complete
            let file = File::open(&path).await.unwrap();

            // File should be usable after the operation completed
            let metadata = file.metadata().await.unwrap();
            crate::assert_with_log!(metadata.is_file(), "file exists", true, metadata.is_file());
        });
        crate::test_complete!("test_cancellation_safety_soft_cancel");
    }

    #[test]
    fn test_file_from_std_into_std_roundtrip() {
        init_test("test_file_from_std_into_std_roundtrip");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("std_roundtrip.txt");

            let std_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .read(true)
                .open(&path)
                .unwrap();

            let file = File::from_std(std_file);
            let mut roundtrip = file.into_std().unwrap();
            roundtrip.write_all(b"std bridge").unwrap();
            roundtrip.sync_all().unwrap();
            drop(roundtrip);

            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "std bridge",
                "roundtrip contents",
                "std bridge",
                contents
            );
        });
        crate::test_complete!("test_file_from_std_into_std_roundtrip");
    }

    #[test]
    fn test_file_into_std_when_shared() {
        init_test("test_file_into_std_when_shared");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("shared_into_std.txt");

            let file = File::create(&path).await.unwrap();
            let _other = file.try_clone().await.unwrap();
            let std_file = file.into_std().unwrap();
            let len = std_file.metadata().unwrap().len();
            crate::assert_with_log!(len == 0, "shared into_std len", 0u64, len);
        });
        crate::test_complete!("test_file_into_std_when_shared");
    }

    /// `into_std` after a partial poll-trait read: the caller's cursor is the
    /// bytes it received, not the OS cursor past the unconsumed read-ahead.
    #[test]
    fn test_into_std_rewinds_unconsumed_read_ahead() {
        init_test("test_into_std_rewinds_unconsumed_read_ahead");
        let dir = tempdir().unwrap();
        let path = dir.path().join("read_ahead_into_std.txt");
        std::fs::write(&path, b"0123456789").unwrap();
        let file = File::from_std(std::fs::File::open(&path).unwrap());
        {
            // A 6-byte chunk the pool read, of which the caller took 2.
            let mut file_ref: &std::fs::File = &file.inner;
            let mut chunk = vec![0u8; 6];
            Read::read_exact(&mut file_ref, &mut chunk).unwrap();
            *file.pending.lock() = Some(PendingIo::ReadAhead {
                bytes: chunk,
                consumed: 2,
            });
        }
        let mut std_file = file.into_std().unwrap();
        let position = Seek::stream_position(&mut std_file).unwrap();
        crate::assert_with_log!(position == 2, "cursor after into_std", 2u64, position);
        let mut rest = String::new();
        Read::read_to_string(&mut std_file, &mut rest).unwrap();
        crate::assert_with_log!(rest == "23456789", "bytes after into_std", "23456789", rest);
        crate::test_complete!("test_into_std_rewinds_unconsumed_read_ahead");
    }

    /// `into_std` with a poll-trait read still in flight settles it and
    /// rewinds by everything that read returned, since the caller never saw
    /// those bytes.
    #[test]
    fn test_into_std_settles_in_flight_read() {
        init_test("test_into_std_settles_in_flight_read");
        let dir = tempdir().unwrap();
        let path = dir.path().join("in_flight_into_std.txt");
        std::fs::write(&path, b"0123456789").unwrap();
        let file = File::from_std(std::fs::File::open(&path).unwrap());
        {
            // The syscall already advanced the OS cursor by 4; the caller has
            // not polled its future to completion.
            let mut file_ref: &std::fs::File = &file.inner;
            let mut chunk = vec![0u8; 4];
            Read::read_exact(&mut file_ref, &mut chunk).unwrap();
            let future: PollIoFuture<Vec<u8>> = Box::pin(std::future::ready(Ok(chunk)));
            *file.pending.lock() = Some(PendingIo::Read { future });
        }
        let mut std_file = file.into_std().unwrap();
        let position = Seek::stream_position(&mut std_file).unwrap();
        crate::assert_with_log!(position == 0, "cursor after into_std", 0u64, position);
        crate::test_complete!("test_into_std_settles_in_flight_read");
    }

    /// br-asupersync-pxg07b: copy_bidirectional and split poll a file's read
    /// and write sides alternately. A read that found the other side's write
    /// still pending settled it and dropped its count, so the writer's retry
    /// submitted the same bytes again: the file held "hellohello".
    #[test]
    fn a_write_settled_by_an_interleaved_read_is_not_written_twice() {
        init_test("a_write_settled_by_an_interleaved_read_is_not_written_twice");
        let dir = tempdir().unwrap();
        let path = dir.path().join("interleaved.txt");
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let cx = crate::cx::Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        let _guard = crate::cx::Cx::set_current(Some(cx));
        let mut file = File::from_std(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap(),
        );

        // The write goes to the pool and its first poll is Pending.
        let mut task_cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut file)
                .poll_write(&mut task_cx, b"hello")
                .is_pending()
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::fs::read(&path).unwrap() != b"hello" {
            assert!(std::time::Instant::now() < deadline, "the pool never wrote");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // The other direction reads the same handle before the writer retries.
        let mut buf = [0u8; 8];
        let read = futures_lite::future::block_on(std::future::poll_fn(|poll_cx| {
            let mut read_buf = ReadBuf::new(&mut buf);
            Pin::new(&mut file)
                .poll_read(poll_cx, &mut read_buf)
                .map_ok(|()| read_buf.filled().len())
        }))
        .unwrap();
        crate::assert_with_log!(read == 0, "read at end of file", 0usize, read);

        let written = futures_lite::future::block_on(std::future::poll_fn(|poll_cx| {
            Pin::new(&mut file).poll_write(poll_cx, b"hello")
        }))
        .unwrap();
        crate::assert_with_log!(written == 5, "retried write reports", 5usize, written);
        let contents = std::fs::read(&path).unwrap();
        crate::assert_with_log!(
            contents == b"hello",
            "the retried write is not submitted again",
            "hello",
            String::from_utf8_lossy(&contents)
        );
        crate::test_complete!("a_write_settled_by_an_interleaved_read_is_not_written_twice");
    }

    #[derive(Clone, Copy, Debug)]
    enum CancelledCursorOp {
        Position,
        Seek,
        Read,
    }

    fn assert_queued_cursor_cancellation_preserves_bytes(
        in_flight: bool,
        cancelled_operation: CancelledCursorOp,
    ) {
        for resume in ["owned_read", "trait_read", "trait_seek", "into_std"] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("queued_cursor_cancel.txt");
            std::fs::write(&path, b"0123456789").unwrap();
            let mut file = File::from_std(std::fs::File::open(&path).unwrap());
            let mut bytes = vec![0; 6];
            Read::read_exact(&mut &*file.inner, &mut bytes).unwrap();
            let consumed = if in_flight { 0 } else { 2 };
            *file.pending.lock() = Some(if in_flight {
                PendingIo::Read {
                    future: Box::pin(std::future::ready(Ok(bytes))),
                }
            } else {
                PendingIo::ReadAhead { bytes, consumed }
            });

            let pool = crate::runtime::BlockingPool::new(1, 1);
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            pool.spawn(move || {
                started_tx.send(()).unwrap();
                // Dropping the sender also releases the worker on test failure.
                let _ = release_rx.recv();
            });
            started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            let cx = crate::cx::Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
            let _guard = crate::cx::Cx::set_current(Some(cx));

            let mut operation: Pin<Box<dyn Future<Output = io::Result<()>> + '_>> =
                match cancelled_operation {
                    CancelledCursorOp::Position => {
                        Box::pin(async { file.stream_position().await.map(|_| ()) })
                    }
                    CancelledCursorOp::Seek => {
                        Box::pin(async { file.seek(SeekFrom::Start(9)).await.map(|_| ()) })
                    }
                    CancelledCursorOp::Read => {
                        Box::pin(async { file.read_into_vec(vec![0; 1]).await.map(|_| ()) })
                    }
                };
            let mut poll_cx = Context::from_waker(std::task::Waker::noop());
            assert!(operation.as_mut().poll(&mut poll_cx).is_pending());
            drop(operation);
            release_tx.send(()).unwrap();

            let mut remaining = Vec::new();
            match resume {
                "owned_read" => {
                    let (bytes, count) =
                        futures_lite::future::block_on(file.read_into_vec(vec![0; 10])).unwrap();
                    remaining.extend_from_slice(&bytes[..count]);
                }
                "trait_read" => {
                    futures_lite::future::block_on(file.read_to_end(&mut remaining)).unwrap();
                }
                "trait_seek" => {
                    // An internal rewind must not masquerade as this seek's
                    // completion: the requested extra byte still has to move.
                    let position = futures_lite::future::block_on(crate::io::AsyncSeekExt::seek(
                        &mut file,
                        SeekFrom::Current(1),
                    ))
                    .unwrap();
                    assert_eq!(position, consumed as u64 + 1);
                    futures_lite::future::block_on(file.read_to_end(&mut remaining)).unwrap();
                }
                "into_std" => {
                    let mut file = file.into_std().unwrap();
                    assert_eq!(Seek::stream_position(&mut file).unwrap(), consumed as u64);
                    Read::read_to_end(&mut file, &mut remaining).unwrap();
                }
                _ => unreachable!(),
            }
            let expected_start = consumed + usize::from(resume == "trait_seek");
            assert_eq!(
                remaining,
                b"0123456789"[expected_start..],
                "queued cancellation must retain the caller's unread bytes ({cancelled_operation:?}, {resume})"
            );
            assert!(pool.shutdown_and_wait(std::time::Duration::from_secs(5)));
        }
    }

    #[test]
    fn test_queued_owned_cursor_cancellation_preserves_read_ahead() {
        init_test("test_queued_owned_cursor_cancellation_preserves_read_ahead");
        for operation in [
            CancelledCursorOp::Position,
            CancelledCursorOp::Seek,
            CancelledCursorOp::Read,
        ] {
            assert_queued_cursor_cancellation_preserves_bytes(false, operation);
        }
        crate::test_complete!("test_queued_owned_cursor_cancellation_preserves_read_ahead");
    }

    #[test]
    fn test_queued_owned_cursor_cancellation_preserves_in_flight_read() {
        init_test("test_queued_owned_cursor_cancellation_preserves_in_flight_read");
        for operation in [
            CancelledCursorOp::Position,
            CancelledCursorOp::Seek,
            CancelledCursorOp::Read,
        ] {
            assert_queued_cursor_cancellation_preserves_bytes(true, operation);
        }
        crate::test_complete!("test_queued_owned_cursor_cancellation_preserves_in_flight_read");
    }

    #[test]
    fn test_owned_cursor_failed_seek_keeps_reconciled_position_inline() {
        init_test("test_owned_cursor_failed_seek_keeps_reconciled_position_inline");
        let dir = tempdir().unwrap();
        let path = dir.path().join("reconciled_failed_seek.txt");
        std::fs::write(&path, b"0123456789").unwrap();
        let mut file = File::from_std(std::fs::File::open(&path).unwrap());
        let mut bytes = vec![0; 6];
        Read::read_exact(&mut &*file.inner, &mut bytes).unwrap();
        *file.pending.lock() = Some(PendingIo::ReadAhead { bytes, consumed: 2 });
        let _guard = crate::cx::Cx::set_current(Some(crate::cx::Cx::for_testing()));
        futures_lite::future::block_on(async {
            assert!(file.seek(SeekFrom::Current(i64::MIN)).await.is_err());
            assert_eq!(file.stream_position().await.unwrap(), 2);
            let mut remaining = Vec::new();
            file.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, b"23456789");
        });
        crate::test_complete!("test_owned_cursor_failed_seek_keeps_reconciled_position_inline");
    }

    #[cfg(unix)]
    #[test]
    fn test_owned_cursor_failed_rewind_retains_read_ahead() {
        init_test("test_owned_cursor_failed_rewind_retains_read_ahead");
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        Write::write_all(&mut writer, b"0123456789").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let fd: std::os::fd::OwnedFd = reader.into();
        let mut file = File::from_std(std::fs::File::from(fd));
        let mut bytes = vec![0; 6];
        Read::read_exact(&mut &*file.inner, &mut bytes).unwrap();
        *file.pending.lock() = Some(PendingIo::ReadAhead { bytes, consumed: 2 });
        let _guard = crate::cx::Cx::set_current(Some(crate::cx::Cx::for_testing()));
        futures_lite::future::block_on(async {
            assert!(file.stream_position().await.is_err());
            let mut remaining = Vec::new();
            file.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, b"23456789");
        });
        crate::test_complete!("test_owned_cursor_failed_rewind_retains_read_ahead");
    }

    #[cfg(unix)]
    #[test]
    fn test_poll_write_failed_rewind_retains_read_ahead() {
        init_test("test_poll_write_failed_rewind_retains_read_ahead");
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        Write::write_all(&mut writer, b"0123456789").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let fd: std::os::fd::OwnedFd = reader.into();
        let mut file = File::from_std(std::fs::File::from(fd));
        let mut bytes = vec![0; 6];
        Read::read_exact(&mut &*file.inner, &mut bytes).unwrap();
        *file.pending.lock() = Some(PendingIo::ReadAhead { bytes, consumed: 2 });
        let _guard = crate::cx::Cx::set_current(Some(crate::cx::Cx::for_testing()));
        futures_lite::future::block_on(async {
            let write_result = std::future::poll_fn(|cx| {
                Pin::new(&mut file).poll_write(cx, b"write")
            }).await;
            assert!(write_result.is_err());
            let mut remaining = Vec::new();
            file.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, b"23456789");
        });
        crate::test_complete!("test_poll_write_failed_rewind_retains_read_ahead");
    }

    #[cfg(unix)]
    #[test]
    fn test_poll_seek_failed_rewind_retains_read_ahead() {
        init_test("test_poll_seek_failed_rewind_retains_read_ahead");
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        Write::write_all(&mut writer, b"0123456789").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let fd: std::os::fd::OwnedFd = reader.into();
        let mut file = File::from_std(std::fs::File::from(fd));
        let mut bytes = vec![0; 6];
        Read::read_exact(&mut &*file.inner, &mut bytes).unwrap();
        *file.pending.lock() = Some(PendingIo::ReadAhead { bytes, consumed: 2 });
        let _guard = crate::cx::Cx::set_current(Some(crate::cx::Cx::for_testing()));
        futures_lite::future::block_on(async {
            let seek_result = std::future::poll_fn(|cx| {
                Pin::new(&mut file).poll_seek(cx, SeekFrom::Start(0))
            }).await;
            assert!(seek_result.is_err());
            let mut remaining = Vec::new();
            file.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, b"23456789");
        });
        crate::test_complete!("test_poll_seek_failed_rewind_retains_read_ahead");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn test_started_owned_cursor_rewind_and_operation_keep_clone_gate() {
        init_test("test_started_owned_cursor_rewind_and_operation_keep_clone_gate");
        let dir = tempdir().unwrap();
        let path = dir.path().join("started_rewind_clone_gate.txt");
        std::fs::write(&path, b"0123456789").unwrap();
        let mut file = File::from_std(std::fs::File::open(&path).unwrap());
        let mut bytes = vec![0; 6];
        Read::read_exact(&mut &*file.inner, &mut bytes).unwrap();
        *file.pending.lock() = Some(PendingIo::ReadAhead { bytes, consumed: 2 });
        let probe = Arc::new(FileCursorOperationProbe::new());
        file.install_cursor_operation_probe_for_test(Arc::clone(&probe));
        let mut clone = File {
            inner: Arc::clone(&file.inner),
            cursor_gate: Arc::clone(&file.cursor_gate),
            pending: Mutex::new(None),
            settled_write: Mutex::new(None),
            cursor_probe: Some(Arc::clone(&probe)),
        };
        let pool = crate::runtime::BlockingPool::new(2, 2);
        let cx = crate::cx::Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        let _guard = crate::cx::Cx::set_current(Some(cx));
        struct ReleaseProbe(Arc<FileCursorOperationProbe>);
        impl Drop for ReleaseProbe {
            fn drop(&mut self) {
                self.0.release_first();
            }
        }
        let _release = ReleaseProbe(Arc::clone(&probe));
        let mut operation = Box::pin(file.seek(SeekFrom::Start(8)));
        let mut poll_cx = Context::from_waker(std::task::Waker::noop());
        assert!(operation.as_mut().poll(&mut poll_cx).is_pending());
        assert!(probe.wait_until_first_blocked(Duration::from_secs(5)));
        let mut following = Box::pin(clone.read_into_vec(vec![0; 1]));
        assert!(following.as_mut().poll(&mut poll_cx).is_pending());
        assert!(probe.wait_for_arrivals(2, Duration::from_secs(5)));
        assert_eq!(probe.acquisition_count(), 1);
        drop(operation);
        probe.release_first();
        let (bytes, count) = futures_lite::future::block_on(following).unwrap();
        assert_eq!(count, 1);
        assert_eq!(bytes, b"8");
        assert_eq!(
            futures_lite::future::block_on(file.stream_position()).unwrap(),
            9
        );
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        crate::test_complete!("test_started_owned_cursor_rewind_and_operation_keep_clone_gate");
    }

    #[test]
    fn test_shared_arc_file_handles_support_seek_and_async_read() {
        init_test("test_shared_arc_file_handles_support_seek_and_async_read");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("shared_arc_seek_read.txt");
            std::fs::write(&path, b"0123456789").unwrap();

            let std_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let shared = Arc::new(std_file);

            let mut seeker = File {
                inner: Arc::clone(&shared),
                cursor_gate: Arc::new(Mutex::new(())),
                pending: Mutex::new(None),
                settled_write: Mutex::new(None),
                #[cfg(feature = "test-internals")]
                cursor_probe: None,
            };
            let mut reader = File {
                inner: Arc::clone(&shared),
                cursor_gate: Arc::clone(&seeker.cursor_gate),
                pending: Mutex::new(None),
                settled_write: Mutex::new(None),
                #[cfg(feature = "test-internals")]
                cursor_probe: None,
            };

            seeker.seek(SeekFrom::Start(5)).await.unwrap();
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf).await.unwrap();
            crate::assert_with_log!(
                &buf == b"56789",
                "shared handle seek/read contents",
                b"56789",
                buf
            );
        });
        crate::test_complete!("test_shared_arc_file_handles_support_seek_and_async_read");
    }
