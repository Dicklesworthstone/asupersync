    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::io::{self, IoSlice, IoSliceMut, Read};
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    /// GH#67 follow-up (asupersync-tx9j0f): a `UnixStream` polled with no
    /// I/O driver on the current `Cx` parks on the process-global fallback
    /// driver instead of re-waking itself into a hot loop.
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use crate::runtime::{IoDriverHandle, LabReactor};
        use crate::types::{Budget, RegionId, TaskId};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        fn poll_read_once(
            stream: &mut UnixStream,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut read_buf = ReadBuf::new(buf);
            match Pin::new(stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }

        /// The defect: with no I/O driver on the current `Cx`, a `WouldBlock`
        /// read re-woke its own waker synchronously, so an executor re-polled
        /// in a hot loop. The fixed path must (1) return `Pending` without
        /// any wake, (2) stay silent while the peer is idle, and (3) wake
        /// exactly once when bytes arrive, from the fallback reactor pump.
        #[test]
        fn poll_read_without_io_driver_parks_until_data_arrives() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (mut stream, peer) = UnixStream::pair().expect("socket pair");
            let (signal, waker, rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 16];

            assert!(matches!(
                poll_read_once(&mut stream, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless poll must park, not self-wake (GH#67)"
            );
            assert!(
                stream.registration.lock().on_fallback(),
                "driverless poll registers with the process-global fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while the peer is silent"
            );

            let mut writer = &*peer.inner;
            writer.write_all(b"wake").expect("peer write");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);
            match poll_read_once(&mut stream, &mut task_cx, &mut buf) {
                Poll::Ready(Ok(len)) => assert_eq!(&buf[..len], b"wake"),
                other => panic!("expected the bytes after the wake, got {other:?}"),
            }
        }

        /// A stream parked on the fallback driver is handed to the ambient
        /// driver as soon as it is polled under a `Cx` that carries one.
        #[test]
        fn fallback_registration_migrates_to_ambient_io_driver() {
            assert!(Cx::current().is_none());
            let (mut stream, _peer) = UnixStream::pair().expect("socket pair");
            let (_signal, waker, _rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 8];

            assert!(matches!(
                poll_read_once(&mut stream, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(stream.registration.lock().on_fallback());

            let driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
            assert_eq!(driver.waker_count(), 0);
            let ambient = Cx::new_with_observability(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
            );
            let _guard = Cx::set_current(Some(ambient));

            assert!(matches!(
                poll_read_once(&mut stream, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(
                !stream.registration.lock().on_fallback(),
                "ambient driver must take over the registration"
            );
            assert!(stream.registration.lock().is_some());
            assert_eq!(
                driver.waker_count(),
                1,
                "the ambient driver now owns the stream's readiness waker"
            );
        }
    }

    /// br-asupersync-unix-socket-audit-alx18f item 2: several tasks can wait
    /// in the `&self` ancillary methods of one shared stream. Each wait used
    /// to replace the registration's single waker, so only the task that
    /// parked last was woken. These run without a `Cx`, so the waits park on
    /// the process-global fallback driver and its pump delivers the wakes.
    mod shared_ancillary_waiters {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use crate::net::unix::SocketAncillary;
        use std::io::Write;
        use std::time::Duration;

        /// Writes into `stream` until its send direction would block.
        fn fill_send_buffer(stream: &UnixStream) {
            let mut writer = &*stream.inner;
            for chunk_len in [65_536_usize, 1] {
                let chunk = vec![0u8; chunk_len];
                loop {
                    match writer.write(&chunk) {
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => panic!("filling the send buffer: {err}"),
                    }
                }
            }
        }

        #[test]
        fn a_reader_is_woken_although_a_writer_parked_after_it() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (stream, peer) = UnixStream::pair().expect("socket pair");
            fill_send_buffer(&stream);
            let (_reader_signal, reader_waker, reader_rx) = signal_waker();
            let (_writer_signal, writer_waker, _writer_rx) = signal_waker();
            let mut read_buf = [0u8; 16];
            let mut read_ancillary = SocketAncillary::new(64);
            let mut write_ancillary = SocketAncillary::new(64);
            let payload = [7u8; 64];

            let mut recv = Box::pin(stream.recv_with_ancillary(&mut read_buf, &mut read_ancillary));
            assert!(
                recv.as_mut()
                    .poll(&mut Context::from_waker(&reader_waker))
                    .is_pending()
            );
            let mut send = Box::pin(stream.send_with_ancillary(&payload, &mut write_ancillary));
            assert!(
                send.as_mut()
                    .poll(&mut Context::from_waker(&writer_waker))
                    .is_pending(),
                "the send buffer is full, so the writer parks after the reader"
            );

            (&*peer.inner).write_all(b"wake").expect("peer write");
            reader_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the reader is woken when data arrives, although the writer parked later");
            let len = match recv.as_mut().poll(&mut Context::from_waker(&reader_waker)) {
                Poll::Ready(Ok(len)) => len,
                other => panic!("expected the bytes after the wake, got {other:?}"),
            };
            drop(recv);
            assert_eq!(&read_buf[..len], b"wake");
            drop(send);
        }

        #[test]
        fn two_readers_are_both_woken_and_the_one_left_waiting_is_woken_again() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (stream, peer) = UnixStream::pair().expect("socket pair");
            let (_first_signal, first_waker, first_rx) = signal_waker();
            let (_second_signal, second_waker, second_rx) = signal_waker();
            let mut first_buf = [0u8; 16];
            let mut second_buf = [0u8; 16];
            let mut first_ancillary = SocketAncillary::new(64);
            let mut second_ancillary = SocketAncillary::new(64);

            let mut first =
                Box::pin(stream.recv_with_ancillary(&mut first_buf, &mut first_ancillary));
            let mut second =
                Box::pin(stream.recv_with_ancillary(&mut second_buf, &mut second_ancillary));
            assert!(
                first
                    .as_mut()
                    .poll(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            assert!(
                second
                    .as_mut()
                    .poll(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );

            (&*peer.inner).write_all(b"wake").expect("peer write");
            first_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the reader that parked first is woken");
            second_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the reader that parked second is woken");

            let first_len = match first.as_mut().poll(&mut Context::from_waker(&first_waker)) {
                Poll::Ready(Ok(len)) => len,
                other => panic!("the first reader takes the bytes, got {other:?}"),
            };
            assert!(
                second
                    .as_mut()
                    .poll(&mut Context::from_waker(&second_waker))
                    .is_pending(),
                "nothing is left for the second reader, so it parks again"
            );

            (&*peer.inner)
                .write_all(b"more")
                .expect("second peer write");
            second_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the reader that parked again is woken by the next data");
            let second_len = match second
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker))
            {
                Poll::Ready(Ok(len)) => len,
                other => panic!("the second reader takes the next bytes, got {other:?}"),
            };
            drop(first);
            drop(second);
            assert_eq!(&first_buf[..first_len], b"wake");
            assert_eq!(&second_buf[..second_len], b"more");
        }

        /// br-asupersync-reactor-audit-dofi11: past 32 entries the list
        /// evicted its oldest waiter and woke it, so with 33 or more waiting
        /// calls each re-poll evicted the next, and the calls woke each other
        /// forever on an idle socket. Each call now owns one entry, which its
        /// future removes when dropped.
        #[test]
        fn forty_ancillary_waiters_park_without_waking_each_other() {
            const WAITERS: usize = 40;
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (stream, _peer) = UnixStream::pair().expect("socket pair");
            let signals: Vec<_> = (0..WAITERS).map(|_| signal_waker()).collect();
            let mut bufs = vec![[0u8; 16]; WAITERS];
            let mut ancillaries: Vec<SocketAncillary> =
                (0..WAITERS).map(|_| SocketAncillary::new(64)).collect();
            let mut calls: Vec<_> = bufs
                .iter_mut()
                .zip(ancillaries.iter_mut())
                .map(|(buf, ancillary)| Box::pin(stream.recv_with_ancillary(buf, ancillary)))
                .collect();

            for round in 0..2 {
                for (index, (call, (_, waker, _))) in calls.iter_mut().zip(&signals).enumerate() {
                    assert!(
                        call.as_mut()
                            .poll(&mut Context::from_waker(waker))
                            .is_pending(),
                        "call {index} parks in round {round}: no data was sent"
                    );
                }
            }
            for (index, (_, _, rx)) in signals.iter().enumerate() {
                assert!(
                    rx.try_recv().is_err(),
                    "call {index} was woken although the socket stayed idle"
                );
            }
            assert_eq!(
                stream.registration.lock().shared_waiter_count(),
                WAITERS,
                "each waiting call keeps exactly one entry"
            );

            drop(calls);
            assert_eq!(
                stream.registration.lock().shared_waiter_count(),
                0,
                "a dropped call leaves no entry behind"
            );
        }

        /// A waker that records, when its last clone drops, whether the
        /// stream's registration lock was free at that moment.
        struct LockProbe {
            stream: &'static UnixStream,
            lock_was_free: Arc<std::sync::Mutex<Option<bool>>>,
        }

        // Not a no-op waker by accident: what the probe measures is its Drop.
        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for LockProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for LockProbe {
            fn drop(&mut self) {
                let free = self.stream.registration.try_lock().is_some();
                *self.lock_was_free.lock().expect("probe lock") = Some(free);
            }
        }

        /// Review of 740b44300: a re-poll with another waker replaced the
        /// call's entry and dropped the old waker while the stream's
        /// registration lock was still held. That waker can own the last
        /// reference to a task (br-asupersync-9kb866), so it drops after the
        /// lock is released now.
        #[test]
        fn a_replaced_ancillary_waker_drops_after_the_registration_lock() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (stream, _peer) = UnixStream::pair().expect("socket pair");
            let stream: &'static UnixStream = Box::leak(Box::new(stream));
            let lock_was_free = Arc::new(std::sync::Mutex::new(None));
            let first = Waker::from(Arc::new(LockProbe {
                stream,
                lock_was_free: Arc::clone(&lock_was_free),
            }));
            let (_second_signal, second, _second_rx) = signal_waker();
            let mut buf = [0u8; 16];
            let mut ancillary = SocketAncillary::new(64);
            let mut call = Box::pin(stream.recv_with_ancillary(&mut buf, &mut ancillary));

            assert!(
                call.as_mut()
                    .poll(&mut Context::from_waker(&first))
                    .is_pending()
            );
            drop(first);
            assert_eq!(
                *lock_was_free.lock().expect("probe lock"),
                None,
                "the call's entry still holds the first waker"
            );
            assert!(
                call.as_mut()
                    .poll(&mut Context::from_waker(&second))
                    .is_pending()
            );
            assert_eq!(
                *lock_was_free.lock().expect("probe lock"),
                Some(true),
                "the replaced waker dropped with the registration lock free"
            );
            drop(call);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_pair() {
        init_test("test_pair");
        let (mut s1, mut s2) = UnixStream::pair().expect("pair failed");

        std::io::Write::write_all(&mut s1, b"hello").expect("write failed");
        let mut buf = [0u8; 5];
        s2.read_exact(&mut buf).expect("read failed");

        crate::assert_with_log!(&buf == b"hello", "buf", b"hello", buf);
        crate::test_complete!("test_pair");
    }

    #[test]
    fn test_local_peer_addr() {
        init_test("test_local_peer_addr");
        let (s1, s2) = UnixStream::pair().expect("pair failed");

        // Unnamed sockets from pair() don't have pathname addresses
        let local = s1.local_addr().expect("local_addr failed");
        let peer = s2.peer_addr().expect("peer_addr failed");

        // Both should be unnamed (no pathname)
        let local_path = local.as_pathname();
        crate::assert_with_log!(
            local_path.is_none(),
            "local no pathname",
            "None",
            format!("{:?}", local_path)
        );
        let peer_path = peer.as_pathname();
        crate::assert_with_log!(
            peer_path.is_none(),
            "peer no pathname",
            "None",
            format!("{:?}", peer_path)
        );
        crate::test_complete!("test_local_peer_addr");
    }

    #[test]
    fn test_shutdown() {
        init_test("test_shutdown");
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // Shutdown should succeed
        s1.shutdown(Shutdown::Write).expect("shutdown failed");
        crate::test_complete!("test_shutdown");
    }

    #[test]
    fn test_poll_flush_and_shutdown_return_interrupted_when_cancel_requested() {
        init_test("test_poll_flush_and_shutdown_return_interrupted_when_cancel_requested");
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let mut stream = UnixStream::from_std(s1).expect("wrap stream");
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        let flush = Pin::new(&mut stream).poll_flush(&mut task_cx);
        assert!(matches!(
            flush,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let shutdown = Pin::new(&mut stream).poll_shutdown(&mut task_cx);
        assert!(matches!(
            shutdown,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
    }

    #[test]
    fn test_split() {
        init_test("test_split");
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // Split should work
        let (_read, _write) = s1.split();
        crate::test_complete!("test_split");
    }

    #[test]
    fn test_into_split() {
        init_test("test_into_split");
        let (s1, _s2) = UnixStream::pair().expect("pair failed");

        // into_split should work
        let (_read, _write) = s1.into_split();
        crate::test_complete!("test_into_split");
    }

    #[test]
    fn owned_write_half_shutdown_on_drop() {
        init_test("owned_write_half_shutdown_on_drop");
        let (s1, mut s2) = UnixStream::pair().expect("pair failed");

        let (_read, write) = s1.into_split();
        drop(write);

        let mut buf = [0u8; 1];
        let mut is_shutdown = false;
        for _ in 0..64 {
            match s2.read(&mut buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Ok(_) | Err(_) => {
                    is_shutdown = true;
                    break;
                }
            }
        }

        crate::assert_with_log!(
            is_shutdown,
            "write half shutdown on drop",
            true,
            is_shutdown
        );
        crate::test_complete!("owned_write_half_shutdown_on_drop");
    }

    #[test]
    fn test_from_std() {
        init_test("test_from_std");
        let (std_s1, _std_s2) = net::UnixStream::pair().expect("pair failed");
        let stream = UnixStream::from_std(std_s1).expect("wrap stream");
        let flags = fcntl(stream.inner.as_ref(), FcntlArg::F_GETFL).expect("read stream flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        crate::assert_with_log!(
            is_nonblocking,
            "from_std should force nonblocking mode",
            true,
            is_nonblocking
        );
        crate::test_complete!("test_from_std");
    }

    #[test]
    fn test_vectored_io() {
        init_test("test_vectored_io");
        futures_lite::future::block_on(async {
            let (mut tx, mut rx) = UnixStream::pair().expect("pair failed");
            let header = b"hi";
            let body = b"there";
            let bufs = [IoSlice::new(header), IoSlice::new(body)];

            let wrote = crate::io::AsyncWriteExt::write_vectored(&mut tx, &bufs)
                .await
                .expect("write_vectored failed");
            let expected_len = header.len() + body.len();
            crate::assert_with_log!(wrote == expected_len, "wrote", expected_len, wrote);
            let vectored = crate::io::AsyncWrite::is_write_vectored(&tx);
            crate::assert_with_log!(vectored, "is_write_vectored", true, vectored);

            let mut out = Vec::new();
            while out.len() < wrote {
                let mut a = [0u8; 2];
                let mut b = [0u8; 8];
                let mut rbufs = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];

                let n = crate::io::AsyncReadVectoredExt::read_vectored(&mut rx, &mut rbufs)
                    .await
                    .expect("read_vectored failed");
                if n == 0 {
                    break;
                }

                let first = n.min(a.len());
                out.extend_from_slice(&a[..first]);
                if n > a.len() {
                    out.extend_from_slice(&b[..n - a.len()]);
                }
            }

            let mut expected = Vec::new();
            expected.extend_from_slice(header);
            expected.extend_from_slice(body);
            crate::assert_with_log!(out == expected, "out", expected, out);
        });
        crate::test_complete!("test_vectored_io");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_connect_abstract() {
        init_test("test_connect_abstract");
        // Test that connect_abstract compiles and returns an error when no listener exists
        futures_lite::future::block_on(async {
            // This will fail because no listener, but validates the API
            let err = UnixStream::connect_abstract(b"nonexistent_test_socket")
                .await
                .expect_err("connect should fail without a listener");
            // A broken abstract-address encoding would fail earlier as InvalidInput.
            crate::assert_with_log!(
                err.kind() != io::ErrorKind::InvalidInput,
                "connect_abstract error kind",
                "non-InvalidInput",
                err.kind()
            );
        });
        crate::test_complete!("test_connect_abstract");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_connect_abstract_listener_interop() {
        use std::os::linux::net::SocketAddrExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        init_test("test_connect_abstract_listener_interop");

        let nonce = SystemTime::now() // ubs:ignore - test helper
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let name = format!(
            // ubs:ignore - test helper
            "asupersync_connect_abstract_{}_{}",
            std::process::id(), // ubs:ignore - test helper
            nonce
        );
        let addr =
            net::SocketAddr::from_abstract_name(name.as_bytes()).expect("build abstract addr");
        let listener = net::UnixListener::bind_addr(&addr).expect("bind abstract listener");

        let accept_handle = std::thread::spawn(move || {
            let (_stream, _addr) = listener.accept().expect("accept client");
        });

        futures_lite::future::block_on(async {
            let _client = UnixStream::connect_abstract(name.as_bytes())
                .await
                .expect("connect abstract listener");
        });

        accept_handle.join().expect("accept thread panicked");
        crate::test_complete!("test_connect_abstract_listener_interop");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn test_peer_cred() {
        init_test("test_peer_cred");
        let (s1, s2) = UnixStream::pair().expect("pair failed");

        // Both sides should be able to get peer credentials
        let cred1 = s1.peer_cred().expect("peer_cred s1 failed");
        let cred2 = s2.peer_cred().expect("peer_cred s2 failed");

        // Both should report the same process (ourselves)
        let user_id = nix::unistd::getuid().as_raw() as u32;
        let group_id = nix::unistd::getgid().as_raw() as u32;

        crate::assert_with_log!(cred1.uid == user_id, "s1 uid", user_id, cred1.uid);
        crate::assert_with_log!(cred1.gid == group_id, "s1 gid", group_id, cred1.gid);
        crate::assert_with_log!(cred2.uid == user_id, "s2 uid", user_id, cred2.uid);
        crate::assert_with_log!(cred2.gid == group_id, "s2 gid", group_id, cred2.gid);

        // On Linux, pid should be available and match our process
        #[cfg(target_os = "linux")]
        {
            let proc_id = i32::try_from(std::process::id()).expect("process id fits in i32");
            let pid1 = cred1.pid.expect("pid should be available on Linux");
            let pid2 = cred2.pid.expect("pid should be available on Linux");
            crate::assert_with_log!(pid1 == proc_id, "s1 pid", proc_id, pid1);
            crate::assert_with_log!(pid2 == proc_id, "s2 pid", proc_id, pid2);
        }

        crate::test_complete!("test_peer_cred");
    }

    #[test]
    fn test_send_recv_with_ancillary() {
        use crate::net::unix::{AncillaryMessage, SocketAncillary};
        use std::os::unix::io::AsRawFd;

        init_test("test_send_recv_with_ancillary");
        futures_lite::future::block_on(async {
            let (tx, rx) = UnixStream::pair().expect("pair failed");

            // Create a pipe to get a file descriptor to pass
            let (pipe_read, pipe_write) = nix::unistd::pipe().expect("pipe failed");
            let pipe_read_raw = pipe_read.as_raw_fd();
            let _pipe_write_raw = pipe_write.as_raw_fd();

            // Write something to the pipe so we can verify the fd works
            nix::unistd::write(&pipe_write, b"test data").expect("write to pipe failed");

            // Send the read end of the pipe
            let mut send_ancillary = SocketAncillary::new(128);
            let added = send_ancillary.add_fds(&[pipe_read_raw]);
            crate::assert_with_log!(added, "add_fds", true, added);

            let sent = tx
                .send_with_ancillary(b"file descriptor attached", &mut send_ancillary)
                .await
                .expect("send_with_ancillary failed");
            crate::assert_with_log!(sent == 24, "sent bytes", 24, sent);

            // Close the original fd (the receiver now owns it)
            // Dropping the OwnedFd will close it
            drop(pipe_read);

            // Receive the data and file descriptor
            let mut recv_buf = [0u8; 64];
            let mut recv_ancillary = SocketAncillary::new(128);

            let received = rx
                .recv_with_ancillary(&mut recv_buf, &mut recv_ancillary)
                .await
                .expect("recv_with_ancillary failed");
            crate::assert_with_log!(received == 24, "received bytes", 24, received);
            crate::assert_with_log!(
                &recv_buf[..received] == b"file descriptor attached",
                "received data",
                b"file descriptor attached",
                &recv_buf[..received]
            );

            // Extract the file descriptor
            let mut received_fd = None;
            for msg in recv_ancillary.messages() {
                let AncillaryMessage::ScmRights(fds) = msg;
                for fd in fds {
                    received_fd = Some(fd);
                }
            }

            let fd = received_fd.expect("should have received a file descriptor");
            drop(pipe_write);
            nix::unistd::close(fd).expect("close received fd");
        });
        crate::test_complete!("test_send_recv_with_ancillary");
    }

    /// Received descriptors were not close-on-exec, so every child process
    /// the receiver spawned inherited them. std passes MSG_CMSG_CLOEXEC.
    #[cfg(target_os = "linux")]
    #[test]
    fn received_fds_are_close_on_exec() {
        use crate::net::unix::{AncillaryMessage, SocketAncillary};
        use std::os::unix::io::AsRawFd;

        futures_lite::future::block_on(async {
            let (tx, rx) = UnixStream::pair().expect("pair");
            let (pipe_read, _pipe_write) = nix::unistd::pipe().expect("pipe");
            let mut send = SocketAncillary::new(128);
            assert!(send.add_fds(&[pipe_read.as_raw_fd()]));
            tx.send_with_ancillary(b"fd", &mut send)
                .await
                .expect("send_with_ancillary");
            let mut buf = [0_u8; 8];
            let mut recv = SocketAncillary::new(128);
            rx.recv_with_ancillary(&mut buf, &mut recv)
                .await
                .expect("recv_with_ancillary");
            let mut received = None;
            for message in recv.messages() {
                let AncillaryMessage::ScmRights(fds) = message;
                for fd in fds {
                    received = Some(fd);
                }
            }
            let fd = received.expect("a descriptor was received");
            // /proc/self/fdinfo reports O_CLOEXEC in `flags` for a
            // close-on-exec descriptor.
            let fdinfo =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).expect("read fdinfo");
            let flags = fdinfo
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .map(|value| u32::from_str_radix(value.trim(), 8).expect("octal flags"))
                .expect("fdinfo flags line");
            nix::unistd::close(fd).expect("close received fd");
            assert_ne!(
                flags & libc::O_CLOEXEC as u32,
                0,
                "the received descriptor must be close-on-exec"
            );
        });
    }

    /// A full AF_UNIX backlog makes connect return EAGAIN and abandon the
    /// attempt. connect treated that as "in progress" and waited, spinning,
    /// for a connection that would never be made, even after the server
    /// drained its backlog.
    #[cfg(target_os = "linux")]
    #[test]
    fn connect_to_a_full_backlog_returns_would_block_instead_of_hanging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("full.sock");
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).expect("socket");
        listener
            .bind(&SockAddr::unix(&path).expect("socket address"))
            .expect("bind");
        listener.listen(0).expect("listen");
        let _queued = net::UnixStream::connect(&path).expect("the first connect fills the backlog");

        let (tx, rx) = std::sync::mpsc::channel();
        let target = path.clone();
        std::thread::spawn(move || {
            let result = futures_lite::future::block_on(UnixStream::connect(&target));
            let _ = tx.send(result.map(drop).map_err(|err| err.kind()));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("connect must return rather than wait for a connection that never comes");
        assert_eq!(result, Err(io::ErrorKind::WouldBlock));
    }

    /// A truncated SCM_RIGHTS message whose header still claims the sender's
    /// length (XNU, FreeBSD) yields only the descriptors the kernel copied
    /// (br-asupersync-8vrx8q).
    #[test]
    fn scm_rights_fd_count_is_bounded_by_the_copied_control_bytes() {
        let fd = std::mem::size_of::<RawFd>();
        // The header claims eight descriptors; the buffer holds one.
        assert_eq!(scm_rights_fd_count(8 * fd, fd), 1);
        assert_eq!(scm_rights_fd_count(8 * fd, fd + 3), 1);
        assert_eq!(scm_rights_fd_count(8 * fd, 0), 0);
        // An intact message is counted from its header.
        assert_eq!(scm_rights_fd_count(2 * fd, 64), 2);
    }

    #[test]
    fn recv_with_ancillary_reports_truncation_via_msg_ctrunc() {
        use crate::net::unix::{AncillaryMessage, SocketAncillary};
        use std::os::unix::io::AsRawFd;
        init_test("recv_with_ancillary_reports_truncation_via_msg_ctrunc");

        // Connected Unix stream pair for a synchronous sendmsg/recvmsg exchange.
        let (sender, receiver) = UnixStream::pair().expect("UnixStream::pair");

        // An fd worth passing (the read end of a pipe).
        let (pipe_read, pipe_write) = nix::unistd::pipe().expect("pipe");

        let mut send_ancillary = SocketAncillary::new(0);
        send_ancillary.add_fds(&[pipe_read.as_raw_fd()]);
        let sent = send_with_ancillary_impl(sender.as_raw_fd(), b"x", &mut send_ancillary)
            .expect("send_with_ancillary_impl");
        crate::assert_with_log!(sent == 1, "sent one byte", 1, sent);

        // Receive with a control buffer too small to hold even one SCM_RIGHTS
        // header: the kernel sets MSG_CTRUNC and delivers no fds while cmsgs()
        // still returns Ok (not ENOBUFS). Before the MSG_CTRUNC check this left
        // is_truncated() == false, so the caller silently believed it received
        // every fd.
        let mut recv_buf = [0u8; 8];
        let mut recv_ancillary = SocketAncillary::new(1);
        let received =
            recv_with_ancillary_impl(receiver.as_raw_fd(), &mut recv_buf, &mut recv_ancillary)
                .expect("recv_with_ancillary_impl");
        crate::assert_with_log!(received == 1, "received one byte", 1, received);
        crate::assert_with_log!(
            recv_ancillary.is_truncated(),
            "MSG_CTRUNC must surface as is_truncated()",
            true,
            recv_ancillary.is_truncated()
        );

        // Close any fds that were delivered so the test leaks nothing.
        for msg in recv_ancillary.messages() {
            let AncillaryMessage::ScmRights(fds) = msg;
            for fd in fds {
                let _ = nix::unistd::close(fd);
            }
        }
        drop(pipe_read);
        drop(pipe_write);

        crate::test_complete!("recv_with_ancillary_reports_truncation_via_msg_ctrunc");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recv_with_ancillary_surfaces_partial_truncation_fds_without_leak() {
        use crate::net::unix::{AncillaryMessage, SocketAncillary, ancillary_space_for_fds};
        use std::collections::HashSet;
        use std::os::unix::io::AsRawFd;
        use std::path::PathBuf;

        fn fd_target(fd: RawFd) -> PathBuf {
            std::fs::read_link(format!("/proc/self/fd/{fd}")).expect("read fd target")
        }

        fn matching_open_fd_targets(targets: &HashSet<PathBuf>) -> Vec<PathBuf> {
            let mut matches = Vec::new();
            for entry in std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd") {
                let Ok(entry) = entry else {
                    continue;
                };
                let Ok(target) = std::fs::read_link(entry.path()) else {
                    continue;
                };
                if targets.contains(&target) {
                    matches.push(target);
                }
            }
            matches
        }

        init_test("recv_with_ancillary_surfaces_partial_truncation_fds_without_leak");
        let mut sent_read_targets = HashSet::new();

        {
            let (sender, receiver) = UnixStream::pair().expect("UnixStream::pair");
            let pipes: Vec<_> = (0..8).map(|_| nix::unistd::pipe().expect("pipe")).collect();
            let send_fds: Vec<_> = pipes
                .iter()
                .map(|(read_end, _write_end)| read_end.as_raw_fd())
                .collect();
            sent_read_targets.extend(send_fds.iter().copied().map(fd_target));

            let mut send_ancillary = SocketAncillary::new(0);
            send_ancillary.add_fds(&send_fds);
            let sent = send_with_ancillary_impl(sender.as_raw_fd(), b"x", &mut send_ancillary)
                .expect("send_with_ancillary_impl");
            crate::assert_with_log!(sent == 1, "sent one byte", 1, sent);

            let mut recv_buf = [0u8; 8];
            let mut recv_ancillary = SocketAncillary::new(ancillary_space_for_fds(1));
            let received =
                recv_with_ancillary_impl(receiver.as_raw_fd(), &mut recv_buf, &mut recv_ancillary)
                    .expect("recv_with_ancillary_impl");
            crate::assert_with_log!(received == 1, "received one byte", 1, received);
            crate::assert_with_log!(
                recv_ancillary.is_truncated(),
                "partial SCM_RIGHTS truncation must be flagged",
                true,
                recv_ancillary.is_truncated()
            );

            let mut delivered_fds = Vec::new();
            for msg in recv_ancillary.messages() {
                let AncillaryMessage::ScmRights(fds) = msg;
                delivered_fds.extend(fds);
            }
            crate::assert_with_log!(
                !delivered_fds.is_empty(),
                "partial truncation should surface fitted fds",
                true,
                !delivered_fds.is_empty()
            );
            crate::assert_with_log!(
                delivered_fds.len() < send_fds.len(),
                "receive buffer should not fit every sent fd",
                true,
                delivered_fds.len() < send_fds.len()
            );

            for fd in delivered_fds {
                nix::unistd::close(fd).expect("close delivered fd");
            }
        }

        let leaked_targets = matching_open_fd_targets(&sent_read_targets);
        crate::assert_with_log!(
            leaked_targets.is_empty(),
            "partial truncation must not leak fds",
            Vec::<PathBuf>::new(),
            leaked_targets
        );
        crate::test_complete!("recv_with_ancillary_surfaces_partial_truncation_fds_without_leak");
    }

    #[test]
    fn wait_for_connect_fallback_returns_interrupted_when_cancel_requested() {
        init_test("wait_for_connect_fallback_returns_interrupted_when_cancel_requested");
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).expect("socket");
        socket.set_nonblocking(true).expect("nonblocking");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let result = futures_lite::future::block_on(crate::time::timeout(
            crate::time::wall_now(),
            std::time::Duration::from_millis(20),
            wait_for_connect_fallback(&socket),
        ));

        match result {
            Ok(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::Interrupted),
            Ok(Ok(())) => panic!("cancelled fallback connect unexpectedly succeeded"),
            Err(_) => panic!("cancelled fallback connect hung instead of returning Interrupted"),
        }
    }

    #[test]
    fn send_with_ancillary_returns_interrupted_without_sending_when_cancel_requested() {
        use crate::net::unix::SocketAncillary;

        init_test("send_with_ancillary_returns_interrupted_without_sending_when_cancel_requested");
        futures_lite::future::block_on(async {
            let (tx, mut rx) = UnixStream::pair().expect("pair failed");

            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            let guard = Cx::set_current(Some(cx));

            let mut ancillary = SocketAncillary::new(64);
            let err = tx
                .send_with_ancillary(b"cancelled-send", &mut ancillary)
                .await
                .expect_err("cancelled send_with_ancillary must fail");
            assert_eq!(err.kind(), io::ErrorKind::Interrupted);

            drop(guard);

            let mut buf = [0u8; 32];
            let err = rx
                .read(&mut buf)
                .expect_err("cancelled ancillary send must not publish bytes");
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        });
    }

    #[test]
    fn recv_with_ancillary_returns_interrupted_without_consuming_when_cancel_requested() {
        use crate::net::unix::SocketAncillary;

        init_test(
            "recv_with_ancillary_returns_interrupted_without_consuming_when_cancel_requested",
        );
        futures_lite::future::block_on(async {
            let (mut tx, rx) = UnixStream::pair().expect("pair failed");
            std::io::Write::write_all(&mut tx, b"hello").expect("seed bytes");

            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            let guard = Cx::set_current(Some(cx));

            let mut cancelled_buf = [0u8; 8];
            let mut cancelled_ancillary = SocketAncillary::new(64);
            let err = rx
                .recv_with_ancillary(&mut cancelled_buf, &mut cancelled_ancillary)
                .await
                .expect_err("cancelled recv_with_ancillary must fail");
            assert_eq!(err.kind(), io::ErrorKind::Interrupted);

            drop(guard);

            let mut buf = [0u8; 8];
            let mut ancillary = SocketAncillary::new(64);
            let n = rx
                .recv_with_ancillary(&mut buf, &mut ancillary)
                .await
                .expect("bytes should still be readable after cancelled recv");
            assert_eq!(&buf[..n], b"hello");
        });
    }

    #[test]
    fn ucred_debug_clone_copy_eq() {
        let c = UCred {
            uid: 1000,
            gid: 1000,
            pid: Some(42),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("1000"), "{dbg}");
        let copied: UCred = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        assert_ne!(
            c,
            UCred {
                uid: 0,
                gid: 0,
                pid: None
            }
        );
    }

    #[test]
    fn send_with_ancillary_empty_buffer_handling() {
        use crate::net::unix::SocketAncillary;
        use std::os::unix::io::AsRawFd;

        init_test("send_with_ancillary_empty_buffer_handling");
        futures_lite::future::block_on(async {
            let (tx, _rx) = UnixStream::pair().expect("pair failed");

            // Empty buffer with no fds succeeds with Ok(0)
            let mut empty_ancillary = SocketAncillary::new(64);
            let n = tx
                .send_with_ancillary(b"", &mut empty_ancillary)
                .await
                .expect("empty send without fds must succeed");
            assert_eq!(n, 0);

            // Empty buffer with queued fds returns InvalidInput error
            let file = tempfile::tempfile().expect("tempfile");
            let mut fd_ancillary = SocketAncillary::new(64);
            assert!(fd_ancillary.add_fds(&[file.as_raw_fd()]));

            let err = tx
                .send_with_ancillary(b"", &mut fd_ancillary)
                .await
                .expect_err("sending fds with empty buffer on stream socket must fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("cannot send file descriptors with an empty buffer"),
                "unexpected error message: {err}"
            );
        });
    }
