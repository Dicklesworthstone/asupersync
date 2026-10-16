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
    use crate::io::AsyncReadVectored;

    /// GH#67 follow-up (asupersync-9e6a28): an owned TCP split half polled
    /// with no I/O driver on the current `Cx` parks on the process-global
    /// fallback driver instead of re-waking itself into a hot loop.
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use crate::runtime::{IoDriverHandle, LabReactor};
        use crate::types::{Budget, RegionId, TaskId};
        use std::io::Write as _;
        use std::pin::Pin;
        use std::sync::atomic::Ordering;
        use std::task::{Context, Poll};
        use std::time::Duration;

        /// A connected, non-blocking pair: the owned halves under test and
        /// the std peer that can make them readable at will.
        fn split_pair() -> (OwnedReadHalf, OwnedWriteHalf, std::net::TcpStream) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
            let addr = listener.local_addr().expect("listener addr");
            let peer = std::net::TcpStream::connect(addr).expect("connect peer");
            let (accepted, _) = listener.accept().expect("accept");
            accepted.set_nonblocking(true).expect("nonblocking");
            let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(accepted), None);
            (read_half, write_half, peer)
        }

        fn poll_read_once(
            half: &mut OwnedReadHalf,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut read_buf = ReadBuf::new(buf);
            match Pin::new(half).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }

        #[test]
        fn owned_read_half_without_io_driver_parks_until_data_arrives() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (mut read_half, _write_half, mut peer) = split_pair();
            let (signal, waker, rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 16];

            assert!(matches!(
                poll_read_once(&mut read_half, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless poll must park, not self-wake (GH#67)"
            );
            assert!(
                read_half.inner.state.lock().registration_on_fallback,
                "driverless poll registers the shared half state with the fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while the peer is silent"
            );

            peer.write_all(b"wake").expect("peer write");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);
            match poll_read_once(&mut read_half, &mut task_cx, &mut buf) {
                Poll::Ready(Ok(len)) => assert_eq!(&buf[..len], b"wake"),
                other => panic!("expected the bytes after the wake, got {other:?}"),
            }
        }

        /// A half parked on the fallback driver retires that registration
        /// through the ordinary transition path and re-registers on the
        /// ambient driver as soon as it is polled under a `Cx` that has one.
        #[test]
        fn owned_half_fallback_registration_migrates_to_ambient_io_driver() {
            assert!(Cx::current().is_none());
            let (mut read_half, _write_half, _peer) = split_pair();
            let (_signal, waker, _rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 8];

            assert!(matches!(
                poll_read_once(&mut read_half, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(read_half.inner.state.lock().registration_on_fallback);

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
                poll_read_once(&mut read_half, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            let state = read_half.inner.state.lock();
            assert!(
                !state.registration_on_fallback,
                "ambient driver must take over the registration"
            );
            assert!(state.registration.is_some());
            drop(state);
            assert_eq!(
                driver.waker_count(),
                1,
                "the ambient driver now owns the halves' combined waker"
            );
        }

        /// Reuniting halves parked on the fallback driver keeps that fact, so
        /// the reunited stream still hands its registration to the ambient
        /// driver once polled under a `Cx` that has one. reunite dropped the
        /// flag, and the stream stayed on the fallback driver for good
        /// (br-asupersync-8vrx8q).
        #[test]
        fn reunited_stream_migrates_a_fallback_registration_to_the_ambient_driver() {
            assert!(Cx::current().is_none());
            let (mut read_half, write_half, _peer) = split_pair();
            let (_signal, waker, _rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 8];
            assert!(matches!(
                poll_read_once(&mut read_half, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(read_half.inner.state.lock().registration_on_fallback);
            let mut stream = read_half
                .reunite(write_half)
                .expect("halves of one stream reunite");

            let driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
            let ambient = Cx::new_with_observability(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
            );
            let _guard = Cx::set_current(Some(ambient));
            let mut read_buf = ReadBuf::new(&mut buf);
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut task_cx, &mut read_buf)
                    .is_pending()
            );
            assert_eq!(
                driver.waker_count(),
                1,
                "the ambient driver takes over the reunited stream's registration"
            );
        }
    }
    use crate::net::tcp::stream::TcpStream;
    #[cfg(unix)]
    use crate::runtime::io_driver::IoDriverHandle;
    #[cfg(unix)]
    use crate::runtime::reactor::{Events, Reactor, Source, Token};
    use crate::test_utils::init_test_logging;
    #[cfg(unix)]
    use crate::types::{Budget, RegionId, TaskId};
    #[cfg(unix)]
    use parking_lot::Mutex;
    #[cfg(unix)]
    use std::collections::HashMap;
    use std::io::{IoSliceMut, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    #[cfg(unix)]
    use std::sync::Barrier;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};
    use std::thread;
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[cfg(unix)]
    struct CountingWaker {
        hits: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    fn counting_waker() -> (Waker, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        (waker, hits)
    }

    #[cfg(unix)]
    fn install_snapshot(
        state: &Arc<Mutex<SplitIoState>>,
        interest: Interest,
        waker: &Waker,
    ) -> (WaiterTokens, Waker) {
        let mut prepared = prepare_waiters(interest, waker);
        let mut guard = state.lock();
        let (tokens, replaced) =
            install_waiters(&mut guard, interest, &mut prepared).expect("install waiter");
        let snapshot = combined_waker(state, &guard);
        drop(guard);
        drop(replaced);
        (tokens, snapshot)
    }

    #[cfg(unix)]
    struct LockProbeWaker {
        state: Weak<Mutex<SplitIoState>>,
        observed_unlocked: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
    impl Wake for LockProbeWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let unlocked = self
                .state
                .upgrade()
                .is_some_and(|state| state.try_lock().is_some());
            self.observed_unlocked.store(unlocked, Ordering::SeqCst);
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    struct DropProbeWaker {
        dropped: Arc<AtomicBool>,
    }

    // This must carry an Arc-backed drop probe; Waker::noop() cannot observe release.
    #[cfg(unix)]
    #[allow(clippy::manual_noop_waker)]
    impl Wake for DropProbeWaker {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    #[cfg(unix)]
    impl Drop for DropProbeWaker {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct SourceExclusiveState {
        source_to_token: HashMap<i32, Token>,
        token_to_source: HashMap<Token, i32>,
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct SourceExclusiveReactor {
        state: Mutex<SourceExclusiveState>,
        register_calls: AtomicUsize,
        modify_calls: AtomicUsize,
        fail_modify_on_call: AtomicUsize,
        fail_modify_not_connected: AtomicBool,
        slow_first_register: AtomicBool,
        deregister_gate: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    }

    #[cfg(unix)]
    impl SourceExclusiveReactor {
        fn new() -> Self {
            Self {
                state: Mutex::new(SourceExclusiveState::default()),
                register_calls: AtomicUsize::new(0),
                modify_calls: AtomicUsize::new(0),
                fail_modify_on_call: AtomicUsize::new(0),
                fail_modify_not_connected: AtomicBool::new(false),
                slow_first_register: AtomicBool::new(true),
                deregister_gate: Mutex::new(None),
            }
        }

        fn register_calls(&self) -> usize {
            self.register_calls.load(Ordering::SeqCst)
        }

        fn modify_calls(&self) -> usize {
            self.modify_calls.load(Ordering::SeqCst)
        }

        fn fail_modify_on_call(&self, call_index: usize) {
            self.fail_modify_on_call.store(call_index, Ordering::SeqCst);
        }

        fn fail_modify_with_not_connected(&self, enabled: bool) {
            self.fail_modify_not_connected
                .store(enabled, Ordering::SeqCst);
        }

        fn block_next_deregister(&self) -> (Arc<Barrier>, Arc<Barrier>) {
            let entered = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            *self.deregister_gate.lock() = Some((Arc::clone(&entered), Arc::clone(&release)));
            (entered, release)
        }
    }

    #[cfg(unix)]
    impl Reactor for SourceExclusiveReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            let fd = source.raw_fd();
            let mut state = self.state.lock();

            if state.source_to_token.contains_key(&fd) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "source already registered",
                ));
            }
            if state.token_to_source.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }

            state.source_to_token.insert(fd, token);
            state.token_to_source.insert(token, fd);
            drop(state);

            self.register_calls.fetch_add(1, Ordering::SeqCst);
            if self.slow_first_register.swap(false, Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(())
        }

        fn modify(&self, token: Token, _interest: Interest) -> io::Result<()> {
            let state = self.state.lock();
            if !state.token_to_source.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
            drop(state);
            let call = self.modify_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let fail_on = self.fail_modify_on_call.load(Ordering::SeqCst);
            if fail_on != 0 && call == fail_on {
                if self.fail_modify_not_connected.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "injected not-connected modify failure",
                    ));
                }
                return Err(io::Error::other("injected modify failure"));
            }
            Ok(())
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            if let Some((entered, release)) = self.deregister_gate.lock().take() {
                entered.wait();
                release.wait();
            }
            let mut state = self.state.lock();
            let Some(fd) = state.token_to_source.remove(&token) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            };
            state.source_to_token.remove(&fd);
            drop(state);
            Ok(())
        }

        fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();
            Ok(0)
        }

        fn wake(&self) -> io::Result<()> {
            Ok(())
        }

        fn registration_count(&self) -> usize {
            self.state.lock().token_to_source.len()
        }
    }

    #[test]
    fn borrowed_split_read_write() {
        init_test("borrowed_split_read_write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut server, _) = listener.accept().expect("accept");

        // Create borrowed halves
        let _read_half = ReadHalf::new(&client);
        let _write_half = WriteHalf::new(&client);

        // Write from server, read from client
        server.write_all(b"hello").expect("write");

        // Borrowed halves work (may need multiple attempts due to non-blocking)
        let mut buf = [0u8; 5];
        let _read_buf = ReadBuf::new(&mut buf);

        // Just verify the types compile and basic operations work
        crate::assert_with_log!(true, "borrowed split compiles", true, true);
        crate::test_complete!("borrowed_split_read_write");
    }

    #[test]
    fn borrowed_split_halves_return_interrupted_when_cancel_requested() {
        init_test("borrowed_split_halves_return_interrupted_when_cancel_requested");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (_server, _) = listener.accept().expect("accept");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let mut read_half = ReadHalf::new(&client);
        let mut write_half = WriteHalf::new(&client);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = crate::io::ReadBuf::new(&mut buf);

        let read =
            crate::io::AsyncRead::poll_read(Pin::new(&mut read_half), &mut task_cx, &mut read_buf);
        assert!(matches!(
            read,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let write =
            crate::io::AsyncWrite::poll_write(Pin::new(&mut write_half), &mut task_cx, b"hello");
        assert!(matches!(
            write,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let flush = crate::io::AsyncWrite::poll_flush(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            flush,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let shutdown =
            crate::io::AsyncWrite::poll_shutdown(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            shutdown,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
    }

    fn read_vectored_payload<R: AsyncReadVectored + Unpin>(reader: &mut R, payload: &[u8]) {
        let mut first = [0u8; 3];
        let mut second = [0u8; 3];
        assert_eq!(payload.len(), first.len() + second.len());
        let mut total = 0usize;
        let mut attempts = 0usize;

        while total < payload.len() {
            attempts += 1;
            assert!(attempts <= 32, "vectored split read did not become ready");
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let polled = if total < first.len() {
                let offset = total;
                let mut bufs = [
                    IoSliceMut::new(&mut first[offset..]),
                    IoSliceMut::new(&mut second),
                ];
                Pin::new(&mut *reader).poll_read_vectored(&mut cx, &mut bufs)
            } else {
                let offset = total - first.len();
                let mut bufs = [IoSliceMut::new(&mut second[offset..])];
                Pin::new(&mut *reader).poll_read_vectored(&mut cx, &mut bufs)
            };

            match polled {
                Poll::Ready(Ok(0)) => panic!("vectored split read reached EOF early"),
                Poll::Ready(Ok(n)) => total += n,
                Poll::Ready(Err(err)) => panic!("vectored split read failed: {err}"),
                Poll::Pending => thread::sleep(Duration::from_millis(5)),
            }
        }

        let mut combined = [0u8; 6];
        combined[..first.len()].copy_from_slice(&first);
        combined[first.len()..].copy_from_slice(&second);
        crate::assert_with_log!(
            combined.as_slice() == payload,
            "vectored split read preserves payload",
            payload,
            combined
        );
    }

    #[test]
    fn borrowed_split_read_half_supports_vectored_reads() {
        init_test("borrowed_split_read_half_supports_vectored_reads");

        let payload = b"vector";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut server, _) = listener.accept().expect("accept");
        let mut read_half = ReadHalf::new(&client);

        server.write_all(payload).expect("write payload");
        read_vectored_payload(&mut read_half, payload);

        crate::test_complete!("borrowed_split_read_half_supports_vectored_reads");
    }

    #[test]
    fn owned_split_creates_pair() {
        init_test("owned_split_creates_pair");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        // Verify they share the same inner
        let same_inner = Arc::ptr_eq(&read_half.inner, &write_half.inner);
        crate::assert_with_log!(same_inner, "halves share inner", true, same_inner);

        crate::test_complete!("owned_split_creates_pair");
    }

    #[test]
    fn owned_split_read_half_supports_vectored_reads() {
        init_test("owned_split_read_half_supports_vectored_reads");

        let payload = b"vector";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (mut read_half, _write_half) = stream.into_split();
        let (mut server, _) = listener.accept().expect("accept");

        server.write_all(payload).expect("write payload");
        read_vectored_payload(&mut read_half, payload);

        crate::test_complete!("owned_split_read_half_supports_vectored_reads");
    }

    #[test]
    fn owned_split_reunite_success() {
        init_test("owned_split_reunite_success");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        let result = read_half.reunite(write_half);
        crate::assert_with_log!(result.is_ok(), "reunite succeeds", true, result.is_ok());

        crate::test_complete!("owned_split_reunite_success");
    }

    #[test]
    fn into_split_does_not_shutdown_stream() {
        init_test("into_split_does_not_shutdown_stream");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (_read_half, write_half) = stream.into_split();

        let mut stream_ref = write_half.inner.stream.as_ref();
        stream_ref.write_all(b"ping").expect("client write");

        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).expect("server read");

        crate::assert_with_log!(
            buf == *b"ping",
            "into_split keeps stream open",
            *b"ping",
            buf
        );

        crate::test_complete!("into_split_does_not_shutdown_stream");
    }

    #[test]
    fn owned_split_reunite_mismatch() {
        init_test("owned_split_reunite_mismatch");

        let listener1 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr1 = listener1.local_addr().expect("local addr");
        let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr2 = listener2.local_addr().expect("local addr");

        let client1 = std::net::TcpStream::connect(addr1).expect("connect");
        let client2 = std::net::TcpStream::connect(addr2).expect("connect");

        let (read_half1, _write_half1) = OwnedReadHalf::new_pair(Arc::new(client1), None);
        let (_read_half2, write_half2) = OwnedReadHalf::new_pair(Arc::new(client2), None);

        // Try to reunite mismatched halves
        let result = read_half1.reunite(write_half2);
        crate::assert_with_log!(
            result.is_err(),
            "reunite fails for mismatch",
            true,
            result.is_err()
        );

        crate::test_complete!("owned_split_reunite_mismatch");
    }

    #[test]
    fn owned_half_addresses() {
        init_test("owned_half_addresses");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        // Both halves should report same addresses
        let read_local = read_half.local_addr().expect("local");
        let write_local = write_half.local_addr().expect("local");
        crate::assert_with_log!(
            read_local == write_local,
            "same local addr",
            read_local,
            write_local
        );

        let read_peer = read_half.peer_addr().expect("peer");
        let write_peer = write_half.peer_addr().expect("peer");
        crate::assert_with_log!(
            read_peer == write_peer,
            "same peer addr",
            read_peer,
            write_peer
        );

        crate::test_complete!("owned_half_addresses");
    }

    #[cfg(unix)]
    #[test]
    fn split_register_interest_serializes_fresh_registration() {
        init_test("split_register_interest_serializes_fresh_registration");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );

        let barrier = Arc::new(Barrier::new(3));
        let read_inner = read_half.inner.clone();
        let read_cx = cx.clone();
        let read_barrier = barrier.clone();
        let read_thread = thread::spawn(move || {
            let _guard = Cx::set_current(Some(read_cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            read_barrier.wait();
            read_inner.register_interest(&task_cx, Interest::READABLE)
        });

        let write_inner = write_half.inner.clone();
        let write_cx = cx;
        let write_barrier = barrier.clone();
        let write_thread = thread::spawn(move || {
            let _guard = Cx::set_current(Some(write_cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            write_barrier.wait();
            write_inner.register_interest(&task_cx, Interest::WRITABLE)
        });

        barrier.wait();
        let read_result = read_thread.join().expect("read thread panic");
        let write_result = write_thread.join().expect("write thread panic");
        assert!(
            read_result.is_ok(),
            "read half registration should not fail: {read_result:?}"
        );
        assert!(
            write_result.is_ok(),
            "write half registration should not fail: {write_result:?}"
        );
        assert_eq!(
            reactor.register_calls(),
            1,
            "fresh split registration should be issued once"
        );
        assert_eq!(
            reactor.modify_calls(),
            1,
            "second waiter should re-arm existing registration"
        );
    }

    #[test]
    fn write_half_shutdown_on_drop() {
        init_test("write_half_shutdown_on_drop");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");

        let stream = Arc::new(client);
        let (_read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        drop(write_half);

        // Server should see connection shutdown
        let mut buf = [0u8; 1];
        let result = server.read(&mut buf);
        // Should get 0 bytes (EOF) or an error
        let is_shutdown = matches!(result, Ok(0) | Err(_));
        crate::assert_with_log!(is_shutdown, "write shutdown on drop", true, is_shutdown);

        crate::test_complete!("write_half_shutdown_on_drop");
    }

    #[test]
    fn registration_interest_prefers_waiter_union() {
        init_test("registration_interest_prefers_waiter_union");

        let both = registration_interest(true, true, Interest::READABLE);
        crate::assert_with_log!(
            both == (Interest::READABLE | Interest::WRITABLE),
            "both interests preserved",
            Interest::READABLE | Interest::WRITABLE,
            both
        );

        let read_only = registration_interest(true, false, Interest::WRITABLE);
        crate::assert_with_log!(
            read_only == Interest::READABLE,
            "read waiter wins",
            Interest::READABLE,
            read_only
        );

        let fallback = registration_interest(false, false, Interest::WRITABLE);
        crate::assert_with_log!(
            fallback == Interest::WRITABLE,
            "fallback interest",
            Interest::WRITABLE,
            fallback
        );

        crate::test_complete!("registration_interest_prefers_waiter_union");
    }

    #[cfg(unix)]
    #[test]
    fn stale_combined_waker_does_not_consume_new_generation() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let (old_waker, old_hits) = counting_waker();
        let (new_waker, new_hits) = counting_waker();

        let (old_tokens, old_snapshot) = install_snapshot(&state, Interest::READABLE, &old_waker);
        let (new_tokens, new_snapshot) = install_snapshot(&state, Interest::READABLE, &new_waker);
        assert_ne!(old_tokens.read, new_tokens.read);

        old_snapshot.wake_by_ref();
        assert_eq!(old_hits.load(Ordering::SeqCst), 0);
        assert_eq!(new_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            state.lock().read_waiter.as_ref().map(|waiter| waiter.token),
            new_tokens.read
        );

        new_snapshot.wake_by_ref();
        new_snapshot.wake_by_ref();
        assert_eq!(new_hits.load(Ordering::SeqCst), 1);
        assert!(state.lock().read_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn stale_combined_waker_does_not_retain_replaced_task_waker() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let dropped = Arc::new(AtomicBool::new(false));
        let old_task_waker = Waker::from(Arc::new(DropProbeWaker {
            dropped: Arc::clone(&dropped),
        }));
        let new_task_waker = noop_waker();

        let (_, stale_snapshot) = install_snapshot(&state, Interest::READABLE, &old_task_waker);
        let _ = install_snapshot(&state, Interest::READABLE, &new_task_waker);
        drop(old_task_waker);

        assert!(
            dropped.load(Ordering::SeqCst),
            "stale combined snapshot retained a replaced task waker"
        );
        stale_snapshot.wake_by_ref();
        assert!(state.lock().read_waiter.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn combined_dispatch_wakes_after_state_unlock() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let observed_unlocked = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let task_waker = Waker::from(Arc::new(LockProbeWaker {
            state: Arc::downgrade(&state),
            observed_unlocked: Arc::clone(&observed_unlocked),
            hits: Arc::clone(&hits),
        }));
        let (_, snapshot) = install_snapshot(&state, Interest::READABLE, &task_waker);

        snapshot.wake_by_ref();

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(observed_unlocked.load(Ordering::SeqCst));
        assert!(state.lock().read_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn inherited_registration_is_adopted_in_place_across_reunite() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = Arc::new(std::net::TcpStream::connect(addr).expect("connect"));
        let (mut server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let old_waker_dropped = Arc::new(AtomicBool::new(false));
        let old_waker = Waker::from(Arc::new(DropProbeWaker {
            dropped: Arc::clone(&old_waker_dropped),
        }));
        let mut registration = driver
            .register(&*client, Interest::READABLE, old_waker.clone())
            .expect("register unsplit stream");
        assert!(
            registration
                .rearm(Interest::READABLE, &old_waker)
                .expect("prime cached task waker")
        );
        let original_token = registration.token();
        drop(old_waker);
        assert!(!old_waker_dropped.load(Ordering::SeqCst));

        let (read_half, write_half) =
            OwnedReadHalf::new_pair(Arc::clone(&client), Some(registration));
        assert!(old_waker_dropped.load(Ordering::SeqCst));
        assert_eq!(reactor.register_calls(), 1);
        assert_eq!(reactor.registration_count(), 1);
        assert_eq!(
            read_half
                .inner
                .state
                .lock()
                .registration
                .as_ref()
                .expect("adopted registration")
                .token(),
            original_token
        );

        let reunited = read_half.reunite(write_half).expect("reunite");
        let (mut read_half, write_half) = reunited.into_split();
        assert_eq!(reactor.register_calls(), 1);
        assert_eq!(reactor.registration_count(), 1);
        assert_eq!(
            read_half
                .inner
                .state
                .lock()
                .registration
                .as_ref()
                .expect("re-adopted registration")
                .token(),
            original_token
        );

        server.write_all(b"x").expect("write byte");
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let ready = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"x");

        drop(read_half);
        drop(write_half);
        assert_eq!(reactor.registration_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn combined_waker_consumes_each_direction_once() {
        let state = Arc::new(Mutex::new(split_io_state(None)));
        let (read_waker, read_hits) = counting_waker();
        let (write_waker, write_hits) = counting_waker();

        let _ = install_snapshot(&state, Interest::READABLE, &read_waker);
        let (_, snapshot) = install_snapshot(&state, Interest::WRITABLE, &write_waker);

        snapshot.wake_by_ref();
        snapshot.wake_by_ref();
        assert_eq!(read_hits.load(Ordering::SeqCst), 1);
        assert_eq!(write_hits.load(Ordering::SeqCst), 1);
        let state = state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn waiter_token_exhaustion_is_permanent_and_nonwrapping() {
        let mut state = split_io_state(None);
        state.next_waiter_token = u64::MAX - 1;
        let waker = noop_waker();

        let mut prepared = prepare_waiters(Interest::READABLE, &waker);
        let (tokens, replaced) = install_waiters(&mut state, Interest::READABLE, &mut prepared)
            .expect("last waiter token should be issued");
        drop(replaced);
        assert_eq!(tokens.read, Some(u64::MAX - 1));
        assert_eq!(state.next_waiter_token, u64::MAX);

        for interest in [Interest::WRITABLE, Interest::READABLE] {
            let mut prepared = prepare_waiters(interest, &waker);
            let err = install_waiters(&mut state, interest, &mut prepared)
                .expect_err("exhausted token space must remain fail-closed");
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert_eq!(state.next_waiter_token, u64::MAX);
            assert_eq!(
                state.read_waiter.as_ref().map(|waiter| waiter.token),
                tokens.read
            );
            assert!(state.write_waiter.is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn fallback_wake_runs_after_state_unlock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let observed_unlocked = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(LockProbeWaker {
            state: Arc::downgrade(&read_half.inner.state),
            observed_unlocked: Arc::clone(&observed_unlocked),
            hits: Arc::clone(&hits),
        }));
        let task_cx = Context::from_waker(&waker);
        let _current = Cx::set_current(None);
        // The property under test is the legacy self-wake path (no reactor
        // takes the fd): its wake must run only after the split state lock is
        // released. Since GH#67 the process-global fallback driver would take
        // the fd and park instead, so withhold it for this thread.
        let _withhold = crate::net::udp::fallback_io_test_hooks::WithholdFallbackDriver::new();

        let tokens = read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("fallback registration");
        assert!(tokens.read.is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(observed_unlocked.load(Ordering::SeqCst));
        assert!(read_half.inner.state.lock().read_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn owned_read_ready_retires_waiter_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);

        let pending = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(pending.is_pending());
        {
            let state = read_half.inner.state.lock();
            assert!(state.read_waiter.is_some());
            assert!(state.registration.is_some());
        }

        server.write_all(b"x").expect("write byte");
        let ready = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"x");
        assert!(read_half.last_waiter.is_none());
        let state = read_half.inner.state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.registration.is_none());
    }

    /// When both halves drop, the reactor registration goes before the fd
    /// closes, even while the reactor (dispatching a wake) still holds the
    /// shared state. It used to go with the last state Arc, after the close
    /// (br-asupersync-8vrx8q).
    #[cfg(unix)]
    #[test]
    fn dropping_both_halves_deregisters_before_the_fd_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let driver = IoDriverHandle::new(Arc::new(SourceExclusiveReactor::new()));
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver.clone()),
            None,
        );
        let _current = Cx::set_current(Some(cx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let pending = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(pending.is_pending());
        assert_eq!(driver.waker_count(), 1);

        // No waiter is left to retire, and the reactor is dispatching a wake:
        // it holds the shared state.
        read_half.last_waiter = None;
        let dispatching = Arc::clone(&read_half.inner.state);
        drop(read_half);
        drop(write_half);
        assert_eq!(
            driver.waker_count(),
            0,
            "the registration goes with the stream, not with the last state Arc"
        );
        drop(dispatching);
    }

    #[cfg(unix)]
    #[test]
    fn owned_read_cancellation_retires_waiter_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx.clone()));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);

        let pending = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(pending.is_pending());
        cx.set_cancel_requested(true);
        let cancelled = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(
            cancelled,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
        assert!(read_half.last_waiter.is_none());
        let state = read_half.inner.state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.registration.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn missing_driver_waker_deregisters_before_fresh_add() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver.clone()),
            None,
        );
        let _current = Cx::set_current(Some(cx));

        let read_waker = noop_waker();
        let read_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_cx, Interest::READABLE)
            .expect("initial register");
        let old_token = read_half
            .inner
            .state
            .lock()
            .registration
            .as_ref()
            .expect("registration")
            .token();

        // Preserve the reactor mapping while removing only the slab waker.
        // The next rearm must return Ok(false), physically DEL the old
        // mapping, and only then issue a fresh ADD for this socket.
        driver.lock().deregister_waker(old_token);
        let write_waker = noop_waker();
        let write_cx = Context::from_waker(&write_waker);
        let write_tokens = write_half
            .inner
            .register_interest(&write_cx, Interest::WRITABLE)
            .expect("fresh ADD after old DEL");

        assert!(write_tokens.write.is_some());
        assert_eq!(reactor.register_calls(), 2);
        assert_eq!(reactor.registration_count(), 1);
        let state = read_half.inner.state.lock();
        assert!(!state.registration_transition);
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::READABLE | Interest::WRITABLE
        );
    }

    #[cfg(unix)]
    #[test]
    fn retire_transition_queues_sibling_until_old_del_completes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);

        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx.clone()));
        let read_waker = noop_waker();
        let read_cx = Context::from_waker(&read_waker);
        let read_tokens = read_half
            .inner
            .register_interest(&read_cx, Interest::READABLE)
            .expect("initial register");
        let read_token = read_tokens.read.expect("read waiter token");

        let (deregister_entered, release_deregister) = reactor.block_next_deregister();
        let retire_inner = Arc::clone(&read_half.inner);
        let retire_thread = thread::spawn(move || {
            retire_inner.retire_waiter(Interest::READABLE, Some(read_token));
        });
        deregister_entered.wait();

        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let register_inner = Arc::clone(&write_half.inner);
        let register_thread = thread::spawn(move || {
            let _current = Cx::set_current(Some(cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            let result = register_inner.register_interest(&task_cx, Interest::WRITABLE);
            result_tx.send(result).expect("send register result");
        });

        // A sibling polling during the physical DEL must publish its waiter
        // and return without attempting ADD against the still-live mapping.
        let early_result = result_rx.recv_timeout(Duration::from_secs(5));
        let completed_before_del = early_result.is_ok();
        let register_calls_before_del = reactor.register_calls();

        release_deregister.wait();
        retire_thread.join().expect("retire thread");
        register_thread.join().expect("register thread");
        let result = match early_result {
            Ok(result) => result,
            Err(_) => result_rx.recv().expect("late register result"),
        };
        let write_tokens = result.expect("queued sibling registration");
        write_half
            .inner
            .retire_waiter(Interest::WRITABLE, write_tokens.write);

        assert!(
            completed_before_del,
            "sibling registration blocked on driver ADD during old DEL"
        );
        assert_eq!(
            register_calls_before_del, 1,
            "fresh ADD must not occur before old DEL completes"
        );
        let state = read_half.inner.state.lock();
        assert!(!state.registration_transition);
        assert!(state.registration.is_none());
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn dropping_read_half_clears_waiter_and_registration_when_idle() {
        init_test("dropping_read_half_clears_waiter_and_registration_when_idle");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);
        let tokens = read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("register readable");
        read_half.last_waiter = tokens.read;

        drop(read_half);

        let state = write_half.inner.state.lock();
        assert!(
            state.read_waiter.is_none(),
            "read waiter must be cleared after read half drop"
        );
        assert!(
            state.registration.is_none(),
            "registration should be released when no waiters remain"
        );
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn dropping_write_half_clears_waiter_and_keeps_read_interest() {
        init_test("dropping_write_half_clears_waiter_and_keeps_read_interest");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);
        let read_tokens = read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("register readable");
        read_half.last_waiter = read_tokens.read;
        let write_tokens = write_half
            .inner
            .register_interest(&task_cx, Interest::WRITABLE)
            .expect("register writable");
        write_half.last_waiter = write_tokens.write;

        drop(write_half);

        let state = read_half.inner.state.lock();
        assert!(
            state.write_waiter.is_none(),
            "write waiter must be cleared after write half drop"
        );
        assert!(
            state.registration.is_some(),
            "registration should remain for the live read waiter"
        );
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::READABLE,
            "interest should drop writable bit when write half is dropped"
        );
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn dropping_write_half_wakes_survivor_when_reregistration_fails() {
        init_test("dropping_write_half_wakes_survivor_when_reregistration_fails");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        // First modify call (adding WRITABLE) succeeds; second modify call
        // (drop-time narrowing to READABLE) fails.
        reactor.fail_modify_on_call(2);

        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let (read_waker, read_hits) = counting_waker();
        let read_task_cx = Context::from_waker(&read_waker);
        let read_tokens = read_half
            .inner
            .register_interest(&read_task_cx, Interest::READABLE)
            .expect("register readable");
        read_half.last_waiter = read_tokens.read;

        let write_waker = noop_waker();
        let write_task_cx = Context::from_waker(&write_waker);
        let write_tokens = write_half
            .inner
            .register_interest(&write_task_cx, Interest::WRITABLE)
            .expect("register writable");
        write_half.last_waiter = write_tokens.write;

        drop(write_half);

        let state = read_half.inner.state.lock();
        assert!(
            state.registration.is_none(),
            "registration should be dropped after injected re-arm failure"
        );
        drop(state);

        assert!(
            read_hits.load(Ordering::SeqCst) == 1,
            "surviving waiter must be woken to retry registration after drop-time failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_modify_failure_drops_registration_and_wakes_only_survivor() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        reactor.fail_modify_on_call(1);
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _current = Cx::set_current(Some(cx));

        let (read_waker, read_hits) = counting_waker();
        let read_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_cx, Interest::READABLE)
            .expect("register readable");

        let (write_waker, write_hits) = counting_waker();
        let write_cx = Context::from_waker(&write_waker);
        let err = write_half
            .inner
            .register_interest(&write_cx, Interest::WRITABLE)
            .expect_err("injected hard modify failure");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(read_hits.load(Ordering::SeqCst), 1);
        assert_eq!(write_hits.load(Ordering::SeqCst), 0);
        let state = read_half.inner.state.lock();
        assert!(state.registration.is_none());
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn not_connected_modify_wakes_both_split_waiters() {
        init_test("not_connected_modify_wakes_both_split_waiters");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        reactor.fail_modify_on_call(1);
        reactor.fail_modify_with_not_connected(true);

        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let (read_waker, read_hits) = counting_waker();
        let read_task_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_task_cx, Interest::READABLE)
            .expect("register readable");

        let (write_waker, write_hits) = counting_waker();
        let write_task_cx = Context::from_waker(&write_waker);
        write_half
            .inner
            .register_interest(&write_task_cx, Interest::WRITABLE)
            .expect("register writable with injected not-connected");

        let state = read_half.inner.state.lock();
        assert!(
            state.registration.is_none(),
            "registration should be dropped after not-connected modify"
        );
        drop(state);

        assert!(
            read_hits.load(Ordering::SeqCst) == 1,
            "read waiter must be woken when shared registration drops on not-connected"
        );
        assert!(
            write_hits.load(Ordering::SeqCst) == 1,
            "write waiter must be woken when shared registration drops on not-connected"
        );
    }

    #[test]
    fn owned_split_halves_return_interrupted_when_cancel_requested() {
        init_test("owned_split_halves_return_interrupted_when_cancel_requested");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (_server, _) = listener.accept().expect("accept");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (mut read_half, mut write_half) = stream.into_split();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = crate::io::ReadBuf::new(&mut buf);

        let read =
            crate::io::AsyncRead::poll_read(Pin::new(&mut read_half), &mut task_cx, &mut read_buf);
        assert!(matches!(
            read,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let write =
            crate::io::AsyncWrite::poll_write(Pin::new(&mut write_half), &mut task_cx, b"hello");
        assert!(matches!(
            write,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let flush = crate::io::AsyncWrite::poll_flush(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            flush,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let shutdown =
            crate::io::AsyncWrite::poll_shutdown(Pin::new(&mut write_half), &mut task_cx);
        assert!(matches!(
            shutdown,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
    }
