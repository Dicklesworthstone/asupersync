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
    use crate::runtime::reactor::{Events, Reactor, Source, Token};

    /// GH#67 follow-up (asupersync-9e6a28): an owned Unix split half polled
    /// with no I/O driver on the current `Cx` parks on the process-global
    /// fallback driver instead of re-waking itself into a hot loop.
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use crate::runtime::{IoDriverHandle, LabReactor};
        use crate::types::{Budget, RegionId, TaskId};
        use std::pin::Pin;
        use std::sync::atomic::Ordering;
        use std::task::{Context, Poll};
        use std::time::Duration;

        /// A connected, non-blocking pair: the owned halves under test and
        /// the std peer that can make them readable at will.
        fn split_pair() -> (OwnedReadHalf, OwnedWriteHalf, net::UnixStream) {
            let (ours, peer) = net::UnixStream::pair().expect("socket pair");
            ours.set_nonblocking(true).expect("nonblocking");
            let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(ours), None);
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

        /// When both halves drop, the reactor registration goes before the fd
        /// closes, even while the reactor (dispatching a wake) still holds the
        /// shared state (br-asupersync-8vrx8q).
        #[test]
        fn dropping_both_halves_deregisters_before_the_fd_closes() {
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
            let (mut read_half, write_half, _peer) = split_pair();
            let (_signal, waker, _rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 8];
            assert!(matches!(
                poll_read_once(&mut read_half, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert_eq!(driver.waker_count(), 1);

            // No waiter is left to retire, and the reactor is dispatching a
            // wake: it holds the shared state.
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
    }
    use crate::runtime::{Event, IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct CountingWaker {
        hits: Arc<AtomicUsize>,
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Waker, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        (waker, hits)
    }

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

    struct LockProbeWaker {
        state: Weak<Mutex<SplitIoState>>,
        observed_unlocked: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
    }

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

    #[derive(Default)]
    struct SourceExclusiveState {
        source_to_token: HashMap<i32, Token>,
        token_to_source: HashMap<Token, i32>,
    }

    /// Minimal reactor that rejects a second live registration for one fd.
    /// This models epoll's ADD-before-DEL `EEXIST` behavior deterministically.
    #[derive(Default)]
    struct SourceExclusiveReactor {
        state: Mutex<SourceExclusiveState>,
    }

    impl Reactor for SourceExclusiveReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            let fd = source.raw_fd();
            let mut state = self.state.lock();
            if state.source_to_token.contains_key(&fd) || state.token_to_source.contains_key(&token)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "source or token already registered",
                ));
            }
            state.source_to_token.insert(fd, token);
            state.token_to_source.insert(token, fd);
            Ok(())
        }

        fn modify(&self, token: Token, _interest: Interest) -> io::Result<()> {
            if self.state.lock().token_to_source.contains_key(&token) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ))
            }
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let mut state = self.state.lock();
            let Some(fd) = state.token_to_source.remove(&token) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            };
            state.source_to_token.remove(&fd);
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
    fn test_borrowed_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let _read = ReadHalf::new(&s1);
        let _write = WriteHalf::new(&s1);
    }

    #[test]
    fn test_owned_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (_read, _write) = stream.into_split();
    }

    #[test]
    fn test_reunite_success() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (read, write) = stream.into_split();

        // Should succeed - same stream
        let _reunited = read.reunite(write).expect("reunite should succeed");
    }

    #[test]
    fn test_reunite_failure() {
        let (s1, _s2a) = net::UnixStream::pair().expect("pair failed");
        let (s2, _s2b) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");
        s2.set_nonblocking(true).expect("set_nonblocking failed");

        let stream1 = super::super::UnixStream::from_std(s1).expect("wrap stream1");
        let stream2 = super::super::UnixStream::from_std(s2).expect("wrap stream2");

        let (read1, _write1) = stream1.into_split();
        let (_read2, write2) = stream2.into_split();

        // Should fail - different streams
        let err = read1.reunite(write2).expect_err("reunite should fail");
        assert!(err.to_string().contains("not from the same socket"));
    }

    #[test]
    fn registration_interest_prefers_waiter_union() {
        let both = registration_interest(true, true, Interest::READABLE);
        assert_eq!(both, Interest::READABLE | Interest::WRITABLE);

        let write_only = registration_interest(false, true, Interest::READABLE);
        assert_eq!(write_only, Interest::WRITABLE);

        let fallback = registration_interest(false, false, Interest::READABLE);
        assert_eq!(fallback, Interest::READABLE);
    }

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

    #[test]
    fn inherited_registration_is_adopted_in_place_across_reunite() {
        let (stream, mut peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let stream = Arc::new(stream);
        let reactor = Arc::new(SourceExclusiveReactor::default());
        let driver = IoDriverHandle::new(reactor.clone());
        let registration = driver
            .register(&*stream, Interest::READABLE, noop_waker())
            .expect("register unsplit stream");
        let original_token = registration.token();

        let (read_half, write_half) =
            OwnedReadHalf::new_pair(Arc::clone(&stream), Some(registration));
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

        peer.write_all(b"x").expect("write byte");
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

    #[test]
    fn reactor_readiness_consumes_union_then_rearms_only_current_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let reactor = Arc::new(LabReactor::new());
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
        let (read_waker, read_hits) = counting_waker();
        let (write_waker, write_hits) = counting_waker();

        let read_tokens = read_half
            .inner
            .register_interest(&Context::from_waker(&read_waker), Interest::READABLE)
            .expect("register read");
        read_half.last_waiter = read_tokens.read;
        let write_tokens = write_half
            .inner
            .register_interest(&Context::from_waker(&write_waker), Interest::WRITABLE)
            .expect("register write");
        write_half.last_waiter = write_tokens.write;
        let token = {
            let state = read_half.inner.state.lock();
            let registration = state.registration.as_ref().expect("registration");
            assert_eq!(
                registration.interest(),
                Interest::READABLE | Interest::WRITABLE
            );
            registration.token()
        };

        reactor.set_ready(token, Event::readable(token));
        assert_eq!(
            driver
                .turn_with(Some(Duration::ZERO), |_, _| {})
                .expect("driver turn"),
            1
        );
        assert_eq!(read_hits.load(Ordering::SeqCst), 1);
        assert_eq!(write_hits.load(Ordering::SeqCst), 1);
        {
            let state = read_half.inner.state.lock();
            assert!(state.read_waiter.is_none());
            assert!(state.write_waiter.is_none());
        }

        let (next_write_waker, _) = counting_waker();
        let next_write_tokens = write_half
            .inner
            .register_interest(&Context::from_waker(&next_write_waker), Interest::WRITABLE)
            .expect("re-register write");
        write_half.last_waiter = next_write_tokens.write;
        let state = write_half.inner.state.lock();
        assert!(state.read_waiter.is_none());
        assert!(state.write_waiter.is_some());
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::WRITABLE
        );
    }

    #[test]
    fn missing_driver_waker_deregisters_before_fresh_registration() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let reactor = Arc::new(SourceExclusiveReactor::default());
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
        read_half
            .inner
            .register_interest(&Context::from_waker(&read_waker), Interest::READABLE)
            .expect("initial read registration");
        let old_token = read_half
            .inner
            .state
            .lock()
            .registration
            .as_ref()
            .expect("initial registration")
            .token();

        // Leave the reactor registration live while removing only the driver's
        // waker slot. The next rearm must return Ok(false), transition through
        // a complete DEL, and only then issue the replacement ADD.
        driver.lock().deregister_waker(old_token);

        let write_waker = noop_waker();
        write_half
            .inner
            .register_interest(&Context::from_waker(&write_waker), Interest::WRITABLE)
            .expect("fresh registration after missing driver waker");

        let state = read_half.inner.state.lock();
        assert!(!state.registration_transition);
        assert!(state.read_waiter.is_some());
        assert!(state.write_waiter.is_some());
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("replacement registration")
                .interest(),
            Interest::READABLE | Interest::WRITABLE
        );
        assert_eq!(reactor.registration_count(), 1);
    }

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

    #[test]
    fn exact_retirement_does_not_remove_newer_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let (old_waker, _old_hits) = counting_waker();
        let (new_waker, _new_hits) = counting_waker();

        let (old_tokens, _) =
            install_snapshot(&read_half.inner.state, Interest::READABLE, &old_waker);
        let (new_tokens, _) =
            install_snapshot(&read_half.inner.state, Interest::READABLE, &new_waker);
        read_half
            .inner
            .retire_waiter(Interest::READABLE, old_tokens.read);
        assert_eq!(
            read_half
                .inner
                .state
                .lock()
                .read_waiter
                .as_ref()
                .map(|waiter| waiter.token),
            new_tokens.read
        );
    }

    #[test]
    fn fallback_wake_runs_after_state_unlock() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
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

    #[test]
    fn owned_read_ready_retires_waiter() {
        let (stream, mut peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let waker = noop_waker();
        let tokens = {
            let mut prepared = prepare_waiters(Interest::READABLE, &waker);
            let mut state = read_half.inner.state.lock();
            let (tokens, replaced) = install_waiters(&mut state, Interest::READABLE, &mut prepared)
                .expect("install read");
            drop(state);
            drop(replaced);
            tokens
        };
        read_half.last_waiter = tokens.read;
        peer.write_all(b"x").expect("write byte");

        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let ready = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"x");
        assert!(read_half.last_waiter.is_none());
        assert!(read_half.inner.state.lock().read_waiter.is_none());
    }

    #[test]
    fn owned_read_cancellation_retires_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (mut read_half, _write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let waker = noop_waker();
        let tokens = {
            let mut prepared = prepare_waiters(Interest::READABLE, &waker);
            let mut state = read_half.inner.state.lock();
            let (tokens, replaced) = install_waiters(&mut state, Interest::READABLE, &mut prepared)
                .expect("install read");
            drop(state);
            drop(replaced);
            tokens
        };
        read_half.last_waiter = tokens.read;

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _current = Cx::set_current(Some(cx));
        let mut task_cx = Context::from_waker(&waker);
        let mut bytes = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut bytes);
        let cancelled = Pin::new(&mut read_half).poll_read(&mut task_cx, &mut read_buf);
        assert!(matches!(
            cancelled,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
        assert!(read_half.last_waiter.is_none());
        assert!(read_half.inner.state.lock().read_waiter.is_none());
    }

    #[test]
    fn synchronous_shutdown_retires_write_waiter() {
        let (stream, _peer) = net::UnixStream::pair().expect("pair");
        stream.set_nonblocking(true).expect("nonblocking");
        let (_read_half, mut write_half) = OwnedReadHalf::new_pair(Arc::new(stream), None);
        let waker = noop_waker();
        let tokens = {
            let mut prepared = prepare_waiters(Interest::WRITABLE, &waker);
            let mut state = write_half.inner.state.lock();
            let (tokens, replaced) = install_waiters(&mut state, Interest::WRITABLE, &mut prepared)
                .expect("install write");
            drop(state);
            drop(replaced);
            tokens
        };
        write_half.last_waiter = tokens.write;

        write_half.shutdown().expect("shutdown write");
        assert!(write_half.inner.state.lock().write_waiter.is_none());
    }

    #[test]
    fn borrowed_split_halves_return_interrupted_when_cancel_requested() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let mut read_half = ReadHalf::new(&s1);
        let mut write_half = WriteHalf::new(&s1);
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

    #[test]
    fn owned_split_halves_return_interrupted_when_cancel_requested() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
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
