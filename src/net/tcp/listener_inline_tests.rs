    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::reactor::{Events, Reactor, Source, Token};
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::cell::Cell;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Waker};
    use std::time::Instant;

    thread_local! {
        static TEST_NOW_NANOS: Cell<u64> = const { Cell::new(0) };
    }

    /// GH#67 follow-up (asupersync-2rb75p): a `TcpListener` polled for a
    /// connection with no I/O driver on the current `Cx` parks on the
    /// process-global fallback driver instead of re-waking its accept
    /// waiters into a hot loop.
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use std::time::Duration;

        #[test]
        fn poll_accept_without_io_driver_parks_until_a_peer_connects() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let std_listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
            let addr = std_listener.local_addr().expect("listener addr");
            let listener = TcpListener::from_std(std_listener).expect("wrap listener");
            let (signal, waker, rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);

            assert!(matches!(listener.poll_accept(&mut task_cx), Poll::Pending));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless accept poll must park, not self-wake (GH#67)"
            );
            assert!(
                listener.registration.lock().on_fallback(),
                "driverless accept registers with the process-global fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while nobody connects"
            );

            let _peer = net::TcpStream::connect(addr).expect("peer connect");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);
            match listener.poll_accept(&mut task_cx) {
                Poll::Ready(Ok((_stream, _addr))) => {}
                other => panic!("expected the connection after the wake, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_bind() {
        // We can't await in a sync test without a runtime, but we can check if bind returns a future.
        // Or we can use `futures_lite::future::block_on`.

        futures_lite::future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).await.expect("bind failed");
            assert!(listener.local_addr().is_ok());
        });
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW_NANOS.with(|t| t.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW_NANOS.with(std::cell::Cell::get))
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

    #[test]
    fn listener_registers_on_wouldblock() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        raw.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(LabReactor::new());
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

        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = listener.poll_accept(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        let registered = listener.registration.lock().is_some();
        assert!(registered);
    }

    struct HookReactor {
        on_register: Arc<dyn Fn() + Send + Sync>,
        registrations: AtomicUsize,
    }

    impl std::fmt::Debug for HookReactor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HookReactor")
                .field("registrations", &self.registrations.load(Ordering::SeqCst))
                .finish_non_exhaustive()
        }
    }

    impl Reactor for HookReactor {
        fn register(
            &self,
            _source: &dyn Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            self.registrations.fetch_add(1, Ordering::SeqCst);
            (self.on_register)();
            Ok(())
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            self.registrations
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_sub(1)
                })
                .ok();
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
            self.registrations.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn listener_accepts_connection_that_arrives_during_register_window() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = raw.local_addr().expect("local addr");
        raw.set_nonblocking(true).expect("nonblocking");

        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let reactor = Arc::new(HookReactor {
            on_register: Arc::new(move || {
                let _client = net::TcpStream::connect(addr).expect("client connect");
            }),
            registrations: AtomicUsize::new(0),
        });
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
        let mut cx = Context::from_waker(&waker);

        let poll = listener.poll_accept(&mut cx);
        let Poll::Ready(Ok((_stream, peer_addr))) = poll else {
            panic!("post-register accept recheck should catch the queued connection");
        };

        assert_eq!(peer_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[cfg(unix)]
    #[test]
    fn listener_from_std_forces_nonblocking_mode() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let flags = fcntl(&listener.inner, FcntlArg::F_GETFL).expect("read listener flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "TcpListener::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn fallback_accept_retry_without_timer_wakes_immediately() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let waiters = Arc::new(AcceptWaiters::default());
        waiters.register(None, &waker);
        let started = Instant::now();

        schedule_accept_retry(
            InterestRegistrationMode::FallbackPoll,
            Duration::from_millis(20),
            &waiters,
        );

        assert!(
            started.elapsed() < Duration::from_millis(10),
            "fallback accept retry must not sleep inline when no timer driver exists"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "fallback accept retry should self-wake when no timer driver exists"
        );
    }

    #[test]
    fn reactor_armed_accept_retry_without_timer_does_not_self_wake() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let waiters = Arc::new(AcceptWaiters::default());
        waiters.register(None, &waker);
        let started = Instant::now();

        schedule_accept_retry(
            InterestRegistrationMode::ReactorArmed,
            Duration::from_millis(20),
            &waiters,
        );

        assert!(
            started.elapsed() < Duration::from_millis(10),
            "reactor-armed accept retry must not sleep inline when no timer driver exists"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "reactor-armed accept retry should rely on the reactor instead of self-waking"
        );
    }

    #[test]
    fn listener_fanout_wakes_all_pending_accept_waiters() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        raw.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(LabReactor::new());
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

        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let hits1 = Arc::new(AtomicUsize::new(0));
        let hits2 = Arc::new(AtomicUsize::new(0));
        let waker1 = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits1),
        }));
        let waker2 = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits2),
        }));
        let mut cx1 = Context::from_waker(&waker1);
        let mut cx2 = Context::from_waker(&waker2);

        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));
        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Pending));

        listener.accept_waiters.wake_all();

        assert_eq!(hits1.load(Ordering::SeqCst), 1);
        assert_eq!(hits2.load(Ordering::SeqCst), 1);
    }

    /// More accept() futures than the 32-entry cap the waiter list used to
    /// evict from: registering one must not wake another (the 33rd used to
    /// evict and wake the first, which evicted the next, forever), and a
    /// dropped accept() future must take its waiter with it.
    #[test]
    fn many_pending_accepts_neither_wake_each_other_nor_outlive_their_futures() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        raw.set_nonblocking(true).expect("nonblocking");
        let reactor = Arc::new(LabReactor::new());
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
        let listener = TcpListener::from_std(raw).expect("wrap listener");
        let hits: Vec<Arc<AtomicUsize>> = (0..40).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let wakers: Vec<Waker> = hits
            .iter()
            .map(|hits| {
                Waker::from(Arc::new(CountingWaker {
                    hits: Arc::clone(hits),
                }))
            })
            .collect();
        let mut accepts: Vec<_> = (0..40).map(|_| Box::pin(listener.accept())).collect();
        for (accept, waker) in accepts.iter_mut().zip(&wakers) {
            let mut task_cx = Context::from_waker(waker);
            assert!(accept.as_mut().poll(&mut task_cx).is_pending());
        }
        let woken: usize = hits.iter().map(|hits| hits.load(Ordering::SeqCst)).sum();
        assert_eq!(woken, 0, "a pending accept must not wake another");
        assert_eq!(listener.accept_waiters.waiters.lock().len(), 40);

        drop(accepts);
        assert!(
            listener.accept_waiters.waiters.lock().is_empty(),
            "a dropped accept() future must remove its waiter"
        );
    }

    #[test]
    fn accept_storm_window_respects_custom_time_getter() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        set_test_time(0);
        let listener = TcpListener::from_std_with_time_getter(raw, test_time).expect("wrap");

        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            1,
            "first would-block should start the storm counter"
        );

        set_test_time(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            2,
            "within-window would-block should increment the storm counter"
        );

        set_test_time(
            Duration::from_millis(60)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            1,
            "outside-window would-block should reset the storm counter"
        );
    }

    #[test]
    fn accept_storm_window_from_std_uses_runtime_timer_driver() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer),
            None,
        );
        let _guard = Cx::set_current(Some(cx));
        let listener = TcpListener::from_std(raw).expect("wrap");

        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );

        clock.advance(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            2,
            "from_std should use Cx timer-driver time when available"
        );

        clock.advance(
            Duration::from_millis(60)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            listener.note_accept_would_block(),
            REARMED_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            1,
            "from_std should reset outside the storm window using runtime time"
        );
    }

    #[test]
    fn accept_storm_backoff_escalates_without_sleep() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        set_test_time(0);
        let listener = TcpListener::from_std_with_time_getter(raw, test_time).expect("wrap");

        let mut backoff = Duration::ZERO;
        for idx in 0..65 {
            set_test_time(
                Duration::from_millis(idx)
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
            );
            backoff = listener.note_accept_would_block();
        }

        assert_eq!(
            backoff,
            REARMED_ACCEPT_BACKOFF_BASE.saturating_mul(2),
            "65 consecutive would-blocks inside the storm window should double the backoff"
        );
        assert_eq!(
            listener.accept_storm.lock().consecutive_would_block,
            65,
            "storm counter should track the deterministic sequence length"
        );
    }
