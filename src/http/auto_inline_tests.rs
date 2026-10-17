    use super::*;
    use crate::http::h1::server::{HostPolicy, Http1Config};
    use crate::http::h1::types::Response;
    use crate::http::h2::client::Http2Client;
    use crate::io::AsyncWriteExt;
    use crate::runtime::RuntimeBuilder;
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Wake, Waker};

    struct WakeFlag(AtomicBool);

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn detection_admission_and_idle_wait_cover_every_slot() {
        let tasks = Arc::new(DetectionTasks::default());
        assert!(tasks.acquire(0).is_none());
        let first = tasks.acquire(2).expect("first slot");
        let second = tasks.acquire(2).expect("second slot");
        assert!(tasks.acquire(2).is_none());
        assert_eq!(tasks.active.load(Ordering::Acquire), 2);

        let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        let mut idle = pin!(tasks.wait_idle());
        assert!(idle.as_mut().poll(&mut cx).is_pending());
        drop(first);
        assert!(idle.as_mut().poll(&mut cx).is_pending());
        assert!(!flag.0.load(Ordering::Acquire));
        drop(second);
        assert!(flag.0.load(Ordering::Acquire));
        assert!(idle.as_mut().poll(&mut cx).is_ready());

        // A completed burst may leave a notification permit. It must not
        // make a later drain finish while a new connection is still owned.
        let slot = tasks.acquire(1).expect("reused capacity");
        let mut idle = pin!(tasks.wait_idle());
        assert!(idle.as_mut().poll(&mut cx).is_pending());
        drop(slot);
        assert!(idle.as_mut().poll(&mut cx).is_ready());
        assert_eq!(tasks.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn shutdown_preempts_detection_and_drops_it_before_completion() {
        struct PendingOperation<'a> {
            polls: &'a AtomicUsize,
            dropped: &'a AtomicBool,
        }
        impl Future for PendingOperation<'_> {
            type Output = ();

            fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                Poll::Pending
            }
        }
        impl Drop for PendingOperation<'_> {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        for already_stopped in [false, true] {
            let shutdown = ShutdownSignal::new();
            let polls = AtomicUsize::new(0);
            let dropped = AtomicBool::new(false);
            let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&flag));
            let mut cx = Context::from_waker(&waker);
            if already_stopped {
                shutdown.trigger_immediate();
            }
            let mut operation = pin!(until_shutdown(
                &shutdown,
                PendingOperation {
                    polls: &polls,
                    dropped: &dropped,
                },
            ));
            if !already_stopped {
                assert!(operation.as_mut().poll(&mut cx).is_pending());
                assert_eq!(polls.load(Ordering::Relaxed), 1);
                assert!(!dropped.load(Ordering::Acquire));
                assert!(shutdown.begin_drain(Duration::from_secs(30)));
                assert!(flag.0.load(Ordering::Acquire));
            }
            assert_eq!(operation.as_mut().poll(&mut cx), Poll::Ready(None));
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(polls.load(Ordering::Relaxed), usize::from(!already_stopped));
        }
    }

    #[test]
    fn detection_result_is_preserved_while_running() {
        let shutdown = ShutdownSignal::new();
        let mut operation = pin!(until_shutdown(&shutdown, std::future::ready(42)));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(operation.as_mut().poll(&mut cx), Poll::Ready(Some(42)));
    }

    fn stalled_connection_closes_on_shutdown(mut detection: Detection) {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.spawn(async move {
            // Capture the runtime's clock, as the public listener does.
            detection.shutdown = ShutdownSignal::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let mut client = TcpStream::connect(listener.local_addr().expect("address"))
                .await
                .expect("connect");
            let (stream, peer) = listener.accept().await.expect("accept");
            let tasks = Arc::new(DetectionTasks::default());
            let slot = tasks.acquire(1).expect("detection slot");
            let shutdown = detection.shutdown.clone();
            let mut handoff = pin!(detection.hand_off(DetectingConnection {
                stream,
                peer,
                slot,
            }));

            // This is the actual native TCP read / TLS handshake, polled to
            // Pending before the stop. No sleep guesses that it was reached.
            std::future::poll_fn(|cx| {
                assert!(handoff.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(tasks.active.load(Ordering::Acquire), 1);
            assert!(shutdown.begin_drain(Duration::from_secs(30)));
            crate::time::timeout(now(), Duration::from_secs(2), handoff.as_mut())
                .await
                .expect("shutdown must not wait for the detection deadline");
            assert_eq!(tasks.active.load(Ordering::Acquire), 0);
            let mut buf = [0_u8; 1];
            let read = crate::time::timeout(
                now(),
                Duration::from_secs(2),
                AsyncReadExt::read(&mut client, &mut buf),
            )
            .await
            .expect("detection completion must release the socket")
            .expect("peer read");
            assert_eq!(read, 0, "no protocol response is sent to an undecided peer");
        }));
    }

    fn detection() -> Detection {
        Detection {
            http1: Arc::new(HandoffQueue::default()),
            http2: Arc::new(HandoffQueue::default()),
            #[cfg(feature = "tls")]
            tls: None,
            timeout: Duration::from_secs(60),
            shutdown: ShutdownSignal::new(),
        }
    }

    #[test]
    fn shutdown_interrupts_a_native_preface_read() {
        stalled_connection_closes_on_shutdown(detection());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shutdown_interrupts_a_native_tls_handshake() {
        use crate::tls::{CertificateChain, PrivateKey, TlsAcceptorBuilder};

        let chain = CertificateChain::from_pem(include_bytes!(
            "../../tests/fixtures/tls/server.crt"
        ))
        .expect("certificate chain");
        let key = PrivateKey::from_pem(include_bytes!("../../tests/fixtures/tls/server.key"))
            .expect("private key");
        let mut detection = detection();
        detection.tls = Some(TlsAcceptorBuilder::new(chain, key).build().expect("acceptor"));
        stalled_connection_closes_on_shutdown(detection);
    }

    fn protocol_shutdown() -> ProtocolShutdown {
        ProtocolShutdown {
            signal: ShutdownSignal::new(),
            http1: ConnectionManager::new(None, ShutdownSignal::new()),
            http2: ConnectionManager::new(None, ShutdownSignal::new()),
            completed: false,
        }
    }

    fn empty_stats() -> ShutdownStats {
        ShutdownStats {
            drained: 0,
            force_closed: 0,
            duration: Duration::ZERO,
            drain_report: None,
        }
    }

    #[test]
    fn force_close_is_forwarded_before_and_during_protocol_drain() {
        for immediate in [false, true] {
            let mut shutdown = protocol_shutdown();
            let second_done = AtomicBool::new(false);
            let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&flag));
            let mut cx = Context::from_waker(&waker);
            assert!(shutdown.signal.begin_drain(Duration::from_secs(60)));
            if immediate {
                shutdown.signal.trigger_immediate();
            }
            let first = std::future::ready(Ok(empty_stats()));
            let second = std::future::poll_fn(|_| {
                if second_done.load(Ordering::Acquire) {
                    Poll::Ready(Ok(empty_stats()))
                } else {
                    Poll::Pending
                }
            });
            let mut drain = Box::pin(drain_protocols(&shutdown, first, second));
            assert!(drain.as_mut().poll(&mut cx).is_pending());
            if !immediate {
                assert_eq!(shutdown.http1.shutdown_phase(), ShutdownPhase::Running);
                assert_eq!(shutdown.http2.shutdown_phase(), ShutdownPhase::Running);
                assert!(shutdown.signal.begin_force_close());
                assert!(flag.0.load(Ordering::Acquire));
                assert!(drain.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(shutdown.http1.shutdown_phase(), ShutdownPhase::ForceClosing);
            assert_eq!(shutdown.http2.shutdown_phase(), ShutdownPhase::ForceClosing);
            second_done.store(true, Ordering::Release);
            assert!(matches!(
                drain.as_mut().poll(&mut cx),
                Poll::Ready((Ok(_), Ok(_)))
            ));
            drop(drain);
            shutdown.finish();
            let signal = shutdown.signal.clone();
            drop(shutdown);
            assert_eq!(signal.phase(), ShutdownPhase::Stopped);
        }
    }

    #[test]
    fn protocol_error_forces_the_sibling_but_still_awaits_it() {
        let shutdown = protocol_shutdown();
        let second_done = AtomicBool::new(false);
        let second = std::future::poll_fn(|_| {
            if second_done.load(Ordering::Acquire) {
                Poll::Ready(Ok(empty_stats()))
            } else {
                Poll::Pending
            }
        });
        let first = std::future::ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "listener failed",
        )));
        let mut drain = pin!(drain_protocols(&shutdown, first, second));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(drain.as_mut().poll(&mut cx).is_pending());
        assert_eq!(shutdown.signal.phase(), ShutdownPhase::ForceClosing);
        assert_eq!(shutdown.http1.shutdown_phase(), ShutdownPhase::ForceClosing);
        assert_eq!(shutdown.http2.shutdown_phase(), ShutdownPhase::ForceClosing);
        second_done.store(true, Ordering::Release);
        match drain.as_mut().poll(&mut cx) {
            Poll::Ready((Err(error), Ok(_))) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            }
            _ => panic!("preserve the first error and join the sibling"),
        }
    }

    #[test]
    fn dropping_the_protocol_owner_requests_cleanup_not_quiescence() {
        let shutdown = protocol_shutdown();
        let signal = shutdown.signal.clone();
        let managers = [shutdown.http1.clone(), shutdown.http2.clone()];
        let peer = SocketAddr::from(([127, 0, 0, 1], 1234));
        let connections = managers
            .each_ref()
            .map(|manager| manager.register(peer).expect("admit"));
        drop(shutdown);
        assert_eq!(signal.phase(), ShutdownPhase::ForceClosing);
        for manager in &managers {
            assert_eq!(manager.shutdown_phase(), ShutdownPhase::ForceClosing);
            assert!(manager.register(peer).is_none());
            assert_eq!(
                manager.active_count(),
                1,
                "cleanup has only been requested"
            );
        }
        drop(connections);
        for manager in &managers {
            assert!(manager.is_empty());
        }
        assert!(
            !signal.is_stopped(),
            "only an awaited run may publish completion"
        );
    }

    struct ActiveRequest(Arc<AtomicUsize>);

    impl Drop for ActiveRequest {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[allow(clippy::too_many_lines)] // Keep the native failure/rescue lifecycle together.
    fn native_force_close(http2: bool, immediate: bool) {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let active = Arc::new(AtomicUsize::new(0));
            let handler_entered = Arc::clone(&entered);
            let handler_release = Arc::clone(&release);
            let handler_active = Arc::clone(&active);
            let handler = move |_: Request| {
                let entered = Arc::clone(&handler_entered);
                let release = Arc::clone(&handler_release);
                let active = Arc::clone(&handler_active);
                async move {
                    active.fetch_add(1, Ordering::AcqRel);
                    let _active = ActiveRequest(active);
                    let mut finish = pin!(release.notified());
                    let mut announced = false;
                    std::future::poll_fn(|cx| {
                        let result = finish.as_mut().poll(cx);
                        if !announced {
                            announced = true;
                            entered.notify_one();
                        }
                        result
                    })
                    .await;
                    Response::new(200, "OK", Vec::new())
                }
            };
            let config = HttpAutoListenerConfig::default()
                .http1(
                    Http1ListenerConfig::default()
                        .http_config(Http1Config {
                            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                            ..Http1Config::default()
                        })
                        .drain_timeout(Duration::from_secs(60))
                        .hard_drain_timeout(Duration::from_secs(60)),
                )
                .http2(
                    Http2ListenerConfig::default()
                        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                        .drain_timeout(Duration::from_secs(60))
                        .hard_drain_timeout(Duration::from_secs(60)),
                );
            let listener = HttpAutoListener::bind("127.0.0.1:0", handler, config)
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("address");
            let shutdown = listener.shutdown_signal();
            let run_runtime = handle.clone();
            let mut run = Box::pin(handle.spawn(async move { listener.run(&run_runtime).await }));
            let client = handle.spawn(async move {
                let mut stream = TcpStream::connect(addr).await.expect("connect");
                if http2 {
                    let cx = Cx::current().expect("client context");
                    Http2Client::new()
                        .get(format!("http://localhost:{}/held", addr.port()))
                        .send_on(&cx, stream)
                        .await
                        .is_ok_and(|response| response.status == 200)
                } else {
                    AsyncWriteExt::write_all(
                        &mut stream,
                        b"GET /held HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("request");
                    let mut response = Vec::new();
                    let _ = AsyncReadExt::read_to_end(&mut stream, &mut response).await;
                    response.starts_with(b"HTTP/1.1 200")
                }
            });
            crate::time::timeout(now(), Duration::from_secs(5), entered.notified())
                .await
                .expect("handler must be parked before shutdown");
            assert_eq!(active.load(Ordering::Acquire), 1);
            if immediate {
                shutdown.trigger_immediate();
            } else {
                assert!(shutdown.begin_drain(Duration::from_secs(60)));
                assert!(shutdown.begin_force_close());
            }
            let result = crate::time::timeout(now(), Duration::from_secs(5), run.as_mut()).await;
            let (without_rescue, stats) = match result {
                Ok(stats) => (true, stats),
                Err(_) => {
                    // Release the parked handler on the old/broken path so
                    // the regression fails without leaving a live task behind.
                    release.notify_waiters();
                    let stats = crate::time::timeout(now(), Duration::from_secs(5), run.as_mut())
                        .await
                        .expect("rescue must finish the listener");
                    (false, stats)
                }
            };
            let stats = stats.expect("listener result");
            let succeeded = crate::time::timeout(now(), Duration::from_secs(5), client)
                .await
                .expect("client completion");
            assert_eq!(
                active.load(Ordering::Acquire),
                0,
                "handler resources released"
            );
            assert!(without_rescue, "force-close was not forwarded to the protocol");
            assert!(
                !succeeded,
                "the held handler must not produce its success response"
            );
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            let (served, idle) = if http2 {
                (stats.http2, stats.http1)
            } else {
                (stats.http1, stats.http2)
            };
            assert_eq!(served.force_closed, 1);
            assert_eq!(served.drained, 0);
            assert_eq!(idle.force_closed, 0);
        }));
    }

    #[test]
    fn http1_force_close_releases_a_running_request() {
        for immediate in [false, true] {
            native_force_close(false, immediate);
        }
    }

    #[test]
    fn http2_force_close_releases_a_running_request() {
        for immediate in [false, true] {
            native_force_close(true, immediate);
        }
    }

    #[test]
    fn graceful_run_publishes_stopped() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let listener = HttpAutoListener::bind(
                "127.0.0.1:0",
                |_: Request| async { Response::new(200, "OK", Vec::new()) },
                HttpAutoListenerConfig::default(),
            )
            .await
            .expect("bind");
            let shutdown = listener.shutdown_signal();
            assert!(shutdown.begin_drain(Duration::from_secs(60)));
            let stats = listener.run(&handle).await.expect("drain");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            assert_eq!(stats.http1.force_closed + stats.http2.force_closed, 0);
        }));
    }

    fn localhost_config() -> HttpAutoListenerConfig {
        HttpAutoListenerConfig::default()
            .http1(
                Http1ListenerConfig::default()
                    .http_config(Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                        ..Http1Config::default()
                    })
                    .drain_timeout(Duration::from_secs(60))
                    .hard_drain_timeout(Duration::from_secs(60)),
            )
            .http2(
                Http2ListenerConfig::default()
                    .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                    .drain_timeout(Duration::from_secs(60))
                    .hard_drain_timeout(Duration::from_secs(60)),
            )
    }

    async fn get(addr: SocketAddr) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(
            &mut stream,
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("request");
        let mut response = Vec::new();
        let _ = AsyncReadExt::read_to_end(&mut stream, &mut response).await;
        response
    }

    /// r14 F2 M2 (r11 F4.4): once the task running `run` was cancelled (its
    /// region closing, a runtime drain), accept failed with `Interrupted` on
    /// every poll, that counted as transient, and the backoff sleep completed
    /// at once. The loop spun, nothing drained and `Stopped` never came. The
    /// cancellation now ends accepting like the shutdown signal.
    #[test]
    fn a_cancelled_run_task_stops_accepting_and_publishes_stopped() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let cx = Cx::current().expect("runtime Cx");
            let listener = HttpAutoListener::bind(
                "127.0.0.1:0",
                |_: Request| async { Response::new(200, "OK", Vec::new()) },
                localhost_config(),
            )
            .await
            .expect("bind");
            let addr = listener.local_addr().expect("address");
            let shutdown = listener.shutdown_signal();
            let run_runtime = handle.clone();
            let mut run = cx
                .spawn(move |_| async move { listener.run(&run_runtime).await })
                .expect("spawn the run task");
            // A served request shows the accept loop is running.
            let response = get(addr).await;
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&response)
            );

            run.abort();
            let joined = crate::time::timeout(now(), Duration::from_secs(10), run.join(&cx)).await;
            if joined.is_err() {
                // Stop a spinning loop through the signal, so this failure
                // leaves no live task behind.
                shutdown.trigger_immediate();
            }
            assert!(joined.is_ok(), "the cancelled run task never finished");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        }));
    }

    /// r14 F2 M1 (r11 F2): the listening socket stayed bound until the whole
    /// drain was over (60 s by default), so a client connecting meanwhile
    /// queued in the backlog and was reset at the end. The socket now closes
    /// when accepting ends, as the HTTP/1.1 and HTTP/2 listeners' do, while
    /// the request in flight still completes. As with them,
    /// `lb_compat_keep_socket` keeps it bound through the drain.
    #[test]
    fn new_connections_are_refused_once_the_drain_starts() {
        assert!(
            drain_refuses_new_connections(false),
            "a connection made during the drain was not refused"
        );
        assert!(
            !drain_refuses_new_connections(true),
            "lb_compat_keep_socket must keep the socket connectable through the drain"
        );
    }

    /// Whether a connection attempted while a parked request holds the drain
    /// open is refused, with `lb_compat_keep_socket` set as `keep_socket` in
    /// the HTTP/1.1 config only.
    fn drain_refuses_new_connections(keep_socket: bool) -> bool {
        let mut config = localhost_config();
        config.http1 = config.http1.lb_compat_keep_socket(keep_socket);
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let handler_entered = Arc::clone(&entered);
            let handler_release = Arc::clone(&release);
            let handler = move |_: Request| {
                let entered = Arc::clone(&handler_entered);
                let release = Arc::clone(&handler_release);
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Response::new(200, "OK", Vec::new())
                }
            };
            let listener = HttpAutoListener::bind("127.0.0.1:0", handler, config)
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("address");
            let shutdown = listener.shutdown_signal();
            let run_runtime = handle.clone();
            let run = handle.spawn(async move { listener.run(&run_runtime).await });
            let in_flight = handle.spawn(get(addr));
            crate::time::timeout(now(), Duration::from_secs(5), entered.notified())
                .await
                .expect("the first request reaches its handler");

            // The parked handler holds the drain open.
            assert!(shutdown.begin_drain(Duration::from_secs(60)));
            let mut refused = false;
            for _ in 0..100 {
                match TcpStream::connect(addr).await {
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        refused = true;
                        break;
                    }
                    _ => crate::time::sleep(now(), Duration::from_millis(20)).await,
                }
            }
            release.notify_one();
            let response = crate::time::timeout(now(), Duration::from_secs(10), in_flight)
                .await
                .expect("the request in flight completes");
            let stats = crate::time::timeout(now(), Duration::from_secs(10), run)
                .await
                .expect("the drain completes")
                .expect("listener result");
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&response)
            );
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            assert_eq!(stats.http1.force_closed + stats.http2.force_closed, 0);
            refused
        }))
    }
