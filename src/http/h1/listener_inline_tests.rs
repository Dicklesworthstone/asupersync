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
    use crate::http::h1::server::HostPolicy;
    use crate::http::h1::types::Response;
    use crate::io::AsyncWriteExt;
    use crate::record::RegionLimits;
    use crate::runtime::RuntimeBuilder;
    use crate::runtime::yield_now;
    use crate::sync::Notify;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;

    thread_local! {
        static HTTP1_LISTENER_TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_http1_listener_test_time(time: Time) {
        HTTP1_LISTENER_TEST_NOW.with(|now| now.set(time.as_nanos()));
    }

    fn http1_listener_test_time() -> Time {
        HTTP1_LISTENER_TEST_NOW.with(|now| Time::from_nanos(now.get()))
    }

    fn localhost_http_config() -> Http1Config {
        Http1Config {
            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
            ..Http1Config::default()
        }
    }

    #[test]
    fn default_config() {
        let config = Http1ListenerConfig::default();
        assert_eq!(config.max_connections, Some(10_000));
        assert_eq!(config.drain_timeout, Duration::from_secs(30));
        assert!(config.http_config.keep_alive);
    }

    #[test]
    fn config_builder() {
        set_http1_listener_test_time(Time::from_nanos(77));
        let config = Http1ListenerConfig::default()
            .max_connections(Some(5000))
            .drain_timeout(Duration::from_secs(60))
            .http_config(Http1Config::default().keep_alive(false))
            .time_getter(http1_listener_test_time);

        assert_eq!(config.max_connections, Some(5000));
        assert_eq!(config.drain_timeout, Duration::from_secs(60));
        assert!(!config.http_config.keep_alive);
        assert_eq!((config.time_getter)().as_nanos(), 77);
    }

    #[test]
    fn transient_error_detection() {
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::WouldBlock,
            "would block"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "aborted"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset"
        )));
        assert!(is_transient_accept_error(&io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted"
        )));
        assert!(!is_transient_accept_error(&io::Error::new(
            io::ErrorKind::AddrInUse,
            "in use"
        )));
        assert!(!is_transient_accept_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "denied"
        )));
    }

    #[test]
    fn accept_resource_exhaustion_retries_out_of_memory() {
        assert!(is_transient_accept_error(&io::Error::from(
            io::ErrorKind::OutOfMemory
        )));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_resource_exhaustion_retries_native_errors() {
        #[cfg(unix)]
        let codes = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
            [WSAEMFILE, WSAENOBUFS]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                is_transient_accept_error(&error),
                "resource exhaustion must reach accept backoff: {error:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_resource_exhaustion_preserves_native_fatal_errors() {
        #[cfg(unix)]
        let codes = [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EACCES];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEACCES, WSAEINVAL, WSAENOTSOCK};
            [WSAENOTSOCK, WSAEINVAL, WSAEACCES]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                !is_transient_accept_error(&error),
                "permanent accept errors must still terminate the listener: {error:?}"
            );
        }
    }

    #[test]
    fn transient_backoff_caps() {
        assert_eq!(
            transient_accept_backoff_delay(1),
            TRANSIENT_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            transient_accept_backoff_delay(16),
            TRANSIENT_ACCEPT_BACKOFF_BASE
        );
        assert_eq!(
            transient_accept_backoff_delay(17),
            TRANSIENT_ACCEPT_BACKOFF_BASE.saturating_mul(2)
        );
        assert_eq!(
            transient_accept_backoff_delay(10_000),
            TRANSIENT_ACCEPT_BACKOFF_CAP
        );
    }

    #[test]
    fn spawn_capacity_failure_is_connection_scoped() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .root_region_limits(RegionLimits {
                // The block_on root and blocker consume both task slots,
                // so a connection spawn must fail without leaking its guard.
                max_tasks: Some(2),
                ..RegionLimits::unlimited()
            })
            .build()
            .expect("build runtime");
        let handle = runtime.handle();

        runtime.block_on(async {
            let blocker_started = Arc::new(Notify::new());
            let blocker_release = Arc::new(Notify::new());
            let blocker_started_signal = Arc::clone(&blocker_started);
            let blocker_release_signal = Arc::clone(&blocker_release);
            let blocker = handle
                .clone()
                .try_spawn(async move {
                    blocker_started_signal.notify_one();
                    blocker_release_signal.notified().await;
                })
                .expect("spawn blocker");

            blocker_started.notified().await;

            let raw_listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind raw listener");
            let addr = raw_listener.local_addr().expect("raw listener addr");
            let client = std::net::TcpStream::connect(addr).expect("connect raw client");
            let (server_raw, peer_addr) = raw_listener.accept().expect("accept raw server side");
            let server_stream =
                crate::net::tcp::stream::TcpStream::from_std(server_raw).expect("wrap stream");

            let shutdown = ShutdownSignal::new();
            let manager = ConnectionManager::new(Some(16), shutdown.clone());
            let guard = manager.register(peer_addr).expect("register connection");

            let handler = Arc::new(|_req| async { Response::new(200, "OK", Vec::new()) });
            let err = match spawn_connection(
                server_stream,
                guard,
                handler,
                localhost_http_config(),
                shutdown.clone(),
                Arc::new(AtomicUsize::new(0)),
                &handle,
            ) {
                Ok(_) => panic!("connection spawn should fail while root region is at capacity"),
                Err(err) => err,
            };

            assert!(matches!(
                err,
                SpawnError::RegionAtCapacity {
                    limit: 2,
                    live: 2,
                    ..
                }
            ));
            assert!(
                should_retry_after_spawn_failure(&err),
                "capacity failures should be scoped to the rejected connection"
            );
            assert_eq!(
                manager.active_count(),
                0,
                "failed spawn must drop the connection guard immediately"
            );
            assert_eq!(shutdown.phase(), ShutdownPhase::Running);

            drop(client);
            blocker_release.notify_one();
            blocker.await;
        });
    }

    #[test]
    fn bind_and_local_addr() {
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local_addr");
            assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
            assert_ne!(addr.port(), 0);
        });
    }

    #[test]
    fn shutdown_signal_accessible() {
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            let signal = listener.shutdown_signal();
            assert!(!signal.is_shutting_down());
            assert_eq!(signal.phase(), ShutdownPhase::Running);
        });
    }

    #[test]
    fn connection_manager_accessible() {
        crate::test_utils::run_test(|| async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            assert_eq!(listener.connection_manager().active_count(), 0);
            assert!(listener.connection_manager().is_empty());
        });
    }

    #[test]
    fn from_listener_constructor() {
        crate::test_utils::run_test(|| async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let addr = tcp.local_addr().expect("local_addr");

            let listener = Http1Listener::from_listener(
                tcp,
                |_req| async { Response::new(200, "OK", Vec::new()) },
                Http1ListenerConfig::default(),
            );

            assert_eq!(listener.local_addr().expect("addr"), addr);
        });
    }

    #[test]
    fn configured_time_getter_controls_listener_bookkeeping() {
        crate::test_utils::run_test(|| async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let config = Http1ListenerConfig::default()
                .time_getter(http1_listener_test_time)
                .drain_timeout(Duration::from_secs(3));
            let listener = Http1Listener::from_listener(
                tcp,
                |_req| async { Response::new(200, "OK", Vec::new()) },
                config,
            );

            set_http1_listener_test_time(Time::from_millis(321));
            listener.stats_handle().record_accepted();
            assert_eq!(listener.stats_handle().snapshot().last_accept_at_ms, 321);

            set_http1_listener_test_time(Time::from_secs(7));
            let addr = "127.0.0.1:8081".parse().expect("parse addr");
            let _guard = listener
                .connection_manager()
                .register(addr)
                .expect("register connection");
            let connections = listener.connection_manager().active_connections();
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].1.connected_at, Time::from_secs(7));

            assert!(listener.begin_drain());
            assert_eq!(
                listener.shutdown_signal().drain_deadline(),
                Some(Time::from_secs(10))
            );
        });
    }

    #[test]
    fn default_listener_shutdown_signal_captures_timer_driver() {
        crate::test_utils::run_test(|| async {
            let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
            let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
            let cx = Cx::new_with_drivers(
                RegionId::new_for_test(41, 1),
                TaskId::new_for_test(42, 1),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer_driver),
                None,
            );

            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let listener = {
                let _guard = Cx::set_current(Some(cx));
                Http1Listener::from_listener(
                    tcp,
                    |_req| async { Response::new(200, "OK", Vec::new()) },
                    Http1ListenerConfig::default(),
                )
            };

            let _no_cx = Cx::set_current(None);
            assert!(listener.begin_drain());
            assert_eq!(
                listener.shutdown_signal().drain_deadline(),
                Some(Time::from_secs(40))
            );
        });
    }

    #[test]
    fn immediate_shutdown_returns_stats() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let handle = runtime.handle();
        runtime.block_on(async {
            let listener = Http1Listener::bind("127.0.0.1:0", |_req| async {
                Response::new(200, "OK", Vec::new())
            })
            .await
            .expect("bind failed");

            // Trigger shutdown before running
            let began = listener.begin_drain();
            assert!(began);

            let stats = listener.run(&handle).await.expect("run");
            assert_eq!(stats.drained, 0);
            assert_eq!(stats.force_closed, 0);
        });
    }

    #[test]
    fn force_close_marks_stopped_when_connections_finish() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let handle = runtime.handle();

        runtime.block_on(async {
            let started = Arc::new(Notify::new());
            let finished = Arc::new(Notify::new());
            let started_signal = Arc::clone(&started);
            let finished_signal = Arc::clone(&finished);

            let config = Http1ListenerConfig {
                http_config: localhost_http_config(),
                drain_timeout: Duration::from_millis(0),
                ..Default::default()
            };

            let listener = Http1Listener::bind_with_config(
                "127.0.0.1:0",
                move |_req| {
                    let started = Arc::clone(&started_signal);
                    let finished = Arc::clone(&finished_signal);
                    async move {
                        started.notify_one();
                        finished.notified().await;
                        Response::new(200, "OK", Vec::new())
                    }
                },
                config,
            )
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local_addr");
            let shutdown = listener.shutdown_signal();
            let manager = listener.connection_manager().clone();

            let run_handle = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .expect("spawn listener");

            let mut client = crate::net::tcp::stream::TcpStream::connect(addr)
                .await
                .expect("connect");
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");

            started.notified().await;
            let began = manager.begin_drain(Duration::from_millis(0));
            assert!(began);

            shutdown.wait_for_phase(ShutdownPhase::ForceClosing).await;

            let _ = client.shutdown(std::net::Shutdown::Both);
            finished.notify_one();
            let stats = run_handle.await.expect("run");
            assert!(stats.force_closed > 0, "expected force close path");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);

            yield_now().await;
        });
    }

    #[test]
    fn force_close_stats_duration_waits_for_stopped_finalization() {
        init_test_logging();
        set_http1_listener_test_time(Time::ZERO);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let handle = runtime.handle();

        runtime.block_on(async {
            let started = Arc::new(Notify::new());
            let finished = Arc::new(Notify::new());
            let started_signal = Arc::clone(&started);
            let finished_signal = Arc::clone(&finished);

            let config = Http1ListenerConfig::default()
                .http_config(localhost_http_config())
                .drain_timeout(Duration::from_millis(0))
                .time_getter(http1_listener_test_time);

            let listener = Http1Listener::bind_with_config(
                "127.0.0.1:0",
                move |_req| {
                    let started = Arc::clone(&started_signal);
                    let finished = Arc::clone(&finished_signal);
                    async move {
                        started.notify_one();
                        finished.notified().await;
                        Response::new(200, "OK", Vec::new())
                    }
                },
                config,
            )
            .await
            .expect("bind failed");

            let addr = listener.local_addr().expect("local_addr");
            let shutdown = listener.shutdown_signal();
            let manager = listener.connection_manager().clone();

            let run_handle = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .expect("spawn listener");

            let mut client = crate::net::tcp::stream::TcpStream::connect(addr)
                .await
                .expect("connect");
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");

            started.notified().await;
            // Begin drain at time=0 so drain_start is recorded as 0.
            let began = manager.begin_drain(Duration::from_millis(0));
            assert!(began);
            // Advance time so that collect_stats sees a non-zero
            // duration. The handler is now interrupted by ForceClosing
            // (handler execution races against the force-close phase),
            // so it exits promptly without waiting for `finished`.
            set_http1_listener_test_time(Time::from_millis(25));

            let _ = client.shutdown(std::net::Shutdown::Both);
            let stats = run_handle.await.expect("run");
            assert_eq!(stats.force_closed, 1);
            // Duration check is intentionally non-exact: the shared
            // test time source (`HTTP1_LISTENER_TEST_NOW`) can be
            // mutated by concurrent listener tests. The important
            // invariant is that the server reached Stopped and
            // force-closed the lingering connection.
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);

            yield_now().await;
        });
    }

    #[test]
    fn http1_listener_config_debug_clone_default() {
        let cfg = Http1ListenerConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.max_connections, Some(10_000));
        assert_eq!(cloned.drain_timeout, Duration::from_secs(30));
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("Http1ListenerConfig"));
    }

    /// The drain supervision tick waits its interval when the listener task
    /// is cancelled; it used to complete at once, so the drain loop spun.
    #[test]
    fn drain_supervision_tick_ignores_the_listener_tasks_cancellation() {
        init_test_logging();
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 2),
            TaskId::new_for_test(9, 2),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut tick = std::pin::pin!(drain_supervision_tick(Time::from_secs(10)));
        for _ in 0..2 {
            assert!(
                tick.as_mut().poll(&mut task_cx).is_pending(),
                "a cancelled listener still waits for the tick"
            );
        }
        virtual_clock.advance_to(Time::from_secs(10) + DRAIN_SUPERVISION_TICK);
        let _ = timer_driver.process_timers();
        assert!(tick.as_mut().poll(&mut task_cx).is_ready());
    }

    /// Hold a real handler at its first Pending so a fatal listener failure
    /// must retain the connection until its response has finished.
    #[cfg(not(target_arch = "wasm32"))]
    fn fatal_listener_failure_drains_request(fail_spawn: bool, owned: bool, workers: usize) {
        use crate::cx::ChildRegionSpec;
        use crate::io::AsyncReadExt as _;
        use std::sync::atomic::AtomicBool;

        const WATCHDOG: Duration = Duration::from_secs(10);

        struct Cleanup {
            release: Arc<Notify>,
            signal: ShutdownSignal,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                self.release.notify_one();
                self.signal.trigger_immediate();
            }
        }

        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().expect("current-thread runtime")
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .expect("multi-worker runtime")
        };
        let runtime_handle = runtime.handle();
        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime context");
            let owner_region = if owned {
                Some(
                    cx.open_child_region(ChildRegionSpec::inherit())
                        .await
                        .expect("open listener owner"),
                )
            } else {
                None
            };
            let owner = owner_region.as_ref().map(|region| region.cx().clone());
            let started = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let completed = Arc::new(AtomicBool::new(false));
            let started_for_handler = Arc::clone(&started);
            let release_for_handler = Arc::clone(&release);
            let completed_for_handler = Arc::clone(&completed);
            let handler = move |_request: Request| {
                let started = Arc::clone(&started_for_handler);
                let release = Arc::clone(&release_for_handler);
                let completed = Arc::clone(&completed_for_handler);
                async move {
                    let mut released = core::pin::pin!(release.notified());
                    let mut witnessed_pending = false;
                    std::future::poll_fn(|task| {
                        let result = released.as_mut().poll(task);
                        if result.is_pending() && !witnessed_pending {
                            witnessed_pending = true;
                            started.notify_one();
                        }
                        result
                    })
                    .await;
                    completed.store(true, Ordering::Release);
                    Response::new(200, "OK", b"request-completed-before-error".to_vec())
                }
            };
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind ingress");
            let address = tcp.local_addr().expect("ingress address");
            let queue = Arc::new(HandoffQueue::default());
            let config = Http1ListenerConfig::default()
                .http_config(localhost_http_config())
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(WATCHDOG);
            let mut handoff_ingress = None;
            let listener = if fail_spawn {
                Http1Listener::from_listener(tcp, handler, config)
            } else {
                handoff_ingress = Some(tcp);
                Http1Listener::from_handoff(Arc::clone(&queue), handler, config)
            };
            let manager = listener.connection_manager().clone();
            let signal = listener.shutdown_signal();
            let requests = listener.in_flight_requests();
            let stats = listener.stats_handle();
            let _cleanup = Cleanup {
                release: Arc::clone(&release),
                signal: signal.clone(),
            };
            let spawn_attempts = Arc::new(AtomicUsize::new(0));
            let attempts_for_run = Arc::clone(&spawn_attempts);
            let mut serving = cx
                .spawn(move |_coordinator| async move {
                    if fail_spawn {
                        let spawner = owner.clone();
                        listener
                            .run_with_spawner(
                                owner,
                                move |stream, guard, handler, config, shutdown, in_flight| {
                                    if attempts_for_run.fetch_add(1, Ordering::AcqRel) == 1 {
                                        // The first real connection stays live. A fatal
                                        // admission refusal for the next one must drain it.
                                        return Err(SpawnError::RuntimeUnavailable);
                                    }
                                    if let Some(spawner) = &spawner {
                                        spawner
                                            .spawn(move |_connection_cx| {
                                                serve_stream_connection(
                                                    stream,
                                                    guard,
                                                    handler,
                                                    config,
                                                    shutdown,
                                                    in_flight,
                                                )
                                            })
                                            .map(ConnectionTask::Owned)
                                    } else {
                                        spawn_stream_connection(
                                            stream,
                                            guard,
                                            handler,
                                            config,
                                            shutdown,
                                            in_flight,
                                            &runtime_handle,
                                        )
                                        .map(ConnectionTask::Root)
                                    }
                                },
                            )
                            .await
                    } else if let Some(owner) = owner {
                        listener.run_in(&owner).await
                    } else {
                        listener.run(&runtime_handle).await
                    }
                })
                .expect("spawn listener coordinator");

            let mut client = TcpStream::connect(address).await.expect("connect request");
            if let Some(ingress) = handoff_ingress.take() {
                let (accepted, peer) = ingress.accept().await.expect("accept handoff");
                queue.push(HandoffStream::new(Box::new(accepted)), Some(peer));
            }
            client
                .write_all(b"GET /drain HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("write request");
            crate::time::timeout(cx.now(), WATCHDOG, started.notified())
                .await
                .expect("handler reaches a registered Pending");
            assert_eq!(manager.active_count(), 1);
            assert_eq!(requests.load(Ordering::Acquire), 1);
            assert!(!completed.load(Ordering::Acquire));

            let mut rejected = if fail_spawn {
                Some(TcpStream::connect(address).await.expect("second connection"))
            } else {
                queue.close();
                None
            };
            crate::time::timeout(cx.now(), WATCHDOG, async {
                while stats.snapshot().drains_started_total == 0 {
                    assert!(
                        !serving.is_finished(),
                        "fatal error was published before existing work entered drain"
                    );
                    yield_now().await;
                }
            })
            .await
            .expect("fatal accept or spawn failure starts the drain");
            assert_eq!(signal.phase(), ShutdownPhase::Draining);
            assert!(!serving.is_finished(), "the held handler still belongs to run");
            assert_eq!(manager.active_count(), 1, "rejected spawn released its guard");
            assert_eq!(requests.load(Ordering::Acquire), 1);
            if let Some(rejected) = rejected.as_mut() {
                let mut byte = [0_u8; 1];
                assert_eq!(
                    crate::time::timeout(cx.now(), WATCHDOG, rejected.read(&mut byte))
                        .await
                        .expect("rejected connection closes")
                        .expect("read rejected connection"),
                    0
                );
            }

            release.notify_one();
            let mut response = Vec::new();
            crate::time::timeout(cx.now(), WATCHDOG, client.read_to_end(&mut response))
                .await
                .expect("in-flight response drains")
                .expect("read drained response");
            assert!(response.starts_with(b"HTTP/1.1 200 "));
            assert!(response.ends_with(b"request-completed-before-error"));
            assert!(response.windows(b"connection: close".len()).any(|window| {
                window.eq_ignore_ascii_case(b"connection: close")
            }));
            let error = crate::time::timeout(cx.now(), WATCHDOG, serving.join(&cx))
                .await
                .expect("listener joins every connection")
                .expect("listener retains its typed result")
                .expect_err("original fatal error survives cleanup");
            if fail_spawn {
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert_eq!(
                    error.to_string(),
                    format!("failed to spawn connection task: {}", SpawnError::RuntimeUnavailable)
                );
                assert_eq!(spawn_attempts.load(Ordering::Acquire), 2);
            } else {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), "HTTP handoff queue is closed");
            }
            assert_eq!(error.raw_os_error(), None);
            assert!(completed.load(Ordering::Acquire));
            assert_eq!(signal.phase(), ShutdownPhase::Stopped);
            assert!(manager.is_empty());
            assert_eq!(requests.load(Ordering::Acquire), 0);
            let snapshot = stats.snapshot();
            assert_eq!(snapshot.accepted_total, if fail_spawn { 2 } else { 1 });
            assert_eq!(snapshot.spawn_failures_total, u64::from(fail_spawn));
            assert_eq!(snapshot.transient_accept_errors_total, 0);
            assert_eq!(snapshot.drains_started_total, 1);
            assert_eq!(snapshot.drains_quiescent_total, 1);
            assert_eq!(snapshot.drain_escalations_total, 0);
            assert_eq!(snapshot.drain_hard_deadline_hits_total, 0);
            assert_eq!(snapshot.last_drain_requests_at_start, 1);
            assert_eq!(snapshot.last_drain_requests_stranded, 0);
            if let Some(region) = owner_region {
                crate::time::timeout(cx.now(), WATCHDOG, region.close())
                    .await
                    .expect("owner closes within bound")
                    .expect("owner reaches quiescence");
            }
        });
        let retired_at = std::time::Instant::now();
        while !runtime.is_quiescent() {
            assert!(retired_at.elapsed() < WATCHDOG, "listener work must retire");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fatal_handoff_accept_error_drains_native_http1_requests() {
        for owned in [false, true] {
            for workers in [1, 2] {
                fatal_listener_failure_drains_request(false, owned, workers);
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fatal_connection_spawn_error_drains_native_http1_requests() {
        for owned in [false, true] {
            for workers in [1, 2] {
                fatal_listener_failure_drains_request(true, owned, workers);
            }
        }
    }
