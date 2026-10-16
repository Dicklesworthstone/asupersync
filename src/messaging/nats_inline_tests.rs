    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::{assert_completes_within, run_test_with_cx};
    use serde_json::json;
    use socket2::SockRef;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc as std_mpsc;
    use std::thread::{self, JoinHandle};

    #[cfg(feature = "tls")]
    const NATS_TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls")]
    const NATS_TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

    fn native_parked_read_cancellation(worker_threads: usize, cancel_driver: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind cancellation listener");
        let addr = listener
            .local_addr()
            .expect("cancellation listener address");
        let (release_server, released) = std_mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept cancellation client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set cancellation peer timeout");
            stream
                .write_all(b"INFO {\"server_id\":\"cancel-owner\",\"max_payload\":1048576}\r\n")
                .expect("send cancellation INFO");
            let mut reader = BufReader::new(stream);
            assert!(read_protocol_line(&mut reader).starts_with("CONNECT "));
            // No more bytes arrive until the assertion side releases us. An
            // erroneous implementation therefore cannot pass on a server wake.
            let _ = released.recv_timeout(Duration::from_secs(8));
            let _ = reader.get_mut().shutdown(std::net::Shutdown::Both);
        });

        let owner: Cx = Cx::for_testing();
        let operation_owner = owner.clone();
        let (parked_tx, parked_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(worker_threads)
            .build()
            .expect("build cancellation runtime");
        let task = runtime.handle().spawn(async move {
            let driver = Cx::current().expect("native NATS driver context");
            let config = NatsConfig::from_url(&format!("nats://{addr}"))
                .expect("parse cancellation peer URL");
            let mut connection =
                NatsConnection::connect_with_policy(&driver, config, NatsConnectPolicy::default())
                    .await
                    .expect("connect cancellation peer");
            let owner_baseline = operation_owner
                .inner
                .read()
                .cancel_waker_registrations
                .len();
            let driver_baseline = driver.inner.read().cancel_waker_registrations.len();
            let mut parked_tx = Some(parked_tx);
            let result = {
                let read = connection.process(&operation_owner);
                let mut read = std::pin::pin!(read);
                std::future::poll_fn(|task_cx| {
                    let result = read.as_mut().poll(task_cx);
                    if result.is_pending()
                        && let Some(parked_tx) = parked_tx.take()
                    {
                        // This witnesses the real socket returning Pending,
                        // not a scheduling delay or a self-waking substitute.
                        let _ = parked_tx.send(driver.clone());
                    }
                    result
                })
                .await
            };
            let owner_after = operation_owner
                .inner
                .read()
                .cancel_waker_registrations
                .len();
            let driver_after = driver.inner.read().cancel_waker_registrations.len();
            drop(connection);
            let _ = result_tx.send((
                result,
                owner_baseline == owner_after,
                driver_baseline == driver_after,
            ));
        });

        let parked = parked_rx.recv_timeout(Duration::from_secs(3));
        if let Ok(driver) = &parked {
            if cancel_driver {
                driver.cancel_with(crate::types::CancelKind::Shutdown, Some("NATS driver stop"));
            } else {
                owner.cancel_with(crate::types::CancelKind::User, Some("NATS caller stop"));
            }
        }
        let result = result_rx.recv_timeout(Duration::from_secs(2));
        // Release the real peer before assertions, including the old-code-red
        // timeout path, so a failure does not strand a socket or worker.
        let _ = release_server.send(());
        server.join().expect("join cancellation peer");
        drop(task);
        let drained = runtime.shutdown_timeout(Duration::from_secs(3));

        assert!(parked.is_ok(), "native read never parked: {parked:?}");
        assert!(drained, "native cancellation runtime did not drain");
        match result {
            Ok((Err(NatsError::Cancelled), true, true)) => {}
            other => panic!(
                "NATS_CANCEL_OWNER workers={worker_threads} driver={cancel_driver} \
                 parked=true expected=Cancelled,registrations_retired observed={other:?}"
            ),
        }
    }

    #[test]
    fn nats_native_parked_read_observes_noncurrent_owner_and_retires_registrations() {
        for workers in [1, 2] {
            native_parked_read_cancellation(workers, false);
        }
    }

    #[test]
    fn nats_native_parked_read_still_observes_supervisor_shutdown() {
        for workers in [1, 2] {
            native_parked_read_cancellation(workers, true);
        }
    }

    #[test]
    fn nats_io_observes_cancellation_published_while_retiring_waker() {
        struct CancelOnRetirement(Cx);
        // Not a no-op waker: retiring it (its Drop) is the cancellation under test.
        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for CancelOnRetirement {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for CancelOnRetirement {
            fn drop(&mut self) {
                self.0.cancel_with(
                    crate::types::CancelKind::User,
                    Some("cancel during NATS Waker replacement"),
                );
            }
        }

        let owner: Cx = Cx::for_testing();
        let driver: Cx = Cx::for_testing();
        let _current = Cx::set_current(Some(driver.clone()));
        let first = Waker::from(Arc::new(CancelOnRetirement(owner.clone())));
        let mut operation = Box::pin(nats_io(
            &owner,
            std::future::pending::<Result<(), NatsError>>(),
        ));
        {
            let mut task_cx = std::task::Context::from_waker(&first);
            assert!(operation.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(first);
        assert!(!owner.is_cancel_requested());

        // Replacing the two registrations retires the last old Waker outside
        // their locks; its safe Drop callback publishes cancellation while the
        // registration phase is still running. The same poll must observe it.
        let mut task_cx = std::task::Context::from_waker(Waker::noop());
        assert!(matches!(
            operation.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(NatsError::Cancelled))
        ));
        assert!(!driver.is_cancel_requested());
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        assert!(driver.inner.read().cancel_waker_registrations.is_empty());
    }

    /// A budget deadline must wake work parked on a silent server; a
    /// checkpoint alone notices an expired deadline only when something
    /// polls. With two deadlines, an earlier one that does not end the call
    /// (here the driving task's checkpoints are masked) must not leave the
    /// later one unarmed.
    #[test]
    fn nats_io_wakes_a_parked_call_at_each_budget_deadline() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, RegionId, TaskId, Time};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountWakes(AtomicUsize);
        impl std::task::Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx_with_deadline = |task: u32, deadline_ms: u64| {
            Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(task, 0),
                Budget::new().with_deadline(Time::from_millis(deadline_ms)),
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            )
        };
        let owner = cx_with_deadline(1, 300);
        let driver = cx_with_deadline(2, 100);
        let _current = Cx::set_current(Some(driver.clone()));
        let silent_server = std::future::pending::<Result<(), NatsError>>();
        let mut call = std::pin::pin!(crate::combinator::bracket::commit_section(
            &driver,
            u32::MAX,
            nats_io(&owner, silent_server),
        ));
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(call.as_mut().poll(&mut task_cx).is_pending());

        // The driver's deadline wakes the call, which stays pending because
        // the driver's checkpoints are masked.
        clock.advance(150_000_000);
        let _fired = timer.process_timers();
        assert!(
            wakes.0.load(Ordering::SeqCst) > 0,
            "the driver's deadline must wake the parked call"
        );
        assert!(
            call.as_mut().poll(&mut task_cx).is_pending(),
            "the masked driver does not end the call"
        );

        // Only a timer for the owner's later deadline can wake it now.
        let before = wakes.0.load(Ordering::SeqCst);
        clock.advance(200_000_000);
        let _fired = timer.process_timers();
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "the owner's deadline must wake the parked call"
        );
        assert!(matches!(
            call.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(NatsError::Cancelled))
        ));
    }

    #[test]
    fn nats_connect_policy_defaults_and_zero_timeout_pm29wb() {
        use std::sync::atomic::AtomicBool;

        let default = NatsConnectPolicy::default();
        assert_eq!(default.timeout(), None);
        assert!(!default.confirms_connect());
        assert_eq!(default.keepalive(), NatsKeepalive::default());

        let owner = Cx::for_testing();
        let attempted = AtomicBool::new(false);
        let mut call = nats_connect_attempt(&owner, Some(Duration::ZERO), async {
            attempted.store(true, Ordering::SeqCst);
            Ok(())
        });
        let mut task_cx = std::task::Context::from_waker(Waker::noop());
        let Poll::Ready(Err(error)) = call.as_mut().poll(&mut task_cx) else {
            panic!("zero timeout must refuse the connection before polling transport work");
        };
        assert!(error.is_timeout(), "{error:?}");
        assert!(!attempted.load(Ordering::SeqCst));
    }

    #[test]
    fn nats_connect_attempt_keeps_one_deadline_on_the_owner_clock_pm29wb() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, RegionId, TaskId};
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        struct CountWakes(AtomicUsize);
        impl std::task::Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct ReleaseOnDrop(Arc<AtomicBool>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let owner_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
        let owner_timer = TimerDriverHandle::with_virtual_clock(owner_clock.clone());
        let driver_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10_000)));
        let driver_timer = TimerDriverHandle::with_virtual_clock(driver_clock.clone());
        let make_cx = |task, timer| {
            Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(task, 0),
                Budget::new(),
                None,
                None,
                None,
                Some(timer),
                None,
            )
        };
        let owner = make_cx(1, owner_timer.clone());
        let driver = make_cx(2, driver_timer.clone());
        let _current = Cx::set_current(Some(driver));
        let first_stage_done = Arc::new(AtomicBool::new(false));
        let second_stage_started = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let attempt = {
            let first = Arc::clone(&first_stage_done);
            let second = Arc::clone(&second_stage_started);
            let released = Arc::clone(&released);
            async move {
                let _release = ReleaseOnDrop(released);
                std::future::poll_fn(|_| {
                    if first.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                second.store(true, Ordering::SeqCst);
                std::future::pending::<Result<(), NatsError>>().await
            }
        };
        let mut call = nats_connect_attempt(&owner, Some(Duration::from_millis(100)), attempt);
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(call.as_mut().poll(&mut task_cx).is_pending());
        assert!(!second_stage_started.load(Ordering::SeqCst));

        driver_clock.advance(1_000_000_000);
        let _ = driver_timer.process_timers();
        assert!(call.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        owner_clock.advance(60_000_000);
        let _ = owner_timer.process_timers();
        first_stage_done.store(true, Ordering::SeqCst);
        assert!(call.as_mut().poll(&mut task_cx).is_pending());
        assert!(second_stage_started.load(Ordering::SeqCst));

        owner_clock.advance(40_000_000);
        let _ = owner_timer.process_timers();
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(Err(error)) = call.as_mut().poll(&mut task_cx) else {
            panic!("the second stage received a new timeout instead of the remaining 40 ms");
        };
        assert!(error.is_timeout(), "{error:?}");
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(owner_timer.pending_count(), 0);
    }

    #[test]
    fn nats_connect_attempt_cancellation_wins_an_expired_timeout_pm29wb() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, CancelKind, RegionId, TaskId};

        for cancel_driver in [false, true] {
            let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
            let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(1, 0),
                Budget::new(),
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let driver = Cx::for_testing();
            let _current = Cx::set_current(Some(driver.clone()));
            let mut call = nats_connect_attempt(
                &owner,
                Some(Duration::from_millis(100)),
                std::future::pending::<Result<(), NatsError>>(),
            );
            let mut task_cx = std::task::Context::from_waker(Waker::noop());
            assert!(call.as_mut().poll(&mut task_cx).is_pending());
            let cancelled = if cancel_driver { &driver } else { &owner };
            cancelled.cancel_with(CancelKind::User, Some("cancel NATS connection attempt"));
            clock.advance(100_000_000);
            let _ = timer.process_timers();
            assert!(matches!(
                call.as_mut().poll(&mut task_cx),
                Poll::Ready(Err(NatsError::Cancelled))
            ));
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert!(driver.inner.read().cancel_waker_registrations.is_empty());
            assert_eq!(timer.pending_count(), 0);
        }
    }

    #[test]
    fn nats_io_drop_retires_both_owners_without_stale_wakes() {
        struct WakeCount(AtomicU64);
        impl std::task::Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let owner: Cx = Cx::for_testing();
        let driver: Cx = Cx::for_testing();
        let _current = Cx::set_current(Some(driver.clone()));
        let wakes = Arc::new(WakeCount(AtomicU64::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut operation = Box::pin(nats_io(
            &owner,
            std::future::pending::<Result<(), NatsError>>(),
        ));
        assert!(operation.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
        assert_eq!(driver.inner.read().cancel_waker_registrations.len(), 1);
        drop(operation);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        assert!(driver.inner.read().cancel_waker_registrations.is_empty());
        owner.cancel_with(crate::types::CancelKind::User, Some("after wait drop"));
        driver.cancel_with(crate::types::CancelKind::Shutdown, Some("after wait drop"));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    }

    fn scrub_reply_subject(reply_to: Option<&str>) -> Option<&str> {
        let value = reply_to?;
        Some(if value.starts_with("_INBOX.") {
            "_INBOX.[SCRUBBED]"
        } else {
            value
        })
    }

    fn message_event_snapshot(message: &Message) -> serde_json::Value {
        json!({
            "subject": message.subject,
            "sid": message.sid,
            "reply_to": scrub_reply_subject(message.reply_to.as_deref()),
            "payload_utf8": String::from_utf8_lossy(&message.payload),
            "payload_len": message.payload.len(),
        })
    }

    fn read_protocol_line(reader: &mut BufReader<std::net::TcpStream>) -> String {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).expect("read protocol line");
        assert!(bytes > 0, "peer closed before sending a full protocol line");
        line
    }

    fn parse_pub_payload_len(header: &str) -> usize {
        let parts: Vec<_> = header.split_whitespace().collect();
        assert_eq!(parts.first().copied(), Some("PUB"));
        assert_eq!(parts.len(), 4, "request publish must include reply-to");
        parts[3].parse().expect("parse PUB payload length")
    }

    #[test]
    fn encode_nats_headers_rejects_oversize_block_before_allocation_uu9ayc() {
        let err = encode_nats_headers(&[("Nats-Msg-Id", b"1234567890")], 16)
            .expect_err("oversize header block must fail closed");
        match err {
            NatsError::Protocol(msg) => {
                assert_eq!(msg, "NATS header block too large: 37 > 16");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn encode_nats_headers_rejects_empty_block_when_base_exceeds_cap() {
        let err = encode_nats_headers(&[], 0)
            .expect_err("mandatory empty header block must respect max_header_bytes");
        match err {
            NatsError::Protocol(msg) => {
                assert_eq!(msg, "NATS header block too large: 12 > 0");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    fn read_optional_protocol_line(reader: &mut BufReader<std::net::TcpStream>) -> Option<String> {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(line),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(err) => panic!("read protocol line: {err}"),
        }
    }

    fn trim_protocol_line(line: String) -> String {
        line.trim_end_matches(['\r', '\n']).to_string()
    }

    fn parse_connect_json(connect_line: &str) -> serde_json::Value {
        let connect_json = connect_line
            .strip_prefix("CONNECT ")
            .expect("CONNECT prefix");
        serde_json::from_str(connect_json).expect("CONNECT JSON")
    }

    fn spawn_connect_recorder(
        info_json: &str,
        post_connect_line: Option<&str>,
    ) -> (SocketAddr, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind connect test listener");
        let addr = listener.local_addr().expect("listener addr");
        let info_line = format!("INFO {info_json}\r\n");
        let post_connect_line = post_connect_line.map(|line| format!("{line}\r\n"));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connect client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .write_all(info_line.as_bytes())
                .expect("write INFO line");
            stream.flush().expect("flush INFO line");

            let mut reader = BufReader::new(stream);
            let connect_line = trim_protocol_line(read_protocol_line(&mut reader));
            if let Some(post_connect_line) = post_connect_line {
                let stream = reader.get_mut();
                stream
                    .write_all(post_connect_line.as_bytes())
                    .expect("write post-CONNECT response");
                stream.flush().expect("flush post-CONNECT response");
            }
            connect_line
        });
        (addr, server)
    }

    /// Messages the burst server sends ahead of its PONG.
    const BURST: usize = 300;

    /// Answers the client's first PING with `BURST` messages for the client's
    /// subscription, then the PONG, so every message is dispatched before
    /// `ping` returns and none is received in between.
    fn spawn_burst_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind burst listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept burst client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            stream
                .write_all(b"INFO {\"server_id\":\"burst\",\"max_payload\":1048576}\r\n")
                .expect("write INFO line");
            let mut reader = BufReader::new(stream);
            assert!(read_protocol_line(&mut reader).starts_with("CONNECT "));
            let subscribe = read_protocol_line(&mut reader);
            let sid = subscribe
                .split_whitespace()
                .nth(2)
                .expect("SUB sid")
                .to_string();
            assert_eq!(trim_protocol_line(read_protocol_line(&mut reader)), "PING");
            let mut burst = String::new();
            for index in 0..BURST {
                burst.push_str(&format!("MSG burst {sid} 4\r\n{index:04}\r\n"));
            }
            burst.push_str("PONG\r\n");
            let stream = reader.get_mut();
            stream.write_all(burst.as_bytes()).expect("write burst");
            stream.flush().expect("flush burst");
        });
        (addr, server)
    }

    #[test]
    fn a_subscription_sized_for_a_burst_keeps_every_message() {
        // Frames that arrive while the subscriber is not receiving (here, all
        // of them before the PONG) are dispatched into its buffer, and the
        // buffer used to hold 256 whatever the burst.
        let (addr, server) = spawn_burst_server();
        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("connect burst server");
            let mut sub = client
                .subscribe_with_capacity(&cx, "burst", BURST)
                .await
                .expect("subscribe");
            client.ping(&cx).await.expect("ping");
            let mut received = Vec::new();
            while let Some(msg) = sub.try_next() {
                received.push(msg.payload);
            }
            assert_eq!(received.len(), BURST, "every burst message is kept");
            assert_eq!(received[BURST - 1], b"0299".to_vec());
        });
        server.join().expect("join burst server");
    }

    fn deterministic_user_seed(byte: u8) -> String {
        KeyPair::new_from_raw(KeyPairType::User, [byte; 32])
            .expect("deterministic user seed")
            .seed()
            .expect("seed encoding")
    }

    #[test]
    fn validate_nonce_accepts_real_stock_server_nonce_length() {
        // A stock nats-server nonce is 11 random bytes base64url-encoded to 15
        // chars. The prior `< 16` floor rejected this and broke all real auth.
        let fifteen_char_nonce = "AbCd012EfGh345_"; // 15 base64url chars
        assert_eq!(fifteen_char_nonce.len(), 15);
        validate_nonce_quality(fifteen_char_nonce)
            .expect("a realistic 15-char server nonce must validate");
    }

    #[test]
    fn validate_nonce_rejects_truncated_handshake() {
        assert!(validate_nonce_quality("").is_err());
        assert!(validate_nonce_quality("abc").is_err());
    }

    fn deterministic_cluster_seed(byte: u8) -> String {
        KeyPair::new_from_raw(KeyPairType::Cluster, [byte; 32])
            .expect("deterministic cluster seed")
            .seed()
            .expect("seed encoding")
    }

    fn deterministic_valid_nonce(suffix: &str) -> String {
        format!("authNonceValid-{suffix}")
    }

    fn deterministic_operator_key(label: &str) -> KeyPair {
        let mut raw = [0u8; 32];
        for (index, byte) in label.bytes().enumerate() {
            let slot = index % raw.len();
            let offset = u8::try_from(index % 251).expect("bounded offset");
            raw[slot] = raw[slot].wrapping_add(byte).wrapping_add(offset);
        }
        if label.is_empty() {
            raw[0] = 1;
        }
        KeyPair::new_from_raw(KeyPairType::Operator, raw).expect("deterministic operator key")
    }

    fn test_user_jwt_for_seed(seed: &str, issuer: &str, name: &str) -> String {
        let public_key = KeyPair::from_seed(seed).expect("seed").public_key();
        let issuer_key = deterministic_operator_key(issuer);
        let issuer_public_key = issuer_key.public_key();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ed25519-nkey","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": public_key,
                "iss": issuer_public_key,
                "name": name,
                "exp": 4_102_444_800_u64,
            })
            .to_string()
            .as_bytes(),
        );
        let signed_data = format!("{header}.{payload}");
        let signature = issuer_key
            .sign(signed_data.as_bytes())
            .expect("sign deterministic user JWT");
        let signature = URL_SAFE_NO_PAD.encode(signature);
        format!("{signed_data}.{signature}")
    }

    fn test_creds_document(jwt: &str, seed: &str) -> String {
        format!(
            "{jwt_begin}\n{jwt}\n{jwt_end}\n\n************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n{seed_begin}\n{seed}\n{seed_end}\n",
            jwt_begin = NATS_CREDS_JWT_BEGIN,
            jwt_end = NATS_CREDS_JWT_END,
            seed_begin = NATS_CREDS_SEED_BEGIN,
            seed_end = NATS_CREDS_SEED_END,
        )
    }

    fn spawn_reconnect_replay_recorder(
        expected_sub_count: usize,
    ) -> (SocketAddr, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind reconnect test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept reconnect client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"id\",\"server_name\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut reader = BufReader::new(stream);
            let mut lines = Vec::with_capacity(expected_sub_count + 1);
            lines.push(trim_protocol_line(read_protocol_line(&mut reader)));
            for _ in 0..expected_sub_count {
                lines.push(trim_protocol_line(read_protocol_line(&mut reader)));
            }
            if let Some(extra) = read_optional_protocol_line(&mut reader) {
                lines.push(format!("EXTRA:{}", trim_protocol_line(extra)));
            }
            lines
        });
        (addr, server)
    }

    fn insert_replay_subscription(
        state: &Arc<SharedState>,
        sid: u64,
        subject: &str,
        queue_group: Option<&str>,
    ) {
        let (tx, _rx) = mpsc::channel(8);
        state.subscriptions.lock().insert(
            sid,
            SubscriptionState {
                subject: subject.to_string(),
                queue_group: queue_group.map(str::to_string),
                sender: tx,
            },
        );
    }

    #[test]
    fn reconnect_replay_zero_subscriptions_sends_no_sub_commands_jh9g1j() {
        let (addr, server) = spawn_reconnect_replay_recorder(0);

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect reconnect client");
            let state = Arc::new(SharedState::new());
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("zero-subscription reconnect must succeed");
            assert!(client.connected, "client should be connected after replay");
        });

        let lines = server.join().expect("server join");
        assert_eq!(lines.len(), 1, "zero replay must only send CONNECT");
        assert!(
            lines[0].starts_with("CONNECT "),
            "unexpected CONNECT line: {:?}",
            lines[0]
        );
        println!(
            "NATS_RECONNECT_REPLAY scenario=zero subscriptions=0 replay_count=0 exact_rch_command='rch exec -- env CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_asupersync_jh9g1j_nats cargo test -p asupersync --lib reconnect_replay --features test-internals -- --nocapture' verdict=pass"
        );
    }

    #[test]
    fn reconnect_replays_existing_subscriptions_sorted_with_queue_groups_jh9g1j() {
        let (addr, server) = spawn_reconnect_replay_recorder(3);

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect reconnect client");
            let state = Arc::new(SharedState::new());
            insert_replay_subscription(&state, 7, "metrics.cpu", None);
            insert_replay_subscription(&state, 2, "orders.*", Some("workers"));
            insert_replay_subscription(&state, 5, "events.>", None);

            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state,
                next_sid: AtomicU64::new(8),
                connected: false,
                tls_required_on_connect: false,
            };

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("subscription replay must succeed");
            assert!(client.connected, "client should be connected after replay");
        });

        let lines = server.join().expect("server join");
        assert!(
            lines[0].starts_with("CONNECT "),
            "unexpected CONNECT line: {:?}",
            lines[0]
        );
        assert_eq!(
            &lines[1..],
            &[
                "SUB orders.* workers 2".to_string(),
                "SUB events.> 5".to_string(),
                "SUB metrics.cpu 7".to_string(),
            ],
            "subscriptions must replay once in deterministic SID order"
        );
        println!(
            "NATS_RECONNECT_REPLAY scenario=many_queue_wildcard subscription_ids=[2,5,7] queue_groups=1 replay_count=3 failure_point=none cancellation_state=active verdict=pass"
        );
    }

    #[test]
    fn repeated_reconnect_replays_each_subscription_once_per_connection_jh9g1j() {
        let (first_addr, first_server) = spawn_reconnect_replay_recorder(2);
        let (second_addr, second_server) = spawn_reconnect_replay_recorder(2);

        run_test_with_cx(|cx| async move {
            let state = Arc::new(SharedState::new());
            insert_replay_subscription(&state, 11, "alpha", None);
            insert_replay_subscription(&state, 12, "beta", Some("queue"));

            let first_stream = TcpStream::connect(format!("{first_addr}"))
                .await
                .expect("connect first reconnect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: first_stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(13),
                connected: false,
                tls_required_on_connect: false,
            };

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("first replay must succeed");

            client.stream = TcpStream::connect(format!("{second_addr}"))
                .await
                .expect("connect second reconnect client")
                .into();
            client.read_buf = NatsReadBuffer::new();
            client.connected = false;

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("second replay must succeed");
        });

        for (label, server) in [("first", first_server), ("second", second_server)] {
            let lines = server.join().expect("server join");
            assert_eq!(
                &lines[1..],
                &["SUB alpha 11".to_string(), "SUB beta queue 12".to_string()],
                "{label} reconnect must replay each active subscription exactly once"
            );
        }
        println!(
            "NATS_RECONNECT_REPLAY scenario=repeated subscription_ids=[11,12] replay_count_per_connection=2 duplicate_sub_commands=0 verdict=pass"
        );
    }

    #[test]
    fn reconnect_replay_failure_keeps_subscription_state_and_disconnects_jh9g1j() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay failure listener");
        let addr = listener.local_addr().expect("listener addr");
        let (accepted_tx, accepted_rx) = std_mpsc::channel();
        let (close_now_tx, close_now_rx) = std_mpsc::channel();
        let (closed_tx, closed_rx) = std_mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept replay failure client");
            accepted_tx.send(()).expect("accepted ack");
            close_now_rx.recv().expect("close command");
            SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .expect("force reset on close");
            drop(stream);
            closed_tx.send(()).expect("closed ack");
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect replay failure client");
            accepted_rx.recv().expect("server accepted");
            close_now_tx.send(()).expect("request reset");
            closed_rx.recv().expect("server closed");

            let state = Arc::new(SharedState::new());
            insert_replay_subscription(&state, 42, "svc.echo", None);
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(43),
                connected: true,
                tls_required_on_connect: false,
            };

            let err = client
                .replay_subscriptions_after_reconnect(&cx)
                .await
                .expect_err("replay write to reset peer must fail");
            assert!(
                matches!(err, NatsError::Io(_)),
                "expected I/O replay failure, got {err:?}"
            );
            assert!(
                !client.connected,
                "failed replay must leave connection marked unusable"
            );
            assert!(
                state.subscriptions.lock().contains_key(&42),
                "local subscription must survive failed replay for next reconnect"
            );
        });

        server.join().expect("server join");
        println!(
            "NATS_RECONNECT_REPLAY scenario=replay_failure subscription_ids=[42] replay_count=0 failure_point=write cancellation_state=active local_state_preserved=true verdict=pass"
        );
    }

    #[test]
    fn test_config_from_url_simple() {
        let config = NatsConfig::from_url("nats://localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert!(config.user.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_config_from_url_with_auth() {
        let config = NatsConfig::from_url("nats://user:pass@localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert_eq!(config.user, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    // br-asupersync-5in552: NatsConfig's Debug output MUST NOT
    // contain cleartext credentials. The manual Debug impl
    // substitutes "<redacted>" for any present user / password /
    // token. This test pins the redaction so a future refactor
    // that re-derives Debug (or adds a new credential field
    // without updating the manual impl) is caught immediately.
    #[test]
    fn test_natsconfig_debug_redacts_credentials_5in552() {
        let config =
            NatsConfig::from_url("nats://alice:supersecret123@nats.internal:4222").unwrap();
        let debug_output = format!("{config:?}");

        // Cleartext credential strings MUST NOT appear anywhere in
        // the Debug output.
        assert!(
            !debug_output.contains("supersecret123"),
            "Debug output leaked password: {debug_output}"
        );
        assert!(
            !debug_output.contains("alice"),
            "Debug output leaked username: {debug_output}"
        );

        // The redaction sentinel SHOULD appear for the present fields
        // so operators reading logs can see that credentials WERE
        // configured (not silently absent).
        assert!(
            debug_output.contains("<redacted>"),
            "Debug output should mark redacted credentials with sentinel: {debug_output}"
        );

        // Non-sensitive fields (host, port) are still visible.
        assert!(debug_output.contains("nats.internal"));
        assert!(debug_output.contains("4222"));
    }

    #[test]
    fn test_natsconfig_debug_redacts_token_5in552() {
        let mut config = NatsConfig::default();
        config.token = Some("eyJhbGciOiJIUzI1NiJ9.payload.signature".to_string());
        let debug_output = format!("{config:?}");

        assert!(
            !debug_output.contains("eyJhbGciOiJIUzI1NiJ9"),
            "Debug output leaked token: {debug_output}"
        );
        assert!(
            !debug_output.contains("signature"),
            "Debug output leaked token tail: {debug_output}"
        );
        assert!(
            debug_output.contains("<redacted>"),
            "Debug output should mark redacted token: {debug_output}"
        );
    }

    #[test]
    fn test_natsconfig_debug_redacts_jwt_and_nkey_seed_h1gf40() {
        let seed = deterministic_user_seed(7);
        let jwt = test_user_jwt_for_seed(&seed, "issuer", "operator");
        let mut config = NatsConfig::default();
        config.user_jwt = Some(jwt.clone());
        config.nkey_seed = Some(seed.clone());
        let debug_output = format!("{config:?}");

        assert!(
            !debug_output.contains(&jwt),
            "Debug output leaked JWT: {debug_output}"
        );
        assert!(
            !debug_output.contains(&seed),
            "Debug output leaked seed: {debug_output}"
        );
        assert!(
            debug_output.contains("user_jwt: Some(\"<redacted>\")"),
            "JWT field must be redacted: {debug_output}"
        );
        assert!(
            debug_output.contains("nkey_seed: Some(\"<redacted>\")"),
            "seed field must be redacted: {debug_output}"
        );
    }

    #[test]
    fn test_natsconfig_debug_unset_credentials_show_none_5in552() {
        let config = NatsConfig::default();
        let debug_output = format!("{config:?}");

        // Default config has None for user/password/token. Debug
        // output should show None for those fields, NOT <redacted>
        // (so operators can distinguish 'no credential configured'
        // from 'credential configured but redacted').
        assert!(
            !debug_output.contains("<redacted>"),
            "Default config should not show <redacted>; got: {debug_output}"
        );
        // The fields must still appear in the output as None for
        // diagnostic clarity.
        assert!(debug_output.contains("user: None"));
        assert!(debug_output.contains("password: None"));
        assert!(debug_output.contains("token: None"));
        assert!(debug_output.contains("user_jwt: None"));
        assert!(debug_output.contains("nkey_seed: None"));
    }

    #[test]
    fn nats_config_apply_creds_extracts_jwt_and_seed_h1gf40() {
        let seed = deterministic_user_seed(5);
        let jwt = test_user_jwt_for_seed(&seed, "issuer-A", "operator-A");
        let creds = test_creds_document(&jwt, &seed);
        let mut config = NatsConfig::default();
        config.apply_creds(&creds).expect("parse creds");

        assert_eq!(config.user_jwt.as_deref(), Some(jwt.as_str()));
        assert_eq!(config.nkey_seed.as_deref(), Some(seed.as_str()));
    }

    #[test]
    fn nats_config_apply_creds_rejects_missing_seed_block_h1gf40() {
        let seed = deterministic_user_seed(6);
        let jwt = test_user_jwt_for_seed(&seed, "issuer-B", "operator-B");
        let creds = format!("{NATS_CREDS_JWT_BEGIN}\n{jwt}\n{NATS_CREDS_JWT_END}\n");
        let mut config = NatsConfig::default();
        let err = config
            .apply_creds(&creds)
            .expect_err("missing seed block must fail closed");

        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("USER NKEY SEED")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_jwt_without_seed_h1gf40() {
        let mut config = NatsConfig::default();
        config.user_jwt = Some("a.b.c".to_string());
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("jwt-no-seed")),
                ..ServerInfo::default()
            }))
            .expect_err("JWT without seed must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("requires an nkey_seed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_non_user_seed_h1gf40() {
        let mut config = NatsConfig::default();
        config.nkey_seed = Some(deterministic_cluster_seed(4));
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("cluster-seed")),
                ..ServerInfo::default()
            }))
            .expect_err("non-user seed must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("USER seed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_malformed_seed_h1gf40() {
        let mut config = NatsConfig::default();
        config.nkey_seed = Some("not-a-valid-seed".to_string());
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("malformed-seed")),
                ..ServerInfo::default()
            }))
            .expect_err("malformed seed must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("invalid NKey seed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_malformed_jwt_h1gf40() {
        let mut config = NatsConfig::default();
        config.user_jwt = Some("not-a-jwt".to_string());
        config.nkey_seed = Some(deterministic_user_seed(12));
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("malformed-jwt")),
                ..ServerInfo::default()
            }))
            .expect_err("malformed JWT must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("compact JWT")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn connect_user_password_auth_fields_unchanged_h1gf40() {
        let (addr, server) = spawn_connect_recorder(
            r#"{"server_id":"id","server_name":"test","version":"2.10.0","proto":1,"max_payload":1048576}"#,
            None,
        );

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                ..Default::default()
            };
            let _client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("legacy user/password connect should still succeed");
        });

        let connect_line = server.join().expect("server join");
        let connect = parse_connect_json(&connect_line);
        assert_eq!(connect["user"], "alice");
        assert_eq!(connect["pass"], "secret");
        assert!(connect.get("jwt").is_none());
        assert!(connect.get("nkey").is_none());
        assert!(connect.get("sig").is_none());
    }

    #[test]
    fn connect_nkey_auth_emits_signed_nonce_fields_h1gf40() {
        let seed = deterministic_user_seed(9);
        let nonce = "nkey-challenge-12345";
        let (addr, server) = spawn_connect_recorder(
            &format!(
                r#"{{"server_id":"id","server_name":"test","version":"2.10.0","proto":1,"max_payload":1048576,"nonce":"{nonce}"}}"#
            ),
            None,
        );
        let seed_for_client = seed.clone();

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                nkey_seed: Some(seed_for_client),
                ..Default::default()
            };
            let _client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("nkey auth connect should succeed");
        });

        let connect_line = server.join().expect("server join");
        let connect = parse_connect_json(&connect_line);
        let public_key = KeyPair::from_seed(&seed).expect("seed").public_key();
        let sig = connect["sig"].as_str().expect("sig field");
        let sig = decode_base64_url(sig, "CONNECT sig").expect("decode sig");
        KeyPair::from_public_key(&public_key)
            .expect("public key")
            .verify(nonce.as_bytes(), &sig)
            .expect("signature verification");
        assert_eq!(connect["nkey"], public_key);
        assert!(connect.get("jwt").is_none());
        assert!(connect.get("auth_token").is_none());
        println!(
            "NATS_AUTH_HANDSHAKE scenario=nkey_connect mode=nkey nonce_len={} signature_verified=true jwt_claims=none server_response=connect_ok reconnect_behavior=not_exercised verdict=pass",
            nonce.len()
        );
    }

    #[test]
    fn connect_jwt_auth_signs_nonce_and_maps_auth_error_h1gf40() {
        let seed = deterministic_user_seed(11);
        let jwt = test_user_jwt_for_seed(&seed, "issuer-C", "operator-C");
        let nonce = "jwt-challenge-abcdef";
        let (addr, server) = spawn_connect_recorder(
            &format!(
                r#"{{"server_id":"id","server_name":"test","version":"2.10.0","proto":1,"max_payload":1048576,"nonce":"{nonce}"}}"#
            ),
            Some("-ERR 'Authorization Violation'"),
        );
        let seed_for_client = seed.clone();
        let jwt_for_client = jwt.clone();

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user_jwt: Some(jwt_for_client),
                nkey_seed: Some(seed_for_client),
                verbose: true,
                ..Default::default()
            };
            let err = NatsClient::connect_with_config(&cx, config)
                .await
                .expect_err("server auth violation must map to NatsError::Server");
            assert!(
                matches!(err, NatsError::Server(ref msg) if msg.contains("Authorization Violation")),
                "unexpected error: {err:?}"
            );
        });

        let connect_line = server.join().expect("server join");
        let connect = parse_connect_json(&connect_line);
        let claims = parse_nats_jwt_claims(&jwt).expect("claims summary");
        let public_key = KeyPair::from_seed(&seed).expect("seed").public_key();
        let sig = connect["sig"].as_str().expect("sig field");
        let sig = decode_base64_url(sig, "CONNECT sig").expect("decode sig");
        KeyPair::from_public_key(&public_key)
            .expect("public key")
            .verify(nonce.as_bytes(), &sig)
            .expect("signature verification");
        assert_eq!(connect["jwt"], jwt);
        assert!(connect.get("nkey").is_none());
        println!(
            "NATS_AUTH_HANDSHAKE scenario=jwt_connect mode=jwt nonce_len={} signature_verified=true jwt_claims=\"{}\" server_response=authorization_violation reconnect_behavior=not_exercised verdict=pass",
            nonce.len(),
            claims.log_summary()
        );
    }

    #[test]
    fn test_config_from_url_with_token() {
        let config = NatsConfig::from_url("nats://mytoken@localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert_eq!(config.token, Some("mytoken".to_string()));
    }

    #[test]
    fn test_config_from_url_default_port() {
        let config = NatsConfig::from_url("nats://localhost").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222); // Default port
    }

    #[test]
    fn test_config_from_tls_url_sets_require_tls() {
        let config = NatsConfig::from_url("tls://localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert!(config.require_tls);
    }

    #[test]
    fn test_config_from_url_ipv6() {
        let config = NatsConfig::from_url("nats://[::1]:4333").unwrap();
        assert_eq!(config.host, "[::1]");
        assert_eq!(config.port, 4333);
    }

    #[test]
    fn test_config_from_url_password_with_at_sign() {
        let config = NatsConfig::from_url("nats://user:pa@ss@localhost:4222").unwrap();
        assert_eq!(config.user.as_deref(), Some("user"));
        assert_eq!(config.password.as_deref(), Some("pa@ss"));
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
    }

    /// br-asupersync-2kmc12: when the server's INFO frame advertises
    /// `tls_required = true`, NatsClient::connect_with_config MUST
    /// upgrade to TLS BEFORE sending the CONNECT command. In builds
    /// that cannot construct TLS, it must still fail closed before
    /// plaintext CONNECT. This is the credential-leak defense: the
    /// previous implementation read tls_required into ServerInfo but
    /// never consulted it, sending CONNECT (with user/pass/token in
    /// cleartext) to a server that claimed to require TLS.
    ///
    /// The test server scripts the wire exchange:
    ///   1. Accept the TCP connection.
    ///   2. Write an INFO frame with tls_required = true.
    ///   3. Read whatever the client sends. Plaintext CONNECT is
    ///      forbidden; TLS ClientHello bytes are acceptable in TLS
    ///      builds and prove the upgrade happens before credentials.
    #[test]
    fn connect_aborts_without_sending_connect_when_server_requires_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept test client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            // 1. Send INFO with tls_required=true.
            let info = b"INFO {\"server_id\":\"test\",\"server_name\":\"test\",\"version\":\"2.9.0\",\"proto\":1,\"max_payload\":1048576,\"tls_required\":true}\r\n";
            stream.write_all(info).expect("write INFO");
            stream.flush().expect("flush INFO");

            // 2. Read whatever the client sends. The client MUST NOT
            //    send plaintext CONNECT. TLS-enabled builds may send a
            //    ClientHello here; this plaintext test server then
            //    closes and the client surfaces a handshake error.
            let mut buf = [0u8; 1024];
            match stream.read(&mut buf) {
                Ok(0) => {
                    // Clean EOF — TLS unavailable/configured fail-closed.
                }
                Ok(n) => {
                    let leaked = String::from_utf8_lossy(&buf[..n]);
                    assert!(
                        !leaked.starts_with("CONNECT "),
                        "br-asupersync-2kmc12 REGRESSION: plaintext CONNECT \
                         sent after server INFO advertised tls_required=true; \
                         payload starts with: {leaked:?}"
                    );
                    assert!(
                        !leaked.contains("secret"),
                        "br-asupersync-2kmc12 REGRESSION: credentials leaked \
                         before TLS handshake; payload starts with: {leaked:?}"
                    );
                    // Non-CONNECT bytes are expected TLS handshake bytes.
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!(
                        "client neither closed nor attempted TLS after server \
                         signalled tls_required"
                    );
                }
                Err(_) => {
                    // Connection-reset / broken pipe — also acceptable;
                    // the client closed its side, OS reports the reset.
                }
            }
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                ..Default::default()
            };
            let result = NatsClient::connect_with_config(&cx, config).await;
            result.expect_err(
                "plaintext test server cannot complete TLS, but client must never send plaintext CONNECT",
            );
        });

        server.join().expect("server thread join");
    }

    /// br-asupersync-2kmc12: when the client config sets require_tls =
    /// true, the same pre-CONNECT TLS gate fires regardless of what
    /// the server advertises.
    #[test]
    fn connect_aborts_without_sending_connect_when_client_requires_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept test client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            // Server advertises tls_required=false (legacy plaintext NATS).
            // Client config still mandates TLS so the gate must fire.
            let info = b"INFO {\"server_id\":\"test\",\"server_name\":\"test\",\"version\":\"2.9.0\",\"proto\":1,\"max_payload\":1048576,\"tls_required\":false}\r\n";
            stream.write_all(info).expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let leaked = String::from_utf8_lossy(&buf[..n]);
                    assert!(
                        !leaked.starts_with("CONNECT "),
                        "br-asupersync-2kmc12 REGRESSION: plaintext CONNECT \
                         sent despite client require_tls=true; payload: {leaked:?}"
                    );
                    assert!(
                        !leaked.contains("secret"),
                        "br-asupersync-2kmc12 REGRESSION: credentials leaked \
                         before TLS handshake; payload: {leaked:?}"
                    );
                }
            }
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                require_tls: true,
                ..Default::default()
            };
            let result = NatsClient::connect_with_config(&cx, config).await;
            result.expect_err(
                "plaintext test server cannot complete TLS, but client must never send plaintext CONNECT",
            );
        });

        server.join().expect("server thread join");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn connect_upgrades_to_tls_before_connect_when_server_requires_tls() {
        use crate::io::AsyncReadExt;
        use crate::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept TLS client");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"test\",\"server_name\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576,\"tls_required\":true}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let async_stream = TcpStream::from_std(stream).expect("wrap accepted TCP stream");
            let chain = CertificateChain::from_pem(NATS_TEST_CERT_PEM).expect("test cert chain");
            let key = PrivateKey::from_pem(NATS_TEST_KEY_PEM).expect("test private key");
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .build()
                .expect("build test acceptor");

            futures_lite::future::block_on(async move {
                let mut tls_stream = acceptor.accept(async_stream).await.expect("accept TLS");
                let mut buf = [0_u8; 4096];
                let n = tls_stream.read(&mut buf).await.expect("read TLS CONNECT");
                assert!(n > 0, "client must send CONNECT over TLS");
                let connect = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    connect.starts_with("CONNECT "),
                    "expected CONNECT over TLS, got {connect:?}"
                );
                assert!(
                    connect.contains("\"tls_required\":true"),
                    "CONNECT should advertise TLS requirement, got {connect:?}"
                );
                assert!(
                    connect.contains("\"user\":\"alice\"")
                        && connect.contains("\"pass\":\"secret\""),
                    "credentials should be present only inside TLS, got {connect:?}"
                );
            });
        });

        run_test_with_cx(|cx| async move {
            let certs = Certificate::from_pem(NATS_TEST_CERT_PEM).expect("parse test cert");
            let connector = TlsConnectorBuilder::new()
                .insecure_add_root_certificate(&certs[0])
                .handshake_timeout(Duration::from_secs(2))
                .build()
                .expect("build test connector");
            let config = NatsConfig {
                host: "localhost".to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                tls_connector: Some(connector),
                ..Default::default()
            };

            let client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("TLS NATS handshake should succeed");
            assert!(
                matches!(
                    &client.mode,
                    NatsClientMode::Direct(connection) if connection.tls_required_on_connect
                ),
                "TLS requirement must be preserved on the direct connection for reconnect downgrade defense"
            );
        });

        server.join().expect("TLS server thread join");
    }

    #[test]
    fn test_server_info_parse() {
        let json = r#"{"server_id":"id123","server_name":"test","version":"2.9.0","proto":1,"max_payload":1048576,"tls_required":false,"nonce":"abc123"}"#;
        let info = ServerInfo::parse(json).expect("valid INFO JSON");
        assert_eq!(info.server_id, "id123");
        assert_eq!(info.server_name, "test");
        assert_eq!(info.version, "2.9.0");
        assert_eq!(info.proto, 1);
        assert_eq!(info.max_payload, 1_048_576);
        assert!(!info.tls_required);
        assert_eq!(info.nonce.as_deref(), Some("abc123"));
    }

    #[test]
    fn server_info_reads_top_level_fields_whatever_the_json_spacing() {
        // br-asupersync-pm29wb: fields were found by the text `"key":`, so
        // valid JSON with a space before the colon read tls_required as false
        // (the TLS upgrade was skipped) and a nested key shadowed the real one.
        let info = ServerInfo::parse(
            r#"{"cluster": {"tls_required": false, "max_payload": 7},
                "tls_required" : true, "max_payload" : 1048576,
                "server_id" : "S1", "proto" : 1, "headers" : true}"#,
        )
        .expect("valid INFO");
        assert!(info.tls_required);
        assert_eq!(info.max_payload, 1_048_576);
        assert_eq!(info.server_id, "S1");
        assert_eq!(info.proto, 1);
        assert!(info.headers);
    }

    #[test]
    fn test_config_invalid_url() {
        let result = NatsConfig::from_url("http://localhost:4222");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_config_invalid_port() {
        let result = NatsConfig::from_url("nats://localhost:notaport");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_config_invalid_empty_host() {
        let result = NatsConfig::from_url("nats://:4222");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_nats_error_display() {
        assert_eq!(
            format!("{}", NatsError::Cancelled),
            "NATS operation cancelled"
        );
        assert_eq!(format!("{}", NatsError::Closed), "NATS connection closed");
        assert_eq!(format!("{}", NatsError::NotConnected), "NATS not connected");
        assert_eq!(
            format!("{}", NatsError::SubscriptionNotFound(42)),
            "NATS subscription not found: 42"
        );
        assert_eq!(
            format!("{}", NatsError::Server("auth error".to_string())),
            "NATS server error: auth error"
        );
        assert_eq!(
            format!("{}", NatsError::Protocol("parse error".to_string())),
            "NATS protocol error: parse error"
        );
        assert_eq!(
            format!("{}", NatsError::InvalidUrl("bad".to_string())),
            "Invalid NATS URL: bad"
        );
        assert_eq!(
            format!("{}", NatsError::InvalidAuth("bad auth".to_string())),
            "NATS invalid auth configuration: bad auth"
        );
    }

    #[test]
    fn test_validate_nats_token_rejects_whitespace_and_controls() {
        assert!(validate_nats_token("foo.bar", "subject").is_ok());
        assert!(validate_nats_token("", "subject").is_err());
        assert!(validate_nats_token("foo bar", "subject").is_err());
        assert!(validate_nats_token("foo\r\nPUB x 1\r\nx", "subject").is_err());
        assert!(validate_nats_token("queue\tgroup", "queue group").is_err());
    }

    #[test]
    fn test_validate_nats_publish_subject_rejects_wildcards_and_empty_tokens() {
        assert!(validate_nats_publish_subject("foo.bar", "subject").is_ok());
        assert!(validate_nats_publish_subject("_INBOX.123.abc", "subject").is_ok());
        assert!(validate_nats_publish_subject("foo.bar.>", "subject").is_err());
        assert!(validate_nats_publish_subject("*", "subject").is_err());
        assert!(validate_nats_publish_subject("foo.*", "subject").is_err());
        assert!(validate_nats_publish_subject("foo..bar", "subject").is_err());
    }

    #[test]
    fn test_validate_nats_subscription_pattern_enforces_wildcard_grammar() {
        assert!(validate_nats_subscription_pattern("foo.bar", "subject").is_ok());
        assert!(validate_nats_subscription_pattern("foo.*", "subject").is_ok());
        assert!(validate_nats_subscription_pattern("foo.>", "subject").is_ok());
        assert!(validate_nats_subscription_pattern(">", "subject").is_ok());
        assert!(validate_nats_subscription_pattern("foo.>.bar", "subject").is_err());
        assert!(validate_nats_subscription_pattern("foo*>", "subject").is_err());
        assert!(validate_nats_subscription_pattern("foo..bar", "subject").is_err());
        assert!(validate_nats_subscription_pattern("foo.*.>.bar", "subject").is_err());
    }

    #[test]
    fn test_subscription_matches_subject_exact_and_single_wildcard() {
        assert!(subscription_matches_subject("time.us.east", "time.us.east"));
        assert!(subscription_matches_subject("time.*.east", "time.us.east"));
        assert!(!subscription_matches_subject(
            "time.*.east",
            "time.us.east.atlanta"
        ));
        assert!(!subscription_matches_subject("time.*.east", "time.east"));
    }

    #[test]
    fn test_subscription_matches_subject_tail_wildcard_requires_trailing_tokens() {
        assert!(subscription_matches_subject("time.>", "time.us"));
        assert!(subscription_matches_subject(
            "time.>",
            "time.us.east.atlanta"
        ));
        assert!(!subscription_matches_subject("time.>", "time"));
        assert!(subscription_matches_subject(">", "time.us"));
    }

    #[test]
    fn test_subscription_matches_subject_rejects_invalid_wildcard_placements() {
        assert!(!subscription_matches_subject("time>.east", "time.us.east"));
        assert!(!subscription_matches_subject("time.>.east", "time.us.east"));
        assert!(!subscription_matches_subject("time.*east", "time.us.east"));
        assert!(!subscription_matches_subject("time.east", "time.*"));
    }

    #[test]
    fn test_subscription_matches_subject_rejects_empty_tokens() {
        assert!(!subscription_matches_subject("time..east", "time.us.east"));
        assert!(!subscription_matches_subject(".time.east", "time.us.east"));
        assert!(!subscription_matches_subject("time.east", "time..east"));
        assert!(!subscription_matches_subject("time.east", "time.east."));
    }

    #[test]
    fn test_random_suffix_format() {
        let cx: Cx = Cx::for_testing();
        let s1 = random_suffix(&cx);
        let s2 = random_suffix(&cx);
        // Verify format is correct (16 hex chars)
        assert_eq!(s1.len(), 16);
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s2.len(), 16);
        assert!(s2.chars().all(|c| c.is_ascii_hexdigit()));
        // With deterministic entropy, successive calls should differ
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_server_info_parse_minimal() {
        let json = "{}";
        let info = ServerInfo::parse(json).expect("valid empty INFO JSON");
        assert_eq!(info.server_id, "");
        assert_eq!(info.max_payload, 0);
        assert!(!info.tls_required);
    }

    #[test]
    fn test_server_info_parse_with_tls() {
        let json = r#"{"tls_required":true,"tls_available":true}"#;
        let info = ServerInfo::parse(json).expect("valid TLS INFO JSON");
        assert!(info.tls_required);
        assert!(info.tls_available);
    }

    #[test]
    fn test_nats_config_default() {
        let config = NatsConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 4222);
        assert!(config.user.is_none());
        assert!(config.password.is_none());
        assert!(config.token.is_none());
        assert!(config.user_jwt.is_none());
        assert!(config.nkey_seed.is_none());
        assert!(!config.verbose);
        assert!(!config.pedantic);
        assert_eq!(config.max_payload, 1_048_576);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_read_buffer_operations() {
        let mut buf = NatsReadBuffer::new();
        assert!(buf.available().is_empty());

        buf.extend(b"hello\r\n").unwrap();
        assert_eq!(buf.available(), b"hello\r\n");
        assert_eq!(buf.find_crlf(), Some(5));

        buf.consume(7);
        assert!(buf.available().is_empty());
    }

    #[test]
    fn test_read_buffer_partial_crlf() {
        let mut buf = NatsReadBuffer::new();
        buf.extend(b"hello\r").unwrap();
        assert_eq!(buf.find_crlf(), None); // Incomplete CRLF

        buf.extend(b"\n").unwrap();
        assert_eq!(buf.find_crlf(), Some(5));
    }

    #[test]
    fn test_nats_json_escape_c1_control() {
        // C1 control U+0080 is 2 bytes in UTF-8 (0xC2, 0x80).
        // Must emit a single \u0080 escape, not per-byte \u00c2\u0080.
        let input = "\u{0080}";
        let escaped = nats_json_escape(input);
        assert_eq!(escaped, "\\u0080");
    }

    #[test]
    fn test_nats_json_escape_c0_control() {
        // C0 control U+0001 (SOH) is 1 byte in UTF-8.
        let escaped = nats_json_escape("\u{0001}");
        assert_eq!(escaped, "\\u0001");
    }

    #[test]
    fn test_nats_json_escape_common_chars() {
        assert_eq!(nats_json_escape(r#"hello"world"#), r#"hello\"world"#);
        assert_eq!(nats_json_escape("back\\slash"), "back\\\\slash");
        assert_eq!(nats_json_escape("new\nline"), "new\\nline");
        assert_eq!(nats_json_escape("plain"), "plain");
    }

    // Pure data-type tests (wave 14 – CyanBarn)

    #[test]
    fn nats_error_display_all_variants() {
        assert!(
            NatsError::Io(io::Error::other("e"))
                .to_string()
                .contains("I/O error")
        );
        assert!(
            NatsError::Protocol("p".into())
                .to_string()
                .contains("protocol error")
        );
        assert!(
            NatsError::Server("s".into())
                .to_string()
                .contains("server error")
        );
        assert!(
            NatsError::InvalidUrl("bad://".into())
                .to_string()
                .contains("bad://")
        );
        assert!(
            NatsError::InvalidAuth("bad auth".into())
                .to_string()
                .contains("bad auth")
        );
        assert!(NatsError::Cancelled.to_string().contains("cancelled"));
        assert!(NatsError::Closed.to_string().contains("closed"));
        assert!(
            NatsError::SubscriptionNotFound(42)
                .to_string()
                .contains("42")
        );
        assert!(
            NatsError::NotConnected
                .to_string()
                .contains("not connected")
        );
    }

    #[test]
    fn nats_error_debug() {
        let err = NatsError::Closed;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Closed"));
    }

    #[test]
    fn nats_error_source_io() {
        let err = NatsError::Io(io::Error::other("disk"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn nats_request_timeout_error_is_classified_as_timeout() {
        assert!(request_timeout_error().is_timeout());
    }

    #[test]
    fn request_enforces_timeout_while_socket_reads_are_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"id\",\"server_name\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut reader = BufReader::new(stream);
            let connect = read_protocol_line(&mut reader);
            assert!(
                connect.starts_with("CONNECT "),
                "unexpected CONNECT: {connect:?}"
            );

            let subscribe = read_protocol_line(&mut reader);
            assert!(
                subscribe.starts_with("SUB _INBOX."),
                "unexpected SUB: {subscribe:?}"
            );

            let publish = read_protocol_line(&mut reader);
            assert!(
                publish.starts_with("PUB svc.echo _INBOX."),
                "unexpected PUB: {publish:?}"
            );

            let payload_len = parse_pub_payload_len(&publish);
            let mut payload = vec![0_u8; payload_len + 2];
            reader
                .read_exact(&mut payload)
                .expect("read request payload");
            assert_eq!(&payload[..payload_len], b"ping");
            assert_eq!(&payload[payload_len..], b"\r\n");

            read_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                request_timeout: Duration::from_millis(100),
                ..Default::default()
            };

            assert_completes_within(
                Duration::from_secs(2),
                "nats request timeout enforcement",
                move || {
                    let config = config.clone();
                    Box::pin(async move {
                        let mut client = NatsClient::connect_with_config(&cx, config)
                            .await
                            .expect("connect to test server");
                        let err = client
                            .request(&cx, "svc.echo", b"ping")
                            .await
                            .expect_err("request must time out");
                        assert!(
                            matches!(err, NatsError::Io(ref io_err) if io_err.kind() == io::ErrorKind::TimedOut),
                            "expected timed out I/O error, got {err:?}"
                        );
                        assert!(err.is_timeout(), "expected timeout classification");
                    })
                },
            )
            .await;
        });

        let unsubscribe = server.join().expect("server join");
        assert!(
            unsubscribe.starts_with("UNSUB "),
            "timeout cleanup must unsubscribe, got {unsubscribe:?}"
        );
    }

    #[test]
    fn publish_request_with_headers_rejects_oversize_headers_before_wire_write_uu9ayc() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            *state.server_info.lock() = Some(ServerInfo {
                headers: true,
                max_payload: 32,
                ..ServerInfo::default()
            });
            let mut client = NatsConnection {
                config: NatsConfig {
                    max_payload: 32,
                    ..Default::default()
                },
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state,
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let err = client
                .publish_request_with_headers(
                    &cx,
                    "svc.echo",
                    "_INBOX.reply",
                    &[("Nats-Msg-Id", b"1234567890abcdef")],
                    b"",
                )
                .await
                .expect_err("oversize headers must fail closed");
            match err {
                NatsError::Protocol(msg) => {
                    assert_eq!(msg, "NATS header block too large: 43 > 32");
                }
                other => panic!("expected Protocol error, got {other:?}"),
            }
        });

        let wire = server.join().expect("server join");
        assert!(
            wire.is_none(),
            "oversize headers must not emit HPUB bytes, got {wire:?}"
        );
    }

    #[test]
    fn unsubscribe_on_disconnected_client_skips_wire_write() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            let sid = 41;
            let (tx, _rx) = mpsc::channel(8);
            state.subscriptions.lock().insert(
                sid,
                SubscriptionState {
                    subject: "svc.echo".to_string(),
                    queue_group: None,
                    sender: tx,
                },
            );

            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };

            let err = client
                .unsubscribe(&cx, sid)
                .await
                .expect_err("disconnected unsubscribe must fail closed");
            assert!(matches!(err, NatsError::NotConnected));
            assert!(
                !state.subscriptions.lock().contains_key(&sid),
                "local subscription must still be removed"
            );
        });

        let line = server.join().expect("server join");
        assert!(
            line.is_none(),
            "disconnected unsubscribe must not emit UNSUB, got {line:?}"
        );
    }

    #[test]
    fn received_reply_survives_unsubscribe_cleanup_failure_ne8jdw() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            let sid = 42;
            let (tx, _rx) = mpsc::channel(8);
            state.subscriptions.lock().insert(
                sid,
                SubscriptionState {
                    subject: "_INBOX.reply".to_string(),
                    queue_group: None,
                    sender: tx,
                },
            );
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };
            let message = Message {
                subject: "_INBOX.reply".to_string(),
                sid,
                reply_to: None,
                headers: None,
                payload: b"completed".to_vec(),
            };

            let reply = client
                .finalize_request_reply(&cx, sid, message)
                .await
                .expect("cleanup failure must not replace a completed reply");
            assert_eq!(reply.payload, b"completed");
            assert!(state.subscriptions.lock().is_empty());
            assert!(!client.connected);
        });

        let line = server.join().expect("server join");
        assert!(
            line.is_none(),
            "failed cleanup on a disconnected client must not emit wire bytes"
        );
    }

    #[test]
    fn ping_on_disconnected_client_skips_wire_write() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };

            let err = client
                .ping(&cx)
                .await
                .expect_err("disconnected ping must fail closed");
            assert!(matches!(err, NatsError::NotConnected));
        });

        let line = server.join().expect("server join");
        assert!(
            line.is_none(),
            "disconnected ping must not emit wire bytes, got {line:?}"
        );
    }

    /// br-asupersync-messaging-client-audit-k6pxks item 8: the `PONG` that
    /// answers an earlier keepalive `PING` is not `ping()`'s own. `ping()`
    /// returns on the second one, after the message the server sent between
    /// them, so the publish-then-ping flush still covers what came before it.
    #[test]
    fn ping_waits_past_the_pong_of_an_earlier_keepalive_ping_k6pxks() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            let lines: Vec<String> = (0..3)
                .map(|_| read_protocol_line(&mut reader).trim_end().to_string())
                .collect();
            reader
                .get_mut()
                .write_all(b"PONG\r\nMSG svc.flush 1 5\r\nafter\r\nPONG\r\n")
                .expect("write both PONGs");
            reader.get_mut().flush().expect("flush both PONGs");
            let _ = read_optional_protocol_line(&mut reader);
            lines
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let mut flushed = client.subscribe(&cx, "svc.flush").await.expect("subscribe");
            client
                .send_keepalive_ping(&cx)
                .await
                .expect("keepalive PING");
            client.ping(&cx).await.expect("ping");
            assert_eq!(
                client.state.pongs.load(Ordering::Acquire),
                2,
                "ping returned on the keepalive's PONG"
            );
            assert_eq!(client.unanswered_pings(), 0);
            let message = flushed
                .try_next()
                .expect("the message between the two PONGs is dispatched first");
            assert_eq!(message.payload, b"after");
            assert!(client.connected);
        });

        let lines = server.join().expect("server join");
        assert_eq!(lines, ["SUB svc.flush 1", "PING", "PING"]);
    }

    #[test]
    fn process_ping_write_failure_marks_client_disconnected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (close_tx, close_rx) = std_mpsc::channel();
        let (closed_tx, closed_rx) = std_mpsc::channel();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            close_rx.recv().expect("close signal");
            SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .expect("force reset on close");
            drop(stream);
            closed_tx.send(()).expect("closed ack");
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            client.read_buf.extend(b"PING\r\n").expect("buffer ping");
            close_tx.send(()).expect("signal close");
            closed_rx.recv().expect("server closed");
            thread::sleep(Duration::from_millis(20));

            let err = client
                .process(&cx)
                .await
                .expect_err("PONG write must fail against reset peer");
            assert!(
                matches!(err, NatsError::Io(_)),
                "expected I/O error, got {err:?}"
            );
            assert!(
                !client.connected,
                "client must remain disconnected after failed PONG write"
            );

            let follow_up = client
                .publish(&cx, "svc.echo", b"ping")
                .await
                .expect_err("fail-closed client must reject follow-up publish");
            assert!(matches!(follow_up, NatsError::NotConnected));
        });

        server.join().expect("server join");
    }

    #[test]
    fn request_ping_write_failure_cleans_up_temporary_subscription() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let mut reader = BufReader::new(stream);

            let subscribe = read_protocol_line(&mut reader);
            assert!(
                subscribe.starts_with("SUB _INBOX."),
                "unexpected SUB: {subscribe:?}"
            );

            let publish = read_protocol_line(&mut reader);
            assert!(
                publish.starts_with("PUB svc.echo _INBOX."),
                "unexpected PUB: {publish:?}"
            );

            let payload_len = parse_pub_payload_len(&publish);
            let mut payload = vec![0_u8; payload_len + 2];
            reader
                .read_exact(&mut payload)
                .expect("read request payload");
            assert_eq!(&payload[..payload_len], b"ping");
            assert_eq!(&payload[payload_len..], b"\r\n");

            let stream = reader.into_inner();
            SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .expect("force reset on close");
            drop(stream);
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            client.read_buf.extend(b"PING\r\n").expect("buffer ping");

            let err = client
                .request(&cx, "svc.echo", b"ping")
                .await
                .expect_err("request must fail when PONG write fails");
            assert!(
                matches!(err, NatsError::Io(_)),
                "expected I/O error, got {err:?}"
            );
            assert!(
                state.subscriptions.lock().is_empty(),
                "temporary request inbox subscription must be cleaned up after PONG write failure"
            );
            assert!(
                !client.connected,
                "client must remain disconnected after failed PONG write"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn nats_error_source_none_for_others() {
        assert!(std::error::Error::source(&NatsError::Cancelled).is_none());
        assert!(std::error::Error::source(&NatsError::Closed).is_none());
        assert!(std::error::Error::source(&NatsError::NotConnected).is_none());
    }

    #[test]
    fn nats_error_from_io() {
        let io_err = io::Error::other("net");
        let err: NatsError = NatsError::from(io_err);
        assert!(matches!(err, NatsError::Io(_)));
    }

    #[test]
    fn nats_config_debug_clone() {
        let cfg = NatsConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("NatsConfig"));

        let cloned = cfg;
        assert_eq!(cloned.host, "127.0.0.1");
        assert_eq!(cloned.port, 4222);
    }

    #[test]
    fn nats_config_from_url_with_creds() {
        let cfg = NatsConfig::from_url("nats://user:pass@myhost:4223").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 4223);
        assert_eq!(cfg.user, Some("user".into()));
        assert_eq!(cfg.password, Some("pass".into()));
    }

    #[test]
    fn nats_config_from_url_with_token() {
        let cfg = NatsConfig::from_url("nats://mytoken@server:4222").unwrap();
        assert_eq!(cfg.token, Some("mytoken".into()));
        assert!(cfg.user.is_none());
    }

    #[test]
    fn nats_config_from_url_host_only() {
        let cfg = NatsConfig::from_url("nats://myhost").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 4222); // default
    }

    #[test]
    fn nats_config_from_url_invalid_scheme() {
        assert!(NatsConfig::from_url("http://localhost").is_err());
    }

    #[test]
    fn message_debug_clone() {
        let msg = Message {
            subject: "foo.bar".into(),
            sid: 1,
            reply_to: Some("_INBOX.123".into()),
            headers: None,
            payload: b"hello".to_vec(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("foo.bar"));
        assert!(dbg.contains("_INBOX"));

        let cloned = msg;
        assert_eq!(cloned.subject, "foo.bar");
        assert_eq!(cloned.sid, 1);
        assert_eq!(cloned.payload, b"hello");
    }

    #[test]
    fn message_no_reply() {
        let msg = Message {
            subject: "test".into(),
            sid: 0,
            reply_to: None,
            headers: None,
            payload: vec![],
        };
        assert!(msg.reply_to.is_none());
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn nats_pubsub_event_snapshot_scrubbed() {
        let msg = Message {
            subject: "svc.echo".into(),
            sid: 7,
            reply_to: Some("_INBOX.42.reply".into()),
            headers: None,
            payload: b"{\"event\":\"published\",\"seq\":12}".to_vec(),
        };

        insta::assert_json_snapshot!("nats_pubsub_event_scrubbed", message_event_snapshot(&msg));
    }

    #[test]
    fn parse_hmsg_preserves_header_block_and_payload_72u8k4() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            drop(stream);
        });

        run_test_with_cx(|_cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let headers = b"NATS/1.0\r\nFoo: bar\r\n\r\n";
            let payload = b"hello";
            let frame = format!(
                "HMSG headers.test 789 {} {}\r\n",
                headers.len(),
                headers.len() + payload.len()
            );
            client
                .read_buf
                .extend(frame.as_bytes())
                .expect("buffer HMSG header");
            client.read_buf.extend(headers).expect("buffer headers");
            client.read_buf.extend(payload).expect("buffer payload");
            client.read_buf.extend(b"\r\n").expect("buffer terminator");

            let parsed = client
                .try_parse_message()
                .expect("parse HMSG")
                .expect("complete HMSG frame");
            let NatsMessage::Msg(message) = parsed else {
                panic!("expected HMSG to parse as Msg");
            };

            assert_eq!(message.subject, "headers.test");
            assert_eq!(message.sid, 789);
            assert!(message.reply_to.is_none());
            assert_eq!(message.headers.as_deref(), Some(headers.as_slice()));
            assert_eq!(message.payload, payload);
        });

        server.join().expect("server join");
    }

    /// nats-server 2.10 sends the no-responders status as a bare
    /// `NATS/1.0 503` line with no Description header (observed against the
    /// real server); the client must still name the condition.
    #[test]
    fn reply_status_error_names_no_responders_for_bare_503_header() {
        let message = Message {
            subject: "_INBOX.2".into(),
            sid: 2,
            reply_to: None,
            headers: Some(b"NATS/1.0 503\r\n\r\n".to_vec()),
            payload: Vec::new(),
        };

        let err = NatsConnection::reply_status_error(&message)
            .expect("bare 503 status reply must surface as error");
        match err {
            NatsError::Server(message) => {
                assert_eq!(message, "status 503: No Responders");
            }
            other => panic!("expected server error, got {other:?}"),
        }

        // Planted negative: an unknown bare code keeps the numeric fallback
        // and is not relabelled.
        let unknown = Message {
            subject: "_INBOX.3".into(),
            sid: 3,
            reply_to: None,
            headers: Some(b"NATS/1.0 599\r\n\r\n".to_vec()),
            payload: Vec::new(),
        };
        match NatsConnection::reply_status_error(&unknown).expect("599 must surface as error") {
            NatsError::Server(message) => assert_eq!(message, "status 599: status 599"),
            other => panic!("expected server error, got {other:?}"),
        }
    }

    #[test]
    fn reply_status_error_surfaces_no_responders_hmsg_72u8k4() {
        let message = Message {
            subject: "_INBOX.1".into(),
            sid: 1,
            reply_to: None,
            headers: Some(
                b"NATS/1.0\r\nStatus: 503\r\nDescription: No Responders\r\n\r\n".to_vec(),
            ),
            payload: Vec::new(),
        };

        let err = NatsConnection::reply_status_error(&message)
            .expect("empty status-only HMSG reply must surface as error");
        match err {
            NatsError::Server(message) => {
                assert!(
                    message.contains("503"),
                    "expected status code, got {message}"
                );
                assert!(
                    message.contains("No Responders"),
                    "expected server description, got {message}"
                );
            }
            other => panic!("expected server error, got {other:?}"),
        }
    }

    #[test]
    fn parse_hmsg_accepts_nats_status_line_header_block_6xjxd7() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            drop(stream);
        });

        run_test_with_cx(|_cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let headers = b"NATS/1.0 408 Request Timeout\r\n\r\n";
            let frame = format!("HMSG _INBOX.1 42 {} {}\r\n", headers.len(), headers.len());
            client
                .read_buf
                .extend(frame.as_bytes())
                .expect("buffer HMSG status header");
            client.read_buf.extend(headers).expect("buffer headers");
            client.read_buf.extend(b"\r\n").expect("buffer terminator");

            let parsed = client
                .try_parse_message()
                .expect("parse status HMSG")
                .expect("complete status HMSG frame");
            let NatsMessage::Msg(message) = parsed else {
                panic!("expected status HMSG to parse as Msg");
            };

            assert_eq!(message.subject, "_INBOX.1");
            assert_eq!(message.sid, 42);
            assert!(message.payload.is_empty());
            assert_eq!(message.headers.as_deref(), Some(headers.as_slice()));

            let err = NatsConnection::reply_status_error(&message)
                .expect("status-line HMSG reply must surface as server error");
            match err {
                NatsError::Server(message) => {
                    assert!(
                        message.contains("408"),
                        "expected status code, got {message}"
                    );
                    assert!(
                        message.contains("Request Timeout"),
                        "expected status description, got {message}"
                    );
                }
                other => panic!("expected server error, got {other:?}"),
            }
        });

        server.join().expect("server join");
    }

    #[test]
    fn server_info_default() {
        let info = ServerInfo::default();
        assert!(info.server_id.is_empty());
        assert!(info.server_name.is_empty());
        assert!(info.version.is_empty());
        assert_eq!(info.proto, 0);
        assert_eq!(info.max_payload, 0);
        assert!(!info.tls_required);
        assert!(!info.tls_available);
        assert!(info.connect_urls.is_empty());
    }

    #[test]
    fn server_info_debug_clone() {
        let info = ServerInfo {
            server_id: "test-id".into(),
            ..Default::default()
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ServerInfo"));

        let cloned = info;
        assert_eq!(cloned.server_id, "test-id");
    }

    #[test]
    fn server_info_parse_full() {
        let json = r#"{"server_id":"abc","server_name":"srv","version":"2.10","proto":1,"max_payload":1048576}"#;
        let info = ServerInfo::parse(json).expect("valid INFO JSON");
        assert_eq!(info.server_id, "abc");
        assert_eq!(info.server_name, "srv");
        assert_eq!(info.version, "2.10");
        assert_eq!(info.proto, 1);
        assert_eq!(info.max_payload, 1_048_576);
    }

    #[test]
    fn server_info_parse_empty() {
        let info = ServerInfo::parse("{}").expect("valid empty INFO JSON");
        assert!(info.server_id.is_empty());
        assert_eq!(info.proto, 0);
    }

    #[test]
    fn server_info_parse_rejects_malformed_json() {
        let err = ServerInfo::parse(r#"{"server_id":"abc""#)
            .expect_err("malformed INFO JSON must fail closed");
        assert!(
            matches!(err, NatsError::Protocol(ref message) if message.contains("malformed INFO JSON")),
            "expected malformed INFO protocol error, got {err:?}"
        );
    }

    #[test]
    fn server_info_parse_rejects_non_object_json() {
        let err = ServerInfo::parse("[]").expect_err("INFO JSON must be an object");
        assert!(
            matches!(err, NatsError::Protocol(ref message) if message.contains("expected object")),
            "expected non-object INFO protocol error, got {err:?}"
        );
    }

    #[test]
    fn nats_config_debug_clone_default() {
        let cfg = NatsConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.host, "127.0.0.1");
        assert_eq!(cloned.port, 4222);
        assert!(!cloned.verbose);
        assert!(!cloned.pedantic);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("NatsConfig"));
    }

    #[test]
    fn server_info_debug_clone_default() {
        let info = ServerInfo::default();
        assert!(info.server_id.is_empty());
        assert_eq!(info.proto, 0);
        assert!(!info.tls_required);
        let cloned = info.clone();
        assert_eq!(cloned.max_payload, 0);
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ServerInfo"));
    }

    // ====================================================================
    // T6.7 Hardening tests
    // ====================================================================

    #[test]
    fn test_max_read_buffer_constant() {
        assert_eq!(DEFAULT_MAX_READ_BUFFER, 8 * 1024 * 1024);
    }

    #[test]
    fn test_read_buffer_rejects_oversized() {
        let mut buf = NatsReadBuffer::new();
        let big = vec![0u8; DEFAULT_MAX_READ_BUFFER + 1];
        let err = buf.extend(&big).unwrap_err();
        assert!(matches!(err, NatsError::Protocol(_)));
    }

    #[test]
    fn test_read_buffer_accepts_max() {
        let mut buf = NatsReadBuffer::new();
        let data = vec![0u8; DEFAULT_MAX_READ_BUFFER];
        buf.extend(&data).unwrap();
        assert_eq!(buf.available().len(), DEFAULT_MAX_READ_BUFFER);
    }

    #[test]
    fn test_read_buffer_consumed_data_not_counted() {
        let mut buf = NatsReadBuffer::new();
        // Fill to near max
        let data = vec![0u8; DEFAULT_MAX_READ_BUFFER - 100];
        buf.extend(&data).unwrap();
        // Consume most of it
        buf.consume(DEFAULT_MAX_READ_BUFFER - 200);
        // Now should be able to add more
        let more = vec![0u8; 200];
        buf.extend(&more).unwrap();
    }

    #[test]
    fn test_read_buffer_consume_clamps_when_over_consumed() {
        let mut buf = NatsReadBuffer::new();
        buf.extend(b"abc").unwrap();
        buf.consume(usize::MAX);
        assert!(buf.available().is_empty());

        // Buffer remains usable after an oversized consume request.
        buf.extend(b"xy").unwrap();
        assert_eq!(buf.available(), b"xy");
    }

    #[test]
    fn test_config_max_payload_default() {
        let config = NatsConfig::default();
        assert_eq!(config.max_payload, 1_048_576);
    }

    #[test]
    fn test_server_info_parse_max_payload() {
        let json = r#"{"max_payload":524288}"#;
        let info = ServerInfo::parse(json).expect("valid max_payload INFO JSON");
        assert_eq!(info.max_payload, 524_288);
    }

    #[test]
    fn test_validate_nats_token_accepts_valid_queue_group_token() {
        assert!(validate_nats_token("workers.v1", "queue group").is_ok());
    }

    #[test]
    fn test_validate_nats_token_rejects_empty() {
        assert!(validate_nats_token("", "subject").is_err());
    }

    #[test]
    fn test_validate_nats_token_rejects_newline_injection() {
        // A subject with \r\nPUB would inject a second command
        assert!(validate_nats_token("foo\r\nPUB evil 0\r\n", "subject").is_err());
    }

    #[test]
    fn test_validate_nats_token_rejects_oversized_subject() {
        let oversized = "a".repeat(MAX_NATS_SUBJECT_BYTES + 1);
        let err = validate_nats_token(&oversized, "subject").unwrap_err();
        match err {
            NatsError::Protocol(message) => {
                assert!(message.contains("exceeds"));
                assert!(message.contains("4096-byte"));
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_nats_token_rejects_tab() {
        assert!(validate_nats_token("foo\tbar", "queue").is_err());
    }

    #[test]
    fn test_parse_publish_subject_rejects_oversized_subject() {
        let oversized = "a".repeat(MAX_NATS_SUBJECT_BYTES + 1);
        assert!(parse_publish_subject(&oversized).is_none());
    }

    #[test]
    fn test_nats_json_escape_empty() {
        assert_eq!(nats_json_escape(""), "");
    }

    #[test]
    fn test_nats_json_escape_tab_and_cr() {
        assert_eq!(nats_json_escape("\t"), "\\t");
        assert_eq!(nats_json_escape("\r"), "\\r");
    }

    #[test]
    fn test_server_info_escapes_negatives_and_missing_flags() {
        let info = ServerInfo::parse(r#"{"server_name":"val\"ue","max_payload":-42,"proto":-1}"#)
            .expect("valid INFO");
        assert_eq!(info.server_name, "val\"ue");
        assert_eq!(info.max_payload, 0, "a negative max_payload is not a size");
        assert_eq!(info.proto, -1);
        assert!(!info.tls_required, "a missing flag stays false");
        assert!(!info.headers);
    }

    #[test]
    fn test_config_from_url_ipv6_default_port() {
        let config = NatsConfig::from_url("nats://[::1]").unwrap();
        assert_eq!(config.host, "[::1]");
        assert_eq!(config.port, 4222);
    }

    #[test]
    fn test_config_from_url_ipv6_invalid() {
        let result = NatsConfig::from_url("nats://[::1");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn handle_pending_messages_propagates_server_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            drop(stream);
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            client
                .read_buf
                .extend(b"-ERR 'Permissions Violation'\r\n")
                .expect("buffer server error");

            let err = client
                .handle_pending_messages(&cx)
                .await
                .expect_err("server -ERR must propagate as error");
            assert!(
                matches!(&err, NatsError::Server(msg) if msg.contains("Permissions Violation")),
                "expected server error with permissions message, got {err:?}"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn server_errors_that_keep_the_connection_are_anchored_and_unknown_ones_are_fatal() {
        for kept in [
            "Permissions Violation for Subscription to \"events.denied\"",
            "Permissions Violation for Subscription to \"orders.*\" using queue \"workers\"",
            "Permissions Violation for Publish to \"events.denied\"",
            "Permissions Violation for Publish with Reply of \"_INBOX.x\"",
            "permissions violation for subscription to foo",
            "Maximum Subscriptions Exceeded",
            "Invalid Subject",
            "Invalid Publish Subject",
        ] {
            assert!(server_error_keeps_connection(kept), "{kept}");
        }
        for fatal in [
            "Authorization Violation",
            "Authentication Timeout",
            "Stale Connection",
            "Maximum Connections Exceeded",
            "Maximum Payload Violation",
            "Unknown Protocol Operation",
            "Slow Consumer",
            "Permissions Violation",
            "Expected Permissions Violation for Publish to \"x\"",
            "Invalid Subject Foo",
            "",
        ] {
            assert!(!server_error_keeps_connection(fatal), "{fatal}");
        }
    }

    #[test]
    fn malformed_server_frame_poisoning_disconnects_client_ne8jdw() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).expect("observe client shutdown")
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };
            client
                .read_buf
                .extend(b"PING invalid\r\n")
                .expect("buffer malformed frame");

            let err = client
                .process(&cx)
                .await
                .expect_err("malformed server frame must fail closed");
            assert!(matches!(err, NatsError::Protocol(_)));
            assert!(!client.connected, "protocol error must poison connection");

            let follow_up = client
                .process(&cx)
                .await
                .expect_err("poisoned connection must reject later processing");
            assert!(matches!(follow_up, NatsError::NotConnected));
        });

        assert_eq!(server.join().expect("server join"), 0);
    }

    #[test]
    fn dropping_client_terminates_subscription_receivers_ne8jdw() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).expect("observe client shutdown")
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            let sid = 73;
            let (tx, rx) = mpsc::channel(8);
            state.subscriptions.lock().insert(
                sid,
                SubscriptionState {
                    subject: "events.lifecycle".to_string(),
                    queue_group: None,
                    sender: tx,
                },
            );
            let mut subscription = Subscription {
                sid,
                subject: "events.lifecycle".to_string(),
                rx,
                state: Arc::clone(&state),
            };
            let client = NatsConnection {
                config: NatsConfig::default(),
                connect_policy: NatsConnectPolicy::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            drop(client);

            assert!(state.closed.load(Ordering::Acquire));
            assert!(state.subscriptions.lock().is_empty());
            assert!(
                subscription
                    .next(&cx)
                    .await
                    .expect("subscription close result")
                    .is_none(),
                "dropping the client must terminate subscription receivers"
            );
        });

        assert_eq!(server.join().expect("server join"), 0);
    }

    #[test]
    fn nats_connect_confirmation_counts_confirmation_ping_in_pings_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .write_all(b"INFO {\"server_id\":\"confirm-pin\",\"max_payload\":1048576}\r\n")
                .expect("send INFO");
            let mut reader = BufReader::new(stream);
            let connect_line = read_protocol_line(&mut reader);
            assert!(connect_line.starts_with("CONNECT "));
            let ping_line = read_protocol_line(&mut reader);
            assert_eq!(ping_line.trim_end(), "PING");
            reader.get_mut().write_all(b"PONG\r\n").expect("send PONG");
            reader.get_mut().flush().expect("flush PONG");
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig::from_url(&format!("nats://{addr}")).expect("config");
            let policy = NatsConnectPolicy::new()
                .with_connect_confirmation(true)
                .with_keepalive(NatsKeepalive::disabled());
            let conn = NatsConnection::connect_with_policy(&cx, config, policy)
                .await
                .expect("connect with confirmation");

            assert_eq!(
                conn.state.pings_sent.load(Ordering::Acquire),
                1,
                "confirmation PING must increment pings_sent"
            );
            assert_eq!(
                conn.state.pongs.load(Ordering::Acquire),
                1,
                "confirmation PONG must increment pongs"
            );
            assert_eq!(
                conn.unanswered_pings(),
                0,
                "confirmed connection must have 0 unanswered pings"
            );
        });

        server.join().expect("server join");
    }
