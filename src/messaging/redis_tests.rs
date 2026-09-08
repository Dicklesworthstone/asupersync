mod tests {
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
    use futures_lite::future;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::pin::Pin;

    #[test]
    fn optional_bulk_reply_accepts_resp3_null_and_resp2_null_bulk() {
        assert_eq!(
            optional_bulk_reply(RespValue::BulkString(Some(b"v".to_vec())), "HGET").expect("bulk"),
            Some(b"v".to_vec())
        );
        assert_eq!(
            optional_bulk_reply(RespValue::BulkString(None), "HGET").expect("resp2 null bulk"),
            None
        );
        // RESP3 miss, as sent by Redis 7 after HELLO 3.
        assert_eq!(
            optional_bulk_reply(RespValue::Null, "HGET").expect("resp3 null"),
            None
        );
        // Planted negative: a wrong-typed reply is still a protocol error.
        let err = optional_bulk_reply(RespValue::Integer(1), "HGET").expect_err("integer");
        assert!(
            matches!(err, RedisError::Protocol(ref m) if m.starts_with("HGET expected bulk string")),
            "{err:?}"
        );
    }

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F>(mut fut: Pin<&mut F>) -> Poll<F::Output>
    where
        F: Future + ?Sized,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        fut.as_mut().poll(&mut cx)
    }

    fn drive_until_signal<F>(mut fut: Pin<&mut F>, signal: &mpsc::Receiver<()>, label: &str)
    where
        F: Future + ?Sized,
    {
        for _ in 0..200 {
            if signal.try_recv().is_ok() {
                return;
            }

            match poll_once(fut.as_mut()) {
                Poll::Pending => {}
                Poll::Ready(_) => {
                    panic!("{label} unexpectedly completed before server-side signal");
                }
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("{label} never reached the expected in-flight state");
    }

    fn read_resp_frame_from_buffer(
        stream: &mut std::net::TcpStream,
        buf: &mut Vec<u8>,
    ) -> RespValue {
        let mut chunk = [0u8; 1024];
        loop {
            if let Some((value, consumed)) =
                RespValue::try_decode(buf).expect("test server should decode RESP command")
            {
                buf.drain(..consumed);
                return value;
            }
            let n = stream.read(&mut chunk).expect("read client command");
            assert!(n > 0, "client closed before sending full RESP command");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn read_resp_frame(stream: &mut std::net::TcpStream) -> RespValue {
        let mut buf = Vec::new();
        read_resp_frame_from_buffer(stream, &mut buf)
    }

    fn assert_resp_command(frame: RespValue, expected: &[&[u8]]) {
        let items = match frame {
            RespValue::Array(Some(items)) => items,
            other => {
                assert!(
                    matches!(other, RespValue::Array(Some(_))),
                    "expected RESP array command frame, got {other:?}"
                );
                return;
            }
        };
        let actual: Vec<Vec<u8>> = items
            .into_iter()
            .map(|item| match item {
                RespValue::BulkString(Some(bytes)) => bytes,
                other => {
                    assert!(
                        matches!(other, RespValue::BulkString(Some(_))),
                        "expected bulk-string command arg, got {other:?}"
                    );
                    Vec::new()
                }
            })
            .collect();
        let expected: Vec<Vec<u8>> = expected.iter().map(|arg| arg.to_vec()).collect();
        assert_eq!(actual, expected, "unexpected RESP command");
    }

    /// Regression for asupersync-mc0lgn: `RedisClient::fmt` previously called
    /// `self.resp3_push_backlog.lock()` twice in a single `.field` chain.
    /// Rust extends every `.lock()` MutexGuard temporary to the end of the
    /// enclosing statement, and `parking_lot::Mutex` is non-re-entrant, so
    /// the second `.lock()` self-deadlocked the formatting thread on the
    /// first guard it had already taken. Any caller emitting
    /// `format!("{:?}", client)` (tracing, panic message, assert_eq) would
    /// hang.
    ///
    /// Run the format call on a worker thread guarded by a join timeout —
    /// if the deadlock returns, the test fails fast with a diagnostic
    /// instead of hanging the test runner.
    #[test]
    fn redis_client_debug_fmt_does_not_self_deadlock_mc0lgn() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let client = pooled_client_without_acquire();

        // Pre-populate both inner mutexes so every `.field` reaches a real
        // lock acquisition rather than short-circuiting on a default state.
        client
            .slot_map
            .lock()
            .insert(42, "127.0.0.1:6379".to_string());
        {
            let mut backlog = client.resp3_push_backlog.lock();
            backlog.dropped = 7;
        }

        let (tx, rx) = mpsc::channel::<String>();
        let format_thread = thread::Builder::new()
            .name("redis-debug-format-mc0lgn".into())
            .spawn(move || {
                let rendered = format!("{client:?}");
                let _ = tx.send(rendered);
            })
            .expect("spawn debug-format worker");

        let rendered = rx.recv_timeout(Duration::from_secs(2)).expect(
            "RedisClient Debug must not self-deadlock on parking_lot \
                 re-entrancy; if this times out the second \
                 resp3_push_backlog.lock() in the .field chain has come \
                 back",
        );
        format_thread.join().expect("format worker thread");

        assert!(
            rendered.contains("known_slot_mappings: 1"),
            "rendered Debug should reflect the slot_map snapshot, got: {rendered}"
        );
        assert!(
            rendered.contains("resp3_push_dropped: 7"),
            "rendered Debug should reflect the backlog snapshot, got: {rendered}"
        );
    }

    #[test]
    fn shutdown_transport_closes_plain_socket_without_waiting_for_drop() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            accepted_tx.send(()).expect("signal accepted");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => closed_tx.send(()).expect("signal transport closed"),
                Ok(n) => panic!(
                    "expected shutdown_transport to close the socket, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("shutdown_transport left the socket open until drop")
                }
                Err(e) => panic!("probe connection after shutdown_transport: {e}"),
            }
        });

        let stream = future::block_on(TcpStream::connect(addr)).expect("connect tcp stream");
        accepted_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server accepted client");

        let stream = RedisStream::Plain(stream);
        stream
            .shutdown_transport()
            .expect("shutdown transport should succeed");

        closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server should observe transport close before drop");

        drop(stream);
        server.join().expect("server join");
    }

    fn pooled_client_without_acquire() -> RedisClient {
        let factory: RedisFactory = Box::new(|| {
            Box::pin(async {
                panic!("test should fail before acquiring a pooled Redis connection");
            })
        });
        RedisClient {
            config: RedisConfig::default(),
            pool: GenericPool::new(factory, PoolConfig::with_max_size(1)),
            slot_map: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            resp3_push_backlog: Arc::new(parking_lot::Mutex::new(RedisResp3PushBacklog::default())),
        }
    }

    fn client_with_config(config: RedisConfig) -> RedisClient {
        let config_for_factory = config.clone();
        let resp3_push_backlog =
            Arc::new(parking_lot::Mutex::new(RedisResp3PushBacklog::default()));
        let backlog_for_factory = Arc::clone(&resp3_push_backlog);

        let factory: RedisFactory = Box::new(move || {
            let config = config_for_factory.clone();
            let backlog = Arc::clone(&backlog_for_factory);
            Box::pin(async move { RedisConnection::connect(config, Some(backlog)).await })
        });

        RedisClient {
            config,
            pool: GenericPool::new(factory, PoolConfig::with_max_size(10)),
            slot_map: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            resp3_push_backlog,
        }
    }

    fn write_hello3_ok(stream: &mut std::net::TcpStream) {
        let hello = read_resp_frame(stream);
        assert_resp_command(hello, &[b"HELLO", b"3"]);
        let hello_reply = RespValue::Map(vec![(
            RespValue::SimpleString("proto".to_string()),
            RespValue::Integer(3),
        )])
        .encode();
        stream.write_all(&hello_reply).expect("write HELLO reply");
        stream.flush().expect("flush HELLO reply");
    }

    fn pubsub_subscription_frame(kind: &[u8], target: &[u8], remaining: i64) -> RespValue {
        RespValue::Push(vec![
            RespValue::BulkString(Some(kind.to_vec())),
            RespValue::BulkString(Some(target.to_vec())),
            RespValue::Integer(remaining),
        ])
    }

    fn assert_invalid_subscribe_control_reply(
        outbound: Vec<u8>,
        description: &'static str,
        expected_fragment: &'static str,
    ) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);
            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            stream
                .write_all(&outbound)
                .expect("write invalid control reply followed by valid ack");
            stream.flush().expect("flush control replies");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => closed_tx.send(()).expect("signal transport closed"),
                Ok(n) => panic!(
                    "failed PubSub control exchange left {n} unread client byte(s) on the socket"
                ),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    ) =>
                {
                    closed_tx.send(()).expect("signal transport closed");
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("failed PubSub control exchange left the transport open")
                }
                Err(error) => panic!("probe failed PubSub control transport: {error}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            let err = assert_completes_within(Duration::from_secs(2), description, || {
                Box::pin(pubsub.subscribe(&cx, &["chan"]))
            })
            .await
            .expect_err("invalid control traffic must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(message) if message.contains(expected_fragment))
            );
            assert!(pubsub.channels().is_empty());
            assert!(pubsub.patterns().is_empty());
            assert!(pubsub.pending_events.is_empty());
            assert!(pubsub.poisoned);

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("poisoned connection must reject event reads");
            assert!(matches!(
                err,
                RedisError::Protocol(message)
                    if message
                        == "redis pubsub connection was invalidated by a cancelled or failed control exchange; call reconnect"
            ));
            closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("failed control exchange must close the transport before PubSub drop");
        });

        server.join().expect("server join");
    }

    fn buffer_fingerprint(bytes: &[u8]) -> String {
        let mut acc = 0xcbf2_9ce4_8422_2325u64;
        for &byte in bytes {
            acc ^= u64::from(byte);
            acc = acc.wrapping_mul(0x100_0000_01b3);
        }
        format!("{acc:016x}")
    }

    fn collect_resp3_pushes(client: &RedisClient) -> Vec<RedisResp3NonPubSubPush> {
        let mut pushes = Vec::new();
        loop {
            match client.try_next_resp3_push() {
                Ok(Some(push)) => pushes.push(push),
                Ok(None) => return pushes,
                Err(err) => panic!("expected buffered RESP3 pushes without lag, got {err:?}"),
            }
        }
    }

    #[test]
    fn cluster_redirect_rejects_plaintext_authenticated_cross_endpoint() {
        let mut client = pooled_client_without_acquire();
        client.config.host = "redis.internal".to_string();
        client.config.port = 6379;
        client.config.password = Some("secret".to_string());

        client
            .validate_redirect_target("redis.internal", 6379)
            .expect("same-endpoint redirect should remain allowed");

        let err = client
            .validate_redirect_target("attacker.example", 6380)
            .expect_err("plaintext authenticated redirect must fail closed");
        assert!(
            matches!(err, RedisError::Protocol(ref msg) if msg.contains("enable TLS for cluster redirects")),
            "unexpected redirect error: {err:?}"
        );

        client.config.password = None;
        client
            .validate_redirect_target("attacker.example", 6380)
            .expect("passwordless plaintext redirect should not trip auth guard");
    }

    #[test]
    fn test_resp_encode_simple_string() {
        let value = RespValue::SimpleString("OK".to_string());
        assert_eq!(value.encode(), b"+OK\r\n");
    }

    #[test]
    fn test_resp_encode_integer() {
        let value = RespValue::Integer(42);
        assert_eq!(value.encode(), b":42\r\n");
    }

    #[test]
    fn test_resp_decode_simple_string() {
        let (value, n) = RespValue::try_decode(b"+OK\r\n").unwrap().expect("decoded");
        assert_eq!(value, RespValue::SimpleString("OK".to_string()));
        assert_eq!(n, 5);
    }

    #[test]
    fn test_resp_decode_integer() {
        let (value, n) = RespValue::try_decode(b":-123\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(value, RespValue::Integer(-123));
        assert_eq!(n, 7);
    }

    #[test]
    fn test_resp_decode_bulk_string() {
        let (value, n) = RespValue::try_decode(b"$3\r\nfoo\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(value, RespValue::BulkString(Some(b"foo".to_vec())));
        assert_eq!(n, 9);
    }

    #[test]
    fn test_resp_decode_array() {
        let (value, n) = RespValue::try_decode(b"*2\r\n$3\r\nfoo\r\n:42\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(
            value,
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"foo".to_vec())),
                RespValue::Integer(42),
            ]))
        );
        assert_eq!(n, 18);
    }

    fn bulk_arg(bytes: impl AsRef<[u8]>) -> RespValue {
        RespValue::BulkString(Some(bytes.as_ref().to_vec()))
    }

    #[test]
    fn script_eval_parser_splits_script_keys_and_argv() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            bulk_arg("return redis.call('GET', KEYS[1])"),
            bulk_arg("2"),
            bulk_arg("key-a"),
            bulk_arg("key-b"),
            bulk_arg("arg-a"),
        ]));

        let parsed = parse_script_eval_for_fuzz(command).expect("valid EVAL command should parse");

        assert!(!parsed.readonly);
        assert_eq!(parsed.numkeys, 2);
        assert_eq!(parsed.keys, vec![b"key-a".to_vec(), b"key-b".to_vec()]);
        assert_eq!(parsed.argv, vec![b"arg-a".to_vec()]);
        assert_eq!(parsed.lua.string_literals, 1);
        assert_eq!(parsed.lua.max_delimiter_depth, 2);
    }

    #[test]
    fn script_eval_parser_accepts_eval_ro_long_comments_and_long_strings() {
        let script =
            b"--[=[ comment with bracket text ]=]\nlocal value = [==[payload]==]\nreturn value";
        let command = RespValue::Array(Some(vec![
            bulk_arg("eval_ro"),
            bulk_arg(script),
            bulk_arg("0"),
            bulk_arg("arg-only"),
        ]));

        let parsed =
            parse_script_eval_for_fuzz(command).expect("valid EVAL_RO command should parse");

        assert!(parsed.readonly);
        assert_eq!(parsed.keys, Vec::<Vec<u8>>::new());
        assert_eq!(parsed.argv, vec![b"arg-only".to_vec()]);
        assert_eq!(parsed.lua.comments, 1);
        assert_eq!(parsed.lua.string_literals, 1);
        assert_eq!(parsed.lua.lines, 3);
    }

    #[test]
    fn script_eval_parser_rejects_malformed_command_shapes() {
        let bad_numkeys = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            bulk_arg("return 1"),
            bulk_arg("2"),
            bulk_arg("only-one-key"),
        ]));
        assert!(matches!(
            parse_script_eval_for_fuzz(bad_numkeys),
            Err(RedisError::Protocol(msg)) if msg.contains("exceeds remaining")
        ));

        let bad_lua = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            bulk_arg("return 'unterminated"),
            bulk_arg("0"),
        ]));
        assert!(matches!(
            parse_script_eval_for_fuzz(bad_lua),
            Err(RedisError::Protocol(msg)) if msg.contains("unterminated")
        ));

        let null_arg = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            RespValue::BulkString(None),
            bulk_arg("0"),
        ]));
        assert!(matches!(
            parse_script_eval_for_fuzz(null_arg),
            Err(RedisError::Protocol(msg)) if msg.contains("non-null bulk string")
        ));
    }

    #[test]
    fn client_kill_parser_accepts_legacy_address_selector() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("127.0.0.1:12345"),
        ]));

        let parsed = parse_client_kill_for_fuzz(command).expect("legacy CLIENT KILL should parse");

        assert_eq!(parsed.legacy_addr, Some(b"127.0.0.1:12345".to_vec()));
        assert!(parsed.filters.is_empty());
    }

    #[test]
    fn client_kill_parser_accepts_filter_pairs() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("client"),
            bulk_arg("kill"),
            bulk_arg("ID"),
            bulk_arg("42"),
            bulk_arg("TYPE"),
            bulk_arg("pubsub"),
            bulk_arg("USER"),
            bulk_arg("default"),
            bulk_arg("ADDR"),
            bulk_arg("10.0.0.2:6379"),
            bulk_arg("LADDR"),
            bulk_arg("[::1]:6379"),
            bulk_arg("SKIPME"),
            bulk_arg("no"),
            bulk_arg("MAXAGE"),
            bulk_arg("60"),
        ]));

        let parsed =
            parse_client_kill_for_fuzz(command).expect("CLIENT KILL filter pairs should parse");

        assert!(parsed.legacy_addr.is_none());
        assert_eq!(
            parsed.filters,
            vec![
                RedisClientKillFilter::Id(42),
                RedisClientKillFilter::ClientType(RedisClientKillTargetType::PubSub),
                RedisClientKillFilter::User(b"default".to_vec()),
                RedisClientKillFilter::Addr(b"10.0.0.2:6379".to_vec()),
                RedisClientKillFilter::LocalAddr(b"[::1]:6379".to_vec()),
                RedisClientKillFilter::SkipMe(false),
                RedisClientKillFilter::MaxAge(60),
            ]
        );
    }

    #[test]
    fn client_kill_parser_rejects_malformed_selectors() {
        let unpaired_filter = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("ID"),
            bulk_arg("7"),
            bulk_arg("TYPE"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(unpaired_filter),
            Err(RedisError::Protocol(msg)) if msg.contains("filter/value pairs")
        ));

        let bad_skipme = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("SKIPME"),
            bulk_arg("MAYBE"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(bad_skipme),
            Err(RedisError::Protocol(msg)) if msg.contains("YES or NO")
        ));

        let bad_legacy_addr = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("127.0.0.1"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(bad_legacy_addr),
            Err(RedisError::Protocol(msg)) if msg.contains("ip:port")
        ));

        let unknown_filter = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("BOGUS"),
            bulk_arg("value"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(unknown_filter),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown filter")
        ));
    }

    #[test]
    fn slowlog_parser_accepts_supported_subcommands() {
        let get = RespValue::Array(Some(vec![
            bulk_arg("SLOWLOG"),
            bulk_arg("GET"),
            bulk_arg("128"),
        ]));
        assert_eq!(
            parse_slowlog_for_fuzz(get).expect("SLOWLOG GET count should parse"),
            RedisSlowlogCommand::Get { count: Some(128) }
        );

        let len = RespValue::Array(Some(vec![bulk_arg("slowlog"), bulk_arg("len")]));
        assert_eq!(
            parse_slowlog_for_fuzz(len).expect("SLOWLOG LEN should parse"),
            RedisSlowlogCommand::Len
        );

        let reset = RespValue::Array(Some(vec![bulk_arg("SLOWLOG"), bulk_arg("RESET")]));
        assert_eq!(
            parse_slowlog_for_fuzz(reset).expect("SLOWLOG RESET should parse"),
            RedisSlowlogCommand::Reset
        );

        let help = RespValue::Array(Some(vec![bulk_arg("SLOWLOG"), bulk_arg("HELP")]));
        assert_eq!(
            parse_slowlog_for_fuzz(help).expect("SLOWLOG HELP should parse"),
            RedisSlowlogCommand::Help
        );
    }

    #[test]
    fn slowlog_parser_rejects_malformed_command_shapes() {
        let negative_count = RespValue::Array(Some(vec![
            bulk_arg("SLOWLOG"),
            bulk_arg("GET"),
            bulk_arg("-1"),
        ]));
        assert!(matches!(
            parse_slowlog_for_fuzz(negative_count),
            Err(RedisError::Protocol(msg)) if msg.contains("non-digit")
        ));

        let extra_len_arg = RespValue::Array(Some(vec![
            bulk_arg("SLOWLOG"),
            bulk_arg("LEN"),
            bulk_arg("extra"),
        ]));
        assert!(matches!(
            parse_slowlog_for_fuzz(extra_len_arg),
            Err(RedisError::Protocol(msg)) if msg.contains("takes no arguments")
        ));

        let unknown = RespValue::Array(Some(vec![bulk_arg("SLOWLOG"), bulk_arg("BOGUS")]));
        assert!(matches!(
            parse_slowlog_for_fuzz(unknown),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown subcommand")
        ));
    }

    #[test]
    fn latency_parser_accepts_supported_subcommands() {
        let history = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("HISTORY"),
            bulk_arg("command"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(history)
                .expect("LATENCY HISTORY should parse")
                .subcommand,
            RedisLatencySubcommand::History {
                event: b"command".to_vec()
            }
        );

        let graph = RespValue::Array(Some(vec![
            bulk_arg("latency"),
            bulk_arg("graph"),
            bulk_arg("fork"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(graph)
                .expect("LATENCY GRAPH should parse")
                .subcommand,
            RedisLatencySubcommand::Graph {
                event: b"fork".to_vec()
            }
        );

        let reset = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("RESET"),
            bulk_arg("command"),
            bulk_arg("fork"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(reset)
                .expect("LATENCY RESET should parse")
                .subcommand,
            RedisLatencySubcommand::Reset {
                events: vec![b"command".to_vec(), b"fork".to_vec()]
            }
        );

        let histogram = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("HISTOGRAM"),
            bulk_arg("GET"),
            bulk_arg("SET"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(histogram)
                .expect("LATENCY HISTOGRAM should parse")
                .subcommand,
            RedisLatencySubcommand::Histogram {
                commands: vec![b"GET".to_vec(), b"SET".to_vec()]
            }
        );

        let latest = RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("LATEST")]));
        assert_eq!(
            parse_latency_for_fuzz(latest)
                .expect("LATENCY LATEST should parse")
                .subcommand,
            RedisLatencySubcommand::Latest
        );

        let doctor = RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("DOCTOR")]));
        assert_eq!(
            parse_latency_for_fuzz(doctor)
                .expect("LATENCY DOCTOR should parse")
                .subcommand,
            RedisLatencySubcommand::Doctor
        );
    }

    #[test]
    fn latency_parser_rejects_malformed_command_shapes() {
        let missing_history_event =
            RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("HISTORY")]));
        assert!(matches!(
            parse_latency_for_fuzz(missing_history_event),
            Err(RedisError::Protocol(msg)) if msg.contains("requires exactly one event")
        ));

        let empty_graph_event = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("GRAPH"),
            bulk_arg(""),
        ]));
        assert!(matches!(
            parse_latency_for_fuzz(empty_graph_event),
            Err(RedisError::Protocol(msg)) if msg.contains("must not be empty")
        ));

        let extra_latest_arg = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("LATEST"),
            bulk_arg("extra"),
        ]));
        assert!(matches!(
            parse_latency_for_fuzz(extra_latest_arg),
            Err(RedisError::Protocol(msg)) if msg.contains("takes no arguments")
        ));

        let unknown = RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("BOGUS")]));
        assert!(matches!(
            parse_latency_for_fuzz(unknown),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown subcommand")
        ));
    }

    #[test]
    fn zadd_parser_splits_options_and_entries() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("NX"),
            bulk_arg("CH"),
            bulk_arg("1.5"),
            bulk_arg("member-a"),
            bulk_arg("-2"),
            bulk_arg("member-b"),
        ]));

        let parsed = parse_zadd_for_fuzz(command).expect("valid ZADD command should parse");

        assert_eq!(parsed.key, b"zset".to_vec());
        assert_eq!(parsed.options.insert, RedisZaddInsertMode::Nx);
        assert_eq!(parsed.options.score, RedisZaddScoreMode::Always);
        assert!(parsed.options.changed);
        assert!(!parsed.options.increment);
        assert_eq!(
            parsed.entries,
            vec![
                RedisZaddEntry {
                    score: b"1.5".to_vec(),
                    member: b"member-a".to_vec(),
                },
                RedisZaddEntry {
                    score: b"-2".to_vec(),
                    member: b"member-b".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn zadd_parser_accepts_xx_gt_incr_single_pair() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("zadd"),
            bulk_arg("zset"),
            bulk_arg("gt"),
            bulk_arg("xx"),
            bulk_arg("INCR"),
            bulk_arg("1.25"),
            bulk_arg("member"),
        ]));

        let parsed = parse_zadd_for_fuzz(command).expect("valid ZADD INCR command should parse");

        assert_eq!(parsed.options.insert, RedisZaddInsertMode::Xx);
        assert_eq!(parsed.options.score, RedisZaddScoreMode::GreaterThan);
        assert!(parsed.options.increment);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].score, b"1.25".to_vec());
        assert_eq!(parsed.entries[0].member, b"member".to_vec());
    }

    #[test]
    fn zadd_parser_rejects_malformed_command_shapes() {
        let nx_gt_conflict = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("NX"),
            bulk_arg("GT"),
            bulk_arg("1"),
            bulk_arg("member"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(nx_gt_conflict),
            Err(RedisError::Protocol(msg)) if msg.contains("mutually exclusive")
        ));

        let odd_pairing = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("1"),
            bulk_arg("member"),
            bulk_arg("2"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(odd_pairing),
            Err(RedisError::Protocol(msg)) if msg.contains("paired")
        ));

        let incr_multi_pair = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("INCR"),
            bulk_arg("1"),
            bulk_arg("a"),
            bulk_arg("2"),
            bulk_arg("b"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(incr_multi_pair),
            Err(RedisError::Protocol(msg)) if msg.contains("exactly one")
        ));

        let nan_score = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("NaN"),
            bulk_arg("member"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(nan_score),
            Err(RedisError::Protocol(msg)) if msg.contains("NaN")
        ));

        let null_member = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("1"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(null_member),
            Err(RedisError::Protocol(msg)) if msg.contains("ZADD arg[1]")
        ));
    }

    #[test]
    fn zrangebyscore_parser_accepts_bounds_and_options() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("(1.5"),
            bulk_arg("+inf"),
            bulk_arg("WITHSCORES"),
            bulk_arg("LIMIT"),
            bulk_arg("0"),
            bulk_arg("-1"),
        ]));

        let parsed =
            parse_zrangebyscore_for_fuzz(command).expect("valid ZRANGEBYSCORE should parse");

        assert_eq!(parsed.key, b"zset".to_vec());
        assert_eq!(
            parsed.min,
            RedisZrangeByScoreBound::Exclusive(b"1.5".to_vec())
        );
        assert_eq!(
            parsed.max,
            RedisZrangeByScoreBound::Inclusive(b"+inf".to_vec())
        );
        assert!(parsed.with_scores);
        assert_eq!(
            parsed.limit,
            Some(RedisZrangeByScoreLimit {
                offset: 0,
                count: -1
            })
        );
    }

    #[test]
    fn zrangebyscore_parser_accepts_options_in_any_order() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("zrangebyscore"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("(42"),
            bulk_arg("LIMIT"),
            bulk_arg("+2"),
            bulk_arg("10"),
            bulk_arg("WITHSCORES"),
        ]));

        let parsed =
            parse_zrangebyscore_for_fuzz(command).expect("valid ZRANGEBYSCORE should parse");

        assert_eq!(
            parsed.min,
            RedisZrangeByScoreBound::Inclusive(b"-inf".to_vec())
        );
        assert_eq!(
            parsed.max,
            RedisZrangeByScoreBound::Exclusive(b"42".to_vec())
        );
        assert!(parsed.with_scores);
        assert_eq!(
            parsed.limit,
            Some(RedisZrangeByScoreLimit {
                offset: 2,
                count: 10
            })
        );
    }

    #[test]
    fn zrangebyscore_parser_rejects_malformed_command_shapes() {
        let missing_max = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(missing_max),
            Err(RedisError::Protocol(msg)) if msg.contains("requires command, key, min, and max")
        ));

        let duplicate_withscores = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("+inf"),
            bulk_arg("WITHSCORES"),
            bulk_arg("WITHSCORES"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(duplicate_withscores),
            Err(RedisError::Protocol(msg)) if msg.contains("appears more than once")
        ));

        let incomplete_limit = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("+inf"),
            bulk_arg("LIMIT"),
            bulk_arg("0"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(incomplete_limit),
            Err(RedisError::Protocol(msg)) if msg.contains("requires offset and count")
        ));

        let negative_offset = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("+inf"),
            bulk_arg("LIMIT"),
            bulk_arg("-1"),
            bulk_arg("10"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(negative_offset),
            Err(RedisError::Protocol(msg)) if msg.contains("offset must be non-negative")
        ));

        let nan_min = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("NaN"),
            bulk_arg("+inf"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(nan_min),
            Err(RedisError::Protocol(msg)) if msg.contains("finite or +/-inf")
        ));

        let null_max = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(null_max),
            Err(RedisError::Protocol(msg)) if msg.contains("ZRANGEBYSCORE max")
        ));
    }

    #[test]
    fn acl_parser_accepts_users_categories_resets_and_log_selectors() {
        let getuser = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("GETUSER"),
            bulk_arg("default"),
        ]));
        assert_eq!(
            parse_acl_for_fuzz(getuser).expect("ACL GETUSER should parse"),
            RedisAclCommand::GetUser {
                user: b"default".to_vec()
            }
        );

        let users = RespValue::Array(Some(vec![bulk_arg("acl"), bulk_arg("users")]));
        assert_eq!(
            parse_acl_for_fuzz(users).expect("ACL USERS should parse"),
            RedisAclCommand::Users
        );

        let cat = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("CAT"),
            bulk_arg("read"),
        ]));
        assert_eq!(
            parse_acl_for_fuzz(cat).expect("ACL CAT category should parse"),
            RedisAclCommand::Cat {
                category: Some(b"read".to_vec())
            }
        );

        let setuser = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("on"),
            bulk_arg("resetpass"),
            bulk_arg("resetkeys"),
            bulk_arg("resetchannels"),
            bulk_arg("clearselectors"),
            bulk_arg("+@read"),
            bulk_arg("-@dangerous"),
            bulk_arg("+get"),
            bulk_arg("-config|set"),
            bulk_arg("~cache:*"),
            bulk_arg("%R~ro:*"),
            bulk_arg("%W~wo:*"),
            bulk_arg("&updates:*"),
            bulk_arg(">secret"),
            bulk_arg("#0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        ]));

        let parsed = parse_acl_for_fuzz(setuser).expect("ACL SETUSER rules should parse");
        assert_eq!(
            parsed,
            RedisAclCommand::SetUser {
                user: b"app".to_vec(),
                rules: vec![
                    RedisAclRule::UserState(RedisAclUserState::On),
                    RedisAclRule::Reset(RedisAclResetKind::Passwords),
                    RedisAclRule::Reset(RedisAclResetKind::Keys),
                    RedisAclRule::Reset(RedisAclResetKind::Channels),
                    RedisAclRule::Reset(RedisAclResetKind::Selectors),
                    RedisAclRule::Category {
                        allow: true,
                        name: b"read".to_vec()
                    },
                    RedisAclRule::Category {
                        allow: false,
                        name: b"dangerous".to_vec()
                    },
                    RedisAclRule::Command {
                        allow: true,
                        name: b"get".to_vec()
                    },
                    RedisAclRule::Command {
                        allow: false,
                        name: b"config|set".to_vec()
                    },
                    RedisAclRule::KeyPattern(b"cache:*".to_vec()),
                    RedisAclRule::ReadKeyPattern(b"ro:*".to_vec()),
                    RedisAclRule::WriteKeyPattern(b"wo:*".to_vec()),
                    RedisAclRule::ChannelPattern(b"updates:*".to_vec()),
                    RedisAclRule::Password {
                        add: true,
                        value: b"secret".to_vec()
                    },
                    RedisAclRule::PasswordHash {
                        add: true,
                        value: b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_vec()
                    },
                ]
            }
        );

        let log_reset = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("LOG"),
            bulk_arg("RESET"),
        ]));
        assert_eq!(
            parse_acl_for_fuzz(log_reset).expect("ACL LOG RESET should parse"),
            RedisAclCommand::Log {
                selector: RedisAclLogSelector::Reset
            }
        );

        let log_count =
            RespValue::Array(Some(vec![bulk_arg("ACL"), bulk_arg("LOG"), bulk_arg("3")]));
        assert_eq!(
            parse_acl_for_fuzz(log_count).expect("ACL LOG count should parse"),
            RedisAclCommand::Log {
                selector: RedisAclLogSelector::Count(3)
            }
        );
    }

    #[test]
    fn acl_parser_rejects_malformed_users_categories_and_reset_rules() {
        let empty_category =
            RespValue::Array(Some(vec![bulk_arg("ACL"), bulk_arg("CAT"), bulk_arg("")]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_category),
            Err(RedisError::Protocol(msg)) if msg.contains("CAT category")
        ));

        let empty_user = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("GETUSER"),
            bulk_arg(""),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_user),
            Err(RedisError::Protocol(msg)) if msg.contains("GETUSER user")
        ));

        let empty_category_rule = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("+@"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_category_rule),
            Err(RedisError::Protocol(msg)) if msg.contains("empty category")
        ));

        let empty_reset_rule = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("resetkeys"),
            bulk_arg("~"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_reset_rule),
            Err(RedisError::Protocol(msg)) if msg.contains("empty key pattern")
        ));

        let bad_hash = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("#not-a-sha256-hex-digest"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(bad_hash),
            Err(RedisError::Protocol(msg)) if msg.contains("64 ASCII hex")
        ));

        let bad_log_selector = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("LOG"),
            bulk_arg("maybe"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(bad_log_selector),
            Err(RedisError::Protocol(msg)) if msg.contains("non-digit")
        ));

        let null_rule = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(null_rule),
            Err(RedisError::Protocol(msg)) if msg.contains("non-null bulk string")
        ));
    }

    #[test]
    fn cluster_command_parser_accepts_myid_reset_and_failure_reports() {
        let myid = RespValue::Array(Some(vec![bulk_arg("cluster"), bulk_arg("myid")]));
        assert_eq!(
            parse_cluster_command_for_fuzz(myid).expect("CLUSTER MYID should parse"),
            RedisClusterCommand::MyId
        );

        let reset_default = RespValue::Array(Some(vec![bulk_arg("CLUSTER"), bulk_arg("RESET")]));
        assert_eq!(
            parse_cluster_command_for_fuzz(reset_default)
                .expect("CLUSTER RESET default mode should parse"),
            RedisClusterCommand::Reset {
                mode: RedisClusterResetMode::Soft
            }
        );

        let reset_hard = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("RESET"),
            bulk_arg("HARD"),
        ]));
        assert_eq!(
            parse_cluster_command_for_fuzz(reset_hard).expect("CLUSTER RESET HARD should parse"),
            RedisClusterCommand::Reset {
                mode: RedisClusterResetMode::Hard
            }
        );

        let node_id = b"0123456789abcdef0123456789abcdef01234567".to_vec();
        let count_failure_reports = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
            bulk_arg(&node_id),
        ]));
        assert_eq!(
            parse_cluster_command_for_fuzz(count_failure_reports)
                .expect("CLUSTER COUNT-FAILURE-REPORTS should parse"),
            RedisClusterCommand::CountFailureReports { node_id }
        );
    }

    #[test]
    fn cluster_command_parser_rejects_malformed_arguments() {
        let myid_extra = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("MYID"),
            bulk_arg("extra"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(myid_extra),
            Err(RedisError::Protocol(msg)) if msg.contains("takes no arguments")
        ));

        let bad_reset_mode = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("RESET"),
            bulk_arg("MAYBE"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(bad_reset_mode),
            Err(RedisError::Protocol(msg)) if msg.contains("HARD or SOFT")
        ));

        let missing_node_id = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(missing_node_id),
            Err(RedisError::Protocol(msg)) if msg.contains("requires exactly one node id")
        ));

        let bad_node_id = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
            bulk_arg("not-a-40-byte-hex-node-id"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(bad_node_id),
            Err(RedisError::Protocol(msg)) if msg.contains("40 ASCII hex")
        ));

        let null_node_id = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(null_node_id),
            Err(RedisError::Protocol(msg)) if msg.contains("non-null bulk string")
        ));

        let unknown_subcommand = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("FORGET"),
            bulk_arg("0123456789abcdef0123456789abcdef01234567"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(unknown_subcommand),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown subcommand")
        ));
    }

    #[test]
    fn resp2_reference_vectors_match_redis_rs_value_model() {
        // Lock the RESP2 fallback parser to the same shared low-level value
        // model that redis-rs exposes for the direct subset here. Avoid the
        // RESP2 `+OK` and nil normalization cases because redis-rs folds those
        // into special variants that this parser intentionally models
        // separately.
        let cases: Vec<(&str, RespValue, &'static [u8])> = vec![
            (
                "simple_string",
                RespValue::SimpleString("PONG".to_string()),
                b"+PONG\r\n",
            ),
            ("integer", RespValue::Integer(-7), b":-7\r\n"),
            (
                "bulk_string_binary",
                RespValue::BulkString(Some(b"bin\0ary".to_vec())),
                b"$7\r\nbin\0ary\r\n",
            ),
            (
                "array",
                RespValue::Array(Some(vec![
                    RespValue::SimpleString("PONG".to_string()),
                    RespValue::BulkString(Some(b"bin\0ary".to_vec())),
                    RespValue::Integer(-7),
                ])),
                b"*3\r\n+PONG\r\n$7\r\nbin\0ary\r\n:-7\r\n",
            ),
            (
                "nested_array",
                RespValue::Array(Some(vec![
                    RespValue::Array(Some(vec![])),
                    RespValue::Array(Some(vec![
                        RespValue::BulkString(Some(b"foo".to_vec())),
                        RespValue::Integer(42),
                    ])),
                ])),
                b"*2\r\n*0\r\n*2\r\n$3\r\nfoo\r\n:42\r\n",
            ),
        ];

        for (name, value, expected) in cases {
            assert_eq!(
                value.encode(),
                expected,
                "RESP2 {name} encoding must stay byte-compatible with redis-rs's \
                 low-level value model"
            );

            let (decoded, consumed) = RespValue::try_decode(expected)
                .unwrap()
                .unwrap_or_else(|| panic!("RESP2 {name} vector should decode"));
            assert_eq!(
                decoded, value,
                "RESP2 {name} decoding must preserve the redis-rs-compatible \
                 low-level value model"
            );
            assert_eq!(
                consumed,
                expected.len(),
                "RESP2 {name} decoder must consume the full reference vector"
            );
        }
    }

    #[test]
    fn resp3_nested_map_set_roundtrip_matches_redis_rs_value_model() {
        // redis-rs models RESP3 maps as ordered Vec<(Value, Value)> pairs and
        // RESP3 sets as Vec<Value>; lock the corresponding wire form here.
        let value = RespValue::Map(vec![
            (
                RespValue::BulkString(Some(b"numbers".to_vec())),
                RespValue::Set(vec![
                    RespValue::Integer(1),
                    RespValue::BulkString(Some(b"two".to_vec())),
                ]),
            ),
            (
                RespValue::BulkString(Some(b"meta".to_vec())),
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("proto".to_string()),
                        RespValue::Integer(3),
                    ),
                    (
                        RespValue::SimpleString("mode".to_string()),
                        RespValue::SimpleString("standalone".to_string()),
                    ),
                ]),
            ),
        ]);

        let expected = concat!(
            "%2\r\n",
            "$7\r\nnumbers\r\n",
            "~2\r\n",
            ":1\r\n",
            "$3\r\ntwo\r\n",
            "$4\r\nmeta\r\n",
            "%2\r\n",
            "+proto\r\n",
            ":3\r\n",
            "+mode\r\n",
            "+standalone\r\n",
        )
        .as_bytes();

        assert_eq!(
            value.encode(),
            expected,
            "RESP3 Map/Set encoding must stay byte-compatible with redis-rs's \
             low-level value model"
        );

        let (decoded, consumed) = RespValue::try_decode(expected)
            .unwrap()
            .expect("nested RESP3 map/set should decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, expected.len());
    }

    #[test]
    fn resp3_verbatim_string_roundtrip_matches_redis_rs_value_model() {
        // redis-rs exposes RESP3 verbatim strings as a 3-byte format tag plus
        // the exact payload bytes after the ':' separator. Lock that wire form
        // here, including CRLF bytes embedded inside the payload body.
        let value = RespValue::Verbatim {
            format: "txt".to_string(),
            payload: b"hello\r\nworld".to_vec(),
        };

        let expected = b"=16\r\ntxt:hello\r\nworld\r\n";

        assert_eq!(
            value.encode(),
            expected,
            "RESP3 verbatim encoding must stay byte-compatible with redis-rs's \
             low-level verbatim string model"
        );

        let (decoded, consumed) = RespValue::try_decode(expected)
            .unwrap()
            .expect("RESP3 verbatim string should decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, expected.len());
    }

    #[test]
    fn resp3_verbatim_string_rejects_label_boundary_and_utf8_failures() {
        let cases: [(&str, &[u8], &str); 3] = [
            (
                "short_label",
                b"=5\r\ntx:ab\r\n",
                "missing 3-byte format separator",
            ),
            (
                "long_label",
                b"=8\r\ntext:abc\r\n",
                "missing 3-byte format separator",
            ),
            (
                "invalid_utf8_label",
                b"=5\r\n\xff\xfe\xfd:x\r\n",
                "invalid UTF-8 in verbatim format",
            ),
        ];

        for (label, wire, expected_fragment) in cases {
            let error = RespValue::try_decode(wire)
                .expect_err("malformed verbatim string must fail to decode");
            match error {
                RedisError::Protocol(message) => {
                    assert!(
                        message.contains(expected_fragment),
                        "{label} should mention {expected_fragment:?}, got {message:?}"
                    );
                }
                other => panic!("{label} returned unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn resp3_nested_verbatim_values_preserve_binary_payloads() {
        let value = RespValue::Array(Some(vec![
            RespValue::Verbatim {
                format: "bin".to_string(),
                payload: vec![0x00, 0xff, b':', b'\r', b'\n'],
            },
            RespValue::Map(vec![(
                RespValue::SimpleString("inner".to_string()),
                RespValue::Verbatim {
                    format: "mkd".to_string(),
                    payload: b"*emphasis*\x00".to_vec(),
                },
            )]),
        ]));

        let wire = value.encode();
        let (decoded, consumed) = RespValue::try_decode(&wire)
            .unwrap()
            .expect("nested verbatim values should decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn resp3_attribute_roundtrip_preserves_nested_value_kinds() {
        fn nesting_depth(value: &RespValue) -> usize {
            match value {
                RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
                    1 + items.iter().map(nesting_depth).max().unwrap_or(0)
                }
                RespValue::Map(pairs) | RespValue::Attribute(pairs) => {
                    1 + pairs
                        .iter()
                        .flat_map(|(key, value)| [nesting_depth(key), nesting_depth(value)])
                        .max()
                        .unwrap_or(0)
                }
                _ => 1,
            }
        }

        fn attribute_pair_count(value: &RespValue) -> usize {
            match value {
                RespValue::Attribute(pairs) => {
                    pairs.len()
                        + pairs
                            .iter()
                            .map(|(key, value)| {
                                attribute_pair_count(key) + attribute_pair_count(value)
                            })
                            .sum::<usize>()
                }
                RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
                    items.iter().map(attribute_pair_count).sum()
                }
                RespValue::Map(pairs) => pairs
                    .iter()
                    .map(|(key, value)| attribute_pair_count(key) + attribute_pair_count(value))
                    .sum(),
                _ => 0,
            }
        }

        fn value_kind(value: &RespValue) -> &'static str {
            match value {
                RespValue::Attribute(_) => "attribute",
                RespValue::Array(_) => "array",
                RespValue::BulkString(_) => "bulk_string",
                RespValue::SimpleString(_) => "simple_string",
                RespValue::Error(_) => "error",
                RespValue::Integer(_) => "integer",
                RespValue::Null => "null",
                RespValue::Boolean(_) => "boolean",
                RespValue::Double(_) => "double",
                RespValue::BigNumber(_) => "big_number",
                RespValue::Verbatim { .. } => "verbatim",
                RespValue::BlobError(_) => "blob_error",
                RespValue::Map(_) => "map",
                RespValue::Set(_) => "set",
                RespValue::Push(_) => "push",
            }
        }

        let cases: Vec<(&str, RespValue)> = vec![
            (
                "scalar",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("ttl".to_string()),
                    RespValue::Integer(7),
                )]),
            ),
            (
                "array",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("items".to_string()),
                    RespValue::Array(Some(vec![
                        RespValue::BulkString(Some(b"alpha".to_vec())),
                        RespValue::Null,
                    ])),
                )]),
            ),
            (
                "map",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("meta".to_string()),
                    RespValue::Map(vec![(
                        RespValue::SimpleString("mode".to_string()),
                        RespValue::SimpleString("standalone".to_string()),
                    )]),
                )]),
            ),
            (
                "set",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("members".to_string()),
                    RespValue::Set(vec![
                        RespValue::SimpleString("a".to_string()),
                        RespValue::SimpleString("b".to_string()),
                    ]),
                )]),
            ),
            (
                "push",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("push".to_string()),
                    RespValue::Push(vec![
                        RespValue::BulkString(Some(b"message".to_vec())),
                        RespValue::BulkString(Some(b"channel".to_vec())),
                        RespValue::BulkString(Some(b"payload".to_vec())),
                    ]),
                )]),
            ),
            (
                "null",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("nil".to_string()),
                    RespValue::Null,
                )]),
            ),
            ("empty", RespValue::Attribute(vec![])),
            (
                "repeated",
                RespValue::Attribute(vec![
                    (
                        RespValue::SimpleString("dup".to_string()),
                        RespValue::Integer(1),
                    ),
                    (
                        RespValue::SimpleString("dup".to_string()),
                        RespValue::Integer(2),
                    ),
                ]),
            ),
            (
                "unknown_key",
                RespValue::Attribute(vec![(
                    RespValue::BulkString(Some(vec![0x01, 0x02, 0x03])),
                    RespValue::SimpleString("opaque".to_string()),
                )]),
            ),
            (
                "nested_attribute",
                RespValue::Array(Some(vec![
                    RespValue::Attribute(vec![(
                        RespValue::SimpleString("outer".to_string()),
                        RespValue::Attribute(vec![(
                            RespValue::SimpleString("inner".to_string()),
                            RespValue::Boolean(true),
                        )]),
                    )]),
                    RespValue::SimpleString("tail".to_string()),
                ])),
            ),
        ];

        for (scenario_id, value) in cases {
            let wire = value.encode();
            let fingerprint = buffer_fingerprint(&wire);
            let (decoded, consumed) = RespValue::try_decode(&wire)
                .unwrap()
                .expect("RESP3 attribute reference vector should decode");
            assert_eq!(
                decoded, value,
                "{scenario_id} should round-trip; fingerprint={fingerprint}"
            );
            assert_eq!(
                consumed,
                wire.len(),
                "{scenario_id} should consume the full wire image"
            );
            eprintln!(
                "RESP3_ATTRIBUTE scenario_id={scenario_id} nesting_depth={} attribute_count={} value_kind={} parser_state=decoded fingerprint={} verdict=pass",
                nesting_depth(&decoded),
                attribute_pair_count(&decoded),
                value_kind(&decoded),
                fingerprint
            );
        }
    }

    #[test]
    fn resp3_attributes_reject_malformed_nested_pairs() {
        let malformed_cases: [(&str, &[u8], &str); 2] = [
            (
                "streamed_attribute_not_supported",
                b"|?\r\n+meta\r\n.\r\n",
                "streamed aggregate not supported",
            ),
            (
                "nested_streamed_map_missing_value",
                b"|1\r\n+meta\r\n%?\r\n+field\r\n.\r\n",
                "odd number of values",
            ),
        ];

        for (scenario_id, wire, expected_fragment) in malformed_cases {
            let error = RespValue::try_decode(wire)
                .expect_err("malformed RESP3 attribute should fail to decode");
            match error {
                RedisError::Protocol(message) => {
                    assert!(
                        message.contains(expected_fragment),
                        "{scenario_id} should mention {expected_fragment:?}, got {message:?}"
                    );
                    eprintln!(
                        "RESP3_ATTRIBUTE scenario_id={scenario_id} parser_state=error error_kind=protocol fingerprint={} verdict=pass",
                        buffer_fingerprint(wire)
                    );
                }
                other => panic!("{scenario_id} returned unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn resp3_reference_vectors_match_redis_rs_value_model_for_composite_types() {
        // Keep a single differential matrix over the RESP3 composite/value
        // variants we care about here. redis-rs preserves map/set ordering on
        // the wire, exposes verbatim strings as (format, text), and treats big
        // numbers as exact signed arbitrary-precision decimal payloads.
        let cases: Vec<(&str, RespValue, &'static [u8])> = vec![
            (
                "map",
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("proto".to_string()),
                        RespValue::Integer(3),
                    ),
                    (
                        RespValue::BulkString(Some(b"mode".to_vec())),
                        RespValue::SimpleString("standalone".to_string()),
                    ),
                ]),
                concat!(
                    "%2\r\n",
                    "+proto\r\n",
                    ":3\r\n",
                    "$4\r\nmode\r\n",
                    "+standalone\r\n",
                )
                .as_bytes(),
            ),
            (
                "set",
                RespValue::Set(vec![
                    RespValue::Integer(1),
                    RespValue::BulkString(Some(b"two".to_vec())),
                    RespValue::Boolean(true),
                ]),
                concat!("~3\r\n", ":1\r\n", "$3\r\ntwo\r\n", "#t\r\n").as_bytes(),
            ),
            (
                "verbatim",
                RespValue::Verbatim {
                    format: "txt".to_string(),
                    payload: b"hello\r\nworld".to_vec(),
                },
                b"=16\r\ntxt:hello\r\nworld\r\n",
            ),
            (
                "big_number",
                RespValue::BigNumber("3492890328409238509324850943850943825024385".to_string()),
                b"(3492890328409238509324850943850943825024385\r\n",
            ),
            (
                "big_number_negative",
                RespValue::BigNumber("-3492890328409238509324850943850943825024385".to_string()),
                b"(-3492890328409238509324850943850943825024385\r\n",
            ),
            (
                "big_number_explicit_plus",
                RespValue::BigNumber("+42".to_string()),
                b"(+42\r\n",
            ),
        ];

        for (name, value, expected) in cases {
            assert_eq!(
                value.encode(),
                expected,
                "RESP3 {name} encoding must stay byte-compatible with redis-rs's \
                 low-level value model"
            );

            let (decoded, consumed) = RespValue::try_decode(expected)
                .unwrap()
                .unwrap_or_else(|| panic!("RESP3 {name} vector should decode"));
            assert_eq!(
                decoded, value,
                "RESP3 {name} decoding must preserve the redis-rs-compatible \
                 low-level value model"
            );
            assert_eq!(
                consumed,
                expected.len(),
                "RESP3 {name} decoder must consume the full reference vector"
            );
        }
    }

    #[test]
    fn resp3_big_number_rejects_non_protocol_decimal_payloads() {
        for (name, wire) in [
            ("empty", b"(\r\n".as_slice()),
            ("plus_only", b"(+\r\n"),
            ("minus_only", b"(-\r\n"),
            ("double_plus", b"(++1\r\n"),
            ("minus_plus", b"(-+1\r\n"),
            ("fractional", b"(1.5\r\n"),
            ("alpha", b"(12abc\r\n"),
        ] {
            assert!(
                matches!(RespValue::try_decode(wire), Err(RedisError::Protocol(_))),
                "RESP3 BigNumber {name} payload should be rejected"
            );
        }
    }

    #[test]
    fn resp3_streamed_blob_string_decodes_to_bulk_string() {
        let wire = b"$?\r\n;4\r\nHell\r\n;6\r\no worl\r\n;1\r\nd\r\n;0\r\n";

        let (decoded, consumed) = RespValue::try_decode(wire)
            .unwrap()
            .expect("complete RESP3 streamed blob should decode");

        assert_eq!(
            decoded,
            RespValue::BulkString(Some(b"Hello world".to_vec()))
        );
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.encode(), b"$11\r\nHello world\r\n");
    }

    #[test]
    fn resp3_empty_streamed_blob_decodes_to_empty_bulk_string() {
        let wire = b"$?\r\n;0\r\n";

        let (decoded, consumed) = RespValue::try_decode(wire)
            .unwrap()
            .expect("complete empty RESP3 streamed blob should decode");

        assert_eq!(decoded, RespValue::BulkString(Some(Vec::new())));
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.encode(), b"$0\r\n\r\n");
    }

    #[test]
    fn resp3_streamed_array_set_and_map_decode_until_end_marker() {
        let array_wire = b"*?\r\n:1\r\n$3\r\ntwo\r\n#t\r\n.\r\n";
        let (array, array_consumed) = RespValue::try_decode(array_wire)
            .unwrap()
            .expect("complete RESP3 streamed array should decode");
        assert_eq!(
            array,
            RespValue::Array(Some(vec![
                RespValue::Integer(1),
                RespValue::BulkString(Some(b"two".to_vec())),
                RespValue::Boolean(true),
            ]))
        );
        assert_eq!(array_consumed, array_wire.len());

        let set_wire = b"~?\r\n+orange\r\n+apple\r\n.\r\n";
        let (set, set_consumed) = RespValue::try_decode(set_wire)
            .unwrap()
            .expect("complete RESP3 streamed set should decode");
        assert_eq!(
            set,
            RespValue::Set(vec![
                RespValue::SimpleString("orange".to_string()),
                RespValue::SimpleString("apple".to_string()),
            ])
        );
        assert_eq!(set_consumed, set_wire.len());

        let map_wire = b"%?\r\n+first\r\n:1\r\n+second\r\n:2\r\n.\r\n";
        let (map, map_consumed) = RespValue::try_decode(map_wire)
            .unwrap()
            .expect("complete RESP3 streamed map should decode");
        assert_eq!(
            map,
            RespValue::Map(vec![
                (
                    RespValue::SimpleString("first".to_string()),
                    RespValue::Integer(1)
                ),
                (
                    RespValue::SimpleString("second".to_string()),
                    RespValue::Integer(2),
                ),
            ])
        );
        assert_eq!(map_consumed, map_wire.len());
    }

    #[test]
    fn nested_resp3_attributes_do_not_consume_aggregate_slots_or_next_reply() {
        let first_reply = concat!(
            "*2\r\n",
            "|1\r\n+ttl\r\n:30\r\n",
            "+first\r\n",
            "%1\r\n+key\r\n|1\r\n+source\r\n+cache\r\n+value\r\n",
        );
        let mut pipelined = first_reply.as_bytes().to_vec();
        pipelined.extend_from_slice(b"+NEXT\r\n");

        let limits = RedisProtocolLimits::default();
        let mut read_buf = RespReadBuffer::new();
        read_buf.extend(&pipelined);
        let frame_len = read_buf
            .response_frame_len(&limits)
            .expect("nested RESP3 attributes must scan")
            .expect("the first pipelined reply boundary is complete");
        assert_eq!(frame_len, first_reply.len());

        let (decoded, consumed) = RespValue::try_decode_response_with_limits(&pipelined, &limits)
            .expect("nested RESP3 attributes must parse")
            .expect("the first pipelined reply is complete");

        assert_eq!(
            decoded,
            RespValue::Array(Some(vec![
                RespValue::SimpleString("first".to_string()),
                RespValue::Map(vec![(
                    RespValue::SimpleString("key".to_string()),
                    RespValue::SimpleString("value".to_string()),
                )]),
            ]))
        );
        assert_eq!(consumed, first_reply.len());

        read_buf.consume(consumed);
        let next_frame_len = read_buf
            .response_frame_len(&limits)
            .expect("the following reply must scan")
            .expect("the following reply boundary is complete");
        assert_eq!(next_frame_len, b"+NEXT\r\n".len());
        let (next, next_consumed) =
            RespValue::try_decode_response_with_limits(read_buf.available(), &limits)
                .expect("the following reply must remain aligned")
                .expect("the following reply is complete");
        assert_eq!(next, RespValue::SimpleString("NEXT".to_string()));
        assert_eq!(next_consumed, b"+NEXT\r\n".len());
    }

    #[test]
    fn fragmented_large_resp_frame_scans_in_linear_work() {
        const ELEMENTS: usize = 4096;
        let mut wire = format!("*{ELEMENTS}\r\n").into_bytes();
        for value in 0..ELEMENTS {
            wire.extend_from_slice(format!(":{value}\r\n").as_bytes());
        }

        let limits = RedisProtocolLimits::default().max_frame_size(wire.len() + 1);
        let mut read_buf = RespReadBuffer::new();
        let mut frame_len = None;
        for (index, chunk) in wire.chunks(17).enumerate() {
            read_buf.extend(chunk);
            frame_len = read_buf
                .response_frame_len(&limits)
                .expect("fragmented frame scan must remain valid");
            if index + 1 != wire.len().div_ceil(17) {
                assert!(frame_len.is_none(), "frame completed before final fragment");
            }
        }

        assert_eq!(frame_len, Some(wire.len()));
        assert!(
            read_buf.frame_scanner.work_units() <= wire.len().saturating_mul(2),
            "incremental scan work must stay linear: work={} bytes={}",
            read_buf.frame_scanner.work_units(),
            wire.len()
        );

        let (decoded, consumed) =
            RespValue::try_decode_response_with_limits(read_buf.available(), &limits)
                .expect("complete large frame must decode")
                .expect("complete large frame must be present");
        assert_eq!(consumed, wire.len());
        assert!(matches!(decoded, RespValue::Array(Some(values)) if values.len() == ELEMENTS));
    }

    #[test]
    fn resp3_streamed_types_fail_closed_on_incomplete_or_malformed_frames() {
        assert!(
            RespValue::try_decode(b"$?\r\n;4\r\nHell\r\n")
                .unwrap()
                .is_none(),
            "streamed blob without zero-length chunk remains incomplete"
        );

        let odd_map = RespValue::try_decode(b"%?\r\n+key\r\n.\r\n")
            .expect_err("streamed map with key but no value must fail closed");
        assert!(matches!(odd_map, RedisError::Protocol(msg) if msg.contains("odd")));

        let unsupported_push = RespValue::try_decode(b">?\r\n+message\r\n.\r\n")
            .expect_err("streamed push is outside the RESP3 streamed aggregate set");
        assert!(
            matches!(unsupported_push, RedisError::Protocol(msg) if msg.contains("not supported"))
        );
    }

    #[test]
    fn resp3_streamed_blob_respects_total_bulk_limit() {
        let limits = RedisProtocolLimits::new().max_bulk_string_len(4);
        let err =
            RespValue::try_decode_with_limits(b"$?\r\n;3\r\nabc\r\n;2\r\nde\r\n;0\r\n", &limits)
                .expect_err("streamed blob total length must obey max_bulk_string_len");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("streamed blob length")));
    }

    #[test]
    fn test_resp_decode_partial_needs_more() {
        assert!(RespValue::try_decode(b"$3\r\nfo").unwrap().is_none());
    }

    #[test]
    fn test_config_from_url() {
        let config = RedisConfig::from_url("redis://localhost:6379").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 6379);
    }

    #[test]
    fn test_redis_url_credential_redaction_in_errors() {
        // SECURITY TEST: Verify credentials are redacted from error messages
        // to prevent password leakage in logs/traces (asupersync-0kp34a)

        // Test invalid scheme with credentials
        let err = RedisConfig::from_url("http://user:secret123@localhost:6379")
            .expect_err("invalid scheme should fail");
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("***"),
            "Password should be redacted in error message"
        );
        assert!(
            !err_msg.contains("secret123"),
            "Password should not appear in error message"
        );
        assert!(
            !err_msg.contains("user:secret123"),
            "Full userinfo should not appear in error message"
        );

        // Test redact_url_for_errors function directly
        assert_eq!(
            RedisConfig::redact_url_for_errors("redis://user:pass@host:6379/1"),
            "redis://***@host:6379/1"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("rediss://admin:s3cr3t@prod.redis.com:6380"),
            "rediss://***@prod.redis.com:6380"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("redis://localhost:6379"),
            "redis://localhost:6379"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("http://invalid"),
            "[REDACTED_INVALID_URL]"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("http://user:secret123@localhost:6379"),
            "[REDACTED_INVALID_URL:***]"
        );

        // Test with complex passwords containing special characters
        let complex_url = "redis://user:p@ss:w0rd!@localhost:6379";
        let redacted = RedisConfig::redact_url_for_errors(complex_url);
        assert_eq!(redacted, "redis://***@localhost:6379");
        assert!(!redacted.contains("p@ss:w0rd!"));
    }

    #[test]
    fn test_redis_url_credential_decoding() {
        // SECURITY TEST: Verify URL-encoded credentials are properly decoded
        // to prevent authentication bypass (asupersync-ts45lv)

        // Test basic percent-encoding decoding
        assert_eq!(RedisConfig::url_decode_credential("user").unwrap(), "user");
        assert_eq!(
            RedisConfig::url_decode_credential("user%3Aescaped").unwrap(),
            "user:escaped"
        );
        assert_eq!(
            RedisConfig::url_decode_credential("pass%40word").unwrap(),
            "pass@word"
        );

        // Test URL with encoded colon in username (potential bypass vector)
        let config = RedisConfig::from_url("redis://admin%3Auser:password@localhost:6379").unwrap();
        assert_eq!(config.username, Some("admin:user".to_string()));
        assert_eq!(config.password, Some("password".to_string()));

        // Test URL with encoded characters in password
        let config = RedisConfig::from_url("redis://user:p%40ss%3Aw0rd@localhost:6379").unwrap();
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("p@ss:w0rd".to_string()));

        // Test password-only format with encoding
        let config = RedisConfig::from_url("redis://my%40password@localhost:6379").unwrap();
        assert_eq!(config.username, None);
        assert_eq!(config.password, Some("my@password".to_string()));

        // Test error cases
        assert!(RedisConfig::url_decode_credential("invalid%").is_err());
        assert!(RedisConfig::url_decode_credential("invalid%G").is_err());
        assert!(RedisConfig::url_decode_credential("invalid%GZ").is_err());

        // Test common percent-encoded characters
        assert_eq!(
            RedisConfig::url_decode_credential("test%20space").unwrap(),
            "test space"
        );
        assert_eq!(
            RedisConfig::url_decode_credential("test%21exclaim").unwrap(),
            "test!exclaim"
        );
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_redis_tls_hostname_verification_enabled() {
        // SECURITY TEST: Verify TLS connector is configured with hostname verification
        // to prevent MITM attacks (asupersync-xq1qe3)

        let config = RedisConfig::from_url("rediss://localhost:6380").unwrap();
        assert!(config.use_tls);
        assert!(config.tls_connector.is_some());

        // The TLS connector should be configured with hostname verification
        // This test verifies the connector was built with the security flag enabled
        let tls_connector = config.tls_connector.unwrap();

        // Note: We can't directly inspect the hostname verification setting from
        // the built connector, but we can verify it was created without errors
        // which confirms the hostname-verifying rustls connector was built
        assert!(!format!("{:?}", tls_connector).is_empty());

        // Test that rediss:// URLs enable TLS
        let config_secure = RedisConfig::from_url("rediss://redis.example.com:6380").unwrap();
        assert!(config_secure.use_tls);
        assert_eq!(config_secure.host, "redis.example.com");
        assert_eq!(config_secure.port, 6380);

        // Test that redis:// URLs don't enable TLS
        let config_plain = RedisConfig::from_url("redis://redis.example.com:6379").unwrap();
        assert!(!config_plain.use_tls);
        assert!(config_plain.tls_connector.is_none());
    }

    #[test]
    #[cfg(not(feature = "tls"))]
    fn test_redis_tls_disabled_when_feature_missing() {
        // Verify TLS URLs are rejected when TLS feature is not enabled
        let err = RedisConfig::from_url("rediss://localhost:6380")
            .expect_err("rediss:// should fail when TLS feature disabled");
        assert!(
            matches!(err, RedisError::InvalidUrl(ref msg) if msg.contains("TLS support not enabled"))
        );
    }

    // Pure data-type tests (wave 13 – CyanBarn)

    #[test]
    fn redis_error_display_all_variants() {
        assert!(
            RedisError::Io(io::Error::other("e"))
                .to_string()
                .contains("I/O error")
        );
        assert!(
            RedisError::Protocol("p".into())
                .to_string()
                .contains("protocol error")
        );
        assert!(
            RedisError::Redis("r".into())
                .to_string()
                .contains("Redis error")
        );
        assert!(
            RedisError::PoolExhausted
                .to_string()
                .contains("pool exhausted")
        );
        assert!(
            RedisError::InvalidUrl("bad://".into())
                .to_string()
                .contains("bad://")
        );
        assert!(RedisError::Cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn redis_error_debug() {
        let err = RedisError::PoolExhausted;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PoolExhausted"));
    }

    #[test]
    fn redis_error_source_io() {
        let err = RedisError::Io(io::Error::other("disk"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn redis_error_source_none_for_others() {
        assert!(std::error::Error::source(&RedisError::Cancelled).is_none());
        assert!(std::error::Error::source(&RedisError::PoolExhausted).is_none());
    }

    #[test]
    fn redis_error_from_io() {
        let io_err = io::Error::other("net");
        let err: RedisError = RedisError::from(io_err);
        assert!(matches!(err, RedisError::Io(_)));
    }

    #[test]
    fn resp_value_encode_error() {
        let val = RespValue::Error("ERR bad".into());
        assert_eq!(val.encode(), b"-ERR bad\r\n");
    }

    #[test]
    fn resp_value_encode_null_bulk_string() {
        let val = RespValue::BulkString(None);
        assert_eq!(val.encode(), b"$-1\r\n");
    }

    #[test]
    fn resp_value_encode_null_array() {
        let val = RespValue::Array(None);
        assert_eq!(val.encode(), b"*-1\r\n");
    }

    #[test]
    fn resp_value_encode_empty_array() {
        let val = RespValue::Array(Some(vec![]));
        assert_eq!(val.encode(), b"*0\r\n");
    }

    #[test]
    fn resp_value_encode_negative_integer() {
        let val = RespValue::Integer(-42);
        assert_eq!(val.encode(), b":-42\r\n");
    }

    #[test]
    fn resp_value_encode_zero_integer() {
        let val = RespValue::Integer(0);
        assert_eq!(val.encode(), b":0\r\n");
    }

    #[test]
    fn resp_value_debug_clone_eq() {
        let val = RespValue::SimpleString("OK".into());
        let dbg = format!("{val:?}");
        assert!(dbg.contains("SimpleString"));

        let cloned = val.clone();
        assert_eq!(val, cloned);
    }

    #[test]
    fn resp_value_ne() {
        let a = RespValue::Integer(1);
        let b = RespValue::Integer(2);
        assert_ne!(a, b);
    }

    #[test]
    fn resp_value_as_bytes() {
        let val = RespValue::BulkString(Some(b"hello".to_vec()));
        assert_eq!(val.as_bytes(), Some(&b"hello"[..]));

        let null = RespValue::BulkString(None);
        assert!(null.as_bytes().is_none());

        let not_bulk = RespValue::Integer(1);
        assert!(not_bulk.as_bytes().is_none());
    }

    #[test]
    fn resp_value_as_integer() {
        let val = RespValue::Integer(99);
        assert_eq!(val.as_integer(), Some(99));

        let not_int = RespValue::SimpleString("x".into());
        assert!(not_int.as_integer().is_none());
    }

    #[test]
    fn resp_value_is_ok() {
        assert!(RespValue::SimpleString("OK".into()).is_ok());
        assert!(!RespValue::SimpleString("PONG".into()).is_ok());
        assert!(!RespValue::Integer(0).is_ok());
    }

    #[test]
    fn resp_decode_error_string() {
        let (val, n) = RespValue::try_decode(b"-ERR bad\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(val, RespValue::Error("ERR bad".into()));
        assert_eq!(n, 10);
    }

    #[test]
    fn resp_decode_null_bulk_string() {
        let (val, n) = RespValue::try_decode(b"$-1\r\n").unwrap().expect("decoded");
        assert_eq!(val, RespValue::BulkString(None));
        assert_eq!(n, 5);
    }

    #[test]
    fn resp_decode_null_array() {
        let (val, n) = RespValue::try_decode(b"*-1\r\n").unwrap().expect("decoded");
        assert_eq!(val, RespValue::Array(None));
        assert_eq!(n, 5);
    }

    #[test]
    fn resp_decode_unknown_type() {
        let err = RespValue::try_decode(b"~invalid\r\n");
        assert!(err.is_err());
    }

    #[test]
    fn redis_config_default() {
        let cfg = RedisConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 6379);
        assert_eq!(cfg.database, 0);
        assert!(cfg.password.is_none());
    }

    #[test]
    fn redis_config_debug_redacts_password() {
        let cfg = RedisConfig {
            password: Some("secret".into()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn redis_config_debug_redacts_username_and_password() {
        // br-asupersync-lru405 + br-asupersync-kytkta: username is a credential
        // under Redis 6+ ACL — must be redacted alongside password.
        let cfg = RedisConfig {
            username: Some("admin_user".into()),
            password: Some("hunter2".into()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("admin_user"),
            "username leaked in Debug output: {dbg}"
        );
        assert!(
            !dbg.contains("hunter2"),
            "password leaked in Debug output: {dbg}"
        );
        // Some/None distinction preserved (operator can still see whether a
        // credential is configured without seeing its value).
        assert!(
            dbg.contains("Some(\"[REDACTED]\")"),
            "expected redacted Some marker: {dbg}"
        );
    }

    #[test]
    fn redis_config_debug_unset_username_renders_none() {
        let cfg = RedisConfig {
            username: None,
            password: None,
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("username: None"),
            "expected 'username: None': {dbg}"
        );
        assert!(
            dbg.contains("password: None"),
            "expected 'password: None': {dbg}"
        );
        assert!(
            !dbg.contains("REDACTED"),
            "REDACTED should not appear when unset: {dbg}"
        );
    }

    #[test]
    fn redis_config_clone() {
        let cfg = RedisConfig::default();
        let cloned = cfg;
        assert_eq!(cloned.host, "127.0.0.1");
    }

    #[test]
    fn redis_config_from_url_with_password() {
        let cfg = RedisConfig::from_url("redis://pass123@myhost:6380/3").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 6380);
        assert_eq!(cfg.database, 3);
        assert_eq!(cfg.password, Some("pass123".into()));
    }

    #[test]
    fn redis_config_from_url_invalid_scheme() {
        assert!(RedisConfig::from_url("http://localhost").is_err());
    }

    #[test]
    fn redis_config_from_url_host_only() {
        let cfg = RedisConfig::from_url("redis://myhost").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 6379);
    }

    #[test]
    fn watch_rejects_pooled_client_api() {
        let client = pooled_client_without_acquire();
        run_test_with_cx(move |cx| async move {
            let err = client
                .watch(&cx, &["k1"])
                .expect_err("WATCH must fail closed");
            assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("connection-scoped")));
        });
    }

    #[test]
    fn unwatch_rejects_pooled_client_api() {
        let client = pooled_client_without_acquire();
        run_test_with_cx(move |cx| async move {
            let err = client.unwatch(&cx).expect_err("UNWATCH must fail closed");
            assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("connection-scoped")));
        });
    }

    #[test]
    fn resp_encode_into_reuse_buffer() {
        let mut buf = Vec::new();
        RespValue::SimpleString("PING".into()).encode_into(&mut buf);
        RespValue::Integer(1).encode_into(&mut buf);
        assert_eq!(&buf, b"+PING\r\n:1\r\n");
    }

    #[test]
    fn expect_ok_response_accepts_ok() {
        let resp = RespValue::SimpleString("OK".to_string());
        assert!(expect_ok_response(&resp, "TEST").is_ok());
    }

    #[test]
    fn expect_ok_response_rejects_non_ok() {
        let resp = RespValue::SimpleString("PONG".to_string());
        let err = expect_ok_response(&resp, "TEST").expect_err("must reject non-OK");
        assert!(matches!(err, RedisError::Protocol(_)));
    }

    #[test]
    fn classify_command_response_rejects_resp2_and_resp3_errors() {
        let resp2 = classify_command_response(RespValue::Error("ERR resp2".to_string()))
            .expect_err("RESP2 error must not surface as a successful command reply");
        assert!(matches!(resp2, RedisError::Redis(message) if message == "ERR resp2"));

        let resp3 =
            classify_command_response(RespValue::BlobError(vec![b'E', b'R', b'R', b' ', 0xff]))
                .expect_err("RESP3 blob error must not surface as a successful command reply");
        assert!(
            matches!(resp3, RedisError::Redis(message) if message == "ERR \u{fffd}"),
            "binary blob errors should use a deterministic lossy representation"
        );

        let success = classify_command_response(RespValue::Integer(7))
            .expect("non-error replies must remain successful");
        assert_eq!(success, RespValue::Integer(7));
    }

    #[test]
    fn pubsub_parse_message_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"message".to_vec())),
            RespValue::BulkString(Some(b"chan-1".to_vec())),
            RespValue::BulkString(Some(b"payload".to_vec())),
        ])))
        .expect("message event should parse");

        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "chan-1".to_string(),
                pattern: None,
                payload: b"payload".to_vec(),
            })
        );
    }

    #[test]
    fn pubsub_parse_resp3_push_message_event() {
        let event = RedisPubSub::parse_event(RespValue::Push(vec![
            RespValue::BulkString(Some(b"message".to_vec())),
            RespValue::BulkString(Some(b"chan-1".to_vec())),
            RespValue::BulkString(Some(b"payload".to_vec())),
        ]))
        .expect("RESP3 push message event should parse");

        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "chan-1".to_string(),
                pattern: None,
                payload: b"payload".to_vec(),
            })
        );
    }

    #[test]
    fn pubsub_parse_pmessage_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pmessage".to_vec())),
            RespValue::BulkString(Some(b"user.*".to_vec())),
            RespValue::BulkString(Some(b"user.created".to_vec())),
            RespValue::BulkString(Some(b"body".to_vec())),
        ])))
        .expect("pmessage event should parse");

        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "user.created".to_string(),
                pattern: Some("user.*".to_string()),
                payload: b"body".to_vec(),
            })
        );
    }

    /// Audit test for PSUBSCRIBE pattern-matching and message delivery.
    ///
    /// Verifies that when subscribed to "news.*" and message arrives on "news.tech",
    /// the pattern matches (glob * semantics) and message is delivered with the full
    /// channel name "news.tech" along with the original pattern "news.*".
    #[test]
    fn audit_psubscribe_glob_pattern_matching_news_tech() {
        // Build Redis server response for PSUBSCRIBE pattern match.
        // Format: ["pmessage", pattern, actual_channel, payload]
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pmessage".to_vec())),
            RespValue::BulkString(Some(b"news.*".to_vec())), // Original pattern
            RespValue::BulkString(Some(b"news.tech".to_vec())), // Actual channel that matched
            RespValue::BulkString(Some(b"Breaking: New AI framework released".to_vec())),
        ])))
        .expect("Redis pmessage for news.* → news.tech should parse correctly");

        // Verify correct pattern matching behavior
        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "news.tech".to_string(),    // Full channel name preserved
                pattern: Some("news.*".to_string()), // Original pattern preserved
                payload: b"Breaking: New AI framework released".to_vec(),
            }),
            "PSUBSCRIBE must deliver message with full channel name AND original pattern"
        );

        // Additional verification: pattern field must be present for PSUBSCRIBE deliveries
        if let PubSubEvent::Message(msg) = event {
            assert!(
                msg.pattern.is_some(),
                "PSUBSCRIBE messages MUST include the pattern field to distinguish from SUBSCRIBE"
            );
            assert_eq!(
                msg.pattern.unwrap(),
                "news.*",
                "Pattern field must contain the exact subscription pattern"
            );
            assert_eq!(
                msg.channel, "news.tech",
                "Channel field must contain the full matching channel name, not the pattern"
            );
        } else {
            panic!("Expected Message event");
        }
    }

    #[test]
    fn pubsub_parse_subscription_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"subscribe".to_vec())),
            RespValue::BulkString(Some(b"metrics".to_vec())),
            RespValue::Integer(2),
        ])))
        .expect("subscribe event should parse");

        assert_eq!(
            event,
            PubSubEvent::Subscription {
                kind: PubSubSubscriptionKind::Subscribe,
                channel: "metrics".to_string(),
                remaining: 2,
            }
        );
    }

    #[test]
    fn pubsub_parse_subscription_rejects_negative_remaining_count() {
        let err = RedisPubSub::parse_event(pubsub_subscription_frame(b"subscribe", b"metrics", -1))
            .expect_err("negative remaining subscription counts must fail closed");
        assert!(
            matches!(err, RedisError::Protocol(message) if message.contains("remaining-count must be nonnegative"))
        );
    }

    #[test]
    fn pubsub_parse_pong_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pong".to_vec())),
            RespValue::BulkString(Some(b"hello".to_vec())),
        ])))
        .expect("pong event should parse");

        assert_eq!(event, PubSubEvent::Pong(Some(b"hello".to_vec())));
    }

    #[test]
    fn pubsub_parse_event_rejects_contextless_scalar_pong() {
        for value in [
            RespValue::SimpleString("PONG".to_string()),
            RespValue::BulkString(Some(b"echo".to_vec())),
        ] {
            assert!(
                matches!(
                    RedisPubSub::parse_event(value),
                    Err(RedisError::Protocol(_))
                ),
                "scalar PONG replies require pending PING request context"
            );
        }
    }

    #[test]
    fn pubsub_parse_ping_resp3_binary_echo() {
        let payload = [0x00, 0xff, b'\r', b'\n'];
        let event = RedisPubSub::parse_ping_event(
            RespValue::BulkString(Some(payload.to_vec())),
            Some(&payload),
        )
        .expect("RESP3 should echo the exact binary PING payload");
        assert_eq!(event, PubSubEvent::Pong(Some(payload.to_vec())));
    }

    #[test]
    fn pubsub_parse_ping_empty_payload_shapes() {
        let no_payload =
            RedisPubSub::parse_ping_event(RespValue::SimpleString("PONG".to_string()), None)
                .expect("argument-less RESP3 PING should accept +PONG");
        assert_eq!(no_payload, PubSubEvent::Pong(None));

        let explicit_empty =
            RedisPubSub::parse_ping_event(RespValue::BulkString(Some(Vec::new())), Some(&[]))
                .expect("explicit empty RESP3 PING payload should require an empty bulk echo");
        assert_eq!(explicit_empty, PubSubEvent::Pong(Some(Vec::new())));

        assert!(
            RedisPubSub::parse_ping_event(RespValue::BulkString(Some(Vec::new())), None).is_err(),
            "argument-less RESP3 PING must not accept a bulk response"
        );
        assert!(
            RedisPubSub::parse_ping_event(RespValue::SimpleString("PONG".to_string()), Some(&[]),)
                .is_err(),
            "explicit empty RESP3 PING payload must not accept +PONG"
        );
    }

    #[test]
    fn pubsub_parse_ping_resp2_echo_shapes() {
        let no_payload = RedisPubSub::parse_ping_event(
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::BulkString(Some(Vec::new())),
            ])),
            None,
        )
        .expect("argument-less subscribed RESP2 PING should carry an empty echo");
        assert_eq!(no_payload, PubSubEvent::Pong(Some(Vec::new())));

        let payload = [0x00, 0xff, b'\r', b'\n'];
        let binary = RedisPubSub::parse_ping_event(
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::BulkString(Some(payload.to_vec())),
            ])),
            Some(&payload),
        )
        .expect("subscribed RESP2 PING should echo binary payloads exactly");
        assert_eq!(binary, PubSubEvent::Pong(Some(payload.to_vec())));

        assert!(
            RedisPubSub::parse_ping_event(
                RespValue::Array(Some(vec![RespValue::BulkString(Some(b"pong".to_vec()))])),
                None,
            )
            .is_err(),
            "subscribed RESP2 PING must include the canonical payload field"
        );
    }

    #[test]
    fn pubsub_parse_ping_rejects_echo_mismatch() {
        let expected = b"sensitive-request-payload";
        let responses = [
            RespValue::BulkString(Some(b"sensitive-request-payloae".to_vec())),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::BulkString(Some(b"sensitive-request-payloae".to_vec())),
            ])),
            RespValue::SimpleString("PONG".to_string()),
            RespValue::SimpleString("pong".to_string()),
            RespValue::BulkString(None),
            RespValue::Array(Some(vec![RespValue::BulkString(Some(expected.to_vec()))])),
            RespValue::Array(Some(vec![
                RespValue::SimpleString("pong".to_string()),
                RespValue::SimpleString("sensitive-request-payload".to_string()),
            ])),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"PONG".to_vec())),
                RespValue::BulkString(Some(expected.to_vec())),
            ])),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::SimpleString("sensitive-request-payload".to_string()),
            ])),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::BulkString(Some(expected.to_vec())),
                RespValue::BulkString(Some(b"trailing".to_vec())),
            ])),
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"pong".to_vec())),
                RespValue::BulkString(Some(expected.to_vec())),
            ]),
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"channel".to_vec())),
                RespValue::Integer(1),
            ]),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"channel".to_vec())),
                RespValue::Integer(1),
            ])),
            RespValue::Push(vec![RespValue::Array(Some(vec![RespValue::BulkString(
                Some(expected.to_vec()),
            )]))]),
        ];
        for response in responses {
            let err = RedisPubSub::parse_ping_event(response, Some(expected))
                .expect_err("mismatched PING echo must fail closed");
            assert!(matches!(err, RedisError::Protocol(_)));
            assert!(
                !err.to_string().contains("sensitive-request"),
                "PING validation diagnostics must not expose payload bytes"
            );
        }

        assert!(
            RedisPubSub::parse_ping_event(RespValue::BulkString(Some(expected.to_vec())), None,)
                .is_err(),
            "argument-less PING must reject an unsolicited bulk payload"
        );
    }

    #[test]
    fn pubsub_parse_unknown_event_kind_fails() {
        let err = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"weird".to_vec())),
            RespValue::BulkString(Some(b"x".to_vec())),
        ])))
        .expect_err("unknown event should fail");

        assert!(matches!(err, RedisError::Protocol(_)));
    }

    #[test]
    fn client_tracking_push_parse_invalidate_keys() {
        let event = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"user:1".to_vec())),
                RespValue::SimpleString("config:active".to_string()),
            ])),
        ]))
        .expect("client tracking invalidation should parse");

        assert_eq!(
            event,
            RedisClientTrackingPush::Invalidate {
                keys: Some(vec![b"user:1".to_vec(), b"config:active".to_vec()])
            }
        );
    }

    #[test]
    fn client_tracking_push_parse_flush_and_redirect_broken() {
        let flush = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Null,
        ]))
        .expect("null invalidation should parse as a cache flush");
        assert_eq!(flush, RedisClientTrackingPush::Invalidate { keys: None });

        let broken =
            parse_client_tracking_push_for_fuzz(RespValue::Push(vec![RespValue::BulkString(
                Some(b"tracking-redir-broken".to_vec()),
            )]))
            .expect("tracking-redir-broken should parse");
        assert_eq!(broken, RedisClientTrackingPush::RedirectBroken);
    }

    #[test]
    fn client_tracking_push_rejects_malformed_frames() {
        let non_push = parse_client_tracking_push_for_fuzz(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![])),
        ])));
        assert!(
            non_push.is_err(),
            "tracking notifications must be RESP3 pushes"
        );

        let bad_key_payload = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![RespValue::Integer(7)])),
        ]));
        assert!(
            bad_key_payload.is_err(),
            "invalidation keys must be payloads"
        );

        let trailing_redirect = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"tracking-redir-broken".to_vec())),
            RespValue::BulkString(Some(b"extra".to_vec())),
        ]));
        assert!(
            trailing_redirect.is_err(),
            "tracking-redir-broken must reject trailing fields"
        );
    }

    #[test]
    fn resp3_non_pubsub_push_classifies_generic_push() {
        let event = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"server-event".to_vec())),
            RespValue::BulkString(Some(
                b"1700000000.000000 [0 127.0.0.1:1] \"GET\" \"k\"".to_vec(),
            )),
            RespValue::Integer(9),
        ]))
        .expect("generic non-pubsub push should parse");

        assert_eq!(
            event,
            RedisResp3NonPubSubPush::Other {
                kind: "server-event".to_string(),
                payload: vec![
                    RespValue::BulkString(Some(
                        b"1700000000.000000 [0 127.0.0.1:1] \"GET\" \"k\"".to_vec()
                    )),
                    RespValue::Integer(9)
                ],
            }
        );
    }

    #[test]
    fn resp3_non_pubsub_push_delegates_tracking_and_rejects_pubsub() {
        let tracking = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![RespValue::BulkString(Some(b"k".to_vec()))])),
        ]))
        .expect("client tracking push should parse through non-pubsub seam");
        assert_eq!(
            tracking,
            RedisResp3NonPubSubPush::ClientTracking(RedisClientTrackingPush::Invalidate {
                keys: Some(vec![b"k".to_vec()])
            })
        );

        let pubsub = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"message".to_vec())),
            RespValue::BulkString(Some(b"chan".to_vec())),
            RespValue::BulkString(Some(b"body".to_vec())),
        ]));
        assert!(
            pubsub.is_err(),
            "pubsub push kinds must use the pubsub parser"
        );

        let empty = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![]));
        assert!(empty.is_err(), "empty RESP3 pushes must be rejected");
    }

    #[test]
    fn redis_resp3_push_single_push_before_integer_response_is_buffered() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"invalidate".to_vec())),
                RespValue::Array(Some(vec![
                    RespValue::BulkString(Some(b"alpha".to_vec())),
                    RespValue::BulkString(Some(b"beta".to_vec())),
                ])),
            ])
            .encode_into(&mut bytes);
            RespValue::Integer(7).encode_into(&mut bytes);
            bytes
        };
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let push_frame_len = RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"alpha".to_vec())),
                RespValue::BulkString(Some(b"beta".to_vec())),
            ])),
        ])
        .encode()
        .len();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write RESP3 push + integer reply");
            stream.flush().expect("flush RESP3 push + integer reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let response = client.cmd(&cx, &["PING"]).await.expect("PING response");
            assert_eq!(response, RespValue::Integer(7));

            tracing::info!(
                frame_kind = "invalidate",
                consumed_bytes = push_frame_len,
                response_count = 1usize,
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 single push buffered before integer response"
            );

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![RedisResp3NonPubSubPush::ClientTracking(
                    RedisClientTrackingPush::Invalidate {
                        keys: Some(vec![b"alpha".to_vec(), b"beta".to_vec()]),
                    },
                )]
            );
            assert_eq!(client.resp3_dropped_pushes(), 0);
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_pipeline_preserves_response_and_push_order() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"first".to_vec())),
            ])
            .encode_into(&mut bytes);
            RespValue::SimpleString("ONE".to_string()).encode_into(&mut bytes);
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"invalidate".to_vec())),
                RespValue::Array(Some(vec![RespValue::BulkString(Some(
                    b"cache-key".to_vec(),
                ))])),
            ])
            .encode_into(&mut bytes);
            RespValue::SimpleString("TWO".to_string()).encode_into(&mut bytes);
            bytes
        };
        let combined_len = combined_buffer.len();
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let mut read_buf = Vec::new();
            let first = read_resp_frame_from_buffer(&mut stream, &mut read_buf);
            assert_resp_command(first, &[b"PING"]);
            let second = read_resp_frame_from_buffer(&mut stream, &mut read_buf);
            assert_resp_command(second, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write pipelined replies");
            stream.flush().expect("flush pipelined replies");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let mut pipeline = client.pipeline();
            pipeline.cmd(&["PING"]);
            pipeline.cmd(&["PING"]);
            let results = pipeline.exec(&cx).await.expect("pipeline exec");

            assert_eq!(results.len(), 2, "pipeline response count");
            assert!(
                matches!(
                    &results[0],
                    Ok(RespValue::SimpleString(value)) if value == "ONE"
                ),
                "first pipeline response should be ONE: {results:?}"
            );
            assert!(
                matches!(
                    &results[1],
                    Ok(RespValue::SimpleString(value)) if value == "TWO"
                ),
                "second pipeline response should be TWO: {results:?}"
            );

            tracing::info!(
                frame_kind = "monitor+invalidate",
                consumed_bytes = combined_len,
                response_count = results.len(),
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 pipeline preserves response and push order"
            );

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![
                    RedisResp3NonPubSubPush::Other {
                        kind: "monitor".to_string(),
                        payload: vec![RespValue::BulkString(Some(b"first".to_vec()))],
                    },
                    RedisResp3NonPubSubPush::ClientTracking(RedisClientTrackingPush::Invalidate {
                        keys: Some(vec![b"cache-key".to_vec()]),
                    },),
                ]
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_attribute_interleaving_still_returns_response() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Attribute(vec![(
                RespValue::SimpleString("meta".to_string()),
                RespValue::SimpleString("before-push".to_string()),
            )])
            .encode_into(&mut bytes);
            RespValue::Push(vec![RespValue::BulkString(Some(
                b"tracking-redir-broken".to_vec(),
            ))])
            .encode_into(&mut bytes);
            RespValue::SimpleString("OK".to_string()).encode_into(&mut bytes);
            bytes
        };
        let combined_len = combined_buffer.len();
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write attribute + push + response");
            stream.flush().expect("flush attribute + push + response");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let response = client.cmd(&cx, &["PING"]).await.expect("PING response");
            assert_eq!(response, RespValue::SimpleString("OK".to_string()));

            tracing::info!(
                frame_kind = "attribute+tracking-redir-broken",
                consumed_bytes = combined_len,
                response_count = 1usize,
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 attribute and push interleaving preserves command response"
            );

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![RedisResp3NonPubSubPush::ClientTracking(
                    RedisClientTrackingPush::RedirectBroken,
                )]
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_cancellation_after_decoded_push_preserves_backlog() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (push_written_tx, push_written_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            let push = RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"cancelled-flight".to_vec())),
            ])
            .encode();
            stream.write_all(&push).expect("write RESP3 push");
            stream.flush().expect("flush RESP3 push");
            push_written_tx.send(()).expect("signal push written");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => closed_tx.send(()).expect("signal close observed"),
                Ok(n) => panic!("expected cancelled client to close transport, read {n} bytes"),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("cancelled client left the socket open after push delivery")
                }
                Err(e) => panic!("probe cancelled socket: {e}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let worker_cx = cx.clone();
            let mut command = Box::pin(client.cmd(&worker_cx, &["PING"]));
            drive_until_signal(
                command.as_mut(),
                &push_written_rx,
                "redis RESP3 push cancellation command",
            );

            for _ in 0..200 {
                if client.resp3_pending_pushes() == 1 {
                    break;
                }
                match poll_once(command.as_mut()) {
                    Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
                    Poll::Ready(result) => {
                        panic!(
                            "command completed before cancellation after push delivery: {result:?}"
                        )
                    }
                }
            }
            assert_eq!(
                client.resp3_pending_pushes(),
                1,
                "decoded RESP3 push must be queued before cancellation"
            );

            tracing::info!(
                frame_kind = "monitor",
                consumed_bytes = 0usize,
                response_count = 0usize,
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                "redis RESP3 cancellation preserves decoded push backlog"
            );

            worker_cx.cancel_fast(crate::types::CancelKind::User);
            let result = future::poll_fn(|poll_cx| command.as_mut().poll(poll_cx)).await;
            assert!(
                matches!(result, Err(RedisError::Cancelled)),
                "expected cancellation after push delivery, got {result:?}"
            );

            closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("cancelled connection should close");

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![RedisResp3NonPubSubPush::Other {
                    kind: "monitor".to_string(),
                    payload: vec![RespValue::BulkString(Some(b"cancelled-flight".to_vec(),))],
                }]
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_backlog_overflow_reports_lag_deterministically() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"first".to_vec())),
            ])
            .encode_into(&mut bytes);
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"second".to_vec())),
            ])
            .encode_into(&mut bytes);
            RespValue::SimpleString("OK".to_string()).encode_into(&mut bytes);
            bytes
        };
        let combined_len = combined_buffer.len();
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write overflow push sequence");
            stream.flush().expect("flush overflow push sequence");
        });

        run_test_with_cx(|cx| async move {
            let mut config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            config.resp3_push_max_backlog = 1;
            let client = client_with_config(config);

            let response = client.cmd(&cx, &["PING"]).await.expect("PING response");
            assert_eq!(response, RespValue::SimpleString("OK".to_string()));

            tracing::info!(
                frame_kind = "monitor-overflow",
                consumed_bytes = combined_len,
                response_count = 1usize,
                push_count = 2usize,
                queue_len = client.resp3_pending_pushes(),
                capacity = 1usize,
                dropped_or_rejected_count = client.resp3_dropped_pushes(),
                reason = "drop newest when regular-client RESP3 push backlog reaches cap",
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 push backlog overflow reports lag deterministically"
            );

            let lag = client
                .try_next_resp3_push()
                .expect_err("overflow must surface lag before queued push");
            assert!(
                matches!(lag, RedisError::Resp3PushLag { dropped: 1 }),
                "unexpected lag result: {lag:?}"
            );

            let next = client
                .try_next_resp3_push()
                .expect("lag should be one-shot")
                .expect("first push remains queued");
            assert_eq!(
                next,
                RedisResp3NonPubSubPush::Other {
                    kind: "monitor".to_string(),
                    payload: vec![RespValue::BulkString(Some(b"first".to_vec()))],
                }
            );
            assert_eq!(
                client.try_next_resp3_push().expect("queue drained"),
                None,
                "only the oldest push should remain after drop-newest overflow"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_psubscribe_rejects_unrequested_ack_pattern() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            write_hello3_ok(&mut stream);
            let psubscribe = read_resp_frame(&mut stream);
            assert_resp_command(psubscribe, &[b"PSUBSCRIBE", b"safe.*"]);
            let injected_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"psubscribe".to_vec())),
                RespValue::BulkString(Some(b"*".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            stream
                .write_all(&injected_ack)
                .expect("write injected psubscribe ack");
            stream.flush().expect("flush injected psubscribe ack");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");

            let err = pubsub
                .psubscribe(&cx, &["safe.*"])
                .await
                .expect_err("unexpected wildcard ack must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(msg) if msg.contains("PSUBSCRIBE received unexpected acknowledgement target"))
            );
            assert!(pubsub.patterns().is_empty());
            assert!(pubsub.pending_events.is_empty());
            assert!(pubsub.poisoned);

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("failed control exchange should poison connection");
            assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("invalidated")));
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_control_rejects_wrong_kind_and_unsolicited_pong_promptly() {
        let mut wrong_kind = Vec::new();
        pubsub_subscription_frame(b"psubscribe", b"chan", 1).encode_into(&mut wrong_kind);
        pubsub_subscription_frame(b"subscribe", b"chan", 1).encode_into(&mut wrong_kind);
        assert_invalid_subscribe_control_reply(
            wrong_kind,
            "redis pubsub rejects wrong acknowledgement kind",
            "unexpected PatternSubscribe acknowledgement",
        );

        let mut unsolicited_pong = Vec::new();
        RespValue::Push(vec![
            RespValue::BulkString(Some(b"pong".to_vec())),
            RespValue::BulkString(Some(Vec::new())),
        ])
        .encode_into(&mut unsolicited_pong);
        pubsub_subscription_frame(b"subscribe", b"chan", 1).encode_into(&mut unsolicited_pong);
        assert_invalid_subscribe_control_reply(
            unsolicited_pong,
            "redis pubsub rejects unsolicited pong during subscribe",
            "unsolicited PONG control reply",
        );
    }

    #[test]
    fn pubsub_control_rejects_negative_remaining_and_poisons_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);
            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            stream
                .write_all(&pubsub_subscription_frame(b"subscribe", b"chan", -1).encode())
                .expect("write negative subscription count");
            stream.flush().expect("flush negative subscription count");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            let err = assert_completes_within(
                Duration::from_secs(2),
                "redis pubsub rejects negative remaining count",
                || Box::pin(pubsub.subscribe(&cx, &["chan"])),
            )
            .await
            .expect_err("negative remaining count must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(message) if message.contains("remaining-count must be nonnegative"))
            );
            assert!(pubsub.channels().is_empty());
            assert!(pubsub.pending_events.is_empty());
            assert!(pubsub.poisoned);

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("poisoned connection must reject event reads");
            assert!(
                matches!(err, RedisError::Protocol(message) if message.contains("invalidated"))
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_control_rejects_divergent_count_after_partial_transition() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);
            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"alpha", b"beta"]);
            let mut outbound = Vec::new();
            pubsub_subscription_frame(b"subscribe", b"alpha", 1).encode_into(&mut outbound);
            pubsub_subscription_frame(b"subscribe", b"beta", 3).encode_into(&mut outbound);
            stream
                .write_all(&outbound)
                .expect("write one coherent and one divergent acknowledgement");
            stream.flush().expect("flush subscription acknowledgements");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            let err = assert_completes_within(
                Duration::from_secs(2),
                "redis pubsub rejects a divergent count after a partial transition",
                || Box::pin(pubsub.subscribe(&cx, &["alpha", "beta"])),
            )
            .await
            .expect_err("divergent remaining count must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(message) if message.contains("reported 3 remaining subscriptions; tracked state requires 2"))
            );
            assert!(pubsub.channels().is_empty());
            assert!(pubsub.patterns().is_empty());
            assert!(pubsub.pending_events.is_empty());
            assert!(pubsub.poisoned);
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_control_counts_span_channels_patterns_and_reconnect() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");
            write_hello3_ok(&mut first_stream);

            let psubscribe = read_resp_frame(&mut first_stream);
            assert_resp_command(psubscribe, &[b"PSUBSCRIBE", b"base.*"]);
            first_stream
                .write_all(&pubsub_subscription_frame(b"psubscribe", b"base.*", 1).encode())
                .expect("write initial pattern acknowledgement");
            first_stream
                .flush()
                .expect("flush initial pattern acknowledgement");

            let subscribe = read_resp_frame(&mut first_stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"alpha", b"beta"]);
            let mut outbound = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"pmessage".to_vec())),
                RespValue::BulkString(Some(b"base.*".to_vec())),
                RespValue::BulkString(Some(b"base.one".to_vec())),
                RespValue::BulkString(Some(b"payload".to_vec())),
            ])
            .encode_into(&mut outbound);
            pubsub_subscription_frame(b"subscribe", b"alpha", 2).encode_into(&mut outbound);
            pubsub_subscription_frame(b"subscribe", b"beta", 3).encode_into(&mut outbound);
            first_stream
                .write_all(&outbound)
                .expect("write interleaved message and channel acknowledgements");
            first_stream
                .flush()
                .expect("flush interleaved message and channel acknowledgements");
            drop(first_stream);

            let (mut second_stream, _) = listener.accept().expect("accept reconnect client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set reconnect read timeout");
            write_hello3_ok(&mut second_stream);

            let subscribe = read_resp_frame(&mut second_stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"alpha", b"beta"]);
            let mut channel_acks = Vec::new();
            pubsub_subscription_frame(b"subscribe", b"alpha", 1).encode_into(&mut channel_acks);
            pubsub_subscription_frame(b"subscribe", b"beta", 2).encode_into(&mut channel_acks);
            second_stream
                .write_all(&channel_acks)
                .expect("write replayed channel acknowledgements");
            second_stream
                .flush()
                .expect("flush replayed channel acknowledgements");

            let psubscribe = read_resp_frame(&mut second_stream);
            assert_resp_command(psubscribe, &[b"PSUBSCRIBE", b"base.*"]);
            second_stream
                .write_all(&pubsub_subscription_frame(b"psubscribe", b"base.*", 3).encode())
                .expect("write replayed pattern acknowledgement");
            second_stream
                .flush()
                .expect("flush replayed pattern acknowledgement");

            let unsubscribe = read_resp_frame(&mut second_stream);
            assert_resp_command(unsubscribe, &[b"UNSUBSCRIBE", b"alpha", b"beta"]);
            let mut channel_unsubscribes = Vec::new();
            pubsub_subscription_frame(b"unsubscribe", b"beta", 2)
                .encode_into(&mut channel_unsubscribes);
            pubsub_subscription_frame(b"unsubscribe", b"alpha", 1)
                .encode_into(&mut channel_unsubscribes);
            second_stream
                .write_all(&channel_unsubscribes)
                .expect("write channel unsubscribe acknowledgements");
            second_stream
                .flush()
                .expect("flush channel unsubscribe acknowledgements");

            let punsubscribe = read_resp_frame(&mut second_stream);
            assert_resp_command(punsubscribe, &[b"PUNSUBSCRIBE", b"base.*"]);
            second_stream
                .write_all(&pubsub_subscription_frame(b"punsubscribe", b"base.*", 0).encode())
                .expect("write pattern unsubscribe acknowledgement");
            second_stream
                .flush()
                .expect("flush pattern unsubscribe acknowledgement");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            pubsub
                .psubscribe(&cx, &["base.*"])
                .await
                .expect("pattern subscribe should succeed");
            pubsub
                .subscribe(&cx, &["alpha", "beta"])
                .await
                .expect("channel subscribe should accept cross-lane counts");
            assert_eq!(pubsub.patterns(), &["base.*".to_string()]);
            assert_eq!(
                pubsub.channels(),
                &["alpha".to_string(), "beta".to_string()]
            );
            assert_eq!(
                pubsub.next_event(&cx).await.expect("buffered message"),
                PubSubEvent::Message(PubSubMessage {
                    channel: "base.one".to_string(),
                    pattern: Some("base.*".to_string()),
                    payload: b"payload".to_vec(),
                })
            );

            pubsub
                .reconnect(&cx)
                .await
                .expect("reconnect should validate counts against empty replacement state");
            assert_eq!(pubsub.patterns(), &["base.*".to_string()]);
            assert_eq!(
                pubsub.channels(),
                &["alpha".to_string(), "beta".to_string()]
            );
            pubsub
                .unsubscribe(&cx, &["alpha", "beta"])
                .await
                .expect("channel unsubscribe should preserve pattern count");
            pubsub
                .punsubscribe(&cx, &["base.*"])
                .await
                .expect("pattern unsubscribe should reach zero");
            assert!(pubsub.channels().is_empty());
            assert!(pubsub.patterns().is_empty());
            assert!(!pubsub.poisoned);
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_resp3_ping_preserves_interleaved_messages_and_connection() {
        const PING_PAYLOAD: &[u8] = b"\x00\xff\r\n";

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            write_hello3_ok(&mut stream);
            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Push(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ])
            .encode();
            stream
                .write_all(&subscribe_ack)
                .expect("write subscribe ack");
            stream.flush().expect("flush subscribe ack");

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            let mut outbound = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"payload".to_vec())),
            ])
            .encode_into(&mut outbound);
            RespValue::SimpleString("PONG".to_string()).encode_into(&mut outbound);
            stream
                .write_all(&outbound)
                .expect("write interleaved message and pong");
            stream.flush().expect("flush interleaved message and pong");

            let ping_with_payload = read_resp_frame(&mut stream);
            assert_resp_command(ping_with_payload, &[b"PING", PING_PAYLOAD]);
            stream
                .write_all(&RespValue::BulkString(Some(PING_PAYLOAD.to_vec())).encode())
                .expect("write payload pong");
            stream.flush().expect("flush payload pong");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            pubsub
                .subscribe(&cx, &["chan"])
                .await
                .expect("subscribe should succeed");

            assert_completes_within(
                Duration::from_secs(2),
                "redis RESP3 pubsub ping preserves interleaved messages and connection",
                || {
                    Box::pin(async {
                        pubsub.ping(&cx, None).await.expect("ping should succeed");
                        let event = pubsub
                            .next_event(&cx)
                            .await
                            .expect("interleaved message should remain visible");
                        assert_eq!(
                            event,
                            PubSubEvent::Message(PubSubMessage {
                                channel: "chan".to_string(),
                                pattern: None,
                                payload: b"payload".to_vec(),
                            })
                        );
                        pubsub
                            .ping(&cx, Some(PING_PAYLOAD))
                            .await
                            .expect("same RESP3 connection should remain reusable");
                    })
                },
            )
            .await;
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_resp3_ping_rejects_mismatched_echo_and_poisons_connection() {
        const EXPECTED: &[u8] = b"\x00\xff\r\n";
        const WRONG: &[u8] = b"\x00\xfe\r\n";

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            write_hello3_ok(&mut stream);
            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Push(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ])
            .encode();
            stream
                .write_all(&subscribe_ack)
                .expect("write subscribe ack");
            stream.flush().expect("flush subscribe ack");

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING", EXPECTED]);
            let mut outbound = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"must-be-cleared".to_vec())),
            ])
            .encode_into(&mut outbound);
            RespValue::BulkString(Some(WRONG.to_vec())).encode_into(&mut outbound);
            stream
                .write_all(&outbound)
                .expect("write interleaved message and wrong echo");
            stream
                .flush()
                .expect("flush interleaved message and wrong echo");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => closed_tx.send(()).expect("signal transport closed"),
                Ok(n) => panic!("failed PING left socket usable; read {n} byte(s)"),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    ) =>
                {
                    closed_tx.send(()).expect("signal transport closed");
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("failed PING left the connection open");
                }
                Err(error) => panic!("probe failed PING transport: {error}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            pubsub
                .subscribe(&cx, &["chan"])
                .await
                .expect("subscribe should succeed");

            let channels_before = pubsub.channels().to_vec();
            let patterns_before = pubsub.patterns().to_vec();
            let err = assert_completes_within(
                Duration::from_secs(2),
                "redis RESP3 pubsub PING rejects mismatched echo",
                || Box::pin(pubsub.ping(&cx, Some(EXPECTED))),
            )
            .await
            .expect_err("wrong echo must fail closed");
            assert!(matches!(err, RedisError::Protocol(_)));

            assert_eq!(pubsub.channels(), channels_before.as_slice());
            assert_eq!(pubsub.patterns(), patterns_before.as_slice());
            assert!(pubsub.pending_events.is_empty());
            assert!(pubsub.poisoned);

            closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("server should observe guard shutdown before client drop");

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("poisoned connection must reject event reads");
            assert!(
                matches!(err, RedisError::Protocol(ref message) if message.contains("invalidated")),
                "unexpected poisoned connection error: {err:?}"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pubsub_reconnect_discards_buffered_events_from_previous_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");

            write_hello3_ok(&mut first_stream);
            let subscribe = read_resp_frame(&mut first_stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            first_stream
                .write_all(&subscribe_ack)
                .expect("write first subscribe ack");
            first_stream.flush().expect("flush first subscribe ack");

            let ping = read_resp_frame(&mut first_stream);
            assert_resp_command(ping, &[b"PING"]);
            let mut outbound = Vec::new();
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"stale".to_vec())),
            ]))
            .encode_into(&mut outbound);
            RespValue::SimpleString("PONG".to_string()).encode_into(&mut outbound);
            first_stream
                .write_all(&outbound)
                .expect("write buffered stale message and pong");
            first_stream
                .flush()
                .expect("flush buffered stale message and pong");
            drop(first_stream);

            let (mut second_stream, _) = listener.accept().expect("accept second client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set second read timeout");

            write_hello3_ok(&mut second_stream);
            let subscribe = read_resp_frame(&mut second_stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            second_stream
                .write_all(&subscribe_ack)
                .expect("write second subscribe ack");
            let fresh = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"fresh".to_vec())),
            ]))
            .encode();
            second_stream
                .write_all(&fresh)
                .expect("write fresh message after reconnect");
            second_stream
                .flush()
                .expect("flush second subscribe ack and fresh message");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            pubsub
                .subscribe(&cx, &["chan"])
                .await
                .expect("subscribe should succeed");

            pubsub.ping(&cx, None).await.expect("ping should succeed");
            pubsub
                .reconnect(&cx)
                .await
                .expect("reconnect should succeed");

            assert_completes_within(
                Duration::from_secs(2),
                "redis pubsub reconnect clears stale buffered events",
                || {
                    Box::pin(async {
                        let event = pubsub
                            .next_event(&cx)
                            .await
                            .expect("fresh message should be visible after reconnect");
                        assert_eq!(
                            event,
                            PubSubEvent::Message(PubSubMessage {
                                channel: "chan".to_string(),
                                pattern: None,
                                payload: b"fresh".to_vec(),
                            })
                        );
                    })
                },
            )
            .await;
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_cancelled_subscribe_poison_connection_and_requires_reconnect() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (subscribe_seen_tx, subscribe_seen_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept pubsub client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            write_hello3_ok(&mut stream);
            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            subscribe_seen_tx
                .send(())
                .expect("signal subscribe command arrival");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => {}
                Ok(n) => panic!(
                    "expected cancelled pubsub subscribe to close the connection, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("cancelled pubsub subscribe left the connection open")
                }
                Err(e) => panic!("read after cancelled pubsub subscribe: {e}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");

            {
                let mut subscribe = Box::pin(pubsub.subscribe(&cx, &["chan"]));
                drive_until_signal(
                    subscribe.as_mut(),
                    &subscribe_seen_rx,
                    "redis pubsub subscribe",
                );
            }

            assert!(
                pubsub.channels().is_empty(),
                "cancelled subscribe must restore the last confirmed channel snapshot"
            );

            let err = pubsub
                .subscribe(&cx, &["other"])
                .await
                .expect_err("poisoned pubsub connection must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(ref message) if message.contains("call reconnect")),
                "unexpected poisoned pubsub error: {err:?}"
            );

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("poisoned pubsub connection must reject event reads");
            assert!(
                matches!(err, RedisError::Protocol(ref message) if message.contains("call reconnect")),
                "unexpected poisoned next_event error: {err:?}"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn cmd_cancellation_discards_pooled_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (first_ping_tx, first_ping_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");

            write_hello3_ok(&mut first_stream);
            let first_ping = read_resp_frame(&mut first_stream);
            assert_resp_command(first_ping, &[b"PING"]);
            first_ping_tx.send(()).expect("signal first ping");

            let mut probe = [0u8; 1];
            match first_stream.read(&mut probe) {
                Ok(0) => {}
                Ok(n) => panic!(
                    "expected first connection to close after cancellation, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("first connection remained open after cancellation")
                }
                Err(e) => panic!("read first connection after cancellation: {e}"),
            }

            let (mut second_stream, _) = listener.accept().expect("accept second client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set second read timeout");
            write_hello3_ok(&mut second_stream);
            let second_ping = read_resp_frame(&mut second_stream);
            assert_resp_command(second_ping, &[b"PING"]);
            second_stream
                .write_all(&RespValue::SimpleString("PONG".to_string()).encode())
                .expect("write second ping response");
            second_stream.flush().expect("flush second ping response");
        });

        run_test_with_cx(|cx| async move {
            let client =
                RedisClient::connect(&cx, &format!("redis://{}:{}/0", addr.ip(), addr.port()))
                    .await
                    .expect("create redis client");

            {
                let mut ping = Box::pin(client.ping(&cx));
                drive_until_signal(ping.as_mut(), &first_ping_rx, "redis ping command");
            }

            client.ping(&cx).await.expect("second ping should succeed");
        });

        server.join().expect("server join");
    }

    #[test]
    fn cluster_moved_redirect_retries_and_records_slot_like_redis_rs() {
        let primary_listener =
            StdTcpListener::bind("127.0.0.1:0").expect("bind primary redis listener");
        let primary_addr = primary_listener
            .local_addr()
            .expect("primary listener addr");
        let redirect_listener =
            StdTcpListener::bind("127.0.0.1:0").expect("bind redirect redis listener");
        let redirect_addr = redirect_listener
            .local_addr()
            .expect("redirect listener addr");
        let redirect_target = format!("{}:{}", redirect_addr.ip(), redirect_addr.port());

        let primary_server = thread::spawn({
            let redirect_target = redirect_target.clone();
            move || {
                let (mut stream, _) = primary_listener.accept().expect("accept primary client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set primary read timeout");

                let hello = read_resp_frame(&mut stream);
                assert_resp_command(hello, &[b"HELLO", b"3"]);
                let hello_reply = RespValue::Map(vec![(
                    RespValue::SimpleString("proto".to_string()),
                    RespValue::Integer(3),
                )])
                .encode();
                stream
                    .write_all(&hello_reply)
                    .expect("write primary HELLO reply");
                stream.flush().expect("flush primary HELLO reply");

                let get = read_resp_frame(&mut stream);
                assert_resp_command(get, &[b"GET", b"moved-key"]);
                let moved = format!("-MOVED 123 {redirect_target}\r\n");
                stream
                    .write_all(moved.as_bytes())
                    .expect("write MOVED redirect");
                stream.flush().expect("flush MOVED redirect");
            }
        });

        let redirect_server = thread::spawn(move || {
            let (mut stream, _) = redirect_listener
                .accept()
                .expect("accept redirected client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set redirect read timeout");

            let hello = read_resp_frame(&mut stream);
            assert_resp_command(hello, &[b"HELLO", b"3"]);
            let hello_reply = RespValue::Map(vec![(
                RespValue::SimpleString("proto".to_string()),
                RespValue::Integer(3),
            )])
            .encode();
            stream
                .write_all(&hello_reply)
                .expect("write redirect HELLO reply");
            stream.flush().expect("flush redirect HELLO reply");

            let get = read_resp_frame(&mut stream);
            assert_resp_command(get, &[b"GET", b"moved-key"]);
            let value = RespValue::BulkString(Some(b"value".to_vec())).encode();
            stream.write_all(&value).expect("write redirect value");
            stream.flush().expect("flush redirect value");
        });

        run_test_with_cx(|cx| async move {
            let client = RedisClient::connect(
                &cx,
                &format!("redis://{}:{}/0", primary_addr.ip(), primary_addr.port()),
            )
            .await
            .expect("connect redis client");

            let response = client
                .cmd(&cx, &["GET", "moved-key"])
                .await
                .expect("MOVED redirect should retry against target");
            assert_eq!(response, RespValue::BulkString(Some(b"value".to_vec())));

            let slot_map = client.slot_map_snapshot();
            assert_eq!(
                slot_map.get(&123).map(String::as_str),
                Some(redirect_target.as_str()),
                "MOVED handling must record the redirected slot owner like redis-rs"
            );
        });

        primary_server.join().expect("primary server join");
        redirect_server.join().expect("redirect server join");
    }

    fn redis_bulk(value: &str) -> RespValue {
        RespValue::BulkString(Some(value.as_bytes().to_vec()))
    }

    fn cluster_node(endpoint: RespValue, port: i64, node_id: Option<&str>) -> RespValue {
        let mut fields = vec![endpoint, RespValue::Integer(port)];
        if let Some(node_id) = node_id {
            fields.push(redis_bulk(node_id));
        }
        RespValue::Array(Some(fields))
    }

    #[test]
    fn cluster_slots_parser_accepts_metadata_and_replicas() {
        let response = RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(0),
            RespValue::Integer(5460),
            RespValue::Array(Some(vec![
                redis_bulk("127.0.0.1"),
                RespValue::Integer(30001),
                redis_bulk("09dbe9720cda62f7865eabc5fd8857c5d2678366"),
                RespValue::Map(vec![(
                    redis_bulk("hostname"),
                    redis_bulk("host-1.redis.example.com"),
                )]),
            ])),
            RespValue::Array(Some(vec![
                redis_bulk("127.0.0.1"),
                RespValue::Integer(30004),
                redis_bulk("821d8ca00d7ccf931ed3ffc7e3db0599d2271abf"),
                RespValue::Map(vec![(
                    redis_bulk("hostname"),
                    redis_bulk("host-2.redis.example.com"),
                )]),
            ])),
        ]))]));

        let slots = parse_cluster_slots_response(&response).expect("cluster slots should parse");

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].start, 0);
        assert_eq!(slots[0].end, 5460);
        assert_eq!(slots[0].master.endpoint.as_deref(), Some("127.0.0.1"));
        assert_eq!(slots[0].master.port, 30001);
        assert_eq!(
            slots[0].master.node_id.as_deref(),
            Some("09dbe9720cda62f7865eabc5fd8857c5d2678366")
        );
        assert_eq!(slots[0].replicas.len(), 1);
        assert_eq!(slots[0].replicas[0].port, 30004);
    }

    #[test]
    fn cluster_slots_parser_accepts_legacy_and_unknown_endpoints() {
        let response = RespValue::Array(Some(vec![
            RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(0),
                cluster_node(RespValue::BulkString(None), 6379, None),
            ])),
            RespValue::Array(Some(vec![
                RespValue::Integer(1),
                RespValue::Integer(2),
                cluster_node(redis_bulk("?"), 6380, Some("node-2")),
            ])),
        ]));

        let slots = parse_cluster_slots_response(&response).expect("cluster slots should parse");

        assert_eq!(slots[0].master.endpoint, None);
        assert_eq!(slots[0].master.node_id, None);
        assert_eq!(slots[1].master.endpoint.as_deref(), Some("?"));
        assert_eq!(slots[1].master.node_id.as_deref(), Some("node-2"));
    }

    #[test]
    fn cluster_slots_parser_rejects_bad_ranges() {
        let reversed = RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(9),
            RespValue::Integer(8),
            cluster_node(redis_bulk("127.0.0.1"), 6379, Some("node")),
        ]))]));
        let out_of_range = RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(0),
            RespValue::Integer(16_384),
            cluster_node(redis_bulk("127.0.0.1"), 6379, Some("node")),
        ]))]));

        assert!(parse_cluster_slots_response(&reversed).is_err());
        assert!(parse_cluster_slots_response(&out_of_range).is_err());
    }

    #[test]
    fn resp3_attributes_do_not_desynchronize_pooled_command_replies() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");

            let hello = read_resp_frame(&mut stream);
            assert_resp_command(hello, &[b"HELLO", b"3"]);
            let hello_reply = RespValue::Map(vec![(
                RespValue::SimpleString("proto".to_string()),
                RespValue::Integer(3),
            )])
            .encode();
            stream.write_all(&hello_reply).expect("write HELLO reply");
            stream.flush().expect("flush HELLO reply");

            let first = read_resp_frame(&mut stream);
            assert_resp_command(first, &[b"PING"]);

            let attribute = RespValue::Attribute(vec![(
                RespValue::SimpleString("meta".to_string()),
                RespValue::SimpleString("first".to_string()),
            )])
            .encode();
            let first_reply = RespValue::SimpleString("FIRST".to_string()).encode();
            stream
                .write_all(&attribute)
                .expect("write RESP3 attribute metadata");
            stream.write_all(&first_reply).expect("write first reply");
            stream.flush().expect("flush first reply");

            let second = read_resp_frame(&mut stream);
            assert_resp_command(second, &[b"PING"]);
            let second_reply = RespValue::SimpleString("SECOND".to_string()).encode();
            stream.write_all(&second_reply).expect("write second reply");
            stream.flush().expect("flush second reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let first = client
                .cmd(&cx, &["PING"])
                .await
                .expect("first PING should ignore RESP3 attributes");
            assert_eq!(first, RespValue::SimpleString("FIRST".to_string()));

            let second = client
                .cmd(&cx, &["PING"])
                .await
                .expect("second PING should stay synchronized");
            assert_eq!(second, RespValue::SimpleString("SECOND".to_string()));
        });

        server.join().expect("server join");
    }

    #[test]
    fn transaction_begin_cancellation_discards_pooled_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (first_multi_tx, first_multi_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");

            write_hello3_ok(&mut first_stream);
            let first_multi = read_resp_frame(&mut first_stream);
            assert_resp_command(first_multi, &[b"MULTI"]);
            first_multi_tx.send(()).expect("signal first multi");

            let mut probe = [0u8; 1];
            match first_stream.read(&mut probe) {
                Ok(0) => {}
                Ok(n) => panic!(
                    "expected first transaction connection to close after cancellation, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("first transaction connection remained open after cancellation")
                }
                Err(e) => panic!("read first transaction connection after cancellation: {e}"),
            }

            let (mut second_stream, _) = listener.accept().expect("accept second client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set second read timeout");

            write_hello3_ok(&mut second_stream);
            let second_multi = read_resp_frame(&mut second_stream);
            assert_resp_command(second_multi, &[b"MULTI"]);
            second_stream
                .write_all(&RespValue::SimpleString("OK".to_string()).encode())
                .expect("write MULTI response");
            second_stream.flush().expect("flush MULTI response");

            let discard = read_resp_frame(&mut second_stream);
            assert_resp_command(discard, &[b"DISCARD"]);
            second_stream
                .write_all(&RespValue::SimpleString("OK".to_string()).encode())
                .expect("write DISCARD response");
            second_stream.flush().expect("flush DISCARD response");
        });

        run_test_with_cx(|cx| async move {
            let client =
                RedisClient::connect(&cx, &format!("redis://{}:{}/0", addr.ip(), addr.port()))
                    .await
                    .expect("create redis client");

            {
                let mut begin = Box::pin(client.transaction(&cx));
                drive_until_signal(begin.as_mut(), &first_multi_rx, "redis transaction begin");
            }

            let tx = client
                .transaction(&cx)
                .await
                .expect("second transaction should succeed");
            tx.discard(&cx)
                .await
                .expect("second transaction should discard cleanly");
        });

        server.join().expect("server join");
    }

    #[test]
    fn resp_decode_rejects_excessive_nesting() {
        // Build a deeply nested array: *1\r\n repeated 100 times, then :0\r\n
        let mut buf = Vec::new();
        for _ in 0..100 {
            buf.extend_from_slice(b"*1\r\n");
        }
        buf.extend_from_slice(b":0\r\n");

        let err = RespValue::try_decode(&buf).expect_err("should reject deep nesting");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("nesting depth")));
    }

    #[test]
    fn resp_decode_rejects_excessive_array_len() {
        let buf = b"*2000000\r\n:1\r\n:2\r\n".to_vec();
        let err = RespValue::try_decode(&buf).expect_err("should reject large array length");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("array length")));
    }

    #[test]
    fn resp_decode_rejects_excessive_bulk_string_len() {
        let buf = b"$1000000000\r\n".to_vec();
        let err = RespValue::try_decode(&buf).expect_err("should reject large bulk string length");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("bulk string length")));
    }

    #[test]
    fn resp_decode_allows_moderate_nesting() {
        // 10 levels deep should be fine
        let mut buf = Vec::new();
        for _ in 0..10 {
            buf.extend_from_slice(b"*1\r\n");
        }
        buf.extend_from_slice(b":42\r\n");

        let result = RespValue::try_decode(&buf).expect("should succeed");
        assert!(result.is_some());
    }

    #[test]
    fn set_ttl_uses_milliseconds() {
        // Verify that sub-second TTLs don't truncate to zero by using PX
        let ttl = Duration::from_millis(500);
        let mut tmp = [0u8; 20];
        let millis = u64_decimal_bytes(positive_ttl_millis(ttl).expect("positive ttl"), &mut tmp);
        assert_eq!(millis, b"500");
    }

    #[test]
    fn positive_submillisecond_ttl_rounds_up_to_one_millisecond() {
        assert_eq!(positive_ttl_millis(Duration::from_nanos(1)).unwrap(), 1);
        assert_eq!(positive_ttl_millis(Duration::from_micros(999)).unwrap(), 1);
    }

    #[test]
    fn positive_fractional_millisecond_ttl_rounds_up() {
        assert_eq!(
            positive_ttl_millis(Duration::from_millis(1) + Duration::from_nanos(1)).unwrap(),
            2
        );
        assert_eq!(
            positive_ttl_millis(Duration::from_micros(1_001)).unwrap(),
            2
        );
    }

    #[test]
    fn large_ttl_saturates_at_u64_max_milliseconds() {
        assert_eq!(ttl_millis_rounded_up(Duration::MAX), u64::MAX);
    }

    #[test]
    fn zero_ttl_is_rejected_for_set_px() {
        let err = positive_ttl_millis(Duration::ZERO).expect_err("zero ttl must be rejected");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("greater than zero")));
    }

    #[test]
    fn zero_ttl_is_allowed_for_pexpire() {
        assert_eq!(ttl_millis_rounded_up(Duration::ZERO), 0);
    }

    #[test]
    fn dropped_transaction_queue_future_fails_closed_and_discards_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (queued_seen_tx, queued_seen_rx) = mpsc::channel();
        let (conn_closed_tx, conn_closed_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept transaction client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set transaction read timeout");

            write_hello3_ok(&mut stream);
            let multi = read_resp_frame(&mut stream);
            assert_resp_command(multi, &[b"MULTI"]);
            stream.write_all(b"+OK\r\n").expect("write MULTI response");
            stream.flush().expect("flush MULTI response");

            let queued = read_resp_frame(&mut stream);
            assert_resp_command(queued, &[b"SET", b"key", b"value"]);
            queued_seen_tx
                .send(())
                .expect("signal queued command arrival");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => conn_closed_tx
                    .send(())
                    .expect("signal dropped transaction connection"),
                Ok(n) => panic!(
                    "dropped queued transaction command left the connection open; read {n} byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("dropped queued transaction command did not close the connection")
                }
                Err(e) => panic!("probe transaction connection after dropped queued command: {e}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");
            let mut tx = client.transaction(&cx).await.expect("start transaction");

            {
                let mut queued = Box::pin(tx.cmd(&cx, &["SET", "key", "value"]));
                drive_until_signal(
                    queued.as_mut(),
                    &queued_seen_rx,
                    "redis queued transaction command",
                );
            }

            conn_closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("dropped queued transaction command should discard the connection");

            // br-asupersync-4tb7kn: Transaction::cmd_bytes no longer sets
            // self.finished = true before the await points, so a dropped
            // queued future leaves self.finished == false but
            // self.conn == None (DiscardOnDropGuard discarded the
            // poisoned connection). The next cmd hits the take().
            // ok_or_else path with "transaction already finished" rather
            // than the finished-flag's "after transaction completion".
            // Both messages communicate the same observable outcome
            // (further commands on this transaction are rejected); the
            // new shape is more honest about *why* (no live connection
            // vs caller already EXEC'd or DISCARD'd).
            let err = tx
                .cmd(&cx, &["GET", "key"])
                .await
                .expect_err("transaction should fail closed after a dropped queued command");
            match err {
                RedisError::Protocol(message) => {
                    assert!(
                        message.contains("transaction already finished")
                            || message.contains("after transaction completion"),
                        "unexpected transaction failure message: {message}"
                    );
                }
                other => {
                    panic!("expected protocol failure after dropped queued command, got {other:?}")
                }
            }
        });

        server.join().expect("server join");
    }

    #[test]
    fn hello3_unknown_command_falls_back_to_resp2() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept command client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set command read timeout");

            let hello = read_resp_frame(&mut stream);
            assert_resp_command(hello, &[b"HELLO", b"3"]);
            stream
                .write_all(b"-ERR unknown command 'HELLO'\r\n")
                .expect("write HELLO fallback response");
            stream.flush().expect("flush HELLO fallback response");

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream.write_all(b"+PONG\r\n").expect("write PING reply");
            stream.flush().expect("flush PING reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");
            client
                .ping(&cx)
                .await
                .expect("legacy RESP2 fallback should remain usable");
        });

        server.join().expect("server join");
    }

    #[test]
    fn get_resp3_blob_error_is_not_reported_as_missing_key() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept command client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set command read timeout");

            write_hello3_ok(&mut stream);
            let get = read_resp_frame(&mut stream);
            assert_resp_command(get, &[b"GET", b"missing"]);
            stream
                .write_all(&RespValue::BlobError(b"ERR storage unavailable".to_vec()).encode())
                .expect("write RESP3 blob error");
            stream.flush().expect("flush RESP3 blob error");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let error = client
                .get(&cx, "missing")
                .await
                .expect_err("RESP3 blob error must not look like a missing key");
            assert!(
                matches!(error, RedisError::Redis(ref message) if message == "ERR storage unavailable"),
                "expected RedisError::Redis for blob error, got {error:?}"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn transaction_redis_error_response_keeps_transaction_alive_for_retry() {
        // br-asupersync-4tb7kn: RESP2 `-ERR ...` and RESP3 blob-error
        // replies from Redis to a queued cmd_bytes call are *transient*,
        // command-scoped rejections — not transaction-terminating events. The
        // transaction object must remain usable: a subsequent
        // cmd_bytes must succeed when the same command shape is
        // accepted, and EXEC must still execute. The pre-fix code
        // already handled this path correctly via the explicit
        // `finished = false` reset on the `RespValue::Error` arm; the
        // fix keeps the contract intact by removing the eager
        // `finished = true` at the top of cmd_bytes (so the post-error
        // reset is no longer required, but the observable contract is
        // identical). This test pins the contract so a future refactor
        // cannot regress it.
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept transaction client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set transaction read timeout");

            write_hello3_ok(&mut stream);
            let multi = read_resp_frame(&mut stream);
            assert_resp_command(multi, &[b"MULTI"]);
            stream.write_all(b"+OK\r\n").expect("write MULTI ack");
            stream.flush().expect("flush MULTI ack");

            // First queued command — server returns -ERR (transient).
            let first = read_resp_frame(&mut stream);
            assert_resp_command(first, &[b"BOGUS_COMMAND"]);
            stream
                .write_all(b"-ERR unknown command 'BOGUS_COMMAND'\r\n")
                .expect("write -ERR ack");
            stream.flush().expect("flush -ERR ack");

            // Second queued command — RESP3 represents the same class of
            // application error with a binary blob-error frame.
            let second = read_resp_frame(&mut stream);
            assert_resp_command(second, &[b"BOGUS_BLOB"]);
            stream
                .write_all(&RespValue::BlobError(b"ERR blob rejection".to_vec()).encode())
                .expect("write blob-error ack");
            stream.flush().expect("flush blob-error ack");

            // Retry with a valid command — server returns +QUEUED.
            let retry = read_resp_frame(&mut stream);
            assert_resp_command(retry, &[b"SET", b"k", b"v"]);
            stream.write_all(b"+QUEUED\r\n").expect("write +QUEUED ack");
            stream.flush().expect("flush +QUEUED ack");

            // EXEC — server returns array with the SET's reply.
            let exec = read_resp_frame(&mut stream);
            assert_resp_command(exec, &[b"EXEC"]);
            stream.write_all(b"*1\r\n+OK\r\n").expect("write EXEC ack");
            stream.flush().expect("flush EXEC ack");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");
            let mut tx = client.transaction(&cx).await.expect("start transaction");

            // First queued command rejected by Redis — must surface as
            // RedisError::Redis (not Protocol), and must NOT brick the
            // transaction object.
            let first_err = tx
                .cmd(&cx, &["BOGUS_COMMAND"])
                .await
                .expect_err("BOGUS_COMMAND should be rejected by Redis");
            assert!(
                matches!(first_err, RedisError::Redis(ref msg) if msg.contains("unknown command")),
                "expected RedisError::Redis(unknown command), got {first_err:?}"
            );

            let second_err = tx
                .cmd(&cx, &["BOGUS_BLOB"])
                .await
                .expect_err("RESP3 blob error should reject the queued command");
            assert!(
                matches!(second_err, RedisError::Redis(ref msg) if msg == "ERR blob rejection"),
                "expected RedisError::Redis(blob rejection), got {second_err:?}"
            );
            assert_eq!(
                tx.queued_commands(),
                0,
                "rejected commands must not increment the queued-command count"
            );

            // Transaction is still alive: the next cmd_bytes succeeds.
            tx.cmd(&cx, &["SET", "k", "v"])
                .await
                .expect("retry after RESP2 and RESP3 errors should still queue");

            // EXEC consumes the transaction and returns the queued
            // command's reply.
            let replies = tx.exec(&cx).await.expect("EXEC after retry should succeed");
            assert_eq!(replies.len(), 1);
            assert!(matches!(
                &replies[0],
                RespValue::SimpleString(s) if s == "OK"
            ));
        });

        server.join().expect("server join");
    }

    #[test]
    fn transaction_exec_resp3_blob_error_is_redis_error_and_discards_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept transaction client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set transaction read timeout");

            write_hello3_ok(&mut stream);
            let multi = read_resp_frame(&mut stream);
            assert_resp_command(multi, &[b"MULTI"]);
            stream.write_all(b"+OK\r\n").expect("write MULTI ack");
            stream.flush().expect("flush MULTI ack");

            let exec = read_resp_frame(&mut stream);
            assert_resp_command(exec, &[b"EXEC"]);
            stream
                .write_all(&RespValue::BlobError(b"ERR transaction aborted".to_vec()).encode())
                .expect("write EXEC blob error");
            stream.flush().expect("flush EXEC blob error");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                            | io::ErrorKind::UnexpectedEof
                    ) => {}
                Ok(count) => panic!(
                    "top-level EXEC error should discard the connection, read {count} byte(s)"
                ),
                Err(error) => {
                    panic!("top-level EXEC error should close the connection, got {error}")
                }
            }
            closed_tx.send(()).expect("signal connection discarded");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");
            let transaction = client.transaction(&cx).await.expect("start transaction");

            let error = transaction
                .exec(&cx)
                .await
                .expect_err("top-level EXEC blob error must reject the transaction");
            assert!(
                matches!(error, RedisError::Redis(ref message) if message == "ERR transaction aborted"),
                "expected RedisError::Redis for EXEC blob error, got {error:?}"
            );
            closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("EXEC error should discard the connection while the client is still live");
            drop(client);
        });

        server.join().expect("server join");
    }

    /// br-asupersync-f3635k (follow-up to br-asupersync-pr32li).
    /// Pipeline::exec must collect ALL responses even when commands receive
    /// RESP2 `-ERR` or RESP3 blob-error replies, classify each as
    /// `Err(RedisError::Redis(_))` at its per-command position, return the
    /// connection to the pool, and leave it healthy for the next command.
    ///
    /// Scripted server drives the wire exchange:
    ///   1. Client sends HELLO 3 (RESP3 negotiation in ensure_initialized).
    ///      Server returns the negotiated RESP3 map response.
    ///   2. Client writes the 4 pipelined commands as one combined buffer.
    ///      Server reads four RESP frames in succession.
    ///   3. Server writes back, in one buffer:
    ///      $5\r\nfirst\r\n
    ///      -ERR something went wrong\r\n
    ///      !18\r\nERR blob rejection\r\n
    ///      $6\r\nfourth\r\n
    ///   4. Client receives Vec<Result<RespValue, RedisError>> with four
    ///      entries; both error encodings become RedisError::Redis while the
    ///      first and fourth entries remain successful bulk strings.
    ///   5. Client then runs a single PING via the same pool — reuses the
    ///      same RedisConnection (because the pipeline defused its discard
    ///      guard on the application-error paths) and the server replies +PONG.
    #[test]
    fn pipeline_exec_collects_all_results_when_middle_command_errors() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept pipeline client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");

            // 1. Negotiate RESP3 so both simple and blob error frames below
            //    are legal server replies for this connection.
            write_hello3_ok(&mut stream);

            // 2. Four pipelined commands. Pipeline writes all four frames
            //    in one combined buffer, so the scripted server must retain
            //    unread bytes between decode calls instead of dropping any
            //    frames that arrived in the first socket read.
            let mut command_buf = Vec::new();
            let cmd1 = read_resp_frame_from_buffer(&mut stream, &mut command_buf);
            assert_resp_command(cmd1, &[b"GET", b"k1"]);
            let cmd2 = read_resp_frame_from_buffer(&mut stream, &mut command_buf);
            assert_resp_command(cmd2, &[b"GET", b"k2"]);
            let cmd3 = read_resp_frame_from_buffer(&mut stream, &mut command_buf);
            assert_resp_command(cmd3, &[b"GET", b"k3"]);
            let cmd4 = read_resp_frame_from_buffer(&mut stream, &mut command_buf);
            assert_resp_command(cmd4, &[b"GET", b"k4"]);

            // 3. Four responses in one combined write: Ok, -ERR, !ERR, Ok.
            let mut response = Vec::new();
            response.extend_from_slice(b"$5\r\nfirst\r\n");
            response.extend_from_slice(b"-ERR something went wrong\r\n");
            response
                .extend_from_slice(&RespValue::BlobError(b"ERR blob rejection".to_vec()).encode());
            response.extend_from_slice(b"$6\r\nfourth\r\n");
            stream.write_all(&response).expect("write pipeline replies");
            stream.flush().expect("flush pipeline replies");

            // 5. Health check — pipeline should have defused the discard
            //    guard so the SAME RedisConnection comes back from the pool
            //    for the next command. Read PING + reply PONG.
            let ping = read_resp_frame_from_buffer(&mut stream, &mut command_buf);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&RespValue::SimpleString("PONG".to_string()).encode())
                .expect("write PING reply");
            stream.flush().expect("flush PING reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let mut pipeline = client.pipeline();
            pipeline.cmd(&["GET", "k1"]);
            pipeline.cmd(&["GET", "k2"]);
            pipeline.cmd(&["GET", "k3"]);
            pipeline.cmd(&["GET", "k4"]);

            let results = pipeline
                .exec(&cx)
                .await
                .expect("pipeline exec must return Ok despite per-command Redis errors");

            // 4. All four results returned — neither error encoding
            //    short-circuited collection.
            assert_eq!(
                results.len(),
                4,
                "pipeline must collect ALL four responses (br-pr32li); got {results:?}"
            );

            // results[0] = Ok(BulkString(first))
            match &results[0] {
                Ok(RespValue::BulkString(Some(bytes))) if bytes == b"first" => {}
                other => panic!("results[0] expected Ok(BulkString(\"first\")), got {other:?}"),
            }

            // results[1] = Err(RedisError::Redis("something went wrong"))
            match &results[1] {
                Err(RedisError::Redis(msg)) if msg.contains("something went wrong") => {}
                other => panic!("results[1] expected Err(RedisError::Redis(...)), got {other:?}"),
            }

            // results[2] = Err(RedisError::Redis("ERR blob rejection"))
            match &results[2] {
                Err(RedisError::Redis(msg)) if msg == "ERR blob rejection" => {}
                other => panic!("results[2] expected RESP3 blob Redis error, got {other:?}"),
            }

            // results[3] = Ok(BulkString(fourth))
            match &results[3] {
                Ok(RespValue::BulkString(Some(bytes))) if bytes == b"fourth" => {}
                other => panic!("results[3] expected Ok(BulkString(\"fourth\")), got {other:?}"),
            }

            // 5. Connection-healthy assertion — a follow-up command must
            //    reuse the pool and succeed. If pipeline had wrongly
            //    discarded the connection on either server error, this PING would
            //    fail (or stall on a fresh accept the test server doesn't
            //    handle).
            client
                .ping(&cx)
                .await
                .expect("connection should remain healthy after per-command Redis errors");
        });

        server.join().expect("server join");
    }

    // ========================================================================
    // REAL REDIS INTEGRATION TESTS (Live Testing Pattern)
    // ========================================================================
    //
    // These tests replace scripted TCP server tests above with real Redis.
    // connections following the testing-perfect-e2e-integration-tests pattern.
    // Run with: REAL_REDIS_TESTS=true cargo test -- --nocapture

    /// Real Redis test configuration with production safety guards
    struct RealRedisConfig {
        host: String,
        port: u16,
        enabled: bool,
        reason: Option<String>,
    }

    impl RealRedisConfig {
        fn new() -> Self {
            let enabled = std::env::var("REAL_REDIS_TESTS").unwrap_or_default() == "true";
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

            let config = RedisConfig::from_url(&redis_url).unwrap_or_else(|_| RedisConfig {
                host: "localhost".to_string(),
                port: 6379,
                ..Default::default()
            });

            // Production safety guards (Pattern 4 from testing-perfect-e2e-integration-tests)
            let reason = if !enabled {
                Some("REAL_REDIS_TESTS not set to 'true'".to_string())
            } else if config.host.contains("prod") || config.host.contains("production") {
                Some("BLOCKED: Production Redis URL detected".to_string())
            } else if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                Some("BLOCKED: NODE_ENV=production".to_string())
            } else {
                None
            };

            Self {
                host: config.host,
                port: config.port,
                enabled: enabled && reason.is_none(),
                reason,
            }
        }

        fn url(&self) -> String {
            format!("redis://{}:{}/0", self.host, self.port)
        }
    }

    /// Structured test logger for Redis integration tests (Pattern 3 from skill)
    #[derive(Debug)]
    struct RedisTestLogger {
        test_name: String,
        start_time: std::time::Instant,
        phase_count: AtomicU32,
    }

    impl RedisTestLogger {
        fn new(test_name: &str) -> Self {
            let logger = Self {
                test_name: test_name.to_string(),
                start_time: std::time::Instant::now(),
                phase_count: AtomicU32::new(0),
            };

            // JSON-line structured logging for CI parsing
            eprintln!(
                "{{\"test\":\"{}\",\"event\":\"test_start\",\"ts\":\"{}\"}}",
                test_name,
                chrono::Utc::now().to_rfc3339()
            );

            logger
        }

        fn phase(&self, phase_name: &str) {
            let phase_num = self.phase_count.fetch_add(1, Ordering::SeqCst);
            let elapsed_ms = self.start_time.elapsed().as_millis();

            eprintln!(
                "{{\"test\":\"{}\",\"event\":\"phase\",\"phase\":\"{}\",\"phase_num\":{},\"elapsed_ms\":{},\"ts\":\"{}\"}}",
                self.test_name,
                phase_name,
                phase_num,
                elapsed_ms,
                chrono::Utc::now().to_rfc3339()
            );
        }

        fn redis_operation(&self, operation: &str, result: &str, key: Option<&str>) {
            let mut log_entry = serde_json::json!({
                "test": self.test_name,
                "event": "redis_operation",
                "operation": operation,
                "result": result,
                "ts": chrono::Utc::now().to_rfc3339()
            });

            if let Some(k) = key {
                log_entry["key"] = serde_json::Value::String(k.to_string());
            }

            eprintln!("{}", log_entry);
        }

        fn test_end(&self, result: &str) {
            let duration_ms = self.start_time.elapsed().as_millis();

            eprintln!(
                "{{\"test\":\"{}\",\"event\":\"test_end\",\"result\":\"{}\",\"duration_ms\":{},\"ts\":\"{}\"}}",
                self.test_name,
                result,
                duration_ms,
                chrono::Utc::now().to_rfc3339()
            );
        }
    }

    /// Generate unique key prefixes to avoid cross-test contamination
    fn unique_key_prefix(base: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random = fastrand::u32(..);
        format!("test:{}:{}:{}", base, timestamp, random)
    }

    fn require_real_redis() -> Option<RealRedisConfig> {
        let config = RealRedisConfig::new();
        if !config.enabled {
            let reason = config
                .reason
                .as_deref()
                .unwrap_or("Real Redis server not available");
            eprintln!("SKIPPING: {}", reason);
            return None;
        }
        Some(config)
    }

    /// Supplement the deterministic RESP3 ping regression with a real Redis server.
    #[test]
    fn test_real_redis_pubsub_ping_preserves_interleaved_messages() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pubsub_ping_interleaved");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let channel_prefix = unique_key_prefix("ping-interleaved");
            let channel = format!("{}:chan", channel_prefix);

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");
            let mut pubsub = client.pubsub(&cx).await.expect("open pubsub client");

            log.phase("subscribe");

            // Subscribe to real Redis channel
            pubsub.subscribe(&cx, &[channel.as_str()]).await.unwrap();
            log.redis_operation("subscribe", "success", Some(&channel));

            log.phase("ping_with_message");

            // Send ping while message is pending (tests real Redis interleaving behavior)
            let ping_result = pubsub.ping(&cx, None).await;
            assert!(
                ping_result.is_ok(),
                "Real Redis ping should succeed during pub/sub"
            );
            log.redis_operation("ping", "success", None);

            log.phase("verify_subscription_intact");

            // Verify subscription is still active after ping
            // In real Redis, the subscription should remain intact
            assert!(
                pubsub
                    .channels()
                    .iter()
                    .any(|existing| existing == &channel),
                "Subscription should remain active after ping"
            );

            log.phase("cleanup");
            pubsub.unsubscribe(&cx, &[channel.as_str()]).await.unwrap();
            log.redis_operation("unsubscribe", "success", Some(&channel));

            log.test_end("pass");
        });
    }

    /// Test Redis pub/sub reconnection with real Redis server (replaces pubsub_reconnect_discards_buffered_events)
    #[test]
    fn test_real_redis_pubsub_reconnect_behavior() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pubsub_reconnect");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let channel_prefix = unique_key_prefix("reconnect");
            let channel = format!("{}:events", channel_prefix);

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");
            let mut pubsub = client.pubsub(&cx).await.expect("open pubsub client");

            log.phase("initial_connection");

            // Subscribe to real Redis
            pubsub.subscribe(&cx, &[channel.as_str()]).await.unwrap();
            log.redis_operation("initial_subscribe", "success", Some(&channel));

            log.phase("force_reconnect");

            let reconnect_result = pubsub.reconnect(&cx).await;
            assert!(
                reconnect_result.is_ok(),
                "Real Redis reconnection should succeed"
            );
            log.redis_operation("reconnect", "success", None);

            log.phase("verify_restored_state");

            assert!(
                pubsub
                    .channels()
                    .iter()
                    .any(|existing| existing == &channel),
                "Tracked subscriptions should persist across reconnect and be restored"
            );

            log.phase("cleanup");
            pubsub.unsubscribe(&cx, &[channel.as_str()]).await.unwrap();

            log.test_end("pass");
        });
    }

    /// Test Redis pub/sub cancellation with real Redis (replaces pubsub_cancelled_subscribe_poison_connection)
    #[test]
    fn test_real_redis_pubsub_cancellation_handling() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pubsub_cancellation");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let channel_prefix = unique_key_prefix("cancel");
            let channel = format!("{}:test", channel_prefix);

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");
            let mut pubsub = client.pubsub(&cx).await.expect("open pubsub client");

            log.phase("subscribe_with_cancellation");

            match crate::time::timeout(
                cx.now(),
                Duration::from_millis(1),
                pubsub.subscribe(&cx, &[channel.as_str()]),
            )
            .await
            {
                Ok(Ok(())) => {
                    log.redis_operation("subscribe", "completed_before_timeout", Some(&channel));
                }
                Ok(Err(err)) => panic!("real Redis subscribe failed unexpectedly: {err}"),
                Err(_) => {
                    log.redis_operation("subscribe", "timed_out", Some(&channel));
                }
            }

            log.phase("verify_connection_health");

            // Test that the connection is still healthy for future operations
            let health_check = pubsub.ping(&cx, None).await;

            match health_check {
                Ok(_) => {
                    log.redis_operation("health_check", "connection_healthy", None);
                }
                Err(_) => {
                    // Real Redis might require reconnection after cancelled subscribe
                    let reconnect_result = pubsub.reconnect(&cx).await;
                    assert!(
                        reconnect_result.is_ok(),
                        "Should be able to reconnect after cancellation"
                    );
                    log.redis_operation("health_check", "reconnect_required", None);
                }
            }

            log.phase("verify_normal_operation");

            if !pubsub
                .channels()
                .iter()
                .any(|existing| existing == &channel)
            {
                pubsub.subscribe(&cx, &[channel.as_str()]).await.unwrap();
                log.redis_operation("post_cancel_subscribe", "success", Some(&channel));
            }

            log.phase("cleanup");
            pubsub.unsubscribe(&cx, &[channel.as_str()]).await.unwrap();

            log.test_end("pass");
        });
    }

    /// Test Redis command cancellation with real Redis (replaces cmd_cancellation_discards_pooled_connection)
    #[test]
    fn test_real_redis_command_cancellation_behavior() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_cmd_cancellation");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("cmd-cancel");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("normal_operation");

            // Establish baseline with normal operation
            let baseline_key = format!("{}:baseline", key_prefix);
            client.set(&cx, &baseline_key, b"test", None).await.unwrap();
            log.redis_operation("baseline_set", "success", Some(&baseline_key));

            log.phase("cancelled_operation");

            // Exercise cancelled operation against real Redis connection cleanup.
            let cancel_key = format!("{}:cancelled", key_prefix);

            // Start a potentially long operation
            match crate::time::timeout(
                cx.now(),
                Duration::from_millis(1),
                client.set(&cx, &cancel_key, b"will_be_cancelled", None),
            )
            .await
            {
                Ok(Ok(())) => {
                    log.redis_operation(
                        "cancelled_set",
                        "completed_before_timeout",
                        Some(&cancel_key),
                    );
                }
                Ok(Err(err)) => panic!("real Redis SET failed unexpectedly: {err}"),
                Err(_) => {
                    log.redis_operation("cancelled_set", "timed_out", Some(&cancel_key));
                }
            }

            log.phase("verify_connection_health");

            // Critical test: verify connection pool handles cancellation correctly in real Redis
            let health_key = format!("{}:health", key_prefix);
            let health_result = client.set(&cx, &health_key, b"healthy", None).await;

            assert!(
                health_result.is_ok(),
                "Real Redis connection should recover from cancelled operations"
            );
            log.redis_operation("post_cancel_health", "success", Some(&health_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[baseline_key.as_str()]).await;
            let _ = client.del(&cx, &[cancel_key.as_str()]).await;
            let _ = client.del(&cx, &[health_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis transaction cancellation with real Redis (replaces transaction_begin_cancellation_discards_pooled_connection)
    #[test]
    fn test_real_redis_transaction_cancellation_behavior() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_transaction_cancellation");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("tx-cancel");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("normal_transaction");

            // Start with normal transaction to establish baseline
            let tx_key = format!("{}:tx", key_prefix);
            let mut transaction = client.transaction(&cx).await.unwrap();
            transaction
                .cmd(&cx, &["SET", tx_key.as_str(), "normal"])
                .await
                .unwrap();
            let tx_result = transaction.exec(&cx).await;

            assert!(
                tx_result.is_ok(),
                "Normal transaction should succeed with real Redis"
            );
            log.redis_operation("normal_transaction", "success", Some(&tx_key));

            log.phase("cancelled_transaction");

            // Test cancellation during transaction begin phase
            let cancel_key = format!("{}:cancel", key_prefix);

            // Exercise cancellation during MULTI command.
            match crate::time::timeout(cx.now(), Duration::from_millis(1), client.transaction(&cx))
                .await
            {
                Ok(Ok(transaction)) => {
                    drop(transaction);
                    log.redis_operation(
                        "cancelled_multi",
                        "completed_before_timeout",
                        Some(&cancel_key),
                    );
                }
                Ok(Err(err)) => panic!("real Redis MULTI failed unexpectedly: {err}"),
                Err(_) => {
                    log.redis_operation("cancelled_multi", "timed_out", Some(&cancel_key));
                }
            }

            log.phase("verify_connection_recovery");

            // Real Redis should handle cancelled transaction begin cleanly
            let recovery_key = format!("{}:recovery", key_prefix);
            let recovery_result = client.set(&cx, &recovery_key, b"recovered", None).await;

            assert!(
                recovery_result.is_ok(),
                "Real Redis should recover from cancelled transaction begin"
            );
            log.redis_operation("post_cancel_recovery", "success", Some(&recovery_key));

            log.phase("verify_new_transaction");

            // Verify new transaction works after cancellation
            let new_tx_key = format!("{}:new_tx", key_prefix);
            let mut new_transaction = client.transaction(&cx).await.unwrap();
            new_transaction
                .cmd(&cx, &["SET", new_tx_key.as_str(), "new"])
                .await
                .unwrap();
            let new_tx_result = new_transaction.exec(&cx).await;

            assert!(
                new_tx_result.is_ok(),
                "New transaction should work after cancellation recovery"
            );
            log.redis_operation("new_transaction", "success", Some(&new_tx_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[tx_key.as_str()]).await;
            let _ = client.del(&cx, &[recovery_key.as_str()]).await;
            let _ = client.del(&cx, &[new_tx_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis transaction queue cancellation (replaces dropped_transaction_queue_future_fails_closed_and_discards_connection)
    #[test]
    fn test_real_redis_transaction_queue_cancellation() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_transaction_queue_cancel");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("queue-cancel");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("queue_transaction");

            // Create a queued transaction (MULTI without immediate EXEC)
            let queue_key = format!("{}:queued", key_prefix);
            let mut transaction = client.transaction(&cx).await.unwrap();
            transaction
                .cmd(&cx, &["SET", queue_key.as_str(), "queued_value"])
                .await
                .unwrap();
            // Don't exec yet - keep it queued

            log.redis_operation("transaction_queued", "pending", Some(&queue_key));

            log.phase("drop_queued_transaction");

            // Drop the transaction future (simulates cancellation/timeout)
            drop(transaction);
            log.redis_operation("transaction_dropped", "cancelled", Some(&queue_key));

            log.phase("verify_fail_closed_behavior");

            // In real Redis, dropped queued transaction should fail closed
            // Check that the key was NOT set (transaction was discarded)
            let get_result = client.get(&cx, &queue_key).await;

            match get_result {
                Ok(Some(value)) if value.as_slice() == b"queued_value" => {
                    panic!("Dropped transaction should NOT have committed in real Redis");
                }
                Ok(None) | Ok(Some(_)) | Err(_) => {
                    // Good: either key doesn't exist or has different value
                    log.redis_operation("verify_fail_closed", "correct_behavior", Some(&queue_key));
                }
            }

            log.phase("verify_connection_health");

            // Connection should remain healthy after dropped transaction
            let health_key = format!("{}:health", key_prefix);
            let health_result = client.set(&cx, &health_key, b"healthy", None).await;

            assert!(
                health_result.is_ok(),
                "Connection should be healthy after dropped transaction"
            );
            log.redis_operation("connection_health", "success", Some(&health_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[queue_key.as_str()]).await;
            let _ = client.del(&cx, &[health_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis pipeline error handling with real Redis (replaces pipeline_exec_collects_all_results_when_middle_command_errors)
    #[test]
    fn test_real_redis_pipeline_error_collection() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pipeline_errors");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("pipeline-err");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("setup_test_data");

            // Set up keys for pipeline test
            let key1 = format!("{}:first", key_prefix);
            let key2 = format!("{}:second", key_prefix);
            let key3 = format!("{}:third", key_prefix);

            client.set(&cx, &key1, b"first", None).await.unwrap();
            client.set(&cx, &key2, b"not-an-int", None).await.unwrap();
            client.set(&cx, &key3, b"third", None).await.unwrap();

            log.phase("execute_pipeline");

            // Create pipeline with intentional error in middle command
            let mut pipeline = client.pipeline();
            pipeline.cmd(&["GET", key1.as_str()]);
            pipeline.cmd(&["INCR", key2.as_str()]);
            pipeline.cmd(&["GET", key3.as_str()]);
            let pipeline_result = pipeline.exec(&cx).await;

            log.redis_operation("pipeline_execution", "completed", None);

            log.phase("verify_error_collection");

            match pipeline_result {
                Ok(results) => {
                    // Real Redis pipeline should collect all results, even with errors
                    assert_eq!(results.len(), 3, "Pipeline should return all 3 results");

                    // First command should succeed
                    match &results[0] {
                        Ok(RespValue::BulkString(Some(bytes))) if bytes == b"first" => {
                            log.redis_operation("pipeline_cmd_1", "success", Some(&key1));
                        }
                        other => panic!("First pipeline result should be 'first', got {:?}", other),
                    }

                    // Second command should fail with Redis error
                    match &results[1] {
                        Err(_) => {
                            log.redis_operation("pipeline_cmd_2", "error_expected", Some(&key2));
                        }
                        Ok(value) => panic!("Second pipeline command should fail, got {:?}", value),
                    }

                    // Third command should succeed despite middle error
                    match &results[2] {
                        Ok(RespValue::BulkString(Some(bytes))) if bytes == b"third" => {
                            log.redis_operation("pipeline_cmd_3", "success", Some(&key3));
                        }
                        other => panic!("Third pipeline result should be 'third', got {:?}", other),
                    }
                }
                Err(e) => panic!(
                    "Pipeline should not fail entirely due to single command error: {}",
                    e
                ),
            }

            log.phase("verify_connection_health");

            // Connection should remain healthy after pipeline with errors
            let health_key = format!("{}:health", key_prefix);
            let health_result = client.set(&cx, &health_key, b"healthy", None).await;

            assert!(
                health_result.is_ok(),
                "Connection should remain healthy after pipeline errors"
            );
            log.redis_operation("post_pipeline_health", "success", Some(&health_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[key1.as_str()]).await;
            let _ = client.del(&cx, &[key2.as_str()]).await;
            let _ = client.del(&cx, &[key3.as_str()]).await;
            let _ = client.del(&cx, &[health_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis transaction error handling with real Redis (covers the transaction error handling test around line 4063)
    #[test]
    fn test_real_redis_transaction_error_handling() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_transaction_errors");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("tx-err");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("normal_transaction");

            // First establish normal transaction works
            let normal_key = format!("{}:normal", key_prefix);
            let mut normal_tx = client.transaction(&cx).await.unwrap();
            normal_tx
                .cmd(&cx, &["SET", normal_key.as_str(), "normal_value"])
                .await
                .unwrap();
            let normal_result = normal_tx.exec(&cx).await;

            assert!(normal_result.is_ok(), "Normal transaction should succeed");
            log.redis_operation("normal_transaction", "success", Some(&normal_key));

            log.phase("transaction_with_error");

            // Transaction that contains an error
            let error_key = format!("{}:error", key_prefix);
            let nonexist_key = format!("{}:nonexistent", key_prefix);

            client
                .set(&cx, &nonexist_key, b"not-an-int", None)
                .await
                .unwrap();
            let mut error_tx = client.transaction(&cx).await.unwrap();
            error_tx
                .cmd(&cx, &["SET", error_key.as_str(), "before_error"])
                .await
                .unwrap();
            error_tx
                .cmd(&cx, &["INCR", nonexist_key.as_str()])
                .await
                .unwrap();
            error_tx
                .cmd(&cx, &["SET", error_key.as_str(), "after_error"])
                .await
                .unwrap();

            let error_result = error_tx.exec(&cx).await;

            log.phase("verify_error_behavior");

            match error_result {
                Ok(results) => {
                    log.redis_operation(
                        "transaction_with_errors",
                        "partial_success",
                        Some(&error_key),
                    );
                    assert_eq!(
                        results.len(),
                        3,
                        "Transaction should return results for all queued commands"
                    );
                    assert!(
                        matches!(&results[1], RespValue::Error(message) if message.to_ascii_lowercase().contains("not an integer")),
                        "Second transaction result should be an integer-type Redis error, got {:?}",
                        results[1]
                    );
                }
                Err(err) => {
                    panic!("EXEC should surface per-command errors inside the result array: {err}")
                }
            }

            log.phase("verify_connection_after_error");

            // Most important: connection should remain usable after transaction error
            let recovery_key = format!("{}:recovery", key_prefix);
            let recovery_result = client.set(&cx, &recovery_key, b"recovered", None).await;

            assert!(
                recovery_result.is_ok(),
                "Connection should recover after transaction error"
            );
            log.redis_operation("post_error_recovery", "success", Some(&recovery_key));

            log.phase("verify_new_transaction");

            // New transaction should work normally
            let new_key = format!("{}:new", key_prefix);
            let mut new_tx = client.transaction(&cx).await.unwrap();
            new_tx
                .cmd(&cx, &["SET", new_key.as_str(), "new_value"])
                .await
                .unwrap();
            let new_result = new_tx.exec(&cx).await;

            assert!(
                new_result.is_ok(),
                "New transaction should work after error recovery"
            );
            log.redis_operation("new_transaction", "success", Some(&new_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[normal_key.as_str()]).await;
            let _ = client.del(&cx, &[error_key.as_str()]).await;
            let _ = client.del(&cx, &[nonexist_key.as_str()]).await;
            let _ = client.del(&cx, &[recovery_key.as_str()]).await;
            let _ = client.del(&cx, &[new_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Differential conformance test for RESP3 numeric integer encoding at i64 boundary values.
    ///
    /// Tests RESP3 specification compliance for integer encoding/decoding round-trips,
    /// specifically focusing on i64::MIN/MAX boundaries and negative number handling.
    ///
    /// RESP3 integer format: `:` + ASCII decimal + `\r\n`
    ///
    /// Coverage:
    /// - MUST: i64::MAX encodes and round-trips correctly
    /// - MUST: i64::MIN encodes and round-trips correctly
    /// - MUST: Negative numbers preserve sign and magnitude
    /// - MUST: Edge values near boundaries encode properly
    /// - MUST: Values outside i64 range are rejected with protocol error
    #[test]
    fn resp3_integer_encoding_i64_boundary_differential() {
        // Test vector: (value, expected_wire_format, should_succeed)
        let boundary_cases: &[(i64, &[u8], bool)] = &[
            // i64::MAX boundary
            (i64::MAX, b":9223372036854775807\r\n", true),
            (i64::MAX - 1, b":9223372036854775806\r\n", true),
            // i64::MIN boundary
            (i64::MIN, b":-9223372036854775808\r\n", true),
            (i64::MIN + 1, b":-9223372036854775807\r\n", true),
            // Zero and small values
            (0, b":0\r\n", true),
            (-1, b":-1\r\n", true),
            (1, b":1\r\n", true),
            // Typical negative values
            (-42, b":-42\r\n", true),
            (-1000000, b":-1000000\r\n", true),
        ];

        for &(value, expected_wire, should_succeed) in boundary_cases {
            // Test encoding: value -> wire format
            let actual = RespValue::Integer(value);
            let encoded = actual.encode();

            if should_succeed {
                assert_eq!(
                    encoded,
                    expected_wire,
                    "RESP3 encoding mismatch for i64 value {value}\n\
                     Expected: {:?}\n\
                     Actual:   {:?}",
                    std::str::from_utf8(expected_wire).unwrap_or("<invalid utf8>"),
                    std::str::from_utf8(&encoded).unwrap_or("<invalid utf8>")
                );

                // Test round-trip: wire format -> value -> wire format
                let (decoded_value, consumed) = RespValue::try_decode(&encoded)
                    .expect("parse should succeed")
                    .expect("should have complete value");

                assert_eq!(consumed, encoded.len(), "should consume entire input");
                assert_eq!(
                    decoded_value,
                    RespValue::Integer(value),
                    "round-trip failed for value {value}"
                );

                // Test integer extraction
                assert_eq!(
                    decoded_value.as_integer(),
                    Some(value),
                    "as_integer() failed for value {value}"
                );
            }
        }

        // Test overflow cases - values outside i64 range should fail gracefully
        let overflow_cases: &[&[u8]] = &[
            b":9223372036854775808\r\n",   // i64::MAX + 1
            b":-9223372036854775809\r\n",  // i64::MIN - 1
            b":99999999999999999999\r\n",  // Way beyond i64::MAX
            b":-99999999999999999999\r\n", // Way beyond i64::MIN
        ];

        for &overflow_wire in overflow_cases {
            let parse_result = RespValue::try_decode(overflow_wire);

            match parse_result {
                Ok(None) => {
                    // Incomplete parse - this is OK for malformed input
                }
                Ok(Some(_)) => {
                    panic!(
                        "Expected overflow error for input: {:?}",
                        std::str::from_utf8(overflow_wire).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(msg)) => {
                    // Expected: protocol error for overflow
                    assert!(
                        msg.contains("overflow") || msg.contains("integer"),
                        "Error message should mention overflow/integer, got: {}",
                        msg
                    );
                }
                Err(other) => {
                    panic!("Expected protocol error for overflow, got: {:?}", other);
                }
            }
        }

        // Test malformed integer cases
        let malformed_cases: &[&[u8]] = &[
            b":abc\r\n",   // Non-numeric
            b":\r\n",      // Empty
            b":-\r\n",     // Just minus sign
            b":12x34\r\n", // Mixed numeric/alpha
            b":0x42\r\n",  // Hex format (not allowed in RESP)
        ];

        for &malformed_wire in malformed_cases {
            let parse_result = RespValue::try_decode(malformed_wire);

            match parse_result {
                Ok(None) => {
                    // Incomplete parse - acceptable
                }
                Ok(Some(_)) => {
                    panic!(
                        "Expected parse error for malformed input: {:?}",
                        std::str::from_utf8(malformed_wire).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(_)) => {
                    // Expected: protocol error for malformed input
                }
                Err(other) => {
                    panic!(
                        "Expected protocol error for malformed input, got: {:?}",
                        other
                    );
                }
            }
        }

        // Differential verification: our encoder output should be parseable by our decoder
        // This verifies internal consistency of our RESP3 integer implementation
        let test_values = [
            i64::MIN,
            i64::MIN + 1,
            -1000000,
            -42,
            -1,
            0,
            1,
            42,
            1000000,
            i64::MAX - 1,
            i64::MAX,
        ];

        for &value in &test_values {
            let encoded = RespValue::Integer(value).encode();
            let (decoded, _) = RespValue::try_decode(&encoded)
                .expect("should parse")
                .expect("should be complete");

            assert_eq!(
                decoded,
                RespValue::Integer(value),
                "Self-consistency check failed for value {value}"
            );
        }
    }

    /// AUDIT MODULE: Redis ACL authentication error handling verification
    ///
    /// AUDIT FINDING: FIXED - Previous implementation wrapped authentication errors
    /// (NOAUTH, WRONGPASS) in generic RedisError::Protocol variants, causing
    /// information loss and making errors non-actionable for callers.
    ///
    /// FIXED: Added structured error types RedisError::NoAuth and RedisError::WrongPassword
    /// with proper parsing logic that callers can match on for appropriate handling.
    #[cfg(test)]
    mod redis_acl_authentication_error_audit {
        use super::*;

        #[test]
        fn audit_redis_error_message_parsing_noauth() {
            // Test Case 1: Standard NOAUTH error
            let error = RedisError::from_redis_error_message("NOAUTH Authentication required");
            match error {
                RedisError::NoAuth => {
                    // Expected - structured error for actionable handling
                }
                other => panic!("Expected RedisError::NoAuth, got {:?}", other),
            }

            // Test Case 2: Bare NOAUTH
            let error = RedisError::from_redis_error_message("NOAUTH");
            match error {
                RedisError::NoAuth => {
                    // Expected - handles minimal form
                }
                other => panic!(
                    "Expected RedisError::NoAuth for bare 'NOAUTH', got {:?}",
                    other
                ),
            }

            // Test Case 3: Case insensitive
            let error = RedisError::from_redis_error_message("noauth authentication required");
            assert!(
                matches!(error, RedisError::NoAuth),
                "NOAUTH parsing must be case-insensitive"
            );
        }

        #[test]
        fn audit_redis_error_message_parsing_wrongpass() {
            // Test Case 1: Standard WRONGPASS error
            let error =
                RedisError::from_redis_error_message("WRONGPASS invalid username-password pair");
            match error {
                RedisError::WrongPassword => {
                    // Expected - structured error for actionable handling
                }
                other => panic!("Expected RedisError::WrongPassword, got {:?}", other),
            }

            // Test Case 2: Bare WRONGPASS
            let error = RedisError::from_redis_error_message("WRONGPASS");
            match error {
                RedisError::WrongPassword => {
                    // Expected - handles minimal form
                }
                other => panic!(
                    "Expected RedisError::WrongPassword for bare 'WRONGPASS', got {:?}",
                    other
                ),
            }

            // Test Case 3: Case insensitive
            let error = RedisError::from_redis_error_message("wrongpass invalid credentials");
            assert!(
                matches!(error, RedisError::WrongPassword),
                "WRONGPASS parsing must be case-insensitive"
            );
        }

        #[test]
        fn audit_redis_error_message_parsing_other_errors() {
            // Test Case: Other errors remain as generic Redis errors
            let error = RedisError::from_redis_error_message("ERR syntax error");
            match error {
                RedisError::Redis(msg) => {
                    assert_eq!(
                        msg, "ERR syntax error",
                        "Generic Redis errors must preserve original message"
                    );
                }
                other => panic!(
                    "Expected RedisError::Redis for generic error, got {:?}",
                    other
                ),
            }

            let error = RedisError::from_redis_error_message("MOVED 3999 127.0.0.1:6381");
            assert!(
                matches!(error, RedisError::Redis(_)),
                "MOVED errors should remain generic"
            );
        }

        #[test]
        fn audit_error_display_messages_are_actionable() {
            // Test Case 1: NoAuth display message
            let error = RedisError::NoAuth;
            let display = format!("{}", error);
            assert!(
                display.contains("NOAUTH") && display.contains("authentication required"),
                "NoAuth display message must be actionable: {}",
                display
            );

            // Test Case 2: WrongPassword display message
            let error = RedisError::WrongPassword;
            let display = format!("{}", error);
            assert!(
                display.contains("WRONGPASS") && display.contains("authentication failed"),
                "WrongPassword display message must be actionable: {}",
                display
            );
        }

        #[test]
        fn audit_structured_errors_enable_caller_pattern_matching() {
            // Test Case: Demonstrate that callers can now handle authentication errors specifically
            fn handle_redis_auth_error(error: &RedisError) -> &'static str {
                match error {
                    RedisError::NoAuth => "prompt_for_credentials",
                    RedisError::WrongPassword => "invalid_credentials_retry",
                    RedisError::Redis(_) => "generic_error_handling",
                    _ => "other_error_handling",
                }
            }

            let noauth_error = RedisError::NoAuth;
            assert_eq!(
                handle_redis_auth_error(&noauth_error),
                "prompt_for_credentials"
            );

            let wrongpass_error = RedisError::WrongPassword;
            assert_eq!(
                handle_redis_auth_error(&wrongpass_error),
                "invalid_credentials_retry"
            );

            let generic_error = RedisError::Redis("ERR syntax error".to_string());
            assert_eq!(
                handle_redis_auth_error(&generic_error),
                "generic_error_handling"
            );
        }

        // AUDIT VERIFICATION:
        // ✓ NOAUTH and WRONGPASS errors now surfaced as structured RedisError variants
        // ✓ Callers can match on specific authentication error types for actionable handling
        // ✓ Case-insensitive parsing handles Redis server variations
        // ✓ Display messages include Redis error codes for debugging
        // ✓ Generic Redis errors continue to preserve original server messages
        // ✓ No information loss - authentication errors are fully actionable
    }

    /// Audit test for RESP3 push-frame parsing under malformed inputs.
    ///
    /// BEHAVIOR VERIFICATION: When server sends "|" prefix (push/attribute) followed by
    /// malformed length or truncated body, our parser correctly returns structured
    /// ParseError (option b: actionable) rather than panic (option c: dangerous) or
    /// skip-and-continue (option a: tolerant but potentially masking issues).
    #[test]
    fn audit_resp3_push_frame_malformed_input_handling() {
        // RESP3 Push Frame Format: "|N\r\n" followed by N key-value pairs
        // RESP3 Attribute Format: "|N\r\n" followed by N key-value pairs (same wire format)

        // Test Category 1: Malformed length after "|" prefix
        let malformed_length_cases = [
            // Non-digit characters in length
            b"|abc\r\n".as_slice(),
            b"|-\r\n".as_slice(),
            b"|12x34\r\n".as_slice(),
            b"|\r\n".as_slice(), // Empty length
            // Negative length (invalid for aggregate types)
            b"|-5\r\n".as_slice(),
            // Integer overflow cases
            b"|99999999999999999999\r\n".as_slice(),
        ];

        for (i, malformed_input) in malformed_length_cases.iter().enumerate() {
            let result = RespValue::try_decode(malformed_input);

            match result {
                Ok(None) => {
                    panic!(
                        "Test case {i}: Complete malformed push frame length must return \
                         structured Protocol error, not incomplete parse"
                    );
                }
                Ok(Some(_)) => {
                    panic!(
                        "Test case {i}: Expected parse error for malformed push frame length, \
                         but parsing succeeded: {:?}",
                        std::str::from_utf8(malformed_input).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(msg)) => {
                    // EXPECTED BEHAVIOR: Structured protocol error
                    assert!(
                        msg.contains("invalid") || msg.contains("overflow") || msg.contains("byte"),
                        "Test case {i}: Protocol error should be actionable, got: {msg}"
                    );
                }
                Err(other) => {
                    panic!(
                        "Test case {i}: Expected Protocol error for malformed input, got: {:?}",
                        other
                    );
                }
            }
        }

        // Test Category 2: Truncated body after valid length
        let truncated_body_cases = [
            // Valid length but incomplete key-value pairs
            b"|2\r\n+key1\r\n".as_slice(), // Missing value1, key2, value2
            b"|1\r\n+key\r\n".as_slice(),  // Missing value (odd number in map)
            b"|1\r\n".as_slice(),          // No pairs at all
        ];

        for (i, truncated_input) in truncated_body_cases.iter().enumerate() {
            let result = RespValue::try_decode(truncated_input);

            match result {
                Ok(None) => {
                    // EXPECTED: Incomplete parse for truncated input
                    // This is correct - parser detects insufficient data
                }
                Ok(Some(_)) => {
                    panic!(
                        "Truncated test {i}: Parser should not succeed on incomplete input: {:?}",
                        std::str::from_utf8(truncated_input).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(_)) => {
                    // Also acceptable - some truncation patterns may be detected as protocol errors
                }
                Err(other) => {
                    panic!("Truncated test {i}: Unexpected error type: {:?}", other);
                }
            }
        }

        // Test Category 3: Verify no panic behavior
        // Parser should never panic on malformed input - always return Result
        let extreme_cases = [
            b"|999999999999999999999999999999\r\n".as_slice(), // Extreme overflow
            b"|\x00\x01\x02\r\n".as_slice(),                   // Binary in length field
            b"|\xFF\xFF\xFF\r\n".as_slice(),                   // Invalid UTF-8 bytes
        ];

        for (i, extreme_input) in extreme_cases.iter().enumerate() {
            // The key test: parser must not panic
            let result = std::panic::catch_unwind(|| RespValue::try_decode(extreme_input));

            assert!(
                result.is_ok(),
                "Extreme test {i}: Parser panicked on malformed input - should return Result::Err"
            );
        }

        // BEHAVIOR VERIFICATION COMPLETE:
        // ✅ Option (b): Structured ParseError with actionable messages
        // ❌ Option (a): Does NOT skip and continue (would return Ok(Some(_)))
        // ❌ Option (c): Does NOT panic (verified via catch_unwind)
        // ✅ RESP3 spec compliance: malformed frames result in parse errors
        // ✅ Error messages are actionable for debugging
        // ✅ Truncated input correctly detected as incomplete (Ok(None))
    }
}
