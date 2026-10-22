    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::io::Read;

    fn test_snapshot() -> RuntimeSnapshot {
        RuntimeSnapshot {
            timestamp: 12345,
            regions: vec![],
            tasks: vec![],
            obligations: vec![],
            recent_events: vec![],
            finalizer_history: vec![],
            loser_drain_history: vec![],
        }
    }

    fn inspector_fixture() -> InspectorSnapshot {
        let mut lab = crate::LabRuntime::with_seed(41);
        let root = lab.state.create_root_region(crate::Budget::INFINITE);
        let (holder, _handle) = lab
            .state
            .create_task(root, crate::Budget::INFINITE, std::future::pending::<()>())
            .unwrap();
        let cx = lab.state.task(holder).unwrap().cx.as_ref().unwrap().clone();
        lab.advance_time_to(crate::types::Time::from_secs(2));
        cx.checkpoint_with("private-http-checkpoint-canary")
            .unwrap();
        let obligation = lab
            .state
            .create_obligation(
                crate::record::ObligationKind::Ack,
                holder,
                root,
                Some("private-http-obligation-canary".to_string()),
            )
            .unwrap();
        let snapshot = InspectorSnapshot::from_state(&lab.state, InspectorProfile::Full);
        lab.state.commit_obligation(obligation).unwrap();
        snapshot
    }

    fn inspector_server() -> DebugServer {
        DebugServer::with_config(
            0,
            Arc::new(test_snapshot),
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        )
    }

    fn request_server(server: &DebugServer, method: &str, path: &str) -> String {
        let mut stream = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .expect("complete HTTP response");
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(body.len(), length, "response must have a complete body");
        response
    }

    fn response_body(response: &str) -> &str {
        response.split_once("\r\n\r\n").unwrap().1
    }

    #[test]
    fn inspector_http_defaults_to_shareable_and_query_cannot_escalate() {
        let mut full = inspector_fixture();
        let expected = full.clone().into_shareable();
        // Even a provider that mislabels its full data cannot bypass scrubbing.
        full.profile = InspectorProfile::Shareable;
        let mut server = inspector_server().with_inspector_snapshot_fn(Arc::new(move |profile| {
            assert_eq!(profile, InspectorProfile::Shareable);
            Some(full.clone())
        }));
        server.start().unwrap();
        assert!(server.local_addr().unwrap().ip().is_loopback());

        for path in ["/inspector?profile=full", "/debug/inspector"] {
            let response = request_server(&server, "GET", path);
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
            assert!(response.contains("Content-Type: application/json\r\n"));
            assert!(response.contains("Cache-Control: no-store\r\n"));
            assert!(response.contains("X-Content-Type-Options: nosniff\r\n"));
            assert!(
                !response
                    .to_ascii_lowercase()
                    .contains("access-control-allow-origin")
            );
            for canary in [
                "private-http-checkpoint-canary",
                "private-http-obligation-canary",
                "debug_inline_tests.rs",
            ] {
                assert!(
                    !response.contains(canary),
                    "diagnostic text escaped: {canary}"
                );
            }
            let snapshot: InspectorSnapshot =
                serde_json::from_str(response_body(&response)).unwrap();
            assert_eq!(snapshot, expected);
            let wire: serde_json::Value = serde_json::from_str(response_body(&response)).unwrap();
            assert_eq!(
                wire["schema_version"],
                crate::observability::INSPECTOR_SNAPSHOT_SCHEMA_V1
            );
            assert_eq!(wire["counters"]["reserved_obligations"], 1);
            assert!(wire["tasks"][0]["budget"]["poll_quota"].is_number());
        }

        // Adding the provider does not replace the dashboard's legacy data.
        let legacy = request_server(&server, "GET", "/debug/snapshot");
        assert!(legacy.starts_with("HTTP/1.1 200 OK\r\n"));
        let wire: serde_json::Value = serde_json::from_str(response_body(&legacy)).unwrap();
        assert_eq!(wire["timestamp"], 12345);
    }

    #[test]
    fn inspector_http_full_profile_requires_server_configuration() {
        let full = inspector_fixture();
        let expected = full.clone();
        let mut server = inspector_server()
            .with_inspector_snapshot_fn(Arc::new(move |profile| {
                assert_eq!(profile, InspectorProfile::Full);
                Some(full.clone())
            }))
            .with_inspector_profile(InspectorProfile::Full);
        server.start().unwrap();
        let response = request_server(&server, "GET", "/inspector");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("private-http-checkpoint-canary"));
        assert!(response.contains("private-http-obligation-canary"));
        assert!(response.contains("debug_inline_tests.rs"));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert_eq!(
            serde_json::from_str::<InspectorSnapshot>(response_body(&response)).unwrap(),
            expected
        );
    }

    #[test]
    fn inspector_http_unavailable_and_route_errors_are_distinct() {
        let mut unconfigured = inspector_server();
        unconfigured.start().unwrap();
        for path in ["/inspector", "/debug/inspector"] {
            let response = request_server(&unconfigured, "GET", path);
            assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
            let error: serde_json::Value = serde_json::from_str(response_body(&response)).unwrap();
            assert_eq!(error["error"], "inspector_unavailable");
        }
        let unknown = request_server(&unconfigured, "GET", "/inspectors");
        assert!(unknown.starts_with("HTTP/1.1 404 Not Found\r\n"));

        let captures = Arc::new(AtomicUsize::new(0));
        let capture_count = Arc::clone(&captures);
        let mut unavailable = inspector_server().with_inspector_snapshot_fn(Arc::new(move |_| {
            capture_count.fetch_add(1, Ordering::Relaxed);
            None
        }));
        unavailable.start().unwrap();
        let method = request_server(&unavailable, "POST", "/inspector");
        assert!(method.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert_eq!(captures.load(Ordering::Relaxed), 0);
        let response = request_server(&unavailable, "GET", "/inspector");
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        let error: serde_json::Value = serde_json::from_str(response_body(&response)).unwrap();
        assert_eq!(error["error"], "inspector_unavailable");
        assert_eq!(captures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn inspector_http_response_limit_is_exact_and_never_truncates_json() {
        let snapshot = inspector_fixture();
        let shareable = snapshot.clone().into_shareable();
        let expected_bytes = serde_json::to_vec(&shareable).unwrap();
        for limit in [expected_bytes.len(), expected_bytes.len() - 1, 0] {
            let captured = snapshot.clone();
            let mut server = inspector_server()
                .with_inspector_snapshot_fn(Arc::new(move |_| Some(captured.clone())))
                .with_inspector_max_response_bytes(limit);
            server.start().unwrap();
            let response = request_server(&server, "GET", "/inspector");
            let body = response_body(&response);
            if limit == expected_bytes.len() {
                assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
                assert_eq!(body.as_bytes(), expected_bytes);
            } else {
                assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
                let error: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(error["error"], "inspector_response_too_large");
                assert!(error.get("tasks").is_none());
            }
            assert!(!response.contains("private-http-checkpoint-canary"));
        }
    }

    #[test]
    fn inspector_http_capture_panic_returns_error_and_releases_connection_slot() {
        let captures = Arc::new(AtomicUsize::new(0));
        let capture_count = Arc::clone(&captures);
        let snapshot = inspector_fixture();
        let mut server = DebugServer::with_config(
            0,
            Arc::new(test_snapshot),
            DebugServerConfig {
                print_url: false,
                max_connections: 1,
                ..Default::default()
            },
        )
        .with_inspector_snapshot_fn(Arc::new(move |_| {
            assert_ne!(
                capture_count.fetch_add(1, Ordering::Relaxed),
                0,
                "private-panic-canary"
            );
            Some(snapshot.clone())
        }));
        server.start().unwrap();
        let failed = request_server(&server, "GET", "/inspector");
        assert!(failed.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(!failed.contains("private-panic-canary"));
        let error: serde_json::Value = serde_json::from_str(response_body(&failed)).unwrap();
        assert_eq!(error["error"], "inspector_capture_failed");

        // The previous connection can still be dropping its guard when the
        // client sees EOF. Allow that guard to release before requiring success.
        let mut recovered = false;
        for _ in 0..20 {
            let response = request_server(&server, "GET", "/inspector");
            if response.starts_with("HTTP/1.1 200 OK\r\n") {
                serde_json::from_str::<InspectorSnapshot>(response_body(&response)).unwrap();
                recovered = true;
                break;
            }
            assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        }
        assert!(
            recovered,
            "provider panic must not consume a connection slot permanently"
        );
        assert_eq!(captures.load(Ordering::Relaxed), 2);
    }

    async fn wait_for_inspector(mut probe: impl FnMut() -> bool) -> bool {
        for _ in 0..20_000 {
            if probe() {
                return true;
            }
            crate::runtime::yield_now().await;
        }
        probe()
    }

    #[test]
    fn inspector_http_native_runtime_obligation_lifecycle_across_state_shapes() {
        use crate::record::{ObligationKind, ObligationState};
        use crate::runtime::RuntimeBuilder;

        for workers in [1, 2] {
            for sharded in [false, true] {
                let builder = if workers == 1 {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::multi_thread().worker_threads(workers)
                };
                let runtime = builder.with_sharded_state(sharded).build().unwrap();
                let inspector = runtime.task_inspector(TaskInspectorConfig::default());
                let mut server = inspector_server().with_runtime_inspector(runtime.handle());
                server.start().unwrap();

                runtime.block_on(async {
                    let cx = crate::Cx::current().unwrap();
                    let holder = cx.task_id();
                    let token = cx
                        .try_register_obligation_checked(ObligationKind::Ack, holder)
                        .unwrap()
                        .unwrap();
                    assert!(
                        wait_for_inspector(|| {
                            inspector
                                .runtime_snapshot(InspectorProfile::Shareable)
                                .obligations
                                .iter()
                                .any(|ob| {
                                    ob.holder == holder && ob.state == ObligationState::Reserved
                                })
                        })
                        .await,
                        "workers={workers} sharded={sharded}: reservation must be admitted"
                    );

                    let response = request_server(&server, "GET", "/inspector");
                    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
                    let held: InspectorSnapshot =
                        serde_json::from_str(response_body(&response)).unwrap();
                    assert_eq!(
                        held.schema_version,
                        crate::observability::INSPECTOR_SNAPSHOT_SCHEMA_V1
                    );
                    assert_eq!(held.profile, InspectorProfile::Shareable);
                    assert!(held.coverage.record_tables_locked);
                    assert_eq!(held.coverage.external_obligation_table, sharded);
                    let obligation = held
                        .obligations
                        .iter()
                        .find(|ob| ob.holder == holder && ob.state == ObligationState::Reserved)
                        .unwrap();
                    let obligation_id = obligation.id;
                    let task = held
                        .tasks
                        .iter()
                        .find(|task| task.details.id == holder)
                        .unwrap();
                    let region = held
                        .regions
                        .iter()
                        .find(|region| region.id == cx.region_id())
                        .unwrap();
                    assert_eq!(obligation.region, region.id);
                    assert_eq!(task.details.region_id, region.id);
                    assert!(task.details.obligations.contains(&obligation_id));
                    assert!(region.tasks.contains(&holder));
                    assert_eq!(held.counters.reserved_obligations, 1);
                    assert!(task.budget.is_some());
                    assert!(obligation.description.is_none());
                    assert!(obligation.acquired_at.is_none());

                    assert!(token.commit());
                    assert!(
                        wait_for_inspector(|| {
                            inspector
                                .runtime_snapshot(InspectorProfile::Shareable)
                                .obligations
                                .iter()
                                .find(|ob| ob.id == obligation_id)
                                .is_none_or(|ob| ob.state == ObligationState::Committed)
                        })
                        .await,
                        "workers={workers} sharded={sharded}: resolution must be applied"
                    );
                    let response = request_server(&server, "GET", "/inspector");
                    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
                    let resolved: InspectorSnapshot =
                        serde_json::from_str(response_body(&response)).unwrap();
                    assert_eq!(resolved.counters.reserved_obligations, 0);
                    assert!(
                        resolved
                            .tasks
                            .iter()
                            .all(|task| !task.details.obligations.contains(&obligation_id))
                    );
                });
                server.stop();
            }
        }
    }

    #[test]
    fn server_starts_and_serves_snapshot() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0, // OS-assigned port
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().expect("server should start");
        assert!(server.is_running());

        let url = server.url();
        assert!(url.contains("/debug"));

        // Fetch snapshot endpoint.
        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/snapshot HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        // serde_json pretty-printing adds spaces: "timestamp": 12345
        assert!(response.contains("12345"));
        assert!(response.contains("timestamp"));

        server.stop();
    }

    #[test]
    fn server_serves_dashboard_html() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(stream, "GET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        assert!(response.contains("Asupersync Debug Dashboard"));

        server.stop();
    }

    #[test]
    fn server_serves_dashboard_html_with_refresh_query() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                refresh_interval_secs: 7,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug?refresh=7000 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        assert!(response.contains("Asupersync Debug Dashboard"));

        server.stop();
    }

    #[test]
    fn server_returns_404_for_unknown_path() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("404"));

        server.stop();
    }

    #[test]
    fn server_returns_trace_json() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/trace HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        assert!(response.contains("[]")); // empty events list

        server.stop();
    }

    #[test]
    fn server_returns_memory_residency_snapshot_json() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/memory-residency HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        assert!(response.contains("asupersync.memory-residency-accounting-snapshot.v1"));
        assert!(response.contains("\"status\": \"unknown\""));

        server.stop();
    }

    #[test]
    fn websocket_upgrade_and_frame_push() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/ws HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut buf = Vec::new();
        let n = stream.read_to_end(&mut buf).unwrap();
        let resp = &buf[..n];
        let text = String::from_utf8_lossy(resp);
        assert!(text.contains("101 Switching Protocols"), "response: {text}");
        assert!(text.contains("Sec-WebSocket-Accept"), "response: {text}");
        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("websocket header terminator should exist");
        assert!(
            n > header_end + 4 + 2,
            "expected frame bytes after websocket upgrade"
        );

        server.stop();
    }

    /// Sends one raw request to a fresh server and returns the whole reply.
    fn exchange(request: &str) -> String {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();
        let mut stream = TcpStream::connect(server.local_addr.unwrap()).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        server.stop();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn responses_carry_no_wildcard_cors_header() {
        // With `Access-Control-Allow-Origin: *` any web page the developer
        // visited could read the runtime snapshot from loopback.
        let reply = exchange("GET /debug/snapshot HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(reply.contains("200 OK"), "reply: {reply}");
        assert!(
            !reply
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "reply: {reply}"
        );
    }

    #[test]
    fn websocket_upgrade_refuses_a_foreign_origin() {
        let upgrade = |origin: &str| {
            exchange(&format!(
                "GET /debug/ws HTTP/1.1\r\n\
                 Host: localhost:9999\r\n\
                 Origin: {origin}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 \r\n"
            ))
        };
        let foreign = upgrade("https://evil.example");
        assert!(!foreign.contains("101 Switching Protocols"), "{foreign}");
        assert!(foreign.contains("400 Bad Request"), "{foreign}");
        let same = upgrade("http://localhost:9999");
        assert!(same.contains("101 Switching Protocols"), "{same}");
    }

    #[test]
    fn stop_eventually_closes_listener() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        server.stop();

        let mut listener_closed = false;
        for _ in 0..20 {
            if TcpStream::connect(addr).is_err() {
                listener_closed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }

        assert!(
            listener_closed,
            "listener should close shortly after stop()"
        );
    }

    #[test]
    fn default_config_values() {
        let config = DebugServerConfig::default();
        assert!(config.print_url);
        assert_eq!(config.bind_addr, "127.0.0.1");
        assert_eq!(config.refresh_interval_secs, 2);
        assert_eq!(config.max_connections, 16);
    }

    #[test]
    fn url_includes_configured_refresh_query() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                refresh_interval_secs: 7,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let url = server.url();
        assert!(url.contains("/debug?refresh=7000"), "url was {url}");

        server.stop();
    }

    #[test]
    fn server_rejects_connections_over_limit() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                max_connections: 1,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let first_stream = TcpStream::connect(addr).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut second_stream = TcpStream::connect(addr).unwrap();
        write!(
            second_stream,
            "GET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        second_stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&second_stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(
            response.contains("503 Service Unavailable"),
            "response: {response}"
        );

        drop(first_stream);
        server.stop();
    }

    #[test]
    fn panicking_snapshot_request_does_not_leak_connection_slots() {
        let panicked_once = Arc::new(AtomicBool::new(false));
        let panicked_once_clone = Arc::clone(&panicked_once);
        let snapshot_fn: SnapshotFn = Arc::new(move || {
            assert!(
                panicked_once_clone.swap(true, Ordering::SeqCst),
                "snapshot boom"
            );
            test_snapshot()
        });
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                max_connections: 1,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();

        let mut first_stream = TcpStream::connect(addr).unwrap();
        write!(
            first_stream,
            "GET /debug/snapshot HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        first_stream.flush().unwrap();
        let mut first_response = Vec::new();
        let _ = first_stream.read_to_end(&mut first_response);

        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut second_stream = TcpStream::connect(addr).unwrap();
        write!(
            second_stream,
            "GET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        second_stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&second_stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(
            response.contains("200 OK"),
            "server should recover after a panicking request; response: {response}"
        );
        assert!(
            !response.contains("503 Service Unavailable"),
            "panicking request must not leak a connection slot"
        );

        server.stop();
    }

    #[test]
    fn dashboard_html_content() {
        assert!(DASHBOARD_HTML.contains("Asupersync Debug Dashboard"));
        assert!(DASHBOARD_HTML.contains("/debug/snapshot"));
        assert!(DASHBOARD_HTML.contains("CONFIG"));
    }

    #[test]
    fn debug_server_config_debug_clone() {
        let c = DebugServerConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DebugServerConfig"));
        assert!(dbg.contains("127.0.0.1"));

        let c2 = c;
        assert_eq!(c2.bind_addr, "127.0.0.1");
        assert_eq!(c2.max_connections, 16);
        assert_eq!(c2.refresh_interval_secs, 2);
        assert!(c2.print_url);
    }

    /// GitHub #80 census: the connection thread's handle used to be dropped at
    /// spawn, detaching a thread that may already be exiting. It is parked
    /// instead, and joined once the thread has finished.
    #[test]
    fn a_running_connection_thread_is_parked_not_detached() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        // A connection that sends nothing keeps its handler in the request
        // read (5 s timeout), so that thread is still running.
        let silent = TcpStream::connect(server.local_addr.unwrap()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        let parked = loop {
            let parked =
                crate::runtime::spawn_blocking::parked_thread_named("asupersync-debug-connection");
            if parked == Some(false) || std::time::Instant::now() >= deadline {
                break parked;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            parked,
            Some(false),
            "the running connection thread must be parked, not detached"
        );

        drop(silent);
        server.stop();
    }
