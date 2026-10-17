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
