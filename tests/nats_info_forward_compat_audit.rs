//! NATS server INFO forward-compatibility regressions.

use asupersync::messaging::nats::{NatsClient, NatsConfig, NatsError, ServerInfo};
use asupersync::test_utils::run_test_with_cx;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn connect_with_info_json(json: &str, expect_connect: bool) -> Result<ServerInfo, NatsError> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let json = json.to_owned();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept test client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let info_message = format!("INFO {json}\r\n");
        stream
            .write_all(info_message.as_bytes())
            .expect("write INFO");
        stream.flush().expect("flush INFO");

        if expect_connect {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).expect("read CONNECT");
            let line = std::str::from_utf8(&buf[..n]).expect("CONNECT must be UTF-8");
            assert!(
                line.starts_with("CONNECT "),
                "expected CONNECT after valid INFO, got {line:?}"
            );
            return;
        }

        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!(
                "client sent bytes after invalid INFO: {:?}",
                String::from_utf8_lossy(&buf[..n])
            ),
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(err) => panic!("unexpected server read error: {err}"),
        }
    });

    let captured = Arc::new(Mutex::new(None));
    let captured_for_client = Arc::clone(&captured);
    run_test_with_cx(|cx| async move {
        let config = NatsConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            ..Default::default()
        };

        let outcome = match NatsClient::connect_with_config(&cx, config).await {
            Ok(client) => Ok(client
                .server_info()
                .expect("connected client stores ServerInfo")),
            Err(err) => Err(err),
        };
        *captured_for_client.lock().expect("capture result") = Some(outcome);
    });

    let outcome = captured
        .lock()
        .expect("capture result")
        .take()
        .expect("client completed");
    server.join().expect("server thread join");
    outcome
}

#[test]
fn info_connection_tolerates_unknown_fields() {
    let info = connect_with_info_json(
        concat!(
            "{",
            "\"server_id\":\"future-server\",",
            "\"server_name\":\"nats-2030\",",
            "\"version\":\"3.0.0\",",
            "\"proto\":2,",
            "\"max_payload\":2097152,",
            "\"tls_required\":false,",
            "\"foo\":\"bar\",",
            "\"future_bool\":true,",
            "\"cluster_topology\":{\"nodes\":5},",
            "\"experimental_flags\":[\"flag1\",\"flag2\"]",
            "}"
        ),
        true,
    )
    .expect("unknown INFO fields must be ignored");

    assert_eq!(info.server_id, "future-server");
    assert_eq!(info.server_name, "nats-2030");
    assert_eq!(info.version, "3.0.0");
    assert_eq!(info.proto, 2);
    assert_eq!(info.max_payload, 2_097_152);
    assert!(!info.tls_required);
}

#[test]
fn info_connection_accepts_minimal_and_nested_unknown_fields() {
    let cases = [
        (r#"{"server_id":"minimal"}"#, "minimal"),
        ("{}", ""),
        (
            r#"{"server_id":"valid","foo":"bar","nested":{"key":"value"}}"#,
            "valid",
        ),
    ];

    for (json, expected_id) in cases {
        let info = connect_with_info_json(json, true).expect("valid INFO JSON should connect");
        assert_eq!(info.server_id, expected_id);
    }
}

#[test]
fn info_connection_rejects_malformed_json_without_connect() {
    let err = connect_with_info_json(r#"{"server_id":"broken""#, false)
        .expect_err("malformed INFO JSON must fail");
    assert!(
        matches!(err, NatsError::Protocol(ref message) if message.contains("malformed INFO JSON")),
        "expected malformed INFO JSON protocol error, got {err:?}"
    );
}

#[test]
fn info_connection_rejects_non_object_json_without_connect() {
    let err = connect_with_info_json("[]", false).expect_err("INFO JSON must be an object");
    assert!(
        matches!(err, NatsError::Protocol(ref message) if message.contains("expected object")),
        "expected non-object INFO JSON protocol error, got {err:?}"
    );
}
