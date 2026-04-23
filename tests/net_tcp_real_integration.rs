#![allow(warnings)]
#![allow(clippy::all)]
//! Perfect E2E & Integration Tests (No Mocks) for TCP
//!
//! Follows the manifesto from /testing-perfect-e2e-integration-tests-with-logging-and-no-mocks:
//! 1. No virtual environments or mocked network connections.
//! 2. Structured JSON-line logging (phase, timing, asserts).
//! 3. Real sockets.

#[macro_use]
mod common;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use common::*;
use futures_lite::future::block_on;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

fn json_log(suite: &str, phase: &str, event: &str, data: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    println!(
        r#"{{"ts":{}, "suite":"{}","phase":"{}","event":"{}","data":{}}}"#,
        ts, suite, phase, event, data
    );
}

/// A perfect mock-free integration test for TCP data framing and echo
#[test]
fn net_tcp_real_integration_echo_log() {
    init_test("net_tcp_real_integration_echo_log");
    let suite = "tcp_real_integration";

    json_log(suite, "setup", "phase_start", r#"{}"#);

    let result = block_on(async {
        // 1. SETUP: Real TCP Listener
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        json_log(
            suite,
            "setup",
            "listener_bound",
            &format!(r#"{{"port": {}}}"#, addr.port()),
        );

        // Server Task (Echoes until connection drops)
        let server_handle = std::thread::spawn(move || {
            block_on(async {
                let (mut stream, peer_addr) = listener.accept().await?;
                let mut buf = vec![0u8; 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(n) => n,
                        Err(_) => break, // Error
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok::<_, io::Error>(())
            })
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        // 2. ACT: Client sends data
        json_log(suite, "act", "phase_start", r#"{}"#);
        let mut client = TcpStream::connect(addr).await?;
        let test_payload = b"integration_test_payload_123";
        client.write_all(test_payload).await?;
        
        let mut response = vec![0u8; test_payload.len()];
        client.read_exact(&mut response).await?;

        // 3. ASSERT: Compare real received data with sent payload
        json_log(suite, "assert", "phase_start", r#"{}"#);
        let match_ok = response == test_payload;
        json_log(
            suite,
            "assert",
            "assertion",
            &format!(
                r#"{{"field":"echo matching payload","expected":true,"actual":{},"match":{}}}"#,
                match_ok, match_ok
            ),
        );
        assert!(match_ok, "Echoed data must match exactly");

        // 4. TEARDOWN: Clean closure
        json_log(suite, "teardown", "phase_start", r#"{}"#);
        drop(client);
        let _ = server_handle.join();

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "test should complete successfully");
    json_log(
        suite,
        "teardown",
        "test_end",
        r#"{"result":"pass"}"#,
    );
    test_complete!("net_tcp_real_integration_echo_log");
}
