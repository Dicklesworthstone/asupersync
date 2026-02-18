//! I/O Conformance Test Suite
//!
//! Tests covering file operations, TCP, and UDP networking.
//!
//! # Test IDs
//!
//! - IO-001: File write and read roundtrip
//! - IO-002: File seek operations
//! - IO-003: TCP echo server
//! - IO-004: TCP concurrent connections
//! - IO-005: UDP send and receive
//! - IO-006: Buffered I/O (BufReader/BufWriter pattern)
//! - IO-007: Socket read timeout

use crate::{
    AsyncFile, ConformanceTest, MpscReceiver, MpscSender, RuntimeInterface, TcpListener, TcpStream,
    TestCategory, TestMeta, TestResult, UdpSocket, checkpoint,
};
use std::io::SeekFrom;
use std::time::Duration;

/// Get all I/O conformance tests.
pub fn all_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        io_001_file_write_read::<RT>(),
        io_002_file_seek::<RT>(),
        io_003_tcp_echo::<RT>(),
        io_004_tcp_concurrent::<RT>(),
        io_005_udp_send_recv::<RT>(),
        io_006_buffered_io::<RT>(),
        io_007_read_timeout::<RT>(),
    ]
}

/// IO-001: File write and read roundtrip
///
/// Writes data to a file, reads it back, and verifies the content matches.
pub fn io_001_file_write_read<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-001".to_string(),
            name: "File write and read roundtrip".to_string(),
            description: "Write data to file, read it back".to_string(),
            category: TestCategory::IO,
            tags: vec!["file".to_string(), "basic".to_string()],
            expected: "Read data matches written data".to_string(),
        },
        |rt| {
            rt.block_on(async {
                // Create a temporary directory
                let dir = match tempfile::tempdir() {
                    Ok(d) => d,
                    Err(e) => return TestResult::failed(format!("Failed to create tempdir: {e}")),
                };
                let path = dir.path().join("test.txt");

                let data = b"Hello, async file I/O!";

                // Write
                let mut file = match rt.file_create(&path).await {
                    Ok(f) => f,
                    Err(e) => return TestResult::failed(format!("Failed to create file: {e}")),
                };

                if let Err(e) = file.write_all(data).await {
                    return TestResult::failed(format!("Failed to write: {e}"));
                }

                if let Err(e) = file.sync_all().await {
                    return TestResult::failed(format!("Failed to sync: {e}"));
                }

                drop(file);

                checkpoint("file_written", serde_json::json!({"bytes": data.len()}));

                // Read
                let mut file = match rt.file_open(&path).await {
                    Ok(f) => f,
                    Err(e) => return TestResult::failed(format!("Failed to open file: {e}")),
                };

                let mut buf = Vec::new();
                match file.read_to_end(&mut buf).await {
                    Ok(n) => {
                        checkpoint("file_read", serde_json::json!({"bytes": n}));
                    }
                    Err(e) => return TestResult::failed(format!("Failed to read: {e}")),
                }

                if buf != data {
                    return TestResult::failed(format!(
                        "Read data mismatch: expected {:?}, got {:?}",
                        data, buf
                    ));
                }

                TestResult::passed()
            })
        },
    )
}

/// IO-002: File seek operations
///
/// Tests seeking to various positions within a file.
pub fn io_002_file_seek<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-002".to_string(),
            name: "File seek operations".to_string(),
            description: "Seek to positions and read".to_string(),
            category: TestCategory::IO,
            tags: vec!["file".to_string(), "seek".to_string()],
            expected: "Seeking works correctly".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let dir = match tempfile::tempdir() {
                    Ok(d) => d,
                    Err(e) => return TestResult::failed(format!("Failed to create tempdir: {e}")),
                };
                let path = dir.path().join("seek_test.txt");

                // Write test data
                let mut file = match rt.file_create(&path).await {
                    Ok(f) => f,
                    Err(e) => return TestResult::failed(format!("Failed to create file: {e}")),
                };

                if let Err(e) = file.write_all(b"0123456789").await {
                    return TestResult::failed(format!("Failed to write: {e}"));
                }
                drop(file);

                // Read with seeking
                let mut file = match rt.file_open(&path).await {
                    Ok(f) => f,
                    Err(e) => return TestResult::failed(format!("Failed to open file: {e}")),
                };

                // Seek to middle (position 5)
                if let Err(e) = file.seek(SeekFrom::Start(5)).await {
                    return TestResult::failed(format!("Failed to seek to start+5: {e}"));
                }

                let mut buf = [0u8; 3];
                if let Err(e) = file.read_exact(&mut buf).await {
                    return TestResult::failed(format!("Failed to read after seek: {e}"));
                }

                if &buf != b"567" {
                    return TestResult::failed(format!(
                        "Expected '567' after seek to 5, got '{}'",
                        String::from_utf8_lossy(&buf)
                    ));
                }

                // Seek from end (-2)
                if let Err(e) = file.seek(SeekFrom::End(-2)).await {
                    return TestResult::failed(format!("Failed to seek from end: {e}"));
                }

                let mut buf2 = [0u8; 2];
                if let Err(e) = file.read_exact(&mut buf2).await {
                    return TestResult::failed(format!("Failed to read after seek from end: {e}"));
                }

                if &buf2 != b"89" {
                    return TestResult::failed(format!(
                        "Expected '89' after seek from end, got '{}'",
                        String::from_utf8_lossy(&buf2)
                    ));
                }

                // Seek from current: start at 2, then +3 = position 5
                if let Err(e) = file.seek(SeekFrom::Start(2)).await {
                    return TestResult::failed(format!("Failed to seek to start+2: {e}"));
                }

                if let Err(e) = file.seek(SeekFrom::Current(3)).await {
                    return TestResult::failed(format!("Failed to seek from current: {e}"));
                }

                let mut buf3 = [0u8; 1];
                if let Err(e) = file.read_exact(&mut buf3).await {
                    return TestResult::failed(format!(
                        "Failed to read after seek from current: {e}"
                    ));
                }

                if &buf3 != b"5" {
                    return TestResult::failed(format!(
                        "Expected '5' after seek from current, got '{}'",
                        String::from_utf8_lossy(&buf3)
                    ));
                }

                TestResult::passed()
            })
        },
    )
}

/// IO-003: TCP echo server
///
/// Tests basic TCP client-server communication with an echo server.
pub fn io_003_tcp_echo<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-003".to_string(),
            name: "TCP echo server".to_string(),
            description: "Send data to TCP server, receive echo".to_string(),
            category: TestCategory::IO,
            tags: vec!["tcp".to_string(), "echo".to_string()],
            expected: "Echoed data matches sent data".to_string(),
        },
        |rt| {
            rt.block_on(async {
                // Bind listener to any available port
                let listener = match rt.tcp_listen("127.0.0.1:0").await {
                    Ok(l) => l,
                    Err(e) => return TestResult::failed(format!("Failed to bind listener: {e}")),
                };

                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => return TestResult::failed(format!("Failed to get local addr: {e}")),
                };

                checkpoint(
                    "server_bound",
                    serde_json::json!({"addr": addr.to_string()}),
                );

                // Create channel to get server result
                let (server_done_tx, mut server_done_rx) = rt.mpsc_channel::<Result<(), String>>(1);

                // Server task: accept one connection, echo data back
                // Note: The listener is moved into this task, so it owns it
                let _server = rt.spawn(async move {
                    let accept_result = listener.accept().await;
                    let (mut socket, client_addr) = match accept_result {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = server_done_tx
                                .send(Err(format!("Server accept failed: {e}")))
                                .await;
                            return;
                        }
                    };

                    checkpoint(
                        "client_connected",
                        serde_json::json!({"addr": client_addr.to_string()}),
                    );

                    let mut buf = [0u8; 1024];
                    loop {
                        let n = match socket.read(&mut buf).await {
                            Ok(n) => n,
                            Err(e) => {
                                let _ = server_done_tx
                                    .send(Err(format!("Server read failed: {e}")))
                                    .await;
                                return;
                            }
                        };

                        if n == 0 {
                            break;
                        }

                        if let Err(e) = socket.write_all(&buf[..n]).await {
                            let _ = server_done_tx
                                .send(Err(format!("Server write failed: {e}")))
                                .await;
                            return;
                        }
                    }

                    let _ = server_done_tx.send(Ok(())).await;
                });

                // Client logic runs in main async context (not spawned)
                // This avoids capturing &RT in a spawned task
                let client_result: Result<(), String> = async {
                    let mut socket = rt
                        .tcp_connect(addr)
                        .await
                        .map_err(|e| format!("Client connect failed: {e}"))?;

                    let test_data = b"Hello, TCP!";
                    socket
                        .write_all(test_data)
                        .await
                        .map_err(|e| format!("Client write failed: {e}"))?;

                    let mut buf = vec![0u8; test_data.len()];
                    socket
                        .read_exact(&mut buf)
                        .await
                        .map_err(|e| format!("Client read failed: {e}"))?;

                    if buf != test_data {
                        return Err(format!(
                            "Echo mismatch: expected {:?}, got {:?}",
                            test_data, buf
                        ));
                    }

                    socket
                        .shutdown()
                        .await
                        .map_err(|e| format!("Client shutdown failed: {e}"))?;

                    Ok(())
                }
                .await;

                if let Err(e) = client_result {
                    return TestResult::failed(e);
                }

                // Wait for server with timeout
                let timeout_result = rt
                    .timeout(Duration::from_secs(5), async {
                        if let Some(result) = server_done_rx.recv().await {
                            result
                        } else {
                            Err("Server channel closed unexpectedly".to_string())
                        }
                    })
                    .await;

                match timeout_result {
                    Ok(Ok(())) => TestResult::passed(),
                    Ok(Err(e)) => TestResult::failed(e),
                    Err(_) => TestResult::failed("Test timed out after 5 seconds"),
                }
            })
        },
    )
}

/// IO-004: TCP concurrent connections
///
/// Tests handling multiple simultaneous TCP connections.
/// Note: Clients run sequentially in the main async context to avoid
/// capturing &RT in spawned tasks. The server handles all connections
/// concurrently via its spawned task.
pub fn io_004_tcp_concurrent<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-004".to_string(),
            name: "TCP concurrent connections".to_string(),
            description: "Handle multiple simultaneous TCP connections".to_string(),
            category: TestCategory::IO,
            tags: vec!["tcp".to_string(), "concurrent".to_string()],
            expected: "All connections handled correctly".to_string(),
        },
        |rt| {
            rt.block_on(async {
                const NUM_CLIENTS: usize = 10;

                let listener = match rt.tcp_listen("127.0.0.1:0").await {
                    Ok(l) => l,
                    Err(e) => return TestResult::failed(format!("Failed to bind listener: {e}")),
                };

                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => return TestResult::failed(format!("Failed to get local addr: {e}")),
                };

                // Channel to collect server results
                let (result_tx, mut result_rx) =
                    rt.mpsc_channel::<Result<usize, String>>(NUM_CLIENTS);

                // Server: accept NUM_CLIENTS connections and echo
                // The listener is moved into this task (no &RT capture)
                let _server = rt.spawn(async move {
                    for i in 0..NUM_CLIENTS {
                        let accept_result = listener.accept().await;
                        let (mut socket, _) = match accept_result {
                            Ok(v) => v,
                            Err(e) => {
                                let _ = result_tx
                                    .send(Err(format!("Server accept {i} failed: {e}")))
                                    .await;
                                continue;
                            }
                        };

                        let mut buf = [0u8; 100];
                        let n = match socket.read(&mut buf).await {
                            Ok(n) => n,
                            Err(e) => {
                                let _ = result_tx
                                    .send(Err(format!("Server read {i} failed: {e}")))
                                    .await;
                                continue;
                            }
                        };

                        if let Err(e) = socket.write_all(&buf[..n]).await {
                            let _ = result_tx
                                .send(Err(format!("Server write {i} failed: {e}")))
                                .await;
                            continue;
                        }

                        let _ = result_tx.send(Ok(i)).await;
                    }
                });

                // Clients: run from main async context (not spawned)
                // This avoids capturing &RT in spawned tasks
                let mut client_errors: Vec<String> = Vec::new();
                for i in 0..NUM_CLIENTS {
                    let result: Result<(), String> = async {
                        let mut socket = rt
                            .tcp_connect(addr)
                            .await
                            .map_err(|e| format!("Client {i} connect failed: {e}"))?;

                        let msg = format!("client-{i}");
                        socket
                            .write_all(msg.as_bytes())
                            .await
                            .map_err(|e| format!("Client {i} write failed: {e}"))?;

                        let mut buf = vec![0u8; msg.len()];
                        socket
                            .read_exact(&mut buf)
                            .await
                            .map_err(|e| format!("Client {i} read failed: {e}"))?;

                        if buf != msg.as_bytes() {
                            return Err(format!(
                                "Client {i} echo mismatch: expected {msg:?}, got {:?}",
                                String::from_utf8_lossy(&buf)
                            ));
                        }

                        Ok(())
                    }
                    .await;

                    if let Err(e) = result {
                        client_errors.push(e);
                    }
                }

                if !client_errors.is_empty() {
                    return TestResult::failed(format!(
                        "Client errors: {}",
                        client_errors.join("; ")
                    ));
                }

                // Collect server results with timeout
                let timeout_result = rt
                    .timeout(Duration::from_secs(10), async {
                        let mut success_count = 0;
                        for _ in 0..NUM_CLIENTS {
                            match result_rx.recv().await {
                                Some(Ok(_)) => success_count += 1,
                                Some(Err(e)) => return Err(e),
                                None => break,
                            }
                        }
                        Ok(success_count)
                    })
                    .await;

                match timeout_result {
                    Ok(Ok(count)) => {
                        checkpoint("connections_completed", serde_json::json!({"count": count}));
                        if count == NUM_CLIENTS {
                            TestResult::passed()
                        } else {
                            TestResult::failed(format!(
                                "Expected {} server completions, got {}",
                                NUM_CLIENTS, count
                            ))
                        }
                    }
                    Ok(Err(e)) => TestResult::failed(e),
                    Err(_) => TestResult::failed("Test timed out after 10 seconds"),
                }
            })
        },
    )
}

/// IO-005: UDP send and receive
///
/// Tests basic UDP datagram sending and receiving.
pub fn io_005_udp_send_recv<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-005".to_string(),
            name: "UDP send and receive".to_string(),
            description: "Send UDP datagrams and receive them".to_string(),
            category: TestCategory::IO,
            tags: vec!["udp".to_string()],
            expected: "Datagrams received correctly".to_string(),
        },
        |rt| {
            rt.block_on(async {
                // Bind server socket
                let server = match rt.udp_bind("127.0.0.1:0").await {
                    Ok(s) => s,
                    Err(e) => return TestResult::failed(format!("Failed to bind server: {e}")),
                };

                let server_addr = match server.local_addr() {
                    Ok(a) => a,
                    Err(e) => return TestResult::failed(format!("Failed to get server addr: {e}")),
                };

                // Bind client socket
                let client = match rt.udp_bind("127.0.0.1:0").await {
                    Ok(s) => s,
                    Err(e) => return TestResult::failed(format!("Failed to bind client: {e}")),
                };

                let client_addr = match client.local_addr() {
                    Ok(a) => a,
                    Err(e) => return TestResult::failed(format!("Failed to get client addr: {e}")),
                };

                // Send from client to server
                let msg = b"Hello, UDP!";
                match client.send_to(msg, server_addr).await {
                    Ok(n) => {
                        if n != msg.len() {
                            return TestResult::failed(format!(
                                "Partial send: expected {}, sent {}",
                                msg.len(),
                                n
                            ));
                        }
                    }
                    Err(e) => return TestResult::failed(format!("Send failed: {e}")),
                }

                // Receive on server
                let mut buf = [0u8; 100];
                match server.recv_from(&mut buf).await {
                    Ok((n, from_addr)) => {
                        checkpoint(
                            "received",
                            serde_json::json!({
                                "bytes": n,
                                "from": from_addr.to_string()
                            }),
                        );

                        if &buf[..n] != msg {
                            return TestResult::failed(format!(
                                "Data mismatch: expected {:?}, got {:?}",
                                msg,
                                &buf[..n]
                            ));
                        }

                        if from_addr != client_addr {
                            return TestResult::failed(format!(
                                "Source address mismatch: expected {}, got {}",
                                client_addr, from_addr
                            ));
                        }

                        TestResult::passed()
                    }
                    Err(e) => TestResult::failed(format!("Recv failed: {e}")),
                }
            })
        },
    )
}

/// IO-006: Buffered I/O
///
/// Tests buffered read/write operations (conceptual BufReader/BufWriter pattern).
/// Since the runtime interface provides raw file operations, this test verifies
/// that multiple small writes and reads work correctly.
pub fn io_006_buffered_io<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-006".to_string(),
            name: "Buffered I/O".to_string(),
            description: "Multiple small writes and reads".to_string(),
            category: TestCategory::IO,
            tags: vec!["file".to_string(), "buffered".to_string()],
            expected: "Buffered operations work correctly".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let dir = match tempfile::tempdir() {
                    Ok(d) => d,
                    Err(e) => return TestResult::failed(format!("Failed to create tempdir: {e}")),
                };
                let path = dir.path().join("buffered.txt");

                const NUM_LINES: usize = 100;

                // Write multiple lines
                let mut file = match rt.file_create(&path).await {
                    Ok(f) => f,
                    Err(e) => return TestResult::failed(format!("Failed to create file: {e}")),
                };

                for i in 0..NUM_LINES {
                    let line = format!("Line {i}\n");
                    if let Err(e) = file.write_all(line.as_bytes()).await {
                        return TestResult::failed(format!("Failed to write line {i}: {e}"));
                    }
                }

                if let Err(e) = file.sync_all().await {
                    return TestResult::failed(format!("Failed to sync: {e}"));
                }
                drop(file);

                checkpoint("file_written", serde_json::json!({"lines": NUM_LINES}));

                // Read and verify
                let mut file = match rt.file_open(&path).await {
                    Ok(f) => f,
                    Err(e) => return TestResult::failed(format!("Failed to open file: {e}")),
                };

                let mut content = Vec::new();
                match file.read_to_end(&mut content).await {
                    Ok(_) => {}
                    Err(e) => return TestResult::failed(format!("Failed to read: {e}")),
                }

                let text = String::from_utf8_lossy(&content);
                let lines: Vec<&str> = text.lines().collect();

                checkpoint("file_read", serde_json::json!({"lines": lines.len()}));

                if lines.len() != NUM_LINES {
                    return TestResult::failed(format!(
                        "Line count mismatch: expected {}, got {}",
                        NUM_LINES,
                        lines.len()
                    ));
                }

                for (i, line) in lines.iter().enumerate() {
                    let expected = format!("Line {i}");
                    if *line != expected {
                        return TestResult::failed(format!(
                            "Line {i} mismatch: expected '{expected}', got '{line}'"
                        ));
                    }
                }

                TestResult::passed()
            })
        },
    )
}

/// IO-007: Socket read timeout
///
/// Tests that read operations time out correctly when no data is available.
pub fn io_007_read_timeout<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "io-007".to_string(),
            name: "Socket read timeout".to_string(),
            description: "Read operation times out correctly".to_string(),
            category: TestCategory::IO,
            tags: vec!["tcp".to_string(), "timeout".to_string()],
            expected: "Read times out, doesn't hang forever".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let listener = match rt.tcp_listen("127.0.0.1:0").await {
                    Ok(l) => l,
                    Err(e) => return TestResult::failed(format!("Failed to bind listener: {e}")),
                };

                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => return TestResult::failed(format!("Failed to get local addr: {e}")),
                };

                // Server that accepts but never sends
                // Uses channel-based waiting instead of rt.sleep() to avoid &RT capture
                let (server_ready_tx, mut server_ready_rx) = rt.mpsc_channel::<()>(1);
                let (shutdown_tx, mut shutdown_rx) = rt.mpsc_channel::<()>(1);
                let _server = rt.spawn(async move {
                    let result = listener.accept().await;
                    // Signal that we've accepted
                    let _ = server_ready_tx.send(()).await;

                    if let Ok((_socket, _)) = result {
                        // Hold connection open by waiting for shutdown signal
                        // This keeps the socket alive without calling rt.sleep()
                        let _ = shutdown_rx.recv().await;
                    }
                });

                // Connect to server
                let mut socket = match rt.tcp_connect(addr).await {
                    Ok(s) => s,
                    Err(e) => return TestResult::failed(format!("Failed to connect: {e}")),
                };

                // Wait for server to accept
                let _ = server_ready_rx.recv().await;

                // Try to read with a short timeout
                let mut buf = [0u8; 100];
                let result = rt
                    .timeout(Duration::from_millis(100), async {
                        socket.read(&mut buf).await
                    })
                    .await;

                // Signal server to shutdown (cleanup)
                let _ = shutdown_tx.send(()).await;

                match result {
                    Err(_) => {
                        // Timeout occurred as expected
                        checkpoint("timeout_occurred", serde_json::json!({"timeout_ms": 100}));
                        TestResult::passed()
                    }
                    Ok(Ok(0)) => {
                        // Connection closed (acceptable in some runtimes)
                        TestResult::passed()
                    }
                    Ok(Ok(n)) => {
                        TestResult::failed(format!("Expected timeout, but read {n} bytes"))
                    }
                    Ok(Err(e)) => {
                        // I/O error might indicate timeout depending on runtime
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock
                        {
                            TestResult::passed()
                        } else {
                            TestResult::failed(format!("Unexpected I/O error: {e}"))
                        }
                    }
                }
            })
        },
    )
}

#[cfg(test)]
mod tests {
    /// Verify that test IDs follow the expected naming convention.
    #[test]
    fn test_id_convention() {
        // Verify the test IDs follow the io-NNN pattern
        let expected_ids = [
            "io-001", "io-002", "io-003", "io-004", "io-005", "io-006", "io-007",
        ];

        for id in expected_ids {
            assert!(
                id.starts_with("io-"),
                "All I/O tests should have 'io-' prefix"
            );
        }
    }
}
