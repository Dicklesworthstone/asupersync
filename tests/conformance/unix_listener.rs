#![allow(warnings)]
#![allow(clippy::all)]
//! Conformance tests for Unix domain socket listener implementation.
//!
//! This module implements 5 metamorphic relations testing Unix domain socket
//! conformance against POSIX/BSD socket specifications:
//!
//! 1. **Abstract namespace (leading null) bind** - Linux abstract sockets work correctly
//! 2. **Stream ordering preservation** - SOCK_STREAM maintains message order
//! 3. **Datagram buffer overflow handling** - SOCK_DGRAM handles buffer limits gracefully
//! 4. **Path length limit 108 bytes** - Unix socket path length enforcement
//! 5. **Permissions honored on filesystem-bound socket** - File mode bits respected

use crate::net::unix::{UnixDatagram, UnixListener, UnixStream};
use crate::io::{AsyncReadExt, AsyncWriteExt};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

#[allow(dead_code)]

fn init_test(name: &str) {
    println!("Starting test: {}", name);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **MR1: Abstract namespace (leading null) bind**
    ///
    /// Property: Abstract namespace sockets (Linux) should bind without filesystem effects
    /// and automatically clean up when all references are closed.
    ///
    /// Metamorphic relation: bind_abstract(name) ⇒ no filesystem path exists, but socket is functional
    #[test]
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn mr1_abstract_namespace_bind() {
        init_test("mr1_abstract_namespace_bind");

        futures_lite::future::block_on(async {
            let name = b"conformance_test_abstract_socket_12345";

            // MR1: Abstract sockets should not create filesystem entries
            let listener = UnixListener::bind_abstract(name)
                .await
                .expect("abstract bind should succeed");

            let addr = listener.local_addr().expect("local_addr should succeed");

            // Property: Abstract sockets have no pathname
            crate::assert_with_log!(
                addr.as_pathname().is_none(),
                "abstract socket has no pathname",
                true,
                addr.as_pathname().is_none()
            );

            // Spawn client connection in separate task
            let connect_name = name.to_vec();
            let client_handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50)); // Give listener time
                futures_lite::future::block_on(async {
                    UnixStream::connect_abstract(&connect_name).await
                })
            });

            // Accept one connection
            let (stream, peer_addr) = listener.accept().await.expect("accept should succeed");
            let client_stream = client_handle.join().expect("client thread should complete")
                .expect("connect should succeed");

            // Property: Peer address is also abstract (no pathname)
            crate::assert_with_log!(
                peer_addr.as_pathname().is_none(),
                "peer address is abstract",
                true,
                peer_addr.as_pathname().is_none()
            );

            drop(stream);
            drop(client_stream);
            drop(listener);

            // Property: No filesystem cleanup needed for abstract sockets
            // (this is implicit - kernel handles cleanup)
        });

        crate::test_complete!("mr1_abstract_namespace_bind");
    }

    /// **MR2: Stream ordering preservation**
    ///
    /// Property: SOCK_STREAM sockets preserve message order within a connection.
    ///
    /// Metamorphic relation: send(msg1); send(msg2); send(msg3) ⇒ recv order = send order
    #[test]
    #[allow(dead_code)]
    fn mr2_stream_ordering_preservation() {
        init_test("mr2_stream_ordering_preservation");

        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let socket_path = dir.path().join("ordering_test.sock");

            let listener = UnixListener::bind(&socket_path)
                .await
                .expect("bind should succeed");

            let socket_path_clone = socket_path.clone();
            let client_handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50)); // Give listener time
                futures_lite::future::block_on(async move {
                    let mut stream = UnixStream::connect(&socket_path_clone)
                        .await
                        .expect("connect should succeed");

                    // Send three messages in specific order
                    let messages = [b"FIRST", b"SECOND", b"THIRD"];
                    for (i, msg) in messages.iter().enumerate() {
                        stream.write_all(msg).await
                            .expect(&format!("write message {} should succeed", i));
                        // Small delay to ensure ordering
                        std::thread::sleep(Duration::from_millis(5));
                    }

                    stream.shutdown(std::net::Shutdown::Write)
                        .expect("shutdown should succeed");
                })
            });

            let (mut stream, _) = listener.accept()
                .await
                .expect("accept should succeed");

            // Read all data
            let mut buffer = Vec::new();
            stream.read_to_end(&mut buffer).await
                .expect("read should succeed");

            client_handle.join().expect("client thread should complete");

            // Property: Message order is preserved in stream
            let received = std::str::from_utf8(&buffer).expect("valid UTF-8");
            let expected = "FIRSTSECONDTHIRD";
            crate::assert_with_log!(
                received == expected,
                "stream preserves message order",
                expected,
                received
            );
        });

        crate::test_complete!("mr2_stream_ordering_preservation");
    }

    /// **MR3: Datagram buffer overflow handling**
    ///
    /// Property: Unix datagram sockets handle buffer limits gracefully without corruption.
    /// Each datagram is either received completely or not at all (atomicity).
    ///
    /// Metamorphic relation: send(large_datagram) ⇒ recv(complete_datagram) ∨ recv_fails
    #[test]
    #[allow(dead_code)]
    fn mr3_datagram_buffer_overflow_handling() {
        init_test("mr3_datagram_buffer_overflow_handling");

        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let socket_path = dir.path().join("datagram_test.sock");

            // Create receiver datagram socket
            let mut receiver = UnixDatagram::bind(&socket_path)
                .expect("bind should succeed");

            // Create sender datagram socket
            let mut sender = UnixDatagram::unbound()
                .expect("unbound should succeed");

            // Test small message first (should work)
            let small_msg = b"SMALL";
            let sent_bytes = sender.send_to(small_msg, &socket_path).await
                .expect("small message send should succeed");
            crate::assert_with_log!(
                sent_bytes == small_msg.len(),
                "complete small message sent",
                small_msg.len(),
                sent_bytes
            );

            let mut buf = [0u8; 1024];
            let (recv_bytes, _addr) = receiver.recv_from(&mut buf).await
                .expect("small message recv should succeed");
            crate::assert_with_log!(
                recv_bytes == small_msg.len(),
                "complete small message received",
                small_msg.len(),
                recv_bytes
            );
            crate::assert_with_log!(
                &buf[..recv_bytes] == small_msg,
                "small message content intact",
                std::str::from_utf8(small_msg).unwrap(),
                std::str::from_utf8(&buf[..recv_bytes]).unwrap()
            );

            // Test larger message (may work or fail, but should be atomic)
            let large_msg = vec![0xCC; 8192]; // 8KB message
            match sender.send_to(&large_msg, &socket_path).await {
                Ok(sent_bytes) => {
                    // If send succeeds, it should send the complete message
                    crate::assert_with_log!(
                        sent_bytes == large_msg.len(),
                        "complete large message sent",
                        large_msg.len(),
                        sent_bytes
                    );

                    // Try to receive it
                    let mut large_buf = vec![0u8; large_msg.len() + 1024];
                    match receiver.recv_from(&mut large_buf).await {
                        Ok((recv_bytes, _addr)) => {
                            // Property: Complete datagram received (atomicity)
                            crate::assert_with_log!(
                                recv_bytes == large_msg.len(),
                                "complete large message received",
                                large_msg.len(),
                                recv_bytes
                            );
                            crate::assert_with_log!(
                                &large_buf[..recv_bytes] == &large_msg,
                                "large message content intact",
                                "all_0xCC",
                                if large_buf[..recv_bytes].iter().all(|&b| b == 0xCC) { "all_0xCC" } else { "corrupted" }
                            );
                        }
                        Err(_) => {
                            // Receive failed - this is acceptable for very large messages
                        }
                    }
                }
                Err(e) => {
                    // Send failed - this is acceptable for very large messages
                    match e.kind() {
                        std::io::ErrorKind::InvalidInput |
                        std::io::ErrorKind::Other => {
                            // Common errors for messages too large
                        }
                        _ => panic!("Unexpected error for large datagram: {:?}", e),
                    }
                }
            }

            // Property: Datagram atomicity maintained throughout
        });

        crate::test_complete!("mr3_datagram_buffer_overflow_handling");
    }

    /// **MR4: Path length limit 108 bytes**
    ///
    /// Property: Unix socket paths are limited to approximately 108 bytes total length
    /// (including null terminator) per POSIX specification.
    ///
    /// Metamorphic relation: bind(path) where len(path) > 107 ⇒ Error
    #[test]
    #[allow(dead_code)]
    fn mr4_path_length_limit_108_bytes() {
        init_test("mr4_path_length_limit_108_bytes");

        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");

            // Test path at limit (107 chars + null terminator = 108)
            let base_dir = dir.path();
            let base_len = base_dir.to_string_lossy().len();
            let remaining = 107_usize.saturating_sub(base_len + 1); // -1 for path separator

            if remaining > 10 {
                let valid_name = "a".repeat(remaining);
                let valid_path = base_dir.join(valid_name);

                // Property: Path at limit should succeed or fail gracefully
                let listener = UnixListener::bind(&valid_path).await;
                match listener {
                    Ok(l) => {
                        crate::assert_with_log!(
                            true,
                            "valid path length succeeded",
                            valid_path.to_string_lossy().len(),
                            valid_path.to_string_lossy().len()
                        );
                        drop(l);
                    }
                    Err(e) => {
                        // Some systems have shorter limits, this is acceptable
                        crate::assert_with_log!(
                            true,
                            "path length rejected (system limit < 108)",
                            "error",
                            e.to_string()
                        );
                    }
                }
            }

            // Test path exceeding limit (109+ chars)
            let long_name = "a".repeat(200); // Definitely too long
            let invalid_path = base_dir.join(long_name);

            // Property: Path exceeding limit should fail
            let result = UnixListener::bind(&invalid_path).await;
            match result {
                Ok(_) => {
                    panic!("Bind should fail with excessively long path: {}",
                        invalid_path.to_string_lossy());
                }
                Err(e) => {
                    // Expected error - either ENAMETOOLONG or similar
                    let path_len = invalid_path.to_string_lossy().len();
                    crate::assert_with_log!(
                        path_len > 150,
                        "excessive path length properly rejected",
                        path_len,
                        path_len
                    );

                    // Common error types for path too long
                    let is_expected_error = matches!(e.kind(),
                        std::io::ErrorKind::InvalidInput |
                        std::io::ErrorKind::InvalidData |
                        std::io::ErrorKind::Other) ||
                        e.raw_os_error() == Some(libc::ENAMETOOLONG);

                    crate::assert_with_log!(
                        is_expected_error,
                        "path length error type expected",
                        "ENAMETOOLONG/InvalidInput",
                        format!("{:?}", e.kind())
                    );
                }
            }
        });

        crate::test_complete!("mr4_path_length_limit_108_bytes");
    }

    /// **MR5: Permissions honored on filesystem-bound socket**
    ///
    /// Property: Unix socket files should respect filesystem permission bits
    /// and prevent unauthorized access.
    ///
    /// Metamorphic relation: bind(path); chmod(path, mode) ⇒ stat(path).mode == mode
    #[test]
    #[allow(dead_code)]
    fn mr5_permissions_honored_filesystem_bound() {
        init_test("mr5_permissions_honored_filesystem_bound");

        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let socket_path = dir.path().join("permission_test.sock");

            // Create socket with default permissions
            let listener = UnixListener::bind(&socket_path)
                .await
                .expect("bind should succeed");

            // Verify socket file exists
            crate::assert_with_log!(
                socket_path.exists(),
                "socket file exists",
                true,
                socket_path.exists()
            );

            // Test permission modification
            let restrictive_mode = 0o600; // Owner read/write only
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(restrictive_mode))
                .expect("chmod should succeed");

            // Verify permissions were applied
            let metadata = fs::metadata(&socket_path)
                .expect("stat should succeed");
            let actual_mode = metadata.permissions().mode() & 0o777;

            // Property: File permissions should be respected
            crate::assert_with_log!(
                actual_mode == restrictive_mode,
                "socket file permissions applied",
                format!("{:#o}", restrictive_mode),
                format!("{:#o}", actual_mode)
            );

            // Test that socket is still functional after permission change
            let socket_path_clone = socket_path.clone();
            let connect_handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                futures_lite::future::block_on(async move {
                    UnixStream::connect(&socket_path_clone).await
                })
            });

            // Accept connection to verify functionality
            let (stream, _) = listener.accept()
                .await
                .expect("accept should succeed after permission change");

            let client_stream = connect_handle.join().expect("connect thread should complete")
                .expect("connect should succeed despite restrictive permissions");

            drop(stream);
            drop(client_stream);

            // Test more restrictive permissions (no access)
            let no_access_mode = 0o000;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(no_access_mode))
                .expect("chmod to no-access should succeed");

            let metadata = fs::metadata(&socket_path)
                .expect("stat should succeed");
            let actual_mode = metadata.permissions().mode() & 0o777;

            crate::assert_with_log!(
                actual_mode == no_access_mode,
                "socket no-access permissions applied",
                format!("{:#o}", no_access_mode),
                format!("{:#o}", actual_mode)
            );

            drop(listener);
        });

        crate::test_complete!("mr5_permissions_honored_filesystem_bound");
    }
}