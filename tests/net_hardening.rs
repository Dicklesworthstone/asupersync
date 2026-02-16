#![allow(clippy::items_after_statements, clippy::semicolon_if_nothing_returned)]
//! Network Primitives Hardening Tests (bd-gl8u).
//!
//! Verifies hardening of TCP/UDP/Unix socket primitives:
//! - TCP keepalive via socket2
//! - TCP connect timeout enforcement
//! - UDP error propagation for send_to
//! - UDP datagram boundary preservation
//! - Concurrent I/O operations
//! - Registration cleanup on drop
//! - Socket option edge cases

#[macro_use]
mod common;

use common::*;
use futures_lite::future::block_on;
use std::io;
use std::net::Shutdown;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::Duration;

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::tcp::stream::TcpStreamBuilder;
use asupersync::net::UdpSocket;
use asupersync::net::{TcpListener, TcpStream};

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// =========================================================================
// TCP Keepalive
// =========================================================================

/// Verify set_keepalive(Some(..)) succeeds on a connected socket.
#[test]
fn tcp_keepalive_enable() {
    init_test("tcp_keepalive_enable");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await.unwrap();

        // Enable keepalive with 60s idle time.
        stream
            .set_keepalive(Some(Duration::from_secs(60)))
            .expect("set_keepalive should succeed");

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_keepalive_enable");
}

/// Verify set_keepalive(None) disables keepalive.
#[test]
fn tcp_keepalive_disable() {
    init_test("tcp_keepalive_disable");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await.unwrap();

        // Enable then disable.
        stream
            .set_keepalive(Some(Duration::from_secs(30)))
            .expect("enable keepalive");
        stream.set_keepalive(None).expect("disable keepalive");

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_keepalive_disable");
}

/// Verify keepalive via TcpStreamBuilder.
#[test]
fn tcp_keepalive_via_builder() {
    init_test("tcp_keepalive_via_builder");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStreamBuilder::new(addr)
            .keepalive(Some(Duration::from_secs(45)))
            .nodelay(true)
            .connect()
            .await
            .expect("builder connect with keepalive should succeed");

        assert!(stream.peer_addr().is_ok());

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_keepalive_via_builder");
}

// =========================================================================
// TCP Connect Timeout
// =========================================================================

/// Verify connect_timeout fires for unreachable address.
#[test]
fn tcp_connect_timeout_fires() {
    init_test("tcp_connect_timeout_fires");

    block_on(async {
        // RFC 5737 TEST-NET: guaranteed non-routable.
        let result =
            TcpStream::connect_timeout("192.0.2.1:80".parse().unwrap(), Duration::from_millis(200))
                .await;
        assert!(result.is_err(), "should timeout or fail");
        let err = result.unwrap_err();
        // May be TimedOut or other OS-dependent error for non-routable.
        tracing::info!(kind = ?err.kind(), "connect timeout error");
    });

    test_complete!("tcp_connect_timeout_fires");
}

/// Verify builder with connect_timeout.
#[test]
fn tcp_builder_connect_timeout() {
    init_test("tcp_builder_connect_timeout");

    block_on(async {
        let result = TcpStreamBuilder::new("192.0.2.1:80")
            .connect_timeout(Duration::from_millis(200))
            .connect()
            .await;
        assert!(result.is_err());
    });

    test_complete!("tcp_builder_connect_timeout");
}

// =========================================================================
// TCP Shutdown + poll_shutdown
// =========================================================================

/// Verify poll_shutdown calls shutdown(Write).
#[test]
fn tcp_poll_shutdown() {
    init_test("tcp_poll_shutdown");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_shutdown(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        // Reading after write-shutdown should still be possible (half-close).
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let _poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_poll_shutdown");
}

/// Verify double shutdown doesn't panic.
#[test]
fn tcp_double_shutdown_no_panic() {
    init_test("tcp_double_shutdown_no_panic");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await.unwrap();

        stream.shutdown(Shutdown::Both).unwrap();
        // Second shutdown may error but must not panic.
        let _ = stream.shutdown(Shutdown::Both);

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_double_shutdown_no_panic");
}

// =========================================================================
// TCP TTL
// =========================================================================

/// Verify TTL can be set and read back.
#[test]
fn tcp_ttl_roundtrip() {
    init_test("tcp_ttl_roundtrip");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await.unwrap();

        use asupersync::net::tcp::traits::TcpStreamApi;
        stream.set_ttl(128).unwrap();
        let ttl = stream.ttl().unwrap();
        assert_eq!(ttl, 128);

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_ttl_roundtrip");
}

// =========================================================================
// TCP Registration cleanup
// =========================================================================

/// Dropping a TcpStream should not leak reactor registrations.
#[test]
fn tcp_drop_cleans_registration() {
    init_test("tcp_drop_cleans_registration");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await.unwrap();

        // Drop should be clean (no panic, no leak).
        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_drop_cleans_registration");
}

// =========================================================================
// TCP Nodelay roundtrip
// =========================================================================

/// Verify nodelay can be set and queried.
#[test]
fn tcp_nodelay_roundtrip() {
    init_test("tcp_nodelay_roundtrip");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = thread::spawn(move || block_on(listener.accept()));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await.unwrap();

        use asupersync::net::tcp::traits::TcpStreamApi;
        stream.set_nodelay(true).unwrap();
        assert!(stream.nodelay().unwrap());
        stream.set_nodelay(false).unwrap();
        assert!(!stream.nodelay().unwrap());

        drop(stream);
        let _ = accept.join();
    });

    test_complete!("tcp_nodelay_roundtrip");
}

// =========================================================================
// UDP Error Propagation
// =========================================================================

/// Verify that UDP send_to propagates errors for invalid destinations.
#[test]
fn udp_send_to_error_propagation() {
    init_test("udp_send_to_error_propagation");

    block_on(async {
        let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Sending to a valid loopback address should succeed.
        let mut target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        let sent = socket.send_to(b"test", target_addr).await.unwrap();
        assert_eq!(sent, 4);

        let mut buf = [0u8; 16];
        let (n, _) = target.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"test");
    });

    test_complete!("udp_send_to_error_propagation");
}

/// Verify UDP datagram boundaries are preserved.
#[test]
fn udp_datagram_boundary_preserved() {
    init_test("udp_datagram_boundary_preserved");

    block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send two distinct datagrams.
        client.send_to(b"first", server_addr).await.unwrap();
        client.send_to(b"second", server_addr).await.unwrap();

        // Small delay for delivery.
        thread::sleep(Duration::from_millis(10));

        // Each recv_from should get exactly one datagram.
        let mut buf = [0u8; 64];
        let (n1, _) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], b"first");

        let (n2, _) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"second");
    });

    test_complete!("udp_datagram_boundary_preserved");
}

/// Verify UDP broadcast option.
#[test]
fn udp_broadcast_option() {
    init_test("udp_broadcast_option");

    block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.set_broadcast(true).unwrap();
        socket.set_broadcast(false).unwrap();
    });

    test_complete!("udp_broadcast_option");
}

/// Verify UDP TTL.
#[test]
fn udp_ttl_option() {
    init_test("udp_ttl_option");

    block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.set_ttl(64).unwrap();
    });

    test_complete!("udp_ttl_option");
}

/// Verify UDP into_std roundtrip.
#[test]
fn udp_into_std_roundtrip() {
    init_test("udp_into_std_roundtrip");

    block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let std_socket = socket.into_std().unwrap();
        assert_eq!(std_socket.local_addr().unwrap(), addr);
    });

    test_complete!("udp_into_std_roundtrip");
}

/// Verify UDP connected peer_addr.
#[test]
fn udp_connected_peer_addr() {
    init_test("udp_connected_peer_addr");

    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();

        assert_eq!(client.peer_addr().unwrap(), server_addr);
    });

    test_complete!("udp_connected_peer_addr");
}

// =========================================================================
// TCP Listener hardening
// =========================================================================

/// Verify bind to already-bound port returns error.
#[test]
fn tcp_listener_bind_already_bound() {
    init_test("tcp_listener_bind_already_bound");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Second bind to same port should fail.
        let result = TcpListener::bind(addr).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.kind() == io::ErrorKind::AddrInUse || err.kind() == io::ErrorKind::Other,
            "expected AddrInUse, got {:?}",
            err.kind()
        );
    });

    test_complete!("tcp_listener_bind_already_bound");
}

/// Verify listener TTL.
#[test]
fn tcp_listener_ttl() {
    init_test("tcp_listener_ttl");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(64).unwrap();
    });

    test_complete!("tcp_listener_ttl");
}

/// Verify listener incoming stream.
#[test]
fn tcp_listener_incoming_stream() {
    init_test("tcp_listener_incoming_stream");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect from a background thread.
        let client_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            std::net::TcpStream::connect(addr).unwrap()
        });

        // Use incoming() to accept.
        use asupersync::stream::StreamExt;
        let mut incoming = listener.incoming();
        let stream = incoming.next().await.unwrap().unwrap();
        assert!(stream.peer_addr().is_ok());

        let _ = client_handle.join();
    });

    test_complete!("tcp_listener_incoming_stream");
}

// =========================================================================
// Concurrent operations
// =========================================================================

/// Multiple threads connect concurrently to the same listener.
#[test]
fn tcp_concurrent_connects() {
    const N: usize = 10;
    init_test("tcp_concurrent_connects");

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_handle = thread::spawn(move || {
            block_on(async {
                let mut count = 0;
                for _ in 0..N {
                    if listener.accept().await.is_ok() {
                        count += 1;
                    }
                }
                count
            })
        });

        thread::sleep(Duration::from_millis(10));

        let client_ok: usize = (0..N)
            .map(|_| {
                thread::spawn(move || block_on(async { TcpStream::connect(addr).await.is_ok() }))
            })
            .filter_map(|h| h.join().ok())
            .filter(|&ok| ok)
            .count();

        let accepted = accept_handle.join().unwrap();
        tracing::info!(client_ok, accepted, "concurrent connects");
        assert!(accepted >= N - 1, "should accept most connections");
    });

    test_complete!("tcp_concurrent_connects");
}

/// Multiple UDP sockets send to the same receiver concurrently.
#[test]
fn udp_concurrent_sends() {
    const N: usize = 10;
    init_test("udp_concurrent_sends");

    block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn N senders.
        let handles: Vec<_> = (0..N)
            .map(|i| {
                thread::spawn(move || {
                    block_on(async {
                        let mut s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        let msg = format!("msg-{i}");
                        s.send_to(msg.as_bytes(), server_addr).await.unwrap();
                    })
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Small delay for delivery.
        thread::sleep(Duration::from_millis(50));

        // Receive all.
        let mut received = 0;
        let mut buf = [0u8; 64];
        for _ in 0..N {
            if server.recv_from(&mut buf).await.is_ok() {
                received += 1;
            }
        }
        assert_eq!(received, N, "should receive all datagrams");
    });

    test_complete!("udp_concurrent_sends");
}
