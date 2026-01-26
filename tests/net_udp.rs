#![allow(missing_docs)]
//! UDP Integration Tests
//!
//! End-to-end integration tests for UDP primitives with real I/O.
//!
//! Test Coverage:
//! - NET-UDP-001: Basic send/recv
//! - NET-UDP-002: Connected mode
//! - NET-UDP-003: Multiple datagrams
//! - NET-UDP-004: Local address binding
//! - NET-UDP-005: Large datagram (within MTU)

#[macro_use]
mod common;

use asupersync::net::UdpSocket;
use common::*;
use futures_lite::future::block_on;
use std::io;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

/// NET-UDP-001: Basic send/recv
///
/// Verifies that datagrams can be sent and received.
#[test]
fn net_udp_001_basic_send_recv() {
    init_test("net_udp_001_basic_send_recv");

    let result = block_on(async {
        // Create two sockets
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;
        tracing::info!(?server_addr, "server bound");

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;
        let client_addr = client.local_addr()?;
        tracing::info!(?client_addr, "client bound");

        // Send from client to server
        let msg = b"hello udp";
        let sent = client.send_to(msg, server_addr).await?;
        tracing::info!(sent, "client sent datagram");
        assert_eq!(sent, msg.len(), "should send full datagram");

        // Receive on server
        let mut buf = [0u8; 1024];
        let (received, from_addr) = server.recv_from(&mut buf).await?;
        tracing::info!(received, ?from_addr, "server received datagram");

        assert_eq!(received, msg.len(), "should receive full datagram");
        assert_eq!(&buf[..received], msg, "data should match");
        assert_eq!(from_addr, client_addr, "source should be client");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "basic send/recv should succeed: {:?}",
        result
    );
    test_complete!("net_udp_001_basic_send_recv");
}

/// NET-UDP-002: Connected mode
///
/// Verifies that connected UDP sockets work correctly.
#[test]
fn net_udp_002_connected_mode() {
    init_test("net_udp_002_connected_mode");

    let result = block_on(async {
        // Create two sockets
        let mut a = UdpSocket::bind("127.0.0.1:0").await?;
        let a_addr = a.local_addr()?;

        let mut b = UdpSocket::bind("127.0.0.1:0").await?;
        let b_addr = b.local_addr()?;

        // Connect both to each other
        a.connect(b_addr).await?;
        b.connect(a_addr).await?;
        tracing::info!("sockets connected");

        // Send using connected send (not send_to)
        let msg = b"ping";
        let sent = a.send(msg).await?;
        assert_eq!(sent, msg.len());
        tracing::info!("a sent ping");

        // Receive using connected recv
        let mut buf = [0u8; 1024];
        let received = b.recv(&mut buf).await?;
        assert_eq!(received, msg.len());
        assert_eq!(&buf[..received], msg);
        tracing::info!("b received ping");

        // Send back
        let reply = b"pong";
        let sent = b.send(reply).await?;
        assert_eq!(sent, reply.len());
        tracing::info!("b sent pong");

        // Receive reply
        let received = a.recv(&mut buf).await?;
        assert_eq!(received, reply.len());
        assert_eq!(&buf[..received], reply);
        tracing::info!("a received pong");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "connected mode should succeed: {:?}",
        result
    );
    test_complete!("net_udp_002_connected_mode");
}

/// NET-UDP-003: Multiple datagrams
///
/// Verifies that multiple datagrams can be sent and received.
#[test]
fn net_udp_003_multiple_datagrams() {
    init_test("net_udp_003_multiple_datagrams");

    const NUM_DATAGRAMS: usize = 10;

    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;

        // Send multiple datagrams
        for i in 0..NUM_DATAGRAMS {
            let msg = format!("datagram {}", i);
            let sent = client.send_to(msg.as_bytes(), server_addr).await?;
            assert_eq!(sent, msg.len());
            tracing::debug!(i, "sent datagram");
        }
        tracing::info!(count = NUM_DATAGRAMS, "all datagrams sent");

        // Receive all (or as many as we can)
        let mut received_count = 0;
        let mut buf = [0u8; 1024];

        // Set a timeout for receiving
        for _ in 0..NUM_DATAGRAMS {
            match tokio_timeout(Duration::from_millis(100), server.recv_from(&mut buf)).await {
                Ok(Ok((n, _addr))) => {
                    let msg = std::str::from_utf8(&buf[..n]).unwrap_or("<invalid>");
                    tracing::debug!(received_count, msg, "received datagram");
                    received_count += 1;
                }
                Ok(Err(e)) => {
                    tracing::warn!(?e, "recv error");
                    break;
                }
                Err(_) => {
                    tracing::debug!("timeout waiting for datagram");
                    break;
                }
            }
        }

        tracing::info!(received_count, "datagrams received");

        // UDP may drop some, but we should get at least some
        assert!(received_count > 0, "should receive at least some datagrams");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "multiple datagrams test should complete: {:?}",
        result
    );
    test_complete!("net_udp_003_multiple_datagrams");
}

/// Simple timeout helper for tests
async fn tokio_timeout<F: std::future::Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, ()> {
    use std::future::poll_fn;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    let start = std::time::Instant::now();
    let mut fut = pin!(future);

    poll_fn(|cx| {
        if start.elapsed() > duration {
            return Poll::Ready(Err(()));
        }

        match fut.as_mut().poll(cx) {
            Poll::Ready(val) => Poll::Ready(Ok(val)),
            Poll::Pending => {
                // Wake immediately to retry
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    })
    .await
}

/// NET-UDP-004: Local address binding
///
/// Verifies that local_addr() returns correct information.
#[test]
fn net_udp_004_local_addr() {
    init_test("net_udp_004_local_addr");

    let result = block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;

        assert!(addr.ip().is_loopback(), "address should be loopback");
        assert!(addr.port() > 0, "port should be assigned");

        tracing::info!(?addr, "socket local address");

        // Bind to specific port
        let socket2 = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let addr2 = socket2.local_addr()?;

        assert!(addr2.ip().is_loopback(), "address should be loopback");
        assert!(addr2.port() > 0, "port should be assigned");
        assert_ne!(addr.port(), addr2.port(), "ports should be different");

        tracing::info!(?addr2, "socket2 local address");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "local addr test should complete: {:?}",
        result
    );
    test_complete!("net_udp_004_local_addr");
}

/// NET-UDP-005: Large datagram
///
/// Verifies that larger datagrams (within typical MTU) work correctly.
#[test]
fn net_udp_005_large_datagram() {
    init_test("net_udp_005_large_datagram");

    // Use a size that's within typical MTU (1500 bytes Ethernet, ~1472 for UDP)
    const DATAGRAM_SIZE: usize = 1400;

    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;

        // Create large datagram with pattern
        let data: Vec<u8> = (0..DATAGRAM_SIZE).map(|i| (i % 256) as u8).collect();

        // Send
        let sent = client.send_to(&data, server_addr).await?;
        assert_eq!(sent, DATAGRAM_SIZE, "should send full datagram");
        tracing::info!(size = DATAGRAM_SIZE, "sent large datagram");

        // Receive
        let mut buf = vec![0u8; DATAGRAM_SIZE + 100]; // Extra space
        let (received, _addr) = server.recv_from(&mut buf).await?;
        tracing::info!(received, "received large datagram");

        assert_eq!(received, DATAGRAM_SIZE, "should receive full datagram");
        assert_eq!(&buf[..received], &data[..], "data should match");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "large datagram test should complete: {:?}",
        result
    );
    test_complete!("net_udp_005_large_datagram");
}

/// NET-UDP-006: Bidirectional communication
///
/// Verifies that UDP sockets can communicate in both directions.
#[test]
fn net_udp_006_bidirectional() {
    init_test("net_udp_006_bidirectional");

    let result = block_on(async {
        let mut socket_a = UdpSocket::bind("127.0.0.1:0").await?;
        let addr_a = socket_a.local_addr()?;

        let mut socket_b = UdpSocket::bind("127.0.0.1:0").await?;
        let addr_b = socket_b.local_addr()?;

        // A sends to B
        let msg_a = b"message from A";
        socket_a.send_to(msg_a, addr_b).await?;
        tracing::info!("A sent message");

        // B receives
        let mut buf = [0u8; 1024];
        let (n, from) = socket_b.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], msg_a);
        assert_eq!(from, addr_a);
        tracing::info!("B received from A");

        // B sends to A
        let msg_b = b"message from B";
        socket_b.send_to(msg_b, addr_a).await?;
        tracing::info!("B sent message");

        // A receives
        let (n, from) = socket_a.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], msg_b);
        assert_eq!(from, addr_b);
        tracing::info!("A received from B");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "bidirectional test should complete: {:?}",
        result
    );
    test_complete!("net_udp_006_bidirectional");
}
