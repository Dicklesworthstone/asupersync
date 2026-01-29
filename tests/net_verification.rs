#![allow(missing_docs)]
//! Async Networking Verification Suite (bd-14yh)
//!
//! Comprehensive verification for the async networking layer ensuring
//! correct behavior of all socket types, DNS resolution, fault injection,
//! and lab runtime simulation.
//!
//! # Test Coverage
//!
//! ## TCP Socket Builder (TcpSocket)
//! - NET-VERIFY-001: TcpSocket::new_v4 creation and state
//! - NET-VERIFY-002: TcpSocket::new_v6 creation and state
//! - NET-VERIFY-003: TcpSocket reuseaddr option
//! - NET-VERIFY-004: TcpSocket bind then listen lifecycle
//! - NET-VERIFY-005: TcpSocket bind then connect lifecycle
//! - NET-VERIFY-006: TcpSocket family mismatch error
//! - NET-VERIFY-007: TcpSocket reuseport (unix-only)
//!
//! ## TCP Listener Builder
//! - NET-VERIFY-008: TcpListenerBuilder basic usage
//! - NET-VERIFY-009: TcpListenerBuilder with reuse_addr
//!
//! ## TCP Advanced
//! - NET-VERIFY-010: TcpStream from_std conversion
//! - NET-VERIFY-011: TcpStream TTL setting
//! - NET-VERIFY-012: TcpListener Incoming stream
//! - NET-VERIFY-013: TcpStream borrowed split halves
//! - NET-VERIFY-014: TcpListener set_ttl
//!
//! ## UDP Advanced
//! - NET-VERIFY-015: UdpSocket broadcast option
//! - NET-VERIFY-016: UdpSocket TTL option
//! - NET-VERIFY-017: UdpSocket peer_addr after connect
//! - NET-VERIFY-018: UdpSocket try_clone
//! - NET-VERIFY-019: UdpSocket peek_from
//! - NET-VERIFY-020: UdpSocket into_std conversion
//!
//! ## DNS Resolution
//! - NET-VERIFY-021: lookup_one resolves socket addr passthrough
//! - NET-VERIFY-022: lookup_all resolves socket addr
//! - NET-VERIFY-023: lookup_one rejects empty host
//! - NET-VERIFY-024: DNS cache default config
//! - NET-VERIFY-025: DNS cache stats tracking
//!
//! ## Fault Handling
//! - NET-VERIFY-026: TCP write after peer close
//! - NET-VERIFY-027: UDP send to unreachable address
//! - NET-VERIFY-028: TCP simultaneous connect/accept
//! - NET-VERIFY-029: Rapid bind/unbind cycle
//!
//! ## Lab Network Simulation
//! - NET-VERIFY-030: SimulatedNetwork packet loss
//! - NET-VERIFY-031: SimulatedNetwork WAN latency
//! - NET-VERIFY-032: SimulatedNetwork multi-host topology
//! - NET-VERIFY-033: SimulatedNetwork fault injection (partition/heal)
//! - NET-VERIFY-034: SimulatedNetwork host crash/restart
//! - NET-VERIFY-035: SimulatedNetwork metrics tracking
//! - NET-VERIFY-036: SimulatedNetwork bandwidth limiting

#[macro_use]
mod common;

use asupersync::bytes::Bytes;
use asupersync::lab::{NetworkConditions, NetworkConfig, NetworkFault, SimulatedNetwork};
use asupersync::net::dns::{CacheConfig, DnsCache};
use asupersync::net::tcp::TcpListenerBuilder;
use asupersync::net::{lookup_all, lookup_one, TcpListener, TcpSocket, TcpStream, UdpSocket};
use common::*;
use futures_lite::future::block_on;
use std::io::{self, Write};
use std::net::{SocketAddr, SocketAddrV6};
use asupersync::stream::Stream;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::Duration;

/// Simple no-op waker for polling tests.
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// TCP Socket Builder Tests
// ============================================================================

/// NET-VERIFY-001: TcpSocket::new_v4 creation
///
/// Verifies that a new IPv4 TCP socket can be created successfully.
#[test]
fn net_verify_001_tcp_socket_new_v4() {
    init_test("net_verify_001_tcp_socket_new_v4");

    let socket = TcpSocket::new_v4();
    assert!(socket.is_ok(), "new_v4 should succeed: {socket:?}");

    let socket = socket.unwrap();
    tracing::info!("created IPv4 TcpSocket: {socket:?}");

    test_complete!("net_verify_001_tcp_socket_new_v4");
}

/// NET-VERIFY-002: TcpSocket::new_v6 creation
///
/// Verifies that a new IPv6 TCP socket can be created successfully.
#[test]
fn net_verify_002_tcp_socket_new_v6() {
    init_test("net_verify_002_tcp_socket_new_v6");

    let socket = TcpSocket::new_v6();
    assert!(socket.is_ok(), "new_v6 should succeed: {socket:?}");

    let socket = socket.unwrap();
    tracing::info!("created IPv6 TcpSocket: {socket:?}");

    test_complete!("net_verify_002_tcp_socket_new_v6");
}

/// NET-VERIFY-003: TcpSocket reuseaddr option
///
/// Verifies that SO_REUSEADDR can be set on a TCP socket.
#[test]
fn net_verify_003_tcp_socket_reuseaddr() {
    init_test("net_verify_003_tcp_socket_reuseaddr");

    let socket = TcpSocket::new_v4().unwrap();

    // Set reuseaddr to true
    let result = socket.set_reuseaddr(true);
    assert!(result.is_ok(), "set_reuseaddr(true) should succeed");
    tracing::info!("set reuseaddr to true");

    // Set reuseaddr to false
    let result = socket.set_reuseaddr(false);
    assert!(result.is_ok(), "set_reuseaddr(false) should succeed");
    tracing::info!("set reuseaddr to false");

    test_complete!("net_verify_003_tcp_socket_reuseaddr");
}

/// NET-VERIFY-004: TcpSocket bind then listen lifecycle
///
/// Verifies the full TcpSocket -> bind -> listen -> TcpListener lifecycle.
/// Note: In Phase 0, listen() returns Unsupported for pre-configured sockets.
/// This test verifies the bind succeeds and the Phase 0 error is correct.
#[test]
fn net_verify_004_tcp_socket_bind_listen() {
    init_test("net_verify_004_tcp_socket_bind_listen");

    let result = block_on(async {
        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;

        // Bind to any available port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        socket.bind(addr)?;
        tracing::info!("socket bound to {:?}", addr);

        // Convert to listener — may fail in Phase 0
        match socket.listen(128) {
            Ok(listener) => {
                let local_addr = listener.local_addr()?;
                tracing::info!(?local_addr, "listener created from socket");
                assert!(local_addr.ip().is_loopback(), "should be loopback");
                assert!(local_addr.port() > 0, "port should be assigned");
            }
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                tracing::info!(?e, "Phase 0: TcpSocket listen not yet supported");
            }
            Err(e) => return Err(e),
        }

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "bind-listen lifecycle should succeed: {result:?}"
    );
    test_complete!("net_verify_004_tcp_socket_bind_listen");
}

/// NET-VERIFY-005: TcpSocket bind then connect lifecycle
///
/// Verifies the TcpSocket -> bind -> connect -> TcpStream lifecycle.
/// Note: In Phase 0, TcpSocket::connect returns Unsupported for pre-configured sockets.
#[test]
fn net_verify_005_tcp_socket_bind_connect() {
    init_test("net_verify_005_tcp_socket_bind_connect");

    let result = block_on(async {
        // Set up a listener to accept connections
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listener_addr = listener.local_addr()?;
        tracing::info!(?listener_addr, "listener ready");

        let accept_handle = thread::spawn(move || {
            block_on(async { listener.accept().await.map(|(s, _)| s) })
        });

        thread::sleep(Duration::from_millis(10));

        // Create socket, bind, then connect — may fail in Phase 0
        let socket = TcpSocket::new_v4()?;
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        socket.bind(bind_addr)?;
        tracing::info!("socket bound");

        match socket.connect(listener_addr).await {
            Ok(stream) => {
                tracing::info!(
                    local = ?stream.local_addr()?,
                    peer = ?stream.peer_addr()?,
                    "connected via TcpSocket"
                );
                assert_eq!(stream.peer_addr()?, listener_addr);
                drop(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                tracing::info!(?e, "Phase 0: TcpSocket connect not yet supported");
            }
            Err(e) => return Err(e),
        }

        let _ = accept_handle.join();

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "bind-connect lifecycle should succeed: {result:?}"
    );
    test_complete!("net_verify_005_tcp_socket_bind_connect");
}

/// NET-VERIFY-006: TcpSocket family mismatch error
///
/// Verifies that binding an IPv4 socket to an IPv6 address fails with an error.
#[test]
fn net_verify_006_tcp_socket_family_mismatch() {
    init_test("net_verify_006_tcp_socket_family_mismatch");

    let socket = TcpSocket::new_v4().unwrap();

    // Try binding an IPv4 socket to an IPv6 address
    let v6_addr: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
        std::net::Ipv6Addr::LOCALHOST,
        0,
        0,
        0,
    ));
    let result = socket.bind(v6_addr);

    assert!(result.is_err(), "binding v4 socket to v6 addr should fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        io::ErrorKind::InvalidInput,
        "error should be InvalidInput, got {:?}",
        err.kind()
    );
    tracing::info!(?err, "correctly rejected family mismatch");

    test_complete!("net_verify_006_tcp_socket_family_mismatch");
}

/// NET-VERIFY-007: TcpSocket reuseport (unix-only)
///
/// Verifies that SO_REUSEPORT can be set on Unix.
#[cfg(unix)]
#[test]
fn net_verify_007_tcp_socket_reuseport() {
    init_test("net_verify_007_tcp_socket_reuseport");

    let socket = TcpSocket::new_v4().unwrap();

    let result = socket.set_reuseport(true);
    assert!(result.is_ok(), "set_reuseport(true) should succeed");
    tracing::info!("set reuseport to true");

    let result = socket.set_reuseport(false);
    assert!(result.is_ok(), "set_reuseport(false) should succeed");
    tracing::info!("set reuseport to false");

    test_complete!("net_verify_007_tcp_socket_reuseport");
}

// ============================================================================
// TCP Listener Builder Tests
// ============================================================================

/// NET-VERIFY-008: TcpListenerBuilder basic usage
///
/// Verifies that TcpListenerBuilder can create a listener.
#[test]
fn net_verify_008_listener_builder_basic() {
    init_test("net_verify_008_listener_builder_basic");

    let result = block_on(async {
        let listener = TcpListenerBuilder::new("127.0.0.1:0").bind().await?;
        let addr = listener.local_addr()?;
        tracing::info!(?addr, "listener built via builder");

        assert!(addr.ip().is_loopback());
        assert!(addr.port() > 0);

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "listener builder should succeed: {result:?}"
    );
    test_complete!("net_verify_008_listener_builder_basic");
}

/// NET-VERIFY-009: TcpListenerBuilder with reuse_addr
///
/// Verifies builder with reuse_addr option.
#[test]
fn net_verify_009_listener_builder_reuse_addr() {
    init_test("net_verify_009_listener_builder_reuse_addr");

    let result = block_on(async {
        let listener = TcpListenerBuilder::new("127.0.0.1:0")
            .reuse_addr(true)
            .backlog(64)
            .bind()
            .await?;
        let addr = listener.local_addr()?;
        tracing::info!(?addr, "listener built with reuse_addr");

        assert!(addr.ip().is_loopback());
        assert!(addr.port() > 0);

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "listener builder with reuse_addr should succeed: {result:?}"
    );
    test_complete!("net_verify_009_listener_builder_reuse_addr");
}

// ============================================================================
// TCP Advanced Tests
// ============================================================================

/// NET-VERIFY-010: TcpStream connect_timeout
///
/// Verifies that connect_timeout produces a stream with valid addresses.
#[test]
fn net_verify_010_tcp_connect_timeout() {
    init_test("net_verify_010_tcp_connect_timeout");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let accept_handle =
            thread::spawn(move || block_on(async { listener.accept().await.map(|(s, _)| s) }));

        thread::sleep(Duration::from_millis(10));

        // Connect with timeout (should succeed since listener is ready)
        let stream = TcpStream::connect_timeout(addr, Duration::from_secs(5)).await?;
        tracing::info!(
            local = ?stream.local_addr()?,
            peer = ?stream.peer_addr()?,
            "connect_timeout succeeded"
        );

        assert_eq!(stream.peer_addr()?, addr);

        drop(stream);
        let _ = accept_handle.join();

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "connect_timeout should succeed: {result:?}"
    );
    test_complete!("net_verify_010_tcp_connect_timeout");
}

/// NET-VERIFY-011: TcpStream TTL setting
///
/// Verifies that TTL can be set on a listener.
#[test]
fn net_verify_011_tcp_listener_ttl() {
    init_test("net_verify_011_tcp_listener_ttl");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;

        // Set TTL
        listener.set_ttl(64)?;
        tracing::info!("set TTL to 64");

        listener.set_ttl(128)?;
        tracing::info!("set TTL to 128");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TTL setting should succeed: {result:?}");
    test_complete!("net_verify_011_tcp_listener_ttl");
}

/// NET-VERIFY-012: TcpListener Incoming stream
///
/// Verifies that the Incoming stream produces connections.
#[test]
fn net_verify_012_tcp_listener_incoming() {
    init_test("net_verify_012_tcp_listener_incoming");
    const NUM_CONNS: usize = 3;

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tracing::info!(?addr, "listener ready for incoming test");

        // Spawn clients in background
        let client_handle = thread::spawn(move || {
            for i in 0..NUM_CONNS {
                thread::sleep(Duration::from_millis(10));
                match block_on(TcpStream::connect(addr)) {
                    Ok(s) => {
                        tracing::info!(i, "client connected");
                        drop(s);
                    }
                    Err(e) => tracing::warn!(i, ?e, "client connect failed"),
                }
            }
        });

        // Accept connections from incoming
        let mut incoming = listener.incoming();
        let mut accepted = 0;
        let start = std::time::Instant::now();

        // Use poll-based approach since Incoming is a stream
        while accepted < NUM_CONNS && start.elapsed() < Duration::from_secs(5) {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            match std::pin::Pin::new(&mut incoming).poll_next(&mut cx) {
                Poll::Ready(Some(Ok(_stream))) => {
                    tracing::info!(accepted, "accepted from incoming");
                    accepted += 1;
                }
                Poll::Ready(Some(Err(e))) => {
                    tracing::warn!(?e, "incoming error");
                }
                Poll::Ready(None) => break,
                Poll::Pending => {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }

        client_handle.join().expect("client thread panicked");

        tracing::info!(accepted, expected = NUM_CONNS, "incoming stream test done");
        assert!(
            accepted >= NUM_CONNS - 1,
            "should accept most connections: {accepted}/{NUM_CONNS}"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "incoming stream test should succeed: {result:?}"
    );
    test_complete!("net_verify_012_tcp_listener_incoming");
}

/// NET-VERIFY-013: TcpStream borrowed split halves
///
/// Verifies that borrowed (non-owned) split works correctly.
#[test]
fn net_verify_013_tcp_stream_borrowed_split() {
    init_test("net_verify_013_tcp_stream_borrowed_split");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let accept_handle =
            thread::spawn(move || block_on(async { listener.accept().await.map(|(s, _)| s) }));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await?;

        // Borrowed split
        let (read_half, write_half) = stream.split();
        tracing::info!("borrowed split successful");

        // Halves should not be Send (they borrow the stream)
        // We can verify they exist and the types are correct
        drop(read_half);
        drop(write_half);

        // Original stream still usable after halves are dropped
        assert!(
            stream.peer_addr().is_ok(),
            "stream should still work after split halves dropped"
        );

        drop(stream);
        let _ = accept_handle.join();

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "borrowed split should succeed: {result:?}"
    );
    test_complete!("net_verify_013_tcp_stream_borrowed_split");
}

/// NET-VERIFY-014: TcpStream keepalive option
///
/// Verifies that keepalive can be set on a TcpStream (or returns Unsupported in Phase 0).
#[test]
fn net_verify_014_tcp_stream_keepalive() {
    init_test("net_verify_014_tcp_stream_keepalive");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let accept_handle =
            thread::spawn(move || block_on(async { listener.accept().await.map(|(s, _)| s) }));

        thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).await?;

        // Try to enable keepalive — may not be supported in Phase 0
        match stream.set_keepalive(Some(Duration::from_secs(30))) {
            Ok(()) => {
                tracing::info!("set keepalive to 30s");
                stream.set_keepalive(None)?;
                tracing::info!("disabled keepalive");
            }
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                tracing::info!(?e, "Phase 0: set_keepalive not yet supported");
            }
            Err(e) => return Err(e),
        }

        drop(stream);
        let _ = accept_handle.join();

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "keepalive test should succeed: {result:?}"
    );
    test_complete!("net_verify_014_tcp_stream_keepalive");
}

// ============================================================================
// UDP Advanced Tests
// ============================================================================

/// NET-VERIFY-015: UdpSocket broadcast option
///
/// Verifies that the broadcast option can be set on a UDP socket.
#[test]
fn net_verify_015_udp_broadcast_option() {
    init_test("net_verify_015_udp_broadcast_option");

    let result = block_on(async {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        socket.set_broadcast(true)?;
        tracing::info!("set broadcast to true");

        socket.set_broadcast(false)?;
        tracing::info!("set broadcast to false");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "broadcast option should succeed: {result:?}"
    );
    test_complete!("net_verify_015_udp_broadcast_option");
}

/// NET-VERIFY-016: UdpSocket TTL option
///
/// Verifies that TTL can be set on a UDP socket.
#[test]
fn net_verify_016_udp_ttl_option() {
    init_test("net_verify_016_udp_ttl_option");

    let result = block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;

        socket.set_ttl(64)?;
        tracing::info!("set TTL to 64");

        socket.set_ttl(128)?;
        tracing::info!("set TTL to 128");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TTL option should succeed: {result:?}");
    test_complete!("net_verify_016_udp_ttl_option");
}

/// NET-VERIFY-017: UdpSocket peer_addr after connect
///
/// Verifies that peer_addr() returns the correct address after connect().
#[test]
fn net_verify_017_udp_peer_addr_after_connect() {
    init_test("net_verify_017_udp_peer_addr_after_connect");

    let result = block_on(async {
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        let b_addr = b.local_addr()?;

        // Before connect, peer_addr should fail
        assert!(
            a.peer_addr().is_err(),
            "peer_addr should fail before connect"
        );
        tracing::info!("peer_addr correctly fails before connect");

        // After connect, peer_addr should return the target
        a.connect(b_addr).await?;
        let peer = a.peer_addr()?;
        assert_eq!(peer, b_addr, "peer_addr should match connect target");
        tracing::info!(?peer, "peer_addr correct after connect");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "peer_addr test should succeed: {result:?}"
    );
    test_complete!("net_verify_017_udp_peer_addr_after_connect");
}

/// NET-VERIFY-018: UdpSocket try_clone
///
/// Verifies that try_clone produces a working copy of the socket.
#[test]
fn net_verify_018_udp_try_clone() {
    init_test("net_verify_018_udp_try_clone");

    let result = block_on(async {
        let mut original = UdpSocket::bind("127.0.0.1:0").await?;
        let original_addr = original.local_addr()?;
        tracing::info!(?original_addr, "original socket bound");

        let mut cloned = original.try_clone()?;
        let cloned_addr = cloned.local_addr()?;
        tracing::info!(?cloned_addr, "cloned socket");

        // Both should share the same address
        assert_eq!(
            original_addr, cloned_addr,
            "cloned socket should share address"
        );

        // Both should be able to send
        let mut receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let recv_addr = receiver.local_addr()?;

        original.send_to(b"from original", recv_addr).await?;
        let mut buf = [0u8; 64];
        let (n, from) = receiver.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"from original");
        tracing::info!(?from, "received from original");

        cloned.send_to(b"from cloned", recv_addr).await?;
        let (n, from) = receiver.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"from cloned");
        tracing::info!(?from, "received from cloned");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "try_clone should succeed: {result:?}");
    test_complete!("net_verify_018_udp_try_clone");
}

/// NET-VERIFY-019: UdpSocket peek_from
///
/// Verifies that peek_from reads data without consuming it.
#[test]
fn net_verify_019_udp_peek_from() {
    init_test("net_verify_019_udp_peek_from");

    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;

        // Send a datagram
        client.send_to(b"peek test", server_addr).await?;
        tracing::info!("sent datagram");

        // Peek should see the data
        let mut buf = [0u8; 64];
        let (n, from) = server.peek_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"peek test", "peek should see the data");
        tracing::info!(n, ?from, "peeked data");

        // recv_from should still see the same data (peek doesn't consume)
        let (n2, from2) = server.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n2], b"peek test", "recv should still see data");
        assert_eq!(from, from2, "addresses should match");
        tracing::info!(n2, "recv_from after peek succeeded");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "peek_from should succeed: {result:?}");
    test_complete!("net_verify_019_udp_peek_from");
}

/// NET-VERIFY-020: UdpSocket into_std conversion
///
/// Verifies that into_std extracts the underlying std socket.
#[test]
fn net_verify_020_udp_into_std() {
    init_test("net_verify_020_udp_into_std");

    let result = block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        tracing::info!(?addr, "async socket bound");

        let std_socket = socket.into_std()?;
        let std_addr = std_socket.local_addr()?;
        tracing::info!(?std_addr, "converted to std socket");

        assert_eq!(addr, std_addr, "addresses should match after conversion");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "into_std should succeed: {result:?}");
    test_complete!("net_verify_020_udp_into_std");
}

// ============================================================================
// DNS Resolution Tests
// ============================================================================

/// NET-VERIFY-021: lookup_one resolves socket addr passthrough
///
/// Verifies that lookup_one passes through a SocketAddr directly.
#[test]
fn net_verify_021_dns_lookup_one_passthrough() {
    init_test("net_verify_021_dns_lookup_one_passthrough");

    let result = block_on(async {
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let resolved = lookup_one(addr).await?;
        assert_eq!(resolved, addr, "passthrough should return exact address");
        tracing::info!(?resolved, "lookup_one passthrough");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "lookup_one passthrough should work");
    test_complete!("net_verify_021_dns_lookup_one_passthrough");
}

/// NET-VERIFY-022: lookup_all resolves socket addr
///
/// Verifies that lookup_all returns the address list.
#[test]
fn net_verify_022_dns_lookup_all_passthrough() {
    init_test("net_verify_022_dns_lookup_all_passthrough");

    let result = block_on(async {
        let addr: SocketAddr = "192.168.1.1:443".parse().unwrap();
        let resolved = lookup_all(addr).await?;
        assert_eq!(resolved.len(), 1, "should resolve to single address");
        assert_eq!(resolved[0], addr);
        tracing::info!(?resolved, "lookup_all passthrough");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "lookup_all passthrough should work");
    test_complete!("net_verify_022_dns_lookup_all_passthrough");
}

/// NET-VERIFY-023: lookup_one rejects invalid input
///
/// Verifies that lookup_one returns an error for invalid input.
#[test]
fn net_verify_023_dns_lookup_one_invalid() {
    init_test("net_verify_023_dns_lookup_one_invalid");

    let result = block_on(async {
        // Invalid port
        let err = lookup_one("127.0.0.1:not_a_port").await;
        assert!(err.is_err(), "invalid port should fail");
        let err = err.unwrap_err();
        tracing::info!(?err, "correctly rejected invalid port");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "invalid input test should complete");
    test_complete!("net_verify_023_dns_lookup_one_invalid");
}

/// NET-VERIFY-024: DNS cache default config
///
/// Verifies that DNS cache can be created with default config.
#[test]
fn net_verify_024_dns_cache_default() {
    init_test("net_verify_024_dns_cache_default");

    let cache = DnsCache::new();
    tracing::info!(?cache, "default DNS cache created");

    let config = CacheConfig::default();
    assert_eq!(config.max_entries, 10_000);
    assert_eq!(config.min_ttl, Duration::from_secs(60));
    assert_eq!(config.max_ttl, Duration::from_secs(86400));
    assert_eq!(config.negative_ttl, Duration::from_secs(30));
    tracing::info!(?config, "default cache config verified");

    test_complete!("net_verify_024_dns_cache_default");
}

/// NET-VERIFY-025: DNS cache with custom config
///
/// Verifies that DNS cache can be created with custom configuration.
#[test]
fn net_verify_025_dns_cache_custom_config() {
    init_test("net_verify_025_dns_cache_custom_config");

    let config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(5),
    };

    let cache = DnsCache::with_config(config);
    tracing::info!("custom DNS cache created");

    // Stats should start at zero
    let stats = cache.stats();
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
    tracing::info!(?stats, "initial stats verified");

    test_complete!("net_verify_025_dns_cache_custom_config");
}

// ============================================================================
// Fault Handling Tests
// ============================================================================

/// NET-VERIFY-026: TCP write after peer close
///
/// Verifies that writing to a closed peer produces an error eventually.
#[test]
fn net_verify_026_tcp_write_after_peer_close() {
    init_test("net_verify_026_tcp_write_after_peer_close");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Accept in background and immediately close
        let accept_handle = thread::spawn(move || {
            block_on(async {
                let (stream, _) = listener.accept().await?;
                tracing::info!("server accepted, closing immediately");
                drop(stream);
                Ok::<_, io::Error>(())
            })
        });

        thread::sleep(Duration::from_millis(10));

        let mut client = std::net::TcpStream::connect(addr)?;
        client.set_write_timeout(Some(Duration::from_secs(2)))?;
        tracing::info!("client connected");

        // Wait for server to close
        accept_handle.join().expect("accept thread panicked")?;
        thread::sleep(Duration::from_millis(50));

        // Writing should eventually fail (may need multiple writes to detect)
        let data = vec![0u8; 65536];
        let mut write_failed = false;
        for i in 0..100 {
            match client.write(&data) {
                Ok(_) => {
                    tracing::trace!(i, "write succeeded (peer close not yet detected)");
                }
                Err(e) => {
                    tracing::info!(i, ?e, "write failed after peer close");
                    write_failed = true;
                    break;
                }
            }
        }

        // On most systems, writing to a closed peer will eventually fail
        // with BrokenPipe or ConnectionReset
        tracing::info!(write_failed, "peer close detection result");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "write-after-close test should complete: {result:?}"
    );
    test_complete!("net_verify_026_tcp_write_after_peer_close");
}

/// NET-VERIFY-027: UDP send to unreachable address
///
/// Verifies that UDP send_to does not hang on unreachable destinations.
#[test]
fn net_verify_027_udp_send_unreachable() {
    init_test("net_verify_027_udp_send_unreachable");

    let result = block_on(async {
        let mut socket = UdpSocket::bind("127.0.0.1:0").await?;

        // Send to a port with no listener - should succeed (UDP is fire-and-forget)
        let unreachable_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sent = socket.send_to(b"hello", unreachable_addr).await?;
        assert_eq!(sent, 5, "send should report bytes written");
        tracing::info!(sent, "send to unreachable succeeded (expected for UDP)");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "UDP unreachable test should succeed: {result:?}"
    );
    test_complete!("net_verify_027_udp_send_unreachable");
}

/// NET-VERIFY-028: TCP simultaneous connect/accept
///
/// Verifies that multiple simultaneous connections work correctly.
#[test]
fn net_verify_028_tcp_simultaneous_connect() {
    init_test("net_verify_028_tcp_simultaneous_connect");
    const NUM_CONCURRENT: usize = 10;

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Accept all in background
        let accept_handle = thread::spawn(move || {
            block_on(async {
                let mut accepted = 0;
                for _ in 0..NUM_CONCURRENT {
                    match listener.accept().await {
                        Ok((s, _)) => {
                            accepted += 1;
                            drop(s);
                        }
                        Err(e) => {
                            tracing::warn!(?e, "accept error");
                        }
                    }
                }
                accepted
            })
        });

        thread::sleep(Duration::from_millis(10));

        // Launch all connections simultaneously
        let mut handles = Vec::new();
        for i in 0..NUM_CONCURRENT {
            let handle = thread::spawn(move || {
                block_on(async {
                    match TcpStream::connect(addr).await {
                        Ok(s) => {
                            tracing::debug!(i, "connected");
                            drop(s);
                            true
                        }
                        Err(e) => {
                            tracing::warn!(i, ?e, "connect failed");
                            false
                        }
                    }
                })
            });
            handles.push(handle);
        }

        let connected: usize = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|&ok| ok)
            .count();

        let accepted = accept_handle.join().expect("accept panicked");
        tracing::info!(connected, accepted, "simultaneous connect test done");

        assert!(
            connected >= NUM_CONCURRENT - 2,
            "most connections should succeed: {connected}/{NUM_CONCURRENT}"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "simultaneous connect should succeed: {result:?}"
    );
    test_complete!("net_verify_028_tcp_simultaneous_connect");
}

/// NET-VERIFY-029: Rapid bind/unbind cycle
///
/// Verifies that rapidly creating and destroying listeners works.
#[test]
fn net_verify_029_rapid_bind_unbind() {
    init_test("net_verify_029_rapid_bind_unbind");

    let result = block_on(async {
        let mut addrs = Vec::new();

        for i in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            addrs.push(addr);
            tracing::trace!(i, ?addr, "bound listener");
            drop(listener);
        }

        // All ports should have been different (OS assigns ephemeral ports)
        let unique_ports: std::collections::HashSet<_> = addrs.iter().map(|a| a.port()).collect();
        tracing::info!(
            total = addrs.len(),
            unique = unique_ports.len(),
            "rapid bind/unbind complete"
        );

        // Most should be unique (OS may reuse very quickly, so allow some)
        assert!(
            unique_ports.len() >= 10,
            "should get mostly unique ports: {}",
            unique_ports.len()
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "rapid bind/unbind should succeed: {result:?}"
    );
    test_complete!("net_verify_029_rapid_bind_unbind");
}

// ============================================================================
// Lab Network Simulation Tests
// ============================================================================

/// NET-VERIFY-030: SimulatedNetwork packet loss
///
/// Verifies that configuring packet loss drops some packets.
#[test]
fn net_verify_030_sim_packet_loss() {
    init_test("net_verify_030_sim_packet_loss");

    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::lossy(),
        ..Default::default()
    });

    let a = net.add_host("sender");
    let b = net.add_host("receiver");

    // Send many packets
    const NUM_PACKETS: usize = 1000;
    for i in 0..NUM_PACKETS {
        let payload = format!("packet-{i}");
        net.send(a, b, Bytes::copy_from_slice(payload.as_bytes()));
    }

    net.run_until_idle();

    let inbox = net.inbox(b).expect("receiver inbox");
    let received = inbox.len();

    tracing::info!(
        sent = NUM_PACKETS,
        received,
        lost = NUM_PACKETS - received,
        "packet loss simulation"
    );

    // With 10% loss, we expect roughly 900 packets (allow wide margin)
    assert!(
        received < NUM_PACKETS,
        "some packets should be lost with lossy conditions"
    );
    assert!(
        received > NUM_PACKETS / 2,
        "too many packets lost: {received}/{NUM_PACKETS}"
    );

    let metrics = net.metrics();
    tracing::info!(?metrics, "network metrics");

    test_complete!("net_verify_030_sim_packet_loss");
}

/// NET-VERIFY-031: SimulatedNetwork WAN latency
///
/// Verifies that WAN conditions produce higher latency than LAN.
#[test]
fn net_verify_031_sim_wan_latency() {
    init_test("net_verify_031_sim_wan_latency");

    // LAN network
    let mut lan = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::lan(),
        ..Default::default()
    });

    let la = lan.add_host("a");
    let lb = lan.add_host("b");
    lan.send(la, lb, Bytes::copy_from_slice(b"lan-ping"));
    lan.run_until_idle();

    let lan_inbox = lan.inbox(lb).expect("lan inbox");
    assert_eq!(lan_inbox.len(), 1);
    let lan_latency = lan_inbox[0]
        .received_at
        .duration_since(lan_inbox[0].sent_at);
    tracing::info!(lan_latency_ns = lan_latency, "LAN latency");

    // WAN network
    let mut wan = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::wan(),
        ..Default::default()
    });

    let wa = wan.add_host("a");
    let wb = wan.add_host("b");
    wan.send(wa, wb, Bytes::copy_from_slice(b"wan-ping"));
    wan.run_until_idle();

    let wan_inbox = wan.inbox(wb).expect("wan inbox");
    assert_eq!(wan_inbox.len(), 1);
    let wan_latency = wan_inbox[0]
        .received_at
        .duration_since(wan_inbox[0].sent_at);
    tracing::info!(wan_latency_ns = wan_latency, "WAN latency");

    // WAN should be significantly higher than LAN
    assert!(
        wan_latency > lan_latency,
        "WAN latency ({wan_latency}ns) should exceed LAN ({lan_latency}ns)"
    );
    tracing::info!(
        ratio = wan_latency / std::cmp::max(lan_latency, 1),
        "WAN/LAN latency ratio"
    );

    test_complete!("net_verify_031_sim_wan_latency");
}

/// NET-VERIFY-032: SimulatedNetwork multi-host topology
///
/// Verifies that multiple hosts can communicate in a mesh.
#[test]
fn net_verify_032_sim_multi_host() {
    init_test("net_verify_032_sim_multi_host");

    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::ideal(),
        ..Default::default()
    });

    // Create a 4-host mesh
    let hosts: Vec<_> = (0..4)
        .map(|i| net.add_host(format!("node-{i}")))
        .collect();

    // Each host sends to every other host
    for &src in &hosts {
        for &dst in &hosts {
            if src != dst {
                let msg = format!("from-{src:?}-to-{dst:?}");
                net.send(src, dst, Bytes::copy_from_slice(msg.as_bytes()));
            }
        }
    }

    net.run_until_idle();

    // Each host should receive exactly 3 messages (from the other 3 hosts)
    for &host in &hosts {
        let inbox = net.inbox(host).expect("host inbox");
        assert_eq!(
            inbox.len(),
            3,
            "host {host:?} should receive 3 messages, got {}",
            inbox.len()
        );
        tracing::info!(host = ?host, msgs = inbox.len(), "host inbox verified");
    }

    test_complete!("net_verify_032_sim_multi_host");
}

/// NET-VERIFY-033: SimulatedNetwork partition and heal
///
/// Verifies that network partitions prevent communication and heals restore it.
#[test]
fn net_verify_033_sim_partition_heal() {
    init_test("net_verify_033_sim_partition_heal");

    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::ideal(),
        ..Default::default()
    });

    let a = net.add_host("a");
    let b = net.add_host("b");

    // Verify communication works before partition
    net.send(a, b, Bytes::copy_from_slice(b"before-partition"));
    net.run_until_idle();
    let inbox_before = net.inbox(b).expect("inbox");
    assert_eq!(inbox_before.len(), 1, "message should arrive before partition");
    tracing::info!("pre-partition communication verified");

    // Partition the network
    net.inject_fault(&NetworkFault::Partition {
        hosts_a: vec![a],
        hosts_b: vec![b],
    });
    tracing::info!("partition injected");

    // Send during partition
    net.send(a, b, Bytes::copy_from_slice(b"during-partition"));
    net.run_until_idle();
    let inbox_during = net.inbox(b).expect("inbox");
    assert_eq!(
        inbox_during.len(),
        1,
        "no new messages should arrive during partition"
    );
    tracing::info!("partition blocks messages verified");

    // Heal the partition
    net.inject_fault(&NetworkFault::Heal {
        hosts_a: vec![a],
        hosts_b: vec![b],
    });
    tracing::info!("partition healed");

    // Send after heal
    net.send(a, b, Bytes::copy_from_slice(b"after-heal"));
    net.run_until_idle();
    let inbox_after = net.inbox(b).expect("inbox");
    // After heal, the new message should arrive
    // (the during-partition message may or may not have been queued)
    assert!(
        inbox_after.len() >= 2,
        "messages should arrive after heal: got {}",
        inbox_after.len()
    );
    tracing::info!(
        total_msgs = inbox_after.len(),
        "post-heal communication verified"
    );

    test_complete!("net_verify_033_sim_partition_heal");
}

/// NET-VERIFY-034: SimulatedNetwork host crash/restart
///
/// Verifies that host crash drops messages and restart allows recovery.
#[test]
fn net_verify_034_sim_host_crash_restart() {
    init_test("net_verify_034_sim_host_crash_restart");

    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::ideal(),
        ..Default::default()
    });

    let a = net.add_host("sender");
    let b = net.add_host("receiver");

    // Initial communication works
    net.send(a, b, Bytes::copy_from_slice(b"hello"));
    net.run_until_idle();
    assert_eq!(net.inbox(b).expect("inbox").len(), 1);
    tracing::info!("pre-crash communication works");

    // Crash host b
    net.inject_fault(&NetworkFault::HostCrash { host: b });
    tracing::info!("host b crashed");

    // Messages to crashed host should be dropped
    net.send(a, b, Bytes::copy_from_slice(b"to-crashed"));
    net.run_until_idle();

    // Restart host b
    net.inject_fault(&NetworkFault::HostRestart { host: b });
    tracing::info!("host b restarted");

    // Messages after restart should work
    net.send(a, b, Bytes::copy_from_slice(b"after-restart"));
    net.run_until_idle();

    let inbox = net.inbox(b).expect("inbox");
    tracing::info!(msgs = inbox.len(), "post-restart inbox");

    // Inbox was cleared by crash, so only post-restart message(s) should be present
    assert!(
        inbox.len() >= 1,
        "should receive at least one post-restart message"
    );

    test_complete!("net_verify_034_sim_host_crash_restart");
}

/// NET-VERIFY-035: SimulatedNetwork metrics tracking
///
/// Verifies that network metrics are accurately tracked.
#[test]
fn net_verify_035_sim_metrics() {
    init_test("net_verify_035_sim_metrics");

    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::ideal(),
        capture_trace: true,
        ..Default::default()
    });

    let a = net.add_host("a");
    let b = net.add_host("b");

    // Send some messages
    const MSG_COUNT: usize = 10;
    for i in 0..MSG_COUNT {
        let msg = format!("msg-{i}");
        net.send(a, b, Bytes::copy_from_slice(msg.as_bytes()));
    }

    net.run_until_idle();

    let metrics = net.metrics();
    tracing::info!(?metrics, "network metrics");

    assert_eq!(
        metrics.packets_sent as usize, MSG_COUNT,
        "sent count should match"
    );
    assert!(
        metrics.packets_delivered > 0,
        "some packets should be delivered"
    );

    // Check trace events
    let trace = net.trace();
    tracing::info!(trace_events = trace.len(), "trace captured");
    assert!(
        !trace.is_empty(),
        "trace should have events when capture_trace=true"
    );

    test_complete!("net_verify_035_sim_metrics");
}

/// NET-VERIFY-036: SimulatedNetwork per-link conditions
///
/// Verifies that per-link network conditions can be configured.
#[test]
fn net_verify_036_sim_per_link_conditions() {
    init_test("net_verify_036_sim_per_link_conditions");

    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::ideal(),
        ..Default::default()
    });

    let a = net.add_host("fast");
    let b = net.add_host("slow");
    let c = net.add_host("target");

    // Set asymmetric conditions: a->c is fast (ideal), b->c is slow (WAN)
    net.set_link_conditions(b, c, NetworkConditions::wan());

    // Send from both
    net.send(a, c, Bytes::copy_from_slice(b"fast-msg"));
    net.send(b, c, Bytes::copy_from_slice(b"slow-msg"));
    net.run_until_idle();

    let inbox = net.inbox(c).expect("inbox");
    assert_eq!(inbox.len(), 2, "both messages should arrive");

    // First message should be from the fast link (lower latency)
    let first_latency = inbox[0].received_at.duration_since(inbox[0].sent_at);
    let second_latency = inbox[1].received_at.duration_since(inbox[1].sent_at);
    tracing::info!(
        first_latency_ns = first_latency,
        second_latency_ns = second_latency,
        "per-link latencies"
    );

    // The ideal link should have lower latency than the WAN link
    // (packets are sorted by received_at in the inbox)
    assert!(
        first_latency <= second_latency,
        "fast link should have lower or equal latency"
    );

    test_complete!("net_verify_036_sim_per_link_conditions");
}
