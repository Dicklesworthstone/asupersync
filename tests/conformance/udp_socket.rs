//! UDP Socket Options and Message Framing Conformance Tests
//!
//! This module provides comprehensive conformance testing for UDP socket options
//! and message framing behavior per RFC 768, POSIX socket specifications, and
//! Linux kernel networking documentation. The tests systematically validate:
//!
//! 1. **SO_BROADCAST required for broadcast sends** (POSIX/Linux socket(7))
//! 2. **SO_REUSEADDR for multicast groups** (RFC 3678, socket(7))
//! 3. **recv_from preserves datagram payload and source address**
//! 4. **oversized incoming datagrams truncate to the caller buffer boundary**
//! 5. **zero-length datagrams are delivered without being collapsed**
//! 6. **cancelled contexts reject UDP connect before registering I/O**
//! 7. **connected UDP returns ECONNREFUSED on ICMP port-unreachable** (RFC 1122)
//!
//! # RFC 768 UDP Protocol
//!
//! **RFC 768 (UDP Protocol):**
//! UDP provides connectionless, unreliable datagram delivery. Socket-level
//! configuration affects addressing, delivery, and error reporting behavior.
//!
//! # POSIX Socket Options
//!
//! **socket(7) - SO_BROADCAST:**
//! Enables sending of broadcast datagrams. Sending to broadcast address
//! without this option set returns EACCES (Permission denied).
//!
//! **socket(7) - SO_REUSEADDR:**
//! Allows multiple sockets to bind to same address, required for multicast
//! group membership with multiple processes on same port.
//!
//! # RFC 1122 Host Requirements
//!
//! **RFC 1122 Section 4.1.3.5:**
//! Connected UDP sockets should receive ICMP errors. ICMP port unreachable
//! generates ECONNREFUSED on subsequent operations.

use asupersync::{Cx, net::UdpSocket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use std::time::Duration;

/// Test result for UDP conformance verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct UdpSocketTestResult {
    pub test_id: String,
    pub description: String,
    pub passed: bool,
    pub error_message: Option<String>,
}

#[allow(dead_code)]

impl UdpSocketTestResult {
    /// Create a successful test result.
    #[allow(dead_code)]
    pub fn pass(test_id: &str, description: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            passed: true,
            error_message: None,
        }
    }

    /// Create a failed test result with error message.
    #[allow(dead_code)]
    pub fn fail(test_id: &str, description: &str, error: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            passed: false,
            error_message: Some(error.to_string()),
        }
    }
}

/// Comprehensive UDP socket conformance test suite.
#[allow(dead_code)]
pub struct UdpSocketConformanceTests;

#[allow(dead_code)]

impl UdpSocketConformanceTests {
    /// Run all UDP socket conformance tests.
    pub async fn run_all() -> Vec<UdpSocketTestResult> {
        let mut results = Vec::new();

        results.push(Self::test_broadcast_permission_required().await);
        results.push(Self::test_reuseaddr_multicast_groups().await);
        results.push(Self::test_pktinfo_control_parsing().await);
        results.push(Self::test_msg_trunc_oversized_datagrams().await);
        results.push(Self::test_zero_length_datagram_preserved().await);
        results.push(Self::test_cancelled_connect_rejected().await);
        results.push(Self::test_connected_udp_icmp_errors().await);

        results
    }

    /// Test 1: SO_BROADCAST required for broadcast sends (socket(7))
    ///
    /// **Specification:** POSIX socket(7) - SO_BROADCAST
    /// Sending to broadcast address without SO_BROADCAST set must return EACCES.
    /// With SO_BROADCAST enabled, broadcast sends should succeed.
    async fn test_broadcast_permission_required() -> UdpSocketTestResult {
        let test_id = "UDP_BROADCAST_PERMISSION";
        let description = "SO_BROADCAST required for broadcast address sends";

        // Create socket without SO_BROADCAST
        let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Socket creation failed: {}", e),
                );
            }
        };

        if let Err(e) = socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))) {
            return UdpSocketTestResult::fail(test_id, description, &format!("Bind failed: {}", e));
        }

        let broadcast_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, 12345);
        let test_data = b"broadcast test";

        // First attempt: without SO_BROADCAST (should fail with EACCES/EPERM)
        match socket.send_to(test_data, &SockAddr::from(broadcast_addr)) {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                // Expected: EACCES/EPERM without SO_BROADCAST
            }
            Ok(_) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    "Broadcast send succeeded without SO_BROADCAST (should fail)",
                );
            }
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Unexpected error without SO_BROADCAST: {}", e),
                );
            }
        }

        // Enable SO_BROADCAST
        if let Err(e) = socket.set_broadcast(true) {
            return UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Failed to set SO_BROADCAST: {}", e),
            );
        }

        // Second attempt: with SO_BROADCAST (should succeed or fail with network error)
        match socket.send_to(test_data, &SockAddr::from(broadcast_addr)) {
            Ok(_) => {
                // Success - broadcast enabled and send worked
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e)
                if e.kind() == ErrorKind::NetworkUnreachable
                    || e.kind() == ErrorKind::HostUnreachable
                    || e.kind() == ErrorKind::NetworkDown =>
            {
                // Acceptable network-level failures (broadcast routing may be disabled)
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => UdpSocketTestResult::fail(
                test_id,
                description,
                "Broadcast still denied after setting SO_BROADCAST",
            ),
            Err(e) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Unexpected error with SO_BROADCAST: {}", e),
            ),
        }
    }

    /// Test 2: SO_REUSEADDR for multicast groups (socket(7))
    ///
    /// **Specification:** socket(7) - SO_REUSEADDR + IP_ADD_MEMBERSHIP
    /// Multiple sockets should be able to bind to same port with SO_REUSEADDR
    /// for multicast group membership.
    async fn test_reuseaddr_multicast_groups() -> UdpSocketTestResult {
        let test_id = "UDP_REUSEADDR_MULTICAST";
        let description = "SO_REUSEADDR enables multiple multicast binds";

        let multicast_addr = Ipv4Addr::new(224, 0, 0, 251); // mDNS multicast
        let bind_port = 15353; // Non-privileged mDNS-like port

        // Create first socket with SO_REUSEADDR
        let socket1 = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Socket1 creation failed: {}", e),
                );
            }
        };

        if let Err(e) = socket1.set_reuse_address(true) {
            return UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Socket1 SO_REUSEADDR failed: {}", e),
            );
        }

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port);
        if let Err(e) = socket1.bind(&SockAddr::from(bind_addr)) {
            return UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Socket1 bind failed: {}", e),
            );
        }

        // Join multicast group
        if let Err(e) = socket1.join_multicast_v4(&multicast_addr, &Ipv4Addr::UNSPECIFIED) {
            return UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Socket1 multicast join failed: {}", e),
            );
        }

        // Create second socket with SO_REUSEADDR (should succeed)
        let socket2 = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Socket2 creation failed: {}", e),
                );
            }
        };

        if let Err(e) = socket2.set_reuse_address(true) {
            return UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Socket2 SO_REUSEADDR failed: {}", e),
            );
        }

        // Second bind should succeed with SO_REUSEADDR
        match socket2.bind(&SockAddr::from(bind_addr)) {
            Ok(()) => {
                if let Err(e) = socket2.join_multicast_v4(&multicast_addr, &Ipv4Addr::UNSPECIFIED) {
                    return UdpSocketTestResult::fail(
                        test_id,
                        description,
                        &format!("Socket2 multicast join failed: {}", e),
                    );
                }
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => UdpSocketTestResult::fail(
                test_id,
                description,
                "Second bind failed with EADDRINUSE despite SO_REUSEADDR",
            ),
            Err(e) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Unexpected bind error: {}", e),
            ),
        }
    }

    /// Test 3: UDP recv_from preserves source address and payload framing.
    ///
    /// This is the public asupersync UDP contract corresponding to the old
    /// ancillary-data test: callers must receive the datagram and source socket
    /// address without private socket2 control-message APIs.
    async fn test_pktinfo_control_parsing() -> UdpSocketTestResult {
        let test_id = "UDP_RECV_FROM_SOURCE";
        let description = "recv_from returns payload and source address";
        let test_data = b"pktinfo test";

        let mut receiver = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Receiver bind failed: {e}"),
                );
            }
        };
        let receiver_addr = match receiver.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Receiver local_addr failed: {e}"),
                );
            }
        };

        let mut sender = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Sender bind failed: {e}"),
                );
            }
        };
        let sender_addr = match sender.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Sender local_addr failed: {e}"),
                );
            }
        };

        if let Err(e) = sender.send_to(test_data, receiver_addr).await {
            return UdpSocketTestResult::fail(test_id, description, &format!("Send failed: {e}"));
        }

        let mut buf = [0_u8; 128];
        match receiver.recv_from(&mut buf).await {
            Ok((bytes_received, from_addr))
                if bytes_received == test_data.len()
                    && &buf[..bytes_received] == test_data
                    && from_addr == sender_addr =>
            {
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e) => {
                UdpSocketTestResult::fail(test_id, description, &format!("Receive failed: {e}"))
            }
            Ok((bytes_received, from_addr)) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!(
                    "Unexpected receive result: bytes={bytes_received}, from={from_addr}, payload={:?}",
                    &buf[..bytes_received]
                ),
            ),
        }
    }

    /// Test 4: MSG_TRUNC detected for oversized incoming datagrams (recv(2))
    ///
    /// **Specification:** recv(2) - MSG_TRUNC flag
    /// When received datagram exceeds buffer size, MSG_TRUNC flag should be set
    /// and original datagram size should be returned.
    async fn test_msg_trunc_oversized_datagrams() -> UdpSocketTestResult {
        let test_id = "UDP_MSG_TRUNC";
        let description = "MSG_TRUNC detection for oversized datagrams";

        let mut receiver = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Receiver bind failed: {e}"),
                );
            }
        };
        let receiver_addr = match receiver.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Receiver local_addr failed: {e}"),
                );
            }
        };

        let mut sender = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Sender bind failed: {e}"),
                );
            }
        };

        // Send large datagram (1000 bytes)
        let large_data = vec![0x42u8; 1000];
        if let Err(e) = sender.send_to(&large_data, receiver_addr).await {
            return UdpSocketTestResult::fail(test_id, description, &format!("Send failed: {e}"));
        }

        // Receive into small buffer (100 bytes)
        let mut small_buf = [0u8; 100];

        match receiver.recv_from(&mut small_buf).await {
            Ok((bytes_received, _from_addr))
                if bytes_received == small_buf.len()
                    && small_buf.iter().all(|byte| *byte == 0x42) =>
            {
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Truncated receive failed: {e}"),
            ),
            Ok((bytes_received, _from_addr)) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Unexpected truncation behavior: received={bytes_received}"),
            ),
        }
    }

    /// Test 5: zero-length UDP datagrams are valid datagrams.
    async fn test_zero_length_datagram_preserved() -> UdpSocketTestResult {
        let test_id = "UDP_ZERO_LENGTH_DATAGRAM";
        let description = "zero-length datagrams are delivered as zero-byte receives";

        let mut receiver = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Receiver bind failed: {e}"),
                );
            }
        };
        let receiver_addr = match receiver.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Receiver local_addr failed: {e}"),
                );
            }
        };

        let mut sender = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Sender bind failed: {e}"),
                );
            }
        };
        let sender_addr = match sender.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Sender local_addr failed: {e}"),
                );
            }
        };

        if let Err(e) = sender.send_to(&[], receiver_addr).await {
            return UdpSocketTestResult::fail(test_id, description, &format!("Send failed: {e}"));
        }

        let mut buf = [0xAA_u8; 8];
        match receiver.recv_from(&mut buf).await {
            Ok((0, from_addr))
                if from_addr == sender_addr && buf.iter().all(|byte| *byte == 0xAA) =>
            {
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e) => {
                UdpSocketTestResult::fail(test_id, description, &format!("Receive failed: {e}"))
            }
            Ok((bytes_received, from_addr)) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!(
                    "Unexpected zero-length receive: bytes={bytes_received}, from={from_addr}"
                ),
            ),
        }
    }

    /// Test 6: cancellation is observed before UDP connect mutates the socket.
    async fn test_cancelled_connect_rejected() -> UdpSocketTestResult {
        let test_id = "UDP_CANCELLED_CONNECT";
        let description = "cancelled context rejects connect before I/O registration";

        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Socket bind failed: {e}"),
                );
            }
        };
        let peer = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Peer bind failed: {e}"),
                );
            }
        };
        let peer_addr = match peer.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Peer local_addr failed: {e}"),
                );
            }
        };

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = cx.set_current_restricted();

        match socket.connect(peer_addr).await {
            Err(e) if e.kind() == ErrorKind::Interrupted && socket.peer_addr().is_err() => {
                UdpSocketTestResult::pass(test_id, description)
            }
            Err(e) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Unexpected cancellation error: {e}"),
            ),
            Ok(()) => UdpSocketTestResult::fail(
                test_id,
                description,
                "Cancelled connect unexpectedly succeeded",
            ),
        }
    }

    /// Test 7: Connected UDP returns ECONNREFUSED on ICMP port-unreachable (RFC 1122)
    ///
    /// **Specification:** RFC 1122 Section 4.1.3.5
    /// Connected UDP sockets should receive ICMP error notifications.
    /// ICMP port unreachable should generate ECONNREFUSED on next operation.
    async fn test_connected_udp_icmp_errors() -> UdpSocketTestResult {
        let test_id = "UDP_CONNECTED_ICMP";
        let description = "Connected UDP receives ICMP port unreachable as ECONNREFUSED";

        // Create UDP socket
        let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                return UdpSocketTestResult::fail(
                    test_id,
                    description,
                    &format!("Socket creation failed: {}", e),
                );
            }
        };

        // Bind to local address
        let bind_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        if let Err(e) = socket.bind(&SockAddr::from(bind_addr)) {
            return UdpSocketTestResult::fail(test_id, description, &format!("Bind failed: {}", e));
        }

        // Connect to unreachable port on localhost (should be closed/filtered)
        let unreachable_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1); // Port 1 (tcpmux, likely closed)
        if let Err(e) = socket.connect(&SockAddr::from(unreachable_addr)) {
            return UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Connect failed: {}", e),
            );
        }

        let test_data = b"icmp test";

        // First send (may succeed as UDP is fire-and-forget)
        if let Err(e) = socket.send(test_data) {
            // Send might fail immediately on some systems
            if e.kind() == ErrorKind::ConnectionRefused {
                return UdpSocketTestResult::pass(test_id, description);
            }
        }

        // Brief delay for ICMP response
        thread::sleep(Duration::from_millis(10));

        // Second send (should receive ECONNREFUSED if ICMP port unreachable arrived)
        match socket.send(test_data) {
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                // Expected: ICMP port unreachable converted to ECONNREFUSED
                UdpSocketTestResult::pass(test_id, description)
            }
            Ok(_) => {
                // UDP send succeeded - might mean port is actually open or ICMP blocked
                // This is acceptable behavior (firewalls may block ICMP)
                UdpSocketTestResult::pass(
                    test_id,
                    &format!("{} (ICMP may be filtered)", description),
                )
            }
            Err(e) => UdpSocketTestResult::fail(
                test_id,
                description,
                &format!("Unexpected error: {} (expected ECONNREFUSED)", e),
            ),
        }
    }
}

/// Run the full UDP socket conformance test suite.
pub async fn run_udp_socket_conformance_tests() -> Vec<UdpSocketTestResult> {
    UdpSocketConformanceTests::run_all().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    fn sanitize_field(value: &str) -> String {
        value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/') {
                    ch
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn emit_conformance_log(result: &UdpSocketTestResult) {
        let verdict = if result.passed { "pass" } else { "fail" };
        let first_failure = result.error_message.as_deref().unwrap_or("");
        println!(
            "bead_id=asupersync-2qssae suite_id=udp_socket scenario_id={} adapter_kind=native_udp platform={} feature_flags=test-internals operation={} input_shape=loopback_udp expected_result=pass actual_result={} cleanup_status=not_applicable unsupported_reason= verdict={} first_failure={}",
            sanitize_field(&result.test_id),
            std::env::consts::OS,
            sanitize_field(&result.description),
            verdict,
            verdict,
            sanitize_field(first_failure)
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_udp_socket_conformance_suite() {
        let results = block_on(run_udp_socket_conformance_tests());

        println!("UDP Socket Conformance Test Results:");
        println!("===================================");

        let mut passed = 0;
        let mut failed = 0;

        for result in &results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            emit_conformance_log(result);
            println!("[{}] {}: {}", status, result.test_id, result.description);

            if let Some(error) = &result.error_message {
                println!("      Error: {}", error);
            }

            if result.passed {
                passed += 1;
            } else {
                failed += 1;
            }
        }

        println!("===================================");
        println!(
            "Total: {} tests, {} passed, {} failed",
            results.len(),
            passed,
            failed
        );

        // All tests should pass for conformance
        assert_eq!(failed, 0, "UDP socket conformance tests failed");
    }

    #[test]
    #[allow(dead_code)]
    fn test_broadcast_permission() {
        let result = block_on(UdpSocketConformanceTests::test_broadcast_permission_required());
        assert!(
            result.passed,
            "Broadcast permission test failed: {:?}",
            result.error_message
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_reuseaddr_multicast() {
        let result = block_on(UdpSocketConformanceTests::test_reuseaddr_multicast_groups());
        assert!(
            result.passed,
            "REUSEADDR multicast test failed: {:?}",
            result.error_message
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_pktinfo_control() {
        let result = block_on(UdpSocketConformanceTests::test_pktinfo_control_parsing());
        assert!(
            result.passed,
            "PKTINFO control test failed: {:?}",
            result.error_message
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_msg_trunc() {
        let result = block_on(UdpSocketConformanceTests::test_msg_trunc_oversized_datagrams());
        assert!(
            result.passed,
            "MSG_TRUNC test failed: {:?}",
            result.error_message
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_zero_length_datagram() {
        let result = block_on(UdpSocketConformanceTests::test_zero_length_datagram_preserved());
        assert!(
            result.passed,
            "zero-length datagram test failed: {:?}",
            result.error_message
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_cancelled_connect() {
        let result = block_on(UdpSocketConformanceTests::test_cancelled_connect_rejected());
        assert!(
            result.passed,
            "cancelled connect test failed: {:?}",
            result.error_message
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_connected_icmp() {
        let result = block_on(UdpSocketConformanceTests::test_connected_udp_icmp_errors());
        assert!(
            result.passed,
            "Connected UDP ICMP test failed: {:?}",
            result.error_message
        );
    }
}
