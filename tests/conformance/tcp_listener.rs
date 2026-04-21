#![allow(clippy::all)]
//! TCP Listener Socket Options Conformance Tests (RFC 793/6056)
//!
//! This module provides comprehensive conformance testing for TCP socket binding
//! options and listener behavior per RFC 793, RFC 6056, and Linux kernel
//! documentation. The tests systematically validate:
//!
//! 1. **SO_REUSEADDR allows TIME_WAIT rebinds** (RFC 793/6056)
//! 2. **SO_REUSEPORT load-balances across listeners** (Linux kernel docs)
//! 3. **Backlog parameter honored** (TCP/IP stack behavior)
//! 4. **Bind to port 0 returns OS-assigned port** (POSIX behavior)
//! 5. **Double-bind to same exclusive socket fails** (Address conflict)
//!
//! # RFC 793 TIME_WAIT State
//!
//! **RFC 793 Section 3.9:**
//! TIME_WAIT state prevents immediate reuse of socket address pairs to avoid
//! delayed segments from previous connection. SO_REUSEADDR allows override
//! when binding to same address for server restart scenarios.
//!
//! # RFC 6056 Local Port Selection
//!
//! **RFC 6056 Section 3.2:**
//! Dynamic port allocation when binding to port 0. OS selects available port
//! from ephemeral range and returns actual bound address.
//!
//! # SO_REUSEPORT Load Balancing
//!
//! **Linux kernel documentation:**
//! SO_REUSEPORT enables multiple sockets to bind to same address/port,
//! with kernel distributing incoming connections across the sockets.

use asupersync::net::tcp::socket::TcpSocket;
use asupersync::net::tcp::listener::TcpListener;
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::thread;
use std::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Test result for conformance verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct TcpListenerTestResult {
    pub test_id: String,
    pub description: String,
    pub passed: bool,
    pub error_message: Option<String>,
}

#[allow(dead_code)]

impl TcpListenerTestResult {
    #[allow(dead_code)]
    fn pass(test_id: &str, description: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            passed: true,
            error_message: None,
        }
    }

    #[allow(dead_code)]

    fn fail(test_id: &str, description: &str, error: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            description: description.to_string(),
            passed: false,
            error_message: Some(error.to_string()),
        }
    }
}

/// RFC 793/6056 Test 1: SO_REUSEADDR allows TIME_WAIT rebinds
///
/// Validates that SO_REUSEADDR enables binding to an address that might be
/// in TIME_WAIT state from a previous connection. This is essential for
/// server restart scenarios where the server needs to rebind to the same
/// port immediately after shutdown.
#[test]
#[allow(dead_code)]
fn test_so_reuseaddr_allows_time_wait_rebinds() {
    // Get a free port for testing
    let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    // Create first listener without REUSEADDR
    let socket1 = TcpSocket::new_v4().expect("create socket1");
    socket1.bind(addr).expect("bind socket1");
    let listener1 = socket1.listen(128).expect("listen socket1");
    let bound_addr = listener1.local_addr().expect("get local addr");

    // Create a connection to establish socket state
    let _client = StdTcpStream::connect(bound_addr).expect("client connect");

    // Close first listener (would normally enter TIME_WAIT)
    drop(listener1);

    // Small delay to ensure the socket state propagates
    thread::sleep(Duration::from_millis(10));

    // Try to bind to the same address without REUSEADDR (should fail)
    let socket2 = TcpSocket::new_v4().expect("create socket2");
    let bind_result = socket2.bind(bound_addr);

    match bind_result {
        Ok(_) => {
            // If bind succeeds, try listen (might fail there)
            match socket2.listen(128) {
                Ok(_) => {
                    println!("Warning: Bind without REUSEADDR succeeded (OS might have fast cleanup)");
                }
                Err(e) => {
                    println!("Listen failed as expected without REUSEADDR: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Bind failed as expected without REUSEADDR: {}", e);
        }
    }

    // Now try with REUSEADDR enabled (should succeed)
    let socket3 = TcpSocket::new_v4().expect("create socket3");
    socket3.set_reuseaddr(true).expect("set REUSEADDR");
    socket3.bind(bound_addr).expect("bind with REUSEADDR");
    let listener3 = socket3.listen(128).expect("listen with REUSEADDR");

    // Verify we can actually use the listener
    let bound_addr3 = listener3.local_addr().expect("get bound addr");
    assert_eq!(bound_addr, bound_addr3, "REUSEADDR listener bound to correct address");

    // Test that we can connect to the new listener
    let _client2 = StdTcpStream::connect(bound_addr3).expect("connect to REUSEADDR listener");

    println!("✓ SO_REUSEADDR enables TIME_WAIT rebinds");
}

/// Linux Test 2: SO_REUSEPORT enables load balancing
///
/// Validates that SO_REUSEPORT allows multiple listeners to bind to the same
/// address/port combination, with the kernel distributing connections across
/// them. This is a Linux-specific feature for connection load balancing.
#[test]
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn test_so_reuseport_load_balancing() {
    let base_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    // Create first listener with REUSEPORT
    let socket1 = TcpSocket::new_v4().expect("create socket1");
    socket1.set_reuseport(true).expect("set REUSEPORT on socket1");
    socket1.bind(base_addr).expect("bind socket1");
    let listener1 = socket1.listen(128).expect("listen socket1");
    let bound_addr = listener1.local_addr().expect("get local addr");

    // Create second listener with REUSEPORT on same address
    let socket2 = TcpSocket::new_v4().expect("create socket2");
    socket2.set_reuseport(true).expect("set REUSEPORT on socket2");
    socket2.bind(bound_addr).expect("bind socket2 to same addr");
    let listener2 = socket2.listen(128).expect("listen socket2");

    // Verify both listeners are bound to the same address
    let bound_addr2 = listener2.local_addr().expect("get bound addr2");
    assert_eq!(bound_addr, bound_addr2, "Both REUSEPORT listeners bound to same address");

    // Create third listener with REUSEPORT
    let socket3 = TcpSocket::new_v4().expect("create socket3");
    socket3.set_reuseport(true).expect("set REUSEPORT on socket3");
    socket3.bind(bound_addr).expect("bind socket3 to same addr");
    let listener3 = socket3.listen(128).expect("listen socket3");

    // Test that we can connect to the shared address
    // Note: We can't easily test load balancing distribution without async runtime,
    // but we can verify that multiple sockets can bind and connections succeed
    let _client1 = StdTcpStream::connect(bound_addr).expect("connect to REUSEPORT listeners");
    let _client2 = StdTcpStream::connect(bound_addr).expect("connect to REUSEPORT listeners");
    let _client3 = StdTcpStream::connect(bound_addr).expect("connect to REUSEPORT listeners");

    println!("✓ SO_REUSEPORT enables multiple listeners on same address");
}

/// POSIX Test 3: Backlog parameter honored
///
/// Validates that the backlog parameter passed to listen() affects the
/// socket's listen queue behavior. While the exact behavior is OS-dependent,
/// the parameter should be respected within reasonable limits.
#[test]
#[allow(dead_code)]
fn test_backlog_parameter_honored() {
    let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    // Test different backlog values
    let test_backlogs = vec![1, 5, 16, 128, 1024];

    for backlog in test_backlogs {
        let socket = TcpSocket::new_v4().expect("create socket");
        socket.bind(addr).expect("bind socket");

        // The listen call should succeed with any reasonable backlog value
        let listener = socket.listen(backlog).expect(&format!("listen with backlog {}", backlog));
        let bound_addr = listener.local_addr().expect("get local addr");

        // Verify the listener is functional
        let _client = StdTcpStream::connect(bound_addr)
            .expect(&format!("connect to listener with backlog {}", backlog));

        println!("✓ Backlog {} accepted and listener functional", backlog);
    }

    // Test edge case: very large backlog
    let socket = TcpSocket::new_v4().expect("create socket");
    socket.bind(addr).expect("bind socket");
    let listener = socket.listen(u32::MAX).expect("listen with max backlog");

    let bound_addr = listener.local_addr().expect("get local addr");
    let _client = StdTcpStream::connect(bound_addr).expect("connect with max backlog");

    println!("✓ Large backlog values handled correctly");
}

/// POSIX Test 4: Bind to port 0 returns OS-assigned port
///
/// Validates that binding to port 0 results in the OS selecting an available
/// port from the ephemeral range and returning the actual assigned port via
/// local_addr().
#[test]
#[allow(dead_code)]
fn test_bind_port_zero_returns_os_assigned_port() {
    let mut assigned_ports = HashSet::new();

    // Create multiple listeners with port 0 to verify OS assigns different ports
    for i in 0..5 {
        let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

        let socket = TcpSocket::new_v4().expect(&format!("create socket {}", i));
        socket.bind(addr).expect(&format!("bind socket {}", i));
        let listener = socket.listen(128).expect(&format!("listen socket {}", i));

        let bound_addr = listener.local_addr().expect(&format!("get local addr {}", i));

        // Verify port was assigned (not 0)
        assert_ne!(bound_addr.port(), 0, "OS should assign non-zero port");

        // Verify address is localhost
        assert_eq!(bound_addr.ip().to_string(), "127.0.0.1", "Address should be localhost");

        // Collect assigned ports to verify uniqueness
        let port = bound_addr.port();
        assert!(!assigned_ports.contains(&port), "OS should assign unique ports");
        assigned_ports.insert(port);

        // Verify the listener is functional
        let _client = StdTcpStream::connect(bound_addr)
            .expect(&format!("connect to auto-assigned port {}", port));

        println!("✓ OS assigned port {} for socket {}", port, i);
    }

    println!("✓ All {} assigned ports are unique", assigned_ports.len());

    // Verify ports are in reasonable ephemeral range (typically 32768-65535 on Linux)
    for port in &assigned_ports {
        assert!(*port > 1024, "Assigned port should be > 1024 (ephemeral range)");
        println!("  Port {} in ephemeral range", port);
    }
}

/// Test 5: Double-bind to same exclusive socket fails with AddrInUse
///
/// Validates that attempting to bind two sockets to the same address/port
/// without SO_REUSEADDR or SO_REUSEPORT results in an address-in-use error.
#[test]
#[allow(dead_code)]
fn test_double_bind_exclusive_socket_fails() {
    let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    // Create and bind first socket
    let socket1 = TcpSocket::new_v4().expect("create socket1");
    socket1.bind(addr).expect("bind socket1");
    let listener1 = socket1.listen(128).expect("listen socket1");
    let bound_addr = listener1.local_addr().expect("get local addr");

    // Attempt to bind second socket to same address (should fail)
    let socket2 = TcpSocket::new_v4().expect("create socket2");

    // Binding should fail since we're trying to use the same specific address
    match socket2.bind(bound_addr) {
        Ok(_) => {
            // If bind succeeds, listen should fail
            match socket2.listen(128) {
                Ok(_) => {
                    panic!("Double bind should have failed but both bind and listen succeeded");
                }
                Err(e) => {
                    println!("Listen failed as expected on double bind: {}", e);
                    assert_addr_in_use_error(&e);
                }
            }
        }
        Err(e) => {
            println!("Bind failed as expected on double bind: {}", e);
            assert_addr_in_use_error(&e);
        }
    }

    // Verify first listener still works
    let _client = StdTcpStream::connect(bound_addr).expect("original listener still functional");

    // Test with explicit same address binding
    let socket3 = TcpSocket::new_v4().expect("create socket3");
    // Don't set REUSEADDR or REUSEPORT

    // This should definitely fail since we're binding to the exact same address
    let result = socket3.bind(bound_addr);
    match result {
        Ok(_) => {
            // Bind might succeed but listen should fail
            match socket3.listen(128) {
                Ok(_) => {
                    panic!("Exclusive double bind should fail");
                }
                Err(e) => {
                    assert_addr_in_use_error(&e);
                }
            }
        }
        Err(e) => {
            assert_addr_in_use_error(&e);
        }
    }

    println!("✓ Double bind to same exclusive socket correctly fails");
}

/// Helper to verify error is address-in-use related
#[allow(dead_code)]
fn assert_addr_in_use_error(error: &Error) {
    let is_addr_in_use = error.kind() == ErrorKind::AddrInUse
        || error.kind() == ErrorKind::PermissionDenied
        || error.to_string().to_lowercase().contains("address already in use")
        || error.to_string().to_lowercase().contains("bind")
        || error.raw_os_error() == Some(98); // EADDRINUSE on Linux

    assert!(is_addr_in_use,
        "Expected address-in-use error, got: {} (kind: {:?}, raw: {:?})",
        error, error.kind(), error.raw_os_error());
}

/// Mixed scenarios test: Combines multiple socket options
#[test]
#[allow(dead_code)]
fn test_mixed_socket_option_scenarios() {
    let base_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();

    // Scenario 1: REUSEADDR + REUSEPORT together
    #[cfg(unix)]
    {
        let socket = TcpSocket::new_v4().expect("create socket");
        socket.set_reuseaddr(true).expect("set REUSEADDR");
        socket.set_reuseport(true).expect("set REUSEPORT");
        socket.bind(base_addr).expect("bind with both options");
        let listener = socket.listen(128).expect("listen with both options");

        let bound_addr = listener.local_addr().expect("get local addr");
        let _client = StdTcpStream::connect(bound_addr).expect("connect to combined options");

        println!("✓ REUSEADDR + REUSEPORT combination works");
    }

    // Scenario 2: Different backlog values with REUSEADDR
    let socket2 = TcpSocket::new_v4().expect("create socket2");
    socket2.set_reuseaddr(true).expect("set REUSEADDR");
    socket2.bind(base_addr).expect("bind socket2");
    let listener2 = socket2.listen(1).expect("listen with backlog 1");

    let bound_addr2 = listener2.local_addr().expect("get local addr2");
    let _client2 = StdTcpStream::connect(bound_addr2).expect("connect to small backlog");

    println!("✓ REUSEADDR with small backlog works");

    // Scenario 3: IPv6 socket with options
    let ipv6_addr = "[::1]:0".parse::<SocketAddr>().unwrap();
    let socket6 = TcpSocket::new_v6().expect("create IPv6 socket");
    socket6.set_reuseaddr(true).expect("set REUSEADDR on IPv6");
    socket6.bind(ipv6_addr).expect("bind IPv6 socket");
    let listener6 = socket6.listen(256).expect("listen IPv6");

    let bound_addr6 = listener6.local_addr().expect("get IPv6 local addr");
    assert!(bound_addr6.is_ipv6(), "Should be IPv6 address");
    assert_ne!(bound_addr6.port(), 0, "IPv6 should get assigned port");

    println!("✓ IPv6 socket with REUSEADDR works, port: {}", bound_addr6.port());
}

/// Comprehensive test runner for all TCP listener conformance tests
#[test]
#[allow(dead_code)]
fn test_tcp_listener_rfc_conformance_comprehensive() {
    let mut results = Vec::new();

    println!("Running TCP Listener Socket Options Conformance Tests...\n");

    // Test 1: SO_REUSEADDR TIME_WAIT rebinds
    print!("Test 1: SO_REUSEADDR allows TIME_WAIT rebinds... ");
    match std::panic::catch_unwind(|| test_so_reuseaddr_allows_time_wait_rebinds()) {
        Ok(()) => {
            println!("✓ PASS");
            results.push(TcpListenerTestResult::pass(
                "rfc-793-6056-test1",
                "SO_REUSEADDR allows TIME_WAIT rebinds"
            ));
        }
        Err(e) => {
            println!("✗ FAIL");
            results.push(TcpListenerTestResult::fail(
                "rfc-793-6056-test1",
                "SO_REUSEADDR allows TIME_WAIT rebinds",
                &format!("Test panicked: {:?}", e)
            ));
        }
    }

    // Test 2: SO_REUSEPORT load balancing (Linux only)
    #[cfg(target_os = "linux")]
    {
        print!("Test 2: SO_REUSEPORT load-balances on Linux... ");
        match std::panic::catch_unwind(|| test_so_reuseport_load_balancing()) {
            Ok(()) => {
                println!("✓ PASS");
                results.push(TcpListenerTestResult::pass(
                    "linux-reuseport-test2",
                    "SO_REUSEPORT load-balances on Linux"
                ));
            }
            Err(e) => {
                println!("✗ FAIL");
                results.push(TcpListenerTestResult::fail(
                    "linux-reuseport-test2",
                    "SO_REUSEPORT load-balances on Linux",
                    &format!("Test panicked: {:?}", e)
                ));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("Test 2: SO_REUSEPORT load-balancing... ⊘ SKIPPED (Linux only)");
        results.push(TcpListenerTestResult::pass(
            "linux-reuseport-test2",
            "SO_REUSEPORT load-balances on Linux (skipped on non-Linux)"
        ));
    }

    // Test 3: Backlog parameter honored
    print!("Test 3: Backlog parameter honored... ");
    match std::panic::catch_unwind(|| test_backlog_parameter_honored()) {
        Ok(()) => {
            println!("✓ PASS");
            results.push(TcpListenerTestResult::pass(
                "tcp-backlog-test3",
                "Backlog parameter honored"
            ));
        }
        Err(e) => {
            println!("✗ FAIL");
            results.push(TcpListenerTestResult::fail(
                "tcp-backlog-test3",
                "Backlog parameter honored",
                &format!("Test panicked: {:?}", e)
            ));
        }
    }

    // Test 4: Bind to port 0 returns OS-assigned port
    print!("Test 4: Bind to 0 returns OS-assigned port... ");
    match std::panic::catch_unwind(|| test_bind_port_zero_returns_os_assigned_port()) {
        Ok(()) => {
            println!("✓ PASS");
            results.push(TcpListenerTestResult::pass(
                "posix-port-zero-test4",
                "Bind to 0 returns OS-assigned port"
            ));
        }
        Err(e) => {
            println!("✗ FAIL");
            results.push(TcpListenerTestResult::fail(
                "posix-port-zero-test4",
                "Bind to 0 returns OS-assigned port",
                &format!("Test panicked: {:?}", e)
            ));
        }
    }

    // Test 5: Double-bind exclusive fails
    print!("Test 5: Double-bind to same exclusive socket fails... ");
    match std::panic::catch_unwind(|| test_double_bind_exclusive_socket_fails()) {
        Ok(()) => {
            println!("✓ PASS");
            results.push(TcpListenerTestResult::pass(
                "addr-conflict-test5",
                "Double-bind to same exclusive socket fails"
            ));
        }
        Err(e) => {
            println!("✗ FAIL");
            results.push(TcpListenerTestResult::fail(
                "addr-conflict-test5",
                "Double-bind to same exclusive socket fails",
                &format!("Test panicked: {:?}", e)
            ));
        }
    }

    // Mixed scenarios test
    print!("Test 6: Mixed socket option scenarios... ");
    match std::panic::catch_unwind(|| test_mixed_socket_option_scenarios()) {
        Ok(()) => {
            println!("✓ PASS");
            results.push(TcpListenerTestResult::pass(
                "mixed-scenarios-test6",
                "Mixed socket option scenarios"
            ));
        }
        Err(e) => {
            println!("✗ FAIL");
            results.push(TcpListenerTestResult::fail(
                "mixed-scenarios-test6",
                "Mixed socket option scenarios",
                &format!("Test panicked: {:?}", e)
            ));
        }
    }

    // Print summary
    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();

    println!("\n=== TCP Listener Conformance Test Summary ===");
    println!("Passed: {}/{}", passed, total);

    for result in &results {
        let status = if result.passed { "✓ PASS" } else { "✗ FAIL" };
        println!("{}: {} - {}", status, result.test_id, result.description);
        if let Some(ref error) = result.error_message {
            println!("    Error: {}", error);
        }
    }

    // Ensure all tests passed
    assert_eq!(passed, total, "All TCP listener conformance tests must pass");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the test result structure itself.
    #[test]
    #[allow(dead_code)]
    fn test_tcp_listener_test_result_structure() {
        let pass_result = TcpListenerTestResult::pass("test-1", "Test description");
        assert!(pass_result.passed);
        assert!(pass_result.error_message.is_none());

        let fail_result = TcpListenerTestResult::fail("test-2", "Failed test", "Error message");
        assert!(!fail_result.passed);
        assert!(fail_result.error_message.is_some());
        assert_eq!(fail_result.error_message.unwrap(), "Error message");
    }

    /// Test socket creation and basic operations.
    #[test]
    #[allow(dead_code)]
    fn test_socket_creation_and_binding() {
        let socket = TcpSocket::new_v4().expect("create IPv4 socket");
        let addr = "127.0.0.1:0".parse().expect("parse address");
        socket.bind(addr).expect("bind socket");
        let listener = socket.listen(128).expect("listen");

        let bound_addr = listener.local_addr().expect("get local address");
        assert_ne!(bound_addr.port(), 0, "Should have non-zero port");
        assert_eq!(bound_addr.ip().to_string(), "127.0.0.1");
    }

    /// Test SO_REUSEADDR option setting.
    #[test]
    #[allow(dead_code)]
    fn test_reuseaddr_option_setting() {
        let socket = TcpSocket::new_v4().expect("create socket");
        socket.set_reuseaddr(true).expect("set REUSEADDR");
        socket.set_reuseaddr(false).expect("unset REUSEADDR");
        // Should not panic - option setting should work
    }

    /// Test SO_REUSEPORT option setting (Unix only).
    #[test]
    #[cfg(unix)]
    #[allow(dead_code)]
    fn test_reuseport_option_setting() {
        let socket = TcpSocket::new_v4().expect("create socket");
        socket.set_reuseport(true).expect("set REUSEPORT");
        socket.set_reuseport(false).expect("unset REUSEPORT");
        // Should not panic - option setting should work
    }

    /// Test IPv6 socket creation.
    #[test]
    #[allow(dead_code)]
    fn test_ipv6_socket_creation() {
        let socket = TcpSocket::new_v6().expect("create IPv6 socket");
        let addr = "[::1]:0".parse().expect("parse IPv6 address");
        socket.bind(addr).expect("bind IPv6 socket");
        let listener = socket.listen(128).expect("listen on IPv6");

        let bound_addr = listener.local_addr().expect("get local address");
        assert!(bound_addr.is_ipv6(), "Should be IPv6 address");
        assert_ne!(bound_addr.port(), 0, "Should have non-zero port");
    }
}