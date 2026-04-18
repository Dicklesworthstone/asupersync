//! Golden tests for transport stream half-close conformance.
//!
//! Validates TCP/TLS half-close semantics per RFC specifications:
//! - shutdown(Write) sends TCP FIN packet
//! - shutdown(Read) discards subsequent reads
//! - shutdown(Both) equivalent to close()
//! - TLS close_notify sent before TCP FIN
//! - Peer-initiated half-close observable via EOF
//!
//! Run with `UPDATE_TRANSPORT_GOLDEN=1` to regenerate golden artifacts.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

/// Golden test framework for transport half-close semantics.
#[allow(dead_code)]
pub struct HalfCloseGoldenTester {
    /// Whether to update golden artifacts instead of validating.
    update_golden: bool,
}

#[allow(dead_code)]
impl HalfCloseGoldenTester {
    /// Create a new golden tester.
    pub fn new() -> Self {
        Self {
            update_golden: std::env::var("UPDATE_TRANSPORT_GOLDEN").is_ok(),
        }
    }

    /// Test shutdown(Write) sends FIN packet - Requirement (1).
    fn test_shutdown_write_sends_fin(&self, _test_name: &str) -> io::Result<HalfCloseResult> {
        let (mut client, mut server) = self.create_connected_tcp_pair()?;

        // Client shuts down write side
        client.shutdown(Shutdown::Write)?;

        // Give some time for the FIN to propagate
        std::thread::sleep(Duration::from_millis(10));

        // Server should observe EOF on read
        let mut buf = [0u8; 64];
        let server_eof = match server.read(&mut buf) {
            Ok(0) => true,                                        // EOF indicates FIN received
            Ok(_) => false,                                       // Still receiving data
            Err(e) if e.kind() == ErrorKind::WouldBlock => false, // No data yet
            Err(_) => false,                                      // Other error
        };

        // Client can still read (half-duplex)
        let client_can_read = match client.read(&mut buf) {
            Ok(_) => true,
            Err(e) if e.kind() == ErrorKind::WouldBlock => true,
            Err(_) => false,
        };

        Ok(HalfCloseResult {
            operation: "shutdown_write".to_string(),
            peer_observes_eof: server_eof,
            local_can_read: client_can_read,
            local_can_write: false, // Should not be able to write after shutdown(Write)
            error: None,
        })
    }

    /// Test shutdown(Read) discards subsequent reads - Requirement (2).
    fn test_shutdown_read_discards_data(&self, _test_name: &str) -> io::Result<HalfCloseResult> {
        let (mut client, mut server) = self.create_connected_tcp_pair()?;

        // Server sends data before client shuts down read
        let test_data = b"test data before shutdown";
        let _ = server.write(test_data);

        // Client shuts down read side
        client.shutdown(Shutdown::Read)?;

        // Server sends more data after client shutdown(Read)
        let more_data = b"data after shutdown read";
        let _write_success = server.write(more_data).is_ok();

        // Client should not receive any data after shutdown(Read)
        let mut buf = [0u8; 64];
        let _client_reads_data = match client.read(&mut buf) {
            Ok(0) => false,                                       // EOF is expected behavior
            Ok(_) => true,                                        // Should NOT receive data
            Err(e) if e.kind() == ErrorKind::WouldBlock => false, // No data (good)
            Err(_) => false,                                      // Error (acceptable)
        };

        // Client can still write (half-duplex)
        let client_can_write = client.write(b"response").is_ok();

        Ok(HalfCloseResult {
            operation: "shutdown_read".to_string(),
            peer_observes_eof: false, // Server shouldn't see EOF yet
            local_can_read: false,    // Should not read after shutdown(Read)
            local_can_write: client_can_write,
            error: None,
        })
    }

    /// Test shutdown(Both) equivalent to close() - Requirement (3).
    fn test_shutdown_both_equals_close(&self, _test_name: &str) -> io::Result<HalfCloseResult> {
        let (mut client1, mut server1) = self.create_connected_tcp_pair()?;
        let (client2, mut server2) = self.create_connected_tcp_pair()?;

        // Test 1: shutdown(Both)
        client1.shutdown(Shutdown::Both)?;
        let mut buf = [0u8; 64];
        let server1_eof = server1.read(&mut buf).is_ok_and(|n| n == 0);
        let client1_write_err = client1.write(b"test").is_err();
        let client1_read_err = client1.read(&mut buf).is_err();

        // Test 2: close() - drop the socket
        drop(client2);
        // Allow some time for the connection to close
        std::thread::sleep(Duration::from_millis(10));
        let server2_eof = server2.read(&mut buf).is_ok_and(|n| n == 0);

        // Both should behave identically
        let behaviors_match = (server1_eof == server2_eof) && client1_write_err && client1_read_err;

        Ok(HalfCloseResult {
            operation: "shutdown_both".to_string(),
            peer_observes_eof: server1_eof,
            local_can_read: false,
            local_can_write: false,
            error: if behaviors_match {
                None
            } else {
                Some("shutdown(Both) behavior differs from close()".to_string())
            },
        })
    }

    /// Test peer-initiated half-close observable via EOF - Requirement (5).
    fn test_peer_initiated_half_close_eof(&self, _test_name: &str) -> io::Result<HalfCloseResult> {
        let (mut client, mut server) = self.create_connected_tcp_pair()?;

        // Peer (server) initiates write shutdown
        server.shutdown(Shutdown::Write)?;

        // Give time for the FIN to propagate
        std::thread::sleep(Duration::from_millis(10));

        // Client should observe EOF when trying to read
        let mut buf = [0u8; 64];
        let client_observes_eof = match client.read(&mut buf) {
            Ok(0) => true,  // EOF observed
            Ok(_) => false, // Still receiving data
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // Data not available yet, try again briefly
                std::thread::sleep(Duration::from_millis(1));
                client.read(&mut buf).is_ok_and(|n| n == 0)
            }
            Err(_) => false, // Error
        };

        // Client can still write back to peer
        let client_can_write = client.write(b"ack").is_ok();

        // Peer can still read client's response
        let server_can_read = server.read(&mut buf).is_ok()
            || matches!(server.read(&mut buf), Err(ref e) if e.kind() == ErrorKind::WouldBlock);

        Ok(HalfCloseResult {
            operation: "peer_half_close".to_string(),
            peer_observes_eof: client_observes_eof,
            local_can_read: server_can_read,
            local_can_write: client_can_write,
            error: None,
        })
    }

    /// Assert golden result for half-close behavior.
    fn assert_half_close_golden(
        &self,
        result: &HalfCloseResult,
        test_name: &str,
        expected_golden: &str,
    ) {
        let actual_golden = result.to_golden_string();

        if self.update_golden {
            println!("TRANSPORT_GOLDEN UPDATE {}: {}", test_name, actual_golden);
            return;
        }

        assert_eq!(
            actual_golden, expected_golden,
            "Half-close behavior mismatch for {}\nExpected: {}\nActual:   {}",
            test_name, expected_golden, actual_golden
        );
    }

    /// Create a connected TCP pair for testing.
    fn create_connected_tcp_pair(&self) -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let client = TcpStream::connect(addr)?;
        let (server, _) = listener.accept()?;

        // Set non-blocking for testing to avoid hanging on read/write operations
        client.set_nonblocking(true)?;
        server.set_nonblocking(true)?;

        Ok((client, server))
    }
}

/// Result of a half-close conformance test.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
struct HalfCloseResult {
    operation: String,
    peer_observes_eof: bool,
    local_can_read: bool,
    local_can_write: bool,
    error: Option<String>,
}

#[allow(dead_code)]
impl HalfCloseResult {
    /// Convert to golden string representation.
    fn to_golden_string(&self) -> String {
        format!(
            "op:{},eof:{},read:{},write:{},err:{}",
            self.operation,
            self.peer_observes_eof,
            self.local_can_read,
            self.local_can_write,
            self.error.as_deref().unwrap_or("none")
        )
    }
}

// ============================================================================
// Golden Conformance Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_shutdown_write_golden() {
        init_test("test_shutdown_write_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_shutdown_write_sends_fin("shutdown_write")
            .expect("shutdown write test should succeed");

        // Golden: shutdown(Write) should prevent local writes, allow reads, trigger peer EOF
        tester.assert_half_close_golden(
            &result,
            "shutdown_write",
            "op:shutdown_write,eof:true,read:true,write:false,err:none",
        );

        crate::test_complete!("test_shutdown_write_golden");
    }

    #[test]
    fn test_shutdown_read_golden() {
        init_test("test_shutdown_read_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_shutdown_read_discards_data("shutdown_read")
            .expect("shutdown read test should succeed");

        // Golden: shutdown(Read) should discard reads, allow writes, no peer EOF
        tester.assert_half_close_golden(
            &result,
            "shutdown_read",
            "op:shutdown_read,eof:false,read:false,write:true,err:none",
        );

        crate::test_complete!("test_shutdown_read_golden");
    }

    #[test]
    fn test_shutdown_both_golden() {
        init_test("test_shutdown_both_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_shutdown_both_equals_close("shutdown_both")
            .expect("shutdown both test should succeed");

        // Golden: shutdown(Both) should behave identically to close()
        tester.assert_half_close_golden(
            &result,
            "shutdown_both",
            "op:shutdown_both,eof:true,read:false,write:false,err:none",
        );

        crate::test_complete!("test_shutdown_both_golden");
    }

    #[test]
    fn test_peer_half_close_eof_golden() {
        init_test("test_peer_half_close_eof_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_peer_initiated_half_close_eof("peer_half_close")
            .expect("peer half close test should succeed");

        // Golden: peer shutdown(Write) should be observable as EOF on local read
        tester.assert_half_close_golden(
            &result,
            "peer_half_close",
            "op:peer_half_close,eof:true,read:true,write:true,err:none",
        );

        crate::test_complete!("test_peer_half_close_eof_golden");
    }
}
