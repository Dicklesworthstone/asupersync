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

        // Server should observe EOF on read
        let server_eof = Self::wait_for_eof(&mut server);

        // Client can still read (half-duplex)
        let mut buf = [0u8; 64];
        let client_can_read = match client.read(&mut buf) {
            Ok(_) => true,
            Err(e) if e.kind() == ErrorKind::WouldBlock => true,
            Err(_) => false,
        };

        // br-asupersync-njo37t: actually probe the post-shutdown write
        // path instead of hardcoding `false`. A transport wrapper that
        // silently dropped shutdown(Write) (or whose Drop / wrapper
        // re-enabled the write half) used to satisfy the golden
        // because `local_can_write` was a literal. Now we observe.
        // Per RFC 9293 §3.10.4 / POSIX shutdown(2): writes attempted
        // after shutdown(SHUT_WR) MUST fail. On Linux + non-blocking
        // we expect Err(BrokenPipe) (or in races where the FIN has
        // not yet been ACKed and the send buffer is full,
        // Err(WouldBlock) — which still means the write did not
        // succeed). Either Err counts as "cannot write".
        let post_shutdown_write = client.write(b"post-shutdown-write-probe");
        let local_can_write = post_shutdown_write.is_ok();
        let error = if local_can_write {
            // The probe wrote bytes after shutdown(Write) — that's
            // the regression we want to surface, and the golden
            // string (which pins `err:none`) will fail loudly.
            Some("shutdown(Write) still allowed local writes".to_string())
        } else {
            None
        };

        Ok(HalfCloseResult {
            operation: "shutdown_write".to_string(),
            peer_observes_eof: server_eof,
            local_can_read: client_can_read,
            local_can_write,
            error,
        })
    }

    /// Test shutdown(Read) discards subsequent reads - Requirement (2).
    fn test_shutdown_read_discards_data(&self, _test_name: &str) -> io::Result<HalfCloseResult> {
        let (mut client, mut server) = self.create_connected_tcp_pair()?;

        // Server sends data before client shuts down read. Linux retains
        // pre-shutdown bytes already in the receive buffer (POSIX leaves
        // this implementation-defined), so the invariant we want to check
        // is "data the peer writes *after* our shutdown(Read) is not
        // delivered" — not "the kernel discards already-buffered bytes".
        let test_data = b"test data before shutdown";
        let _ = server.write(test_data);

        // Drain anything already in flight before the shutdown so the
        // post-shutdown probe is unambiguous. The drain is best-effort:
        // WouldBlock means the data hasn't arrived yet, which is fine —
        // the post-shutdown probe will still flip if delivery sneaks
        // through.
        let mut drain_buf = [0u8; 64];
        let mut drain_attempts = 0;
        while drain_attempts < 32 {
            match client.read(&mut drain_buf) {
                Ok(0) => break,
                Ok(_) => {} // pre-shutdown bytes consumed
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
            drain_attempts += 1;
        }

        // Client shuts down read side
        client.shutdown(Shutdown::Read)?;

        // Server sends more data after client shutdown(Read). Allow the
        // packet to traverse loopback before probing — without this the
        // probe would see WouldBlock simply because data hasn't arrived,
        // not because shutdown is enforcing the invariant.
        let more_data = b"data after shutdown read";
        let _write_success = server.write(more_data).is_ok();
        std::thread::sleep(Duration::from_millis(10));

        // Client should not receive any data after shutdown(Read).
        let mut buf = [0u8; 64];
        let client_reads_data = match client.read(&mut buf) {
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
            // Plumb the actual probe result so a regression that lets bytes
            // through after shutdown(Read) flips the golden string. The
            // expected golden pins `read:false`; if a future change made
            // the kernel-level shutdown a no-op the assertion would now
            // fail instead of silently passing.
            local_can_read: client_reads_data,
            local_can_write: client_can_write,
            error: client_reads_data
                .then_some("shutdown(Read) still allowed local reads".to_string()),
        })
    }

    /// Test shutdown(Both) equivalent to close() - Requirement (3).
    fn test_shutdown_both_equals_close(&self, _test_name: &str) -> io::Result<HalfCloseResult> {
        let (mut client1, mut server1) = self.create_connected_tcp_pair()?;
        let (client2, mut server2) = self.create_connected_tcp_pair()?;

        // Test 1: shutdown(Both)
        client1.shutdown(Shutdown::Both)?;
        let mut buf = [0u8; 64];
        let server1_eof = Self::wait_for_eof(&mut server1);
        let client1_write_err = client1.write(b"test").is_err();
        let client1_cannot_read = match client1.read(&mut buf) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) if e.kind() == ErrorKind::WouldBlock => false,
            Err(_) => true,
        };

        // Test 2: close() - drop the socket
        drop(client2);
        let server2_eof = Self::wait_for_eof(&mut server2);

        // Both should behave identically
        let behaviors_match =
            (server1_eof == server2_eof) && client1_write_err && client1_cannot_read;

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

        // Client should observe EOF when trying to read
        let client_observes_eof = Self::wait_for_eof(&mut client);

        // Client can still write back to peer
        let client_can_write = client.write(b"ack").is_ok();

        // Peer can still read client's response
        let mut buf = [0u8; 64];
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

    fn wait_for_eof(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 64];

        for _ in 0..32 {
            match stream.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => return false,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return false,
            }
        }

        false
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
#[path = "half_close_conformance_tests_inline_tests.rs"]
mod tests;
