//! MySQL LOAD DATA LOCAL INFILE security audit.
//!
//! AUDIT FINDING: SOUND - Local infile disabled and properly rejected
//!
//! The MySQL client correctly implements LOAD DATA LOCAL INFILE security best practices:
//! - Does not advertise CLIENT_LOCAL_FILES capability during handshake (prevention)
//! - Rejects server LOAD DATA LOCAL INFILE requests with protocol error (defense)
//! - Maintains fail-closed connection state after rejection (security)

#![cfg(test)]

use super::{
    Handshake, MySqlConnectOptions, MySqlConnection, MySqlConnectionInner, MySqlError, capability,
};
use crate::cx::Cx;
use crate::types::Outcome;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}

/// Packet buffer helper for building MySQL protocol packets
struct PacketBuffer {
    buf: Vec<u8>,
    sequence: u8,
}

impl PacketBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            sequence: 0,
        }
    }

    fn set_sequence(&mut self, seq: u8) {
        self.sequence = seq;
    }

    fn write_byte(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn build_packet(self) -> MySqlPacket {
        let length = self.buf.len() as u32;
        let mut packet = Vec::new();

        // 3-byte length + 1-byte sequence
        packet.extend_from_slice(&length.to_le_bytes()[0..3]);
        packet.push(self.sequence);
        packet.extend_from_slice(&self.buf);

        MySqlPacket { bytes: packet }
    }
}

struct MySqlPacket {
    bytes: Vec<u8>,
}

fn make_test_connection(stream: crate::net::TcpStream, sequence: u8) -> MySqlConnection {
    MySqlConnection {
        inner: MySqlConnectionInner {
            stream,
            connection_id: 0,
            capabilities: 0,
            charset: 0,
            status_flags: 0,
            sequence,
            closed: false,
            server_version: String::new(),
            needs_rollback: false,
            max_result_rows: super::DEFAULT_MAX_RESULT_ROWS,
            prepared_statement_epoch: 0,
            query_in_flight: AtomicBool::new(false),
        },
        options: None,
    }
}

/// AUDIT: Test that client does not advertise LOCAL INFILE capability by default
///
/// Per MySQL security best practice, clients should not advertise CLIENT_LOCAL_FILES
/// capability unless explicitly configured to allow local file operations.
/// This prevents malicious servers from knowing the client supports file operations.
#[test]
fn audit_handshake_does_not_advertise_local_infile_capability() {
    // AUDIT: MySQL LOAD DATA LOCAL INFILE capability advertisement test

    // AUDIT VERIFICATION: Client handshake response excludes CLIENT_LOCAL_FILES
    //
    // MySQL handshake flow:
    // 1. Server sends Initial Handshake packet with capabilities
    // 2. Client responds with Handshake Response containing client capabilities
    // 3. SECURITY: Client must NOT include CLIENT_LOCAL_FILES unless explicitly enabled

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        // Send Initial Handshake packet
        let handshake = create_initial_handshake_packet();
        stream.write_all(&handshake.bytes).expect("write handshake");
        stream.flush().expect("flush handshake");

        // Read client's Handshake Response
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .expect("read response header");

        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]);
        let mut payload = vec![0u8; length as usize];
        stream
            .read_exact(&mut payload)
            .expect("read response payload");

        // AUDIT: Verify client capabilities exclude LOCAL FILES
        let client_caps = u32::from_le_bytes(
            payload
                .get(0..4)
                .and_then(|s| s.try_into().ok())
                .expect("client capability bytes missing"),
        );

        assert_eq!(
            client_caps & capability::CLIENT_LOCAL_FILES,
            0,
            "SECURITY: Client must not advertise CLIENT_LOCAL_FILES capability by default"
        );

        // Sanity check: verify we're getting a real handshake response
        assert_ne!(
            client_caps & capability::CLIENT_PROTOCOL_41,
            0,
            "Sanity check: expected normal handshake capabilities"
        );
    });

    // Connect and trigger handshake
    let stream = run(async {
        crate::net::TcpStream::connect_socket_addr(addr)
            .await
            .expect("connect to test server")
    });

    let mut conn = make_test_connection(stream, 1);
    let options = MySqlConnectOptions::parse("mysql://user:pass@localhost/testdb")
        .expect("parse mysql options");
    let handshake = Handshake {
        server_version: "8.0.0-test".to_string(),
        connection_id: 99,
        auth_plugin_data: b"01234567890123456789".to_vec(),
        capabilities: capability::CLIENT_PROTOCOL_41
            | capability::CLIENT_SECURE_CONNECTION
            | capability::CLIENT_PLUGIN_AUTH
            | capability::CLIENT_LOCAL_FILES,
        charset: 45,
        status_flags: 0,
        auth_plugin_name: "caching_sha2_password".to_string(),
    };

    run(conn.send_handshake_response(&options, &handshake)).expect("send handshake response");
    server.join().expect("server thread join");

    // AUDIT COMPLETE: Client properly excludes LOCAL INFILE capability
}

/// AUDIT: Test server-initiated LOAD DATA LOCAL INFILE request rejection
///
/// When a malicious server sends a LOAD DATA LOCAL INFILE request (0xFB packet),
/// the client must reject it to prevent local file exfiltration attacks.
#[test]
fn audit_server_local_infile_request_rejection() {
    // AUDIT VERIFICATION: Server LOAD DATA LOCAL INFILE requests are rejected
    //
    // Attack scenario:
    // 1. Client connects to compromised/malicious MySQL server
    // 2. Server responds to query with LOAD DATA LOCAL INFILE request
    // 3. SECURITY: Client must reject (not read local files for server)

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        // Read the query packet (we don't need to parse it for this test)
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).expect("read query header");
        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]);
        let mut _payload = vec![0u8; length as usize];
        stream
            .read_exact(&mut _payload)
            .expect("read query payload");

        // Send malicious LOAD DATA LOCAL INFILE request
        let mut response = PacketBuffer::new();
        response.write_byte(0xFB); // LOAD DATA LOCAL INFILE packet type
        response.write_bytes(b"/etc/passwd"); // Malicious file path

        let mut packet = PacketBuffer::new();
        packet.set_sequence(1);
        packet.buf = response.buf;
        let packet = packet.build_packet();

        stream
            .write_all(&packet.bytes)
            .expect("write malicious LOCAL INFILE request");
        stream.flush().expect("flush LOCAL INFILE request");
    });

    // Create connection without going through full handshake
    let stream = run(async {
        crate::net::TcpStream::connect_socket_addr(addr)
            .await
            .expect("connect client")
    });

    let mut conn = make_test_connection(stream, 0);

    let cx = Cx::for_testing();

    // Execute query that triggers malicious server response
    let outcome = run(conn.query_static_sql(&cx, "SELECT 1"));

    // AUDIT VERIFICATION: Client rejects LOCAL INFILE request
    match outcome {
        Outcome::Err(MySqlError::Protocol(msg)) => {
            assert!(
                msg.contains("LOAD DATA LOCAL INFILE request rejected"),
                "SECURITY: Error message must indicate LOCAL INFILE rejection, got: {msg}"
            );
            assert!(
                msg.contains("disabled by default"),
                "SECURITY: Error message must indicate LOCAL INFILE is disabled, got: {msg}"
            );
        }
        other => {
            panic!(
                "CRITICAL: Expected LOCAL INFILE rejection, got: {other:?}. \
                 Client may be vulnerable to file exfiltration attacks!"
            );
        }
    }

    server.join().expect("server thread join");

    // AUDIT: Verify connection is properly closed after rejection (fail-closed)
    assert!(
        conn.inner.closed,
        "SECURITY: Connection must be closed after LOCAL INFILE rejection (fail-closed behavior)"
    );

    // AUDIT COMPLETE: Server LOCAL INFILE requests properly rejected
}

/// AUDIT: Test LOCAL INFILE rejection with various file paths
///
/// Ensures the rejection is universal and not dependent on the requested file path.
#[test]
fn audit_local_infile_rejection_comprehensive_paths() {
    // AUDIT: Test rejection works for various malicious file paths
    let malicious_paths: &[&[u8]] = &[
        b"/etc/passwd",                        // Unix system file
        b"/etc/shadow",                        // Unix password file
        b"C:\\windows\\system32\\config\\SAM", // Windows SAM file
        b"../../../etc/passwd",                // Directory traversal
        b"/proc/self/environ",                 // Process environment
        b"/home/user/.ssh/id_rsa",             // SSH private key
        b"/var/log/mysql/mysql.log",           // MySQL logs
        b"",                                   // Empty path
        b"/tmp/does-not-exist.txt",            // Non-existent file
    ];

    for (i, &path) in malicious_paths.iter().enumerate() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let path_clone = path.to_vec();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            // Skip query packet
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read query header");
            let length = u32::from_le_bytes([header[0], header[1], header[2], 0]);
            let mut _payload = vec![0u8; length as usize];
            stream
                .read_exact(&mut _payload)
                .expect("read query payload");

            // Send LOAD DATA LOCAL INFILE with malicious path
            let mut response = PacketBuffer::new();
            response.write_byte(0xFB);
            response.write_bytes(&path_clone);

            let mut packet = PacketBuffer::new();
            packet.set_sequence(1);
            packet.buf = response.buf;
            let packet = packet.build_packet();

            stream
                .write_all(&packet.bytes)
                .expect("write LOCAL INFILE request");
            stream.flush().expect("flush LOCAL INFILE request");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = make_test_connection(stream, 0);

        let cx = Cx::for_testing();
        let outcome = run(conn.query_static_sql(&cx, "SELECT 1"));

        // AUDIT: Every path must be rejected
        assert!(
            matches!(outcome, Outcome::Err(MySqlError::Protocol(ref msg))
                if msg.contains("LOAD DATA LOCAL INFILE request rejected")),
            "SECURITY: Path {} (test {}) must be rejected, got: {outcome:?}",
            String::from_utf8_lossy(path),
            i + 1
        );

        server.join().expect("server thread join");
    }

    // AUDIT COMPLETE: All malicious paths properly rejected
}

/// Helper function to create a minimal MySQL Initial Handshake packet
fn create_initial_handshake_packet() -> MySqlPacket {
    let mut handshake = PacketBuffer::new();
    handshake.set_sequence(0);

    // Protocol version
    handshake.write_byte(10);
    // Server version (null-terminated)
    handshake.write_bytes(b"8.0.0-test\0");
    // Connection ID (4 bytes)
    handshake.write_bytes(&99u32.to_le_bytes());
    // Auth plugin data part 1 (8 bytes)
    handshake.write_bytes(b"12345678");
    // Filler (1 byte)
    handshake.write_byte(0);
    // Capability flags lower 2 bytes
    let caps_low = (capability::CLIENT_PROTOCOL_41
        | capability::CLIENT_SECURE_CONNECTION
        | capability::CLIENT_PLUGIN_AUTH
        | capability::CLIENT_LOCAL_FILES) as u16; // Server advertises LOCAL_FILES
    handshake.write_bytes(&caps_low.to_le_bytes());
    // Character set (1 byte)
    handshake.write_byte(45);
    // Status flags (2 bytes)
    handshake.write_bytes(&0u16.to_le_bytes());
    // Capability flags upper 2 bytes
    handshake.write_bytes(&0u16.to_le_bytes());
    // Auth plugin data length (1 byte)
    handshake.write_byte(21);
    // Reserved (10 bytes)
    handshake.write_bytes(&[0u8; 10]);
    // Auth plugin data part 2 (12 bytes)
    handshake.write_bytes(b"123456789012");
    // Auth plugin name (null-terminated)
    handshake.write_bytes(b"caching_sha2_password\0");

    handshake.build_packet()
}
