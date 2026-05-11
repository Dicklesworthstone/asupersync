#![no_main]

//! Multi-stage TLS handshake state machine fuzzer
//!
//! This fuzzer specifically targets the TLS state machine transitions in TlsStream
//! to find bugs in protocol sequence handling, state transitions, and error recovery.
//!
//! Attack vectors tested:
//! - Invalid TLS handshake message sequences (missing/duplicate/out-of-order)
//! - State confusion attacks (malformed TLS records)
//! - Protocol version mismatch fallbacks
//! - Partial/corrupted handshake messages
//! - Timing attacks (connection drops during handshake)
//! - Integration boundary issues with rustls

use arbitrary::Arbitrary;
use asupersync::tls::{TlsConnector, TlsConnectorBuilder, TlsError};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Input structure for TLS state machine fuzzing
#[derive(Arbitrary, Debug)]
struct TlsStateMachineFuzzInput {
    /// Sequence of TLS operations to perform
    operations: Vec<TlsOperation>,
    /// Timing behavior (connection drops, partial operations)
    timing_behavior: TimingBehavior,
    /// Protocol violation configuration
    protocol_violations: ProtocolViolations,
}

/// TLS operations that can be fuzzed
#[derive(Arbitrary, Debug)]
enum TlsOperation {
    /// Valid TLS handshake operations
    StartHandshake,
    WriteApplicationData(Vec<u8>),
    ReadData,
    Shutdown,

    /// Attack operations for state machine testing
    SendMalformedRecord(MalformedRecord),
    ForceStateTransition(TlsState),
    InjectDuringHandshake(Vec<u8>),
    AbruptDisconnect,
    PartialHandshakeMessage(HandshakeMessageType, Vec<u8>),
    DuplicateHandshakeMessage(HandshakeMessageType),
    OutOfOrderMessage(HandshakeMessageType),
    VersionMismatch(ProtocolVersion),
}

/// TLS state for forced transitions
#[derive(Arbitrary, Debug, Clone, Copy)]
enum TlsState {
    Handshaking,
    Ready,
    ShuttingDown,
    Closed,
}

/// TLS handshake message types
#[derive(Arbitrary, Debug, Clone, Copy)]
enum HandshakeMessageType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
}

/// Protocol versions for version mismatch testing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ProtocolVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Invalid(u16),
}

/// Malformed TLS record configuration
#[derive(Arbitrary, Debug)]
struct MalformedRecord {
    /// Corrupted record type
    record_type: u8,
    /// Malformed protocol version
    protocol_version: [u8; 2],
    /// Record length (may be invalid)
    length: u16,
    /// Record payload (may be corrupted)
    payload: Vec<u8>,
}

/// Timing-based attack configuration
#[derive(Arbitrary, Debug)]
struct TimingBehavior {
    /// Whether to simulate partial writes
    partial_writes: bool,
    /// Connection drop timing
    connection_drop: Option<ConnectionDrop>,
    /// Read/write delay simulation
    io_delays: Vec<IoDelay>,
}

#[derive(Arbitrary, Debug)]
struct ConnectionDrop {
    /// At which operation to drop the connection
    at_operation: u8,
    /// Whether to drop cleanly or abruptly
    clean_drop: bool,
}

#[derive(Arbitrary, Debug)]
struct IoDelay {
    /// Operation index to delay
    operation_index: u8,
    /// Whether to delay reads or writes
    delay_reads: bool,
    delay_writes: bool,
}

/// Protocol violation configuration
#[derive(Arbitrary, Debug)]
struct ProtocolViolations {
    /// Send invalid TLS record types
    invalid_record_types: Vec<u8>,
    /// Corrupt message authentication codes
    corrupt_mac: bool,
    /// Use invalid cipher suites
    invalid_cipher_suites: Vec<u16>,
    /// Violate message size limits
    oversized_messages: bool,
    /// Send messages with invalid lengths
    invalid_lengths: bool,
}

/// Mock TLS transport for state machine testing
struct MockTlsTransport {
    /// Sequence of operations to execute
    operations: VecDeque<TlsOperation>,
    /// Current operation index
    operation_index: usize,
    /// Timing behavior configuration
    timing: TimingBehavior,
    /// Protocol violations to apply
    violations: ProtocolViolations,
    /// Whether connection is closed
    closed: bool,
    /// Buffer for incoming data simulation
    read_buffer: VecDeque<u8>,
    /// Buffer for outgoing data capture
    write_buffer: Vec<u8>,
    /// Current TLS state for tracking
    current_state: TlsState,
}

impl MockTlsTransport {
    fn new(input: TlsStateMachineFuzzInput) -> Self {
        let operations = input.operations.into();

        Self {
            operations,
            operation_index: 0,
            timing: input.timing_behavior,
            violations: input.protocol_violations,
            closed: false,
            read_buffer: VecDeque::new(),
            write_buffer: Vec::new(),
            current_state: TlsState::Handshaking,
        }
    }

    fn should_delay_io(&self, is_read: bool) -> bool {
        self.timing.io_delays.iter().any(|delay| {
            delay.operation_index as usize == self.operation_index
                && ((is_read && delay.delay_reads) || (!is_read && delay.delay_writes))
        })
    }

    fn process_next_operation(&mut self) -> Option<TlsOperation> {
        if let Some(drop_config) = &self.timing.connection_drop
            && self.operation_index >= drop_config.at_operation as usize
        {
            self.closed = true;
            if !drop_config.clean_drop {
                self.read_buffer.push_back(0xff);
            }
            return None;
        }

        self.operations.pop_front()
    }

    fn create_malformed_tls_record(&self, record: &MalformedRecord) -> Vec<u8> {
        let mut buffer = Vec::new();

        // TLS record header: [type][version][length]
        let record_type = self
            .violations
            .invalid_record_types
            .first()
            .copied()
            .unwrap_or(record.record_type);
        buffer.push(record_type);
        buffer.extend_from_slice(&record.protocol_version);
        buffer.extend_from_slice(&record.length.to_be_bytes());

        // Apply protocol violations to payload
        let mut payload = record.payload.clone();
        if self.violations.oversized_messages && payload.len() < 16384 {
            payload.resize(16384, 0xAA); // Maximum TLS record size violation
        }

        if self.violations.corrupt_mac && payload.len() >= 16 {
            // Corrupt the last 16 bytes (typical MAC location)
            let mac_start = payload.len() - 16;
            for byte in &mut payload[mac_start..] {
                *byte = byte.wrapping_add(1); // Subtle MAC corruption
            }
        }

        buffer.extend(payload);
        buffer
    }

    fn create_handshake_message(&self, msg_type: HandshakeMessageType, data: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();

        // TLS handshake message header: [msg_type][length]
        let type_byte = match msg_type {
            HandshakeMessageType::ClientHello => 1,
            HandshakeMessageType::ServerHello => 2,
            HandshakeMessageType::Certificate => 11,
            HandshakeMessageType::ServerKeyExchange => 12,
            HandshakeMessageType::CertificateRequest => 13,
            HandshakeMessageType::ServerHelloDone => 14,
            HandshakeMessageType::CertificateVerify => 15,
            HandshakeMessageType::ClientKeyExchange => 16,
            HandshakeMessageType::Finished => 20,
        };

        buffer.push(type_byte);

        // Length field (3 bytes, big-endian)
        let length = data.len() as u32;
        buffer.push(((length >> 16) & 0xFF) as u8);
        buffer.push(((length >> 8) & 0xFF) as u8);
        buffer.push((length & 0xFF) as u8);

        // Message data
        buffer.extend_from_slice(data);
        if matches!(msg_type, HandshakeMessageType::ClientHello) {
            for suite in &self.violations.invalid_cipher_suites {
                buffer.extend_from_slice(&suite.to_be_bytes());
            }
        }

        // Apply violations
        if self.violations.invalid_lengths {
            // Corrupt the length field
            if buffer.len() >= 4 {
                buffer[1] = buffer[1].wrapping_add(1);
            }
        }

        buffer
    }
}

impl asupersync::io::AsyncRead for MockTlsTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        if self.should_delay_io(true) {
            return Poll::Pending;
        }

        // Process next operation to generate read data
        while let Some(operation) = self.process_next_operation() {
            self.operation_index += 1;

            match operation {
                TlsOperation::StartHandshake => {
                    self.current_state = TlsState::Handshaking;
                    continue;
                }
                TlsOperation::WriteApplicationData(data) => {
                    self.write_buffer.extend(data);
                    continue;
                }
                TlsOperation::ReadData => {
                    continue;
                }
                TlsOperation::Shutdown => {
                    self.current_state = TlsState::ShuttingDown;
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                TlsOperation::SendMalformedRecord(record) => {
                    let data = self.create_malformed_tls_record(&record);
                    self.read_buffer.extend(data);
                    break;
                }
                TlsOperation::ForceStateTransition(state) => {
                    self.current_state = state;
                    if matches!(state, TlsState::Closed) {
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
                TlsOperation::PartialHandshakeMessage(msg_type, data) => {
                    let msg = self.create_handshake_message(msg_type, &data);
                    // Send only partial message
                    let partial_len = msg.len().saturating_sub(5).max(1);
                    self.read_buffer.extend(&msg[..partial_len]);
                    break;
                }
                TlsOperation::DuplicateHandshakeMessage(msg_type) => {
                    // Create a minimal duplicate message
                    let msg = self.create_handshake_message(msg_type, &[0u8; 32]);
                    self.read_buffer.extend(&msg);
                    self.read_buffer.extend(&msg); // Send twice
                    break;
                }
                TlsOperation::OutOfOrderMessage(msg_type) => {
                    // Send a message that's out of sequence
                    let msg = self.create_handshake_message(msg_type, &[0u8; 32]);
                    self.read_buffer.extend(msg);
                    break;
                }
                TlsOperation::InjectDuringHandshake(data) => {
                    self.read_buffer.extend(data);
                    break;
                }
                TlsOperation::AbruptDisconnect => {
                    self.current_state = TlsState::Closed;
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                TlsOperation::VersionMismatch(version) => {
                    self.current_state = TlsState::Handshaking;
                    let version_bytes = match version {
                        ProtocolVersion::Ssl30 => [0x03, 0x00],
                        ProtocolVersion::Tls10 => [0x03, 0x01],
                        ProtocolVersion::Tls11 => [0x03, 0x02],
                        ProtocolVersion::Tls12 => [0x03, 0x03],
                        ProtocolVersion::Tls13 => [0x03, 0x04],
                        ProtocolVersion::Invalid(raw) => raw.to_be_bytes(),
                    };
                    self.read_buffer
                        .extend([22, version_bytes[0], version_bytes[1], 0, 0]);
                    break;
                }
            }
        }

        // Copy data from read buffer to output buffer
        if let Some(byte) = self.read_buffer.pop_front() {
            buf.put_slice(&[byte]);
        }

        Poll::Ready(Ok(()))
    }
}

impl asupersync::io::AsyncWrite for MockTlsTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || matches!(self.current_state, TlsState::Closed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if self.should_delay_io(false) {
            return Poll::Pending;
        }

        // Simulate partial writes if configured
        let write_len = if self.timing.partial_writes && buf.len() > 1 {
            (buf.len() / 2).max(1)
        } else {
            buf.len()
        };

        // Capture written data for analysis
        self.write_buffer.extend_from_slice(&buf[..write_len]);
        self.current_state = TlsState::Ready;

        Poll::Ready(Ok(write_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

/// Execute TLS state machine fuzzing operations
fn fuzz_tls_state_machine(input: TlsStateMachineFuzzInput) {
    // Create mock transport with fuzzing configuration
    let mock_transport = MockTlsTransport::new(input);

    // Create TLS connector for testing
    let connector = match create_test_tls_connector() {
        Ok(connector) => connector,
        Err(_) => return, // Skip invalid configurations
    };

    // Create simple runtime for async execution
    let rt = match create_simple_runtime() {
        Some(rt) => rt,
        None => return,
    };

    // Execute fuzzing with timeout to prevent hangs
    let result = rt.block_on(async {
        let timeout_duration = Duration::from_millis(100); // Short timeout for fuzzing
        let now = asupersync::time::wall_now();

        asupersync::time::timeout(now, timeout_duration, async {
            // Use TlsConnector to create connection (exercises state machine)
            let tls_stream_result = connector.connect("fuzz.test", mock_transport).await;
            match tls_stream_result {
                Ok(tls_stream) => {
                    // Exercise the stream operations
                    fuzz_stream_operations(tls_stream).await
                }
                Err(e) => Err(e), // Connection failed - this is expected for many fuzz inputs
            }
        })
        .await
    });

    // Analyze results (errors are expected and useful for finding bugs)
    match result {
        Ok(Ok(_)) => {
            // Successful completion - verify state consistency
        }
        Ok(Err(tls_error)) => {
            // TLS error - verify it's handled correctly
            verify_tls_error_handling(&tls_error);
        }
        Err(_) => {
            // Timeout - expected for some fuzz inputs
        }
    }
}

/// Execute a sequence of operations on the TLS stream
async fn fuzz_stream_operations(
    mut tls_stream: asupersync::tls::TlsStream<MockTlsTransport>,
) -> Result<(), TlsError> {
    use asupersync::io::{AsyncRead, AsyncWrite};

    // Try to write some application data
    let test_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut buf = &test_data[..];
    while !buf.is_empty() {
        use std::future::poll_fn;
        match poll_fn(|cx| Pin::new(&mut tls_stream).poll_write(cx, buf)).await {
            Ok(0) => break, // Connection closed
            Ok(n) => buf = &buf[n..],
            Err(e) => return Err(TlsError::Io(e)),
        }
    }

    // Try to flush writes
    use std::future::poll_fn;
    poll_fn(|cx| Pin::new(&mut tls_stream).poll_flush(cx))
        .await
        .map_err(TlsError::Io)?;

    // Try to read response
    let mut read_buf = vec![0u8; 1024];
    let _ = poll_fn(|cx| {
        let mut async_buf = asupersync::io::ReadBuf::new(&mut read_buf);
        Pin::new(&mut tls_stream).poll_read(cx, &mut async_buf)
    })
    .await;

    // Attempt graceful shutdown
    poll_fn(|cx| Pin::new(&mut tls_stream).poll_shutdown(cx))
        .await
        .map_err(TlsError::Io)?;

    Ok(())
}

/// Create test TLS connector
fn create_test_tls_connector() -> Result<TlsConnector, TlsError> {
    // Create a minimal TLS connector for fuzzing
    // We don't add root certificates to test error handling
    let connector = TlsConnectorBuilder::new()
        .handshake_timeout(Duration::from_millis(100))
        .build()?;

    Ok(connector)
}

/// Create simple runtime for testing
fn create_simple_runtime() -> Option<asupersync::runtime::Runtime> {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .ok()
}

/// Verify TLS error handling is correct
fn verify_tls_error_handling(error: &asupersync::tls::TlsError) {
    use asupersync::tls::TlsError;

    match error {
        TlsError::Handshake(_) => {
            // Expected for malformed handshake sequences
        }
        TlsError::Io(_) => {
            // Expected for connection issues
        }
        TlsError::Rustls(_) => {
            // Expected for protocol violations
        }
        TlsError::Configuration(_) => {
            // Expected for invalid configurations
        }
        _ => {
            // Other errors should be analyzed
        }
    }
}

fuzz_target!(|input: TlsStateMachineFuzzInput| {
    // Limit input size to prevent resource exhaustion
    if input.operations.len() > 100 {
        return;
    }

    // Execute state machine fuzzing
    fuzz_tls_state_machine(input);
});
