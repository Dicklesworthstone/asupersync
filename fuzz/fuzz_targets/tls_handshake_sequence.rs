#![no_main]

use arbitrary::Arbitrary;
use asupersync::tls::{TlsConnector, TlsError};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

/// Comprehensive fuzz target for TLS handshake sequence edge cases
///
/// This fuzzes the TLS handshake state machine to find:
/// - Protocol errors during handshake negotiation
/// - State transition bugs in the handshake loop
/// - Timeout and cancellation handling
/// - Invalid TLS packet processing
/// - Domain name validation edge cases
/// - ALPN negotiation failures
/// - Certificate validation bypasses
/// - I/O error handling during handshake
#[derive(Arbitrary, Debug)]
struct TlsHandshakeFuzz {
    /// Domain name to use for connection (may be malformed)
    domain: String,
    /// TLS connector configuration options
    config: ConnectorConfig,
    /// Mock I/O behavior during handshake
    io_behavior: MockIoBehavior,
}

/// TLS connector configuration for fuzzing
#[derive(Arbitrary, Debug)]
struct ConnectorConfig {
    /// Whether to require ALPN negotiation
    alpn_required: bool,
    /// ALPN protocols to offer
    alpn_protocols: Vec<AlpnProtocol>,
    /// Handshake timeout in milliseconds (0 = no timeout)
    timeout_ms: u16,
    /// Whether to use default root certificates
    use_webpki_roots: bool,
    /// Whether to disable SNI
    disable_sni: bool,
}

/// ALPN protocol variants for testing
#[derive(Arbitrary, Debug)]
enum AlpnProtocol {
    Http11,
    Http2,
    Custom(Vec<u8>),
    Malformed(Vec<u8>),
}

/// Mock I/O behavior to simulate various network conditions
#[derive(Arbitrary, Debug)]
struct MockIoBehavior {
    /// Data to provide when TLS wants to read
    read_data: Vec<Vec<u8>>,
    /// Which read operations should return WouldBlock
    read_blocks: Vec<usize>,
    /// Which read operations should return UnexpectedEof
    read_eof: Vec<usize>,
    /// Which write operations should return WouldBlock
    write_blocks: Vec<usize>,
    /// Which write operations should fail with I/O error
    write_errors: Vec<usize>,
    /// Maximum bytes to write at once (simulates partial writes)
    max_write_size: u16,
    /// Whether to close connection unexpectedly
    unexpected_close: bool,
    /// At which operation to close connection
    close_at_op: u8,
}

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Mock I/O stream for testing TLS handshake
struct MockIo {
    read_data: VecDeque<Vec<u8>>,
    read_ops: usize,
    write_ops: usize,
    behavior: MockIoBehavior,
    closed: bool,
}

impl MockIo {
    fn new(behavior: MockIoBehavior) -> Self {
        let read_data: VecDeque<Vec<u8>> = behavior.read_data.iter().cloned().collect();
        Self {
            read_data,
            read_ops: 0,
            write_ops: 0,
            behavior,
            closed: false,
        }
    }

    fn should_block_read(&self) -> bool {
        self.behavior.read_blocks.contains(&self.read_ops)
    }

    fn should_eof_read(&self) -> bool {
        self.behavior.read_eof.contains(&self.read_ops)
    }

    fn should_block_write(&self) -> bool {
        self.behavior.write_blocks.contains(&self.write_ops)
    }

    fn should_error_write(&self) -> bool {
        self.behavior.write_errors.contains(&self.write_ops)
    }

    fn should_close(&self) -> bool {
        self.behavior.unexpected_close
            && self.read_ops + self.write_ops >= self.behavior.close_at_op as usize
    }
}

impl asupersync::io::AsyncRead for MockIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed || self.should_close() {
            self.closed = true;
            return Poll::Ready(Ok(()));
        }

        if self.should_block_read() {
            self.read_ops += 1;
            return Poll::Pending;
        }

        if self.should_eof_read() {
            self.read_ops += 1;
            return Poll::Ready(Ok(())); // EOF
        }

        let data = match self.read_data.pop_front() {
            Some(data) => data,
            None => {
                self.read_ops += 1;
                return Poll::Ready(Ok(())); // No more data
            }
        };

        let to_copy = std::cmp::min(data.len(), buf.remaining());
        buf.put_slice(&data[..to_copy]);

        // If we didn't read all data, put the rest back
        if to_copy < data.len() {
            self.read_data.push_front(data[to_copy..].to_vec());
        }

        self.read_ops += 1;
        Poll::Ready(Ok(()))
    }
}

impl asupersync::io::AsyncWrite for MockIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.should_close() {
            self.closed = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed",
            )));
        }

        if self.should_block_write() {
            self.write_ops += 1;
            return Poll::Pending;
        }

        if self.should_error_write() {
            self.write_ops += 1;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "injected write error",
            )));
        }

        let max_write = std::cmp::min(buf.len(), self.behavior.max_write_size as usize).max(1); // Always write at least 1 byte if buffer is non-empty

        let written = std::cmp::min(buf.len(), max_write);
        self.write_ops += 1;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

/// Maximum operation limits for safety
const MAX_DOMAIN_LEN: usize = 253; // DNS label limit
const MAX_ALPN_PROTOCOLS: usize = 10;
const MAX_READ_CHUNKS: usize = 20;

fuzz_target!(|input: TlsHandshakeFuzz| {
    let domain = if input.domain.len() > MAX_DOMAIN_LEN {
        &input.domain[..MAX_DOMAIN_LEN]
    } else {
        &input.domain
    };

    // Skip empty domains as they're trivially invalid
    if domain.is_empty() {
        return;
    }

    // Create TLS connector with fuzzing configuration
    let connector_result = create_test_connector(&input.config);
    let connector = match connector_result {
        Ok(c) => c,
        Err(_) => return, // Invalid configuration, skip
    };

    // Create mock I/O with limited read data
    let limited_behavior = MockIoBehavior {
        read_data: input
            .io_behavior
            .read_data
            .into_iter()
            .take(MAX_READ_CHUNKS)
            .collect(),
        ..input.io_behavior
    };

    let mock_io = MockIo::new(limited_behavior);

    // Test domain validation first (this can fail gracefully)
    let domain_validation_result = TlsConnector::validate_domain(domain);

    // Create a simple runtime for async execution
    let rt = match simple_runtime() {
        Ok(rt) => rt,
        Err(_) => return, // Skip if runtime creation fails
    };

    let connection_result = rt.block_on(async {
        // Add timeout to prevent hangs in fuzzing
        let timeout_duration = Duration::from_millis(500);
        // Use asupersync timeout with current time
        let now = asupersync::time::wall_now();
        match asupersync::time::timeout(now, timeout_duration, connector.connect(domain, mock_io))
            .await
        {
            Ok(result) => Some(result),
            Err(_) => None, // Timeout
        }
    });

    // Verify results make sense
    match connection_result {
        Some(Ok(_tls_stream)) => {
            // Handshake succeeded - domain should have been valid
            assert!(
                domain_validation_result.is_ok(),
                "Handshake succeeded but domain validation failed for: {:?}",
                domain
            );
        }
        Some(Err(tls_error)) => {
            // Handshake failed - verify error is reasonable
            verify_tls_error(&tls_error, domain, &input.config);
        }
        None => {
            // Timeout occurred - acceptable for fuzzing scenarios
        }
    }
});

fn create_test_connector(config: &ConnectorConfig) -> Result<TlsConnector, TlsError> {
    use asupersync::tls::TlsConnectorBuilder;
    let mut builder = TlsConnectorBuilder::new();

    // Add root certificates if requested
    if config.use_webpki_roots {
        builder = builder.with_webpki_roots();
    }

    // Configure ALPN protocols
    if !config.alpn_protocols.is_empty() {
        let protocols: Vec<Vec<u8>> = config
            .alpn_protocols
            .iter()
            .take(MAX_ALPN_PROTOCOLS)
            .map(|p| match p {
                AlpnProtocol::Http11 => b"http/1.1".to_vec(),
                AlpnProtocol::Http2 => b"h2".to_vec(),
                AlpnProtocol::Custom(data) => data.clone(),
                AlpnProtocol::Malformed(data) => data.clone(),
            })
            .collect();

        builder = builder.alpn_protocols(protocols);

        if config.alpn_required {
            builder = builder.require_alpn();
        }
    }

    // Configure SNI
    if config.disable_sni {
        builder = builder.disable_sni();
    }

    // Configure timeout
    if config.timeout_ms > 0 {
        let timeout = Duration::from_millis(config.timeout_ms as u64);
        builder = builder.handshake_timeout(timeout);
    }

    builder.build()
}

fn verify_tls_error(error: &TlsError, domain: &str, config: &ConnectorConfig) {
    match error {
        TlsError::InvalidDnsName(name) => {
            assert_eq!(
                name, domain,
                "Invalid DNS name error should match input domain"
            );
        }
        TlsError::Handshake(_msg) => {
            // Handshake errors are expected with malformed data/mock I/O
        }
        TlsError::Configuration(_msg) => {
            // Configuration errors are expected with invalid ALPN/certs
        }
        TlsError::Io(_io_error) => {
            // I/O errors are expected with mock transport failures
        }
        TlsError::Timeout(duration) => {
            if config.timeout_ms > 0 {
                let expected_timeout = Duration::from_millis(config.timeout_ms as u64);
                assert_eq!(
                    *duration, expected_timeout,
                    "Timeout duration should match configured value"
                );
            }
        }
        TlsError::AlpnNegotiationFailed {
            expected,
            negotiated: _,
        } => {
            assert!(
                config.alpn_required,
                "ALPN negotiation failure should only occur when ALPN is required"
            );
            assert!(
                !expected.is_empty(),
                "Expected ALPN protocols should not be empty if negotiation failed"
            );
        }
        TlsError::Certificate(_)
        | TlsError::CertificateExpired { .. }
        | TlsError::CertificateNotYetValid { .. }
        | TlsError::ChainValidation(_)
        | TlsError::PinMismatch { .. } => {
            // Certificate errors are expected with mock transport
        }
        TlsError::Rustls(_) => {
            // Rustls errors are expected with malformed TLS data
        }
    }
}

/// Create a simple runtime for async execution
fn simple_runtime() -> Result<asupersync::runtime::Runtime, asupersync::error::Error> {
    asupersync::runtime::RuntimeBuilder::current_thread().build()
}
