#![no_main]

//! Simplified TLS state machine fuzzer for handshake transitions
//!
//! This targets the TLS stream state machine with malformed inputs
//! to test error handling and state transition robustness.

use arbitrary::Arbitrary;
use asupersync::tls::{TlsConnector, TlsConnectorBuilder, TlsError};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Simplified fuzz input for TLS state machine testing
#[derive(Arbitrary, Debug)]
struct TlsSimpleFuzz {
    /// Sequence of TLS records to inject
    tls_records: Vec<TlsRecordFuzz>,
    /// Connection behavior
    connection_behavior: ConnectionBehavior,
}

/// Malformed TLS record for injection
#[derive(Arbitrary, Debug)]
struct TlsRecordFuzz {
    /// Record type (may be invalid)
    record_type: u8,
    /// Protocol version bytes
    version: [u8; 2],
    /// Record payload
    payload: Vec<u8>,
}

/// Connection behavior configuration
#[derive(Arbitrary, Debug)]
struct ConnectionBehavior {
    /// Drop connection after N operations
    drop_after: Option<u8>,
    /// Return WouldBlock on reads
    block_reads: bool,
    /// Return WouldBlock on writes
    block_writes: bool,
}

/// Mock transport that injects malformed TLS data
struct MockTlsTransport {
    read_data: VecDeque<u8>,
    write_data: Vec<u8>,
    behavior: ConnectionBehavior,
    operations: usize,
    closed: bool,
}

impl MockTlsTransport {
    fn new(input: TlsSimpleFuzz) -> Self {
        let mut read_data = VecDeque::new();

        // Convert TLS record fuzzes to bytes
        for record in input.tls_records {
            // TLS record format: [type][version][length][payload]
            read_data.push_back(record.record_type);
            read_data.extend(record.version);

            // Length as big-endian u16
            let payload_len = record.payload.len().min(0xFFFF) as u16;
            read_data.extend(payload_len.to_be_bytes());
            read_data.extend(record.payload);
        }

        Self {
            read_data,
            write_data: Vec::new(),
            behavior: input.connection_behavior,
            operations: 0,
            closed: false,
        }
    }

    fn should_close(&mut self) -> bool {
        if let Some(drop_after) = self.behavior.drop_after {
            self.operations >= drop_after as usize
        } else {
            false
        }
    }
}

impl asupersync::io::AsyncRead for MockTlsTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.operations += 1;

        if self.closed || self.should_close() {
            self.closed = true;
            return Poll::Ready(Ok(())); // EOF
        }

        if self.behavior.block_reads {
            return Poll::Pending;
        }

        // Provide data from our malformed TLS records
        if let Some(byte) = self.read_data.pop_front() {
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
        self.operations += 1;

        if self.closed || self.should_close() {
            self.closed = true;
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if self.behavior.block_writes {
            return Poll::Pending;
        }

        // Capture written data
        self.write_data.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
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

/// Create a minimal TLS connector for testing
fn create_test_connector() -> Result<TlsConnector, TlsError> {
    TlsConnectorBuilder::new()
        .handshake_timeout(Duration::from_millis(50))
        .build()
}

/// Execute TLS fuzzing
fn fuzz_tls_simple(input: TlsSimpleFuzz) {
    // Create connector
    let connector = match create_test_connector() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Create mock transport
    let transport = MockTlsTransport::new(input);

    // Create runtime
    let rt = match asupersync::runtime::RuntimeBuilder::current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return,
    };

    // Execute with timeout
    let _result = rt.block_on(async {
        let timeout = Duration::from_millis(50);
        let now = asupersync::time::wall_now();

        asupersync::time::timeout(now, timeout, async {
            // Attempt TLS connection - this exercises the state machine
            connector.connect("test.example", transport).await
        })
        .await
    });

    // All errors/timeouts are expected for fuzz inputs
}

fuzz_target!(|input: TlsSimpleFuzz| {
    // Limit input size to prevent resource exhaustion
    if input.tls_records.len() > 10 {
        return;
    }

    for record in &input.tls_records {
        if record.payload.len() > 1024 {
            return;
        }
    }

    fuzz_tls_simple(input);
});
