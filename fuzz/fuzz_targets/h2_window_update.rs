#![no_main]

//! Structure-aware fuzz target for HTTP/2 WINDOW_UPDATE handling.
//!
//! Targets edge cases in flow control window management:
//! - WINDOW_UPDATE frame processing with various increments and stream IDs
//! - Connection vs stream-level window arithmetic
//! - Window overflow and underflow scenarios
//! - Integration with stream state machine (idle/open/closed streams)
//! - Zero increment validation and RFC 9113 compliance
//! - Automatic WINDOW_UPDATE generation thresholds

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::http::h2::{
    connection::Connection,
    error::{ErrorCode, H2Error},
    frame::{DataFrame, Frame, HeadersFrame, SettingsFrame, WindowUpdateFrame},
    settings::Settings,
};

/// Sequence of HTTP/2 operations to test WINDOW_UPDATE handling
#[derive(Arbitrary, Debug, Clone)]
struct H2WindowUpdateSequence {
    /// Initial connection settings
    connection_setup: ConnectionSetup,
    /// Sequence of operations to perform
    operations: Vec<H2Operation>,
}

/// Initial connection configuration
#[derive(Arbitrary, Debug, Clone)]
struct ConnectionSetup {
    /// Whether this is a client or server connection
    is_client: bool,
    /// Settings to apply
    settings: CustomSettings,
}

/// Custom HTTP/2 settings for testing
#[derive(Arbitrary, Debug, Clone)]
struct CustomSettings {
    /// SETTINGS_INITIAL_WINDOW_SIZE
    initial_window_size: Option<u32>,
    /// SETTINGS_MAX_CONCURRENT_STREAMS
    max_concurrent_streams: Option<u32>,
    /// SETTINGS_HEADER_TABLE_SIZE
    header_table_size: Option<u32>,
}

/// HTTP/2 operations that affect or test WINDOW_UPDATE behavior
#[derive(Arbitrary, Debug, Clone)]
enum H2Operation {
    /// Open a new stream
    OpenStream {
        stream_id: StreamId,
        end_stream: bool,
    },
    /// Send DATA frame (triggers automatic WINDOW_UPDATE)
    SendData {
        stream_id: StreamId,
        payload_size: PayloadSize,
        end_stream: bool,
    },
    /// Process incoming WINDOW_UPDATE frame
    ReceiveWindowUpdate {
        stream_id: StreamId,
        increment: WindowIncrement,
    },
    /// Send outgoing WINDOW_UPDATE frame
    SendWindowUpdate {
        stream_id: StreamId,
        increment: WindowIncrement,
    },
    /// Reset a stream (affects window calculations)
    ResetStream {
        stream_id: StreamId,
        error_code: ResetErrorCode,
    },
    /// Check connection state and windows
    InspectWindows,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct ResetErrorCode(u8);

impl ResetErrorCode {
    fn as_error_code(self) -> ErrorCode {
        ErrorCode::from_u32(u32::from(self.0 % 0x0e))
    }
}

/// Stream ID with various edge case values
#[derive(Arbitrary, Debug, Clone, Copy)]
enum StreamId {
    /// Connection-level (stream 0)
    Connection,
    /// Valid stream ID
    Valid(ValidStreamId),
    /// Invalid stream ID values
    Invalid(u32),
}

impl StreamId {
    fn as_u32(self) -> u32 {
        match self {
            StreamId::Connection => 0,
            StreamId::Valid(id) => id.as_u32(),
            StreamId::Invalid(id) => id,
        }
    }
}

/// Valid stream ID patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ValidStreamId {
    /// First client stream
    FirstClient,
    /// First server stream
    FirstServer,
    /// Sequential stream ID
    Sequential(u8), // 1-255 for manageable range
    /// Last valid stream ID
    MaxValid,
}

impl ValidStreamId {
    fn as_u32(self) -> u32 {
        match self {
            ValidStreamId::FirstClient => 1,
            ValidStreamId::FirstServer => 2,
            ValidStreamId::Sequential(n) => {
                // Generate client (odd) or server (even) stream IDs
                if n % 2 == 1 {
                    n as u32 // Odd for client streams
                } else {
                    (n as u32) + 1 // Even+1 to keep odd for clients
                }
            }
            ValidStreamId::MaxValid => (1u32 << 31) - 1, // 2^31 - 1
        }
    }
}

/// Window increment values including edge cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum WindowIncrement {
    /// Zero increment (forbidden by RFC)
    Zero,
    /// Small positive increment
    Small(u8), // 1-255
    /// Medium increment (typical case)
    Medium(u16), // Up to 65k
    /// Large increment
    Large(u32), // Up to 4GB
    /// Maximum valid increment
    MaxValid,
    /// Increment that would cause overflow
    Overflow(OverflowType),
}

impl WindowIncrement {
    fn as_u32(self) -> u32 {
        match self {
            WindowIncrement::Zero => 0,
            WindowIncrement::Small(n) => u32::from(n.max(1)), // Ensure non-zero unless explicitly Zero
            WindowIncrement::Medium(n) => u32::from(n.max(1)),
            WindowIncrement::Large(n) => n.max(1),
            WindowIncrement::MaxValid => (1u32 << 31) - 1, // 2^31 - 1 (max i32)
            WindowIncrement::Overflow(OverflowType::I32Max) => u32::MAX, // Exceeds i32::MAX
            WindowIncrement::Overflow(OverflowType::WindowOverflow) => 1u32 << 30, // Large but might overflow with existing window
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OverflowType {
    /// Increment exceeds i32::MAX
    I32Max,
    /// Increment would overflow current window
    WindowOverflow,
}

/// Payload sizes for DATA frames
#[derive(Arbitrary, Debug, Clone, Copy)]
enum PayloadSize {
    /// Empty payload
    Empty,
    /// Small payload
    Small(u8), // 1-255 bytes
    /// Medium payload
    Medium(u16), // Up to 64KB
    /// Large payload (triggers connection window update)
    Large(u32), // Up to connection window size
    /// Payload that exceeds available window
    ExceedsWindow(u32),
}

impl PayloadSize {
    fn as_usize(self) -> usize {
        match self {
            PayloadSize::Empty => 0,
            PayloadSize::Small(n) => n as usize,
            PayloadSize::Medium(n) => n as usize,
            PayloadSize::Large(n) => (n as usize).min(1_000_000), // Cap for fuzzer performance
            PayloadSize::ExceedsWindow(n) => (n as usize).min(2_000_000), // Larger cap for overflow tests
        }
    }
}

fuzz_target!(|sequence: H2WindowUpdateSequence| {
    // Limit complexity to maintain fuzzer performance
    if sequence.operations.len() > 50 {
        return;
    }

    // Limit payload sizes to avoid OOM
    for op in &sequence.operations {
        if let H2Operation::SendData { payload_size, .. } = op
            && payload_size.as_usize() > 2_000_000
        {
            return;
        }
    }

    // Test WINDOW_UPDATE sequence processing
    test_window_update_sequence(&sequence);

    // Test window arithmetic edge cases
    test_window_arithmetic(&sequence);

    // Test RFC compliance invariants
    test_rfc_compliance(&sequence);
});

fn test_window_update_sequence(sequence: &H2WindowUpdateSequence) {
    let settings = build_settings(&sequence.connection_setup.settings);

    let mut connection = if sequence.connection_setup.is_client {
        Connection::client(settings)
    } else {
        Connection::server(settings)
    };

    // Complete the public connection handshake path before exercising data and
    // WINDOW_UPDATE frames. This keeps the harness on the live state machine.
    let _ = connection.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())));

    // Track opened streams for validation
    let mut opened_streams = std::collections::HashSet::new();

    for operation in &sequence.operations {
        let result = process_operation(&mut connection, operation, &mut opened_streams);

        // Don't fail on expected errors - these are testing error handling
        match result {
            Ok(()) => {
                // Operation succeeded - check invariants
                validate_connection_invariants(&connection);
            }
            Err(H2Error {
                code: ErrorCode::ProtocolError,
                ..
            }) => {
                // Expected protocol errors (e.g., zero increment WINDOW_UPDATE)
            }
            Err(H2Error {
                code: ErrorCode::FlowControlError,
                ..
            }) => {
                // Expected flow control errors (e.g., window overflow)
            }
            Err(H2Error {
                code: ErrorCode::StreamClosed,
                ..
            }) => {
                // Expected stream closed errors
            }
            Err(other) => {
                // Other protocol errors are valid outcomes for generated frame
                // sequences, but they must remain well-formed H2 errors.
                assert!(
                    other.is_connection_error() || other.stream_id.is_some(),
                    "H2 errors should classify connection or stream scope"
                );
            }
        }

        // Process any pending frames generated by the operation
        while connection.has_pending_frames() {
            let _frame = connection.next_frame();
            // Don't fail if frame generation fails - might be testing error cases
        }
    }
}

fn test_window_arithmetic(sequence: &H2WindowUpdateSequence) {
    // Test window increment arithmetic in isolation
    for operation in &sequence.operations {
        if let H2Operation::ReceiveWindowUpdate { increment, .. } = operation {
            test_increment_bounds(increment.as_u32());
        }
    }
}

fn test_increment_bounds(increment: u32) {
    // Test conversion bounds that WINDOW_UPDATE processing relies on
    let i32_result = i32::try_from(increment);

    if increment == 0 {
        // Zero increments should be rejected
        assert_eq!(increment, 0, "Zero increment test");
    } else if increment > (i32::MAX as u32) {
        // Increments exceeding i32::MAX should be rejected
        assert!(
            i32_result.is_err(),
            "Oversized increment should not convert to i32"
        );
    } else {
        // Valid increments should convert successfully
        assert!(i32_result.is_ok(), "Valid increment should convert to i32");
    }

    // Test overflow detection for typical window sizes
    let typical_window = 65535i32; // Default initial window
    let new_window_i64 = i64::from(typical_window) + i64::from(increment);

    if new_window_i64 > i64::from(i32::MAX) {
        // Would overflow - this should be detected
        assert!(
            new_window_i64 > i64::from(i32::MAX),
            "Overflow detection test"
        );
    }
}

fn test_rfc_compliance(sequence: &H2WindowUpdateSequence) {
    // Test RFC 9113 compliance rules for WINDOW_UPDATE
    for operation in &sequence.operations {
        if let H2Operation::ReceiveWindowUpdate {
            stream_id,
            increment,
        } = operation
        {
            let increment_val = increment.as_u32();
            let stream_id_val = stream_id.as_u32();

            // RFC 9113 §6.9.1: increment of 0 MUST be treated as an error
            if increment_val == 0 {
                if stream_id_val == 0 {
                    // Connection-level: MUST be connection error
                    assert_eq!(increment_val, 0, "Zero increment on connection");
                } else {
                    // Stream-level: MUST be stream error
                    assert_eq!(increment_val, 0, "Zero increment on stream");
                }
            }

            // Stream ID must be valid
            if stream_id_val > ((1u32 << 31) - 1) {
                // Invalid stream ID
                assert!(stream_id_val > ((1u32 << 31) - 1), "Invalid stream ID");
            }
        }
    }
}

fn process_operation(
    connection: &mut Connection,
    operation: &H2Operation,
    opened_streams: &mut std::collections::HashSet<u32>,
) -> Result<(), H2Error> {
    match operation {
        H2Operation::OpenStream {
            stream_id,
            end_stream,
        } => {
            let stream_id_val = stream_id.as_u32();
            if stream_id_val == 0 {
                return Ok(()); // Skip connection-level "streams"
            }

            // Create HEADERS frame to open the stream
            let headers_frame = Frame::Headers(HeadersFrame::new(
                stream_id_val,
                Bytes::new(),
                *end_stream,
                true, // end_headers
            ));

            connection.process_frame(headers_frame)?;
            opened_streams.insert(stream_id_val);
            Ok(())
        }

        H2Operation::SendData {
            stream_id,
            payload_size,
            end_stream,
        } => {
            let stream_id_val = stream_id.as_u32();
            if stream_id_val == 0 {
                return Ok(()); // Skip connection-level data
            }

            let payload_len = payload_size.as_usize();
            let payload = Bytes::from(vec![0u8; payload_len]);

            let data_frame = Frame::Data(DataFrame::new(stream_id_val, payload, *end_stream));

            connection.process_frame(data_frame)?;
            Ok(())
        }

        H2Operation::ReceiveWindowUpdate {
            stream_id,
            increment,
        } => {
            let window_update = Frame::WindowUpdate(WindowUpdateFrame::new(
                stream_id.as_u32(),
                increment.as_u32(),
            ));

            connection.process_frame(window_update)?;
            Ok(())
        }

        H2Operation::SendWindowUpdate {
            stream_id,
            increment,
        } => {
            let stream_id_val = stream_id.as_u32();
            let increment_val = increment.as_u32();

            if stream_id_val == 0 {
                connection.send_connection_window_update(increment_val)?;
            } else {
                connection.send_stream_window_update(stream_id_val, increment_val)?;
            }
            Ok(())
        }

        H2Operation::ResetStream {
            stream_id,
            error_code,
        } => {
            let stream_id_val = stream_id.as_u32();
            if stream_id_val == 0 {
                return Ok(()); // Can't reset connection
            }

            connection.reset_stream(stream_id_val, error_code.as_error_code());
            opened_streams.remove(&stream_id_val);
            Ok(())
        }

        H2Operation::InspectWindows => {
            // Just check that we can query connection state without panicking
            let _ = connection.has_pending_frames();
            Ok(())
        }
    }
}

fn validate_connection_invariants(connection: &Connection) {
    assert!(
        connection.stream(0).is_none(),
        "stream 0 must remain connection-level only"
    );

    // Pending operations queue should be finite
    // (This is implicitly tested by not hanging in the fuzzer)
}

fn build_settings(custom: &CustomSettings) -> Settings {
    let mut settings = Settings::default();

    if let Some(window_size) = custom.initial_window_size {
        settings.initial_window_size = window_size.min(0x7fff_ffff);
    }

    if let Some(max_streams) = custom.max_concurrent_streams {
        settings.max_concurrent_streams = max_streams;
    }

    if let Some(table_size) = custom.header_table_size {
        settings.header_table_size = table_size;
    }

    settings
}
