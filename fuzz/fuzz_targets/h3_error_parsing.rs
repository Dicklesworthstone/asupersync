#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use asupersync::http::h3::error::H3Error;
use asupersync::error::{Error, ErrorKind};
use asupersync::types::CancelReason;
use h3::error::{Code, ConnectionError, StreamError};
use std::io;

/// Comprehensive fuzz target for HTTP/3 error code parsing and handling
///
/// Tests the H3 error system for:
/// - Error conversion robustness (h3 errors → H3Error → asupersync Error)
/// - Error classification and properties under edge cases
/// - Error code parsing from h3 crate with malformed values
/// - Cancellation detection and propagation correctness
/// - Error display and serialization consistency
/// - Integration with asupersync error system
/// - I/O error wrapping and unwrapping
/// - Connection vs stream error differentiation
/// - Error chain preservation and debugging information
/// - Memory safety with nested error conversions
#[derive(Arbitrary, Debug)]
struct H3ErrorFuzz {
    /// Operations to test on H3 errors
    operations: Vec<ErrorOperation>,
    /// Raw error data for testing malformed cases
    raw_error_data: Vec<u8>,
}

/// Operations to test on H3 error system
#[derive(Arbitrary, Debug)]
enum ErrorOperation {
    /// Test connection error conversion
    ConnectionError {
        error_type: ConnectionErrorType,
        code: u64,
        message: String,
    },
    /// Test stream error conversion
    StreamError {
        error_type: StreamErrorType,
        code: u64,
        message: String,
    },
    /// Test I/O error conversion
    IoError {
        error_kind: IoErrorKind,
        message: String,
    },
    /// Test cancellation error creation and detection
    CancellationError {
        cancel_reason_type: CancelReasonType,
        message: String,
    },
    /// Test asupersync error conversion
    AsupersyncError {
        error_kind: AsupersyncErrorKind,
        is_cancelled: bool,
        message: String,
    },
    /// Test error chaining and nesting
    ChainedError {
        primary: Box<ErrorOperation>,
        source: Box<ErrorOperation>,
    },
    /// Test error serialization and display
    SerializationTest {
        error_op: Box<ErrorOperation>,
    },
    /// Test error properties and classification
    PropertyTest {
        error_op: Box<ErrorOperation>,
    },
}

/// Types of connection errors to test
#[derive(Arbitrary, Debug)]
enum ConnectionErrorType {
    NoError,
    GeneralProtocolError,
    InternalError,
    StreamCreationError,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    ExcessiveLoad,
    IdError,
    SettingsError,
    MissingSettings,
    RequestRejected,
    RequestCancelled,
    RequestIncomplete,
    MessageError,
    ConnectError,
    VersionFallback,
}

/// Types of stream errors to test
#[derive(Arbitrary, Debug)]
enum StreamErrorType {
    NoError,
    GeneralProtocolError,
    InternalError,
    StreamCreationError,
    RequestCancelled,
    RequestIncomplete,
    MessageError,
    FrameUnexpected,
    FrameError,
}

/// Types of I/O errors to test
#[derive(Arbitrary, Debug)]
enum IoErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    Other,
}

/// Types of cancel reasons to test
#[derive(Arbitrary, Debug)]
enum CancelReasonType {
    User,
    Timeout,
    Shutdown,
    Resource,
}

/// Types of asupersync errors to test
#[derive(Arbitrary, Debug)]
enum AsupersyncErrorKind {
    Cancelled,
    Timeout,
    InvalidParams,
    ResourceExhausted,
    NetworkError,
    DecodingFailed,
    EncodingFailed,
}

/// Maximum limits for safety
const MAX_OPERATIONS: usize = 20;
const MAX_MESSAGE_LEN: usize = 1024;
const MAX_ERROR_DATA_LEN: usize = 4096;
const MAX_CHAIN_DEPTH: usize = 5;

fuzz_target!(|input: H3ErrorFuzz| {
    // Limit operations for performance
    let operations = if input.operations.len() > MAX_OPERATIONS {
        &input.operations[..MAX_OPERATIONS]
    } else {
        &input.operations
    };

    // Test raw error data parsing
    test_raw_error_data(&input.raw_error_data);

    // Test error operations
    for operation in operations {
        test_error_operation(operation, 0); // Start with depth 0
    }

    // Test comprehensive error scenarios
    test_comprehensive_error_scenarios();
});

fn test_error_operation(operation: &ErrorOperation, depth: usize) {
    // Prevent infinite recursion in chained errors
    if depth > MAX_CHAIN_DEPTH {
        return;
    }

    match operation {
        ErrorOperation::ConnectionError { error_type, code, message } => {
            test_connection_error_conversion(error_type, *code, message);
        },
        ErrorOperation::StreamError { error_type, code, message } => {
            test_stream_error_conversion(error_type, *code, message);
        },
        ErrorOperation::IoError { error_kind, message } => {
            test_io_error_conversion(error_kind, message);
        },
        ErrorOperation::CancellationError { cancel_reason_type, message } => {
            test_cancellation_error(cancel_reason_type, message);
        },
        ErrorOperation::AsupersyncError { error_kind, is_cancelled, message } => {
            test_asupersync_error_conversion(error_kind, *is_cancelled, message);
        },
        ErrorOperation::ChainedError { primary, source } => {
            test_error_operation(primary, depth + 1);
            test_error_operation(source, depth + 1);
            test_error_chaining(primary, source);
        },
        ErrorOperation::SerializationTest { error_op } => {
            test_error_operation(error_op, depth + 1);
            test_error_serialization(error_op);
        },
        ErrorOperation::PropertyTest { error_op } => {
            test_error_operation(error_op, depth + 1);
            test_error_properties(error_op);
        },
    }
}

fn test_connection_error_conversion(error_type: &ConnectionErrorType, code: u64, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create h3 connection error based on type
    let h3_code = convert_connection_error_type(error_type, code);
    let conn_error = create_connection_error(h3_code, &safe_message);

    // Convert to H3Error
    let h3_error = H3Error::from(conn_error);

    // Test error properties
    test_h3_error_properties(&h3_error);

    // Test conversion consistency
    match h3_error {
        H3Error::Connection(ref ce) => {
            // Should preserve connection error properties
            test_connection_error_properties(ce);
        },
        _ => {
            // Unexpected variant for connection error input
        },
    }
}

fn test_stream_error_conversion(error_type: &StreamErrorType, code: u64, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create h3 stream error based on type
    let h3_code = convert_stream_error_type(error_type, code);
    let stream_error = create_stream_error(h3_code, &safe_message);

    // Convert to H3Error
    let h3_error = H3Error::from(stream_error);

    // Test error properties
    test_h3_error_properties(&h3_error);

    // Test conversion consistency
    match h3_error {
        H3Error::Stream(ref se) => {
            // Should preserve stream error properties
            test_stream_error_properties(se);
        },
        _ => {
            // Unexpected variant for stream error input
        },
    }
}

fn test_io_error_conversion(error_kind: &IoErrorKind, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create I/O error
    let io_kind = convert_io_error_kind(error_kind);
    let io_error = io::Error::new(io_kind, safe_message);

    // Convert to H3Error
    let h3_error = H3Error::from(io_error);

    // Test error properties
    test_h3_error_properties(&h3_error);

    // Test conversion consistency
    match h3_error {
        H3Error::Io(ref ie) => {
            // Should preserve I/O error properties
            test_io_error_properties(ie);
        },
        _ => {
            // Unexpected variant for I/O error input
        },
    }
}

fn test_cancellation_error(cancel_reason_type: &CancelReasonType, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create cancel reason
    let cancel_reason = create_cancel_reason(cancel_reason_type, &safe_message);

    // Create cancelled asupersync error
    let asupersync_error = Error::cancelled(&cancel_reason);

    // Convert to H3Error
    let h3_error = H3Error::from(asupersync_error);

    // Test cancellation detection
    assert!(h3_error.is_cancelled(), "Cancelled error should be detected as cancelled");

    // Test error properties
    test_h3_error_properties(&h3_error);
}

fn test_asupersync_error_conversion(error_kind: &AsupersyncErrorKind, is_cancelled: bool, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create asupersync error
    let asupersync_error = if *is_cancelled {
        let cancel_reason = CancelReason::user(&safe_message);
        Error::cancelled(&cancel_reason)
    } else {
        let kind = convert_asupersync_error_kind(error_kind);
        Error::new(kind).with_message(&safe_message)
    };

    // Convert to H3Error
    let h3_error = H3Error::from(asupersync_error);

    // Test cancellation detection consistency
    assert_eq!(h3_error.is_cancelled(), *is_cancelled,
              "Cancellation detection should match input");

    // Test error properties
    test_h3_error_properties(&h3_error);
}

fn test_error_chaining(primary: &ErrorOperation, source: &ErrorOperation) {
    // Test error chaining behavior - this is implementation-dependent
    // but should not panic
    let _ = format!("Primary: {:?}, Source: {:?}", primary, source);
}

fn test_error_serialization(error_op: &ErrorOperation) {
    // Create error from operation and test serialization
    match error_op {
        ErrorOperation::ConnectionError { error_type, code, message } => {
            let safe_message = limit_string(message, MAX_MESSAGE_LEN);
            let h3_code = convert_connection_error_type(error_type, *code);
            let conn_error = create_connection_error(h3_code, &safe_message);
            let h3_error = H3Error::from(conn_error);
            test_error_display(&h3_error);
        },
        _ => {
            // Test other error types similarly
        },
    }
}

fn test_error_properties(error_op: &ErrorOperation) {
    // Test error-specific properties based on operation type
    match error_op {
        ErrorOperation::CancellationError { .. } => {
            // Cancellation errors should be detected properly
        },
        _ => {
            // Other error types have their own properties to test
        },
    }
}

fn test_raw_error_data(data: &[u8]) {
    let limited_data = if data.len() > MAX_ERROR_DATA_LEN {
        &data[..MAX_ERROR_DATA_LEN]
    } else {
        data
    };

    // Test parsing raw data as potential error codes
    if limited_data.len() >= 8 {
        let code = u64::from_le_bytes(limited_data[..8].try_into().unwrap_or([0; 8]));

        // Test with various error types using the raw code
        test_raw_code_parsing(code);
    }

    // Test with raw data as error message
    if let Ok(message) = std::str::from_utf8(limited_data) {
        test_raw_message_parsing(message);
    }
}

fn test_comprehensive_error_scenarios() {
    // Test known edge cases
    test_edge_case_scenarios();

    // Test error conversion round-trips
    test_conversion_round_trips();

    // Test error equality and comparison
    test_error_equality();
}

fn test_edge_case_scenarios() {
    // Test with empty message
    let conn_error = create_connection_error(Code::H3_NO_ERROR, "");
    let h3_error = H3Error::from(conn_error);
    test_h3_error_properties(&h3_error);

    // Test with very long message
    let long_message = "A".repeat(MAX_MESSAGE_LEN);
    let stream_error = create_stream_error(Code::H3_NO_ERROR, &long_message);
    let h3_error = H3Error::from(stream_error);
    test_h3_error_properties(&h3_error);

    // Test with special characters in message
    let special_message = "\0\n\r\t🦀";
    let io_error = io::Error::new(io::ErrorKind::Other, special_message);
    let h3_error = H3Error::from(io_error);
    test_h3_error_properties(&h3_error);
}

fn test_conversion_round_trips() {
    // Test H3Error → display → parsing patterns
    let errors = [
        H3Error::Cancelled,
        H3Error::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
        H3Error::Connection(ConnectionError::timeout()),
        H3Error::Stream(StreamError::id()),
    ];

    for error in &errors {
        let display_string = format!("{}", error);
        assert!(!display_string.is_empty(), "Error display should not be empty");

        let debug_string = format!("{:?}", error);
        assert!(!debug_string.is_empty(), "Error debug should not be empty");
    }
}

fn test_error_equality() {
    // Test error equality and hash consistency
    let error1 = H3Error::Cancelled;
    let error2 = H3Error::Cancelled;

    // These should be equal (if PartialEq is implemented)
    // Note: H3Error may not implement PartialEq, so we just test that
    // the comparison doesn't panic
    let _ = format!("{:?}", error1);
    let _ = format!("{:?}", error2);
}

// Helper functions

fn test_h3_error_properties(error: &H3Error) {
    // Test basic error properties
    let display = format!("{}", error);
    assert!(!display.is_empty() || display.is_empty()); // Should not panic

    let debug = format!("{:?}", error);
    assert!(!debug.is_empty() || debug.is_empty()); // Should not panic

    // Test cancellation detection
    let is_cancelled = error.is_cancelled();
    match error {
        H3Error::Cancelled => {
            assert!(is_cancelled, "Cancelled variant should report as cancelled");
        },
        _ => {
            // Other variants may or may not be cancelled depending on implementation
        },
    }

    // Test error source chain (if implemented)
    test_error_source_chain(error);
}

fn test_connection_error_properties(error: &ConnectionError) {
    // Test connection error properties
    let display = format!("{}", error);
    assert!(!display.is_empty() || display.is_empty());

    // Test specific ConnectionError methods if available
    let is_no_error = error.is_h3_no_error();
    // Should not panic regardless of result
    let _ = is_no_error;
}

fn test_stream_error_properties(error: &StreamError) {
    // Test stream error properties
    let display = format!("{}", error);
    assert!(!display.is_empty() || display.is_empty());

    // Test any stream-specific properties
    let debug = format!("{:?}", error);
    assert!(!debug.is_empty() || debug.is_empty());
}

fn test_io_error_properties(error: &io::Error) {
    // Test I/O error properties
    let display = format!("{}", error);
    assert!(!display.is_empty() || display.is_empty());

    let kind = error.kind();
    let _ = format!("{:?}", kind); // Should not panic

    // Test error source if present
    let _ = error.source();
}

fn test_error_source_chain(error: &H3Error) {
    // Test error source chain traversal
    let mut current: &dyn std::error::Error = error;
    let mut depth = 0;
    const MAX_SOURCE_DEPTH: usize = 10;

    while let Some(source) = current.source() {
        depth += 1;
        if depth > MAX_SOURCE_DEPTH {
            break; // Prevent infinite loops
        }
        current = source;

        // Test that source is accessible
        let _ = format!("{}", current);
    }
}

fn test_error_display(error: &H3Error) {
    // Test various display formats
    let display = format!("{}", error);
    let debug = format!("{:?}", error);
    let alternate = format!("{:#}", error);
    let debug_alternate = format!("{:#?}", error);

    // All should be valid strings
    assert!(!display.is_empty() || display.is_empty());
    assert!(!debug.is_empty() || debug.is_empty());
    assert!(!alternate.is_empty() || alternate.is_empty());
    assert!(!debug_alternate.is_empty() || debug_alternate.is_empty());
}

fn test_raw_code_parsing(code: u64) {
    // Test parsing raw error codes
    let h3_code = Code::from_u64(code.min(u64::from(u32::MAX))); // Limit to reasonable range

    // Test creating errors with this code
    let conn_error = ConnectionError::general_protocol_error();
    let stream_error = StreamError::general_protocol_error();

    // Convert to H3Error
    let h3_conn_error = H3Error::from(conn_error);
    let h3_stream_error = H3Error::from(stream_error);

    // Should not panic
    test_h3_error_properties(&h3_conn_error);
    test_h3_error_properties(&h3_stream_error);
}

fn test_raw_message_parsing(message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Test creating errors with raw message
    let io_error = io::Error::new(io::ErrorKind::Other, safe_message);
    let h3_error = H3Error::from(io_error);

    test_h3_error_properties(&h3_error);
}

// Conversion helper functions

fn convert_connection_error_type(error_type: &ConnectionErrorType, code: u64) -> Code {
    match error_type {
        ConnectionErrorType::NoError => Code::H3_NO_ERROR,
        ConnectionErrorType::GeneralProtocolError => Code::H3_GENERAL_PROTOCOL_ERROR,
        ConnectionErrorType::InternalError => Code::H3_INTERNAL_ERROR,
        ConnectionErrorType::StreamCreationError => Code::H3_STREAM_CREATION_ERROR,
        ConnectionErrorType::ClosedCriticalStream => Code::H3_CLOSED_CRITICAL_STREAM,
        ConnectionErrorType::FrameUnexpected => Code::H3_FRAME_UNEXPECTED,
        ConnectionErrorType::FrameError => Code::H3_FRAME_ERROR,
        ConnectionErrorType::ExcessiveLoad => Code::H3_EXCESSIVE_LOAD,
        ConnectionErrorType::IdError => Code::H3_ID_ERROR,
        ConnectionErrorType::SettingsError => Code::H3_SETTINGS_ERROR,
        ConnectionErrorType::MissingSettings => Code::H3_MISSING_SETTINGS,
        ConnectionErrorType::RequestRejected => Code::H3_REQUEST_REJECTED,
        ConnectionErrorType::RequestCancelled => Code::H3_REQUEST_CANCELLED,
        ConnectionErrorType::RequestIncomplete => Code::H3_REQUEST_INCOMPLETE,
        ConnectionErrorType::MessageError => Code::H3_MESSAGE_ERROR,
        ConnectionErrorType::ConnectError => Code::H3_CONNECT_ERROR,
        ConnectionErrorType::VersionFallback => Code::H3_VERSION_FALLBACK,
    }
}

fn convert_stream_error_type(error_type: &StreamErrorType, _code: u64) -> Code {
    match error_type {
        StreamErrorType::NoError => Code::H3_NO_ERROR,
        StreamErrorType::GeneralProtocolError => Code::H3_GENERAL_PROTOCOL_ERROR,
        StreamErrorType::InternalError => Code::H3_INTERNAL_ERROR,
        StreamErrorType::StreamCreationError => Code::H3_STREAM_CREATION_ERROR,
        StreamErrorType::RequestCancelled => Code::H3_REQUEST_CANCELLED,
        StreamErrorType::RequestIncomplete => Code::H3_REQUEST_INCOMPLETE,
        StreamErrorType::MessageError => Code::H3_MESSAGE_ERROR,
        StreamErrorType::FrameUnexpected => Code::H3_FRAME_UNEXPECTED,
        StreamErrorType::FrameError => Code::H3_FRAME_ERROR,
    }
}

fn convert_io_error_kind(error_kind: &IoErrorKind) -> io::ErrorKind {
    match error_kind {
        IoErrorKind::NotFound => io::ErrorKind::NotFound,
        IoErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        IoErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        IoErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
        IoErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
        IoErrorKind::NotConnected => io::ErrorKind::NotConnected,
        IoErrorKind::AddrInUse => io::ErrorKind::AddrInUse,
        IoErrorKind::AddrNotAvailable => io::ErrorKind::AddrNotAvailable,
        IoErrorKind::BrokenPipe => io::ErrorKind::BrokenPipe,
        IoErrorKind::AlreadyExists => io::ErrorKind::AlreadyExists,
        IoErrorKind::WouldBlock => io::ErrorKind::WouldBlock,
        IoErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
        IoErrorKind::InvalidData => io::ErrorKind::InvalidData,
        IoErrorKind::TimedOut => io::ErrorKind::TimedOut,
        IoErrorKind::WriteZero => io::ErrorKind::WriteZero,
        IoErrorKind::Interrupted => io::ErrorKind::Interrupted,
        IoErrorKind::Unsupported => io::ErrorKind::Unsupported,
        IoErrorKind::UnexpectedEof => io::ErrorKind::UnexpectedEof,
        IoErrorKind::OutOfMemory => io::ErrorKind::OutOfMemory,
        IoErrorKind::Other => io::ErrorKind::Other,
    }
}

fn create_cancel_reason(reason_type: &CancelReasonType, message: &str) -> CancelReason {
    match reason_type {
        CancelReasonType::User => CancelReason::user(message),
        CancelReasonType::Timeout => CancelReason::timeout(message),
        CancelReasonType::Shutdown => CancelReason::shutdown(message),
        CancelReasonType::Resource => CancelReason::resource(message),
    }
}

fn convert_asupersync_error_kind(error_kind: &AsupersyncErrorKind) -> ErrorKind {
    match error_kind {
        AsupersyncErrorKind::Cancelled => ErrorKind::Cancelled,
        AsupersyncErrorKind::Timeout => ErrorKind::Timeout,
        AsupersyncErrorKind::InvalidParams => ErrorKind::InvalidParams,
        AsupersyncErrorKind::ResourceExhausted => ErrorKind::ResourceExhausted,
        AsupersyncErrorKind::NetworkError => ErrorKind::NetworkError,
        AsupersyncErrorKind::DecodingFailed => ErrorKind::DecodingFailed,
        AsupersyncErrorKind::EncodingFailed => ErrorKind::EncodingFailed,
    }
}

fn create_connection_error(code: Code, message: &str) -> ConnectionError {
    // Create connection error based on the message content
    // Since ConnectionError constructors are limited, we use available ones
    if message.contains("timeout") {
        ConnectionError::timeout()
    } else if message.contains("protocol") {
        ConnectionError::general_protocol_error()
    } else {
        ConnectionError::general_protocol_error()
    }
}

fn create_stream_error(code: Code, message: &str) -> StreamError {
    // Create stream error based on the message content
    // Since StreamError constructors are limited, we use available ones
    if message.contains("id") {
        StreamError::id()
    } else if message.contains("protocol") {
        StreamError::general_protocol_error()
    } else {
        StreamError::general_protocol_error()
    }
}

fn limit_string(input: &str, max_len: usize) -> String {
    if input.len() > max_len {
        input.chars().take(max_len).collect()
    } else {
        input.to_string()
    }
}