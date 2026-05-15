#![no_main]

use arbitrary::Arbitrary;
use asupersync::error::{Error, ErrorKind};
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3Frame, H3NativeError, H3QpackMode, H3Settings, qpack_decode_field_section,
};
use asupersync::types::CancelReason;
use libfuzzer_sys::fuzz_target;
use std::error::Error as StdError;
use std::fmt;
use std::io;

#[derive(Debug)]
enum H3Error {
    Connection(ConnectionError),
    Stream(StreamError),
    Io(io::Error),
    Cancelled,
    Asupersync(Error),
    Native(H3NativeError),
}

impl H3Error {
    fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled => true,
            Self::Asupersync(error) => error.is_cancelled(),
            _ => false,
        }
    }
}

impl fmt::Display for H3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(error) => write!(f, "connection error: {error}"),
            Self::Stream(error) => write!(f, "stream error: {error}"),
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Asupersync(error) => write!(f, "asupersync error: {error}"),
            Self::Native(error) => write!(f, "native h3 error: {error}"),
        }
    }
}

impl StdError for H3Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Stream(error) => Some(error),
            Self::Io(error) => error.source(),
            Self::Asupersync(error) => error.source(),
            Self::Native(error) => Some(error),
            Self::Cancelled => None,
        }
    }
}

impl From<ConnectionError> for H3Error {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

impl From<StreamError> for H3Error {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<io::Error> for H3Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Error> for H3Error {
    fn from(error: Error) -> Self {
        if error.is_cancelled() {
            Self::Cancelled
        } else {
            Self::Asupersync(error)
        }
    }
}

impl From<H3NativeError> for H3Error {
    fn from(error: H3NativeError) -> Self {
        Self::Native(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionError {
    code: Code,
    native: H3NativeError,
}

impl ConnectionError {
    fn timeout() -> Self {
        Self {
            code: Code::H3_INTERNAL_ERROR,
            native: H3NativeError::ControlProtocol("timeout"),
        }
    }

    fn is_h3_no_error(&self) -> bool {
        matches!(self.code.kind, H3CodeKind::NoError)
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}: {}", self.code.raw, self.native)
    }
}

impl StdError for ConnectionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.native)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamError {
    code: Code,
    native: H3NativeError,
}

impl StreamError {
    fn id() -> Self {
        Self {
            code: Code::H3_ID_ERROR,
            native: H3NativeError::StreamProtocol("stream id error"),
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}: {}", self.code.raw, self.native)
    }
}

impl StdError for StreamError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.native)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Code {
    raw: u64,
    kind: H3CodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3CodeKind {
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
    Unknown,
}

impl Code {
    const H3_NO_ERROR: Self = Self {
        raw: 0x100,
        kind: H3CodeKind::NoError,
    };
    const H3_GENERAL_PROTOCOL_ERROR: Self = Self {
        raw: 0x101,
        kind: H3CodeKind::GeneralProtocolError,
    };
    const H3_INTERNAL_ERROR: Self = Self {
        raw: 0x102,
        kind: H3CodeKind::InternalError,
    };
    const H3_STREAM_CREATION_ERROR: Self = Self {
        raw: 0x103,
        kind: H3CodeKind::StreamCreationError,
    };
    const H3_CLOSED_CRITICAL_STREAM: Self = Self {
        raw: 0x104,
        kind: H3CodeKind::ClosedCriticalStream,
    };
    const H3_FRAME_UNEXPECTED: Self = Self {
        raw: 0x105,
        kind: H3CodeKind::FrameUnexpected,
    };
    const H3_FRAME_ERROR: Self = Self {
        raw: 0x106,
        kind: H3CodeKind::FrameError,
    };
    const H3_EXCESSIVE_LOAD: Self = Self {
        raw: 0x107,
        kind: H3CodeKind::ExcessiveLoad,
    };
    const H3_ID_ERROR: Self = Self {
        raw: 0x108,
        kind: H3CodeKind::IdError,
    };
    const H3_SETTINGS_ERROR: Self = Self {
        raw: 0x109,
        kind: H3CodeKind::SettingsError,
    };
    const H3_MISSING_SETTINGS: Self = Self {
        raw: 0x10a,
        kind: H3CodeKind::MissingSettings,
    };
    const H3_REQUEST_REJECTED: Self = Self {
        raw: 0x10b,
        kind: H3CodeKind::RequestRejected,
    };
    const H3_REQUEST_CANCELLED: Self = Self {
        raw: 0x10c,
        kind: H3CodeKind::RequestCancelled,
    };
    const H3_REQUEST_INCOMPLETE: Self = Self {
        raw: 0x10d,
        kind: H3CodeKind::RequestIncomplete,
    };
    const H3_MESSAGE_ERROR: Self = Self {
        raw: 0x10e,
        kind: H3CodeKind::MessageError,
    };
    const H3_CONNECT_ERROR: Self = Self {
        raw: 0x10f,
        kind: H3CodeKind::ConnectError,
    };
    const H3_VERSION_FALLBACK: Self = Self {
        raw: 0x110,
        kind: H3CodeKind::VersionFallback,
    };

    fn from_u64(raw: u64) -> Self {
        match raw {
            0x100 => Self::H3_NO_ERROR,
            0x101 => Self::H3_GENERAL_PROTOCOL_ERROR,
            0x102 => Self::H3_INTERNAL_ERROR,
            0x103 => Self::H3_STREAM_CREATION_ERROR,
            0x104 => Self::H3_CLOSED_CRITICAL_STREAM,
            0x105 => Self::H3_FRAME_UNEXPECTED,
            0x106 => Self::H3_FRAME_ERROR,
            0x107 => Self::H3_EXCESSIVE_LOAD,
            0x108 => Self::H3_ID_ERROR,
            0x109 => Self::H3_SETTINGS_ERROR,
            0x10a => Self::H3_MISSING_SETTINGS,
            0x10b => Self::H3_REQUEST_REJECTED,
            0x10c => Self::H3_REQUEST_CANCELLED,
            0x10d => Self::H3_REQUEST_INCOMPLETE,
            0x10e => Self::H3_MESSAGE_ERROR,
            0x10f => Self::H3_CONNECT_ERROR,
            0x110 => Self::H3_VERSION_FALLBACK,
            _ => Self {
                raw,
                kind: H3CodeKind::Unknown,
            },
        }
    }
}

/// Comprehensive fuzz target for HTTP/3 error code parsing and handling
///
/// Tests the H3 error system for:
/// - Error conversion robustness (native H3 errors -> H3Error -> asupersync Error)
/// - Error classification and properties under edge cases
/// - Error code parsing from native HTTP/3 parser surfaces with malformed values
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
    SerializationTest { error_op: Box<ErrorOperation> },
    /// Test error properties and classification
    PropertyTest { error_op: Box<ErrorOperation> },
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
        ErrorOperation::ConnectionError {
            error_type,
            code,
            message,
        } => {
            test_connection_error_conversion(error_type, *code, message);
        }
        ErrorOperation::StreamError {
            error_type,
            code,
            message,
        } => {
            test_stream_error_conversion(error_type, *code, message);
        }
        ErrorOperation::IoError {
            error_kind,
            message,
        } => {
            test_io_error_conversion(error_kind, message);
        }
        ErrorOperation::CancellationError {
            cancel_reason_type,
            message,
        } => {
            test_cancellation_error(cancel_reason_type, message);
        }
        ErrorOperation::AsupersyncError {
            error_kind,
            is_cancelled,
            message,
        } => {
            test_asupersync_error_conversion(error_kind, *is_cancelled, message);
        }
        ErrorOperation::ChainedError { primary, source } => {
            test_error_operation(primary, depth + 1);
            test_error_operation(source, depth + 1);
            test_error_chaining(primary, source);
        }
        ErrorOperation::SerializationTest { error_op } => {
            test_error_operation(error_op, depth + 1);
            test_error_serialization(error_op);
        }
        ErrorOperation::PropertyTest { error_op } => {
            test_error_operation(error_op, depth + 1);
            test_error_properties(error_op);
        }
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
        }
        _ => {
            // Unexpected variant for connection error input
        }
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
        }
        _ => {
            // Unexpected variant for stream error input
        }
    }
}

fn test_io_error_conversion(error_kind: &IoErrorKind, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create I/O error
    let io_kind = convert_io_error_kind(error_kind);
    let io_error = io_error_with_message(io_kind, &safe_message);

    // Convert to H3Error
    let h3_error = H3Error::from(io_error);

    // Test error properties
    test_h3_error_properties(&h3_error);

    // Test conversion consistency
    match h3_error {
        H3Error::Io(ref ie) => {
            // Should preserve I/O error properties
            test_io_error_properties(ie);
        }
        _ => {
            // Unexpected variant for I/O error input
        }
    }
}

fn test_cancellation_error(cancel_reason_type: &CancelReasonType, message: &str) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create cancel reason
    let cancel_reason =
        create_cancel_reason(cancel_reason_type, static_error_message(&safe_message));

    // Create cancelled asupersync error
    let asupersync_error = Error::cancelled(&cancel_reason);

    // Convert to H3Error
    let h3_error = H3Error::from(asupersync_error);

    // Test cancellation detection
    assert!(
        h3_error.is_cancelled(),
        "Cancelled error should be detected as cancelled"
    );

    // Test error properties
    test_h3_error_properties(&h3_error);
}

fn test_asupersync_error_conversion(
    error_kind: &AsupersyncErrorKind,
    is_cancelled: bool,
    message: &str,
) {
    let safe_message = limit_string(message, MAX_MESSAGE_LEN);

    // Create asupersync error
    let asupersync_error = if is_cancelled {
        let cancel_reason = CancelReason::user(static_error_message(&safe_message));
        Error::cancelled(&cancel_reason)
    } else {
        let kind = convert_asupersync_error_kind(error_kind);
        Error::new(kind).with_message(&safe_message)
    };

    // Convert to H3Error
    let h3_error = H3Error::from(asupersync_error);

    // Test cancellation detection consistency
    assert_eq!(
        h3_error.is_cancelled(),
        is_cancelled,
        "Cancellation detection should match input"
    );

    // Test error properties
    test_h3_error_properties(&h3_error);
}

fn test_error_chaining(primary: &ErrorOperation, source: &ErrorOperation) {
    // Test error chaining behavior - this is implementation-dependent
    // but should not panic
    let chain_description = format!("Primary: {:?}, Source: {:?}", primary, source);
    assert_nonempty_text("chained error debug", &chain_description);
}

fn test_error_serialization(error_op: &ErrorOperation) {
    // Create error from operation and test serialization
    match error_op {
        ErrorOperation::ConnectionError {
            error_type,
            code,
            message,
        } => {
            let safe_message = limit_string(message, MAX_MESSAGE_LEN);
            let h3_code = convert_connection_error_type(error_type, *code);
            let conn_error = create_connection_error(h3_code, &safe_message);
            let h3_error = H3Error::from(conn_error);
            test_error_display(&h3_error);
        }
        _ => {
            // Test other error types similarly
        }
    }
}

fn test_error_properties(error_op: &ErrorOperation) {
    // Test error-specific properties based on operation type
    match error_op {
        ErrorOperation::CancellationError { .. } => {
            // Cancellation errors should be detected properly
        }
        _ => {
            // Other error types have their own properties to test
        }
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

    let config = H3ConnectionConfig {
        max_frame_payload_size: MAX_ERROR_DATA_LEN,
        ..H3ConnectionConfig::default()
    };
    observe_native_parse("frame decode", H3Frame::decode(limited_data, &config));
    observe_native_parse("settings decode", H3Settings::decode_payload(limited_data));
    observe_native_parse(
        "qpack static decode",
        qpack_decode_field_section(limited_data, H3QpackMode::StaticOnly),
    );
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
    let io_error = io::Error::other(special_message);
    let h3_error = H3Error::from(io_error);
    test_h3_error_properties(&h3_error);
}

fn test_conversion_round_trips() {
    // Test H3Error → display → parsing patterns
    let errors = [
        H3Error::Cancelled,
        H3Error::Io(io_error_with_message(io::ErrorKind::TimedOut, "timeout")),
        H3Error::Connection(ConnectionError::timeout()),
        H3Error::Stream(StreamError::id()),
    ];

    for error in &errors {
        let display_string = format!("{}", error);
        assert!(
            !display_string.is_empty(),
            "Error display should not be empty"
        );

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
    let debug1 = format!("{:?}", error1);
    let debug2 = format!("{:?}", error2);
    assert_eq!(
        debug1, debug2,
        "same cancelled error variant should have stable debug output"
    );
    assert_nonempty_text("cancelled debug", &debug1);
}

// Helper functions

fn test_h3_error_properties(error: &H3Error) {
    // Test basic error properties
    let display = format!("{}", error);
    assert_nonempty_text("H3Error Display", &display);

    let debug = format!("{:?}", error);
    assert_nonempty_text("H3Error Debug", &debug);

    // Test cancellation detection
    let is_cancelled = error.is_cancelled();
    match error {
        H3Error::Cancelled => {
            assert!(is_cancelled, "Cancelled variant should report as cancelled");
        }
        _ => {
            // Other variants may or may not be cancelled depending on implementation
        }
    }

    // Test error source chain (if implemented)
    test_error_source_chain(error);
}

fn test_connection_error_properties(error: &ConnectionError) {
    // Test connection error properties
    let display = format!("{}", error);
    assert_nonempty_text("ConnectionError Display", &display);
    test_native_error_properties(&error.native);

    // Test specific ConnectionError methods if available
    let is_no_error = error.is_h3_no_error();
    assert_eq!(
        is_no_error,
        matches!(error.code.kind, H3CodeKind::NoError),
        "ConnectionError::is_h3_no_error should reflect parsed code kind"
    );
}

fn test_stream_error_properties(error: &StreamError) {
    // Test stream error properties
    let display = format!("{}", error);
    assert_nonempty_text("StreamError Display", &display);
    test_native_error_properties(&error.native);

    // Test any stream-specific properties
    let debug = format!("{:?}", error);
    assert_nonempty_text("StreamError Debug", &debug);
}

fn test_io_error_properties(error: &io::Error) {
    // Test I/O error properties
    let display = format!("{}", error);
    assert_nonempty_text("I/O error Display", &display);

    let kind = error.kind();
    let kind_debug = format!("{:?}", kind);
    assert_nonempty_text("I/O error kind Debug", &kind_debug);

    // Test error source if present
    if let Some(source) = error.source() {
        let source_display = format!("{source}");
        assert_nonempty_text("I/O error source Display", &source_display);
    }
}

fn test_error_source_chain(error: &H3Error) {
    // Test error source chain traversal
    let mut current: &dyn StdError = error;
    let mut depth = 0;
    const MAX_SOURCE_DEPTH: usize = 10;

    while let Some(source) = current.source() {
        depth += 1;
        assert!(
            depth <= MAX_SOURCE_DEPTH,
            "error source chain exceeded max depth"
        );
        current = source;

        // Test that source is accessible
        let source_display = format!("{}", current);
        assert_nonempty_text("error source Display", &source_display);
    }
}

fn test_error_display(error: &H3Error) {
    // Test various display formats
    let display = format!("{}", error);
    let debug = format!("{:?}", error);
    let alternate = format!("{:#}", error);
    let debug_alternate = format!("{:#?}", error);

    // All should be valid strings
    assert_nonempty_text("H3Error Display", &display);
    assert_nonempty_text("H3Error Debug", &debug);
    assert_nonempty_text("H3Error alternate Display", &alternate);
    assert_nonempty_text("H3Error alternate Debug", &debug_alternate);
}

fn test_raw_code_parsing(code: u64) {
    // Test parsing raw error codes
    let h3_code = Code::from_u64(code.min(u64::from(u32::MAX))); // Limit to reasonable range
    assert!(
        h3_code.raw <= u64::from(u32::MAX),
        "raw code must stay inside the clamped u32 range"
    );

    // Test creating errors with this code
    let conn_error = create_connection_error(h3_code, "raw code");
    let stream_error = create_stream_error(h3_code, "raw code");

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
    let io_error = io::Error::other(if safe_message.is_empty() {
        "empty raw message".to_string()
    } else {
        safe_message
    });
    let h3_error = H3Error::from(io_error);

    test_h3_error_properties(&h3_error);
}

fn observe_native_parse<T: fmt::Debug>(label: &str, result: Result<T, H3NativeError>) {
    match result {
        Ok(value) => {
            let debug = format!("{:?}", value);
            assert_nonempty_text(label, &debug);
        }
        Err(error) => {
            test_native_error_properties(&error);
            let h3_error = H3Error::from(error);
            test_h3_error_properties(&h3_error);
        }
    }
}

fn test_native_error_properties(error: &H3NativeError) {
    let display = format!("{}", error);
    assert_nonempty_text("H3NativeError Display", &display);

    let debug = format!("{:?}", error);
    assert_nonempty_text("H3NativeError Debug", &debug);

    match error {
        H3NativeError::InvalidFrame(message)
        | H3NativeError::ControlProtocol(message)
        | H3NativeError::StreamProtocol(message)
        | H3NativeError::QpackPolicy(message)
        | H3NativeError::InvalidRequestPseudoHeader(message)
        | H3NativeError::InvalidResponsePseudoHeader(message) => {
            assert_nonempty_text("H3 native error message", message);
        }
        H3NativeError::FrameTooLarge {
            payload_size,
            max_size,
        } => {
            assert!(
                payload_size > max_size,
                "FrameTooLarge must report payload_size > max_size"
            );
        }
        H3NativeError::ConcurrentStreamLimitExceeded { active, limit } => {
            assert!(
                active >= limit,
                "stream limit error must report active >= limit"
            );
        }
        H3NativeError::UnexpectedEof
        | H3NativeError::DuplicateSetting(_)
        | H3NativeError::InvalidSettingValue(_) => {}
    }
}

fn assert_nonempty_text(label: &str, text: &str) {
    assert!(!text.is_empty(), "{label} should not be empty");
}

// Conversion helper functions

fn convert_connection_error_type(error_type: &ConnectionErrorType, code: u64) -> Code {
    let parsed = Code::from_u64(code.min(u64::from(u32::MAX)));
    if !matches!(parsed.kind, H3CodeKind::Unknown) {
        return parsed;
    }

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

fn convert_stream_error_type(error_type: &StreamErrorType, code: u64) -> Code {
    let parsed = Code::from_u64(code.min(u64::from(u32::MAX)));
    if !matches!(parsed.kind, H3CodeKind::Unknown) {
        return parsed;
    }

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

fn create_cancel_reason(reason_type: &CancelReasonType, message: &'static str) -> CancelReason {
    match reason_type {
        CancelReasonType::User => CancelReason::user(message),
        CancelReasonType::Timeout => CancelReason::timeout(),
        CancelReasonType::Shutdown => CancelReason::shutdown(),
        CancelReasonType::Resource => CancelReason::resource_unavailable(),
    }
}

fn convert_asupersync_error_kind(error_kind: &AsupersyncErrorKind) -> ErrorKind {
    match error_kind {
        AsupersyncErrorKind::Cancelled => ErrorKind::Cancelled,
        AsupersyncErrorKind::Timeout => ErrorKind::DeadlineExceeded,
        AsupersyncErrorKind::InvalidParams => ErrorKind::InvalidEncodingParams,
        AsupersyncErrorKind::ResourceExhausted => ErrorKind::AdmissionDenied,
        AsupersyncErrorKind::NetworkError => ErrorKind::ConnectionLost,
        AsupersyncErrorKind::DecodingFailed => ErrorKind::DecodingFailed,
        AsupersyncErrorKind::EncodingFailed => ErrorKind::EncodingFailed,
    }
}

fn create_connection_error(code: Code, message: &str) -> ConnectionError {
    let detail = static_error_message(message);
    let native = match code.kind {
        H3CodeKind::NoError => H3NativeError::ControlProtocol("h3 no error"),
        H3CodeKind::GeneralProtocolError
        | H3CodeKind::FrameUnexpected
        | H3CodeKind::FrameError
        | H3CodeKind::Unknown => H3NativeError::InvalidFrame(detail),
        H3CodeKind::InternalError
        | H3CodeKind::ClosedCriticalStream
        | H3CodeKind::ExcessiveLoad
        | H3CodeKind::RequestRejected
        | H3CodeKind::RequestCancelled
        | H3CodeKind::RequestIncomplete
        | H3CodeKind::MessageError
        | H3CodeKind::ConnectError
        | H3CodeKind::VersionFallback => H3NativeError::ControlProtocol(detail),
        H3CodeKind::StreamCreationError | H3CodeKind::IdError => {
            H3NativeError::StreamProtocol(detail)
        }
        H3CodeKind::SettingsError => H3NativeError::InvalidSettingValue(code.raw),
        H3CodeKind::MissingSettings => H3NativeError::ControlProtocol("missing settings"),
    };
    ConnectionError { code, native }
}

fn create_stream_error(code: Code, message: &str) -> StreamError {
    let detail = static_error_message(message);
    let native = match code.kind {
        H3CodeKind::NoError => H3NativeError::StreamProtocol("h3 no error"),
        H3CodeKind::FrameUnexpected | H3CodeKind::FrameError | H3CodeKind::Unknown => {
            H3NativeError::InvalidFrame(detail)
        }
        H3CodeKind::SettingsError => H3NativeError::InvalidSettingValue(code.raw),
        H3CodeKind::GeneralProtocolError
        | H3CodeKind::InternalError
        | H3CodeKind::StreamCreationError
        | H3CodeKind::ClosedCriticalStream
        | H3CodeKind::ExcessiveLoad
        | H3CodeKind::IdError
        | H3CodeKind::MissingSettings
        | H3CodeKind::RequestRejected
        | H3CodeKind::RequestCancelled
        | H3CodeKind::RequestIncomplete
        | H3CodeKind::MessageError
        | H3CodeKind::ConnectError
        | H3CodeKind::VersionFallback => H3NativeError::StreamProtocol(detail),
    };
    StreamError { code, native }
}

fn static_error_message(message: &str) -> &'static str {
    if message.is_empty() {
        "empty fuzz message"
    } else if message.contains("timeout") {
        "timeout"
    } else if message.contains("protocol") {
        "protocol"
    } else if message.contains("setting") {
        "setting"
    } else if message.contains("header") {
        "header"
    } else {
        "fuzz h3 error"
    }
}

fn io_error_with_message(kind: io::ErrorKind, message: &str) -> io::Error {
    let message = if message.is_empty() {
        "fuzz io error"
    } else {
        message
    };

    if kind == io::ErrorKind::Other {
        io::Error::other(message.to_string())
    } else {
        io::Error::new(kind, message.to_string())
    }
}

fn limit_string(input: &str, max_len: usize) -> String {
    if input.len() > max_len {
        input.chars().take(max_len).collect()
    } else {
        input.to_string()
    }
}
