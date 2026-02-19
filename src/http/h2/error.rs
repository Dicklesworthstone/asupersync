//! HTTP/2 error types.
//!
//! Defines error codes and error types for HTTP/2 protocol operations.

use std::fmt;

/// HTTP/2 error codes as defined in RFC 7540 Section 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    /// The associated condition is not a result of an error.
    NoError = 0x0,
    /// The endpoint detected an unspecific protocol error.
    ProtocolError = 0x1,
    /// The endpoint encountered an unexpected internal error.
    InternalError = 0x2,
    /// The endpoint detected that its peer violated the flow-control protocol.
    FlowControlError = 0x3,
    /// The endpoint sent a SETTINGS frame but did not receive a response in time.
    SettingsTimeout = 0x4,
    /// The endpoint received a frame after a stream was half-closed.
    StreamClosed = 0x5,
    /// The endpoint received a frame with an invalid size.
    FrameSizeError = 0x6,
    /// The endpoint refused the stream prior to performing any work.
    RefusedStream = 0x7,
    /// Used by the endpoint to indicate that the stream is no longer needed.
    Cancel = 0x8,
    /// The endpoint is unable to maintain the header compression context.
    CompressionError = 0x9,
    /// The connection established was rejected because it was not secure.
    ConnectError = 0xa,
    /// The endpoint detected that its peer is exhibiting behavior that might be generating excessive load.
    EnhanceYourCalm = 0xb,
    /// The underlying transport has properties that do not meet minimum security requirements.
    InadequateSecurity = 0xc,
    /// The endpoint requires HTTP/1.1.
    Http11Required = 0xd,
}

impl ErrorCode {
    /// Create an error code from a u32 value.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            // Unknown error codes are treated as INTERNAL_ERROR per RFC 7540
            _ => Self::InternalError,
        }
    }
}

impl From<ErrorCode> for u32 {
    fn from(code: ErrorCode) -> Self {
        code as Self
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NO_ERROR"),
            Self::ProtocolError => write!(f, "PROTOCOL_ERROR"),
            Self::InternalError => write!(f, "INTERNAL_ERROR"),
            Self::FlowControlError => write!(f, "FLOW_CONTROL_ERROR"),
            Self::SettingsTimeout => write!(f, "SETTINGS_TIMEOUT"),
            Self::StreamClosed => write!(f, "STREAM_CLOSED"),
            Self::FrameSizeError => write!(f, "FRAME_SIZE_ERROR"),
            Self::RefusedStream => write!(f, "REFUSED_STREAM"),
            Self::Cancel => write!(f, "CANCEL"),
            Self::CompressionError => write!(f, "COMPRESSION_ERROR"),
            Self::ConnectError => write!(f, "CONNECT_ERROR"),
            Self::EnhanceYourCalm => write!(f, "ENHANCE_YOUR_CALM"),
            Self::InadequateSecurity => write!(f, "INADEQUATE_SECURITY"),
            Self::Http11Required => write!(f, "HTTP_1_1_REQUIRED"),
        }
    }
}

/// HTTP/2 protocol error.
#[derive(Debug)]
pub struct H2Error {
    /// The error code.
    pub code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
    /// Optional stream ID this error applies to (0 for connection-level).
    pub stream_id: Option<u32>,
}

impl H2Error {
    /// Create a new connection-level error.
    #[must_use]
    pub fn connection(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            stream_id: None,
        }
    }

    /// Create a new stream-level error.
    #[must_use]
    pub fn stream(stream_id: u32, code: ErrorCode, message: impl Into<String>) -> Self {
        if stream_id == 0 {
            // Stream ID 0 is reserved for connection-level signaling in HTTP/2.
            // Normalize accidental stream-0 construction to a connection error
            // so downstream classification stays protocol-correct.
            return Self::connection(code, message);
        }
        Self {
            code,
            message: message.into(),
            stream_id: Some(stream_id),
        }
    }

    /// Create a protocol error.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::connection(ErrorCode::ProtocolError, message)
    }

    /// Create a frame size error.
    #[must_use]
    pub fn frame_size(message: impl Into<String>) -> Self {
        Self::connection(ErrorCode::FrameSizeError, message)
    }

    /// Create a flow control error.
    #[must_use]
    pub fn flow_control(message: impl Into<String>) -> Self {
        Self::connection(ErrorCode::FlowControlError, message)
    }

    /// Create a compression error.
    #[must_use]
    pub fn compression(message: impl Into<String>) -> Self {
        Self::connection(ErrorCode::CompressionError, message)
    }

    /// Returns true if this is a connection-level error.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        self.stream_id.is_none()
    }
}

impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(stream_id) = self.stream_id {
            write!(
                f,
                "HTTP/2 stream {} error ({}): {}",
                stream_id, self.code, self.message
            )
        } else {
            write!(
                f,
                "HTTP/2 connection error ({}): {}",
                self.code, self.message
            )
        }
    }
}

impl std::error::Error for H2Error {}

impl From<std::io::Error> for H2Error {
    fn from(err: std::io::Error) -> Self {
        Self::connection(ErrorCode::InternalError, err.to_string())
    }
}

impl From<&str> for H2Error {
    fn from(message: &str) -> Self {
        Self::protocol(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_error_code_from_u32_known_and_unknown() {
        init_test("test_error_code_from_u32_known_and_unknown");
        crate::assert_with_log!(
            ErrorCode::from_u32(0x0) == ErrorCode::NoError,
            "no error",
            true,
            ErrorCode::from_u32(0x0) == ErrorCode::NoError
        );
        crate::assert_with_log!(
            ErrorCode::from_u32(0x1) == ErrorCode::ProtocolError,
            "protocol error",
            true,
            ErrorCode::from_u32(0x1) == ErrorCode::ProtocolError
        );
        crate::assert_with_log!(
            ErrorCode::from_u32(0x2) == ErrorCode::InternalError,
            "internal error",
            true,
            ErrorCode::from_u32(0x2) == ErrorCode::InternalError
        );
        crate::assert_with_log!(
            ErrorCode::from_u32(0xdead) == ErrorCode::InternalError,
            "unknown maps to internal",
            true,
            ErrorCode::from_u32(0xdead) == ErrorCode::InternalError
        );
        crate::test_complete!("test_error_code_from_u32_known_and_unknown");
    }

    #[test]
    fn test_error_code_u32_roundtrip() {
        init_test("test_error_code_u32_roundtrip");
        let code = ErrorCode::FrameSizeError;
        let value: u32 = code.into();
        crate::assert_with_log!(value == 0x6, "frame size code", 0x6u32, value);
        crate::test_complete!("test_error_code_u32_roundtrip");
    }

    #[test]
    fn test_error_code_display_tokens() {
        init_test("test_error_code_display_tokens");
        let no_error = ErrorCode::NoError.to_string();
        let calm = ErrorCode::EnhanceYourCalm.to_string();
        crate::assert_with_log!(
            no_error == "NO_ERROR",
            "no error token",
            "NO_ERROR",
            no_error
        );
        crate::assert_with_log!(
            calm == "ENHANCE_YOUR_CALM",
            "calm token",
            "ENHANCE_YOUR_CALM",
            calm
        );
        crate::test_complete!("test_error_code_display_tokens");
    }

    #[test]
    fn test_h2error_connection_and_stream_variants() {
        init_test("test_h2error_connection_and_stream_variants");
        let conn = H2Error::connection(ErrorCode::Cancel, "bye");
        crate::assert_with_log!(
            conn.is_connection_error(),
            "connection error",
            true,
            conn.is_connection_error()
        );
        crate::assert_with_log!(
            conn.stream_id.is_none(),
            "no stream id",
            true,
            conn.stream_id.is_none()
        );
        let conn_render = conn.to_string();
        crate::assert_with_log!(
            conn_render.contains("connection error"),
            "connection display",
            true,
            conn_render.contains("connection error")
        );

        let stream = H2Error::stream(7, ErrorCode::ProtocolError, "bad");
        crate::assert_with_log!(
            !stream.is_connection_error(),
            "stream error",
            false,
            stream.is_connection_error()
        );
        crate::assert_with_log!(
            stream.stream_id == Some(7),
            "stream id",
            Some(7u32),
            stream.stream_id
        );
        let stream_render = stream.to_string();
        crate::assert_with_log!(
            stream_render.contains("stream 7"),
            "stream display",
            true,
            stream_render.contains("stream 7")
        );
        crate::test_complete!("test_h2error_connection_and_stream_variants");
    }

    #[test]
    fn test_h2error_stream_zero_normalized_to_connection_error() {
        init_test("test_h2error_stream_zero_normalized_to_connection_error");
        let err = H2Error::stream(0, ErrorCode::StreamClosed, "invalid stream id");
        crate::assert_with_log!(
            err.is_connection_error(),
            "stream 0 normalized to connection-level",
            true,
            err.is_connection_error()
        );
        crate::assert_with_log!(
            err.stream_id.is_none(),
            "stream id must be none for normalized error",
            true,
            err.stream_id.is_none()
        );
        crate::assert_with_log!(
            err.to_string().contains("connection error"),
            "display reports connection-level error",
            true,
            err.to_string().contains("connection error")
        );
        crate::test_complete!("test_h2error_stream_zero_normalized_to_connection_error");
    }

    #[test]
    fn test_h2error_helper_constructors_set_codes() {
        init_test("test_h2error_helper_constructors_set_codes");
        let protocol = H2Error::protocol("bad");
        let frame = H2Error::frame_size("size");
        let flow = H2Error::flow_control("flow");
        let compression = H2Error::compression("hpack");
        crate::assert_with_log!(
            protocol.code == ErrorCode::ProtocolError,
            "protocol code",
            true,
            protocol.code == ErrorCode::ProtocolError
        );
        crate::assert_with_log!(
            frame.code == ErrorCode::FrameSizeError,
            "frame size code",
            true,
            frame.code == ErrorCode::FrameSizeError
        );
        crate::assert_with_log!(
            flow.code == ErrorCode::FlowControlError,
            "flow control code",
            true,
            flow.code == ErrorCode::FlowControlError
        );
        crate::assert_with_log!(
            compression.code == ErrorCode::CompressionError,
            "compression code",
            true,
            compression.code == ErrorCode::CompressionError
        );
        crate::test_complete!("test_h2error_helper_constructors_set_codes");
    }

    #[test]
    fn test_h2error_from_io_error_internal() {
        init_test("test_h2error_from_io_error_internal");
        let io_err = std::io::Error::other("io");
        let err = H2Error::from(io_err);
        crate::assert_with_log!(
            err.code == ErrorCode::InternalError,
            "io maps to internal",
            true,
            err.code == ErrorCode::InternalError
        );
        crate::assert_with_log!(
            err.message.contains("io"),
            "message contains io",
            true,
            err.message.contains("io")
        );
        crate::test_complete!("test_h2error_from_io_error_internal");
    }

    #[test]
    fn test_h2error_from_str_protocol() {
        init_test("test_h2error_from_str_protocol");
        let err = H2Error::from("bad");
        crate::assert_with_log!(
            err.code == ErrorCode::ProtocolError,
            "from str protocol",
            true,
            err.code == ErrorCode::ProtocolError
        );
        crate::test_complete!("test_h2error_from_str_protocol");
    }

    #[test]
    fn error_code_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = ErrorCode::Cancel;
        let b = a; // Copy
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, ErrorCode::NoError);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Cancel"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&ErrorCode::FlowControlError));
    }
}
