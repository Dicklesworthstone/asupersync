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
            0x2 => Self::InternalError,
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
    fn from(code: ErrorCode) -> u32 {
        code as u32
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
